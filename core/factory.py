"""OS 能力工厂 —— 中间层的「技能创造者」。

让「往中间层加一个 OS 能力」变成规范化的两件事：写一份声明 + 写一个实现函数。
其余（进注册表、进状态聚合、被 dashboard 显示、接策略）全部自动登记，核心零改动。

与「可插拔解耦」一脉相承：加能力不碰内核。

理念：在 skill 生态里开辟「OS 生态」——
  · 原语 = OS 生态的能力单元（类比 skill 里的一个技能）
  · 原语工厂 = OS 生态的「技能创造者」（类比 skill-creator）
这样 OS 能力能像 skill 一样：可插拔、可组合、可分享、有规范。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from core.interpreter import ToolRegistry, is_pure_preview

# ── 全局登记表（声明式）：内核 + 状态表 + 策略表，加原语自动跟进 ──
registry = ToolRegistry()
STATE_SCHEMA: dict[str, dict[str, str]] = {}   # 原语名 -> {字段: 标签}（dashboard 据此渲染）
POLICY: dict[str, dict] = {}                    # 原语名 -> 策略规则（如需确认/白名单）
BLOCK_OF: dict[str, str] = {}                   # 原语名 -> 块 id（见 core/blocks.py）


def declare_primitive(name: str, description: str, schema: dict,
                      *, source: str = "native", state: dict | None = None,
                      policy: dict | None = None, block: str | None = None):
    """声明式注册一个原语。用它包住实现函数即可：

        @declare_primitive("disk.usage", "查询指定路径所在磁盘的占用", {...},
                           state={"used_pct": "占用%"}, block="disk")
        def disk_usage(path: str):
            return {"used_pct": ...}

    自动进 registry + 状态表 + 策略表 + 块表。加新能力 = 写一个这样的声明，其余全自动。
    **注意：原语实现放 primitives/，不是这个文件** —— 见文件末尾的说明。

    block: 该原语属于哪一块（id 见 `core.blocks.BLOCK_IDS`）。接入方按块展开工具说明，
    所以**归属要显式写、不靠名字前缀猜**。漏写不会当场报错，但 `load_primitives()`
    结束时会打警告，`blocks.check_coverage()` 能列出全部漏网的原语。
    """
    def wrap(fn):
        registry.tool(name, description, schema, source=source)(fn)
        if state:
            STATE_SCHEMA[name] = state
        if policy:
            POLICY[name] = policy
        if block:
            BLOCK_OF[name] = block
        return fn
    return wrap


def build_policy_gate(allow_headless: bool = False):
    """把全局 POLICY 声明注入解释器的 PolicyGate —— 让 requires_confirmation 真正生效。

    背景（安全洞）：factory.POLICY 与 interpreter.PolicyGate 原本是两套互不相通的表，
    只有 panel.py 读 POLICY 做界面显示。IR 路径走的是 PolicyGate 的 _default_rules()，
    其中没有 process.kill / system.free_memory 的规则 → 回退到通用 call 规则 → 直接放行，
    process.kill 会真的执行。这里把 POLICY 转成 PolicyRule 并覆盖进 gate，堵上。

    allow_headless=False（默认真实运行时）：非交互环境（QQ/微信无 tty）下需确认的操作
    一律 fail-closed 拒绝，且不抛异常、只返回 False（调用方按"用户拒绝执行"处理）。
    """
    from core.interpreter import PolicyGate, PolicyRule
    gate = PolicyGate(allow_headless=allow_headless)  # 先建，自带 op 级默认规则
    for name, pol in POLICY.items():
        gate.rules[name] = PolicyRule(
            op=name,
            allow=True,
            requires_confirmation=bool(pol.get("requires_confirmation")),
            allowed_paths=pol.get("allowed_paths"),
        )
    gate.dry_run_primitives = _dry_run_names()
    gate.preview_exempt = _preview_exempt()
    return gate


def _dry_run_names() -> set[str]:
    """哪些原语的 schema 里**真的**声明了 `dry_run` 参数（点号与下划线两种写法都收）。

    给安全门用 —— 只有声明了 dry_run 的原语，才认它的 `dry_run=True` 是「只读预览」。
    为什么不能只看参数本身：见 `interpreter.PolicyGate.is_preview` 的说明
    （`escape` 这类没有 dry_run 的原语，调用方塞个 `"dry_run": true` 会被误放行）。
    """
    out: set[str] = set()
    for name, t in registry.list_tools().items():
        if "dry_run" in ((t.get("schema") or {}).get("properties") or {}):
            out.add(name)
            out.add(name.replace(".", "_"))
    return out


def _preview_exempt() -> dict[str, set[str]]:
    """哪些原语声明了「会让 dry_run 不再只读」的参数（原语名 → 参数名集合）。

    给安全门用 —— 见 `interpreter.is_pure_preview` 的说明（`net.download` 的 probe
    会在预览分支里真的发 HTTP HEAD，于是「dry_run=True 免确认」的前提被破）。

    原语侧写法：
        @declare_primitive(..., policy={"requires_confirmation": True,
                                        "preview_exempt_args": ["probe"]})

    点号与下划线两种写法都收（同 `_dry_run_names`）—— IR 路径用的是 LLM 侧的下划线名
    （DeepSeek 的 function.name 不许带点），只登记点号会漏。
    """
    out: dict[str, set[str]] = {}
    for name, pol in POLICY.items():
        args = pol.get("preview_exempt_args")
        if not args:
            continue
        s = {str(a) for a in args}
        out[name] = set(s)
        out[name.replace(".", "_")] = set(s)
    return out


class ExecutionGate:
    """原语执行的最后一道门 —— 兜住所有**不经过 IR 解释器**的直接调用。

    背景（安全洞）：Policy Gate 原本只装在解释器那条路上，`registry.execute()` 是裸奔的 ——
    平台面板的 /run、脚本直调、以及任何未来的接入方，都能绕过全部安全检查直接执行。
    README 里那句「Policy Gate 是硬编码，不靠模型自觉」，此前只对 IR 路径成立。

    **「怎么问用户」不自己判断，按优先级取三个来源**：
      1. `confirmer` —— 接入方注入的确认回调。读终端、发 IM 消息等回复、
         等网页点击，都行。**这是唯一能在「用户不在终端里」时把问题问出去的路子。**
      2. 没有确认器但 stdin 是终端 → 门自己读终端问
      3. 都不可用（真的没人在场）→ 拒绝

    ⚠️ 曾经的设计缺陷（2026-09-11 实测抓到）：原以为「stdin 是终端 = 上游会去问」，
    于是直接放行 —— 但**直调场景根本没有上游**，结果是既没问也没拦。
    「有人在」不等于「有人会问」。

    **只管会改状态的原语**（策略表标了 `requires_confirmation` 的）；只读的放行。
    """

    def __init__(self, policy: dict, confirmer=None, allow_headless: bool = False,
                 describe=None, dry_run_primitives=None, preview_exempt=None):
        self.policy = policy
        self.confirmer = confirmer
        self.allow_headless = allow_headless
        # describe: name -> 原语作用说明。确认界面里「作用」那行靠它 ——
        # 用户看不懂 fs.delete 这种名字，但看得懂「删除文件/目录」。
        self.describe = describe
        # 带 dry_run 参数的原语名单（见 _dry_run_names）—— 用来识别「只读预览」
        self.dry_run_primitives = dry_run_primitives or set()
        # 「会让 dry_run 不再只读」的参数（见 _preview_exempt）—— 光看 dry_run 不够
        self.preview_exempt = preview_exempt or {}

    def __call__(self, name: str, args: dict, confirmed: bool = False) -> tuple[bool, str]:
        pol = self.policy.get(name)
        if not pol or not pol.get("requires_confirmation"):
            return True, "ok"                       # 只读 / 未登记策略 → 放行
        if confirmed:
            return True, "上游已确认，不重复询问"      # IR 路径的 PolicyGate.confirm() 问过了
        if is_pure_preview(name, args, self.dry_run_primitives, self.preview_exempt):
            # 只读预览没有可确认的对象 —— 它一个字节的状态都不改。
            # 判定统一在 interpreter.is_pure_preview（三条：真的声明了 dry_run、
            # 显式传了 True、且**没踩中预览例外参数** —— 如 net.download 的 probe）。
            # 两处门共用同一份判定，免得有一天分叉出安全洞。
            return True, "只读预览（dry_run=True），无需确认"
        # ① 接入方给了确认器 —— QQ / 网页 / 终端都能接这条路
        if self.confirmer is not None:
            try:
                ok = bool(self.confirmer(name, args))
            except Exception as e:
                return False, f"确认器异常，按拒绝处理：{e}"
            return ok, ("用户同意" if ok else f"用户拒绝了 {name}")
        # ② 没确认器但人在终端前 —— 自己问
        if sys.stdin and sys.stdin.isatty():
            from core.interpreter import render_confirmation
            desc = self.describe(name) if self.describe else ""
            # ⚠️ 确认框走 **stderr**：stdout 是留给调用方的结构化输出（CLI 的结果 JSON
            # 要靠它接 jq）。提示语走 stdout 会把管道输出弄脏 —— 一旦「确认通过并返回结果」
            # 同时发生，下游解析当场崩。
            print(render_confirmation(name, args, desc), file=sys.stderr)
            try:
                # prompt 单独打到 stderr：input() 自带的 prompt 是写 stdout 的，
                # 被拒路径上它也会把调用方的管道弄脏（实测过）。
                print("     允许执行? [y/N]: ", end="", file=sys.stderr, flush=True)
                ans = input().strip().lower()
                return ans == "y", ("用户同意" if ans == "y" else f"用户拒绝了 {name}")
            except (EOFError, OSError):
                pass                                # 输入不可用 → 落到 ③
        # ③ 真的没人可问
        if self.allow_headless:
            return True, f"无人可确认，按 allow_headless 放行：{name}"
        return False, (f"高危原语 {name} 无人可确认，已拒绝。"
                       f"接入方可装确认器（install_execution_gate(confirmer=...)），"
                       f"自动化场景可传 allow_headless=True")


def install_execution_gate(allow_headless: bool = False, confirmer=None) -> None:
    """把执行门装到全局 registry 上（幂等，重复调用按新参数覆盖）。

    confirmer: 接入方提供的确认回调，签名 (原语名, 参数) -> bool。
       读终端的、发 IM 消息的、等网页点击的，各接入方传各的。
    """
    describe = lambda n: registry._tools.get(n, {}).get("description", "")  # noqa: E731
    registry.gate = ExecutionGate(POLICY, confirmer=confirmer,
                                  allow_headless=allow_headless, describe=describe,
                                  dry_run_primitives=_dry_run_names(),
                                  preview_exempt=_preview_exempt())


def load_primitives(directory: str) -> int:
    """扫描目录下所有 *.py，加载其中 @declare_primitive 声明的原语（自动登记）。

    加新原语 = 往目录加一个文件（声明式）；主程序扫描即自动跟上，核心零改动。
    返回加载的模块数。
    """
    d = Path(directory)
    if not d.is_dir():
        return 0
    loaded = 0
    for p in sorted(d.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"prim_{p.stem}", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # 执行 → 触发 @declare_primitive 登记
            loaded += 1
        except Exception as e:
            print(f"[factory] 加载原语失败 {p.name}: {e}", file=sys.stderr)
    # 原语加载完自动装执行门 —— 策略表此刻才填好，门必须晚于原语注册。
    # 这一步堵的是「直接调 registry.execute() 不过任何安全检查」的洞。
    install_execution_gate()
    _warn_block_coverage()
    return loaded


def _warn_block_coverage() -> None:
    """块归属漏写的当场警告（见 `core.blocks.check_coverage`）。

    「以后加原语忘了写 block」不会让任何功能坏掉 —— 它只会让接入方的块目录里
    少一条原语，而**这种缺失在运行时悄无声息**（模型不知道该有它，也就不会问）。
    所以趁加载这一步喊出来，别等出事再回头找。
    """
    try:
        from core.blocks import BLOCK_IDS, check_coverage
        cov = check_coverage()
    except Exception as e:                     # 校验本身不该拖垮加载
        print(f"[factory] 块归属校验失败（不影响加载）：{e}", file=sys.stderr)
        return
    if cov["missing"]:
        shown = " ".join(cov["missing"][:8])
        more = f" …（共 {len(cov['missing'])} 条）" if len(cov["missing"]) > 8 else ""
        print(f"[factory] ⚠️ 这些原语没声明 block，接入方的块目录里会缺它们："
              f"{shown}{more}", file=sys.stderr)
    if cov["stale"]:
        print(f"[factory] ⚠️ 块表里挂着不存在的原语：{' '.join(cov['stale'])}", file=sys.stderr)
    if cov["unknown_block"]:
        print(f"[factory] ⚠️ 未知块 id：{' '.join(cov['unknown_block'])}"
              f"（可选：{' / '.join(BLOCK_IDS)}）", file=sys.stderr)


# ⚠️ 关于「原语写在哪」：**一律放 primitives/，不要写在这个文件里。**
#
# 这里曾经住着一个真实的 system.uptime —— 它是「加能力不碰 core」那条铁律的**唯一反例**：
# 挂着「示例」的名头，却是注册进 registry 的活原语，core/ 里因此混进了一个外设。
# 2026-09-11 已挪回 primitives/system.py。写法示例见上面 declare_primitive 的说明，
# 或 README 的「新增一个 OS 原语」一节。
