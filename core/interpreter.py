"""
IntentOS 语义解释器 —— IR（语义指令）的本地确定性执行引擎。

**定位**：IntentOS 是**工具**，不是 Agent。它不懂自然语言、不调 LLM、不持有对话状态。
调用方（任何 Agent）把「已经翻译好的 IR + 纯数据上下文」交给它，它执行并返回结果：

    ir = IRProgram(instructions=[Instruction(op="call", tool="disk.list", args={})])
    result = await SemanticInterpreter(registry, gate, workspace).run(ir)

**它替调用方做四件确定性的事**：
  1. **校验** —— 非法操作码 / 未知工具 / 未定义依赖，执行前就拦下
  2. **并行** —— 按依赖关系拓扑分层，同层并发跑
  3. **传值** —— `$寄存器` 把上一步结果喂给下一步，不经调用方转述
  4. **管安全** —— Policy Gate + 执行门，副作用一律过闸

**IR 由谁生成、怎么生成，与它无关** —— 那是调用方的事（可以靠 LLM，也可以手工写）。

> 2026-09-11 瘦身：原先核心里还塞着 `LLMClient` / `AgentRuntime` / `MockLLM` /
> `DEFAULT_SYSTEM_PROMPT` / 内置演示工具 —— 那些都是「Agent 的事」，与「中间层是工具」
> 的定位冲突，已全部移除。见 docs/archive/refactor-proposal.md。
"""
from __future__ import annotations

import asyncio
import inspect
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

# 直接运行本文件时（python core/interpreter.py），sys.path[0] 是 core/ 而非项目根，
# 下面那句 `from core import journal` 会 ImportError —— 先把项目根补上。
# 被当模块 import 时 __package__ 非空，跳过。
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import journal


# ============================================================================
# 1. 语义指令集 (IR) —— AI 输出的 "字节码"
# ============================================================================
# AI 不直接说 "调用 read_file 工具"，而是输出受控的语义动作。
# OpCode 只定义 "元操作"；具体工具调用通过 Instruction.tool 字段，
# 实现 "原生工具直调" 与 "元操作" 的统一。

class OpCode(str, Enum):
    """有限的、确定性的元操作码 —— 只留三个。

    2026-09-11 两次精简：
      ① 删 load / store / search —— 它们只是 read_file / write_file / search_memory
         三个特定工具的硬编码别名，与通用的 call 完全重复；且工具不存在时会静默返回
         参数、不报错（调用方以为成功了）。
      ② 删 exec —— 它是绕过整个中间层的万能口子（跑在**同一个进程**里，能摸到全部注册表、
         工具乃至内存），现由**独立子进程**实现的 `escape` 原语承担，且必须用户点头。
         见 primitives/escape.py 与 docs/archive/refactor-proposal.md。
    """
    CALL   = "call"     # 通用：调用任意已注册原生工具 (tool 字段指定) —— 所有任务都用它
    ASK    = "ask"      # 澄清：向用户提问，不盲目执行
    FINISH = "finish"   # 终止：任务完成


@dataclass
class Instruction:
    """单条语义指令。"""
    op: str
    args: dict[str, Any] = field(default_factory=dict)
    out: Optional[str] = None                        # 结果绑定的寄存器
    depends_on: list[str] = field(default_factory=list)  # 依赖的寄存器 (并行调度)
    tool: Optional[str] = None                       # op=CALL 时，指定工具名
    # 内部字段：这一条在批量确认时被用户点了头。**不属于 IR 协议** —— 调用方不用填，
    # 由解释器在执行前统一标记（见 SemanticInterpreter._confirm_batch）。
    approved: bool = False


@dataclass
class IRProgram:
    """一段 IR 程序 = 一次 LLM 推理的 "意愿"。"""
    instructions: list[Instruction] = field(default_factory=list)
    final_answer: Optional[str] = None


# ============================================================================
# 1b. IR 的 JSON Schema —— 协议的机器可读形式
# ============================================================================
# 调用方若想让 LLM 来生成 IR，把这份 schema 挂成 tool 的 input_schema 即可 ——
# 模型输出即合规，比「在 prompt 里要求返回 JSON」可靠得多。
# IntentOS 自己不会用到它（它只认 IR 对象），但它是「IR 长什么样」的权威定义，供接入方取用。

IR_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "instructions": {
            "type": "array",
            "description": "要执行/并行执行的语义指令序列",
            "items": {
                "type": "object",
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": [o.value for o in OpCode],
                        "description": "操作码",
                    },
                    "tool": {
                        "type": "string",
                        "description": "当 op='call' 时，指定要调用的原生工具名 (如 'read_file')",
                    },
                    "args": {
                        "type": "object",
                        "description": "参数。可用 $reg 引用其他指令的结果",
                    },
                    "out": {"type": "string", "description": "结果绑定的寄存器名"},
                    "depends_on": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "依赖的寄存器，用于并行调度",
                    },
                },
                "required": ["op"],
            },
        },
        "final_answer": {
            "type": "string",
            "description": "任务完成时的自然语言最终答复",
        },
    },
    "required": ["instructions"],
    "additionalProperties": False,
}

# ============================================================================
# 2. 工作空间 (Workspace) —— "内存" 的本地化实现
# ============================================================================

class Workspace:
    """受控内存空间：IR 执行时的 "寄存器堆" + AI 的持久化记忆。"""

    def __init__(self, root: str = "./agent_workspace"):
        self._registers: dict[str, Any] = {}
        self.root = root

    def write(self, name: str, value: Any):
        self._registers[name] = value

    def read(self, ref: str) -> Any:
        key = ref[1:] if ref.startswith("$") else ref
        if "." in key:
            head, *rest = key.split(".")
            val = self._registers.get(head)
            for part in rest:
                val = val.get(part) if isinstance(val, dict) else None
            return val
        return self._registers.get(key)

    def resolve(self, value: Any) -> Any:
        """递归解析参数中的 $引用 —— 指令间数据零拷贝传递。"""
        if isinstance(value, str) and value.startswith("$"):
            return self.read(value)
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        return value

    def snapshot(self) -> dict:
        return dict(self._registers)


# ============================================================================
# 3. 安全策略网关 (Policy Gate)
# ============================================================================

def render_confirmation(name: str, args: dict, description: str = "") -> str:
    """把「马上要执行什么」渲染成人能看懂的一段话 —— 确认界面共用。

    为什么要专门做这个（2026-09-11 定）：改动 2、4 之后，安全兜底全压在
    「用户点头」上。如果弹出来的只是一行命令或一串参数字典，用户看不明白、
    点得飞快，这道关就等于没有。**用户看不懂命令，但看得懂「要删哪个文件」。**

    三条要求：完整显示（不截断）、翻成人话、参数逐行列清。
    """
    lines = ["", "⚠️  即将执行高危操作", f"    原语：{name}"]
    if description:
        first = re.split(r"[。；;\n]", description.strip())[0].strip()
        if first:
            lines.append(f"    作用：{first}")
    if args:
        lines.append("    参数：")
        for k, v in args.items():
            lines.append(f"      {k} = {v}")
    return "\n".join(lines)


@dataclass
class PolicyRule:
    op: str
    allow: bool = True
    requires_confirmation: bool = False
    allowed_paths: Optional[list[str]] = None


def is_pure_preview(name: str, args: dict, dry_run_primitives: set[str],
                    preview_exempt: dict[str, set[str]]) -> bool:
    """这次调用是不是「纯预览」—— 判定只有这一份实现，两处门共用。

    （`PolicyGate.is_preview` 走 IR 路径，`factory.ExecutionGate.__call__` 兜住
      「直接调 registry.execute」那条路。两边各写一份必然有一天会分叉 ——
      而分叉出来的那一条就是安全洞。2026-09-12 统一到这里。）

    三条全满足才算「纯预览」：
      ① 该原语的 schema **真的**声明了 dry_run（在 `dry_run_primitives` 名单里）；
      ② 本次**显式**传了 `dry_run=True`；
      ③ **没有**踩中该原语声明的「预览例外参数」。

    ⚠️ 第 ③ 条是 2026-09-12 审计实测补的，它堵的是一个真口子：
    `net.download` 的 `probe=true` 会在**预览分支里真的发一个 HTTP HEAD**（带着调用方
    自定义的请求头）。而「dry_run=True 免确认」这条规则的前提，恰恰是「dry_run 路径
    零副作用」—— 前提一破，规则就成空话，而且它给的是一条**无摩擦的外泄通道**。
    原语用 `policy={"preview_exempt_args": ["probe"]}` 声明这类参数；内核按声明判、不猜，
    也不认识任何具体原语名。
    """
    if args.get("dry_run") is not True or name not in dry_run_primitives:
        return False
    exempt = preview_exempt.get(name)
    if not exempt:
        return True
    for a in exempt:
        v = args.get(a)
        if v is True or (isinstance(v, str) and v.strip().lower() in ("true", "1", "yes")):
            return False
    return True


class PolicyGate:
    """权限/沙箱/确认 的统一入口。所有副作用必须经过这里。"""

    def __init__(self, rules: Optional[list[PolicyRule]] = None,
                 allow_headless: bool = False):
        """
        allow_headless: 是否在非交互环境 (服务器/CI/沙箱) 自动放行需确认的操作。
          - False (默认，安全优先): 无 tty 时拒绝需确认的操作
          - True (自动化场景): 依据规则本身决定是否放行，跳过交互确认
        """
        self.rules = {r.op: r for r in (rules or self._default_rules())}
        self.allow_headless = allow_headless
        # 带 dry_run 参数的原语名单（点号与下划线两种写法都收），由接入方注入 ——
        # 见 factory.build_policy_gate。内核不认识具体原语，只认得这份名单。
        self.dry_run_primitives: set[str] = set()
        # 「会让 dry_run 不再只读」的参数：原语名 → 参数名集合，同样由接入方注入。
        # 见 is_pure_preview() 的说明 —— 没有这份声明，`net.download` 的 probe
        # 就能披着「预览」的皮出网。
        self.preview_exempt: dict[str, set[str]] = {}

    def _default_rules(self) -> list[PolicyRule]:
        """op 级默认规则。

        **工具级规则不由中间层预设** —— 每个原语自己声明
        （`@declare_primitive(..., policy={"requires_confirmation": True})`），
        由 `factory.build_policy_gate()` 注入进来。
        """
        return [
            PolicyRule(op="call",   allow=True),
            PolicyRule(op="ask",    allow=True),
            PolicyRule(op="finish", allow=True),
        ]

    def _resolve_rule(self, instr: Instruction) -> PolicyRule:
        """
        策略解析优先级：
        1. op=CALL 且有 tool → 先查工具级规则 (如 write_file/run_code 的细粒度策略)
        2. 再查 op 级通用规则 (如 call/ask)
        3. 都没有 → 默认禁止 (fail-closed，安全优先)

        工具名宽容匹配：IR 里的 tool 可能是 LLM 侧的 system_info，而策略表按真实名
        system.info 登记 → 两种写法都要能命中（否则规则失效 = 安全洞）。
        """
        if instr.op == OpCode.CALL.value and instr.tool:
            if instr.tool in self.rules:
                return self.rules[instr.tool]
            dotted = instr.tool.replace("_", ".")  # LLM 侧下划线名 → 策略表的点号真名
            if dotted in self.rules:
                return self.rules[dotted]
            if "call" in self.rules:  # 通用原生工具规则
                return self.rules["call"]
        return self.rules.get(instr.op, PolicyRule(op=instr.op, allow=False))

    def check(self, instr: Instruction) -> tuple[bool, str]:
        rule = self._resolve_rule(instr)
        if not rule.allow:
            return False, f"操作 {instr.op}/{instr.tool} 被策略禁止"
        # 路径白名单
        if rule.allowed_paths:
            path = str(instr.args.get("path", ""))
            if not any(path.startswith(p) for p in rule.allowed_paths):
                return False, f"路径 '{path}' 不在白名单 {rule.allowed_paths}"
        return True, "ok"

    def is_preview(self, instr: Instruction) -> bool:
        """这条指令是不是「只读预览」：原语带 dry_run 参数，且本次**显式**传了 True。

        **为什么预览不该走确认门**：dry_run 的语义就是「零副作用地看一眼」，而
        「先预览、看清楚、再决定要不要真干」恰恰是**最安全**的工作流 —— 可它此前
        必须先过确认门才能看到预览，顺序是反的。结果在非交互环境（脚本 / CI）里，
        预览和真删被一视同仁地拒掉（2026-09-12 四组场景验证实测：退出码 3）。

        判定三条（缺一不可）—— **具体逻辑只有一份，在 `is_pure_preview()`**，
        这里只负责把指令拆开递过去：
          ① 该原语的 schema **真的**声明了 dry_run 参数。只看参数不看名单是不行的：
             `escape` 这类没有 dry_run 的原语，调用方随手塞个 `"dry_run": true` 就会被
             误放行 —— 那是「碰巧安全」（多传的参数会被原语拒掉），不能靠这个。
          ② `args["dry_run"] is True` —— **显式**传 True 才算。传 False 照常走确认门；
             压根不传也照常走 —— 虽然原语默认就是 True（README 的三道门之一），
             但「没写」属于意图不清，不替调用方做主。
          ③ 没有踩中该原语声明的「预览例外参数」—— 即 dry_run 分支**本身有副作用**的
             那些参数（如 `net.download` 的 probe）。
        """
        if instr.op != OpCode.CALL.value or not instr.tool:
            return False
        return is_pure_preview(instr.tool, instr.args,
                               self.dry_run_primitives, self.preview_exempt)

    def needs_confirmation(self, instr: Instruction) -> bool:
        """这条指令是否属于「必须先问用户」的类别 —— 与「用户答没答应」无关。

        单独开这个口子，是因为 `confirm()` 的 True 有**两种**含义：
          ① 规则要求确认，且用户点了同意；
          ② 规则压根不要求确认（没问过任何人）。
        执行门那边 `confirmed=True` 的语义只有 ① ——「上游已经问过用户了」。
        把 ② 也当成 ① 传下去，就等于替用户点头。见 `_exec_instruction` 的注释。

        **只读预览（dry_run=True）不算「需要确认」** —— 它一个字节的状态都不改，
        没有可确认的对象。见 `is_preview()`。
        """
        if not self._resolve_rule(instr).requires_confirmation:
            return False
        return not self.is_preview(instr)

    async def confirm(self, instr: Instruction) -> bool:
        # 走 needs_confirmation 而不是自己查规则 —— 那边已经把「只读预览」排除掉了
        # （dry_run=True 的调用没有可确认的对象，问了也是白问）
        if not self.needs_confirmation(instr):
            return True
        # 交互可用性双重判断：isatty 可能误判（管道/被占用），EOF 兜底再判一次
        interactive = bool(sys.stdin) and sys.stdin.isatty()
        if not interactive:
            # 非交互环境：由 allow_headless 配置决定放行与否 (默认拒绝，安全优先)
            if self.allow_headless:
                print(f"\nℹ️  [PolicyGate] 非交互环境自动放行: {instr.op}/{instr.tool}",
                      file=sys.stderr)
                return True
            print(f"\n⚠️  [PolicyGate] 高危操作 {instr.op}/{instr.tool} 在非交互环境被拒绝 (设 allow_headless=True 可放行)",
                  file=sys.stderr)
            return False
        print(f"[PolicyGate]{render_confirmation(instr.tool or instr.op, instr.args)}",
              file=sys.stderr)
        try:
            print("   允许执行? [y/N]: ", end="", file=sys.stderr, flush=True)
            ans = input().strip().lower()
        except (EOFError, OSError):
            # 输入流读到 EOF（管道/被关闭）：isatty 误判的兜底——按 allow_headless 决定
            if self.allow_headless:
                print(f"ℹ️  [PolicyGate] 交互输入不可用 (EOF)，按 allow_headless 自动放行",
                      file=sys.stderr)
                return True
            print(f"⚠️  [PolicyGate] 交互输入不可用 (EOF)，高危操作被拒绝", file=sys.stderr)
            return False
        return ans == "y"

    async def confirm_many(self, instrs: list[Instruction], describe=None) -> bool:
        """**一次问一批**：把整批「会改状态」的动作一次列清楚，用户点一次头。

        为什么要有它（2026-09-12）：一段计划里常常有好几个要确认的动作，逐条问会把用户
        问烦 —— 而「一次交一批活」恰恰是这套系统的卖点。让用户**一次看清这批要发生什么**，
        比让他被弹五六次更接近「知情的同意」。

        ⚠️ **必须由内核来问、内核来记账**：集成功能 / 接入方都不许自己列清单、自己标记
        「用户已同意」—— 那等于替用户点头（同 `_exec_instruction` 里记的那个洞）。

        describe: 接入方给的「原语名 → 说明」查询函数。用户看不懂 `fs.delete` 这种名字，
        但看得懂「删除文件/目录」。
        """
        lines = ["", f"⚠️  这批活里有 {len(instrs)} 件会改变系统状态，请一次看清："]
        for n, instr in enumerate(instrs, 1):
            lines.append("")
            lines.append(f"  【{n}】{instr.tool or instr.op}")
            if describe is not None:
                try:
                    d = describe(instr.tool or instr.op)
                except Exception:
                    d = ""
                first = re.split(r"[。；;\n]", (d or "").strip())[0].strip()
                if first:
                    lines.append(f"       作用：{first}")
            if instr.args:
                lines.append("       参数：")
                for k, v in instr.args.items():
                    lines.append(f"         {k} = {v}")
        print("\n".join(lines), file=sys.stderr)
        # 交互判断与 confirm() 一致：isatty 会误判，EOF 再兜一次
        interactive = bool(sys.stdin) and sys.stdin.isatty()
        if not interactive:
            if self.allow_headless:
                print(f"ℹ️  [PolicyGate] 非交互环境自动放行这一批（{len(instrs)} 件）",
                      file=sys.stderr)
                return True
            print(f"⚠️  [PolicyGate] 非交互环境下这批操作被拒绝（设 allow_headless=True 可放行）",
                  file=sys.stderr)
            return False
        try:
            print(f"   允许执行这 {len(instrs)} 件? [y/N]: ", end="",
                  file=sys.stderr, flush=True)
            ans = input().strip().lower()
        except (EOFError, OSError):
            if self.allow_headless:
                print("ℹ️  [PolicyGate] 交互输入不可用 (EOF)，按 allow_headless 自动放行",
                      file=sys.stderr)
                return True
            print("⚠️  [PolicyGate] 交互输入不可用 (EOF)，这批操作被拒绝", file=sys.stderr)
            return False
        return ans == "y"


# ============================================================================
# 4. 工具注册表
# ============================================================================

ToolFunc = Callable[..., Any]


class ToolRegistry:
    """工具注册表：每个工具 = 确定性本地函数 + schema 描述。"""

    def __init__(self):
        self._tools: dict[str, dict] = {}
        # LLM 侧名字 → 真实工具名的别名表。
        # 起因：OS 原语名带点（system.info / process.kill），而 DeepSeek API 对
        # function.name 有正则约束 ^[a-zA-Z0-9_-]+$，点号会被 400 拒收。
        # 所以「发给 LLM 用下划线、执行前还原成点号」。
        self._aliases: dict[str, str] = {}
        # 执行门：由工厂装配时注入（见 factory.ExecutionGate / install_execution_gate）。
        # 装上去之后，**任何**直接调 execute() 的地方都得先过这道门 ——
        # 不只是 IR 解释器那条路（面板 /run、脚本直调，以前都是裸奔的）。
        self.gate: Optional[Callable[..., tuple[bool, str]]] = None

    @staticmethod
    def sanitize_name(name: str) -> str:
        """真实工具名 → 可发给 LLM 的安全名字（点号换下划线）。"""
        return name.replace(".", "_")

    def tool(self, name: str, description: str, schema: dict, source: str = "native"):
        """注册工具。source: native(通用原语) / agent(agent自有) / plugin(插件)。

        同名冲突：agent 自有工具优先——若已存在且来源非 agent、本次是 agent → 覆盖，
        否则保留已有（先来先到）。这实现「中间层内核不动、外设按 agent 优先」的适配。
        """
        def decorator(fn: ToolFunc):
            existing = self._tools.get(name)
            if existing is None or (existing.get("source") != "agent" and source == "agent"):
                self._tools[name] = {"description": description, "schema": schema,
                                     "fn": fn, "source": source}
                self._aliases[self.sanitize_name(name)] = name
            return fn
        return decorator

    def resolve_name(self, name: str) -> str:
        """LLM 侧名字 → 真实工具名。已是真名则原样返回（宽容，两种写法都认）。"""
        if name in self._tools:
            return name
        return self._aliases.get(name, name)

    def list_tools(self) -> dict[str, dict]:
        """列出已注册的工具（名字 → description / schema / source），供接入方取用。

        **只给「有哪些能力」，不给实现函数** —— 调用方要清单（做手册、做面板、转成自己的
        工具格式）时用这个，别去翻 `_tools` 私有字段。至于「怎么转成某家 LLM 的格式」，
        那是接入方自己的事：中间层不预设任何 LLM。
        """
        return {n: {"description": t["description"], "schema": t["schema"],
                    "source": t["source"]} for n, t in self._tools.items()}

    def has(self, name: str) -> bool:
        return self.resolve_name(name) in self._tools

    def describe(self, name: str) -> str:
        """拿一个工具的说明文字（确认界面用 —— 用户看不懂 `fs.delete`，但看得懂「删除文件/目录」）。"""
        t = self._tools.get(self.resolve_name(name))
        return t["description"] if t else ""

    def execute(self, name: str, args: dict, confirmed: bool = False) -> Any:
        """执行工具。confirmed=True 表示上游已经问过用户了（IR 路径），执行门不再重复问。

        **这里是调用日志的唯一挂载点**（见 `core/journal.py`）：IR / CLI / 面板 / 直调
        全都经过这一个方法，所以一处挂钩就覆盖全库 —— 97 条原语一条都不用改。
        ⚠️ 但**直抓函数对象调用绕不过去**（测试脚本、或将来图省事的适配器）：
        这是「尽力而为」不是「不可绕过」，跟执行门是同一个性质。
        """
        real = self.resolve_name(name)
        if real not in self._tools:
            raise ValueError(f"未知工具: {name}")
        if self.gate is not None:                 # 执行门：装了才检查（默认不装，保持兼容）
            ok, msg = self.gate(real, args, confirmed=confirmed)
            if not ok:
                # 「想干、但没让干」是事后追查最要紧的一条 —— **先记再拒**
                journal.record(real, args, ok=False, denied=True, note=msg)
                raise PermissionError(msg)
        t0 = time.perf_counter()
        try:
            result = self._tools[real]["fn"](**args)
        except Exception as e:
            # 抛异常也算「发生过一次调用」—— 失败原因正是排障时要看的
            journal.record(real, args, ok=False, error=e,
                           elapsed_ms=(time.perf_counter() - t0) * 1000)
            raise
        # ok 以**原语自己报的**为准（它才是「这件事办成了吗」的权威）；
        # 没返回 ok 字段的老原语算成功，不替它编一个失败。
        done = result.get("ok", True) if isinstance(result, dict) else True
        journal.record(real, args, ok=bool(done),
                       elapsed_ms=(time.perf_counter() - t0) * 1000)
        return result


# ============================================================================
# 5. 语义解释器 (核心)
# ============================================================================

class SemanticInterpreter:
    """
    本地确定性执行引擎 (运行在 CPU 上)：
    - 静态校验 IR (不依赖 LLM)
    - 构建依赖 DAG，并行调度无依赖指令
    - 通过 Policy Gate 后才执行
    - 管理 Workspace 寄存器
    """

    def __init__(self, registry: ToolRegistry, policy: PolicyGate, workspace: Workspace,
                 asker: Optional[Callable[[str], Optional[str]]] = None):
        self.registry = registry
        self.policy = policy
        self.workspace = workspace
        # asker：接入方提供的「向用户提问」回调，签名 (问题) -> 回答文本（None = 没问到）。
        # 跟执行门的 confirmer 一个道理 —— 「怎么问用户」**不能写死成读终端**：
        # 有的读终端、有的发 IM 消息、CI 环境则直接返回 None。
        self.asker = asker

    @staticmethod
    def _collect_refs(value: Any) -> list[str]:
        """递归挑出参数里的 `$寄存器` 引用，返回**寄存器名**（点号后是取字段，不算名字）。

        判定口径与 `Workspace.resolve` 保持一致：**只有以 `$` 开头的字符串**才算引用。
        """
        out: list[str] = []
        if isinstance(value, str):
            if value.startswith("$"):
                out.append(value[1:].split(".")[0])
        elif isinstance(value, dict):
            for v in value.values():
                out.extend(SemanticInterpreter._collect_refs(v))
        elif isinstance(value, list):
            for v in value:
                out.extend(SemanticInterpreter._collect_refs(v))
        return out

    def validate(self, program: IRProgram) -> list[str]:
        """静态分析：非法 op / 未定义依赖 / 未知工具 / 未定义的 `$引用`。"""
        errors: list[str] = []
        defined: set[str] = set()
        valid_ops = {o.value for o in OpCode}
        for i, instr in enumerate(program.instructions):
            # 校验 op
            if instr.op not in valid_ops:
                errors.append(f"指令[{i}] 非法操作码: {instr.op}")
            # CALL 必须指定 tool
            if instr.op == OpCode.CALL.value and not instr.tool:
                errors.append(f"指令[{i}] op=call 但未指定 tool 字段")
            if instr.op == OpCode.CALL.value and instr.tool and not self.registry.has(instr.tool):
                errors.append(f"指令[{i}] 未知工具: {instr.tool}")
            # 依赖是否已定义
            for dep in instr.depends_on:
                if dep not in defined:
                    errors.append(f"指令[{i}] 依赖 '{dep}' 未定义")
            # 参数里的 $引用是否已定义 —— 拼错寄存器名是编排里**最常见**的错误，
            # 而它此前没有任何校验：会一路静默传 None 进原语（2026-09-12 实测：最终报的是
            # 「PID 不是数字：None」，把人往错的方向引）。跟 depends_on 一样，执行前拦下。
            for ref in self._collect_refs(instr.args):
                if ref not in defined:
                    errors.append(f"指令[{i}] 引用了未定义的寄存器: ${ref}")
            if instr.out:
                defined.add(instr.out)
        return errors

    def _resolve_args(self, instr: Instruction) -> dict:
        resolved = self.workspace.resolve(instr.args)
        return resolved if isinstance(resolved, dict) else {}

    async def _confirm_batch(self, instructions: list[Instruction]) -> None:
        """执行前，把整批「要动东西」的指令**一次问清**。

        **为什么放在这一层**（而不是让集成功能自己列清单）：确认必须由内核把关 ——
        调用方自己列清单、自己记「用户同意了」，就等于替用户点头（跟 `_exec_instruction`
        里记的那个洞是同一类问题）。

        只问真正需要确认的那些，只读的连问都不问。**用户拒绝时不整段中止**：
        被拒的那些在 `_exec_instruction` 里各自抛错，只读的部分照常执行 ——
        这比「一个不批就全不干」更接近用户的真实意图。
        """
        need = [ins for ins in instructions
                if ins.op == OpCode.CALL.value and self.policy.needs_confirmation(ins)]
        if not need:
            return
        if len(need) == 1:
            ok = await self.policy.confirm(need[0])
        else:
            ok = await self.policy.confirm_many(need, describe=self.registry.describe)
        for ins in need:
            ins.approved = bool(ok)

    async def _exec_instruction(self, instr: Instruction) -> Any:
        # 1. 安全校验
        ok, msg = self.policy.check(instr)
        if not ok:
            raise PermissionError(msg)
        # ⚠️ **先记下「这条本来需不需要确认」**，它决定下一步敢不敢跳过执行门。
        # confirm() 返回 True 有两种含义：问过且同意 / 压根不需要问。只有前者才算
        # 「上游已确认」。2026-09-11 实测到的洞：调用方装配解释器时若忘了调
        # factory.build_policy_gate()，PolicyGate 就只剩 op 级默认规则，
        # 于是 fs.delete 这类原语**没人问**，却带着 confirmed=True 传给执行门 →
        # 门一句「上游已确认」放行 → 高危原语被静默执行。
        needs_confirm = self.policy.needs_confirmation(instr)
        # 确认已在 run() 开头的 _confirm_batch() 里**成批问过**了，这里只查结果 ——
        # 不再逐条弹（一段计划里五六个要确认的动作，逐条弹会把用户问烦）。
        if needs_confirm and not instr.approved:
            raise PermissionError(f"用户拒绝执行 {instr.tool or instr.op}（或在批量确认里未获批准）")

        args = self._resolve_args(instr)

        # 2. 分发执行
        if instr.op == OpCode.CALL.value:
            # 只有**真问过用户**的才告诉执行门「别重复问」；没问过的传 False，
            # 让执行门自己按 确认器 → 终端 → fail-closed 的顺序把关。
            #
            # ⚠️ 丢进**线程池**执行，不要直接调 —— 原生原语都是同步函数（ctypes 直调系统
            # API），直接调一个同步函数，asyncio.gather 只能把同层的几条排到同一个事件循环
            # 上**排队**，一条阻塞就把循环占住。2026-09-12 实测：同层两条各 1000ms 的调用
            # 耗时 2298ms —— 是相加，不是取最大，README 说的「并行」当时是假的。
            # ctypes 调用会释放 GIL，所以放线程池里是**真并行**；安全性也实测过
            # （8 线程 960 次调用零失败，吞吐约 4 倍），见 thread-safety 验证。
            result = await asyncio.to_thread(
                self.registry.execute, instr.tool, args, needs_confirm)  # type: ignore
            # 接入方的工具可能是 async：结果可能是 awaitable，需 await（M1.2 适配）
            if inspect.isawaitable(result):
                result = await result
        elif instr.op == OpCode.ASK.value:
            result = {"question": args.get("question"),
                      "answered": self._ask(args.get("question", ""))}
        elif instr.op == OpCode.FINISH.value:
            result = {"status": "finished"}
        else:
            # 走到这里只会是 finish 之外、校验漏网的操作码 —— validate() 已经拦过一遍
            result = args

        # 3. 写入寄存器
        if instr.out:
            self.workspace.write(instr.out, result)
        return result

    def _ask(self, question: str) -> Optional[str]:
        """向用户提问并把回答带回来。三条路，优先级从高到低：

        ① 接入方的 asker —— 读终端 / 发 IM 消息 / 等网页点击，由接入方自己定
        ② 没 asker 但人在终端前 —— 自己问
        ③ 谁都问不到 —— 返回 None（由调用方决定：是当失败中止，还是带着「没问到」继续）
        """
        if self.asker is not None:
            try:
                return self.asker(question)
            except Exception:
                return None
        if sys.stdin and sys.stdin.isatty():
            print(f"\n❓ {question}", file=sys.stderr)   # 提问也走 stderr，理由同确认框
            try:
                return input("   > ").strip() or None
            except (EOFError, OSError):
                return None
        return None

    async def run(self, program: IRProgram) -> dict:
        # 空计划：没生成任何操作，视为未完成（修复时若退回空 IR 不该当"成功"）
        if not program.instructions:
            return {"ok": False, "errors": ["IR 计划为空——未生成任何操作，视为未完成"]}
        # 名字还原：LLM 侧是下划线（system_info），执行侧要真名（system.info）。
        # 在入口统一还原，校验 / 策略 / 执行三处看到的都是真名，避免规则失效。
        for instr in program.instructions:
            if instr.tool:
                instr.tool = self.registry.resolve_name(instr.tool)
        errors = self.validate(program)
        if errors:
            return {"ok": False, "errors": errors}

        # 安全闸门：执行前把整批要确认的**一次问清**（不再逐条弹，见 _confirm_batch）
        await self._confirm_batch(program.instructions)

        layers = self._topological_layers(program.instructions)
        all_results: dict = {}
        denied: list[str] = []          # 被安全门拦下的，与「执行出错」分开记
        for layer in layers:
            tasks = [self._exec_instruction(instr) for instr in layer]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for instr, res in zip(layer, results):
                key = instr.out or f"{instr.op}:{instr.tool or ''}"
                if isinstance(res, PermissionError):
                    # ⚠️ 「被安全门拦下」**不是**「执行失败」，必须让顶层看得见。
                    # 2026-09-12 实测过的洞：这里原先把 PermissionError 和普通异常一起塞进
                    # `{"error": ...}`，run() 又没有「有指令被拦」这个概念，于是整批返回
                    # `ok: true` + CLI 退出码 0 —— 脚本拿到的是一份**看起来一切正常**的
                    # 半个结果。比混成「失败」更危险：失败会让人去查，成功不会。
                    name = instr.tool or instr.op
                    denied.append(name)
                    all_results[key] = {"denied": str(res)}
                elif isinstance(res, Exception):
                    all_results[key] = {"error": str(res)}
                else:
                    all_results[key] = res
        out: dict = {"ok": not denied, "results": all_results,
                     "workspace": self.workspace.snapshot()}
        if denied:
            # 被拒的不影响只读的照常执行（这是有意的，更接近用户真实意图）——
            # 但这件事必须**在顶层可见**，不能让调用方自己去翻每一条结果。
            out["denied"] = denied
            out["note"] = (f"有 {len(denied)} 条被安全门拦下（{', '.join(denied)}）；"
                           f"只读的部分照常执行，结果在上面的 results 里")
        return out

    def _topological_layers(self, instructions: list[Instruction]) -> list[list[Instruction]]:
        """拓扑分层：同层无依赖 → 并行执行，减少总耗时。"""
        remaining = list(instructions)
        layers: list[list[Instruction]] = []
        defined: set[str] = set()
        while remaining:
            layer = [instr for instr in remaining
                     if all(d in defined for d in instr.depends_on)]
            if not layer:  # 循环依赖兜底：串行
                layer = [remaining[0]]
            for instr in layer:
                if instr.out:
                    defined.add(instr.out)
            layers.append(layer)
            remaining = [instr for instr in remaining if instr not in layer]
        return layers


# ============================================================================
# 6. 演示 —— 「中间层被调用」长什么样
# ============================================================================

async def main():
    """演示「中间层被调用」是什么样。

    注意这里**没有 LLM、没有 API Key、没有 while 循环** —— IntentOS 是工具，
    IR 由调用方生成，这里手工写一段来演示。真实接入时，这段 IR 由调用方的 Agent 产出。
    """
    from pathlib import Path

    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in sys.path:   # 直接跑本文件时，sys.path[0] 是 core/ 而不是项目根
        sys.path.insert(0, str(_ROOT))
    from core import factory         # 延迟 import：factory 反向依赖本模块，顶层 import 会成环

    factory.load_primitives(str(_ROOT / "primitives"))   # 加载完会自动装上执行门
    registry = factory.registry
    interpreter = SemanticInterpreter(
        registry, factory.build_policy_gate(allow_headless=True), Workspace())

    print("=" * 70)
    print("演示 1: 一次 IR 干三件事 —— 三条只读原语无依赖 → 并行执行")
    print("=" * 70)
    program = IRProgram(instructions=[
        Instruction(op="call", tool="system.info", args={}, out="sys", depends_on=[]),
        Instruction(op="call", tool="disk.list", args={}, out="disks", depends_on=[]),
        Instruction(op="call", tool="service.list",
                    args={"state": "running", "limit": 3}, out="svc", depends_on=[]),
        Instruction(op="finish", args={}, depends_on=["sys", "disks", "svc"]),
    ])
    result = await interpreter.run(program)
    ws = result.get("workspace", {})
    print(f"\n✅ ok={result['ok']}   结果都落在寄存器里: {list(ws)}")
    s = ws.get("sys", {})
    print(f"   system.info  → {s.get('platform')} {s.get('machine')} · "
          f"内存 {s.get('total_mb')}MB 总 / {s.get('avail_mb')}MB 可用")
    print(f"   service.list → 运行中 {len(ws.get('svc', {}).get('services', []))} 条")
    print(f"   disk.list    → {str(ws.get('disks'))[:110]}")

    print("\n" + "=" * 70)
    print("演示 2: 静态校验 —— 引用未定义的寄存器，执行前就拦下（不烧任何调用）")
    print("=" * 70)
    bad = IRProgram(instructions=[
        Instruction(op="call", tool="system.info", args={}, depends_on=["never_defined"]),
    ])
    print(f"\n🚫 {await interpreter.run(bad)}")

    print("\n" + "=" * 70)
    print("演示 3: 执行门 —— 只读的放行；需确认的原语在「无人可问」时被拦住")
    print("=" * 70)
    try:
        registry.execute("fs.delete", {"path": "D:/这个目录不存在"})
        print("   !! 没拦住")
    except PermissionError as e:
        print(f"   ✅ 拦住：{e}")


if __name__ == "__main__":
    asyncio.run(main())
