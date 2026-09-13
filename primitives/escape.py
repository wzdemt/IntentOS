"""逃生舱原语 —— 册子上没有的操作，走这里（escape）。

**它在整个体系里的位置**：IntentOS 的安全来自「能力有限」——原语库就是那份册子。
但册子覆盖不到的需求总会出现。不给出口，用户只会绕开 IntentOS 自己去敲命令，
那样反而**彻底失去可见性**。所以留一扇**有门卫的门**，而不是让人自己在围栏上开洞。

**两道约束（缺一不可）**：
  1. `requires_confirmation=True` → 每次执行都必须用户点头（过执行门 / Policy Gate）
  2. 系统提示里写明它是**最后手段** —— 先用 call 找原语，确实没有才用它

**比原来的 `exec` 操作码强在哪**：
  · 跑在**独立子进程**里 —— 原来的 exec 是在同一个 Python 进程里 `exec()`，
    代码能把整个中间层的内存、注册表、工具全摸一遍；独立进程把这条断了
  · 强制超时
  · 返回结构化的 stdout / stderr / returncode，不是一段要人猜的文本

> 📅 2026-09-11 建立，替代 `core/interpreter.py` 里的 exec 沙箱（见 docs/archive/refactor-proposal.md）

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_escape，注册进 factory.registry）。
"""
from __future__ import annotations

import subprocess
import sys

from core.factory import declare_primitive  # type: ignore

# stdout / stderr 的返回上限 —— 超了就截断，而且**必须把「截了」说出来**（见返回值里的
# stdout_truncated）。2026-09-12 审计抓到：这里是全库唯一「截断了却一声不吭」的地方
# （archive.list / registry.read / net.http_get 都有 truncated 标记，只有它没有）。
_STDOUT_CAP, _STDERR_CAP = 8000, 4000


@declare_primitive(
    "escape",
    "逃生舱 —— 执行原语册子上**没有**的操作（kind=python 跑一段 Python 代码；"
    "kind=shell 跑一条系统命令）。"
    "⚠️ **这是最后手段，不是通用 shell**：正常需求请先走原语（先在你的工具表里把原语找一遍）—— "
    "原语带参数校验、dry_run 预览、路径与禁区判定和审计，逃生舱**一样都没有**，"
    "它只是把代码 / 命令原样交给系统去跑。"
    "**什么时候才该用它（三个条件同时满足）**：① 已经找过一遍原语，"
    "确认确实没有对应能力；② 这件事必须靠一段自定义代码 / 一条外部命令才能完成"
    "（例如要调一个本库没有原语的命令行工具）；③ 用户知道要跑什么并点了头。"
    "只因为「这样写更省事」**不构成理由** —— 能走原语就走原语。每次执行都需要用户确认。"
    "参数怎么填：kind 必填（python / shell）；kind=python 必须提供 code（整段 Python 代码写在一个"
    "字符串里）；kind=shell 必须提供 command（完整命令行，含参数）；"
    "timeout 是**秒**，默认 30，上限 300，超时会被强制终止。"
    "返回什么：ok / kind / returncode / stdout / stderr / stdout_chars / stderr_chars / "
    "stdout_truncated / stderr_truncated / note。"
    "⚠️ ok 只表示**这条命令跑通了（returncode == 0）**，**不代表业务目标达成** —— "
    "结果对不对要看 stdout。"
    "⚠️ **输出有上限**：stdout 最多给 8000 字符、stderr 最多给 4000 —— "
    "返回的 stdout_truncated / stderr_truncated 为 true **就表示内容被砍过**，"
    "此时别把拿到的内容当成全部；stdout_chars / stderr_chars 是**未截断前的真实字符数**，"
    "拿它判断命令到底输出了多少。要完整输出就让它先写进文件，再用 fs.read 读那个文件。"
    "⚠️ 陷阱：① **kind=shell 走的是 Windows 的 cmd.exe，不是 Git Bash / PowerShell** —— "
    "能用的是 cmd 自带的命令（`dir` / `type` / `del` / `findstr` / `where` 等）；"
    "`ls` / `cat` / `rm` / `grep` 这类 **Unix 命令 cmd 本身没有**，只有在 PATH 上恰好装了 "
    "Git 的 `usr\\bin` 或类似工具时才会被找到（开发机上常见，但**不能假设**）—— "
    "要稳妥请用 cmd 的命令；要跑 PowerShell 就把整条命令写成 `powershell -Command \"...\"`。"
    "② kind=python 跑在**独立子进程**里（不是当前进程）：它改的 os.environ、装的包、"
    "切换的工作目录，本进程都看不到 —— 要真正改环境变量或系统配置，请用对应的原语，别指望它。"
    "③ 命令的工作目录就是当前进程的目录，路径请写绝对路径。",
    {"type": "object",
     "properties": {
         "kind": {"type": "string", "enum": ["python", "shell"],
                  "description": "python=执行一段 Python 代码；shell=执行一条系统命令"
                                 "（Windows 下走 cmd.exe，不是 Git Bash）"},
         "code": {"type": "string", "description": "kind=python 时必填：要执行的 Python 代码"},
         "command": {"type": "string", "description": "kind=shell 时必填：要执行的完整命令行"},
         "timeout": {"type": "integer", "minimum": 1, "maximum": 300,
                     "description": "超时秒数，默认 30，上限 300（超出会被截到边界）"},
     },
     "required": ["kind"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="escape",
)
def escape(kind: str, code: str = "", command: str = "", timeout: int = 30) -> dict:
    kind = (kind or "").strip().lower()
    if kind not in ("python", "shell"):
        return {"ok": False, "kind": kind, "note": f"未知 kind={kind!r}；可选 python / shell"}
    try:
        timeout = max(1, min(int(timeout), 300))
    except (TypeError, ValueError):
        timeout = 30

    if kind == "python":
        if not (code or "").strip():
            return {"ok": False, "kind": kind, "note": "kind=python 时必须提供 code"}
        argv: object = [sys.executable, "-c", code]      # 独立解释器进程，不污染本进程
    else:
        if not (command or "").strip():
            return {"ok": False, "kind": kind, "note": "kind=shell 时必须提供 command"}
        argv = command                                   # 完整命令字符串（09-11 定）

    try:
        r = subprocess.run(argv, shell=(kind == "shell"), capture_output=True,
                           timeout=timeout, text=True, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "kind": kind, "timeout": timeout,
                "note": f"执行超时（{timeout}s），已终止"}
    except Exception as e:
        return {"ok": False, "kind": kind, "note": f"执行失败：{e}"}

    so, se = r.stdout or "", r.stderr or ""
    so_cut, se_cut = len(so) > _STDOUT_CAP, len(se) > _STDERR_CAP
    note = "执行完成" if r.returncode == 0 else f"命令返回非零（{r.returncode}）"
    if so_cut or se_cut:
        # 截断了就**说出来**：不说的话调用方会拿半截输出当全部，据此下的结论全是错的
        bits = []
        if so_cut:
            bits.append(f"stdout 实际 {len(so)} 字符，只返回了前 {_STDOUT_CAP}")
        if se_cut:
            bits.append(f"stderr 实际 {len(se)} 字符，只返回了前 {_STDERR_CAP}")
        note += "；⚠️ 输出被截断（" + "；".join(bits) + "）—— 要全文请让它写进文件再读"
    return {"ok": r.returncode == 0,
            "kind": kind,
            "returncode": r.returncode,
            "stdout": so[:_STDOUT_CAP],
            "stderr": se[:_STDERR_CAP],
            "stdout_chars": len(so),
            "stderr_chars": len(se),
            "stdout_truncated": so_cut,
            "stderr_truncated": se_cut,
            "note": note}
