#!/usr/bin/env python
"""IntentOS 命令行入口 —— 让脚本、命令行、Agent 用同一套原语。

用法：
    python adapters/cli.py list [域]                    # 册子里有什么
    python adapters/cli.py describe <原语>               # 一条原语怎么调
    python adapters/cli.py call <原语> [--args JSON]     # 调一条
    python adapters/cli.py run <ir.json 或 ->            # 跑一段 IR（一次交一批）
    python adapters/cli.py blocks [块]                   # 工具分块：块目录 / 展开一块
                                                         # （--text 输出可读文本）
    python adapters/cli.py journal [--limit N]           # 调用日志：刚才做过什么
                                                         # （只读，--text 给模型读的格式）

**输出契约（给脚本用，别破坏）**：
    · **stdout 只放结果 JSON** —— 可直接接 `jq`，不用剥任何前缀
    · 错误与提示一律走 **stderr**
    · 退出码：`0` 成功 / `1` 执行失败 / `2` 用法错误 / **`3` 被安全门拒绝**

退出码 `3` 单独拎出来的意义：脚本必须分得清「**没查到**」和「**被拦住**」——
把两者混成同一个「失败」，正是那些「检查脚本坏了却报一切正常」的病根。

**安全**：一律走 `registry.execute()` —— 跟 Agent 走的是**同一道执行门**，
这里不另开小门。需确认的原语在无人可问时会被拒绝（退出码 3），那是设计不是 bug。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from core import factory                          # type: ignore
from core.interpreter import (                    # type: ignore
    IRProgram,
    Instruction,
    SemanticInterpreter,
    Workspace,
)

PRIMITIVES_DIR = _BASE / "primitives"

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_DENIED = 0, 1, 2, 3


def _die(code: int, msg: str) -> None:
    print(f"[intentos] {msg}", file=sys.stderr)
    raise SystemExit(code)


def _emit(obj, pretty: bool) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None))


def _registry():
    """加载原语并取注册表 —— load_primitives 内部会自动装上执行门。"""
    factory.load_primitives(str(PRIMITIVES_DIR))
    return factory.registry


def _needs_confirm(name: str) -> bool:
    return bool(factory.POLICY.get(name, {}).get("requires_confirmation"))


def cmd_list(a) -> int:
    tools = _registry().list_tools()
    if a.domain:
        tools = {n: t for n, t in tools.items() if n.split(".")[0] == a.domain}
        if not tools:
            _die(EXIT_USAGE, f"没有 {a.domain!r} 这个域（不带参数可看全部）")
    domains: dict[str, list] = {}
    for name in sorted(tools):
        dom = name.split(".")[0] if "." in name else "(无域)"
        domains.setdefault(dom, []).append({
            "name": name,
            "description": tools[name]["description"],
            "requires_confirmation": _needs_confirm(name),
        })
    _emit({"count": len(tools), "domains": domains}, a.pretty)
    return EXIT_OK


def cmd_describe(a) -> int:
    reg = _registry()
    name = reg.resolve_name(a.tool)
    t = reg.list_tools().get(name)
    if t is None:
        _die(EXIT_USAGE, f"册子里没有 {a.tool!r}（用 list 看看有什么）")
    _emit({"name": name, "description": t["description"], "schema": t["schema"],
           "source": t["source"], "requires_confirmation": _needs_confirm(name)},
          a.pretty)
    return EXIT_OK


def cmd_call(a) -> int:
    # 三种传参方式。**为什么要有 args-file / stdin 这两条**：
    # 参数写在命令行里，它就会出现在**调用方自己的命令行**中 —— 查进程时
    # （process.find）会把「正在执行这次查询的 shell」也一并搜出来，因为那个 shell
    # 的命令行里带着查询词。参数从文件或 stdin 进来，查询词就不在命令行里了。
    if a.args_file:
        p = Path(a.args_file)
        if not p.exists():
            _die(EXIT_USAGE, f"参数文件不存在：{a.args_file}")
        raw = p.read_text(encoding="utf-8")
    elif a.args == "-":
        raw = sys.stdin.read()
    elif a.args is None:
        raw = ""
    else:
        raw = a.args

    if not raw.strip():
        params = {}
    else:
        try:
            params = json.loads(raw)
        except ValueError as e:
            _die(EXIT_USAGE, f"参数不是合法 JSON：{e}")
        if not isinstance(params, dict):
            _die(EXIT_USAGE, '参数必须是 JSON 对象，例如 --args \'{"limit": 5}\'')

    reg = _registry()
    if not reg.has(a.tool):
        _die(EXIT_USAGE, f"册子里没有 {a.tool!r}（用 list 看看有什么）")
    try:
        result = reg.execute(a.tool, params)
    except PermissionError as e:
        _die(EXIT_DENIED, f"{e}")                      # ← 被安全门拦住，脚本按 3 处理
    except TypeError as e:
        _die(EXIT_USAGE, f"参数不对：{e}（用 describe {a.tool} 看要哪些参数）")
    except Exception as e:
        _die(EXIT_FAIL, f"执行 {a.tool} 失败：{e}")
    _emit(result, a.pretty)
    return EXIT_OK


def cmd_blocks(a) -> int:
    """工具分块 —— 97 条原语按「操作对象」归成 13 块，按需展开（见 core/blocks.py）。

    不给块名 = 块目录（接入方该常驻的那份清单，约 1K tokens）；
    给块名 = 该块下所有原语的完整说明与 schema。
    `--text` 把块目录渲染成可读文本（参考格式，接入方也可自己写渲染）。
    """
    _registry()                            # 必须先加载 —— 块表是加载时填的
    from core import blocks as blockmod    # type: ignore

    if a.block:
        out = blockmod.export_block(a.block)
    elif a.text:
        # 仍然包在 JSON 里：stdout「只放结果 JSON」这条契约不破，
        # 接入方 `jq -r .catalog` 就能拿到文本。
        # 默认连「通用约定」一起给 —— 那才是接入方该常驻的完整一份。
        out = {"catalog": blockmod.render_catalog()}
    else:
        cats = blockmod.export_catalog()
        out = {"count": len(cats), "blocks": cats,
               "conventions": blockmod.export_conventions()}
    _emit(out, a.pretty)
    return EXIT_OK


def cmd_journal(a) -> int:
    """调用日志 —— 看「刚才做过什么」，默认最新在前。

    **不是原语**：它是中间层自己的记录，不是 OS 能力（见 core/journal.py）。
    日志按天切在 `logs/journal-*.jsonl`，不记返回结果（第一读者是模型，不是审计）。
    `--text` 给一份渲染好的紧凑文本（参考格式，接入方可自己写渲染）。
    """
    from core import journal    # type: ignore

    recs = journal.recent(limit=a.limit, since=a.since or "",
                          name=a.name or "", denied_only=a.denied)
    if a.text:
        out = {"count": len(recs), "text": journal.render(recs)}
    else:
        out = {"count": len(recs), "records": recs}
    _emit(out, a.pretty)
    return EXIT_OK


def cmd_skill(a) -> int:
    """跑一个任务级 skill —— 把几条原语交叉成「一件事的完整答案」。

    不带名字就列出有哪些；带名字则跑它，参数走 --args / --args-file（与 call 一致）。
    skill 与原语是两层：原语进 registry、算原子操作；skill 不进 registry、算组合能力。
    """
    import importlib

    if not a.name:
        found = sorted(p.stem for p in (_BASE / "skills").glob("*.py")
                       if not p.stem.startswith("_"))
        _emit({"count": len(found), "skills": found,
               "usage": "python adapters/cli.py skill <名字> --args '{\"limit\": 30}'"},
              a.pretty)
        return EXIT_OK

    try:
        mod = importlib.import_module(f"skills.{a.name}")
    except Exception as e:
        _die(EXIT_USAGE, f"没有 {a.name!r} 这个 skill（{e}）；不带名字可以列出全部")
    fn = getattr(mod, "detect", None) or getattr(mod, "run", None)
    if not callable(fn):
        _die(EXIT_USAGE, f"skill {a.name!r} 里没有 detect() 或 run() 入口")

    if a.args_file:
        p = Path(a.args_file)
        if not p.exists():
            _die(EXIT_USAGE, f"参数文件不存在：{a.args_file}")
        raw = p.read_text(encoding="utf-8")
    else:
        raw = a.args or "{}"
    try:
        kwargs = json.loads(raw)
    except Exception as e:
        _die(EXIT_USAGE, f"参数不是合法 JSON：{e}")
    if not isinstance(kwargs, dict):
        _die(EXIT_USAGE, "参数要是一个 JSON 对象，如 '{\"limit\": 30}'")
    _emit(fn(**kwargs), a.pretty)
    return EXIT_OK


def _build_program(data) -> IRProgram:
    if not isinstance(data, dict):
        _die(EXIT_USAGE, 'IR 顶层必须是 JSON 对象，形如 {"instructions": [...]}')
    raw = data.get("instructions")
    if not isinstance(raw, list):
        _die(EXIT_USAGE, "IR 必须有 instructions 数组")
    instrs = []
    for i, d in enumerate(raw):
        if not isinstance(d, dict):
            _die(EXIT_USAGE, f"instructions[{i}] 必须是对象")
        instrs.append(Instruction(op=d.get("op", ""), args=d.get("args") or {},
                                  out=d.get("out"),
                                  depends_on=d.get("depends_on") or [],
                                  tool=d.get("tool")))
    return IRProgram(instructions=instrs, final_answer=data.get("final_answer"))


def cmd_run(a) -> int:
    if a.source == "-":
        text = sys.stdin.read()
    else:
        p = Path(a.source)
        if not p.exists():
            _die(EXIT_USAGE, f"IR 文件不存在：{a.source}")
        text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError as e:
        _die(EXIT_USAGE, f"IR 不是合法 JSON：{e}")

    program = _build_program(data)
    interp = SemanticInterpreter(_registry(), factory.build_policy_gate(),
                                 Workspace(str(_BASE)))
    try:
        result = asyncio.run(interp.run(program))
    except PermissionError as e:
        _die(EXIT_DENIED, f"{e}")
    except Exception as e:
        _die(EXIT_FAIL, f"执行 IR 失败：{e}")
    _emit(result, a.pretty)
    # 被安全门拦下 → 与 call 路径同一个退出码。脚本必须能分清
    # 「这批活被拦住了」和「这批活执行出错」—— 把前者混成成功是最危险的。
    if result.get("denied"):
        return EXIT_DENIED
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:      # Windows 控制台默认不是 UTF-8：不显式设，中文会变乱码
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--pretty", action="store_true", help="缩进输出，给人看")

    parser = argparse.ArgumentParser(
        prog="intentos",
        description="IntentOS 命令行入口 —— 用同一套原语给脚本和 Agent 干活")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", parents=[common], help="列出册子里的原语")
    p.add_argument("domain", nargs="?", help="只看某个域，如 process")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("describe", parents=[common], help="看一条原语怎么调")
    p.add_argument("tool", help="原语名，如 process.find")
    p.set_defaults(fn=cmd_describe)

    p = sub.add_parser("call", parents=[common], help="调一条原语")
    p.add_argument("tool", help="原语名，如 process.find")
    p.add_argument("--args", help='参数 JSON，如 \'{"pattern": "rag"}\'；传 - 表示从 stdin 读')
    p.add_argument("--args-file",
                   help="参数 JSON 的文件路径（脚本里推荐用它：查询词不会出现在命令行里）")
    p.set_defaults(fn=cmd_call)

    p = sub.add_parser("run", parents=[common], help="跑一段 IR（一次交一批）")
    p.add_argument("source", help="IR 的 JSON 文件路径，或 - 表示从 stdin 读")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("blocks", parents=[common],
                       help="工具分块：不给块名看目录，给了就展开那一块")
    p.add_argument("block", nargs="?", help="块 id，如 network；不传则列全部块")
    p.add_argument("--text", action="store_true",
                   help="把块目录渲染成可读文本（配合不给块名用）")
    p.set_defaults(fn=cmd_blocks)

    p = sub.add_parser("journal", parents=[common],
                       help="调用日志：看刚才做过什么（含被安全门拒掉的）")
    p.add_argument("--limit", type=int, default=30, help="最多几条，默认 30")
    p.add_argument("--since", default="",
                   help='只看这之后的，如 "2026-09-12" 或 "2026-09-12 20:00"')
    p.add_argument("--name", default="", help='只看某个原语，支持片段（"fs." 是整个文件域）')
    p.add_argument("--denied", action="store_true", help="只看被执行门拒掉的")
    p.add_argument("--text", action="store_true", help="渲染成可读文本（给模型读的格式）")
    p.set_defaults(fn=cmd_journal)

    p = sub.add_parser("skill", parents=[common],
                       help="任务级能力：把几条原语交叉成「一件事的完整答案」")
    p.add_argument("name", nargs="?", help="skill 名字，如 proc_detective；不传则列出全部")
    p.add_argument("--args", help='参数 JSON，如 \'{"limit": 30}\'')
    p.add_argument("--args-file", help="参数 JSON 的文件路径")
    p.set_defaults(fn=cmd_skill)

    a = parser.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
