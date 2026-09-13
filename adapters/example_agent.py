"""把你的 Agent 工具接进 IntentOS —— 最小可运行示例。

IntentOS 是【无状态工具】：它不认识你的 Agent，也不持有你的会话对象。
它只认两样东西 ——

    输入：IR(意图计划) + request_context（纯数据 dict）
    输出：执行结果(JSON)

所以接入只有两步：① 把工具注册进 `ToolRegistry`；② 把上下文当**纯数据**传进来。
本文件用三个「假工具」把这两步演示完，不依赖任何外部项目，clone 下来直接能跑：

    python adapters/example_agent.py

真实接入时，把下面那三个函数换成你自己的工具即可 —— 其余一行都不用改。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if not __package__:            # 直接运行本文件时，sys.path[0] 是 adapters/ 而非项目根
    sys.path.insert(0, str(_ROOT))

from core.interpreter import (  # noqa: E402
    IRProgram, Instruction, SemanticInterpreter, ToolRegistry, Workspace,
)


# ══════════════════════════════════════════════════════════════════════════
# 第一步：写你的工具 —— 普通函数，收 dict 参数、返回 dict 结果
# ══════════════════════════════════════════════════════════════════════════
# **同步异步都行**：遇到 awaitable，IntentOS 会自动 await ——
# 接入方不必为了接进来去改自己工具函数的风格。

def read_file(path: str) -> dict:
    """读文件（示例：返回假内容，不碰真实磁盘）。"""
    return {"ok": True, "path": path, "content": f"（{path} 的内容）", "bytes": 42}


def list_dir(path: str) -> dict:
    """列目录（示例）。"""
    return {"ok": True, "path": path, "entries": ["a.txt", "b.py", "sub/"]}


async def echo(entries: list | None = None, size: int | None = None) -> dict:
    """把两处结果合成一句话（示例：演示异步工具 + 同时引用两个寄存器）。"""
    return {"ok": True, "summary": f"目录里有 {entries}，README 有 {size} 字节"}


# ══════════════════════════════════════════════════════════════════════════
# 第二步：注册进 ToolRegistry
# ══════════════════════════════════════════════════════════════════════════

def _obj(**props: dict) -> dict:
    """随手写 JSON Schema 的小工具（真实项目里通常由框架自动生成）。"""
    return {"type": "object", "properties": props, "required": list(props)}


def build_registry(registry: ToolRegistry | None = None) -> ToolRegistry:
    """把你的工具注册成 IntentOS 能调的工具。

    `source="agent"` 表示「这是接入方自带的工具」—— **同名时它优先于内置原语**。
    这条规则让接入方能用自己的实现覆盖内置版（你的 Agent 原生已经做得更好的能力），
    而 IntentOS 一行都不用改。
    """
    reg = registry or ToolRegistry()
    reg.tool("demo.read_file", "读取指定文件的内容",
             _obj(path={"type": "string", "description": "文件路径"}), source="agent")(read_file)
    reg.tool("demo.list_dir", "列出指定目录的内容",
             _obj(path={"type": "string", "description": "目录路径"}), source="agent")(list_dir)
    reg.tool("demo.echo", "把两处结果合成一句话",
             _obj(entries={"type": "array", "description": "目录条目"},
                  size={"type": "integer", "description": "字节数"}), source="agent")(echo)
    return reg


# ══════════════════════════════════════════════════════════════════════════
# 演示：「一批操作写成一段 IR，交出去一次执行完」
# ══════════════════════════════════════════════════════════════════════════

async def main():
    """注意这里**没有 LLM、没有 API Key、没有 while 循环** —— IntentOS 是工具。

    真实接入时，下面这段 IR 由你的 Agent 产出（LLM 生成 / 模板拼 / 手写都行，
    IntentOS 不关心）。它只负责把 IR 执行掉。
    """
    from core import factory      # 延迟 import：factory 反向依赖本模块，顶层 import 会成环

    factory.load_primitives(str(_ROOT / "primitives"))   # 内置 OS 原语
    registry = build_registry(factory.registry)          # 再把「你自己的工具」挂上去
    interpreter = SemanticInterpreter(
        registry, factory.build_policy_gate(allow_headless=True), Workspace())

    print("=" * 70)
    print("演示：一条 IR 里既有你的工具、也有内置原语 —— 无依赖的并行跑")
    print("=" * 70)
    program = IRProgram(instructions=[
        # 你的工具（外设）
        Instruction(op="call", tool="demo.list_dir", args={"path": "./"}, out="dir", depends_on=[]),
        Instruction(op="call", tool="demo.read_file",
                    args={"path": "README.md"}, out="doc", depends_on=[]),
        # 内置原语（内核自带的 OS 能力）
        Instruction(op="call", tool="system.info", args={}, out="sys", depends_on=[]),
        # 引用前面的结果：`$寄存器.字段` —— 注意**整个字符串必须是引用本身**。
        # 嵌在句子里（如 "结果：$a.b"）不会被解析，拼接是工具自己的活。
        Instruction(op="call", tool="demo.echo",
                    args={"entries": "$dir.entries", "size": "$doc.bytes"},
                    out="summary", depends_on=["dir", "doc"]),
        Instruction(op="finish", args={}, depends_on=["sys", "summary"]),
    ])
    result = await interpreter.run(program)
    ws = result.get("workspace", {})
    print(f"\n✅ ok={result['ok']}   寄存器: {list(ws)}")
    print(f"   你的工具 demo.list_dir → {ws.get('dir')}")
    print(f"   引用传值 demo.echo     → {ws.get('summary')}")
    print(f"   内置原语 system.info   → {ws.get('sys', {}).get('platform')} "
          f"{ws.get('sys', {}).get('machine')}")


if __name__ == "__main__":
    asyncio.run(main())
