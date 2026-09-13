"""IntentOS 案例测试套件 —— 共用脚手架。

**安全约定（全套测试必须遵守）**
  · 会改状态的原语（fs.write / fs.delete / fs.move / fs.copy / power.* / process.kill /
    service.control / system.free_memory …）**一律只传 dry_run=True 做预览**，绝不真执行。
  · 只有只读原语才真跑（system.info / process.list / disk.list / fs.list / service.list …）。
  · 拿不准归类的按「会改状态」处理：要么 dry_run=True，要么干脆不测。

**护栏在调用点上，不靠记性**：`call_readonly()` 拒绝任何被判定为「会改状态」的原语；
`call_preview()` 拒绝任何没显式带 `dry_run=True` 的调用。写错一条就是 AssertionError，
而不是真把系统动了 —— 项目历史上真跑过一次 power.lock，把作者屏幕锁了。
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
PRIMITIVES_DIR = PROJECT_ROOT / "primitives"
CLI_PATH = PROJECT_ROOT / "adapters" / "cli.py"
CLI_TIMEOUT = 300          # 秒。原语会扫服务 / 事件日志，机器慢时给足

for _p in (str(PROJECT_ROOT), str(TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core import factory, journal                                   # noqa: E402
from core.interpreter import (                                      # noqa: E402
    IRProgram, Instruction, PolicyGate, SemanticInterpreter, ToolRegistry, Workspace,
)

# 原语只加载一次：load_primitives() 注册全部原语，并在末尾自动装上执行门
PRIMITIVES_LOADED = factory.load_primitives(str(PRIMITIVES_DIR))
registry = factory.registry
PRIMITIVE_COUNT = len(registry.list_tools())

# 测试期间默认关掉调用日志 —— 一次跑下来会打上百条记录，会把作者 logs/ 里的
# 真实使用痕迹淹掉。要验证「调用日志」这条链路的用例自己临时打开（见 journal_on）。
journal.set_enabled(False)


def _dry_run_capable() -> set[str]:
    """schema 里真的声明了 dry_run 的原语 —— 它们都有「预览」这条只读分支。"""
    out: set[str] = set()
    for name, meta in registry.list_tools().items():
        if "dry_run" in ((meta.get("schema") or {}).get("properties") or {}):
            out.add(name)
    return out


DRY_RUN_CAPABLE = _dry_run_capable()
CONFIRM_REQUIRED = {n for n, pol in factory.POLICY.items()
                    if pol.get("requires_confirmation")}
# 「会改状态」取并集 —— 宁可多算：漏算一条就是铁律上的一个口子
MUTATING = DRY_RUN_CAPABLE | CONFIRM_REQUIRED

# 无论怎么传参都不许在测试里出现的三条：
#   sound.beep —— 会真的出声（项目自己说它「不做 dry_run、会打扰用户」）
#   ui.notify  —— 会真的弹系统通知（同上，用户可见）
#   escape     —— 逃生舱，跑真实代码；它是「逃生」用的，测试不该碰
FORBIDDEN_IN_TESTS = {"sound.beep", "ui.notify", "escape"}


class _NoTtyStdin:
    """假的 stdin：isatty() 恒 False，读它就当流已关。"""

    def isatty(self) -> bool:
        return False

    def read(self, *a):                       # pragma: no cover
        raise OSError("测试环境不提供输入")

    def readline(self, *a):                   # pragma: no cover
        raise OSError("测试环境不提供输入")

    def close(self) -> None:
        pass


@contextmanager
def no_tty():
    """把 stdin 装成「非交互」—— 确认门与执行门才会走 fail-closed 那条路。

    **必须有这个**：从终端里跑 `python tests/smoke_test.py` 时真实的 stdin 就是 tty，
    不装的话安全门会弹出确认框并 input() 阻塞住，整个测试卡死。
    """
    old = sys.stdin
    sys.stdin = _NoTtyStdin()                 # type: ignore[assignment]
    try:
        yield
    finally:
        sys.stdin = old


@contextmanager
def journal_on():
    """临时打开调用日志（用完恢复原状）—— 验证「被拒也记一笔」时用。"""
    before = journal.is_enabled()
    journal.set_enabled(True)
    try:
        yield
    finally:
        journal.set_enabled(before)


@contextmanager
def scratch_dir(prefix: str = "intentos_test_"):
    """一个自建的临时目录（用 pathlib 建，不是调原语），用完整个删掉。

    只有它是可以被测试写的地方 —— 原语层面的写操作**一个都不许真跑**。
    """
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _guard(name: str) -> None:
    if name in FORBIDDEN_IN_TESTS:
        raise AssertionError(f"铁律：{name} 不参与任何测试（会真的打扰用户 / 跑真实代码）")


def parse_ts(s: str) -> datetime.datetime:
    """把原语给的 "YYYY-MM-DD HH:MM:SS" 解析成 datetime —— 解析得动 = 是真时间戳。"""
    return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def call_readonly(name: str, args: dict | None = None) -> dict:
    """真跑一条**只读**原语。会改状态的走到这里直接 AssertionError（不是真跑）。"""
    _guard(name)
    if name in MUTATING:
        raise AssertionError(
            f"铁律：{name} 会改状态（dry_run 能力={name in DRY_RUN_CAPABLE}，"
            f"需确认={name in CONFIRM_REQUIRED}），只读用例不许真跑它")
    return registry.execute(name, args or {})


def call_preview(name: str, args: dict) -> dict:
    """只跑 dry_run=True 的预览分支。少传 dry_run 直接 AssertionError。"""
    _guard(name)
    if args.get("dry_run") is not True:
        raise AssertionError(f"铁律：{name} 的预览调用必须显式传 dry_run=True")
    return registry.execute(name, args)


def run_cli(*argv: str, expect_exit: int | None = None) -> tuple[int, str, str]:
    """跑一次 CLI 子进程，返回 (退出码, stdout, stderr)。

    stdin 固定为 DEVNULL（非交互）—— 可复现，且正好能验证「无人可确认时被拒绝」。
    日志关掉，别把作者的 logs/ 弄脏。
    """
    env = dict(os.environ)
    env["INTENTOS_JOURNAL"] = "0"
    proc = subprocess.run(
        [sys.executable, str(CLI_PATH), *argv],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
        env=env, timeout=CLI_TIMEOUT,
    )
    if expect_exit is not None and proc.returncode != expect_exit:
        raise AssertionError(
            f"CLI {' '.join(argv)} 退出码 {proc.returncode}，期望 {expect_exit}\n"
            f"stdout: {proc.stdout[:400]}\nstderr: {proc.stderr[:400]}")
    return proc.returncode, proc.stdout, proc.stderr


def cli_json(*argv: str, expect_exit: int = 0) -> dict:
    """跑 CLI 并解析它 stdout 上的结果 JSON（stdout 只放 JSON 是它的输出契约）。"""
    _, out, err = run_cli(*argv, expect_exit=expect_exit)
    try:
        return json.loads(out)
    except ValueError as e:
        raise AssertionError(f"CLI {' '.join(argv)} 的 stdout 不是合法 JSON：{e}\n"
                             f"stdout[:400]={out[:400]!r}\nstderr[:400]={err[:400]!r}")


def spy_registry():
    """一个干净的注册表 + 一个只记账的假工具 —— 用来证明「原语到底有没有被调用」。

    真工具会动系统，没法用来断言「没执行」；这个只往列表里塞一条。
    """
    reg = ToolRegistry()
    calls: list[tuple[str, object]] = []

    @reg.tool("spy.echo", "只记录调用，不碰系统",
              {"type": "object", "properties": {"x": {}}, "required": []})
    def _echo(x=None):
        calls.append(("spy.echo", x))
        return {"ok": True, "echo": x}

    @reg.tool("spy.boom", "只记录调用，不碰系统",
              {"type": "object", "properties": {"x": {}}, "required": []})
    def _boom(x=None):
        calls.append(("spy.boom", x))
        return {"ok": True}

    return reg, calls


def program(*instructions: Instruction) -> IRProgram:
    return IRProgram(instructions=list(instructions))


def make_interpreter(reg: ToolRegistry, allow_headless: bool = False) -> SemanticInterpreter:
    return SemanticInterpreter(reg, PolicyGate(allow_headless=allow_headless), Workspace())
