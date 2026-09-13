"""第 3 组：安全门 —— 项目最核心的价值，必须守住。

每道闸都同时给出**正面证据**（该拦的拦住了）与**反面证据**（该放的放过去了）——
只证明「拦住了」的测试，靠「把门焊死」也能全绿。

  ① 静态校验：非法 IR 在**执行前**就被拦下（用假工具记账，证明原语一次都没被调用）
  ② 执行门：高危原语在无人可确认时被拒；dry_run 预览放行；伪造预览不放行

路径禁区与 `$引用` 在 test_security_paths.py。
"""
from __future__ import annotations

import asyncio
import unittest

from helpers import (
    factory, journal, journal_on, make_interpreter, no_tty, program,
    registry, scratch_dir, spy_registry,
)
from core.interpreter import IRProgram, Instruction, is_pure_preview


class StaticValidation(unittest.TestCase):
    """① 非法 IR 在执行前被拦下 —— 证据是假工具的调用记录为空。"""

    def _run(self, *instrs):
        reg, calls = spy_registry()
        interp = make_interpreter(reg)
        result = asyncio.run(interp.run(program(*instrs)))
        return result, calls

    def test_invalid_opcode_rejected_before_execution(self):
        # exec 是 2026-09-11 被删掉的那个万能口子（能摸到整个进程），必须认不出它
        result, calls = self._run(
            Instruction(op="exec", tool="spy.echo", args={"x": 1}, out="r"))
        self.assertFalse(result["ok"])
        self.assertTrue(any("非法操作码" in e for e in result["errors"]), result["errors"])
        self.assertEqual(calls, [], "校验没过却执行了原语")

    def test_unknown_tool_rejected_before_execution(self):
        result, calls = self._run(
            Instruction(op="call", tool="no.such.tool", args={}, out="r"))
        self.assertFalse(result["ok"])
        self.assertTrue(any("未知工具" in e for e in result["errors"]), result["errors"])
        self.assertEqual(calls, [])

    def test_call_without_tool_rejected(self):
        result, calls = self._run(Instruction(op="call", args={}, out="r"))
        self.assertFalse(result["ok"])
        self.assertTrue(any("未指定 tool" in e for e in result["errors"]), result["errors"])
        self.assertEqual(calls, [])

    def test_undefined_dependency_rejected_before_execution(self):
        result, calls = self._run(
            Instruction(op="call", tool="spy.echo", args={"x": 1}, out="r",
                        depends_on=["never_defined"]))
        self.assertFalse(result["ok"])
        self.assertTrue(any("未定义" in e for e in result["errors"]), result["errors"])
        self.assertEqual(calls, [])

    def test_undefined_dollar_reference_rejected_before_execution(self):
        """拼错寄存器名是编排里最常见的错误 —— 不许静默传 None 进原语。"""
        result, calls = self._run(
            Instruction(op="call", tool="spy.echo", args={"x": "$typo.field"}, out="r"))
        self.assertFalse(result["ok"])
        self.assertTrue(any("$typo" in e for e in result["errors"]), result["errors"])
        self.assertEqual(calls, [], "非法引用却执行了原语")

    def test_all_problems_reported_at_once(self):
        """一次把问题全报出来，别让调用方改一条跑一次。"""
        result, _ = self._run(
            Instruction(op="exec", tool="no.such.tool", out="a"),
            Instruction(op="call", tool="spy.echo", args={"x": "$nope"}, out="b",
                        depends_on=["missing"]))
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(len(result["errors"]), 3, result["errors"])

    def test_valid_program_still_runs(self):
        """反面证据：把门做成「什么都拦」也算全绿 —— 合法的必须放行。"""
        result, calls = self._run(
            Instruction(op="call", tool="spy.echo", args={"x": 1}, out="r"),
            Instruction(op="finish", args={}, depends_on=["r"]))
        self.assertTrue(result["ok"], result.get("errors"))
        self.assertEqual(calls, [("spy.echo", 1)])

    def test_empty_program_is_not_success(self):
        """空 IR 不是「成功」—— 否则「什么都没干」会冒充「干完了」。"""
        reg, _ = spy_registry()
        result = asyncio.run(make_interpreter(reg).run(IRProgram(instructions=[])))
        self.assertFalse(result["ok"])


class ExecutionGatePolicy(unittest.TestCase):
    """② 执行门：真实装配（load_primitives 自动装的那一版）。"""

    def setUp(self):
        self.gate = registry.gate
        self.assertIsNotNone(self.gate, "load_primitives() 没有自动装上执行门")

    def test_readonly_passes(self):
        self.assertEqual(self.gate("system.info", {}, confirmed=False)[0], True)

    def test_high_risk_denied_when_nobody_can_confirm(self):
        with no_tty():
            ok, msg = self.gate("fs.delete", {"path": r"D:\intentos_不存在"}, confirmed=False)
        self.assertFalse(ok)
        self.assertIn("无人可确认", msg)

    def test_high_risk_primitive_set_is_guarded(self):
        """每一类会改状态的原语都要被拦 —— 不只是 fs.delete。"""
        with no_tty():
            for name, args in (("fs.write", {"path": "x", "content": "y"}),
                               ("fs.move", {"source": "a", "target": "b"}),
                               ("power.shutdown", {"action": "shutdown"}),
                               ("process.kill", {"pid": 1}),
                               ("system.free_memory", {}),
                               ("service.control", {"name": "Spooler", "action": "stop"}),
                               ("registry.write", {"path": "HKCU\\X", "action": "delete"}),
                               ("escape", {"command": "whoami"})):
            # 用 subTest 逐条跑：一条失败不影响看清其余几条
                with self.subTest(primitive=name):
                    ok, msg = self.gate(name, args, confirmed=False)
                    self.assertFalse(ok, f"{name} 没被拦住：{msg}")

    def test_dry_run_preview_is_exempt(self):
        with no_tty():
            ok, msg = self.gate("fs.delete", {"path": "x", "dry_run": True}, confirmed=False)
        self.assertTrue(ok, msg)
        self.assertIn("只读预览", msg)

    def test_probe_exemption_is_not_a_loophole(self):
        """net.download 的 probe 会在预览分支里真的发 HTTP —— dry_run 免确认不能给它。"""
        with no_tty():
            ok, msg = self.gate("net.download",
                                {"url": "http://example.com", "dry_run": True,
                                 "probe": True}, confirmed=False)
        self.assertFalse(ok, "probe=True 的预览被误放行了")
        self.assertNotIn("只读预览", msg)

    def test_no_dry_run_no_preview_privilege(self):
        """没声明 dry_run 的原语，随手塞个 dry_run=true 不算预览（escape 就是这条）。"""
        self.assertFalse(is_pure_preview("escape", {"dry_run": True},
                                         {"fs.delete"}, {}))
        self.assertFalse(is_pure_preview("fs.delete", {"dry_run": False},
                                         {"fs.delete"}, {}))
        self.assertFalse(is_pure_preview("fs.delete", {},
                                         {"fs.delete"}, {}))
        self.assertTrue(is_pure_preview("fs.delete", {"dry_run": True},
                                        {"fs.delete"}, {}))

    def test_confirmer_decides_when_present(self):
        """接入方给了确认器 → 由它说话（用户点同意/拒绝各一条）。"""
        allow = factory.ExecutionGate(factory.POLICY, confirmer=lambda n, a: True)
        deny = factory.ExecutionGate(factory.POLICY, confirmer=lambda n, a: False)
        self.assertTrue(allow("fs.delete", {"path": "x"})[0])
        self.assertFalse(deny("fs.delete", {"path": "x"})[0])

    def test_confirmer_exception_fails_closed(self):
        def boom(n, a):
            raise RuntimeError("确认通道断了")
        gate = factory.ExecutionGate(factory.POLICY, confirmer=boom)
        ok, msg = gate("fs.delete", {"path": "x"})
        self.assertFalse(ok, "确认器炸了竟然放行")
        self.assertIn("拒绝", msg)

    def test_headless_optin_is_explicit(self):
        """allow_headless=True 是自动化场景的显式选择 —— 默认必须是拒绝。"""
        gate = factory.ExecutionGate(factory.POLICY, allow_headless=True)
        with no_tty():
            default_gate = factory.ExecutionGate(factory.POLICY)
            self.assertFalse(default_gate("fs.delete", {"path": "x"})[0])
            self.assertTrue(gate("fs.delete", {"path": "x"})[0])


class RealDenialPath(unittest.TestCase):
    """② 续：走真实装配路径 —— registry.execute 与 IR 解释器两条路都要被拦住。"""

    def test_registry_execute_denies_and_keeps_the_file(self):
        with scratch_dir() as scratch:
            victim = scratch / "victim.txt"
            victim.write_text("重要的是我还在", encoding="utf-8")
            with no_tty():
                with self.assertRaises(PermissionError) as cm:
                    registry.execute("fs.delete", {"path": str(victim)})
            self.assertIn("无人可确认", str(cm.exception))
            self.assertTrue(victim.is_file(), "安全门没拦住，文件真被删了")

    def test_denied_call_is_journalled(self):
        """「想干、但没让干」是事后追查最要紧的一条 —— 先记再拒。"""
        with scratch_dir() as scratch:
            victim = scratch / "victim.txt"
            victim.write_text("x", encoding="utf-8")
            with journal_on(), no_tty():
                with self.assertRaises(PermissionError):
                    registry.execute("fs.delete", {"path": str(victim)})
            recs = journal.recent(limit=20, denied_only=True)
            self.assertTrue(any(r["name"] == "fs.delete" and r.get("denied")
                                for r in recs), f"被拒的调用没进日志：{recs[:3]}")

    def test_preview_is_allowed_through_the_same_path(self):
        """反面证据：同一条路，带上 dry_run=True 就该放行（而且是预览）。"""
        with scratch_dir() as scratch:
            victim = scratch / "victim.txt"
            victim.write_text("x", encoding="utf-8")
            with no_tty():
                r = registry.execute("fs.delete", {"path": str(victim), "dry_run": True})
            self.assertIs(r["dry_run"], True)
            self.assertFalse(r["deleted"])
            self.assertTrue(victim.is_file())

    def test_ir_path_denies_without_approval(self):
        """IR 路径：没人可确认 → 这条进 denied，且结果顶层可见（不能冒充成功）。"""
        with scratch_dir() as scratch:
            victim = scratch / "victim.txt"
            victim.write_text("x", encoding="utf-8")
            interp = make_interpreter(registry)          # PolicyGate(allow_headless=False)
            ir = program(
                Instruction(op="call", tool="system.info", args={}, out="sys"),
                Instruction(op="call", tool="fs.delete", args={"path": str(victim)},
                            out="del", depends_on=["sys"]),
                Instruction(op="finish", args={}, depends_on=["del"]))
            with no_tty():
                result = asyncio.run(interp.run(ir))
            self.assertFalse(result["ok"], "整批被拒却报 ok=True")
            self.assertIn("fs.delete", result.get("denied", []))
            self.assertIn("sys", result["results"], "只读的部分应当照常执行")
            self.assertTrue(victim.is_file())
            self.assertTrue(result["results"]["del"].get("denied"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
