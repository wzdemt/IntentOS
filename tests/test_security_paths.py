"""第 3 组（续）：路径禁区 + `$引用` 传值。

③ 盘根 / Windows / Program Files / ProgramData 一律拒绝 —— 全程 dry_run=True；
④ `$寄存器.字段` 取到值；引用不存在的寄存器被静态校验拦下。
"""
from __future__ import annotations

import asyncio
import os
import unittest
from pathlib import Path

from helpers import (
    PROJECT_ROOT, make_interpreter, no_tty, program, registry,
)
from core.interpreter import Instruction, Workspace


class PathForbiddenZone(unittest.TestCase):
    """③ 路径禁区：盘根与系统目录一律拒绝。全程 dry_run=True。"""

    FORBIDDEN = ["D:\\", "C:\\", "C:\\Windows", "C:\\Windows\\System32",
                 "C:\\Program Files", "C:\\ProgramData",
                 "C:\\Windows\\..\\Windows\\System32"]     # 末条靠 `..` 爬进去，必须先规范化

    def test_delete_refuses_system_zones(self):
        with no_tty():
            for path in self.FORBIDDEN:
                with self.subTest(path=path):
                    r = registry.execute("fs.delete", {"path": path, "dry_run": True})
                    self.assertFalse(r["deleted"], f"{path} 竟然没被拒")
                    self.assertIn("拒绝删除", r["note"], r)

    def test_allowed_path_is_not_refused(self):
        """反面证据：把「什么都拒」当安全是没意义的 —— 用户目录必须放行。"""
        with no_tty():
            r = registry.execute("fs.delete", {"path": str(PROJECT_ROOT / "README.md"),
                                               "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertNotIn("拒绝删除", r["note"])

    def test_mkdir_link_copy_move_refuse_zones(self):
        with no_tty():
            cases = [
                ("fs.mkdir", {"path": "C:\\Windows\\intentos_new", "dry_run": True}),
                ("fs.copy", {"source": str(PROJECT_ROOT / "README.md"),
                             "target": "C:\\Windows\\intentos_copy", "dry_run": True}),
                ("fs.move", {"source": str(PROJECT_ROOT / "README.md"),
                             "target": "C:\\Windows\\intentos_move", "dry_run": True}),
                ("fs.link", {"source": str(PROJECT_ROOT / "README.md"),
                             "link_path": "C:\\Windows\\intentos_link", "dry_run": True}),
                ("archive.create", {"target": "C:\\Windows\\intentos.zip",
                                    "sources": [str(PROJECT_ROOT / "README.md")],
                                    "dry_run": True}),
                ("shell.shortcut_write", {"path": "C:\\Windows\\intentos.lnk",
                                          "target": str(PROJECT_ROOT / "README.md"),
                                          "dry_run": True}),
            ]
            for name, args in cases:
                with self.subTest(primitive=name):
                    r = registry.execute(name, args)
                    self.assertTrue(r.get("refused"), f"{name} 没有拒绝系统禁区：{r}")
                    self.assertIn("不允许", str(r.get("note", "")), r)

    def test_write_and_append_do_not_check_the_zone(self):
        """⚠️ 已知差异（照实记录，不是为了全绿）：

        fs.write / fs.append **不判系统禁区** —— 它们对 C:\\Windows 下的落点只会给出
        「真执行将新建文件」的预览，靠的是「需用户确认」这道门 + 操作系统 ACL 兜底
        （非管理员写不进 C:\\Windows）。同目录的 fs.delete / fs.copy / fs.move /
        fs.mkdir / fs.link 都判。

        本用例**断言这个观察到的事实**，所以它绿不代表没问题：
        哪天真给 fs.write 加上了禁区判定，这条会失败，届时应当把它改成断言「拒绝」。
        """
        with no_tty():
            for name, args in (
                ("fs.write", {"path": "C:\\Windows\\intentos_probe.txt",
                              "content": "x", "dry_run": True}),
                ("fs.append", {"path": "C:\\Windows\\intentos_probe.txt",
                               "content": "x", "dry_run": True}),
            ):
                with self.subTest(primitive=name):
                    r = registry.execute(name, args)
                    self.assertNotIn("refused", r, f"{name} 现在会判禁区了，请更新本用例")
                    self.assertNotIn("不允许", str(r.get("note", "")))
                    self.assertIs(r["dry_run"], True)      # 至少它老老实实只预览

    def test_guard_function_itself(self):
        """直接测那道共用判定（primitives/_common.system_zone_reason）。"""
        from primitives._common import normalize_path, system_zone_reason
        for path in self.FORBIDDEN:
            with self.subTest(path=path):
                self.assertIsNotNone(system_zone_reason(normalize_path(path), "删除"))
        for path in (str(PROJECT_ROOT), os.path.expanduser("~"),
                     str(Path(os.environ.get("TEMP", "C:\\"))) ):
            with self.subTest(path=path):
                self.assertIsNone(system_zone_reason(normalize_path(path), "删除"))


class HardRejects(unittest.TestCase):
    """③ 续：几条与路径无关的硬拒 —— 安全门不止拦路径。全程 dry_run=True。

    都用 no_tty()：这些调用虽然带了 dry_run=True（本该免确认），但万一哪天预览判定被改坏，
    没有 tty 兜底就会弹出确认框把测试挂住 —— 防御性地按「可能被问」来跑。
    有 tty 时没有别的输入，确认门会 fail-closed 拒绝并让断言失败，那是我们要看到的结果。
    """

    def _call(self, name, args):
        """带 no_tty 地调一条原语 —— 见类 docstring 里为什么。"""
        with no_tty():
            return registry.execute(name, args)

    def test_process_kill_refuses_protected_pids(self):
        """PID 0 / 4 是内核态进程，硬拒、没有绕过的参数（连确认都问不到）。"""
        for pid in (0, 4):
            with self.subTest(pid=pid):
                r = self._call("process.kill", {"pid": pid, "dry_run": True})
                self.assertTrue(r["blocked"], f"PID {pid} 没被硬拒：{r}")
                self.assertFalse(r["killed"])
                self.assertIn("硬拒", r["note"])

    def test_process_kill_refuses_non_numeric_pid(self):
        """pid 会被拼进命令行 —— 字符串注入这条路必须关掉（数字校验 + shell=False）。"""
        r = self._call("process.kill",
                             {"pid": "1 & echo pwned", "dry_run": True})
        self.assertFalse(r["killed"])
        self.assertIn("必须是数字", r["note"])

    def test_task_delete_refuses_builtin_system_tasks(self):
        """\\Microsoft\\Windows\\ 下的系统任务（磁盘整理 / 更新 / 字体缓存…）拒绝删除。

        名字从 task.list 现取，任何机器上都找得到一条系统自带任务。
        """
        listing = self._call("task.list", {"limit": 0,
                                                 "name_contains": "\\Microsoft\\Windows\\"})
        names = [t["name"] for t in listing.get("tasks", [])]
        self.assertTrue(names, "这台机器没有任何 \\Microsoft\\Windows\\ 下的任务")
        r = self._call("task.delete", {"name": names[0], "dry_run": True})
        self.assertTrue(r["blocked"], f"系统任务没被拒：{r}")
        self.assertFalse(r.get("deleted"))
        self.assertIn("系统自带任务", r["note"])

    def test_task_create_refuses_system_dir_program(self):
        """计划任务的目标程序也不许落在系统目录 —— 那等于给自己留一个持久化后门。"""
        r = self._call("task.create", {
            "name": "IntentOSNeverCreated", "trigger": {"type": "logon"},
            "action": {"program": "C:\\Windows\\System32\\cmd.exe"}, "dry_run": True})
        self.assertTrue(r["blocked"], f"System32 下的程序没被拒：{r}")
        self.assertIn("系统目录", r["note"])

    def test_task_create_refuses_microsoft_namespace(self):
        r = self._call("task.create", {
            "name": "\\Microsoft\\IntentOSNever", "trigger": {"type": "logon"},
            "action": {"program": "D:\\fake\\x.exe"}, "dry_run": True})
        self.assertTrue(r["blocked"], f"\\Microsoft\\ 命名空间没被拒：{r}")
        self.assertIn("Microsoft", r["note"])

    def test_task_create_refuses_system_account(self):
        """用 SYSTEM 跑任务 = 提权/持久化的标志性写法 —— 一律不给。"""
        r = self._call("task.create", {
            "name": "IntentOSNeverCreated", "trigger": {"type": "logon"},
            "action": {"program": "D:\\fake\\x.exe"}, "run_as": "SYSTEM", "dry_run": True})
        self.assertTrue(r["blocked"], f"SYSTEM 账户没被拒：{r}")
        self.assertIn("系统账户", r["note"])

    def test_service_control_does_not_pretend_to_succeed(self):
        """启停服务要管理员权限 —— 不够时必须明说，不能假装干成了。

        注意：本条给不出「预览」—— 它在权限判定那一步就返回了（非管理员会话下
        service.control 连预览分支都到不了，所以这里断言的是「如实拒绝」）。
        """
        r = self._call("service.control",
                       {"name": "Spooler", "action": "stop", "dry_run": True})
        if r.get("ok"):
            self.fail(f"非管理员会话竟然报服务已停止：{r}")
        self.assertTrue(r.get("note"))
        self.assertTrue(r.get("requires_admin") or "管理员" in r["note"], r)


class DollarReferences(unittest.TestCase):
    """④ `$引用` 传值：`$寄存器.字段` 取到值；引用不存在的寄存器被静态校验拦下。"""

    def test_workspace_resolves_field_and_nested_paths(self):
        ws = Workspace()
        ws.write("r", {"a": {"b": {"c": 42}}, "list": [1, 2]})
        self.assertEqual(ws.read("$r.a.b.c"), 42)
        self.assertEqual(ws.read("r.a.b.c"), 42)         # 不带 $ 也认
        self.assertEqual(ws.read("$r"), {"a": {"b": {"c": 42}}, "list": [1, 2]})
        self.assertIsNone(ws.read("$r.a.missing"))
        self.assertIsNone(ws.read("$nope"))
        # resolve 递归进 dict / list
        self.assertEqual(ws.resolve({"x": "$r.a.b.c", "y": ["$r.list", "plain"],
                                     "z": {"k": "$r.a.b.c"}}),
                         {"x": 42, "y": [[1, 2], "plain"], "z": {"k": 42}})
        # 嵌在句子里的不算引用 —— 这是文档写明的口径（拼接是工具自己的活）
        self.assertEqual(ws.resolve("结果是 $r.a.b.c"), "结果是 $r.a.b.c")
        self.assertEqual(ws.resolve(7), 7)

    def test_two_real_primitives_pass_values_by_reference(self):
        """真原语之间传值：disk.usage 的结果喂给 fs.stat 与 fs.list。

        证据是「下游拿到的路径必须等于上游报的那个路径」——
        fs.stat 会把落点回显在 path 字段里，正好当交叉核对。
        """
        interp = make_interpreter(registry)
        ir = program(
            Instruction(op="call", tool="disk.usage",
                        args={"path": str(PROJECT_ROOT)}, out="du", depends_on=[]),
            Instruction(op="call", tool="fs.stat",
                        args={"path": "$du.resolved_path"}, out="st", depends_on=["du"]),
            # volume_root 形如 "D:\" —— 引出来的盘根拿去列目录（只读）
            Instruction(op="call", tool="fs.list",
                        args={"path": "$du.volume_root", "limit": 5},
                        out="ls", depends_on=["du"]))
        result = asyncio.run(interp.run(ir))
        self.assertTrue(result["ok"], result.get("results"))
        ws = result["workspace"]
        self.assertEqual(ws["du"]["resolved_path"], str(PROJECT_ROOT))
        self.assertTrue(ws["st"]["ok"], ws["st"])
        self.assertEqual(ws["st"]["path"], ws["du"]["resolved_path"])   # ← 引用真的传过去了
        self.assertTrue(ws["ls"]["ok"], ws["ls"])
        self.assertGreater(ws["ls"]["total"], 0)
        self.assertEqual(len(ws["ls"]["entries"]), min(5, ws["ls"]["total"]))

    def test_agent_tools_from_example_adapter_work(self):
        """照 adapters/example_agent.py 的姿势：$dir.entries / $doc.bytes 跨指令传值。"""
        import adapters.example_agent as example
        from core.interpreter import ToolRegistry
        reg = example.build_registry(ToolRegistry())     # 独立注册表，不污染全局
        interp = make_interpreter(reg)
        ir = program(
            Instruction(op="call", tool="demo.list_dir", args={"path": "./"},
                        out="dir", depends_on=[]),
            Instruction(op="call", tool="demo.read_file", args={"path": "README.md"},
                        out="doc", depends_on=[]),
            Instruction(op="call", tool="demo.echo",
                        args={"entries": "$dir.entries", "size": "$doc.bytes"},
                        out="summary", depends_on=["dir", "doc"]))
        result = asyncio.run(interp.run(ir))
        self.assertTrue(result["ok"], result.get("results"))
        summary = result["workspace"]["summary"]["summary"]
        self.assertIn("a.txt", summary)          # 取到了 $dir.entries
        self.assertIn("42", summary)             # 取到了 $doc.bytes

    def test_out_register_holds_the_real_result(self):
        interp = make_interpreter(registry)
        ir = program(Instruction(op="call", tool="system.info", args={}, out="sys"))
        result = asyncio.run(interp.run(ir))
        self.assertEqual(result["workspace"]["sys"]["platform"], "Windows")


if __name__ == "__main__":
    unittest.main(verbosity=2)
