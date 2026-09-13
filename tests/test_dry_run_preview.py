"""第 2 组：写类原语**只跑 dry_run 预览** —— 断言返回的是「将要做什么」而不是做完了。

铁律：这一组里**没有任何一条会真执行**。每条参数都显式带 `dry_run=True`，
`helpers.call_preview()` 在调用点上强制这一点（少传就是 AssertionError，不是真跑）。

每条都断言三件事：
  ① `dry_run is True` —— 原语自己承认这是预览；
  ② 「做完了」那个字段是假的（written / deleted / moved / copied / created / locked / killed …）；
  ③ `note` 里说清了**将要做什么**（含「预览」与「真执行将…」）——
     只返回一个 False 而不说会做什么，等于没预览。
最后再核对磁盘：预览过的落点**一个都不许出现**（预览连父目录都不该建）。
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

from helpers import PROJECT_ROOT, call_preview, call_readonly, scratch_dir

README = PROJECT_ROOT / "README.md"
NEVER = "__intentos_never_created__"          # 会被替换成 scratch 下的真实路径

# 唯一一条「将要做什么」不在 note 里、而在结构化字段里的原语：
# fs.delete 的 note 是「只读预览，未删除；真删需 dry_run=False + 过确认」——
# 它说了「没删」，却没像其余各条那样说「真执行会做什么」。这个差异如实记在这里
# （见报告），下面要求它至少把「要删什么」给全（method / type / items / file_count）。
EVIDENCE_IN_FIELDS = {"fs.delete"}


def cases(scratch: Path):
    """(原语, 参数, 「已执行」字段名) —— 参数里的 {S} 会被换成本次运行的临时目录。"""
    S = str(scratch / NEVER)
    return [
        ("fs.write", {"path": S + "/w.txt", "content": "hello", "create_dirs": True,
                      "dry_run": True}, "written"),
        ("fs.append", {"path": S + "/a.txt", "content": "hello", "create_dirs": True,
                       "dry_run": True}, "appended"),
        ("fs.mkdir", {"path": S + "/newdir", "dry_run": True}, "created"),
        ("fs.delete", {"path": str(README), "recursive": False, "dry_run": True}, "deleted"),
        ("fs.copy", {"source": str(README), "target": S + "/c.md", "create_dirs": True,
                     "dry_run": True}, "copied"),
        ("fs.move", {"source": str(README), "target": S + "/m.md", "create_dirs": True,
                     "dry_run": True}, "moved"),
        ("fs.link", {"source": str(README), "link_path": S + "/l.md",
                     "dry_run": True}, "created"),
        ("fs.temp", {"content": "temp-body", "dry_run": True}, "created"),
        ("power.lock", {"dry_run": True}, "locked"),
        ("power.shutdown", {"action": "shutdown", "delay": 60, "dry_run": True}, None),
        ("power.sleep", {"mode": "sleep", "dry_run": True}, None),
        # pid 故意用一个不存在的：就算预览分支哪天坏了，taskkill 也只会失败
        ("process.kill", {"pid": 999999, "dry_run": True}, "killed"),
        ("ui.clipboard_set", {"text": "intentos-preview-only", "dry_run": True}, None),
        ("ui.type_text", {"text": "intentos-preview-only", "dry_run": True}, None),
        ("event.clear", {"channel": "Application", "dry_run": True}, None),
        ("shell.recycle", {"action": "empty", "dry_run": True}, None),
        # 落点目录得真实存在 —— net.download 不自动建目录，目录不在就连预览都不给
        ("net.download", {"url": "http://127.0.0.1:1/intentos-never",
                          "path": str(scratch / "d.bin"), "dry_run": True}, None),
        ("net.http_get", {"url": "http://127.0.0.1:1/", "dry_run": True}, None),
        ("time.set_zone", {"zone": "UTC", "dry_run": True}, None),
        ("archive.create", {"target": S + "/a.zip", "sources": [str(README)],
                            "create_dirs": True, "dry_run": True}, "created"),
        ("shell.shortcut_write", {"path": S + "/s.lnk", "target": str(README),
                                  "create_dirs": True, "dry_run": True}, "written"),
        ("registry.write", {"path": r"HKCU\Software\IntentOSTestNever", "action": "set",
                            "name": "x", "value": "1", "create_key": True,
                            "dry_run": True}, None),
        ("env.set", {"name": "INTENTOS_TEST_NEVER_SET", "value": "1",
                     "dry_run": True}, None),
        ("fs.attrs", {"path": str(README), "hidden": True, "dry_run": True}, None),
    ]


class DryRunPreview(unittest.TestCase):
    """逐条断言：只预览、不执行、说清将做什么。"""

    def test_every_preview_is_a_preview(self):
        with scratch_dir() as scratch:
            for name, args, done_key in cases(scratch):
                with self.subTest(primitive=name):
                    r = call_preview(name, args)
                    self.assertIsInstance(r, dict, f"{name} 没返回 dict")
                    self.assertIs(r.get("dry_run"), True,
                                  f"{name} 返回里没有 dry_run=True：{r}")
                    if done_key:
                        self.assertFalse(r.get(done_key),
                                         f"{name} 的 {done_key} 不是假 —— 预览分支可能真动了手：{r}")
                    note = str(r.get("note", ""))
                    if name == "fs.attrs":       # fs.attrs 用 mode 字段表达（见下）
                        self.assertEqual(r["mode"], "preview")
                    elif name in EVIDENCE_IN_FIELDS:
                        # 见 EVIDENCE_IN_FIELDS 的说明：它的「要删什么」在结构化字段里
                        self.assertIn("预览", note, note)
                        self.assertEqual(r["method"], "preview")
                        self.assertGreaterEqual(r["file_count"], 1)
                        self.assertTrue(r["items"], "预览没列出要删的东西")
                    else:
                        self.assertIn("预览", note, f"{name} 的 note 没说这是预览：{note}")
                        self.assertIn("真执行", note,
                                      f"{name} 的 note 没说清真执行会做什么：{note}")
            self.assertFalse((scratch / NEVER).exists(),
                             f"预览竟然建出了目录：{scratch / NEVER}")
            self.assertFalse((scratch / "d.bin").exists(), "预览竟然落了盘")

    def test_preview_does_not_touch_disk_at_all(self):
        """预览一个「父目录还不存在」的落点：预览**连父目录都不许建**。"""
        with scratch_dir() as scratch:
            target = scratch / NEVER / "sub" / "deep.txt"
            r = call_preview("fs.write", {"path": str(target), "content": "x",
                                          "create_dirs": True, "dry_run": True})
            self.assertIs(r["dry_run"], True)
            self.assertFalse(r["written"])
            self.assertIs(r["will_create_dirs"], True)     # 声明了会建
            self.assertFalse(target.exists())
            self.assertFalse(target.parent.exists())
            self.assertFalse((scratch / NEVER).exists())   # 连第一层都没建

    def test_preview_never_deletes_the_target(self):
        """删这条最要命：预览过的文件必须原封不动。"""
        before = (README.stat().st_size, README.stat().st_mtime_ns)
        r = call_preview("fs.delete", {"path": str(README), "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["deleted"])
        self.assertEqual(r["method"], "preview")
        self.assertGreaterEqual(r["file_count"], 1)
        self.assertTrue(r["items"], "预览没有列出要删的东西")
        self.assertTrue(README.is_file())
        self.assertEqual((README.stat().st_size, README.stat().st_mtime_ns), before)

    def test_power_lock_preview_stays_awake(self):
        """这条就是那次事故的原型：真跑会锁屏。历史事故不能重演 —— 只许预览。"""
        r = call_preview("power.lock", {"dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["locked"])
        self.assertIsNone(r["verified"])
        self.assertIn("未锁屏", r["note"])

    def test_power_shutdown_preview_shows_command_only(self):
        r = call_preview("power.shutdown", {"action": "shutdown", "delay": 60,
                                            "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["ok"])
        self.assertEqual(r["command"][:2], ["shutdown", "/s"])   # 只是把命令拼出来
        self.assertIn("未执行", r["note"])

    def test_free_memory_preview_frees_nothing(self):
        """它不用 dry_run 字段表达预览，用 preview=True —— 单独断言，别混过去。"""
        r = call_preview("system.free_memory", {"dry_run": True})
        self.assertIs(r["preview"], True)
        self.assertIsNone(r["freed_mb"], "预览竟然报了释放量")
        self.assertIn("没有清理", r["note"])

    def test_fs_attrs_preview_path(self):
        r = call_preview("fs.attrs", {"path": str(README), "hidden": True, "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertEqual(r["mode"], "preview")
        self.assertFalse(r["attributes"]["hidden"])          # 属性没被改
        self.assertTrue(README.is_file())

    def test_task_create_preview_creates_no_task(self):
        """建计划任务这条，预览必须一个任务都不建。

        program 故意指向临时目录里的假程序 —— 指 System32 下的真程序会先被
        「系统目录不许当计划任务目标」拦掉（那条也是对的，见 test_security_paths）。
        """
        with scratch_dir() as scratch:
            r = call_preview("task.create", {
                "name": "IntentOSPreviewOnlyNeverCreated",
                "trigger": {"type": "logon"},
                "action": {"program": str(scratch / "fake_program.exe")},
                "dry_run": True})
            self.assertIs(r["dry_run"], True)
            self.assertFalse(r["ok"])
            self.assertIn("没有创建任何任务", r["note"])
            # 只读复核：任务表里不该出现它
            listing = call_readonly("task.list", {"name_contains": "IntentOSPreviewOnly"})
            self.assertEqual(listing["returned"], 0, "预览竟然真建了任务")

    def test_task_control_preview_executes_nothing(self):
        """启停/立刻跑一次计划任务 —— 预览不许真动。任务名从 task.list 现取。"""
        name = call_readonly("task.list", {"limit": 1})["tasks"][0]["name"]
        for action in ("disable", "run"):
            with self.subTest(action=action):
                r = call_preview("task.control",
                                 {"name": name, "action": action, "dry_run": True})
                self.assertIs(r["dry_run"], True)
                self.assertFalse(r["ok"])
                self.assertIn("没有执行任何操作", r["note"])
                self.assertTrue(r["plan"].startswith("schtasks"))   # 只是把命令拼出来
        # 只读复核：这条任务仍然是启用的（预览没把它停用）
        after = call_readonly("task.info", {"name": name})
        self.assertTrue(after["enabled"], "预览竟然把任务停用了")

    def test_process_set_priority_preview_changes_nothing(self):
        """拿测试进程自己当靶子（pid=本进程），预览分支必须停在改优先级之前。"""
        r = call_preview("process.set_priority",
                         {"pid": os.getpid(), "priority": "below_normal", "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["changed"])
        self.assertIsNone(r["priority_after"])
        self.assertTrue(r["priority_before"])       # 只读探测，读得到
        self.assertIn("未做任何修改", r["note"])

    def test_archive_extract_preview_extracts_nothing(self):
        import zipfile
        with scratch_dir() as scratch:
            z = scratch / "fixture.zip"
            with zipfile.ZipFile(z, "w") as f:
                f.writestr("a.txt", "x")
            target = scratch / "extracted_never"
            r = call_preview("archive.extract", {"path": str(z), "target": str(target),
                                                 "dry_run": True})
            self.assertIs(r["dry_run"], True)
            self.assertFalse(r["extracted"])
            self.assertEqual(r["file_count"], 1)
            self.assertTrue(r["will_create_target"])
            self.assertFalse(target.exists(), "预览竟然解压出了目录")

    def test_window_activate_preview_does_not_steal_focus(self):
        """抢焦点会打断正在打字的用户 —— 预览不许改前台窗口（用真 hwnd 验）。"""
        listing = call_readonly("ui.window_list", {"limit": 1})
        before = listing["foreground"]["hwnd"]
        wins = listing["windows"]
        if not wins:
            self.skipTest("当前没有可见顶层窗口（无桌面会话）")
        h = wins[0]["hwnd"]
        r = call_preview("ui.window_activate", {"hwnd": h, "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["activated"])
        self.assertTrue(r["would_activate"])
        self.assertIn("未改变焦点", r["note"])
        after = call_readonly("ui.window_list", {"limit": 1})["foreground"]["hwnd"]
        self.assertEqual(before, after, "预览竟然把前台窗口换了")

    def test_window_control_preview_does_nothing(self):
        listing = call_readonly("ui.window_list", {"limit": 1})
        wins = listing["windows"]
        if not wins:
            self.skipTest("当前没有可见顶层窗口（无桌面会话）")
        w = wins[0]
        r = call_preview("ui.window_control",
                         {"hwnd": w["hwnd"], "action": "minimize", "dry_run": True})
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["would_do"])
        after = call_readonly("ui.window_list", {"include_hidden": True, "limit": 50})
        same = next((x for x in after["windows"] if x["hwnd"] == w["hwnd"]), None)
        self.assertIsNotNone(same, "预览竟然把窗口弄没了")
        self.assertEqual(same["minimized"], w["minimized"], "预览竟然真最小化了窗口")

    def test_screenshot_preview_writes_no_file(self):
        target = PROJECT_ROOT / "__intentos_never_shot.png"
        try:
            r = call_preview("ui.screenshot", {"path": str(target), "dry_run": True})
            self.assertIs(r["dry_run"], True)
            self.assertFalse(target.exists(), "预览竟然真截了图")
            self.assertIsInstance(r.get("estimated_bytes"), int)
        finally:
            target.unlink(missing_ok=True)

    def test_power_plan_branches(self):
        """power.plan 不走上面那张表：它有三个分支，且最后一支**不符合通用约定**。

        为了不依赖「这台机器上装了哪几个电源计划」，目标方案直接取它自己报的当前方案 ——
        这样「已经就是当前方案」那一支在任何机器上都能命中。
        """
        # ① action=get：只读，但本条声明了 requires_confirmation，
        #    所以**读也要过确认门**（通用约定第 3 条），dry_run=True 才免确认放行
        cur = call_preview("power.plan", {"action": "get", "dry_run": True})
        self.assertTrue(cur["ok"], cur.get("note"))
        self.assertTrue(cur["active_plan"])

        # ② 目标就是当前方案 → 空操作分支：ok=True、already_active=True
        same = call_preview("power.plan", {"action": "set", "plan": cur["active_plan"],
                                           "dry_run": True})
        self.assertTrue(same["already_active"])
        self.assertTrue(same["ok"])
        # ⚠️ 已知差异（见报告）：这一支**没有 dry_run 字段**，而通用约定第 2 条说
        #    「判断有没有真的动手看 dry_run」。

        # ③ 本机没有的方案：明确说没有 + 给出恢复办法，**不盲发命令**
        missing = call_preview("power.plan", {"action": "set",
                                              "plan": "intentos-no-such-plan",
                                              "dry_run": True})
        self.assertFalse(missing["ok"])
        self.assertNotIn("dry_run", missing)
        self.assertIn("没有名字含", missing["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
