"""第 1 组（续）：文件 / 服务 / 事件 / 网络 —— 只读原语真跑。

只读原语才是可以真跑的：它们不改这台机器的任何状态。能跟标准库/系统独立量出来的量
（目录条目数、文件字节数、哈希、OS 走出来的 .py 文件数）都做了交叉核对。
"""
from __future__ import annotations

import hashlib
import os
import unittest
from pathlib import Path

from helpers import PROJECT_ROOT, call_readonly, parse_ts

README = PROJECT_ROOT / "README.md"


class FileFacts(unittest.TestCase):
    def test_fs_list_matches_os_listdir(self):
        r = call_readonly("fs.list", {"path": str(PROJECT_ROOT), "limit": 0})
        self.assertTrue(r["ok"], r.get("note"))
        self.assertEqual(r["total"], len(os.listdir(PROJECT_ROOT)))
        self.assertEqual(r["count"], r["total"])
        names = {e["name"] for e in r["entries"]}
        self.assertEqual(names, set(os.listdir(PROJECT_ROOT)))
        kind = {e["name"]: e["type"] for e in r["entries"]}
        self.assertEqual(kind["core"], "dir")
        self.assertEqual(kind["README.md"], "file")

    def test_fs_stat_size_matches_stdlib(self):
        r = call_readonly("fs.stat", {"path": str(README)})
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"], "file")
        self.assertEqual(r["size_bytes"], README.stat().st_size)
        self.assertTrue(parse_ts(r["modified"]))

    def test_fs_hash_matches_hashlib(self):
        """比 fs.stat 更硬的核对：算出来的摘要要和 hashlib 一字不差。"""
        r = call_readonly("fs.hash", {"path": str(README), "algorithm": "sha256"})
        self.assertTrue(r["ok"])
        self.assertTrue(r["complete"])
        self.assertEqual(r["digest"],
                         hashlib.sha256(README.read_bytes()).hexdigest())

    def test_fs_search_recursive_matches_os_walk(self):
        r = call_readonly("fs.search", {"pattern": "**/*.py", "path": str(PROJECT_ROOT),
                                        "limit": 0})
        self.assertTrue(r["ok"])
        expected = sum(1 for _, _, files in os.walk(PROJECT_ROOT)
                       for f in files if f.endswith(".py"))
        self.assertEqual(r["total"], expected)
        for m in r["matches"]:
            self.assertTrue(Path(m).is_file())
            self.assertTrue(m.endswith(".py"))

    def test_fs_entries_and_read(self):
        e = call_readonly("fs.entries", {"path": str(PROJECT_ROOT)})
        self.assertTrue(e["ok"])
        self.assertEqual(e["count"], len(e["entries"]))
        rd = call_readonly("fs.read", {"path": str(README), "limit": 2})
        self.assertTrue(rd["ok"])
        self.assertIn("# IntentOS", rd["content"])
        self.assertEqual(rd["lines_returned"], 2)

    def test_fs_grep_finds_real_text(self):
        r = call_readonly("fs.grep", {"path": str(PROJECT_ROOT / "core"),
                                      "pattern": "class ToolRegistry", "max_results": 5})
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["match_count"], 1)
        self.assertIn("class ToolRegistry", r["matches"][0]["text"])

    def test_fs_read_bytes_hash_matches_hashlib(self):
        r = call_readonly("fs.read_bytes", {"path": str(README), "max_read": 64})
        self.assertTrue(r["ok"])
        self.assertEqual(r["bytes_read"], 64)
        self.assertTrue(r["has_more"])
        self.assertEqual(r["size_bytes"], README.stat().st_size)
        # hash_scope=whole：只读了 64 字节，摘要却是**整份文件**的 —— 和 hashlib 对一下
        self.assertEqual(r["sha256"], hashlib.sha256(README.read_bytes()).hexdigest())
        self.assertEqual(r["md5"], hashlib.md5(README.read_bytes()).hexdigest())

    def test_fs_tree_and_size_and_stats(self):
        t = call_readonly("fs.tree", {"path": str(PROJECT_ROOT), "max_depth": 1})
        self.assertTrue(t["ok"])
        self.assertIn("core", t["tree"])
        s = call_readonly("fs.size", {"path": str(README)})
        self.assertTrue(s["ok"])
        self.assertEqual(s["total_bytes"], README.stat().st_size)
        st = call_readonly("fs.stats", {"path": str(PROJECT_ROOT), "max_depth": 1})
        self.assertTrue(st["ok"])
        self.assertGreater(st["file_count"], 0)
        self.assertGreater(st["total_bytes"], 0)

    def test_acl_get_owner_sid(self):
        r = call_readonly("acl.get", {"path": str(README)})
        self.assertTrue(r["ok"])
        self.assertTrue(r["exists"])
        self.assertTrue(r["owner_sid"].startswith("S-1-"))


class ServiceEventFacts(unittest.TestCase):
    def test_service_list_filter_is_real(self):
        r = call_readonly("service.list", {"state": "running", "limit": 5})
        self.assertTrue(r["ok"])
        self.assertEqual(r["returned"], len(r["services"]))
        self.assertGreater(r["total_all"], 0)
        self.assertLessEqual(r["matched"], r["total_all"])
        for s in r["services"]:
            self.assertEqual(s["state"].upper(), "RUNNING")

    def test_service_info(self):
        r = call_readonly("service.info", {"name": "Spooler"})
        self.assertTrue(r["ok"], r.get("note"))
        self.assertEqual(r["name"], "Spooler")
        self.assertTrue(r["state"])
        self.assertTrue(r["binary_path"].lower().endswith(".exe"))

    def test_event_query_real_events(self):
        r = call_readonly("event.query", {"limit": 5})
        self.assertTrue(r["ok"])
        self.assertEqual(r["count"], len(r["events"]))
        self.assertGreater(r["count"], 0)
        # level_names 的键在进程内是 int、过一遍 JSON 就变字符串 —— 两边写法都归一化，
        # 顺便核对「level 数字 → level_name」这张表本身没串行
        levels = {str(k): v for k, v in r["level_names"].items()}
        for e in r["events"]:
            self.assertIsInstance(e["id"], int)
            self.assertTrue(parse_ts(e["time"][:19]))
            self.assertIn(str(e["level"]), levels)
            self.assertEqual(levels[str(e["level"])], e["level_name"])

    def test_event_channels(self):
        r = call_readonly("event.channels", {"limit": 5})
        self.assertTrue(r["ok"])
        self.assertEqual(r["returned"], len(r["channels"]))
        self.assertGreater(r["total"], 0)

    def test_task_and_startup_lists(self):
        t = call_readonly("task.list", {"limit": 5})
        self.assertTrue(t["ok"])
        self.assertEqual(t["returned"], len(t["tasks"]))
        self.assertGreater(t["total_all"], 0)
        st = call_readonly("startup.list", {"limit": 5})
        self.assertTrue(st["ok"])
        self.assertGreater(len(st["items"]), 0)

    def test_task_info_on_a_task_found_by_task_list(self):
        """名字从 task.list 现取 —— 这样任何机器上都跑得通，不写死某台机的任务名。"""
        listing = call_readonly("task.list", {"limit": 1})
        self.assertTrue(listing["tasks"], "这台机器一个计划任务都没有")
        name = listing["tasks"][0]["name"]
        r = call_readonly("task.info", {"name": name})
        self.assertTrue(r["ok"], r.get("note"))
        self.assertEqual(r["name"], name)
        self.assertIsInstance(r["triggers"], list)
        self.assertIsInstance(r["actions"], list)


class NetworkFacts(unittest.TestCase):
    def test_net_interfaces(self):
        r = call_readonly("net.interfaces")
        self.assertTrue(r["ok"])
        self.assertGreater(r["count"], 0)
        self.assertEqual(r["count"], len(r["adapters"]))
        for a in r["adapters"]:
            self.assertTrue(a["name"])
            self.assertTrue(a["status"])

    def test_net_routes(self):
        r = call_readonly("net.routes")
        self.assertTrue(r["ok"])
        self.assertGreater(r["count"], 0)
        for route in r["routes"]:
            self.assertIn("destination", route)
            self.assertIsInstance(route["is_default"], bool)

    def test_net_connections(self):
        r = call_readonly("net.connections", {"limit": 5})
        self.assertTrue(r["ok"])
        self.assertEqual(r["returned"], len(r["connections"]))
        self.assertGreater(r["total_all"], 0)

    def test_net_port_owner_structure(self):
        """只断言结构 —— 445 端口在这台机器上开着，在别人机器上可能关着，
        那是「查不到」不是「查错了」（本库通用约定第 4 条）。"""
        r = call_readonly("net.port_owner", {"port": 445})
        self.assertTrue(r["ok"])
        self.assertEqual(r["port"], 445)
        self.assertEqual(r["count"], len(r["owners"]))

    def test_net_ip_config(self):
        r = call_readonly("net.ip_config")
        self.assertTrue(r["ok"])
        self.assertGreater(r["count"], 0)
        self.assertLessEqual(r["count"], len(r["adapters"]))
        if r["primary_ipv4"]:
            self.assertRegex(r["primary_ipv4"]["ip"], r"^\d+\.\d+\.\d+\.\d+$")

    def test_localhost_network_probes(self):
        """只打本机回环 —— 只读、不出网、不依赖外网可达性。"""
        p = call_readonly("net.ping", {"host": "127.0.0.1", "count": 2})
        self.assertTrue(p["ok"])
        self.assertTrue(p["reachable"])
        self.assertEqual(p["lost"], 0)
        d = call_readonly("net.dns_resolve", {"host": "localhost"})
        self.assertTrue(d["ok"])
        self.assertIn("127.0.0.1", [a["ip"] for a in d["addresses"]])
        t = call_readonly("net.tcp_check", {"host": "127.0.0.1", "port": 445, "timeout": 1})
        self.assertTrue(t["ok"])
        self.assertEqual(t["port"], 445)
        self.assertIsInstance(t["reachable"], bool)      # 开着 / 关着都要如实报


class ArchiveFacts(unittest.TestCase):
    """压缩包只读那两条 —— 素材是测试自己用 zipfile 造的（在临时目录，用完删掉）。"""

    def _fixture(self, scratch):
        import zipfile
        z = scratch / "fixture.zip"
        with zipfile.ZipFile(z, "w") as f:
            f.writestr("hello.txt", "hi")
            f.writestr("sub/nested.txt", "nested")
        return z

    def test_archive_list_reads_a_real_zip(self):
        from helpers import scratch_dir
        with scratch_dir() as scratch:
            z = self._fixture(scratch)
            r = call_readonly("archive.list", {"path": str(z)})
            self.assertTrue(r["ok"], r.get("note"))
            self.assertEqual(r["format"], "zip")
            self.assertEqual(r["file_count"], 2)
            names = {e["name"] for e in r["entries"]}
            self.assertEqual(names, {"hello.txt", "sub/nested.txt"})

    def test_shortcut_read_refuses_non_lnk(self):
        """只解析 .lnk —— 拿别的文件来必须明确说不，不能瞎猜。"""
        from helpers import scratch_dir
        with scratch_dir() as scratch:
            z = self._fixture(scratch)
            r = call_readonly("shell.shortcut_read", {"path": str(z)})
            self.assertFalse(r["ok"])
            self.assertIn("不是 .lnk", r["note"])


class StructureOnly(unittest.TestCase):
    """表驱动：其余只读原语只断言「真跑通了 + 关键字段在 + 类型对」。

    这些都是「本机有什么」类查询（显示 / 电池 / 设备 / 注册表 / 环境变量 / 窗口 /
    剪贴板），字段值随机器而变，不适合硬断言具体数字 —— 但 ok=True 与关键字段
    必须存在，否则就是原语返回结构坏了。
    """

    CASES = [
        ("display.info", {}, ("resolution", "scale", "monitor_count")),
        ("display.monitors", {}, ("count", "monitors")),
        ("display.brightness", {}, ("supported", "percent")),
        ("display.modes", {}, ("current", "resolutions")),
        ("power.battery", {}, ("has_battery", "ac_online")),
        # power.plan 故意不在这张表里：它声明了 requires_confirmation，
        # 于是**连只读地看一眼当前电源计划都要过确认门**（本库通用约定第 3 条）。
        # 它是「需确认」的，所以只在第 2 组里以 dry_run=True 预览的形式出现。
        ("device.printers", {}, ("count", "printers")),
        ("device.usb_list", {}, ("count", "devices")),
        ("env.get", {"limit": 5}, ("variables", "returned", "total_all")),
        ("registry.read", {"path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"},
         ("values", "value_count", "subkey_count")),
        ("reg.assoc", {"ext": ".txt"}, ("ext", "open_with_progids")),
        ("ui.window_list", {"limit": 3}, ("count", "windows", "total_toplevel")),
        ("ui.clipboard_get", {}, ("has_text", "length")),
        ("net.firewall_status", {}, ("profiles", "all_enabled")),
        ("net.io_stats", {}, ("count", "adapters")),
    ]

    def test_contract_table(self):
        for name, args, keys in self.CASES:
            with self.subTest(primitive=name):
                r = call_readonly(name, args)
                self.assertIsInstance(r, dict, f"{name} 没返回 dict")
                self.assertTrue(r.get("ok"), f"{name} ok 不是 True：{r.get('note')}")
                for k in keys:
                    self.assertIn(k, r, f"{name} 少了字段 {k}")

    def test_network_dependent_primitives_honor_contract(self):
        """随机器而异的几条：要么给数据，要么给中文原因 —— 两条都不给才是坏。

        net.wifi_status（台式机没网卡）、net.firewall_rules（需要管理员）都属于
        「读不到 ≠ 没有问题」那一类，按本库通用约定第 4/5 条断言。
        """
        for name, args in (("net.wifi_status", {}), ("net.firewall_rules", {"limit": 3})):
            with self.subTest(primitive=name):
                r = call_readonly(name, args)
                self.assertIsInstance(r.get("ok"), bool)
                if not r["ok"]:
                    self.assertTrue(r.get("note"), f"{name} 失败却没给 note")


if __name__ == "__main__":
    unittest.main(verbosity=2)
