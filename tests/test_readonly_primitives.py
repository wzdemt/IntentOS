"""第 1 组：只读原语**真跑** —— 断言返回的是这台机器的真实数据。

「真实」不是「结构对」：能跟 Python 标准库独立量出来的量（目录条目数、文件字节数、
磁盘剩余空间、本进程 PID、文件哈希）都做了交叉核对 —— 结构断言只能证明它返回了一个
长得像答案的东西，交叉核对才能证明它真的读了这台机器。
"""
from __future__ import annotations

import datetime
import os
import shutil
import sys
import unittest
from pathlib import Path

from helpers import PROJECT_ROOT, call_readonly, parse_ts


class SystemFacts(unittest.TestCase):
    """这台机器「是什么」—— 只读，真跑。"""

    def test_system_info_fields_and_ranges(self):
        r = call_readonly("system.info")
        self.assertTrue(r["ok"], r.get("note"))
        self.assertEqual(r["platform"], "Windows")
        self.assertTrue(r["machine"])
        self.assertGreater(r["cpu_count"], 0)
        self.assertGreater(r["total_mb"], 0)
        self.assertGreater(r["avail_mb"], 0)
        self.assertLessEqual(r["avail_mb"], r["total_mb"])
        self.assertLessEqual(r["load"], 100)

    def test_system_info_matches_stdlib_cpu_count(self):
        """交叉核对：逻辑核数要和 os.cpu_count() 对得上。"""
        r = call_readonly("system.info")
        self.assertEqual(r["cpu_count"], os.cpu_count())

    def test_system_memory_consistent(self):
        r = call_readonly("system.memory")
        self.assertTrue(r["ok"])
        self.assertGreater(r["total_mb"], 0)
        self.assertLessEqual(r["used_mb"], r["total_mb"])
        self.assertAlmostEqual(r["used_mb"] + r["avail_mb"], r["total_mb"], delta=2)

    def test_system_hardware(self):
        r = call_readonly("system.hardware")
        self.assertTrue(r["ok"])
        self.assertTrue(r["cpu_name"])
        self.assertGreaterEqual(r["logical_cores"], 1)
        self.assertGreaterEqual(r["physical_cores"], 1)
        self.assertLessEqual(r["physical_cores"], r["logical_cores"])

    def test_system_uptime_boot_time_parses(self):
        r = call_readonly("system.uptime")
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["uptime_min"], 0)
        boot = parse_ts(r["boot_at"])
        self.assertLess(boot, datetime.datetime.now() + datetime.timedelta(minutes=1))

    def test_system_load_samples(self):
        r = call_readonly("system.load", {"sample_ms": 200})
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["busy_pct"], 0)
        self.assertLessEqual(r["busy_pct"], 100)
        self.assertAlmostEqual(r["busy_pct"] + r["idle_pct"], 100, delta=1)

    def test_time_zones(self):
        r = call_readonly("time.zones")
        self.assertTrue(r["ok"])
        self.assertTrue(r["zone_id"])
        self.assertIsInstance(r["utc_offset_hours"], (int, float))
        self.assertTrue(parse_ts(r["local_time"]))       # 能解析 = 是真时间戳

    def test_system_idle_time(self):
        r = call_readonly("system.idle_time")
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["idle_seconds"], 0)
        self.assertIsInstance(r["is_away"], bool)


class ProcessFacts(unittest.TestCase):
    def test_process_list_real_and_complete(self):
        r = call_readonly("process.list", {"limit": 15})
        self.assertTrue(r["ok"])
        self.assertGreater(r["count"], 0)
        self.assertEqual(r["count"], len(r["processes"]))
        for p in r["processes"]:
            self.assertTrue(p["name"])
            self.assertTrue(str(p["pid"]).isdigit())
            self.assertGreater(p["mem_bytes"], 0)

    def test_process_info_sees_this_test_process(self):
        """最强的「真数据」证据：它看得见**正在跑这次测试的进程自己**。"""
        me = os.getpid()
        r = call_readonly("process.info", {"pid": me})
        self.assertTrue(r["ok"])
        self.assertTrue(r["found"])
        self.assertEqual(int(r["pid"]), me)
        self.assertEqual(r["name"].lower(), Path(sys.executable).name.lower())

    def test_process_find_matches_a_live_process(self):
        """保证命中：名字先跟 process.list 要一条 —— 它刚说在跑的进程，按名字必须搜得到。

        为什么不写死「搜 python 应该有几个」：这台机器上有没有别的 python 进程是环境决定的，
        而 process.find **有意排掉自己与祖先包装层**（见它的实现注释），所以写死就一定时灵时不灵。
        """
        listing = call_readonly("process.list", {"limit": 1})
        name = listing["processes"][0]["name"]
        r = call_readonly("process.find", {"pattern": name, "by": "name", "limit": 5})
        self.assertTrue(r["ok"])
        self.assertEqual(r["by"], "name")
        self.assertGreaterEqual(r["count"], 1, f"刚列出来的 {name!r} 竟然搜不到")
        self.assertEqual(r["count"], len(r["processes"]))
        for p in r["processes"]:
            self.assertTrue(p["pid"])
            self.assertIn(name.lower(), p["name"].lower())

    def test_process_find_returns_nothing_for_a_bogus_pattern(self):
        """反向：不存在的片段必须 0 命中 —— 否则就是「什么都给」而非「查到了」。"""
        r = call_readonly("process.find",
                          {"pattern": "intentos-no-such-process-xyz", "by": "both"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["count"], 0)
        self.assertEqual(r["processes"], [])

    def test_process_stats_on_self(self):
        r = call_readonly("process.stats", {"pid": os.getpid()})
        self.assertTrue(r["ok"])
        self.assertEqual(int(r["pid"]), os.getpid())
        self.assertGreater(r["working_set_mb"], 0)      # 自己这个进程总得占了点内存
        self.assertGreaterEqual(r["threads"], 1)

    def test_process_foreground(self):
        """前台窗口是哪条进程 —— 有窗口时给进程名，无桌面会话时如实说读不到。"""
        r = call_readonly("process.foreground")
        self.assertTrue(r["ok"], r.get("note"))
        self.assertIsInstance(r["hwnd"], int)
        if r["hwnd"]:
            self.assertTrue(r["name"])


class DiskFacts(unittest.TestCase):
    def test_disk_list_matches_stdlib(self):
        r = call_readonly("disk.list")
        self.assertTrue(r["ok"])
        self.assertGreater(r["count"], 0)
        self.assertEqual(r["count"], len(r["volumes"]))
        drive = os.path.splitdrive(str(PROJECT_ROOT))[0] + os.sep
        vol = next((v for v in r["volumes"] if v["drive"].upper() == drive.upper()), None)
        self.assertIsNotNone(vol, f"disk.list 里没有 {drive}：{r['volumes']}")
        # 交叉核对：剩余空间与 shutil 量的相差不超过 2 GB（两次调用之间有别的进程在写）
        usage = shutil.disk_usage(str(PROJECT_ROOT))
        self.assertAlmostEqual(vol["free_gb"], usage.free / 1024 ** 3, delta=2)
        self.assertAlmostEqual(vol["total_gb"], usage.total / 1024 ** 3, delta=2)
        self.assertLessEqual(vol["used_gb"] + vol["free_gb"], vol["total_gb"] + 1)

    def test_disk_usage_matches_stdlib(self):
        r = call_readonly("disk.usage", {"path": str(PROJECT_ROOT)})
        self.assertTrue(r["ok"], r.get("note"))
        self.assertEqual(Path(r["resolved_path"]), PROJECT_ROOT)
        usage = shutil.disk_usage(str(PROJECT_ROOT))
        self.assertAlmostEqual(r["total_gb"], usage.total / 1024 ** 3, delta=2)
        self.assertAlmostEqual(r["available_gb"], usage.free / 1024 ** 3, delta=2)

    def test_disk_health(self):
        """硬盘健康 —— 读不到 SMART 时如实标不可靠，别把「读不到」当「没问题」。"""
        r = call_readonly("disk.health")
        self.assertTrue(r["ok"], r.get("note"))
        self.assertTrue(r["available"])
        self.assertIsInstance(r["health_reliable"], bool)
        self.assertGreaterEqual(r["count"], 1)
        for d in r["disks"]:
            self.assertTrue(d["name"])
            self.assertGreater(d["size_gb"], 0)
            self.assertTrue(d["health"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
