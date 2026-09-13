"""第 4 组：全量冒烟 —— 装对了、都挂上了、命令行能用。

三条线：
  ① 98 条原语全部加载，且每条都带说明与 schema；
  ② 13 个工具块覆盖无遗漏（blocks.check_coverage() 三类问题都为空）；
  ③ CLI 各子命令能跑起来，且 stdout 上就是结果 JSON（它的输出契约）。

**CLI 一律起子进程跑** —— 那才是用户的真实用法（也顺带验证了「换个进程也装得好」）。
"""
from __future__ import annotations

import json
import os
import unittest

from helpers import (
    PROJECT_ROOT, PRIMITIVE_COUNT, cli_json, registry, run_cli,
)
from core import blocks

EXPECTED_BLOCKS = (
    "filesystem", "network", "display_ui", "process_system", "service_task", "config",
    "power", "disk", "event", "archive", "recycle_shortcut", "device", "escape",
)


class PrimitivesLoaded(unittest.TestCase):
    def test_exactly_98_primitives(self):
        tools = registry.list_tools()
        self.assertEqual(len(tools), 98, f"原语数变了：{len(tools)}")
        self.assertEqual(PRIMITIVE_COUNT, 98)
        native = [n for n, t in tools.items() if t["source"] == "native"]
        self.assertEqual(len(native), 98, "有非 native 来源的原语混进来了")

    def test_every_primitive_is_described_and_typed(self):
        for name, t in registry.list_tools().items():
            with self.subTest(primitive=name):
                self.assertTrue(t["description"].strip(), f"{name} 没有说明")
                schema = t["schema"]
                self.assertIsInstance(schema, dict)
                self.assertEqual(schema.get("type"), "object", f"{name} schema 不是对象")
                self.assertIsInstance(schema.get("properties"), dict, f"{name} 没有 properties")

    def test_naming_convention_has_exactly_one_exception(self):
        """除逃生舱外，所有原语都是 `域.动作`；`escape` 是唯一的单名原语（有意为之）。"""
        dotless = sorted(n for n in registry.list_tools() if "." not in n)
        self.assertEqual(dotless, ["escape"], f"单名原语不止逃生舱一条：{dotless}")

    def test_llm_side_alias_resolves_back(self):
        """发给 LLM 的名字是下划线版（点号会被 API 拒收），执行前必须能还原。"""
        self.assertEqual(registry.resolve_name("system_info"), "system.info")
        self.assertEqual(registry.resolve_name("fs_delete"), "fs.delete")
        self.assertTrue(registry.has("system_info"))
        self.assertEqual(registry.resolve_name("system.info"), "system.info")

    def test_unknown_tool_raises(self):
        with self.assertRaises(ValueError):
            registry.execute("no.such.tool", {})

    def test_describe_returns_chinese_description(self):
        self.assertIn("机器", registry.describe("system.info"))


class BlockCoverage(unittest.TestCase):
    def test_thirteen_blocks(self):
        self.assertEqual(len(blocks.BLOCK_IDS), 13)
        self.assertEqual(tuple(blocks.BLOCK_IDS), EXPECTED_BLOCKS)

    def test_check_coverage_is_clean(self):
        cov = blocks.check_coverage()
        self.assertEqual(cov["missing"], [], "有原语没声明 block")
        self.assertEqual(cov["stale"], [], "块表里挂着不存在的原语")
        self.assertEqual(cov["unknown_block"], [], "有块 id 是拼错的")
        self.assertTrue(cov["ok"])

    def test_catalog_covers_every_primitive(self):
        cats = blocks.export_catalog()
        self.assertEqual(len(cats), 13)
        total = 0
        for c in cats:
            with self.subTest(block=c["id"]):
                self.assertGreater(c["count"], 0, f"{c['id']} 块是空的")
                self.assertEqual(c["count"], len(c["primitives"]))
                self.assertTrue(c["title"] and c["summary"])
                total += c["count"]
        self.assertEqual(total, 98, "块里的原语总数对不上 98")

    def test_escape_block_is_always_on(self):
        esc = next(b for b in blocks.export_catalog() if b["id"] == "escape")
        self.assertTrue(esc["always_on"], "逃生舱必须常驻（模型得随时知道它在）")
        self.assertEqual(esc["primitives"], ["escape"])

    def test_export_block_has_full_declarations(self):
        for bid in blocks.BLOCK_IDS:
            with self.subTest(block=bid):
                out = blocks.export_block(bid)
                self.assertTrue(out["ok"], out.get("note"))
                self.assertGreater(out["count"], 0)
                for p in out["primitives"]:
                    self.assertTrue(p["name"])
                    self.assertTrue(p["description"])
                    self.assertIsInstance(p["schema"], dict)
                    self.assertIsInstance(p["requires_confirmation"], bool)

    def test_unknown_block_reports_instead_of_crashing(self):
        out = blocks.export_block("not_a_block")
        self.assertFalse(out["ok"])
        self.assertIn("没有这个块", out["note"])

    def test_conventions_text(self):
        text = blocks.export_conventions()
        self.assertIn("dry_run", text)
        self.assertIn("确认门", text)

    def test_render_catalog_mentions_every_block(self):
        text = blocks.render_catalog()
        for b in blocks.BLOCKS:
            self.assertIn(b.title, text)


class CliSubcommands(unittest.TestCase):
    """CLI 的契约：stdout 只放结果 JSON，提示走 stderr，退出码有意义。"""

    def test_cli_readonly_call(self):
        out = cli_json("call", "system.info")
        self.assertTrue(out["ok"])
        self.assertEqual(out["platform"], "Windows")

    def test_cli_list(self):
        out = cli_json("list")
        self.assertEqual(out["count"], 98)
        self.assertIn("fs", out["domains"])
        self.assertIn("system", out["domains"])
        self.assertGreater(len(out["domains"]["fs"]), 10)

    def test_cli_list_by_domain(self):
        out = cli_json("list", "power")
        names = [p["name"] for p in out["domains"]["power"]]
        self.assertIn("power.lock", names)
        flags = {p["name"]: p["requires_confirmation"] for p in out["domains"]["power"]}
        self.assertTrue(flags["power.shutdown"])
        self.assertFalse(flags["power.lock"])       # ← 见报告：锁屏不挂确认门，只靠 dry_run

    def test_cli_list_unknown_domain_is_usage_error(self):
        code, _, err = run_cli("list", "nope_domain")
        self.assertEqual(code, 2)
        self.assertIn("nope_domain", err)

    def test_cli_describe(self):
        out = cli_json("describe", "system.info")
        self.assertEqual(out["name"], "system.info")
        self.assertIn("properties", out["schema"])
        self.assertFalse(out["requires_confirmation"])
        hard = cli_json("describe", "fs.delete")
        self.assertTrue(hard["requires_confirmation"])
        self.assertIn("dry_run", hard["schema"]["properties"])

    def test_cli_describe_unknown_is_usage_error(self):
        code, _, err = run_cli("describe", "no.such.tool")
        self.assertEqual(code, 2)
        self.assertIn("册子里没有", err)

    def test_cli_blocks_catalog(self):
        out = cli_json("blocks")
        self.assertEqual(out["count"], 13)
        ids = [b["id"] for b in out["blocks"]]
        self.assertEqual(ids, list(EXPECTED_BLOCKS))
        self.assertIn("【本库通用约定】", out["conventions"])
        self.assertEqual(sum(b["count"] for b in out["blocks"]), 98)

    def test_cli_blocks_expand_one_block(self):
        out = cli_json("blocks", "network")
        self.assertTrue(out["ok"])
        self.assertEqual(out["block"], "network")
        self.assertGreater(out["count"], 0)
        self.assertIn("net.ping", [p["name"] for p in out["primitives"]])

    def test_cli_blocks_text_mode(self):
        out = cli_json("blocks", "--text")
        self.assertIn("逃生舱", out["catalog"])
        self.assertIn("文件与目录", out["catalog"])

    def test_cli_journal(self):
        out = cli_json("journal", "--limit", "5")
        self.assertIsInstance(out["count"], int)
        self.assertIsInstance(out["records"], list)
        self.assertEqual(out["count"], len(out["records"]))
        self.assertLessEqual(out["count"], 5)

    def test_cli_journal_text_mode(self):
        out = cli_json("journal", "--limit", "3", "--text")
        self.assertIsInstance(out["text"], str)

    def test_cli_skill_list(self):
        out = cli_json("skill")
        self.assertIn("proc_detective", out["skills"])

    def test_cli_denies_high_risk_without_confirmation(self):
        """CLI 走的是同一道执行门：无 tty（stdin=DEVNULL）时被拒，退出码 3。"""
        code, out, err = run_cli("call", "fs.delete", "--args",
                                 json.dumps({"path": "D:\\__intentos_never_exists__"}))
        self.assertEqual(code, 3, f"stdout={out!r} stderr={err!r}")
        self.assertIn("无人可确认", err)
        self.assertEqual(out.strip(), "", "被拒时 stdout 不该有结果 JSON")

    def test_cli_allows_dry_run_preview(self):
        code, out, _ = run_cli("call", "fs.delete", "--args",
                               json.dumps({"path": str(PROJECT_ROOT / "README.md"),
                                           "dry_run": True}))
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertIs(r["dry_run"], True)
        self.assertFalse(r["deleted"])
        self.assertTrue((PROJECT_ROOT / "README.md").is_file())

    def test_cli_run_valid_ir(self):
        ir = {"instructions": [
            {"op": "call", "tool": "system.info", "args": {}, "out": "sys"},
            {"op": "finish", "args": {}, "depends_on": ["sys"]},
        ]}
        code, out, err = _run_ir(ir)
        self.assertEqual(code, 0, f"stdout={out!r} stderr={err!r}")
        r = json.loads(out)
        self.assertTrue(r["ok"])
        self.assertEqual(r["workspace"]["sys"]["platform"], "Windows")

    def test_cli_run_invalid_ir_is_rejected_before_execution(self):
        ir = {"instructions": [
            {"op": "call", "tool": "no.such.tool", "args": {}, "out": "a"},
            {"op": "call", "tool": "system.info", "args": {}, "out": "b",
             "depends_on": ["never_defined"]},
        ]}
        code, out, err = _run_ir(ir)
        self.assertEqual(code, 1, f"stdout={out!r} stderr={err!r}")
        r = json.loads(out)
        self.assertFalse(r["ok"])
        self.assertGreaterEqual(len(r["errors"]), 2, r["errors"])

    def test_cli_run_denied_ir_exits_3(self):
        """IR 里带一条没人可确认的高危原语 → 顶层 denied 可见 + 退出码 3。"""
        ir = {"instructions": [
            {"op": "call", "tool": "fs.delete", "args": {"path": "D:\\__intentos_no__"},
             "out": "d"},
        ]}
        code, out, err = _run_ir(ir)
        self.assertEqual(code, 3, f"stdout={out!r} stderr={err!r}")
        r = json.loads(out)
        self.assertFalse(r["ok"])
        self.assertIn("fs.delete", r["denied"])

    def test_cli_usage_error_on_bad_json(self):
        code, _, err = run_cli("call", "system.info", "--args", "{not json")
        self.assertEqual(code, 2)
        self.assertIn("JSON", err)


def _run_ir(ir: dict):
    """把 IR 从 stdin 喂给 `cli.py run -`。"""
    import subprocess
    import sys

    from helpers import CLI_PATH, CLI_TIMEOUT
    env = dict(os.environ)
    env["INTENTOS_JOURNAL"] = "0"
    proc = subprocess.run(
        [sys.executable, str(CLI_PATH), "run", "-"],
        cwd=str(PROJECT_ROOT), input=json.dumps(ir), capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env, timeout=CLI_TIMEOUT)
    return proc.returncode, proc.stdout, proc.stderr


if __name__ == "__main__":
    unittest.main(verbosity=2)
