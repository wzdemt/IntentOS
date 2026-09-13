#!/usr/bin/env python
"""IntentOS 案例测试套件 —— 一条命令跑完全部。

    python tests/smoke_test.py

纯标准库（unittest + 自写 runner），**不依赖 pytest 等任何第三方包** ——
这个项目的卖点之一就是零依赖，测试不该把它破掉。

四组：
  test_readonly_primitives + test_readonly_fs_net
                            只读原语真跑，断言是这台机器的真实数据
  test_dry_run_preview      写类原语只跑 dry_run 预览（铁律：绝不真执行）
  test_security_gate        静态校验 / 执行门（安全门四道闸之一二）
  test_security_paths       路径禁区 / $引用（安全门四道闸之三四）
  test_smoke_full           98 条原语 + 13 个块 + CLI 冒烟

安全：会改状态的原语全程只传 dry_run=True；sound.beep / ui.notify / escape 不参与测试。
详见 tests/helpers.py 顶部的约定。
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import helpers  # noqa: E402  —— 先把项目根挂上 sys.path，再 import 其余模块

MODULES = [
    "test_readonly_primitives",
    "test_readonly_fs_net",
    "test_dry_run_preview",
    "test_security_gate",
    "test_security_paths",
    "test_smoke_full",
]

BANNER = "=" * 72


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:                     # Windows 控制台默认不是 UTF-8，中文会乱码
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print(BANNER)
    print("IntentOS 案例测试套件")
    print(f"  项目根   : {helpers.PROJECT_ROOT}")
    print(f"  已加载原语: {helpers.PRIMITIVE_COUNT} 条")
    print(f"  安全护栏 : 会改状态的原语一律 dry_run=True；"
          f"{'/'.join(sorted(helpers.FORBIDDEN_IN_TESTS))} 不参与测试")
    print(BANNER)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    if argv:                                     # 允许只跑指定的模块
        names = [a if a.startswith("test_") else f"test_{a}" for a in argv]
    else:
        names = MODULES
    for mod in names:
        suite.addTests(loader.loadTestsFromName(mod))

    t0 = time.perf_counter()
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(suite)
    elapsed = time.perf_counter() - t0

    print(BANNER)
    total = result.testsRun
    bad = len(result.failures) + len(result.errors)
    print(f"跑了 {total} 个用例，用时 {elapsed:.1f}s —— "
          f"失败 {len(result.failures)} / 异常 {len(result.errors)} / 跳过 {len(result.skipped)}")
    if result.wasSuccessful():
        print(f"\n✅ 全部通过：{total} 个用例全绿。"
              f"（只读原语真跑过、写类原语只预览过、安全门四道都在守）")
        return 0
    print(f"\n❌ 有 {bad} 个用例没过 —— 这是失败，不是噪音。"
          f"见上面的 traceback；别为了让结果变绿去放宽断言。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or None))
