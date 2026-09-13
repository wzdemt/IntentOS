"""进程侦探 —— 进程 × 自启项 × 网络连接，交叉成一份「身份档案」。

**为什么做成一次调用**：原生 agent 要分别调三次（进程 / 自启 / 连接）再自己拼，
而「怎么判断一个进程的来历」这套规则每次都得重想。固化在这里，一次调用拿结论。

**为什么判据是「来历说不说得清」而不是「路径可不可疑」**：实测本机 309 个进程，
「路径不在 Program Files 就可疑」这条判据**完全失效** —— 49 个进程装在 D 盘自建
目录，全是用户自己的软件（VS Code / QQ / Git / Python），一个可疑的都没有；
而「路径在 Temp / 下载 / 盘根」命中 **0** 个，毫无区分度。
真正稳的是问「**这个进程是谁拉起来的**」：父进程是 explorer 就是你双击启动的、
是 services 就是系统拉的、同名就是多进程架构。这个判据**自适应**，不依赖
「某台机器上哪个盘算正常」这种假设 —— 换台机器照样成立。

**它不是「可疑度打分」**：排出前面的几档只表示「需要人扫一眼」，不等于有问题。
所以每条都附上判据依据（`origin_why`），让人能自己复核，而不是给个分数让人信。

调用：`python adapters/cli.py skill proc_detective [--limit 30]`
"""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

_PRIM_DIR = Path(__file__).resolve().parent.parent / "primitives"

# ── 判据用的外部信息 ────────────────────────────────────────────────────
_WIN = (os.environ.get("SystemRoot") or r"C:\Windows").rstrip("\\").lower()
_PROGRAM_DIRS = [
    (os.environ.get("ProgramFiles") or r"C:\Program Files").rstrip("\\").lower(),
    (os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)").rstrip("\\").lower(),
    (os.environ.get("ProgramData") or r"C:\ProgramData").rstrip("\\").lower(),
]

# Windows 核心组件的进程名。**一份名单两处用**：判断「父进程是不是系统」，
# 以及判断「它自己是不是系统组件」。
#
# ⚠️ 名字**单独用不安全** —— 恶意程序完全可以把自己改名成 svchost.exe。所以下面
# `_origin` 里是「名字 + 路径」一起看：名字自称系统、路径却不在系统目录 → 判 mismatch，
# 那反而是最该看的一档。名字只用来**排除误报**，不用来下结论。
_SYSTEM_NAMES = frozenset({
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "conhost.exe",
    "taskhostw.exe", "sihost.exe", "spoolsv.exe", "wudfhost.exe", "wmiprvse.exe",
    "unsecapp.exe", "runtimebroker.exe", "searchindexer.exe", "ctfmon.exe",
    "dllhost.exe", "audiodg.exe", "userinit.exe", "explorer.exe",
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
})

# 来历分档 —— 越靠前越该被先看到。
# ⚠️ 这不是可疑度排序：unexplained / orphan 绝大多数也是正常进程，只是**来历说不清**、
# 需要人扫一眼。真正带「可疑」含义的只有 mismatch（自称系统组件却不在系统目录）。
_ORDER = ["mismatch", "autostart_userdir", "unexplained", "child", "parent_gone",
          "self", "autostart", "service", "system", "user"]

_WHY = {
    "user": "父进程是 explorer.exe —— 你双击启动的",
    "service": "系统拉起来的（父进程是 services / svchost 之类）",
    "system": "Windows 自身组件（名字在核心组件名单里，位置也对得上）",
    "self": "父进程是它自己 —— 程序的多进程架构",
    "child": "父进程是另一个程序（看 parent 字段是谁）",
    "parent_gone": "父进程读不到名字 —— 多半是父进程已经退出了（浏览器、多进程程序常见），"
                   "也可能是权限不够",
    "autostart": "自启项里登记过它，且登记的路径在正常位置",
    "autostart_userdir": "自启项登记过，但**路径在用户目录**（不是 Program Files）—— 这类位置"
                         "既可能是正常软件的用户级安装，也可能是提权跳板，值得看一眼",
    "unexplained": "**父进程读不到、路径读不到、自启项里也没有** —— 来历确实说不清",
    "mismatch": "**名字自称是 Windows 组件，可执行文件却不在系统目录** —— 这正是伪装类"
                "程序的做法，优先核实",
}

# 摘要里用的短标签（_WHY 是给单条看的整句，摘要在同一行里塞不下整句）
_LABEL = {"user": "用户启动", "service": "系统服务", "system": "Windows 组件",
          "self": "自己的子进程", "child": "别的程序启的", "parent_gone": "父进程已退出",
          "autostart": "自启且位置正常", "autostart_userdir": "自启装在用户目录",
          "unexplained": "来历不明", "mismatch": "疑似伪装"}


def _ensure_loaded():
    """按需加载原语。已经有就跳过 —— 重复 load 会白跑一遍登记。"""
    from core.factory import load_primitives, registry
    if registry.list_tools():
        return registry
    load_primitives(str(_PRIM_DIR))
    return registry


def _under(path: str, root: str) -> bool:
    p = path.rstrip("\\").lower()
    return p == root or p.startswith(root + "\\")


def _in_system_dir(path: str) -> bool:
    """可执行文件是不是待在系统 / 程序目录里。"""
    return _under(path, _WIN) or any(_under(path, d) for d in _PROGRAM_DIRS)


def _origin(p: dict, auto_cmd: str = "") -> str:
    """这个进程是谁拉起来的 —— 返回 _ORDER 里的一个代号。

    auto_cmd：命中自启项时那条自启项的**命令行**。父进程和路径都读不到时，它是最后一条线索。
    """
    parent = (p.get("parent_name") or "").strip()
    name = (p.get("name") or "").strip()
    path = (p.get("path") or "").strip()
    pl, nl = parent.lower(), name.lower()

    # ① 先看「**谁**把它拉起来的」—— 这是信息量最大的一条，能答就不必往下走
    if pl == "explorer.exe":
        return "user"
    if pl in _SYSTEM_NAMES:
        return "service"
    if parent and pl == nl:
        return "self"
    if parent:
        return "child"

    # ② 父进程读不到了，这时才看「它自己声称是谁」+ 路径佐证。
    #    实测本机 171 个进程读不到路径 / 父进程，绝大多数是服务类和系统组件 ——
    #    不靠名字排除掉，wininit / csrss / winlogon 这些会被一锅端进「来历不明」。
    if nl in _SYSTEM_NAMES:
        if not path or _in_system_dir(path):
            return "system"
        return "mismatch"      # 名字是系统组件、位置却不对 —— 这才是真该看的

    # ③ 名字也不认识。自启项是最后一条线索 —— 它登记过这个程序，命令行里就带着**它装在哪**。
    #    实测（A 组在测试里挑出来的）：ArcControl.exe 的父进程和路径都读不到（它以高权限跑），
    #    只看进程会把它误判成「来历不明」；可自启项里明明白白写着它在
    #    `C:\Program Files\Intel\Intel Arc Control\` 下 —— 一条线索补上，误报就没了。
    if auto_cmd:
        ap = _exe_path_of(auto_cmd)
        return "autostart" if (ap and _in_system_dir(ap)) else "autostart_userdir"

    # ④ 什么都没有了。⚠️ 有路径但没父进程名字，多半只是**父进程已经退出**
    #    （浏览器、Electron 这类多进程程序很常见），不是可疑信号 —— 所以它排在后面。
    return "parent_gone" if path else "unexplained"


def _exe_path_of(cmd: str) -> str:
    """从自启项命令行里抠出**可执行文件的完整路径**。

    命令行常长这样：`"C:\\Program Files\\X\\a.exe" --minimized --auto`
    —— 带引号的取引号里那段；不带引号的没有明确边界，就取到第一个 `.exe` 为止
    （路径里带空格的裸写法只能这么切，比「取第一个空格前」准）。
    """
    s = (cmd or "").strip()
    if s.startswith('"'):
        s = s[1:].split('"')[0]
    else:
        cut = s.lower().find(".exe")
        s = s[:cut + 4] if cut >= 0 else s.split(" ")[0]
    return s.replace("/", "\\")


def _exe_of(cmd: str) -> str:
    """从自启项命令行里抠出可执行文件名（用来跟进程对上）。"""
    return os.path.basename(_exe_path_of(cmd)).lower()


def detect(limit: int = 30) -> dict:
    """交叉四个来源，给出按「来历说不说得清」排序的进程档案。

    limit：最多返回多少条（默认 30）。总进程数与各档统计**不受它影响**，始终是全量。
    """
    reg = _ensure_loaded()
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 30

    # ① 进程全量（带路径 / 父进程 / 内存）—— 一次 CIM 查询，约 0.7s
    procs = reg.execute("process.list", {"limit": 100000, "detail": True})
    if not procs.get("ok"):
        return {"ok": False, "note": f"读进程失败：{procs.get('note')}"}
    items = procs["processes"]

    # ② 自启项 → {可执行文件名: 自启项}；对不上就说明这个进程不是自启的
    auto: dict[str, dict] = {}
    start = reg.execute("startup.list", {"limit": 2000})
    if start.get("ok"):
        for it in start.get("items", []):
            exe = _exe_of(it.get("command", ""))
            if exe:
                auto.setdefault(exe, it)
    auto_note = "" if start.get("ok") else f"（自启项没读到：{start.get('note')}）"

    # ③ 网络连接 → 按 PID 计数，用来回答「它在联网吗」
    online: Counter = Counter()
    conns = reg.execute("net.connections", {"limit": 10000})
    conn_ok = bool(conns.get("ok"))
    if conn_ok:
        for c in conns.get("connections", []):
            online[str(c.get("pid"))] += 1
    conn_note = "" if conn_ok else f"（连接没读到：{conns.get('note')}）"

    rows = []
    for p in items:
        exe = os.path.basename((p.get("path") or p.get("name") or "").replace("/", "\\")).lower()
        hit = auto.get(exe) or auto.get((p.get("name") or "").lower())
        o = _origin(p, (hit or {}).get("command", ""))
        rows.append({
            "name": p.get("name"), "pid": p.get("pid"),
            "mem_mb": round((p.get("mem_bytes") or 0) / 1048576, 1),
            "origin": o, "origin_why": _WHY[o],
            "parent": p.get("parent_name"),
            "path": p.get("path"),
            "autostart": bool(hit),
            "autostart_where": (f"{hit.get('source')} / {hit.get('name')}" if hit else None),
            "online": online.get(str(p.get("pid")), 0),
        })

    rank = {k: i for i, k in enumerate(_ORDER)}
    # 同一个来历档里：自启的往前、在联网的往前、然后按内存从大到小
    rows.sort(key=lambda r: (rank[r["origin"]], not r["autostart"], -r["online"], -r["mem_mb"]))
    summary = Counter(r["origin"] for r in rows)

    shown = rows[:limit]
    worry = summary["mismatch"] + summary["autostart_userdir"] + summary["unexplained"]
    note = (f"共 {len(rows)} 个进程：" +
            "、".join(f"{_LABEL[k]} {summary[k]}" for k in _ORDER if summary[k]) +
            f"。需要扫一眼的（疑似伪装 + 自启装在用户目录 + 来历不明）有 {worry} 个，排在最前面。")
    if summary["mismatch"]:
        note += f" ⚠️ 其中 {summary['mismatch']} 个疑似伪装成系统组件，优先核实。"
    elif worry == 0:
        note += " 这次一个都没有。"
    note += ("⚠️ 本报告只看**此刻在跑的进程** —— 配了自启但当前没运行的，"
             "它看不见（那些要查 startup.list 或服务/任务列表）。")
    if auto_note or conn_note:
        note += auto_note + conn_note

    return {"ok": True, "total": len(rows), "shown": len(shown),
            "summary": {k: summary[k] for k in _ORDER if summary[k]},
            "processes": shown, "note": note,
            "field_help": {
                "origin": "来历分档（排序依据）。⚠️ 只有 mismatch（名字自称系统组件、"
                          "位置却不在系统目录）带「可疑」含义；unexplained / orphan 排在前面"
                          "只表示「来历说不清、值得扫一眼」，绝大多数是正常的",
                "origin_why": "凭什么这么分 —— 每条都给了依据，可以自己复核",
                "autostart": "这个 exe 出现在自启项里；autostart_where 是它挂在哪、叫什么名字",
                "online": "当前有几个网络连接；0 不代表没联网能力，只代表此刻没有活动连接",
                "parent": "是谁把它拉起来的 —— 这一栏往往比类别更能说明问题",
            }}
