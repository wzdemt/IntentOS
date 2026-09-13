"""系统配置域原语 —— 开机自启动清单（startup.list）。

零依赖：Python 标准库 `winreg` / `os` / `re` / `subprocess` / `xml.etree`，不加任何第三方库。

**聚合视图原语**：自启动项散落在四个互不相干的地方，平时要看全得一个个翻。
这里一次收齐（对应能力地图「组合 A/B/C/H 但语义极清晰」）：
  ① 注册表 Run / RunOnce —— HKCU 一份 + HKLM 的 64/32 位两个视图
  ② 启动文件夹          —— 用户级 + 系统级（shell:startup）
  ③ 自启动服务          —— HKLM\\SYSTEM\\...\\Services 里 Start=2 的
  ④ 开机 / 登录触发的计划任务 —— `schtasks /query /xml`

**为什么安全价值高**：自启动是持久化的头号落脚点。一条命令看清「这台机器开机
都在跑什么」，排查可疑项 / 清流氓软件 / 装机体检都从它起手。

**只读**，无需 dry_run 与确认。**增删自启动项不在这里** —— 那是写操作，
按地图走 `registry.write` + `fs.*` 的组合（同样标为 IR 模板）。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_startup，注册进 factory.registry）。
"""
from __future__ import annotations

import datetime
import os
import re
import subprocess
import winreg
import xml.etree.ElementTree as ET

from core.factory import declare_primitive  # type: ignore
from primitives._common import (BOOT_LOGON_TRIGGERS, SERVICE_START_TYPES, TASK_XML_NS,
                                decode_output, xml_text)

# ── ① 注册表 Run / RunOnce ──
# 用 KEY_WOW64_64KEY / KEY_WOW64_32KEY 显式指定视图，而不是手写 WOW6432Node 路径 ——
# 后者在 32 位 Python 下会被系统再重定向一层，路径就错了。标志写法与 Python 位数无关。
#
# ⚠️ **HKCU 只扫一份**：WOW64 重定向作用在 HKCU 上的只有 `Software\Classes`，
# `HKCU\...\CurrentVersion\Run` 是**不分视图**的同一个键 —— 补一个 32 位标志读到的
# 是同一份数据（实测两边各 10 条逐条相同），只会凭空造出一倍重复项。
# HKLM 的 `SOFTWARE` 是整棵重定向的，两个视图内容不同（实测 3 条 vs 9 条），必须都扫。
_W64 = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
_W32 = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0)
_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_RUN_ONCE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
_RUN_KEYS = (
    ("HKCU", winreg.HKEY_CURRENT_USER, _RUN, _W64, "Run"),
    ("HKCU", winreg.HKEY_CURRENT_USER, _RUN_ONCE, _W64, "RunOnce"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, _RUN, _W64, "Run"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, _RUN_ONCE, _W64, "RunOnce"),
    ("HKLM(32位)", winreg.HKEY_LOCAL_MACHINE, _RUN, _W32, "Run"),
    ("HKLM(32位)", winreg.HKEY_LOCAL_MACHINE, _RUN_ONCE, _W32, "RunOnce"),
)

# ── ③ 自启动服务 ──
_SERVICE_ROOT = r"SYSTEM\CurrentControlSet\Services"

# ── ④ 计划任务 ──

_SOURCES = ("registry", "folder", "service", "task")


def _read_value(key, name: str):
    """读一个值，不存在 / 读不了都返回 None（自启动排查不该因为一个值缺失就整体失败）。"""
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _fmt_time(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return ""


def _scan_registry() -> tuple[list[dict], list[str]]:
    """扫 Run / RunOnce 八条键。"""
    items: list[dict] = []
    errs: list[str] = []
    for label, hive, sub, access, kind in _RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, sub, 0, access)
        except FileNotFoundError:
            continue                      # 该视图下这条键不存在 —— 正常情况，不是错误
        except OSError as e:
            errs.append(f"{label} {kind} 读取失败：{e}")
            continue
        with key:
            i = 0
            while True:
                try:
                    name, data, _typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                items.append({"source": "registry",
                              "location": f"{label}\\{sub}",
                              "name": name or "(默认)",
                              "kind": kind,
                              "command": data if isinstance(data, str) else str(data),
                              "enabled": True})
    return items, errs


def _scan_folders() -> tuple[list[dict], list[str]]:
    """扫两个「启动」文件夹。

    ⚠️ 里面的 `.lnk` 快捷方式**不解析目标** —— 解析要 COM（IShellLink），
    与「零依赖」冲突。这里给文件名 / 路径 / 大小 / 修改时间，够定位；
    要看指向哪，等 `shell.shortcut_read` 那条能力落地。
    """
    items: list[dict] = []
    errs: list[str] = []
    roots = (
        ("用户启动文件夹",
         os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
        ("系统启动文件夹",
         os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                      r"Microsoft\Windows\Start Menu\Programs\Startup")),
    )
    for label, path in roots:
        if not path or not os.path.isdir(path):
            continue
        try:
            names = sorted(os.listdir(path))
        except OSError as e:
            errs.append(f"{label} 读取失败：{e}")
            continue
        for fn in names:
            if fn.lower() == "desktop.ini":
                continue                  # 文件夹的显示配置，不是自启动项
            fp = os.path.join(path, fn)
            size, mtime = None, ""
            try:
                st = os.stat(fp)
                size, mtime = st.st_size, _fmt_time(st.st_mtime)
            except OSError:
                pass
            items.append({"source": "folder", "location": label, "name": fn,
                          "path": fp, "size": size, "mtime": mtime, "enabled": True})
    return items, errs


def _scan_services(include_drivers: bool) -> tuple[list[dict], list[str]]:
    """扫 Start=2（自动启动）的服务；include_drivers 为真时连驱动（Start=0/1）一起。

    结果自然按启动类型排序集中在 AUTO_START —— 内核驱动数量多且噪音大，默认不列。
    """
    items: list[dict] = []
    errs: list[str] = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICE_ROOT, 0, _W64)
    except OSError as e:
        return items, [f"服务根键读取失败：{e}"]
    with root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                sub = winreg.OpenKey(root, name, 0, _W64)
            except OSError:
                continue                  # 个别服务键当前账户读不了 —— 跳过，不中断
            with sub:
                start = _read_value(sub, "Start")
                if not isinstance(start, int):
                    continue
                is_driver = start in (0, 1)
                if start != 2 and not (include_drivers and is_driver):
                    continue
                items.append({"source": "service",
                              "location": _SERVICE_ROOT,
                              "name": name,
                              "display_name": _read_value(sub, "DisplayName") or "",
                              "start_type": SERVICE_START_TYPES.get(start, f"START={start}"),
                              "is_driver": is_driver,
                              "delayed_auto_start": _read_value(sub, "DelayedAutostart") == 1,
                              "image_path": _read_value(sub, "ImagePath") or "",
                              "enabled": True})
    return items, errs


def _task_triggers(root) -> list[dict]:
    """只留开机（BootTrigger）/ 登录（LogonTrigger）触发的。"""
    node = root.find("t:Triggers", TASK_XML_NS)
    if node is None:
        return []
    out: list[dict] = []
    for child in node:
        kind = child.tag.split("}")[-1]
        if kind not in BOOT_LOGON_TRIGGERS:
            continue
        en = child.find("t:Enabled", TASK_XML_NS)
        out.append({"type": kind,
                    "enabled": en is None or (en.text or "").strip().lower() != "false"})
    return out


def _scan_tasks() -> tuple[list[dict], list[str]]:
    """扫计划任务里带开机 / 登录触发器的。

    **走 `schtasks /query /xml`，不读 `System32\\Tasks` 目录**：那个目录的 ACL 只放行
    管理员，普通用户 `os.listdir` 直接 PermissionError；而 `os.walk` 默认**把错误吞掉**，
    会静默返回 0 条 —— 看着像「查过了，没有」，比报错危险得多。schtasks 普通用户就能列全。

    **也不解析 schtasks 的文本表格**：列名和状态都是本地化文本，中文系统上必崩。
    `/xml` 里的触发器标签是固定英文枚举，跨语言稳定。
    """
    items: list[dict] = []
    try:
        r = subprocess.run(["schtasks", "/query", "/xml"], capture_output=True, timeout=120)
    except Exception as e:
        return items, [f"调用 schtasks 失败：{e}"]
    text = decode_output(r.stdout or b"")
    if r.returncode != 0:
        tail = (decode_output(r.stderr or b"") or text).strip()[:200]
        return items, [f"schtasks 查询失败（返回 {r.returncode}）：{tail}"]
    # 输出不是合法 XML 文档：外层一个裸 <Tasks>，里面每块都自带 XML 声明，
    # 拼在一起没法整体解析 —— 逐块切出来单独喂给 ET。
    blocks = re.findall(r"<Task\b.*?</Task>", text, re.S)
    if not blocks:
        return items, ["schtasks 输出里没找到任务定义（格式可能变了）"]
    for block in blocks:
        try:
            root = ET.fromstring(block)
        except ET.ParseError:
            continue
        triggers = _task_triggers(root)
        if not triggers:
            continue
        ex = root.find("t:Actions/t:Exec", TASK_XML_NS)
        command = ""
        if ex is not None:
            command = f"{xml_text(ex, 'Command')} {xml_text(ex, 'Arguments')}".strip()
        items.append({"source": "task",
                      "location": "计划任务",
                      "name": xml_text(root, "RegistrationInfo/URI") or "(无 URI)",
                      "author": xml_text(root, "RegistrationInfo/Author"),
                      "triggers": triggers,
                      "command": command,
                      "enabled": any(t["enabled"] for t in triggers)})
    return items, []


def _normalize_sources(sources) -> tuple[list[str], str]:
    """把 sources 参数收成合法来源列表。返回 (列表, 错误说明)；错误说明非空表示参数非法。"""
    if sources is None or sources == "" or sources == []:
        return list(_SOURCES), ""
    # 字符串也收：既认单个 "registry"，也认逗号分隔的 "registry, task"（同 registry.read 的路径写法，宽容）
    raw = re.split(r"[,，]", sources) if isinstance(sources, str) else list(sources)
    want: list[str] = []
    bad: list[str] = []
    for s in raw:
        k = str(s).strip().lower()
        if k in _SOURCES:
            if k not in want:
                want.append(k)
        elif k:
            bad.append(k)
    if bad:
        return [], (f"未知来源 {bad}，可选：{' / '.join(_SOURCES)}")
    return (want or list(_SOURCES)), ""


def _matches(item: dict, needle: str) -> bool:
    """名字 / 显示名 / 命令行 / 路径任一命中即可。"""
    if not needle:
        return True
    hay = " ".join(str(item.get(k) or "")
                   for k in ("name", "display_name", "command", "path", "image_path"))
    return needle in hay.lower()


@declare_primitive(
    "startup.list",
    "一次性看清「这台电脑开机都自动启动了啥」—— 聚合四类来源：① 注册表 Run / RunOnce"
    "（HKCU + HKLM 的 64/32 位视图）② 启动文件夹（用户级 + 系统级）③ 自启动服务（Start=2）"
    "④ 开机 / 登录触发的计划任务。"
    "排查可疑持久化 / 清流氓软件 / 装机体检时从它起手 —— 这是「开机跑什么」的**唯一聚合入口**，"
    "下面几条各自只覆盖其中一类：只看服务用 `service.list`（要看某个服务的细节用 `service.info`）、"
    "只看计划任务用 `task.list`（要看某个任务的全貌用 `task.info`；要启停 / 立刻跑某个任务用 "
    "`task.control`、要删掉用 `task.delete`，这两条都需确认）、"
    "看某个进程**此刻**在不在跑用 `process.list` / `process.find`。"
    "参数：sources 只查这几类（registry / folder / service / task，默认四类全查）；"
    "name_contains 按名字 / 显示名 / 命令行 / 路径过滤（不区分大小写）；"
    "include_drivers=True 把内核驱动（Start=0/1）也列进服务那一类（默认 False，驱动多且噪音大）；"
    "limit 是返回总条数上限（默认 300，上限 1000，按来源顺序整体截断）。"
    "返回 {ok, total, returned, truncated, counts, sources, errors, items, note}："
    "每条 item 用 source 字段区分来源，字段随来源不同（registry 有 command；folder 有 path / size；"
    "service 有 display_name / start_type / image_path；task 有 triggers / command）。"
    "⚠️ counts 是各类命中数、total 是四类合计；errors 非空表示**某个来源读取失败**、那一类的 counts 会偏少。"
    "⚠️ 启动文件夹里的 .lnk **不解析指向的目标**（只给文件名/路径），"
    "要看它指向哪用 shell.shortcut_read。",
    {"type": "object",
     "properties": {
         "sources": {"type": "array", "items": {"type": "string",
                                                "enum": ["registry", "folder", "service", "task"]},
                     "description": "只查这几类来源，默认四类全查"},
         "name_contains": {"type": "string",
                           "description": "名字 / 显示名 / 命令行 / 路径包含该子串才返回"
                                          "（不区分大小写），默认不过滤"},
         "include_drivers": {"type": "boolean",
                             "description": "服务那类是否连内核驱动（Start=0/1）一起列，"
                                            "默认 False —— 驱动数量多、噪音大"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 1000,
                   "description": "最多返回多少条（按来源顺序整体截断），默认 300，上限 1000"},
     },
     "required": [],
     "additionalProperties": False},
    block="service_task",
)
def startup_list(sources=None, name_contains: str = "",
                 include_drivers: bool = False, limit: int = 300) -> dict:
    want, err = _normalize_sources(sources)
    if err:
        return {"ok": False, "note": err}
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 300
    needle = (name_contains or "").strip().lower()
    want_drivers = bool(include_drivers)

    items: list[dict] = []
    errors: list[str] = []
    counts: dict[str, int] = {}
    scanners = {
        "registry": lambda: _scan_registry(),
        "folder": lambda: _scan_folders(),
        "service": lambda: _scan_services(want_drivers),
        "task": lambda: _scan_tasks(),
    }
    for src in _SOURCES:                   # 固定顺序输出，结果可预期
        if src not in want:
            continue
        try:
            got, errs = scanners[src]()
        except Exception as e:             # 单类崩了不该拖垮整体
            errors.append(f"{src} 扫描异常：{e}")
            continue
        errors.extend(errs)
        got = [it for it in got if _matches(it, needle)]
        got.sort(key=lambda it: (str(it.get("name", "")).lower(),))
        counts[src] = len(got)
        items.extend(got)

    total = len(items)
    page = items[:limit]
    more = total > limit
    parts = " / ".join(f"{src} {counts.get(src, 0)}" for src in _SOURCES if src in want)
    note = f"共 {total} 条自启动项（{parts}）"
    if more:
        note += f"；已截断到前 {limit} 条，调大 limit 或加 name_contains 缩小范围"
    if needle:
        note += f"；已按 {name_contains!r} 过滤"
    if errors:
        note += "；部分来源读取失败：" + "；".join(errors[:3])
    return {"ok": True, "total": total, "returned": len(page), "truncated": more,
            "counts": {src: counts.get(src, 0) for src in _SOURCES if src in want},
            "sources": list(want), "errors": errors,
            "items": page, "note": note}
