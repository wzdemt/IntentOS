"""系统域原语 —— 事件日志查询与管理（event.*）。

零依赖：走系统自带的 `wevtutil qe ... /f:RenderedXml`（Windows 内置），把 XML 解析成结构化 JSON。
**为什么不直接抄 wevtutil 的文本输出**：中文 Windows 上它给的是本地化的人话表格（列宽还随语言变），
模型得自己猜。这里返回的是：
  时间(ISO) / 事件号 / 级别(数字 + 英文名) / 提供者 / 通道 / 计算机 / 用户 SID / 事件数据(键值)
只有 `message` 一个字段是系统渲染的本地化文本（原文照搬，它会随系统语言变），
其余字段（含 `level_name`）都是数字或英文枚举，不随系统语言变化。

**两条读（只读）**：`event.query` 查某一本日志里的事件；`event.channels` 看这台机器上
**都有哪几本日志本**（名字 / 记录数 / 体积 / 启没启用）—— 查之前先用它确认通道名和有没有内容。

**一条写**：`event.clear` 清空某本日志。⚠️ **清日志 = 抹掉证据** —— 这是攻击者掩盖痕迹的
标准动作，与「关杀毒服务」同一级别的红线。所以它默认只允许清 Application / System 两本，
**安全日志一律硬拒**，且必须 `dry_run=False` + 过确认。详见该原语的说明。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_event，注册进 factory.registry）。
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
import xml.etree.ElementTree as ET

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output, is_admin  # type: ignore

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Windows 事件级别：数字是稳定的，文字是本地化的 → 自己映射成英文名
LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error",
               3: "Warning", 4: "Information", 5: "Verbose"}
_LEVEL_NUM = {"critical": 1, "error": 2, "warning": 3, "information": 4, "verbose": 5}


def _local_iso(system_time: str | None) -> str | None:
    """把事件里的 UTC 时间（2026-09-10T14:02:10.9095532Z）转成本地 ISO 字符串。"""
    if not system_time:
        return None
    s = system_time.strip()
    # .NET 的 7 位小数秒 Python 只认 6 位
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return system_time


def _build_query(level: str, event_id, since_hours) -> str:
    """拼 XPath 过滤式。无条件时用 *（全部）。"""
    conds: list[str] = []
    if level and level.lower() != "any":
        num = _LEVEL_NUM.get(level.lower())
        if num is None:
            raise ValueError(f"level 只能是 any/{'/'.join(_LEVEL_NUM)}，收到 {level!r}")
        conds.append(f"(Level={num})")
    if event_id not in (None, "", 0):
        conds.append(f"(EventID={int(event_id)})")
    if since_hours:
        ms = int(float(since_hours) * 3600000)
        conds.append(f"TimeCreated[timediff(@SystemTime) <= {ms}]")
    return "*" if not conds else "*[System[" + " and ".join(conds) + "]]"


def _parse_events(xml_text: str) -> list[dict]:
    """wevtutil /f:xml 输出是**多个并列的 <Event>**（没有统一根节点），
    直接 fromstring 会报 junk after document element → 外面套一层 <root> 再解析。"""
    if not xml_text.strip():
        return []
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", xml_text)
    try:
        root = ET.fromstring("<root>" + cleaned + "</root>")
    except ET.ParseError as e:
        raise ValueError(f"事件 XML 解析失败：{e}")
    events: list[dict] = []
    for el in root.findall(_NS + "Event"):
        system = el.find(_NS + "System")
        if system is None:
            continue
        level_txt = system.findtext(_NS + "Level")
        level_num = int(level_txt) if (level_txt or "").strip().isdigit() else None
        provider = system.find(_NS + "Provider")
        time_created = system.find(_NS + "TimeCreated")
        security = system.find(_NS + "Security")
        execution = system.find(_NS + "Execution")
        rendering = el.find(_NS + "RenderingInfo")
        data_el = el.find(_NS + "EventData")
        item = {
            "id": int(system.findtext(_NS + "EventID") or 0),
            "level": level_num,
            "level_name": LEVEL_NAMES.get(level_num, "Unknown"),
            "time": _local_iso(time_created.get("SystemTime") if time_created is not None else None),
            "time_utc": time_created.get("SystemTime") if time_created is not None else None,
            "provider": provider.get("Name") if provider is not None else None,
            "channel": system.findtext(_NS + "Channel"),
            "computer": system.findtext(_NS + "Computer"),
            "user_sid": security.get("UserID") if security is not None else None,
            "record_id": int(system.findtext(_NS + "EventRecordID") or 0) or None,
            "process_id": int(execution.get("ProcessID")) if execution is not None and execution.get("ProcessID") else None,
            "keywords": system.findtext(_NS + "Keywords"),
            # ↓ 仅 message 是系统渲染的本地化文本（中文系统上就是中文），其余字段都不随语言变
            "message": (rendering.findtext(_NS + "Message") or "").strip()[:1000] if rendering is not None else None,
            "task": rendering.findtext(_NS + "Task") if rendering is not None else None,
            "opcode": rendering.findtext(_NS + "Opcode") if rendering is not None else None,
        }
        if data_el is not None:
            item["data"] = {d.get("Name") or f"param{i}": (d.text or "")
                            for i, d in enumerate(data_el.findall(_NS + "Data"))}
        events.append(item)
    return events


@declare_primitive(
    "event.query",
    "按通道 / 级别 / 事件号 / 时间范围查 Windows 事件日志，返回**结构化 JSON**"
    "（时间 / 事件号 / 级别英文名 / 提供者 / 用户 SID / 事件数据键值）。"
    "开关机历史、错误排查、登录审计都靠它（例：channel=System + event_id=6005 是开机、6006 是关机）。"
    "⚠️ 动手前先确定通道名与有没有内容：用 `event.channels` 列本机**所有日志本**（名字 / 条数 / 大小），"
    "别靠猜 —— 通道名写错在本条只会得到 count=0，与「这本日志是空的」长得完全一样。"
    "要清日志用 `event.clear`（只允许 Application / System，不可逆、需确认）。"
    "参数：channel（默认 System）、level（any/critical/error/warning/information/verbose，默认 any）、"
    "limit（最多返回几条，默认 10，上限 200）、event_id（只要某个事件号）、since_hours（只要最近 N 小时）。"
    "返回 {ok, channel, count, query, level_names, events:[{id, level, level_name, time, time_utc, provider, "
    "channel, computer, user_sid, record_id, process_id, keywords, message, data}]}："
    "⚠️ count 是本次**返回条数**，count=0 既可能是「没有命中」也可能是「通道名不存在 / 需要管理员」"
    "—— 看 ok 与 note 区分，别当成「这本日志是空的」。"
    "⚠️ 只有 message 是系统渲染的**本地化文本**（中文系统上是中文），其余字段（含 level_name）"
    "都是数字或英文枚举，不随系统语言变。",
    {"type": "object",
     "properties": {
         "channel": {"type": "string", "description": "日志通道，如 System / Application / Security，默认 System"},
         "level": {"type": "string",
                   "enum": ["any", "critical", "error", "warning", "information", "verbose"],
                   "description": "级别过滤，默认 any"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 200,
                   "description": "最多返回几条，默认 10，上限 200（全库统一叫 limit）"},
         "event_id": {"type": "integer", "description": "只查指定事件号（如 6005 开机、6006 关机），可选"},
         "since_hours": {"type": "number", "description": "只查最近 N 小时内的事件，可选"},
     },
     "required": [],
     "additionalProperties": False},
    state={"count": "事件数", "channel": "通道"},
    block="event",
)
def event_query(channel: str = "System", level: str = "any", limit: int = 10,
                event_id=None, since_hours=None) -> dict:
    try:
        xpath = _build_query(level, event_id, since_hours)
    except (ValueError, TypeError) as e:
        return {"ok": False, "channel": channel, "count": 0, "events": [], "note": f"参数无效：{e}"}
    n = max(1, min(int(limit or 10), 200))
    # /f:RenderedXml 才带 RenderingInfo（也就是 message/task/opcode）；/f:xml 不带，实测同价
    cmd = ["wevtutil", "qe", str(channel), f"/q:{xpath}", f"/c:{n}", "/rd:true", "/f:RenderedXml"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60)
    except Exception as e:
        return {"ok": False, "channel": channel, "count": 0, "events": [],
                "note": f"调用 wevtutil 失败：{e}"}
    if r.returncode != 0:
        err = (r.stderr or r.stdout).decode("utf-8", "replace").strip()
        return {"ok": False, "channel": channel, "count": 0, "events": [],
                "note": f"wevtutil 返回 {r.returncode}：{err[:300]}（通道名可能不存在，或需要管理员权限）"}
    try:
        events = _parse_events(r.stdout.decode("utf-8", "replace"))
    except ValueError as e:
        return {"ok": False, "channel": channel, "count": 0, "events": [], "note": str(e)}
    return {"ok": True, "channel": channel, "count": len(events), "query": xpath,
            "level_names": LEVEL_NAMES, "events": events}


# ══════════════════════════════════════════════════════════════════════════
# 日志本清单 / 清空：event.channels · event.clear
# ══════════════════════════════════════════════════════════════════════════
#
# **这两条的数据来源为什么从 wevtutil 换成 PowerShell**（event.query 仍是 wevtutil）：
#   「有哪些日志本、各自多大、多少条、启没启用」= 1100+ 本 × 4 个字段。走 `wevtutil el`
#   再加每本两次调用（`gl` 配置 + `gli` 状态）是 2400 次进程启动、约 40 秒；
#   `Get-WinEvent -ListLog * -Force` **一次调用**就把 1100+ 本全带回来（实测 ~1.8 秒）。
#   ⚠️ **两个实测出来的坑**：
#     ① **非管理员看不到 Security** —— 不是报错，是那一本从结果里**整条消失**
#        （`Get-WinEvent -ListLog Security` 返回码 1、输出空）。所以要用 `wevtutil el`
#        的通道名单补漏（它是权威名单，Security 在内），再用 `wevtutil gl` 拿启用态。
#        「查不到」和「不存在」在日志这件事上必须分清楚 —— 静默少一本比报错危险。
#     ② **返回码不等于成败**：Get-WinEvent 碰到读不了的通道会写「非终止错误」，
#        管道照常出结果、返回码却是 1。判据只能是「有没有解析出东西」，不能看返回码。

# Get-WinEvent 的 LogType 数字 → 名字（数字稳定，不随系统语言变）
LOG_TYPE_NAMES = {0: "Administrative", 1: "Operational", 2: "Analytic", 3: "Debug"}

# Get-WinEvent 列不出来、需要用 wevtutil 逐本补的通道，最多补多少本（兜住时间）
_GAP_FILL_MAX = 200
# 补漏名单的解析目标：PowerShell 的 `/Date(1789142958982)/`
_DATE_MS = re.compile(r"/Date\((\d+)\)/")


def _ps(pipeline: str, timeout: int = 240) -> str:
    """跑一段 PowerShell 管道，返回 stdout；调用失败返回空串。

    ⚠️ **不看返回码** —— 见本段开头的坑②（非终止错误会把返回码变成 1，stdout 却是好的）。
    """
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", pipeline],
                           capture_output=True, timeout=timeout)
    except Exception:
        return ""
    return decode_output(r.stdout or b"")


def _ms_to_iso(value) -> str | None:
    """PowerShell 的 `/Date(1789142958982)/` → 本地 ISO 时间字符串。"""
    m = _DATE_MS.match(str(value or ""))
    if not m:
        return None
    try:
        return _dt.datetime.fromtimestamp(int(m.group(1)) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return None


def _human_size(n) -> str | None:
    """字节 → 人话（「20.0 MB」）。给不出来返回 None。"""
    try:
        f = float(n)
    except (TypeError, ValueError):
        return None
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024:
            return f"{f:.0f} B" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


def _ps_log_rows() -> list[dict]:
    """一次拿全所有日志本（Get-WinEvent -ListLog * -Force）。取不到返回空列表，由调用方降级。"""
    pipeline = ("Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue | "
                "Select-Object LogName,RecordCount,FileSize,IsEnabled,LogType,"
                "MaximumSizeInBytes,LastWriteTime | ConvertTo-Json -Compress -Depth 2")
    text = _ps(pipeline)
    if not text.strip():
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):            # 只有一条时 ConvertTo-Json 给的是对象、不是数组
        data = [data]
    rows: list[dict] = []
    for d in data:
        name = str(d.get("LogName") or "").strip()
        if not name:
            continue
        size, cap, lt = d.get("FileSize"), d.get("MaximumSizeInBytes"), d.get("LogType")
        rows.append({
            "name": name,
            "enabled": bool(d.get("IsEnabled")),
            "log_type": LOG_TYPE_NAMES.get(lt, f"Unknown({lt})" if lt is not None else None),
            "records": d.get("RecordCount"),
            "size_bytes": size,
            "size_human": _human_size(size),
            "max_size_bytes": cap,
            # 占满多少 —— 日志写满就按 LogMode 覆盖旧记录，这是「还剩多少新记录可写」
            "usage_pct": (round(size * 100.0 / cap, 1) if size and cap else None),
            "last_write": _ms_to_iso(d.get("LastWriteTime")),
        })
    return rows


def _wevtutil_names() -> list[str]:
    """`wevtutil el` —— 全部通道名（1 次调用，实测 1193 个）。

    它是**权威名单**：Get-WinEvent 列不出来的通道（Security 最典型）这里有。
    """
    try:
        r = subprocess.run(["wevtutil", "el"], capture_output=True, timeout=60)
    except Exception:
        return []
    if r.returncode != 0:
        return []
    return [ln.strip() for ln in decode_output(r.stdout or b"").splitlines() if ln.strip()]


def _gl_config(name: str) -> dict:
    """`wevtutil gl <通道>` → 配置字典（enabled / type / logfilename / maxsize）。

    输出是「key: value」平铺文本（logging / publishing 两段是缩进子项）；
    冒号只切第一个 —— `logFileName` 的值里有盘符冒号。
    """
    try:
        r = subprocess.run(["wevtutil", "gl", name], capture_output=True, timeout=20)
    except Exception:
        return {}
    if r.returncode != 0:
        return {}
    cfg: dict = {}
    for line in decode_output(r.stdout or b"").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k:
            cfg[k] = v.strip()
    return cfg


def _to_bool(v):
    """「true / false」文本 → 布尔；认不出来返回 None（不猜）。"""
    s = str(v or "").strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    return None


def _gl_row(name: str) -> dict:
    """用 wevtutil 给一本 Get-WinEvent 看不到的日志凑出行（典型：Security）。

    ⚠️ 记录数与体积只能是 None：这类通道 `wevtutil gli` 对非管理员一律「Access is denied」
    （实测 Security）—— 如实返回 null 并说明原因，**不猜、也不假装是 0**（0 会被读成「这本是空的」，
    比 null 错得远）。
    """
    cfg = _gl_config(name)
    cap = cfg.get("maxsize")
    try:
        cap = int(cap) if cap else None
    except ValueError:
        cap = None
    row = {"name": name, "enabled": _to_bool(cfg.get("enabled")),
           "log_type": (cfg.get("type") or "").strip() or None,
           "records": None, "size_bytes": None, "size_human": None,
           "max_size_bytes": cap, "usage_pct": None, "last_write": None,
           "file": cfg.get("logfilename") or None}
    if cfg:
        row["note"] = ("这本日志 Get-WinEvent 读不到（需要管理员权限，或日志文件还没建出来）："
                       "信息来自 wevtutil gl，记录数与体积取不到")
    else:
        row["note"] = "连 wevtutil 也读不到这本日志的配置"
    return row


@declare_primitive(
    "event.channels",
    "列这台机器上的**所有日志本**（事件通道）：名字 / 是否启用 / 类型（Administrative 管理·"
    "Operational 运行·Analytic 分析·Debug 调试）/ 记录条数 / 文件大小与上限 / 占满百分比。"
    "「安全日志有多大」「系统日志还剩多少」「某个组件的通道叫什么名」都靠它 —— "
    "先用它确认通道名和有没有内容，再用 event.query 查具体事件；"
    "要**清空**某本日志用 event.clear（只允许 Application / System，不可逆、需确认）。"
    "日志有一千多本，默认只返回前 100 本：用 name_contains 过滤（如 'Microsoft-Windows-Task'）、"
    "enabled_only=True 只看启用中的，配合 offset 翻页；返回里 truncated=True 表示还有更多，"
    "total 是本机总本数、checked 是本次实际看到的本数、enabled 是其中启用本数。"
    "⚠️ 非管理员会话读不到安全日志（Security）的记录数与体积（那两项为 null 并带 note 说明）；"
    "这类通道的条目仍会列出来，因为「读不到」和「不存在」是两回事。",
    {"type": "object",
     "properties": {
         "name_contains": {"type": "string",
                           "description": "通道名包含该子串才返回（不区分大小写）"},
         "enabled_only": {"type": "boolean",
                          "description": "只看已启用的日志本，默认 False（全列）"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 1000,
                   "description": "最多返回条数，默认 100，上限 1000"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "跳过前 N 条（翻页用），默认 0"},
     },
     "required": [],
     "additionalProperties": False},
    state={"total": "日志本数", "enabled": "启用数"},
    block="event",
)
def event_channels(name_contains: str = "", enabled_only: bool = False,
                   limit: int = 100, offset: int = 0) -> dict:
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    needle = (name_contains or "").strip().lower()
    # 权威名单先拿一份：既用来给「总本数」，也用来补 Get-WinEvent 看不到的通道（Security 最典型）
    names_all = _wevtutil_names()
    rows = _ps_log_rows()
    degraded = ""
    if rows:
        known = {r["name"].lower() for r in rows}
        missing = [n for n in names_all if n.lower() not in known]
        #   ⚠️ 补漏是**按需补**：过滤词先过一遍，只补命中的那几本（否则几十本 × 16ms 白问）
        if needle:
            missing = [n for n in missing if needle in n.lower()]
        if len(missing) > _GAP_FILL_MAX:
            degraded = f"Get-WinEvent 没返回的通道共 {len(missing)} 本，只补了前 {_GAP_FILL_MAX} 本"
            missing = missing[:_GAP_FILL_MAX]
        rows += [_gl_row(n) for n in missing]
    else:
        # 降级：PowerShell 不可用（执行策略 / 精简系统）→ 走 wevtutil 名单，
        # 且只为**当前这一页**取启用态（逐本 gl 要 16ms，整份名单逐本问会慢到没法用）
        names = [n for n in names_all if not needle or needle in n.lower()]
        if not names:
            return {"ok": False, "total": 0, "checked": 0, "enabled": 0, "channels": [],
                    "note": "取不到日志清单：PowerShell 与 wevtutil 都没给出结果"}
        degraded = ("PowerShell 取不到数据（可能被执行策略挡住），已降级为 wevtutil 名单："
                    "记录数与体积为空，启用过滤只作用于已取到的那一页")
        rows = [_gl_row(n) for n in names[:offset + limit]]
    # 补漏只做了「命中过滤词」的那几本，所以 total（系统总数）与 checked（本次实际看到的本数）
    # 必须分开报 —— 否则一加过滤词总数就变小，看着像「系统里日志变少了」
    total = len(names_all) or len(rows)
    checked = len(rows)
    enabled = sum(1 for r in rows if r.get("enabled"))
    if needle:
        rows = [r for r in rows if needle in r["name"].lower()]
    if enabled_only:
        rows = [r for r in rows if r.get("enabled")]
    rows.sort(key=lambda r: r["name"].lower())
    matched = len(rows)
    page = rows[offset:offset + limit]
    more = offset + len(page) < matched
    note = f"本机共 {total} 本日志（通道），本次看到 {checked} 本、其中启用 {enabled} 本"
    if needle or enabled_only:
        note += f"，过滤后 {matched} 本"
    note += f"，本次返回 {len(page)} 本"
    if more:
        note += f"（还有 {matched - offset - len(page)} 本，用 offset={offset + len(page)} 继续取）"
    if degraded:
        note += f"；⚠️ {degraded}"
    return {"ok": True, "total": total, "checked": checked, "enabled": enabled,
            "matched": matched, "returned": len(page), "offset": offset, "truncated": more,
            "channels": page, "log_types": LOG_TYPE_NAMES, "note": note}


# ── 清空日志（不可逆）──────────────────────────────────────────────────────

# 允许清空的只有这两本：装的是常规运行日志，清了顶多丢排查线索，是运维的正常动作。
_CLEARABLE_CHANNELS = {"application": "Application", "system": "System"}
# 硬拒名单：安全日志是**证据**。清它没有正当运维理由 —— 这正是掩盖痕迹的标准动作，
# 与「关掉杀毒服务」同一级别的红线（service.py 的 CRITICAL_SERVICES 是同一条线）。
_EVIDENCE_KEYWORDS = ("security", "audit", "defender", "antimalware", "sysmon",
                      "firewall", "powershell/operational", "wmi/activity",
                      "applocker", "codeintegrity", "smartscreen", "threat")


def _channel_records(channel: str) -> tuple[int | None, str]:
    """某本日志现有多少条记录（`wevtutil gli` 的 numberOfLogRecords）。取不到给 (None, 原因)。

    ⚠️ 这个键名是**英文**的（wevtutil 的键不随系统语言变，值才本地化），所以直接按字面找。
    """
    try:
        r = subprocess.run(["wevtutil", "gli", channel], capture_output=True, timeout=30)
    except Exception as e:
        return None, f"调用 wevtutil 失败：{e}"
    if r.returncode != 0:
        err = (decode_output(r.stderr or b"").strip()
               or decode_output(r.stdout or b"").strip() or f"wevtutil 返回 {r.returncode}")
        return None, err[:160]
    m = re.search(r"numberOfLogRecords:\s*(\d+)", decode_output(r.stdout or b""))
    if not m:
        return None, "wevtutil gli 的输出里没有 numberOfLogRecords"
    return int(m.group(1)), ""


@declare_primitive(
    "event.clear",
    "⚠️ **清空一本事件日志 —— 不可逆，等于抹掉证据**（清日志是攻击者掩盖痕迹的标准动作，"
    "与「关掉杀毒服务」同一级别的红线）。所以门下得很重："
    "① **只允许清 Application（应用）和 System（系统）两本**，其余通道一律拒绝；"
    "② **安全日志（Security）以及审计 / Defender / Sysmon / 防火墙这些取证性质的日志硬拒** —— "
    "清它们没有正当运维理由；③ 真清必须 dry_run=False 且过确认；"
    "④ 返回值里带「清掉了多少条」，留痕；⑤ 需要管理员权限，非管理员直接拒绝（不做提权）。"
    "默认 dry_run=True 只预览：先读一遍现在有多少条记录，但**一条都不动**。"
    "注意：Windows 会在系统日志里为「日志已清除」记一条事件；本原语不做备份，"
    "要留档请先用 event.query 把内容导出来。"
    "⚠️ 不确定本机有哪几本日志、叫什么名、各有多少条，先用 event.channels 列一遍"
    "（通道名写错在本原语只会被拒 —— 别靠猜）。",
    {"type": "object",
     "properties": {
         "channel": {"type": "string",
                     "description": "要清空的日志名，只允许 Application / System（安全日志硬拒）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览（默认）；False=真清空（不可逆）"},
     },
     "required": ["channel"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="event",
)
def event_clear(channel: str, dry_run: bool = True) -> dict:
    name = (channel or "").strip()
    low = name.lower()
    out: dict = {"ok": False, "channel": name, "dry_run": bool(dry_run), "is_admin": is_admin()}
    if not low:
        out["note"] = "channel 不能为空"
        return out
    # ① 只认两本 + 硬拒取证性质的日志（顺序很重要：先讲清是**哪一类**拒绝，
    #    不然「Security 不在白名单里」这种话术会让人以为是配置问题，而不是红线）
    if low not in _CLEARABLE_CHANNELS:
        hit = next((k for k in _EVIDENCE_KEYWORDS if k in low), None)
        if low == "security" or hit:
            why = "安全日志本身" if low == "security" else f"命中取证关键词 {hit!r}"
            out.update({"blocked": True, "evidence_log": True,
                        "note": f"拒绝清空 {name}：{why}，属于取证 / 审计性质的日志 —— "
                                f"清它没有正当运维理由，正是掩盖痕迹的标准动作。本原语不给这个能力"})
            return out
        out.update({"blocked": True,
                    "note": f"拒绝清空 {name}：只允许 Application（应用）与 System（系统）两本。"
                            f"其余通道要么是取证性质的，要么是某个组件自己的运行日志"
                            f"（清了会让它失去排查线索）"})
        return out
    out["channel"] = _CLEARABLE_CHANNELS[low]
    before, why = _channel_records(out["channel"])
    out["records_before"] = before
    if before is None and why:
        out["records_note"] = why
    argv = ["wevtutil", "cl", out["channel"]]
    out["plan"] = " ".join(argv)
    # ② 预览先于权限门：预览是只读的，非管理员也该能看（管理员只影响「真清」那一步）
    if dry_run:
        out["cleared_records"] = 0
        out["note"] = (f"只读预览：**没有清空任何日志**。真执行将清空 {out['channel']} 日志"
                       f"（现有 {before if before is not None else '未知'} 条记录，"
                       f"清掉就再也找不回来）。真执行需 dry_run=False 且过确认"
                       + ("；另外当前会话**不是管理员**，真清会被权限挡住" if not out["is_admin"] else "")
                       + "。")
        return out
    # ③ 权限门：wevtutil cl 必须管理员
    if not out["is_admin"]:
        out["note"] = (f"当前会话不是管理员，无法清空 {out['channel']} 日志（wevtutil cl 需要管理员权限）。"
                       f"请以管理员身份重开后再试；本原语不做提权。")
        return out
    # ④ 真清
    try:
        r = subprocess.run(argv, capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
    except Exception as e:
        out["note"] = f"调用 wevtutil 失败：{e}"
        return out
    text = (decode_output(r.stdout or b"") + decode_output(r.stderr or b"")).strip()
    out["output"] = text[:500]
    out["returncode"] = r.returncode
    if r.returncode != 0:
        out["note"] = f"清空失败（wevtutil 返回 {r.returncode}）：{text[:300] or '无输出'}"
        return out
    after, _why2 = _channel_records(out["channel"])
    out["records_after"] = after
    out["cleared_records"] = (before - after if (before is not None and after is not None) else None)
    cleared = out["cleared_records"] if out["cleared_records"] is not None else "未知数量"
    out.update({"ok": True,
                "note": f"已清空 {out['channel']} 日志：清掉 {cleared} 条（清前 {before} 条，"
                        f"清后 {after} 条），不可逆。Windows 会在系统日志里记一条「日志已清除」"
                        f"事件 —— 这次的清理动作本身同样留痕。"})
    return out
