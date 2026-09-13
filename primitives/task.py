"""任务计划域原语 —— 查 Windows 计划任务（task.*）。

零依赖：Python 标准库 `subprocess` / `re` / `csv` / `xml.etree` / `datetime` / `difflib`，
不加任何第三方库。

**为什么单列一个域**：计划任务是「这台机器在没人管的时候会自己做什么」的答案 ——
排查可疑持久化、找谁在半夜跑东西、确认某个更新任务几点跑，都靠它。
`startup.list` 只挑出「开机 / 登录触发」的那一小撮，这里给的是全量 + 细节。

**两条数据来源，各有各的理由（都踩过坑）**：
  ① **结构走 `schtasks /query /xml`**，不读 `C:\\Windows\\System32\\Tasks` 目录 ——
     那个目录的 ACL 只放行管理员，普通用户 `os.listdir` 直接 PermissionError，而
     **`os.walk` 默认把错误吞掉**，会静默返回 0 条：看着像「查过了，没有」，比报错危险得多。
     XML 里的触发器标签是固定英文枚举（BootTrigger / CalendarTrigger…），跨语言稳定。
     ⚠️ 输出的 `<?xml version="1.0" encoding="UTF-16"?>` 是**假声明**（实测是 UTF-8），
     而且外层是一个裸 `<Tasks>`、里面每块自带声明，拼起来不是合法 XML 文档 ——
     必须先按 `<Task>…</Task>` 逐块切出来再单独解析，见 `_split_tasks()`。
  ② **运行态（当前状态 / 下次运行时间）只能走 CSV 输出** —— 任务 XML 里只有**定义**，
     没有「现在什么状态、下次什么时候跑」（那是任务计划程序运行时算出来的）。
     ⚠️ CSV 也有坑：表头行会在输出里**反复出现**上百次；个别任务名带引号/花括号会让
     `csv` 切出来的列数歪掉。所以按「列数一致 + 名字不等于表头列名」筛掉脏行，
     并且按中英双语匹配列名（中文系统上表头是「任务名 / 下次运行时间 / 状态」）。

**只读**：本域两条都是查询，不需要 dry_run 与确认。
建 / 删 / 改任务（`schtasks /create /delete /change`）**不在这里** —— 那是改系统状态的操作，
按安全分级要 dry_run + requires_confirmation，将来单开。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_task，注册进 factory.registry）。
"""
from __future__ import annotations

import csv
import datetime
import difflib
import io
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from core.factory import declare_primitive  # type: ignore
from primitives._common import (BOOT_LOGON_TRIGGERS, TASK_XML_NS,
                                decode_output, is_admin, normalize_path,
                                system_zone_reason, xml_children, xml_text)

# 空值：schtasks 用 N/A 表示「不适用」，中文系统上是「不适用」
_NA = frozenset({"", "n/a", "N/A", "不适用", "-"})

# CSV 列名（英文 + 中文两套）。列顺序由 schtasks 固定，但**列名会本地化**，所以按名字找列。
_COLS = {
    "next_run": ("Next Run Time", "下次运行时间"),
    "status": ("Status", "状态"),
    "last_run": ("Last Run Time", "上次运行时间"),
    "last_result": ("Last Result", "上次结果"),
    "run_as": ("Run As User", "运行方式用户", "以用户身份运行"),
    "command": ("Task To Run", "要运行的任务"),
    "state": ("Scheduled Task State", "计划任务状态"),
    "name": ("TaskName", "任务名"),
}

# 状态 / 启用态的本地化写法 → 统一英文（模型看到的值不随系统语言变）
_STATUS_ALIAS = {"就绪": "Ready", "正在运行": "Running", "已禁用": "Disabled", "禁用": "Disabled",
                 "已排队": "Queued", "已停止": "Stopped", "未知": "Unknown", "准备就绪": "Ready"}
_STATE_ALIAS = {"已启用": "Enabled", "启用": "Enabled", "已禁用": "Disabled", "禁用": "Disabled"}

_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_WEEKDAY_CN = dict(zip(_WEEKDAYS, "周一 周二 周三 周四 周五 周六 周日".split()))
_MONTHS = ("January", "February", "March", "April", "May", "June", "July",
           "August", "September", "October", "November", "December")
_WEEK_ORD = {"First": "第 1 个", "Second": "第 2 个", "Third": "第 3 个",
             "Fourth": "第 4 个", "Last": "最后 1 个"}

# ISO8601 时长（任务 XML 里所有时间都是这个格式：PT30M / P1D / PT1H30M）。
# 注意 `M` 在日期段是「月」、在时间段是「分」—— 靠 `T` 分隔，所以正则要分开写。
_ISO_DUR = re.compile(r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?"
                      r"(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$")

_TIME_FORMATS = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                 "%Y/%m/%d %H:%M", "%Y-%m-%d %H:%M")


# ── 基础工具 ──

def _run(args: list[str], timeout: int = 180) -> tuple[int, str, str]:
    """跑一次 schtasks，返回 (返回码, stdout, stderr)。命令本身失败不该抛异常出去。"""
    try:
        r = subprocess.run(["schtasks"] + args, capture_output=True, timeout=timeout)
    except Exception as e:
        return -1, "", f"调用 schtasks 失败：{e}"
    return r.returncode, decode_output(r.stdout or b""), decode_output(r.stderr or b"")


def _norm(name: str) -> str:
    """任务名归一化：统一反斜杠、去掉开头那个 `\\`、小写 —— 供所有比较/匹配用。

    计划任务的「名字」其实是完整路径（`\\Microsoft\\Windows\\Defrag\\ScheduledDefrag`），
    调用方给的写法五花八门（带不带前导斜杠、正斜杠、大小写），都在这儿收干净。
    """
    return (name or "").strip().replace("/", "\\").lstrip("\\").strip().lower()


def _tree(root) -> tuple[str, str, str]:
    """返回 (完整名, 文件夹, 末段名)。"""
    uri = xml_text(root, "RegistrationInfo/URI")
    leaf = uri.rsplit("\\", 1)[-1] if uri else "(无 URI)"
    folder = uri.rsplit("\\", 1)[0] if "\\" in uri else ""
    return uri or "(无 URI)", folder, leaf


def _split_tasks(text: str) -> list:
    """把 `schtasks /query /xml` 的输出切成一个个已解析的 `<Task>` 根元素。

    ⚠️ 输出**不是合法 XML 文档**：外层一个裸 `<Tasks>`，里面每块都自带 `<?xml ...?>`
    声明，拼在一起无法整体解析 —— 必须逐块切出来单独喂给 ET（这是 startup.py 试出来的坑，
    本文件沿用同一套思路，但不 import 它 —— 那会让它被加载两遍，见 `_common.py` 的说明）。
    """
    out: list = []
    for block in re.findall(r"<Task\b.*?</Task>", text, re.S):
        try:
            out.append(ET.fromstring(re.sub(r"^\s*<\?xml[^>]*\?>", "", block.strip())))
        except ET.ParseError:
            continue                       # 单块坏了跳过，不拖垮整体
    return out


def _load_one(name: str):
    """直接问单个任务（`schtasks /query /tn <名> /xml`）。返回 (根元素 或 None, 来源, 错误说明)。

    这条路比「拉全量再筛」快得多，所以 task.info 优先走它，失败才回退到全量匹配。
    """
    arg = (name or "").strip().replace("/", "\\")
    if not arg.startswith("\\"):
        arg = "\\" + arg                  # /tn 要的是完整路径（含开头那个反斜杠）
    rc, out, err = _run(["/query", "/tn", arg, "/xml"], timeout=60)
    if rc != 0:
        return None, "", ((err or out).strip()[:200] or f"schtasks 返回 {rc}")
    trees = _split_tasks(out)
    if not trees:
        return None, "", "schtasks 没有返回任务定义"
    return trees[0], "schtasks /tn（按完整路径直接取）", ""


def _load_all() -> tuple[list, str]:
    """拉全量任务定义。返回 (根元素列表, 错误说明)。"""
    rc, out, err = _run(["/query", "/xml"])
    if rc != 0:
        return [], f"schtasks 查询失败（返回 {rc}）：{((err or out).strip())[:200]}"
    trees = _split_tasks(out)
    if not trees:
        return [], "schtasks 输出里没找到任务定义（格式可能变了）"
    return trees, ""


def _parse_time(value: str):
    """把「下次运行时间」解析成 datetime 供比较；解析不了返回 None（格式随系统语言变）。"""
    v = (value or "").strip()
    if not v or v in _NA:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def _human_duration(value: str) -> str:
    """ISO8601 时长（`PT30M` / `P1D`）→ 人话（「30 分钟」「1 天」）。翻不动返回空串。

    任务 XML 里所有时间都是 ISO8601，直接丢给模型看等于没给。
    """
    m = _ISO_DUR.match((value or "").strip().upper())
    if not m:
        return ""
    parts: list[str] = []
    for val, unit in zip(m.groups(), ("年", "个月", "周", "天", "小时", "分钟", "秒")):
        if not val:
            continue
        f = float(val)
        if f == 0:
            continue                       # `PT0S` 这类等于「没有」，不占字
        parts.append(f"{int(f) if f.is_integer() else val}{unit}")
    return "".join(parts)          # 「1天2小时」比「1天 2小时」顺


def _pick(node, names, mapping=None) -> list[str]:
    """`<DaysOfWeek><Monday/><Wednesday/></DaysOfWeek>` 这类「点到即选中」的子元素 → 名字列表。"""
    if node is None:
        return []
    got = [n for n in names if node.find("t:" + n, TASK_XML_NS) is not None]
    return [mapping.get(g, g) for g in got] if mapping else got


def _weekly(interval: str, days: list[str]) -> str:
    """「每周的周一、周三」/「每 2 周的周二」—— 周的两种写法共用，省得两处各错一遍。"""
    base = "每周" if interval == "1" else f"每 {interval} 周"
    return base + ("的" + "、".join(days) if days else "")


def _describe_schedule(trigger) -> str:
    """CalendarTrigger 的日历规则翻成人话（每天 / 每周一 / 每月 15 日 / 每月第 2 个周二）。

    触发器 XML 给的是结构化字段，模型要用它得自己再推一遍 —— 这里先推好。
    """
    if trigger.find("t:ScheduleByDay", TASK_XML_NS) is not None:
        n = xml_text(trigger, "ScheduleByDay/DaysInterval") or "1"
        return "每天" if n == "1" else f"每 {n} 天"
    if trigger.find("t:ScheduleByWeek", TASK_XML_NS) is not None:
        n = xml_text(trigger, "ScheduleByWeek/WeeksInterval") or "1"
        ds = _pick(trigger.find("t:ScheduleByWeek/t:DaysOfWeek", TASK_XML_NS), _WEEKDAYS, _WEEKDAY_CN)
        return _weekly(n, ds)
    if trigger.find("t:ScheduleByDayOfWeek", TASK_XML_NS) is not None:
        n = xml_text(trigger, "ScheduleByDayOfWeek/WeeksInterval") or "1"
        ds = _pick(trigger.find("t:ScheduleByDayOfWeek/t:DaysOfWeek", TASK_XML_NS), _WEEKDAYS, _WEEKDAY_CN)
        return _weekly(n, ds)
    if trigger.find("t:ScheduleByMonthDayOfWeek", TASK_XML_NS) is not None:
        ws = _pick(trigger.find("t:ScheduleByMonthDayOfWeek/t:Weeks", TASK_XML_NS),
                   tuple(_WEEK_ORD), _WEEK_ORD)
        ds = _pick(trigger.find("t:ScheduleByMonthDayOfWeek/t:DaysOfWeek", TASK_XML_NS), _WEEKDAYS, _WEEKDAY_CN)
        ms = _pick(trigger.find("t:ScheduleByMonthDayOfWeek/t:Months", TASK_XML_NS), _MONTHS,
                   {k: f"{i + 1}月" for i, k in enumerate(_MONTHS)})
        # 「每月第 2 个周二」：序数词后面直接跟星期几，别插「的」把话读断
        base = f"每月{'、'.join(ws)}{'、'.join(ds)}" if ws else f"每月{'、'.join(ds)}"
        return base + (f"（{'、'.join(ms)}）" if ms else "")
    if trigger.find("t:ScheduleByMonth", TASK_XML_NS) is not None:
        days = [(d.text or "").strip() for d in xml_children(trigger, "ScheduleByMonth/Days")]
        ms = _pick(trigger.find("t:ScheduleByMonth/t:Months", TASK_XML_NS), _MONTHS,
                   {k: f"{i + 1}月" for i, k in enumerate(_MONTHS)})
        ds = "、".join(d for d in days if d) or "?"
        return (f"每年 {'、'.join(ms)}" if ms else "每月") + f" 的 {ds} 日"
    return ""


def _describe_trigger(trigger) -> dict:
    """把一条触发器翻成「什么时候跑」。触发器标签是固定英文枚举，跨语言稳定。"""
    kind = trigger.tag.split("}")[-1]
    out: dict = {"type": kind, "enabled": xml_text(trigger, "Enabled").lower() != "false"}
    if trigger.get("id"):
        out["id"] = trigger.get("id")
    for key, attr in (("StartBoundary", "start"), ("EndBoundary", "end"), ("Delay", "delay"),
                      ("ExecutionTimeLimit", "execution_time_limit"), ("UserId", "user"),
                      ("StateChange", "state_change"), ("StateName", "state_name"),
                      ("Data", "data")):
        v = xml_text(trigger, key)
        if v:
            out[attr] = v
    rep = trigger.find("t:Repetition", TASK_XML_NS)
    if rep is not None:
        r: dict = {}
        for key, attr in (("Interval", "every"), ("Duration", "duration")):
            v = xml_text(rep, key)
            if v:
                r[attr] = v
                human = _human_duration(v)
                if human:
                    r[attr + "_human"] = human
        if xml_text(rep, "StopAtDurationEnd").lower() == "true":
            r["stop_at_duration_end"] = True
        if r:
            out["repetition"] = r
    sched = _describe_schedule(trigger)
    if sched:
        out["schedule"] = sched
    sub = xml_text(trigger, "Subscription")
    if sub:
        out["subscription"] = sub[:300]     # 事件触发器的 XPath 可能很长
    return out


def _triggers(root) -> list[dict]:
    return [_describe_trigger(ch) for ch in xml_children(root, "Triggers")]


def _actions(root) -> list[dict]:
    """执行动作。Exec 是常规的（命令行）；ComHandler 是 COM 组件（没有命令行）。"""
    out: list[dict] = []
    for ch in xml_children(root, "Actions"):
        kind = ch.tag.split("}")[-1]
        if kind == "Exec":
            cmd, args = xml_text(ch, "Command"), xml_text(ch, "Arguments")
            out.append({"kind": "Exec", "command": cmd, "arguments": args,
                        "working_dir": xml_text(ch, "WorkingDirectory"),
                        "command_line": f"{cmd} {args}".strip()})
        elif kind == "ComHandler":
            out.append({"kind": "ComHandler", "class_id": xml_text(ch, "ClassId"),
                        "data": xml_text(ch, "Data")})
        elif kind == "SendEmail":
            out.append({"kind": "SendEmail", "to": xml_text(ch, "To"),
                        "subject": xml_text(ch, "Subject")})
        else:
            out.append({"kind": kind})
    return out


def _principal(root) -> dict:
    """用哪个账户跑。`Author` 是任务自己的那份身份（可能还有别的 Principal）。"""
    pick = None
    for ch in xml_children(root, "Principals"):
        if pick is None or ch.get("id") == "Author":
            pick = ch
        if ch.get("id") == "Author":
            break
    if pick is None:
        return {}
    raw = {"id": pick.get("id", ""), "user_id": xml_text(pick, "UserId"),
           "group_id": xml_text(pick, "GroupId"), "logon_type": xml_text(pick, "LogonType"),
           "run_level": xml_text(pick, "RunLevel")}
    return {k: v for k, v in raw.items() if v}


_SETTING_KEYS = ("Enabled", "Hidden", "AllowStartOnDemand", "StartWhenAvailable",
                 "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "RunOnlyIfIdle",
                 "WakeToRun", "RunOnlyIfNetworkAvailable", "MultipleInstancesPolicy",
                 "ExecutionTimeLimit", "Priority")


def _settings(root) -> dict:
    """任务的运行设置（只挑与「它会不会真跑起来」相关的字段）。"""
    out: dict = {}
    for key in _SETTING_KEYS:
        v = xml_text(root, "Settings/" + key)
        if not v:
            continue
        if key == "ExecutionTimeLimit":
            human = _human_duration(v)
            out[key] = human or v            # PT72H → 「72 小时」，比 ISO 串好读
        else:
            out[key] = v
    interval = xml_text(root, "Settings/RestartOnFailure/Interval")
    count = xml_text(root, "Settings/RestartOnFailure/Count")
    if interval or count:
        out["RestartOnFailure"] = {"interval": _human_duration(interval) or interval,
                                   "count": count}
    return out


def _is_enabled(root) -> bool:
    """任务是否启用。`Settings/Enabled` 缺省即启用（与任务计划程序一致）。"""
    return xml_text(root, "Settings/Enabled").lower() != "false"


def _runtime_rows(extra: list[str] | None = None) -> tuple[dict, str]:
    """跑一次 CSV 输出，返回 (任务名归一化 → 运行态字段, 错误说明)。

    ⚠️ **为什么要读 CSV**：任务 XML 里只有**定义**，没有「现在什么状态、下次什么时候跑」——
    那是任务计划程序运行时算出来的，只在 schtasks 的表格输出里有。
    ⚠️ **CSV 的两个坑**：① 表头行会在输出里**反复出现**（本机 396 行数据里插了 110 个表头），
    不识别就会把表头当成一条任务；② 个别任务名带引号/花括号，`csv` 切出来的列数会歪，
    列数不一致的行直接丢。所以先按「名字列等于列名」筛掉表头行，再按列数筛掉脏行。
    """
    rc, out, err = _run(["/query"] + (extra or []) + ["/fo", "CSV", "/v"])
    if rc != 0:
        return {}, f"schtasks 列表查询失败（返回 {rc}）：{((err or out).strip())[:200]}"
    rows = list(csv.reader(io.StringIO(out)))
    if not rows:
        return {}, "schtasks 的 CSV 输出是空的"
    # 找表头行（可能不在第一行；中文系统上列名是「任务名/下次运行时间/状态」）
    head, cols = -1, {}
    for i, row in enumerate(rows):
        got = {k: j for k, names in _COLS.items()
               for j, cell in enumerate(row) if cell.strip() in names}
        if "name" in got:
            head, cols = i, got
            break
    if head < 0:
        return {}, "schtasks 的 CSV 输出里没找到表头（格式可能变了），本次不返回状态与下次运行时间"
    hdr, name_i, width = rows[head], cols["name"], len(rows[head])
    out_map: dict = {}
    for row in rows[head + 1:]:
        if len(row) != width:
            continue                       # 列数歪掉的脏行（任务名里有引号/花括号时会歪）
        nm = row[name_i].strip()
        if not nm or nm == hdr[name_i].strip():
            continue                       # 反复出现的表头行
        rec = {k: (row[j].strip() if j < len(row) else "")
               for k, j in cols.items() if k != "name"}
        rec["status"] = _STATUS_ALIAS.get(rec.get("status", ""), rec.get("status", ""))
        rec["state"] = _STATE_ALIAS.get(rec.get("state", ""), rec.get("state", ""))
        key = _norm(nm)
        if key in out_map:
            _merge_runtime(out_map[key], rec)
        else:
            out_map[key] = rec
    return out_map, ""


def _merge_runtime(a: dict, b: dict) -> None:
    """一个任务出现多行（每个触发器一行）时怎么合：

    · 状态 —— 有 Running 就用它（「此刻正在跑」最该被看见），否则留第一行
    · 下次运行 —— 取**最早**的那个可解析时间（多触发器时只有其中一行是真正的下一次）
    · 其余 —— 留第一个非空 / 非 N-A 的
    """
    if b.get("status") == "Running":
        a["status"] = "Running"
    t_a, t_b = _parse_time(a.get("next_run", "")), _parse_time(b.get("next_run", ""))
    if t_b and (t_a is None or t_b < t_a):
        a["next_run"] = b["next_run"]
    for k, v in b.items():
        if k in ("status", "next_run"):
            continue
        if v and v not in _NA and (not a.get(k) or a.get(k) in _NA):
            a[k] = v


def _runtime_of(name: str) -> dict:
    """单个任务的运行态（走 `schtasks /query /tn <名> /fo CSV /v`）。取不到就返回 {}。"""
    got, _err = _runtime_rows(["/tn", name])
    if not got:
        return {}
    if _norm(name) in got:
        return got[_norm(name)]
    return next(iter(got.values())) if len(got) == 1 else {}


def _brief(act: dict) -> str:
    """列表里给的命令行：截断，免得上百条任务的命令行把上下文撑爆。"""
    line = act.get("command_line") or act.get("class_id") or ""
    return line if len(line) <= 200 else line[:200] + "…"


@declare_primitive(
    "task.list",
    "列 Windows 计划任务：任务名（完整路径，含所在文件夹）/ 是否启用 / 当前状态 / 下次运行时间 / "
    "是否开机或登录触发 / 执行什么程序。排查「谁在后台定时跑东西」「有没有可疑的持久化任务」"
    "「某个更新任务什么时候跑」都用它。"
    "任务通常有几百个，默认只返回前 50 条：用 name_contains 过滤（任务名带文件夹路径，"
    "如 name_contains='Microsoft' 只看系统任务、'Update' 看更新类）、only_boot_logon=True 只"
    "看开机/登录触发的、配合 offset 翻页；返回里 truncated=True 表示还有更多，"
    "total_all 是系统里的任务总数。"
    "⚠️ status 与 next_run 来自 schtasks 的 CSV 输出（XML 里只有定义、没有运行态），"
    "取不到时为 null，并在 note 里说明。要看某个任务的全部细节用 task.info。"
    "⚠️ 跟 `startup.list` 的分工：本条是**计划任务的全量清单**（几百条，含所有触发类型）；"
    "只关心「开机 / 登录触发」的那一小撮、并且想连带注册表 Run / 启动文件夹 / 自启动服务一起看，"
    "用 `startup.list`（它是「开机跑什么」的聚合入口）。要改任务用 task.control / task.delete（都需确认）。",
    {"type": "object",
     "properties": {
         "name_contains": {"type": "string",
                           "description": "任务名（完整路径）包含该子串才返回（不区分大小写）"},
         "only_boot_logon": {"type": "boolean",
                             "description": "只列开机 / 登录触发的任务，默认 False（全列）"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "最多返回条数，默认 50，上限 500"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "跳过前 N 条（翻页用），默认 0"},
     },
     "required": [],
     "additionalProperties": False},
    block="service_task",
)
def task_list(name_contains: str = "", only_boot_logon: bool = False,
              limit: int = 50, offset: int = 0) -> dict:
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0

    trees, err = _load_all()
    if err:
        return {"ok": False, "note": err}
    runtime, rt_err = _runtime_rows()      # 运行态失败不该让整条原语失败，只降级

    items: list[dict] = []
    for root in trees:
        uri, folder, leaf = _tree(root)
        trigs = _triggers(root)
        types = [t["type"] for t in trigs]
        acts = _actions(root)
        items.append({
            "name": uri, "folder": folder, "leaf": leaf,
            "enabled": _is_enabled(root),
            "boot_or_logon": any(t in BOOT_LOGON_TRIGGERS for t in types),
            "trigger_types": sorted(set(types)),
            "command": _brief(acts[0]) if acts else "",
        })
    total_all = len(items)
    for it in items:
        rec = runtime.get(_norm(it["name"]), {})
        it["status"] = rec.get("status") or None
        it["next_run"] = rec.get("next_run") or None
        it["run_as"] = rec.get("run_as") or None

    needle = (name_contains or "").strip().lower()
    if needle:
        items = [it for it in items if needle in it["name"].lower()]
    if only_boot_logon:
        items = [it for it in items if it["boot_or_logon"]]
    items.sort(key=lambda it: it["name"].lower())
    matched = len(items)
    page = items[offset:offset + limit]
    more = offset + len(page) < matched

    note = f"系统共 {total_all} 个计划任务"
    if needle or only_boot_logon:
        note += f"，过滤后 {matched} 个"
    note += f"，本次返回 {len(page)} 个"
    if more:
        note += f"（还有 {matched - offset - len(page)} 个，用 offset={offset + len(page)} 继续取）"
    if rt_err:
        note += f"；⚠️ 状态与下次运行时间取不到：{rt_err}"
    return {"ok": True, "total_all": total_all, "matched": matched,
            "returned": len(page), "offset": offset, "truncated": more,
            "tasks": page, "note": note}


@declare_primitive(
    "task.info",
    "查单个计划任务的完整定义：全部触发器（是人话描述：每天 3:00 / 登录后延迟 10 分钟 / "
    "开机 30 分钟后 …，含重复间隔与下次运行时间）、执行什么程序（命令行 + 参数 + 工作目录）、"
    "用哪个账户跑（账户 / 登录方式 / 权限级别）、是否启用、以及运行限制（超时 / 错过补跑 / 电池策略）。"
    "name 给任务完整路径（如 \\Microsoft\\Windows\\Defrag\\ScheduledDefrag），"
    "也可以只给最后一段（如 ScheduledDefrag）—— 唯一匹配时自动补全，重名时返回候选列表。"
    "⚠️ 动手改它之前先看本条：要让它**立刻跑一次 / 启停**用 `task.control`（需确认，"
    "其中 run 会把任务当场点燃）；要**删**它用 `task.delete`（不可逆，系统自带任务一律被拒）；"
    "只是想把任务列一遍 / 按关键词搜用 `task.list`；看「开机自动跑什么」的全景用 `startup.list`。"
    "返回 {ok, name, folder, leaf, resolved_by, enabled, boot_or_logon, trigger_count, triggers, actions, "
    "command_line, principal, author, description, version, settings, status, next_run, last_run, last_result, note}："
    "⚠️ resolved_by 是「这个名字是怎么解析到的」（直接取 / 末段唯一匹配 / 全量匹配），名字不完整时看一眼更稳妥。",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "任务名（完整路径，或只给末段名，如 ScheduledDefrag）"},
     },
     "required": ["name"],
     "additionalProperties": False},
    block="service_task",
)
def task_info(name: str) -> dict:
    if not _norm(name):
        return {"ok": False, "note": "任务名不能为空"}
    query = _norm(name)
    # 先直接问单个任务（快）；失败才拉全量做宽容匹配 —— 别为了查一个任务拉 300KB XML
    root, how, msg = _load_one(name)
    if root is None:
        # 直接问失败（名字不完整 / 大小写不对 / 不存在）→ 拉全量做宽容匹配
        trees, err = _load_all()
        if err:
            return {"ok": False, "name": name, "note": f"{msg}；{err}"}
        # (归一化名, 原始名, 根元素)：比较用归一化的，回给调用方的必须是**原始大小写**
        triples = [(_norm(_tree(t)[0]), _tree(t)[0], t) for t in trees]
        exact = [t for u, _o, t in triples if u == query]
        if exact:
            root, how = exact[0], "全量匹配（精确）"
        else:
            # 调用方常只记得最后一段，不记得整条文件夹路径 —— 末段唯一就自动补全
            tail = query.rsplit("\\", 1)[-1]
            if "\\" not in query:
                cand = [(o, t) for u, o, t in triples if u.rsplit("\\", 1)[-1] == tail]
            else:
                cand = [(o, t) for u, o, t in triples if u.endswith("\\" + query)]
            if len(cand) == 1:
                root, how = cand[0][1], "按末段名唯一匹配"
            elif len(cand) > 1:
                return {"ok": False, "name": name, "ambiguous": True,
                        "candidates": [o for o, _ in cand[:20]],
                        "note": f"{name!r} 匹配到 {len(cand)} 个任务，请给完整路径（见 candidates）"}
            else:
                # 给点线索：按**末段名**做近似匹配 —— 拿整条长路径去比相似度会被前缀淹没，
                # 拼错一个末段名也会算成「很不像」；再补上名字里含这段的。
                leaves = {o.rsplit("\\", 1)[-1].lower(): o for _u, o, _t in triples}
                near = [leaves[x] for x in difflib.get_close_matches(tail, list(leaves), n=6, cutoff=0.5)]
                near += [o for _u, o, _t in triples if tail and tail in o.lower()][:5]
                return {"ok": False, "name": name,
                        "suggestions": list(dict.fromkeys(near))[:8],
                        "note": f"找不到任务 {name!r}；suggestions 是名字相近的，"
                                f"也可以用 task.list + name_contains 搜关键词"}
    uri, folder, leaf = _tree(root)
    acts = _actions(root)
    trigs = _triggers(root)
    types = {t["type"] for t in trigs}
    rec = _runtime_of(uri)
    out = {
        "ok": True, "name": uri, "folder": folder, "leaf": leaf,
        "resolved_by": how,
        "enabled": _is_enabled(root),
        "boot_or_logon": bool(types & BOOT_LOGON_TRIGGERS),
        "trigger_count": len(trigs), "triggers": trigs,
        "actions": acts,
        "command_line": next((a.get("command_line", "") for a in acts
                              if a["kind"] == "Exec"), ""),
        "principal": _principal(root),
        "author": xml_text(root, "RegistrationInfo/Author"),
        "description": xml_text(root, "RegistrationInfo/Description"),
        "version": root.get("version", ""),
        "settings": _settings(root),
        "status": rec.get("status") or None,
        "next_run": rec.get("next_run") or None,
        "last_run": rec.get("last_run") or None,
        "last_result": rec.get("last_result") or None,
    }
    if not out["enabled"]:
        out["status"] = out["status"] or "Disabled"
    note = f"{uri}：{len(trigs)} 个触发器，状态 {out['status'] or '未知'}"
    if out["next_run"]:
        note += f"，下次运行 {out['next_run']}"
    if not out["triggers"]:
        note += "；⚠️ 这个任务没有触发器（只能手动 / 被别的程序启动）"
    if not out["actions"]:
        note += "；⚠️ 这个任务没有执行动作（只有触发器）"
    out["note"] = note
    return out


# ══════════════════════════════════════════════════════════════════════════
# 写侧：task.create / task.delete / task.control
# ══════════════════════════════════════════════════════════════════════════
#
# **为什么三条都要重门**（dry_run 默认 True + `requires_confirmation`）：
#
#   · **新建定时任务 = 持久化手法的标准动作** —— 丢个程序 + 建个任务定时跑，就得到一个
#     不依赖当前会话的后门。所以 task.create 在确认之外**再加三道前置判定**：
#       ① **目标程序过系统禁区判定**（`system_zone_reason`）—— 顺带把 System32 下的
#          cmd.exe / powershell.exe / mshta.exe / rundll32.exe 这类「白名单二进制」全挡了；
#          再按**文件名**拦一道 —— 拷一份到用户目录就能绕过路径判定，见 `_BLOCKED_PROGRAM_NAMES`。
#       ② **触发器只开放 5 种**（开机 / 登录 / 每天 / 每周 / 一次）。系统支持的其余类型
#          （MINUTE / HOURLY / ONIDLE / ONEVENT…）刻意不开：事件触发是「等某个日志出现就跑」，
#          高频重复是挖矿/回连的标配，都不该是这个原语的顺手能力。
#       ③ **账户只允许当前用户**，系统账户（SYSTEM / LocalService / NetworkService / 裸 SID）一律拒绝。
#   · **删任务会动系统维护链** —— Windows 自带 180+ 个维护任务（磁盘整理 / 更新 / 字体缓存 /
#     Defender 扫描…）全在 `\Microsoft\Windows\` 下，删了会出问题 → 这部分**一律拒绝**。
#   · **「立刻运行」会把一个既有任务当场点燃**（它可能正在删文件、改配置）→ 同样要确认。
#
# **账户为什么只认当前用户**：schtasks 只要给了 `/RU` 就会要密码（没有 `/RP` 就交互式地问），
# 而本原语**不碰凭据** —— 所以「不给 /RU」（schtasks 默认就是当前用户）才是对的路；
# 子进程一律配 `stdin=DEVNULL`，万一它真要问密码也只会立刻失败，不会把调用方吊住。
#
# **策略粒度**：`requires_confirmation` 是**按原语名**登记的（core 的策略表就是这个名字级），
# 所以 task.control 的启用/停用也走同一道确认门 —— 它们本身可逆、不需要确认，但和
# 「立刻运行」同处一条原语，宁多重问一次，也不放一条能当场执行别人任务的路。


class _Reject(Exception):
    """前置判定拒绝 —— 区分「参数写错」（ValueError）和「安全门不让过」（本异常）。"""

    def __init__(self, msg: str):
        super().__init__(msg)


# 系统自带任务的命名空间。`\Microsoft\Windows\` 下是 Windows 的维护任务；
# `\Microsoft\` 下还有 Office 等自带组件 —— 两个前缀都不由本原语处置。
_SYSTEM_TASK_PREFIX = "microsoft\\windows"
_MICROSOFT_NAMESPACE = "microsoft\\"

# 不允许当「目标程序」的二进制：清一色是系统自带、攻击面最广的一批（脚本宿主 / 下载执行 /
# 注册服务 / 计划任务自身）。**不能只靠路径判定** —— 拷一份到用户目录就绕过系统禁区了，
# 所以这里按**文件名**再拦一道。确有合法用途请走 escape（逃生舱，逐次确认）。
_BLOCKED_PROGRAM_NAMES = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe",
    "schtasks.exe", "reg.exe", "net.exe", "net1.exe", "wmic.exe", "forfiles.exe",
    "installutil.exe", "msbuild.exe", "cmstp.exe", "at.exe", "atbroker.exe",
    "xwizard.exe", "pcalua.exe", "mavinject.exe", "control.exe", "msdt.exe",
    "odbcconf.exe", "runonce.exe", "conhost.exe",
})

# 系统账户：不允许被指定成「用哪个账户跑」。
_SYSTEM_ACCOUNTS = frozenset({
    "system", "nt authority\\system", "localsystem", "local system",
    "localservice", "nt authority\\localservice", "local service",
    "networkservice", "nt authority\\networkservice", "network service",
    "s-1-5-18", "s-1-5-19", "s-1-5-20", "trustedinstaller", "iusr",
})

# 开放的触发器类型 → schtasks 的 /SC 取值。
_TRIGGER_TO_SC = {"daily": "DAILY", "weekly": "WEEKLY", "once": "ONCE",
                  "boot": "ONSTART", "logon": "ONLOGON"}
# 每周的星期几：只认三字母缩写（也接受全拼，取前三个字母）。
_WEEKDAY_SC = {"mon": "MON", "tue": "TUE", "wed": "WED", "thu": "THU",
               "fri": "FRI", "sat": "SAT", "sun": "SUN"}
_WEEKDAY_CN_SHORT = {"MON": "周一", "TUE": "周二", "WED": "周三", "THU": "周四",
                     "FRI": "周五", "SAT": "周六", "SUN": "周日"}

# schtasks /TR 的硬上限（超了任务建不出来，报 "The task run is too long"），先拦一道给人话。
_TR_MAX = 261

# 与系统安全 / 更新相关的任务：停用或中止它们 = 关掉系统防护（与 service.py 的关键服务黑名单同级）。
_PROTECTED_TASK_KEYWORDS = ("defender", "antimalware", "\\security", "security\\",
                            "windows update", "windowsupdate", "updateorchestrator",
                            "firewall", "sysmon", "\\audit", "audit\\")


def _current_user() -> str:
    """当前登录用户名（不带域）。不给 /RU 时 schtasks 用的就是这个账户。"""
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "").strip()


def _render_cmd(argv: list[str]) -> str:
    """把 argv 渲染成一行可读、可复制的命令（含空格的参数加引号）—— 只是**给人看的预览**，
    真正传给 subprocess 的是原始 argv（list），不经过这一层拼串。已经自带引号的参数不再加一层。"""
    return " ".join(a if ((" " not in a and "\t" not in a) or a.startswith('"')) else f'"{a}"'
                    for a in argv)


def _resolve_task(name: str) -> tuple[str, object, str, str]:
    """把调用方给的写法解析成**要动手的那个任务**。返回 (完整路径名, 根元素|None, 匹配方式, 错误说明)。

    容错规则与 task.info 一致（先按完整路径直接问 → 再全量：精确 → 末段唯一 → 近似提示），
    区别只在**这里解析出来是要动手的**：匹配到多个一律拒绝，绝不猜 —— 删错一个任务的代价
    比让人重新输一次名字大得多。
    """
    root, how, msg = _load_one(name)
    if root is not None:
        return _tree(root)[0], root, how, ""
    trees, err = _load_all()
    if err:
        return "", None, "", f"{msg}；{err}"
    triples = [(_norm(_tree(t)[0]), _tree(t)[0], t) for t in trees]
    q = _norm(name)
    for u, o, t in triples:
        if u == q:
            return o, t, "全量匹配（精确）", ""
    tail = q.rsplit("\\", 1)[-1]
    # 调用方常只记得末段名 → 末段唯一就自动补全；带了文件夹就按后缀匹配
    if "\\" not in q:
        cand = [(o, t) for u, o, t in triples if u.rsplit("\\", 1)[-1] == tail]
    else:
        cand = [(o, t) for u, o, t in triples if u.endswith("\\" + q)]
    if len(cand) == 1:
        return cand[0][0], cand[0][1], "按末段名唯一匹配", ""
    if len(cand) > 1:
        return "", None, "", (f"{name!r} 匹配到 {len(cand)} 个任务，请给完整路径："
                              + "、".join(o for o, _ in cand[:8]))
    leaves = {o.rsplit("\\", 1)[-1].lower(): o for _u, o, _t in triples}
    near = [leaves[x] for x in difflib.get_close_matches(tail, list(leaves), n=5, cutoff=0.5)]
    hint = f"；名字相近的有：{'、'.join(dict.fromkeys(near))}" if near else ""
    return "", None, "", f"找不到任务 {name!r}{hint}"


def _system_task_reason(uri: str) -> str | None:
    """这个任务是不是系统自带的。返回中文理由，不是则 None（判据就是命名空间）。

    判据只有「命名空间」这一条 —— 不去猜任务名里有没有 UPDATE / Defrag 这类词：
    系统任务全在 `\\Microsoft\\Windows\\` 下（本机 208 个任务里 181 个是），而第三方任务
    （OneDrive / 酷狗 / WPS…）在根或自己的文件夹里。按命名空间判，误伤和漏网的都少。
    """
    n = _norm(uri)
    if n == _SYSTEM_TASK_PREFIX or n.startswith(_SYSTEM_TASK_PREFIX + "\\"):
        return ("系统自带任务（\\Microsoft\\Windows\\ 下：磁盘整理 / 更新 / 字体缓存 / "
                "Defender 扫描等 Windows 维护链）")
    if n.startswith(_MICROSOFT_NAMESPACE):
        return "微软自带组件的任务（\\Microsoft\\ 命名空间下）"
    return None


def _protected_task_reason(uri: str) -> str | None:
    """这个任务是不是「动它等于关防护」。返回中文理由，不是则 None。"""
    n = _norm(uri)
    for kw in _PROTECTED_TASK_KEYWORDS:
        if kw in n:
            return f"与系统安全 / 更新相关（命中关键词 {kw!r}）：停用或中止它等于关掉系统防护"
    return None


def _parse_hhmm(value) -> str:
    """时间 → schtasks 要的 `HH:MM`（24 小时制）。"""
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(value or "").strip())
    if not m:
        raise ValueError(f"trigger.time 要写成 HH:MM（24 小时制），收到 {value!r}")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def _parse_delay(value) -> str:
    """延迟写法 → schtasks 要的 `mmmm:ss`（5 分钟 → `0005:00`）。

    接受 `5m` / `30s` / `1h` / `1h30m` / 裸数字（按分钟）/ 已经是 `0005:00` 的写法。
    `/DELAY` 的格式是**四位分钟:两位秒**，不是 ISO8601，跟任务 XML 里那套不一样，别混。
    """
    v = str(value or "").strip().lower()
    m = re.fullmatch(r"(\d{1,4}):([0-5]\d)", v)
    if m:
        return f"{int(m.group(1)):04d}:{m.group(2)}"
    total, pos = 0, 0
    for tok in re.finditer(r"(\d+)\s*([hms]?)", v):
        if tok.start() != pos:
            break
        pos = tok.end()
        total += int(tok.group(1)) * {"h": 3600, "m": 60, "s": 1}[tok.group(2) or "m"]
    if pos != len(v) or total <= 0:
        raise ValueError(f"trigger.delay 写法看不懂：{value!r}（例：5m / 30s / 1h30m / 0005:00）")
    if total > 7 * 86400:
        raise ValueError("trigger.delay 最长 7 天")
    return f"{total // 60:04d}:{total % 60:02d}"


def _parse_date(value) -> str:
    """日期 → schtasks 要的 `yyyy/mm/dd`（只认 ISO 写法 `yyyy-mm-dd`，好校验）。"""
    v = str(value or "").strip()
    try:
        d = datetime.date.fromisoformat(v)
    except ValueError:
        raise ValueError(f"trigger.date 要写成 yyyy-mm-dd（如 2026-09-20），收到 {value!r}")
    return f"{d.year:04d}/{d.month:02d}/{d.day:02d}"


def _build_trigger(tr) -> tuple[list[str], str]:
    """结构化触发器 → (schtasks 参数, 人话描述)。不合规抛 ValueError。

    ⚠️ 只开放 5 种类型（见文件顶部说明）：**能开什么触发，是这个原语的安全边界本身** ——
    开放 ONEVENT 就等于「等某个日志出现就跑」，开放 MINUTE 就等于「常驻轮询」。
    """
    if not isinstance(tr, dict):
        raise ValueError('trigger 必须是对象，如 {"type": "daily", "time": "03:00"}')
    kind = str(tr.get("type") or "").strip().lower()
    if kind not in _TRIGGER_TO_SC:
        raise ValueError(f"trigger.type 只能是 {'/'.join(sorted(_TRIGGER_TO_SC))}，"
                         f"收到 {tr.get('type')!r}（MINUTE / HOURLY / MONTHLY / ONIDLE / "
                         f"ONEVENT 等类型刻意不开放）")
    unknown = set(tr) - {"type", "time", "date", "days", "every", "delay"}
    if unknown:
        raise ValueError(f"trigger 里有不认识的字段：{'、'.join(sorted(unknown))}")

    # ① 开机 / 登录：只有「延迟多久跑」有意义
    if kind in ("boot", "logon"):
        for k, hint in (("time", "定点请用 daily / weekly / once"),
                        ("date", "定点请用 once"),
                        ("days", "开机 / 登录每天都会触发，不用给 days"),
                        ("every", "要「过一会儿再跑」请用 delay")):
            if tr.get(k) is not None:
                raise ValueError(f"trigger.type={kind} 不接受 trigger.{k}（{hint}）")
        args = ["/sc", _TRIGGER_TO_SC[kind]]
        desc = "开机时" if kind == "boot" else "任一用户登录时"
        if tr.get("delay") is not None:
            d = _parse_delay(tr["delay"])
            args += ["/delay", d]
            secs = int(d[:4]) * 60 + int(d[5:])      # mmmm:ss → 秒
            if secs >= 3600:
                desc += f"，延迟 {secs // 3600} 小时 {(secs % 3600) // 60} 分钟"
            elif secs >= 60:
                desc += f"，延迟 {secs // 60} 分钟"
            else:
                desc += f"，延迟 {secs} 秒"
        return args, desc

    # ② 定点类：都要 HH:MM
    if tr.get("time") is None:
        raise ValueError(f"trigger.type={kind} 必须给 trigger.time（HH:MM）")
    hhmm = _parse_hhmm(tr["time"])
    args = ["/sc", _TRIGGER_TO_SC[kind], "/st", hhmm]
    if tr.get("delay") is not None:
        raise ValueError(f"trigger.type={kind} 不接受 trigger.delay（只有 boot / logon 支持）")

    if kind == "daily":
        if tr.get("days") is not None or tr.get("date") is not None:
            raise ValueError("trigger.type=daily 不接受 days / date（每周请用 weekly，只跑一次用 once）")
        desc = f"每天 {hhmm}"
        if tr.get("every") is not None:
            n = _int_in(tr["every"], 1, 365, "trigger.every（每 N 天）")
            args += ["/mo", str(n)]
            desc = f"每 {n} 天 {hhmm}" if n > 1 else desc
        return args, desc

    if kind == "weekly":
        days = tr.get("days")
        if not isinstance(days, (list, tuple)) or not days:
            raise ValueError('trigger.type=weekly 必须给 trigger.days，如 ["mon", "fri"]')
        codes: list[str] = []
        for d in days:
            key = str(d or "").strip().lower()[:3]
            if key not in _WEEKDAY_SC:
                raise ValueError(f"trigger.days 里 {d!r} 不认识（只认 mon/tue/wed/thu/fri/sat/sun）")
            if _WEEKDAY_SC[key] not in codes:
                codes.append(_WEEKDAY_SC[key])
        args += ["/d", ",".join(codes)]
        desc = "每周" + "、".join(_WEEKDAY_CN_SHORT[c] for c in codes) + f" {hhmm}"
        if tr.get("every") is not None:
            n = _int_in(tr["every"], 1, 52, "trigger.every（每 N 周）")
            args += ["/mo", str(n)]
            if n > 1:
                desc = f"每 {n} 周" + "、".join(_WEEKDAY_CN_SHORT[c] for c in codes) + f" {hhmm}"
        return args, desc

    # kind == once
    if tr.get("days") is not None or tr.get("every") is not None:
        raise ValueError("trigger.type=once 不接受 days / every")
    desc = f"只在 {hhmm} 跑一次"
    if tr.get("date") is not None:
        sd = _parse_date(tr["date"])
        args += ["/sd", sd]
        desc = f"只在 {sd} {hhmm} 跑一次"
    return args, desc


def _int_in(value, lo: int, hi: int, label: str) -> int:
    """整数区间校验（给 interval 这类字段用）。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} 要填整数，收到 {value!r}")
    if not lo <= n <= hi:
        raise ValueError(f"{label} 要在 {lo}–{hi} 之间，收到 {n}")
    return n


def _zone_reject(target: str, verb: str) -> str | None:
    """路径安全判定：共享层的系统禁区 + **盘根下的文件**这条更严的本地规则。

    为什么要在共享层之上再加一条：`system_zone_reason` 拦的是「盘根目录本身」和系统目录，
    而 `C:\\payload.exe`（**盘根下的文件**）它会放行 —— 那恰恰是投放式持久化最经典的落点
    （文件名短、显眼、且常被当成「工具」）。共享层自己也说了「删/改类动作可能想要更严的规则，
    那是在这一层之上再加的，不塞进去」—— 这里加的就是那条。
    """
    reason = system_zone_reason(target, verb)
    if reason:
        return reason
    parent = target.rsplit("\\", 1)[0] if "\\" in target else ""
    if len(parent) <= 2 and parent[1:2] == ":":       # 父目录是 `C:\` 这种盘根
        return f"盘根目录下的文件（{target}）不允许{verb}：这是投放式持久化最常见的落点"
    return None


def _build_action(action) -> tuple[str, dict]:
    """结构化执行动作 → (/TR 的值, 详情)。不合规抛 ValueError，过不了安全门抛 _Reject。

    ⚠️ **目标程序是本原语最要紧的一道门**：任务动作 = 「以后每次都由系统替你启动这个程序」，
    等于把「这一次的执行权」交出去无数次。所以：
      · 系统目录（Windows / Program Files / ProgramData）与盘根下的文件一律不当目标（`_zone_reject`）
      · 系统自带的高危工具按**文件名**再拦一道（拷到用户目录也不算数）
      · 只收完整路径：裸名字（靠 PATH 找）先解析成绝对路径再判，解不出来就拒绝
    """
    if not isinstance(action, dict):
        raise ValueError('action 必须是对象，如 {"program": "C:\\\\Tools\\\\x.exe"}')
    unknown = set(action) - {"program", "arguments", "working_dir"}
    if unknown:
        raise ValueError(f"action 里有不认识的字段：{'、'.join(sorted(unknown))}")
    program = str(action.get("program") or "").strip()
    if not program:
        raise ValueError("action.program 不能为空")
    if any(c in program for c in '"\r\n\x00'):
        raise ValueError("action.program 里不允许引号与换行（会破坏 /TR 的解析）")

    raw = os.path.expandvars(os.path.expanduser(program))
    if not os.path.isabs(raw):
        found = shutil.which(raw)
        if not found:
            raise _Reject(f"找不到程序 {program!r}：只收完整路径，不接受靠 PATH 找的裸名字"
                          f"（裸名字解析不到，就没法判它落在哪个目录）")
        raw = found
    try:
        target = normalize_path(raw)
    except ValueError as e:
        raise ValueError(f"action.program 无效：{e}")
    reason = _zone_reject(target, "作为计划任务的目标程序")
    if reason:
        raise _Reject(f"拒绝把 {target} 当计划任务的目标程序：{reason}")
    base = target.rsplit("\\", 1)[-1].lower()
    if base in _BLOCKED_PROGRAM_NAMES:
        raise _Reject(f"拒绝用 {base} 当计划任务的目标程序：脚本宿主 / 下载执行 / 注册服务这类"
                      f"系统自带工具是持久化与横向移动最常用的落地件。确有合法用途请走 escape"
                      f"（逃生舱，每次都要用户点头）")

    if os.path.isdir(target):
        raise ValueError(f"action.program 指向的是一个目录（{target}），不是程序")
    details: dict = {"program": target, "exists": os.path.isfile(target)}
    if not details["exists"]:
        details["warning"] = (f"{target} 现在不存在 —— 任务仍会被建出来，但到点跑不起来"
                              f"（也请注意：「先建任务、程序以后再放」正是投放式持久化的姿势，"
                              f"所以这条会留在返回值里）")
    args = str(action.get("arguments") or "").strip()
    wd = str(action.get("working_dir") or "").strip()
    if wd:
        try:
            wd_norm = normalize_path(wd)
        except ValueError as e:
            raise ValueError(f"action.working_dir 无效：{e}")
        reason = system_zone_reason(wd_norm, "作为计划任务的工作目录")
        reason = _zone_reject(wd_norm, "作为计划任务的工作目录")
        if reason:
            raise _Reject(f"拒绝把 {wd_norm} 当计划任务的工作目录：{reason}")
        details["working_dir"] = wd_norm
    # /TR 收的是**一整条命令行**（程序 + 参数），这也是为什么不把拼串的事交给调用方：
    # 结构化进来、这里统一拼，拼出来的东西才有机会被判一遍长度与内容。
    tr_value = (f'"{target}" {args}' if " " in target else f"{target} {args}").strip()
    if len(tr_value) > _TR_MAX:
        raise ValueError(f"程序加参数过长（{len(tr_value)} > {_TR_MAX} 字符），schtasks 建不出来")
    details["command_line"] = tr_value
    if args:
        details["arguments"] = args
    return tr_value, details


@declare_primitive(
    "task.create",
    "新建一个 Windows 计划任务（需确认；**「新建定时任务」是持久化手法的标准动作**，所以门很重）。"
    "参数是**结构化对象**，不要让调用方拼命令行：trigger 说什么时候触发、action 说跑什么程序、"
    "run_as 说用哪个账户。"
    "安全边界：① 目标程序落在系统目录（Windows / Program Files / ProgramData）或被按文件名判为"
    "高危系统工具（cmd / powershell / mshta / rundll32…）→ 拒绝；② 触发器只开放 "
    "daily（每天 HH:MM）/ weekly（每周某几天 HH:MM）/ once（某天 HH:MM 跑一次）/ boot（开机后）/ "
    "logon（登录后），可用 delay 表达「触发后延迟多久」；③ 账户只允许当前用户（不存密码，"
    "任务只在用户登录状态下才跑），系统账户一律拒绝；"
    "④ 权限级别固定为默认（受限），**不提供提权选项**；⑤ 不允许在 \\Microsoft\\ 命名空间下建任务。"
    "只预览时会返回将要执行的 schtasks 命令。"
    "同名任务已存在时默认拒绝，要覆盖得显式传 overwrite=True。"
    "返回 action.exists=False 表示目标程序现在不存在（任务仍会建出来，但到点跑不起来）。",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "任务名，可含文件夹（如 MyFolder\\\\MyTask）；不能是 \\Microsoft\\ 命名空间"},
         "trigger": {
             "type": "object",
             "description": "什么时候触发（结构化，不要拼字符串）",
             "properties": {
                 "type": {"type": "string",
                          "enum": ["daily", "weekly", "once", "boot", "logon"],
                          "description": "每天 / 每周 / 只跑一次 / 开机后 / 登录后"},
                 "time": {"type": "string",
                          "description": "HH:MM（24 小时制），daily / weekly / once 必填"},
                 "date": {"type": "string",
                          "description": "yyyy-mm-dd，仅 once 可选，默认今天"},
                 "days": {"type": "array", "items": {"type": "string"},
                          "description": "weekly 必填，如 [\"mon\", \"fri\"]"},
                 "every": {"type": "integer",
                           "description": "间隔：daily=每 N 天（1-365），weekly=每 N 周（1-52），默认 1"},
                 "delay": {"type": "string",
                           "description": "仅 boot / logon：触发后延迟多久再跑，如 5m / 30s / 1h30m"},
             },
             "required": ["type"],
             "additionalProperties": False},
         "action": {
             "type": "object",
             "description": "跑什么程序（结构化：程序 / 参数 / 工作目录分开给）",
             "properties": {
                 "program": {"type": "string",
                             "description": "要运行的程序完整路径。系统目录下的会被拒绝"},
                 "arguments": {"type": "string", "description": "传给程序的参数（可选）"},
                 "working_dir": {"type": "string",
                                 "description": "工作目录（可选，同样不能在系统目录里）"},
             },
             "required": ["program"],
             "additionalProperties": False},
         "run_as": {"type": "string",
                    "description": "用哪个账户跑。只能省略（=当前用户）或填当前用户名；"
                                   "系统账户（SYSTEM / LocalService / NetworkService / SID）一律拒绝"},
         "overwrite": {"type": "boolean",
                       "description": "同名任务已存在时是否覆盖，默认 False（直接拒绝）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不创建（默认）；False=真创建"},
     },
     "required": ["name", "trigger", "action"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="service_task",
)
def task_create(name: str, trigger, action, run_as: str = "",
                overwrite: bool = False, dry_run: bool = True) -> dict:
    out: dict = {"ok": False, "dry_run": bool(dry_run), "is_admin": is_admin()}
    # ① 任务名校验：不许 ..、不许控制字符、不许进系统命名空间
    tname = (name or "").strip().replace("/", "\\").lstrip("\\")
    out["name"] = tname
    if not tname:
        out["note"] = "任务名不能为空"
        return out
    if ".." in tname or any(ord(c) < 32 for c in tname):
        out["note"] = "任务名里不允许 .. 段或控制字符"
        return out
    if len(tname) > 200:
        out["note"] = "任务名过长（上限 200 字符）"
        return out
    if _norm(tname).startswith(_MICROSOFT_NAMESPACE):
        out.update({"blocked": True,
                    "note": f"拒绝在 \\Microsoft\\ 命名空间下建任务（{tname!r}）："
                            f"那是系统自带任务的地盘 —— 系统任务正是靠这个命名空间识别的，"
                            f"往里塞东西会让「哪些是系统任务」这件事再也说不清"})
        return out
    # ② 触发器 / 执行动作 / 账户：三道前置判定
    try:
        trig_args, trig_desc = _build_trigger(trigger)
        tr_value, act = _build_action(action)
    except _Reject as e:
        out.update({"blocked": True, "note": str(e)})
        return out
    except ValueError as e:
        out["note"] = f"参数无效：{e}"
        return out
    out["trigger"] = trig_desc
    out["action"] = act
    me = _current_user()
    run_as_raw = (run_as or "").strip()
    if run_as_raw:
        low = run_as_raw.lower().lstrip(".\\")
        if low in _SYSTEM_ACCOUNTS or low.startswith("s-1-") or "authority" in low:
            out.update({"blocked": True,
                        "note": f"拒绝用系统账户跑（{run_as_raw}）：SYSTEM / LocalService / "
                                f"NetworkService / 裸 SID 是提权与持久化的标志性写法，本原语不给这个能力"})
            return out
        domain = (os.environ.get("USERDOMAIN") or "").lower()
        if me and low not in (me.lower(), f"{domain}\\{me.lower()}" if domain else ""):
            out.update({"blocked": True,
                        "note": f"只允许用当前用户跑（当前是 {me}），收到 {run_as_raw!r}："
                                f"用别人的账户跑任务要能出示那个账户的密码，本原语不碰凭据"})
            return out
        out["run_as_note"] = (f"run_as={run_as_raw} 就是当前用户 —— 仍按「不给 /RU」建，"
                              f"因为 schtasks 一给 /RU 就会要密码")
    out["run_as"] = me or None
    out["run_level"] = "LIMITED（默认，不可提权）"
    # ③ 同名检查
    exists, _root, _how, _err = _resolve_task(tname)
    if exists:
        if _norm(exists) != _norm(tname):
            out.update({"existing": exists,
                        "note": f"已存在末段同名的任务 {exists}；本原语不猜你想动哪个 ——"
                                f"要改它请用完整路径配合 task.delete / task.control，"
                                f"要新建请换个名字"})
            return out
        if not overwrite:
            out.update({"existing": exists,
                        "note": f"任务 {exists} 已存在。要重新定义它请显式传 overwrite=True"
                                f"（会覆盖触发器与动作）；只想改启用态用 task.control"})
            return out
    # ④ 预览 / 执行
    argv = ["schtasks", "/create", "/tn", tname, "/tr", tr_value] + trig_args
    if overwrite:
        argv.append("/f")
    out["plan"] = _render_cmd(argv)
    if dry_run:
        when = "覆盖" if (overwrite and exists) else "新建"
        out["note"] = (f"只读预览：**没有创建任何任务**。真执行将{when}计划任务 {tname!r}，"
                       f"触发条件：{trig_desc}；执行：{act.get('command_line')}；账户：{me}"
                       f"。真创建需 dry_run=False 且过确认。")
        return out
    try:
        # stdin=DEVNULL：schtasks 万一要交互式问密码，立刻失败而不是把调用方吊住。
        # 不给 /RU 时它用的是当前用户、也不存密码（任务只在用户登录时才会跑）——
        # 这正是我们要的：**不碰凭据**，也不产生「谁都能跑」的任务。
        r = subprocess.run(argv, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    except Exception as e:
        out["note"] = f"调用 schtasks 失败：{e}"
        return out
    text = (decode_output(r.stdout) + decode_output(r.stderr)).strip()
    out["output"] = text[:500]
    out["returncode"] = r.returncode
    if r.returncode != 0:
        hint = "；非管理员会话只能建当前用户的任务，建开机 / 登录触发的任务通常需要管理员权限"
        low = text.lower()
        if "password" in low or "密码" in text or "credential" in low or "凭据" in text:
            hint = ("；报的是凭据类错误 —— 本原语**不接收也不传密码**（不给 /RU /RP）。"
                    "要指定别的账户请用图形界面的任务计划程序，或 Register-ScheduledTask")
        out["note"] = f"创建失败（schtasks 返回 {r.returncode}）：{text[:300] or '无输出'}{hint}"
        return out
    uri, root2, _h, _e = _resolve_task(tname)
    out.update({"ok": True, "created": uri or tname, "enabled": _is_enabled(root2) if root2 is not None else None,
                "note": f"已创建计划任务 {uri or tname}：{trig_desc}；执行 {act.get('command_line')}；"
                        f"账户 {me}（不存密码，只在登录状态下运行）；权限级别受限。"
                        f"要它立刻跑一次用 task.control(action='run')"})
    if act.get("warning"):
        out["note"] += "；⚠️ " + act["warning"]
    return out


@declare_primitive(
    "task.delete",
    "删除一个 Windows 计划任务（⚠️ 需确认，不可逆）。"
    "**系统自带的任务一律拒绝删除** —— Windows 自带 180+ 个维护任务（磁盘整理 / 更新 / 字体缓存 / "
    "Defender 扫描等）都在 \\Microsoft\\Windows\\ 下，删了会破坏系统维护链。"
    "name 可以是完整路径（\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag）或末段名"
    "（ScheduledDefrag，唯一匹配时自动补全）；匹配到多个时**拒绝执行**并列出候选，绝不猜。"
    "⚠️ 删之前先用 `task.info` 确认删的是哪个任务（本条只给命令行与触发器个数，细节在那边）；"
    "想先看清系统里都有哪些任务、任务名到底是什么，用 `task.list`；"
    "只想**停掉**而不是删掉，用 `task.control(action='disable')`（可逆，也仍需确认）。"
    "返回 {ok, name, resolved_by, dry_run, deleted, command_line, trigger_count, boot_or_logon, was_enabled, "
    "plan, output, returncode, blocked, system_task, note}："
    "⚠️ deleted 才是「真的删掉了没有」，ok=true 仅在删除且复核确认后为真。",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "任务名（完整路径或末段名，如 ScheduledDefrag）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不删（默认）；False=真删"},
     },
     "required": ["name"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="service_task",
)
def task_delete(name: str, dry_run: bool = True) -> dict:
    out: dict = {"ok": False, "dry_run": bool(dry_run), "is_admin": is_admin()}
    if not _norm(name):
        out["note"] = "任务名不能为空"
        return out
    uri, root, how, err = _resolve_task(name)
    if not uri:
        out["note"] = err
        return out
    out.update({"name": uri, "resolved_by": how})
    # ① 系统自带任务：不给这个能力（不是「问一句」）
    reason = _system_task_reason(uri)
    if reason:
        out.update({"blocked": True, "system_task": True,
                    "note": f"拒绝删除 {uri}：{reason}，不能删。"
                            f"确实要停掉它的维护动作，用 task.control(action='disable') 更可控"
                            f"（可逆，也仍然要过确认）"})
        return out
    # ② 顺带把「动作是什么」摆出来：删之前该知道自己在删什么
    acts = _actions(root)
    trigs = _triggers(root)
    out["command_line"] = next((a.get("command_line", "") for a in acts if a["kind"] == "Exec"), "")
    out["trigger_count"] = len(trigs)
    out["boot_or_logon"] = bool({t["type"] for t in trigs} & BOOT_LOGON_TRIGGERS)
    out["was_enabled"] = _is_enabled(root)
    argv = ["schtasks", "/delete", "/tn", uri, "/f"]
    out["plan"] = _render_cmd(argv)
    if dry_run:
        out["deleted"] = False
        out["note"] = (f"只读预览：**没有删除任何任务**。真执行将删除 {uri}"
                       f"（{len(trigs)} 个触发器，动作：{out['command_line'] or '（无命令行）'}）。"
                       f"删除不可逆 —— 要恢复只能重新建。真删需 dry_run=False 且过确认。")
        return out
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    except Exception as e:
        out["note"] = f"调用 schtasks 失败：{e}"
        return out
    text = (decode_output(r.stdout) + decode_output(r.stderr)).strip()
    out["output"] = text[:500]
    out["returncode"] = r.returncode
    still, _r2, _h2, _e2 = _resolve_task(uri)
    out["deleted"] = not still
    if r.returncode != 0 or still:
        out["note"] = (f"删除失败（schtasks 返回 {r.returncode}）：{text[:300] or '无输出'}"
                       f"；删任务通常需要管理员权限")
        return out
    out.update({"ok": True, "note": f"已删除计划任务 {uri}（触发器 {len(trigs)} 个，"
                                    f"删除前启用态 {out['was_enabled']}）。此操作不可逆。"})
    return out


@declare_primitive(
    "task.control",
    "让一个既有计划任务**立刻跑一次**（action='run'）/ 中止它（'end'）/ 启用（'enable'）/ "
    "停用（'disable'）。⚠️ 需确认：'run' 会把那个任务当场点燃（它可能正在删文件、改配置），"
    "'end' 会把正在跑的任务掐掉；启用/停用本身可逆。"
    "额外禁令：与系统安全 / 更新相关的任务（Defender / Windows Update / 防火墙 / 审计）"
    "不允许被停用或中止 —— 那等于关掉系统防护。"
    "name 可以是完整路径或末段名（唯一匹配时自动补全，多个候选时拒绝执行并列出）。"
    "⚠️ 动手前先用 `task.info` 看清这个任务是什么（它有哪几个触发器、跑什么程序）—— "
    "尤其 action='run'：那是把一个既有任务**当场点燃**。只想看任务清单用 `task.list`；"
    "要看「开机自动跑什么」的全景用 `startup.list`；要**彻底删掉**这个任务用 `task.delete`"
    "（本条只能停用，删是另一条、也不可逆）。"
    "返回 {ok, name, action, action_label, dry_run, resolved_by, enabled_before, enabled_after, "
    "status_after, plan, output, returncode, blocked, note}："
    "⚠️ 动作未知、被系统防护类任务硬拒（blocked=true）、命令执行失败**都是 ok=false** —— 看 note 区分。",
    {"type": "object",
     "properties": {
         "name": {"type": "string", "description": "任务名（完整路径或末段名）"},
         "action": {"type": "string", "enum": ["run", "end", "enable", "disable"],
                    "description": "立刻跑一次 / 中止 / 启用 / 停用"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览（默认）；False=真执行"},
     },
     "required": ["name", "action"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="service_task",
)
def task_control(name: str, action: str, dry_run: bool = True) -> dict:
    act = (action or "").strip().lower()
    out: dict = {"ok": False, "name": name, "action": act, "dry_run": bool(dry_run),
                 "is_admin": is_admin()}
    _labels = {"run": "立刻运行一次", "end": "中止正在运行的任务",
               "enable": "启用", "disable": "停用"}
    if act not in _labels:
        out["note"] = f"未知动作 {action!r}，可选：run / end / enable / disable"
        return out
    out["action_label"] = _labels[act]
    if not _norm(name):
        out["note"] = "任务名不能为空"
        return out
    uri, root, how, err = _resolve_task(name)
    if not uri:
        out["note"] = err
        return out
    out.update({"name": uri, "resolved_by": how,
                "enabled_before": _is_enabled(root) if root is not None else None})
    # ① 安全 / 更新相关的任务：停用或中止它们 = 关掉系统防护
    if act in ("disable", "end"):
        reason = _protected_task_reason(uri)
        if reason:
            out.update({"blocked": True,
                        "note": f"拒绝{_labels[act]} {uri}：{reason}。"
                                f"（与 service.control 拒绝停杀毒/防火墙服务同一条线）"})
            return out
    # ② 系统自带任务：跑一次 / 启停都允许（可逆，也可能正是为了修问题），但要说清楚它是系统任务
    sys_reason = _system_task_reason(uri)
    if sys_reason:
        out["system_task"] = True
        out["system_task_note"] = f"⚠️ 这是{sys_reason}，请确认这是你要的"
    _arg_map = {"run": ["/run"], "end": ["/end"],
                "enable": ["/change", "/enable"], "disable": ["/change", "/disable"]}
    argv = ["schtasks"] + _arg_map[act] + ["/tn", uri]
    out["plan"] = _render_cmd(argv)
    if dry_run:
        out["note"] = (f"只读预览：**没有执行任何操作**。真执行将对 {uri} 执行「{_labels[act]}」"
                       f"（当前启用态 {out['enabled_before']}）。真执行需 dry_run=False 且过确认。")
        if sys_reason:
            out["note"] += f" ⚠️ {sys_reason}"
        return out
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    except Exception as e:
        out["note"] = f"调用 schtasks 失败：{e}"
        return out
    text = (decode_output(r.stdout) + decode_output(r.stderr)).strip()
    out["output"] = text[:500]
    out["returncode"] = r.returncode
    if r.returncode != 0:
        out["note"] = (f"{_labels[act]}失败（schtasks 返回 {r.returncode}）：{text[:300] or '无输出'}"
                       f"；启停任务通常需要管理员权限")
        return out
    # ③ 动作后核对：启用态读任务定义（XML 里的 Settings/Enabled 才是准的）
    _uri2, root2, _h2, _e2 = _resolve_task(uri)
    out["enabled_after"] = _is_enabled(root2) if root2 is not None else None
    rec = _runtime_of(uri)
    out["status_after"] = rec.get("status") or None
    out["ok"] = True
    extra = ""
    if act in ("enable", "disable"):
        extra = f"，启用态 {out['enabled_before']} → {out['enabled_after']}"
    elif rec.get("status"):
        extra = f"，当前状态 {rec['status']}"
    out["note"] = f"已对 {uri} 执行「{_labels[act]}」{extra}"
    if sys_reason:
        out["note"] += f"；⚠️ 这是系统自带任务，请确认这是你要的"
    return out
