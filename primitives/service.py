"""系统域原语 —— 后台服务启停（service.*）。

零依赖：系统自带 `sc.exe`（Windows 服务控制管理器），零第三方库。
**安全分级 + 前置权限探测**（这条是「必须被管」的样板）：
  1. **关键服务黑名单**：杀毒/防火墙/安全中心/事件日志/RPC 等一律拒绝——关掉它们是典型攻击动作
  2. **前置权限探测**：非管理员直接拒绝，返回清晰中文说明，而不是把 sc 的原始报错丢出去
  3. **需确认 + 默认 dry_run=True**：真启停要显式 dry_run=False 且过确认
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_service，注册进 factory.registry）。
"""
from __future__ import annotations

import subprocess
import time

from core.factory import declare_primitive  # type: ignore
from primitives._common import SERVICE_START_TYPES, decode_output, is_admin

# 关键服务：动了会削弱系统安全或直接搞坏系统 → 一律拒绝（不是「需确认」，是「不给你这个能力」）
CRITICAL_SERVICES = {
    "windefend": "Windows Defender 杀毒",
    "wscsvc": "安全中心",
    "mpssvc": "Windows 防火墙",
    "bfe": "基础筛选引擎（防火墙依赖）",
    "eventlog": "Windows 事件日志",
    "rpcss": "远程过程调用 RPC",
    "dcomlaunch": "DCOM 服务控制启动器",
    "lsm": "本地会话管理器",
    "samss": "安全账户管理器",
    "winlogon": "登录管理器",
    "schedule": "任务计划程序",
    "gpsvc": "组策略客户端",
    "cryptsvc": "加密服务",
    "wuauserv": "Windows 更新",
    "seclogon": "二次登录服务",
    "brokerinfrastructure": "后台任务基建",
    "trustedinstaller": "Windows 模块安装程序",
    "power": "电源服务",
}

# sc query 的 STATE 数字 → 英文状态名（不返回本地化文本）
_STATES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
           4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}


def _query(name: str) -> tuple[bool, dict | None, str]:
    """查服务状态。返回 (是否存在, {name,state,state_code,raw}, 说明)。"""
    try:
        r = subprocess.run(["sc", "query", name], capture_output=True, timeout=20)
    except Exception as e:
        return False, None, f"调用 sc 失败：{e}"
    text = decode_output(r.stdout) + decode_output(r.stderr)
    if r.returncode != 0:
        # 1060 = 服务不存在；5 = 拒绝访问
        if r.returncode == 1060 or "1060" in text:
            return False, None, f"服务不存在：{name}"
        if r.returncode == 5 or "拒绝访问" in text or "Access is denied" in text:
            return False, None, f"拒绝访问：无权查询服务 {name}"
        return False, None, f"查询失败（sc 返回 {r.returncode}）：{text.strip()[:200]}"
    info: dict = {"name": name, "state": None, "state_code": None}
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("STATE"):
            after = line.split(":", 1)[-1].strip()
            parts = after.split(None, 1)
            if parts and parts[0].isdigit():
                info["state_code"] = int(parts[0])
                info["state"] = _STATES.get(info["state_code"], parts[-1].strip())
    info["raw"] = text.strip()
    return True, info, "ok"


def _split_blocks(text: str) -> list[dict]:
    """把 sc 的「空行分块」输出切成 [{SERVICE_NAME, DISPLAY_NAME, STATE}, ...]。

    `sc query type= service state= all` 的输出就是若干块，每块以 SERVICE_NAME 开头、以空行结束。
    拿全量服务列表走这条路最省事：零依赖，也不用解析 CIM 对象。
    """
    blocks: list[dict] = []
    cur: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if ":" not in line:
            continue  # 续行（STATE 后面那行 "(STOPPABLE, ...)"）直接跳过
        key, val = line.split(":", 1)
        key = key.strip().upper()
        if key in ("SERVICE_NAME", "DISPLAY_NAME", "STATE"):
            cur[key] = val.strip()
    if cur:
        blocks.append(cur)
    return blocks


def _fields(text: str) -> dict:
    """收「KEY : VALUE」行成 dict（键统一大写去空格）。

    冒号只切第一个 —— BINARY_PATH_NAME 的值里带盘符冒号（`C:\\WINDOWS\\...`）。
    """
    out: dict = {}
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, val = raw.split(":", 1)
        key = key.strip().upper()
        if key:
            out[key] = val.strip()
    return out


def _parse_state(val: str) -> tuple[str | None, int | None]:
    """STATE 行 → (状态名, 状态码)。`4  RUNNING` → ("RUNNING", 4)。"""
    parts = (val or "").split(None, 1)
    if parts and parts[0].isdigit():
        code = int(parts[0])
        return _STATES.get(code, parts[1].strip() if len(parts) > 1 else None), code
    return (val.strip() or None), None


# sc qc 的 START_TYPE 数字 → 启动类型名（不返回本地化文本）
def _parse_start_type(val: str) -> tuple[str | None, int | None, bool]:
    """START_TYPE 行 → (类型名, 类型码, 是否延迟启动)。`2   AUTO_START  (DELAYED)`。"""
    v = (val or "").strip()
    delayed = "(DELAYED)" in v.upper()
    parts = v.split()
    if parts and parts[0].isdigit():
        code = int(parts[0])
        return SERVICE_START_TYPES.get(code, parts[1] if len(parts) > 1 else None), code, delayed
    return (v or None), None, delayed


@declare_primitive(
    "service.list",
    "枚举 Windows 后台服务：服务名（sc 的 SERVICE_NAME）/ 显示名 / 运行状态（RUNNING / STOPPED 等"
    "**英文枚举**，不随系统语言变）。"
    "问「这台机器开了哪些服务 / 某个服务是不是在跑 / 有哪些服务在运行」时用它。"
    "⚠️ 分工：只想知道**某一个**服务是什么、启动类型、跑在哪个账户、是不是关键服务，用 `service.info`"
    "（单条、更详细）；想知道「开机自动跑什么」（不只服务，还有注册表 Run / 启动文件夹 / 计划任务）用 "
    "`startup.list`（聚合入口）；要启停服务用 `service.control`（需确认，且关键服务会被硬拒）。"
    "参数：state=all/running/stopped（默认 all）、name_contains（服务名或显示名子串，不区分大小写）、"
    "limit（最多返回条数，默认 100，上限 500）、offset（翻页跳过前 N 条）。"
    "返回 {ok, total_all, matched, returned, offset, truncated, services:[{name, display_name, state, state_code}], note}："
    "⚠️ total_all 才是**系统服务总数**、returned 是本次返回条数；truncated=True 表示还有更多，用 offset 接着取"
    "（别把 returned 当总数）。",
    {"type": "object",
     "properties": {
         "state": {"type": "string", "enum": ["all", "running", "stopped"],
                   "description": "按状态过滤，默认 all"},
         "name_contains": {"type": "string",
                           "description": "服务名或显示名包含该子串（不区分大小写），默认不过滤"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "最多返回条数，默认 100，上限 500"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "跳过前 N 条（翻页用），默认 0"},
     },
     "required": [],
     "additionalProperties": False},
    block="service_task",
)
def service_list(state: str = "all", name_contains: str = "",
                 limit: int = 100, offset: int = 0) -> dict:
    state = (state or "all").strip().lower()
    if state not in ("all", "running", "stopped"):
        state = "all"
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    try:
        # sc 的参数解析要求写成 `type= service`（等号后留空格），所以拆成两个 argv 传
        r = subprocess.run(["sc", "query", "type=", "service", "state=", "all"],
                           capture_output=True, timeout=30)
    except Exception as e:
        return {"ok": False, "note": f"调用 sc 失败：{e}"}
    if r.returncode != 0:
        text = (decode_output(r.stdout) + decode_output(r.stderr)).strip()
        return {"ok": False, "note": f"sc query 失败（返回 {r.returncode}）：{text[:200]}"}
    items: list[dict] = []
    for b in _split_blocks(decode_output(r.stdout)):
        name = b.get("SERVICE_NAME", "")
        if not name:
            continue
        st, code = _parse_state(b.get("STATE", ""))
        items.append({"name": name, "display_name": b.get("DISPLAY_NAME", ""),
                      "state": st, "state_code": code})
    total_all = len(items)
    if state != "all":
        want = "RUNNING" if state == "running" else "STOPPED"
        items = [i for i in items if i["state"] == want]
    if name_contains and name_contains.strip():
        needle = name_contains.strip().lower()
        items = [i for i in items
                 if needle in i["name"].lower() or needle in (i["display_name"] or "").lower()]
    matched = len(items)
    page = items[offset:offset + limit]
    more = offset + len(page) < matched
    return {"ok": True, "total_all": total_all, "matched": matched,
            "returned": len(page), "offset": offset, "truncated": more,
            "services": page,
            "note": f"系统共 {total_all} 个服务，过滤后 {matched} 个，本次返回 {len(page)} 个"
                    + (f"；还有 {matched - offset - len(page)} 个，用 offset={offset + len(page)} 继续取"
                       if more else "")}


@declare_primitive(
    "service.info",
    "查**单个** Windows 服务的详情：启动类型（自动 / 手动 / 禁用，是否延迟启动）、跑在哪个账户、"
    "程序文件路径、依赖服务、当前运行状态，以及它是否属于「关键服务」（关键服务会被 service.control 硬拒）。"
    "回答「这个服务干什么 / 能不能停 / 停了会不会出事」时用它。"
    "⚠️ 分工：只知道名字、要把服务列一遍用 `service.list`；要**启停**它用 `service.control`"
    "（开口前先看本条的 is_critical 与 dependencies）；想看「开机自动跑什么」的全景用 `startup.list`。"
    "参数 name 必填，要的是**服务名**（sc 的 SERVICE_NAME，如 Spooler），**不是显示名**"
    "（只知道显示名/中文名的话，先用 service.list 的 name_contains 查出对应的服务名）。"
    "返回 {ok, name, display_name, state, state_code, start_type, start_type_code, delayed_auto_start, "
    "binary_path, start_name, dependencies, type, is_critical, note}："
    "⚠️ is_critical=true 表示 service.control 会**拒绝**操作它；dependencies 是被它依赖的服务，"
    "停它可能连带影响别的服务。",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "服务名（sc 里的 SERVICE_NAME，如 Spooler），不是显示名"},
     },
     "required": ["name"],
     "additionalProperties": False},
    state={"name": "服务名", "state": "状态"},
    block="service_task",
)
def service_info(name: str) -> dict:
    if not (name or "").strip():
        return {"ok": False, "note": "服务名不能为空"}
    # ① 配置（sc qc）：启动类型 / 账户 / 二进制路径 / 依赖
    try:
        r = subprocess.run(["sc", "qc", name], capture_output=True, timeout=20)
    except Exception as e:
        return {"ok": False, "name": name, "note": f"调用 sc 失败：{e}"}
    if r.returncode != 0:
        text = (decode_output(r.stdout) + decode_output(r.stderr)).strip()
        _, _, msg = _query(name)      # 复用查询：区分「服务不存在」与「拒绝访问」
        return {"ok": False, "name": name,
                "note": msg if msg != "ok" else f"sc qc 失败（返回 {r.returncode}）：{text[:200]}"}
    f = _fields(decode_output(r.stdout))
    start_type, start_code, delayed = _parse_start_type(f.get("START_TYPE", ""))
    deps = [d.strip() for d in f.get("DEPENDENCIES", "").split(",") if d.strip()]
    # ② 当前状态：sc qc 只给配置不给运行状态，单独查一次（只读，非管理员也能跑）
    _, live, _ = _query(name)
    key = name.strip().lower()
    out = {"ok": True,
           "name": f.get("SERVICE_NAME", name),
           "display_name": f.get("DISPLAY_NAME", ""),
           "state": (live or {}).get("state"),
           "state_code": (live or {}).get("state_code"),
           "start_type": start_type,
           "start_type_code": start_code,
           "delayed_auto_start": delayed,
           "binary_path": f.get("BINARY_PATH_NAME", ""),
           "start_name": f.get("SERVICE_START_NAME", ""),
           "dependencies": deps,
           "type": f.get("TYPE", ""),
           "is_critical": key in CRITICAL_SERVICES,
           "note": ""}
    if out["is_critical"]:
        out["note"] = f"关键服务（{CRITICAL_SERVICES[key]}）：service.control 会拒绝操作它"
    return out


@declare_primitive(
    "service.control",
    "启动 / 停止 / 重启一个 Windows 后台服务（需确认，会真实改变系统状态）。"
    "⚠️ **action 的默认值是 start** —— 调用方省略 action 就等价于「把这个服务启动起来」："
    "**要停服务必须显式写 action=\"stop\"**，只想省事传 dry_run=False 会把服务拉起来。"
    "安全门：① 关键服务（杀毒 / 防火墙 / 安全中心 / RPC 等）**一律硬拒**，这不是「问一句」而是不给这个能力；"
    "② 非管理员直接拒绝（sc 启停必须管理员，不做提权）。"
    "⚠️ 动手前先用 `service.info` 看它的启动类型、依赖与被依赖关系，并确认 is_critical —— "
    "停掉一个被别的服务依赖的服务会连带影响一片。只想看服务清单用 `service.list`。"
    "参数：name 必填（**服务名** = sc 的 SERVICE_NAME，如 Spooler，不是显示名）；"
    "action=start/stop/restart（**默认 start，停服务务必显式传**）；dry_run。"
    "返回 {ok, name, action, dry_run, is_admin, requires_admin, state_before, state_after, plan, output, "
    "returncode, note}：⚠️ 被关键服务门拒绝（blocked=true）、非管理员被拒、"
    "命令执行失败**都是 ok=false** —— 看 note 与 blocked 区分，别一律当成「没成功」。",
    {"type": "object",
     "properties": {
         "name": {"type": "string", "description": "服务名（sc 里的 SERVICE_NAME，如 Spooler），不是显示名"},
         "action": {"type": "string", "enum": ["start", "stop", "restart"],
                    "description": "动作。⚠️ 默认 start —— 省略 action 就是「启动它」，停服务务必显式填 stop"},
         "dry_run": {"type": "boolean", "description": "True=只预览（默认）；False=真执行"},
     },
     "required": ["name"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"name": "服务名", "state": "状态"},
    block="service_task",
)
def service_control(name: str, action: str = "start", dry_run: bool = True) -> dict:
    action = (action or "start").lower()
    if action not in ("start", "stop", "restart"):
        return {"ok": False, "name": name, "action": action,
                "note": f"未知动作 {action!r}，可选：start/stop/restart"}
    key = (name or "").strip().lower()
    if not key:
        return {"ok": False, "name": name, "action": action, "note": "服务名不能为空"}
    out = {"name": name, "action": action, "dry_run": bool(dry_run), "is_admin": is_admin(),
           "requires_admin": True}
    # ① 关键服务黑名单：不给这个能力，而不是「问一句」
    if key in CRITICAL_SERVICES:
        out.update({"ok": False, "blocked": True,
                    "note": f"拒绝操作：{CRITICAL_SERVICES[key]}（{name}）是关键服务，"
                            f"关掉它会削弱系统安全或导致系统异常"})
        return out
    # ② 服务存在性 + 当前状态（sc query 是只读查询，非管理员也能跑 → 先查，报错更准）
    exists, info, msg = _query(name)
    if not exists:
        out.update({"ok": False, "note": msg})
        return out
    # ③ 前置权限探测：非管理员直接拒绝，不把 sc 的原始报错丢出去
    #   （放在查询之后：先给「服务名写错了」这种更准的提示，再谈权限）
    if not out["is_admin"]:
        verb = {"start": "启动", "stop": "停止", "restart": "重启"}[action]
        out.update({"ok": False, "state_before": info.get("state"),
                    "note": f"当前会话不是管理员，无法{verb}服务（sc 启停需要管理员权限）。"
                            f"请以管理员身份重开后再试；本原语不做提权。"})
        return out
    out["state_before"] = info.get("state")
    if action == "start" and info.get("state") == "RUNNING":
        out.update({"ok": True, "state_after": "RUNNING", "note": "服务已在运行，无需启动"})
        return out
    if action == "stop" and info.get("state") == "STOPPED":
        out.update({"ok": True, "state_after": "STOPPED", "note": "服务已停止，无需操作"})
        return out
    # ④ dry_run 预览
    if dry_run:
        plan = [_sc_cmd(action, name)] if action != "restart" else [["sc", "stop", name], ["sc", "start", name]]
        out.update({"ok": False, "dry_run": True, "plan": [" ".join(c) for c in plan],
                    "note": f"只读预览：未执行。真执行将运行 {'；'.join(' '.join(c) for c in plan)}"})
        return out
    # ⑤ 真执行
    logs: list[str] = []
    try:
        if action == "restart":
            r1 = subprocess.run(["sc", "stop", name], capture_output=True, timeout=60)
            logs.append(decode_output(r1.stdout + r1.stderr).strip())
            time.sleep(2)                        # 给服务一点时间真正停下来
            r2 = subprocess.run(["sc", "start", name], capture_output=True, timeout=60)
            logs.append(decode_output(r2.stdout + r2.stderr).strip())
            rc = r2.returncode
        else:
            r = subprocess.run(["sc", action, name], capture_output=True, timeout=60)
            logs.append(decode_output(r.stdout + r.stderr).strip())
            rc = r.returncode
    except Exception as e:
        out.update({"ok": False, "note": f"执行失败：{e}"})
        return out
    _, after, _ = _query(name)
    out.update({"ok": rc == 0, "returncode": rc, "state_after": after.get("state") if after else None,
                "output": logs,
                "note": f"{action} 指令已下发" if rc == 0 else f"系统拒绝执行（sc 返回 {rc}）：{logs[-1][:200]}"})
    return out


def _sc_cmd(action: str, name: str) -> list[str]:
    return ["sc", "start" if action == "restart" else action, name]
