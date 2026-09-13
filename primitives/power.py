"""系统域原语 —— 电源（power.*）：锁屏 / 关机·重启·睡眠 / 睡眠·休眠 / 电源计划 / 电池。

零依赖：ctypes(user32/kernel32/advapi32/powrprof) + 系统自带 shutdown.exe / powercfg.exe，Windows 优先。
**安全分级样板**：
  · `power.lock`  —— 低危高频，不破坏任何数据 → 无需确认，但**会改变系统状态**，
    故默认 dry_run=True 只预览，真锁屏需显式 dry_run=False
  · `power.shutdown` —— 最高危 → **需确认** + 默认 dry_run=True 只预览 + 支持延时反悔窗口
  · `power.sleep` —— 睡眠 vs 休眠是两种后果，用 mode 区分；睡着/休眠中的机器叫不醒
    （远程调用方直接失联）→ **需确认** + 默认 dry_run=True
  · `power.plan` —— 看是只读、换是系统级影响 → **需确认** + 默认 dry_run=True
  · `power.battery` —— 只读，无需确认（台式机没有电池时如实说明，不编数字）
**权限前置探测**：关机需要令牌里有 SeShutdownPrivilege（普通交互用户默认有；服务账户/受限
令牌里可能没有）。探测失败时返回中文说明，不把系统原始报错甩给调用方。
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_power，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import re
import subprocess
import winreg

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output, is_admin, token_privileges

# ── 锁屏（低危，无需确认）────────────────────────────────────────────────
class _WTSINFOEX_LEVEL1(ctypes.Structure):
    _fields_ = [("SessionId", wintypes.DWORD), ("SessionState", ctypes.c_int),
                ("SessionFlags", ctypes.c_int), ("UserName", ctypes.c_wchar * 33),
                ("DomainName", ctypes.c_wchar * 33), ("WinStationName", ctypes.c_wchar * 33)]


def session_locked() -> bool | None:
    """当前会话是否处于锁屏状态（WTSQuerySessionInformationW 的 SessionFlags：0=已锁屏 1=未锁屏）。
    查不到返回 None——不猜、不冒充结论。"""
    try:
        wts = ctypes.windll.wtsapi32
        buf = ctypes.c_void_p()
        size = wintypes.DWORD()
        if not wts.WTSQuerySessionInformationW(None, 0xFFFFFFFF, 25,  # WTSSessionInfoEx
                                               ctypes.byref(buf), ctypes.byref(size)):
            return None
        try:
            info = ctypes.cast(buf.value, ctypes.POINTER(_WTSINFOEX_LEVEL1)).contents
            return info.SessionFlags == 0
        finally:
            wts.WTSFreeMemory(buf)
    except Exception:
        return None


@declare_primitive(
    "power.lock",
    "立即锁屏（LockWorkStation）：把当前会话锁上，回到登录界面。"
    "用户离开工位、要立刻遮住屏幕时用它。"
    "⚠️ 它跟同域两条**不是一回事**：本条只是锁屏，机器照常运行、随时能解锁；"
    "要让机器进低功耗（睡眠 / 休眠，唤醒前谁都指挥不动）用 `power.sleep`；"
    "要关机 / 重启用 `power.shutdown`。"
    "本条不弹确认门，所以「默认只预览」就是它的安全闸"
    "（锁屏会打断用户当前操作，出过真实事故）。"
    "返回 {ok, locked, verified, dry_run, note}（失败分支可能只给 ok / locked / note）："
    "⚠️ locked 是「系统调用是否返回成功」、"
    "verified 是「复核会话状态是否真的锁上了」，两者可能不一致（受限窗口站 / 远程会话下调用成功但实际没锁）"
    "—— **以 verified 为准**，verified=null 表示查不到状态、不冒充结论。",
    {"type": "object",
     "properties": {
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不锁屏（默认）；False=真锁屏"},
     },
     "required": [], "additionalProperties": False},
    state={"locked": "调用成功", "verified": "复核已锁"},
    block="power",
)
def power_lock(dry_run: bool = True) -> dict:
    # ⚠️ 安全铁律：默认只预览。锁屏会打断用户当前操作（2026-09-10 出过真实事故）。
    if dry_run:
        return {"ok": False, "locked": False, "verified": None, "dry_run": True,
                "note": "只读预览：未锁屏。真执行将调用 LockWorkStation() 立即锁定当前会话，"
                        "需显式传 dry_run=False"}
    try:
        ok = bool(ctypes.windll.user32.LockWorkStation())
    except Exception as e:
        return {"ok": False, "locked": False, "note": f"锁屏失败：{e}"}
    if not ok:
        return {"ok": False, "locked": False, "note": "锁屏调用返回 0（可能被策略禁止）"}
    # 复核：LockWorkStation 返回成功 ≠ 真的锁上了。不复核就等于谎报成功。
    import time as _t
    _t.sleep(0.3)
    state = session_locked()
    if state is None:
        return {"ok": True, "locked": True, "verified": None,
                "note": "锁屏指令已下发；本机查不到会话锁屏状态，无法复核"}
    return {"ok": bool(state), "locked": True, "verified": state,
            "note": "已锁屏" if state else
                    "锁屏调用返回成功，但复核会话状态仍是「未锁屏」——"
                    "该调用在当前运行环境（受限窗口站/远程会话/策略）下没有实际生效"}


# ── 关机 / 重启 / 注销 / 睡眠 / 休眠（最高危，需确认 + dry_run）────────────
_ACTIONS = {
    "shutdown": "关机",
    "restart": "重启",
    "logoff": "注销",
    "sleep": "睡眠",
    "hibernate": "休眠",
    "cancel": "撤销已排定的关机",
}
# 哪些动作需要令牌里有 SeShutdownPrivilege
_NEED_SHUTDOWN_PRIV = {"shutdown", "restart", "logoff", "hibernate"}


def _build_command(action: str, delay: int, force: bool) -> list[str]:
    """把动作翻译成命令行（关机类走 shutdown.exe，睡眠走 powrprof 的挂起）。"""
    if action == "shutdown":
        return ["shutdown", "/s", "/t", str(delay)] + (["/f"] if force else [])
    if action == "restart":
        return ["shutdown", "/r", "/t", str(delay)] + (["/f"] if force else [])
    if action == "logoff":
        return ["shutdown", "/l"]                     # 注销不吃 /t 也不吃 /f
    if action == "hibernate":
        return ["shutdown", "/h"]                     # 休眠，同样不吃 /t
    if action == "sleep":
        # rundll32 的经典三参：0=挂起 1=强制 0=不启用唤醒事件
        return ["rundll32", "powrprof.dll,SetSuspendState", "0,1,0"]
    if action == "cancel":
        return ["shutdown", "/a"]
    raise ValueError(f"未知动作：{action}")


@declare_primitive(
    "power.shutdown",
    "关机 / 重启 / 注销 / 睡眠 / 休眠（最高危，需确认）。action 的取值为 "
    "shutdown=关机 / restart=重启 / logoff=注销 / sleep=睡眠 / hibernate=休眠 / cancel=撤销已排定的关机。"
    "⚠️ **action 的默认值是 shutdown** —— 调用方省略 action 就等价于「让这台机器关机」，"
    "这是「省略参数就执行写操作」的默认值：**要走这条路就必须显式写 action**，"
    "只想省事传个 dry_run=False 会真的排一次关机。"
    "关机 / 重启支持 delay 秒延时（默认 30，上限 600）做反悔窗口，反悔用 action=cancel。"
    "⚠️ 睡眠 / 休眠这一档更推荐用**专门的** `power.sleep`：那条用 mode 参数把「睡眠 vs 休眠」两种"
    "完全不同的后果摆到台面上，还会先探休眠开关；本条的 sleep / hibernate 只是「关机顺带的动作枚举」。"
    "⚠️ 动手前先想清楚是不是只该锁屏 —— 那个用 `power.lock`（不用确认）。"
    "非管理员 / 令牌缺 SeShutdownPrivilege 时前置探测直接拒绝。"
    "返回 {ok, action, action_name, dry_run, delay, command, is_admin, note}（真执行那条路还会带 returncode）："
    "⚠️ dry_run 预览、特权不足被拒、系统拒绝执行**都是 ok=false**，看 note 与 returncode 区分；"
    "ok=true 只表示「命令已下发」，不代表机器真的关了。",
    {"type": "object",
     "properties": {
         "action": {"type": "string",
                    "enum": ["shutdown", "restart", "logoff", "sleep", "hibernate", "cancel"],
                    "description": "动作。⚠️ 默认 shutdown —— 省略 action 就是「关机」，务必显式填"},
         "delay": {"type": "integer", "minimum": 0, "maximum": 600,
                   "description": "延时秒数（仅 shutdown / restart 用，默认 30，上限 600，留反悔窗口）"},
         "force": {"type": "boolean", "description": "是否强制关闭未响应程序，默认 False"},
         "dry_run": {"type": "boolean", "description": "True=只预览命令（默认）；False=真执行"},
     },
     "required": [],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"action": "动作", "ok": "是否已执行"},
    block="power",
)
def power_shutdown(action: str = "shutdown", delay: int = 30, force: bool = False,
                   dry_run: bool = True) -> dict:
    action = (action or "shutdown").lower()
    if action not in _ACTIONS:
        return {"ok": False, "action": action,
                "note": f"未知动作 {action!r}，可选：{'/'.join(_ACTIONS)}"}
    try:
        delay = max(0, int(delay))
        if action in ("shutdown", "restart"):
            delay = min(delay, 600)          # 上限 10 分钟，避免排一个遥遥无期的关机
        else:
            delay = 0
        cmd = _build_command(action, delay, bool(force))
    except (ValueError, TypeError) as e:
        return {"ok": False, "action": action, "note": str(e)}
    out = {"action": action, "action_name": _ACTIONS[action], "dry_run": bool(dry_run),
           "delay": delay, "command": cmd, "is_admin": is_admin()}
    # 前置权限探测：缺特权就别执行，也别把系统原始报错甩出去
    if action in _NEED_SHUTDOWN_PRIV:
        privs = token_privileges()
        if not privs:
            out.update({"ok": False, "note": "权限探测失败：读不到当前进程令牌，无法确认关机权限，已拒绝执行"})
            return out
        if "SeShutdownPrivilege" not in privs:
            out.update({"ok": False,
                        "note": f"当前会话没有关机特权（SeShutdownPrivilege），{_ACTIONS[action]}会被系统拒绝；"
                                f"请改用有该特权的账户，或以管理员身份运行。当前令牌特权：{sorted(privs)}"})
            return out
    if dry_run:
        out.update({"ok": False, "dry_run": True,
                    "note": f"只读预览：未执行。真执行将运行 {' '.join(cmd)}"
                            + ("（可用 action=cancel 撤销）" if action in ("shutdown", "restart") and delay else "")})
        return out
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=20)
    except Exception as e:
        out.update({"ok": False, "note": f"执行失败：{e}"})
        return out
    err = (r.stderr or b"").decode("gbk", "replace").strip()
    out.update({"ok": r.returncode == 0, "returncode": r.returncode,
                "note": f"{_ACTIONS[action]}指令已下发" if r.returncode == 0
                        else f"系统拒绝执行（返回 {r.returncode}）：{err[:200]}"})
    return out


# ── 睡眠 / 休眠（power.sleep）──────────────────────────────────────────────
# 为什么和上面 power.shutdown 的 action=sleep/hibernate 并存：那条是「关机顺带的动作枚举」，
# 本条是**专门的睡眠原语** —— 把 mode 摆到台面上，并在动手前把「休眠到底可不可用」探清楚。
# 两者的后果差得远：
#   · 睡眠(sleep)    内存带电、按任意键即醒，是「暂停」级别，随时能回来
#   · 休眠(hibernate) 内存写进 hiberfil.sys 后**整机断电**，唤醒要重新上电 + 读盘，
#                     更省电但更慢，且**必须先在系统里启用休眠**（默认常常是关的）
# 但两者都不是锁屏那个级别：锁了随时能解，睡着/休眠中的机器在唤醒前谁都指挥不动 ——
# 远程/无人值守的调用方会直接失联。故一律需确认 + 默认只预览。
_SLEEP_MODES = {"sleep": "睡眠", "hibernate": "休眠"}
_HIBERNATE_KEY = r"SYSTEM\CurrentControlSet\Control\Power"


def hibernate_enabled() -> bool | None:
    """系统里到底有没有启用休眠（注册表 HibernateEnabled）。

    ⚠️ **不解析 `powercfg /a` 的文本**：那段输出是本地化的（中文系统上整段中文），
    按它做判断等于把逻辑绑死在界面语言上；注册表这个 DWORD 只有 0/1。
    读不到返回 None —— 不猜（调用方按「不确定可用」处理，见下面）。
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _HIBERNATE_KEY, 0, winreg.KEY_READ) as k:
            return bool(winreg.QueryValueEx(k, "HibernateEnabled")[0])
    except Exception:
        return None


@declare_primitive(
    "power.sleep",
    "让这台电脑进入低功耗状态，用 mode 区分两种**后果完全不同**的方式："
    "mode=sleep 是**睡眠**（内存带电、按任意键即可唤醒，相当于「暂停」，最常用）；"
    "mode=hibernate 是**休眠**（内存写进硬盘后整机彻底断电，更省电，但唤醒要重新上电读盘、"
    "更慢，且**要求系统已启用休眠**，否则会被系统拒绝）。"
    "⚠️ 这跟 power.lock（锁屏，随时能解锁）不是一个级别：睡着/休眠中的机器在唤醒前谁也指挥不动，"
    "远程或无人值守的调用方会**直接失联**。所以本原语**需确认**且默认只预览。"
    "⚠️ 跟 `power.shutdown` 的分工：要**关机 / 重启 / 注销**用那条（它顺带也有 sleep/hibernate 两个动作，"
    "但枚举含义不如本条的 mode 清楚）；本条只管睡眠与休眠，开工前先探好休眠开关与特权。"
    "执行前会探测令牌特权与休眠开关，不满足就当场拒绝并说明原因（不把系统报错原样抛出）。"
    "⚠️ 已知怪癖：在**启用了休眠**的系统上，请求「睡眠」有可能被系统自作主张换成「休眠」"
    "（内存写盘后断电）—— 返回值里的 hibernate_enabled 就是这个风险的指示灯。"
    "注意：真执行成功时，这次调用会**一直阻塞到机器被唤醒之后**才返回。",
    {"type": "object",
     "properties": {
         "mode": {"type": "string", "enum": ["sleep", "hibernate"],
                  "description": "sleep=睡眠（默认：快、按键即醒、内存带电）；"
                                 "hibernate=休眠（断电、慢、需系统先启用休眠）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不执行（默认）；False=真执行（需过确认）"},
     },
     "required": [], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"mode": "模式", "ok": "是否已执行", "hibernate_enabled": "休眠已启用"},
    block="power",
)
def power_sleep(mode: str = "sleep", dry_run: bool = True) -> dict:
    mode = (mode or "sleep").lower()
    if mode not in _SLEEP_MODES:
        return {"ok": False, "mode": mode,
                "note": f"未知模式 {mode!r}，可选：{'/'.join(_SLEEP_MODES)}"
                        f"（睡眠=sleep，休眠=hibernate）"}
    hib = hibernate_enabled()
    out = {"mode": mode, "mode_name": _SLEEP_MODES[mode], "dry_run": bool(dry_run),
           "hibernate_enabled": hib, "is_admin": is_admin()}
    # 前置权限探测（与 power.shutdown 同一套思路）：SetSuspendState 与 shutdown /h
    # 都要求令牌里有 SE_SHUTDOWN_NAME，缺了就别发命令出去挨系统报错。
    privs = token_privileges()
    if not privs:
        out.update({"ok": False,
                    "note": "权限探测失败：读不到当前进程令牌，无法确认睡眠/休眠权限，已拒绝执行"})
        return out
    if "SeShutdownPrivilege" not in privs:
        out.update({"ok": False,
                    "note": f"当前会话没有 SeShutdownPrivilege（睡眠与休眠都需要它），"
                            f"{_SLEEP_MODES[mode]}会被系统拒绝；请改用有该特权的账户，或以管理员身份运行。"
                            f"当前令牌特权：{sorted(privs)}"})
        return out
    # 休眠专属闸门：开关没开就直说，并给出启用办法（而不是发一条注定失败的命令）
    if mode == "hibernate" and hib is not True:
        why = ("系统里没有启用休眠（注册表 HibernateEnabled 不是 1）" if hib is False
               else "读不到休眠开关（注册表 HibernateEnabled 不可读），无法确认休眠可用")
        out.update({"ok": False,
                    "note": f"{why}，休眠会被系统拒绝。若确实要休眠，先以管理员运行：powercfg /hibernate on"})
        return out
    if mode == "sleep":
        out["api"] = "powrprof.SetSuspendState(Hibernate=FALSE, ForceCritical=FALSE, DisableWakeEvent=FALSE)"
    else:
        out["command"] = ["shutdown", "/h"]
    if dry_run:
        out.update({"ok": False, "dry_run": True,
                    "note": f"只读预览：未执行。真执行将让本机进入{_SLEEP_MODES[mode]}"
                            + ("（内存写盘后彻底断电）" if mode == "hibernate"
                               else "（内存带电、按键即醒）")
                            + "；调用方会失联到机器被唤醒为止"})
        return out
    try:
        if mode == "sleep":
            fn = ctypes.windll.powrprof.SetSuspendState
            fn.argtypes = [wintypes.BOOL, wintypes.BOOL, wintypes.BOOL]
            fn.restype = wintypes.BOOL
            # ⚠️ 真睡下去的话，这一行要等机器被唤醒之后才返回 —— 「返回值」天然滞后。
            # ForceCritical 传 FALSE（温和）：程序还能否决睡眠请求（比如放演示时）。
            # ⚠️ 已知怪癖：若系统**启用了休眠**，这里请求的是睡眠，系统却可能真的去休眠
            # （SetSuspendState 的 Hibernate=FALSE 并不总被遵守）。HibernateEnabled=0 才保险。
            ok = bool(fn(False, False, False))
            out.update({"ok": ok,
                        "note": "已从睡眠中唤醒（调用返回）" if ok
                                else "系统没有进入睡眠（SetSuspendState 返回 0）——"
                                     "可能被某个程序否决了睡眠请求，或本机不支持该睡眠状态"})
        else:
            r = subprocess.run(["shutdown", "/h"], capture_output=True, timeout=20)
            err = decode_output(r.stderr or b"").strip()
            out.update({"ok": r.returncode == 0, "returncode": r.returncode,
                        "note": "休眠指令已下发" if r.returncode == 0
                                else f"系统拒绝执行（返回 {r.returncode}）：{err[:200]}"})
    except Exception as e:
        out.update({"ok": False, "note": f"执行失败：{e}"})
    return out


# ── 电源计划（power.plan）──────────────────────────────────────────────────
# GUID 用微软官方那三件套。⚠️ `powercfg /aliases` 里的名字**反直觉**：
#   SCHEME_MAX = 节能（最大程度省电）· SCHEME_MIN = 高性能（最小程度省电）· SCHEME_BALANCED = 平衡
_PLAN_GUIDS = {
    "a1841308-3541-4fab-bc81-f71556f20b4a": "节能 (Power saver)",
    "381b4222-f694-41f0-9685-ff5bb260df2e": "平衡 (Balanced)",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "高性能 (High performance)",
}
# 关键词 ↔ GUID。多写几种写法，中英文界面都能用（显示名匹配是第二道路，见 _resolve_plan）。
_PLAN_ALIASES = {
    "saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "power saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "powersaver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "省电": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "节能": "a1841308-3541-4fab-bc81-f71556f20b4a",
    "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
    "平衡": "381b4222-f694-41f0-9685-ff5bb260df2e",
    "performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "high performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "highperformance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "高性能": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "性能": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
}
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _parse_schemes(text: str) -> list[dict]:
    """把 `powercfg /list` 的输出解析成 [{guid, name, active}]。

    ⚠️ 输出是**本地化文本**（中文系统上形如「电源方案 GUID: <guid>  (平衡) *」），
    所以只认两样跟语言无关的东西：GUID 本身，和**行尾那对括号里的方案名**。
    方案名由系统按界面语言给出（平衡 / Balanced），原样带出、不翻译也不做关键词匹配。
    """
    plans: list[dict] = []
    for line in text.splitlines():
        line = line.rstrip()
        m = _GUID_RE.search(line)
        if not m:
            continue
        tail = line[m.end():]
        nm = re.search(r"\(([^()]*)\)\s*(\*?)\s*$", tail)
        plans.append({"guid": m.group(0).lower(),
                      "name": nm.group(1) if nm else None,
                      "active": bool(nm and nm.group(2)) or tail.strip().endswith("*")})
    return plans


def _list_plans() -> tuple[list[dict], str | None]:
    """跑 powercfg /list，返回 (方案清单, 错误说明)。只读。"""
    try:
        r = subprocess.run(["powercfg", "/list"], capture_output=True, timeout=20)
    except Exception as e:
        return [], f"执行 powercfg /list 失败：{e}"
    if r.returncode != 0:
        return [], f"powercfg /list 返回 {r.returncode}：{decode_output(r.stderr or b'')[:200]}"
    return _parse_schemes(decode_output(r.stdout or b"")), None


def _resolve_plan(query: str, plans: list[dict]) -> tuple[dict | None, str]:
    """把用户给的方案标识解析成方案清单里的**一个**方案。返回 (方案|None, 说明)。

    三道路，从确定到模糊：
      ① 关键词（节能/平衡/高性能/saver/balanced/performance）→ 官方 GUID
      ② GUID 原样（含自定义方案的 GUID）
      ③ 方案名子串（界面语言无关：中文系统上写「平衡」，英文系统上写 Balanced）
    ⚠️ **一定要在本机清单里核对**才肯发命令：新机器常常只剩「平衡」一个方案（实测本机就是），
    对着不存在的方案发 `powercfg /setactive` 只会换回一句系统报错。
    """
    q = (query or "").strip()
    if not q:
        return None, "没给方案：action=set 需要 plan（节能/平衡/高性能、方案名或 GUID）"
    ql = q.lower()
    guid = _PLAN_ALIASES.get(ql) or (ql if _GUID_RE.fullmatch(ql) else None)
    if guid:
        for p in plans:
            if p["guid"] == guid:
                return p, ""
        have = "、".join(f"{p['name']}({p['guid']})" for p in plans) or "（一个都没列出来）"
        return None, (f"本机没有装 {_plan_known(guid)} 这个电源计划。本机现有：{have}。"
                      f"要恢复微软的默认方案，可用管理员运行 powercfg -duplicatescheme {guid} 后再切换")
    hits = [p for p in plans if ql in (p["name"] or "").lower()]
    if len(hits) == 1:
        return hits[0], ""
    if not hits:
        have = "、".join(p["name"] or p["guid"] for p in plans) or "（一个都没列出来）"
        return None, f"本机没有名字含 {q!r} 的电源计划。本机现有：{have}"
    return None, (f"{q!r} 命中了多个方案："
                  + "、".join(f"{p['name']}({p['guid']})" for p in hits) + "，请给完整的 GUID")


def _plan_known(guid: str) -> str:
    """官方 GUID → 可读名；不认识的原样给 GUID（不猜）。"""
    return _PLAN_GUIDS.get(guid.lower(), guid)


@declare_primitive(
    "power.plan",
    "看 / 换 Windows 的电源计划（节能 / 平衡 / 高性能）。"
    "action=get 看当前用的是哪个（只读）；action=list 列本机装了的全部计划（只读）；"
    "action=set 切换，需给 plan（节能/平衡/高性能 关键词，或方案名，或 GUID）。"
    "⚠️ 切换会系统性地改变 CPU/屏幕/硬盘/无线的省电策略 —— 换错会让笔记本续航骤降，属系统级影响，"
    "所以本条**需确认**且默认只预览。"
    "⚠️ 新机器常常只装了「平衡」一个计划：本机清单里没有的方案会**直接说明并给出恢复办法**，"
    "不会盲发命令出去挨系统报错。",
    {"type": "object",
     "properties": {
         "action": {"type": "string", "enum": ["get", "list", "set"],
                    "description": "动作，默认 get（只看当前的，只读）"},
         "plan": {"type": "string",
                  "description": "仅 action=set 需要：节能/平衡/高性能，或方案名（如 平衡/Balanced），或 GUID"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不切换（默认）；False=真切换（需过确认）"},
     },
     "required": [], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"active_plan": "当前计划", "ok": "是否已切换"},
    block="power",
)
def power_plan(action: str = "get", plan: str | None = None, dry_run: bool = True) -> dict:
    action = (action or "get").lower()
    if action not in ("get", "list", "set"):
        return {"ok": False, "action": action, "note": f"未知动作 {action!r}，可选：get/list/set"}
    plans, err = _list_plans()
    if err:
        return {"ok": False, "action": action, "note": err}
    active = next((p for p in plans if p["active"]), None)
    if active is None and len(plans) == 1:
        active = plans[0]                      # 只有一个方案时，* 标记缺失也不影响结论
    out: dict = {"action": action, "is_admin": is_admin(),
                 "active_plan": active["name"] if active else None,
                 "active_guid": active["guid"] if active else None}
    if action == "get":
        if active is None:
            out.update({"ok": False, "plan_count": len(plans),
                        "note": "没能从 powercfg /list 里认出当前方案（输出里没有 * 标记）"})
            return out
        known = _PLAN_GUIDS.get(active["guid"])
        out.update({"ok": True, "plan_count": len(plans),
                    "note": f"当前电源计划：{active['name']}"
                            + (f"（微软标准方案：{known}）" if known else "")})
        return out
    if action == "list":
        out.update({"ok": True, "plan_count": len(plans), "plans": plans,
                    "note": f"本机装了 {len(plans)} 个电源计划"
                            + ("（只有这一个，想切到别的方案得先用 powercfg -duplicatescheme 恢复）"
                               if len(plans) == 1 else "")})
        return out
    # action == "set"
    target, why = _resolve_plan(plan, plans)
    if target is None:
        out.update({"ok": False, "requested": plan, "plan_count": len(plans), "note": why})
        return out
    out.update({"target_plan": target["name"], "target_guid": target["guid"],
                "command": ["powercfg", "/setactive", target["guid"]],
                "already_active": target["guid"] == (active["guid"] if active else None)})
    if out["already_active"]:
        out.update({"ok": True, "note": f"当前已经是「{target['name']}」，无需切换"})
        return out
    if dry_run:
        out.update({"ok": False, "dry_run": True,
                    "note": f"只读预览：未切换。真执行将运行 powercfg /setactive {target['guid']}"
                            f"，把电源计划从「{active['name'] if active else '?'}」换成「{target['name']}」"
                            f"（需过确认）"})
        return out
    try:
        r = subprocess.run(["powercfg", "/setactive", target["guid"]],
                           capture_output=True, timeout=20)
    except Exception as e:
        out.update({"ok": False, "note": f"执行失败：{e}"})
        return out
    if r.returncode != 0:
        err = decode_output(r.stderr or b"").strip()
        out.update({"ok": False, "returncode": r.returncode,
                    "note": f"系统拒绝切换（返回 {r.returncode}）：{err[:200]}"
                            + ("；可试以管理员身份运行" if not is_admin() else "")})
        return out
    # 复核：命令返回 0 ≠ 真的换过去了。不复核就等于谎报成功（power.lock 的教训）。
    after, _ = _list_plans()
    now = next((p for p in after if p["active"]), None)
    verified = bool(now and now["guid"] == target["guid"])
    out.update({"ok": True, "verified": verified, "active_plan": now["name"] if now else None,
                "note": f"电源计划已切到「{target['name']}」" if verified
                        else f"命令返回成功，但复核当前方案是「{now['name'] if now else '读不到'}」，"
                             f"切换可能未生效"})
    return out


# ── 电池状态（power.battery，只读）────────────────────────────────────────
# 两条 API 一起用，因为「有没有电池」这件事必须有两个来源才敢下结论：
#   · GetSystemPowerStatus —— 便宜、通用，但「没有电池」只能靠 BatteryFlag 的 128 位猜
#   · CallNtPowerInformation(SystemBatteryState=5) —— 直接给 BatteryPresent 布尔位，权威
# 台式机上两条都会说「没有电池」；这时**如实说「这台机器没有电池」**，
# 绝不把 -1 / 255 这种占位值当成电量数字报出去。
_AC_STATUS = {0: "电池供电（未插电）", 1: "已插电（交流电）", 255: "未知"}


class _BATTERY_STATE(ctypes.Structure):
    """CallNtPowerInformation(SystemBatteryState) 的出参。

    ⚠️ 前 7 个 BOOLEAN 之后必须**按 4 字节对齐**才轮到 ULONG —— ctypes 默认对齐
    正好是 4，所以字段照头文件顺序摆即可；但别手贱加 `_pack_`，那样后面全错位。
    """
    _fields_ = [("AcOnLine", ctypes.c_byte), ("BatteryPresent", ctypes.c_byte),
                ("Charging", ctypes.c_byte), ("Discharging", ctypes.c_byte),
                ("Spare1", ctypes.c_byte * 3),
                ("MaxCapacity", wintypes.ULONG), ("RemainingCapacity", wintypes.ULONG),
                ("Rate", wintypes.ULONG), ("EstimatedTime", wintypes.ULONG),
                ("DefaultAlert1", wintypes.ULONG), ("DefaultAlert2", wintypes.ULONG)]


def _battery_state() -> dict | None:
    """权威地问一次「有没有电池 / 充电还是放电」。问不到返回 None（不猜）。"""
    try:
        b = _BATTERY_STATE()
        if ctypes.windll.powrprof.CallNtPowerInformation(
                5, None, 0, ctypes.byref(b), ctypes.sizeof(b)) != 0:
            return None
        return {"present": bool(b.BatteryPresent), "ac_online": bool(b.AcOnLine),
                "charging": bool(b.Charging), "discharging": bool(b.Discharging),
                "max_mwh": int(b.MaxCapacity), "remain_mwh": int(b.RemainingCapacity),
                "rate_mw": int(b.Rate) - (1 << 32) if b.Rate >= (1 << 31) else int(b.Rate),
                "estimated_s": int(b.EstimatedTime)}
    except Exception:
        return None


@declare_primitive(
    "power.battery",
    "查这台机器的电池：电量百分比、是否插着电、充电还是放电、按当前功耗还能撑多久（剩余时间）。"
    "回答「电量够不够 / 是不是该充电了 / 拔了电源还能用多久」时用它。"
    "⚠️ **台式机没有电池**：这时会返回 has_battery=false 并说明「这台机器没有电池」，"
    "**不会返回一个编出来的电量数字**（-1 / 255 这类占位值一律不当作数据上报）。"
    "充放电方向看 power_state（charging=在充电 / discharging=在用电池 / ac_idle=接电但没在充放电）"
    "—— 底层那两个原生布尔位在部分固件上会同时为真，所以这里按充放电功率的符号推导，不照抄。"
    "power_now_mw 的符号约定：正=正在充入、负=正在放出，可为 null。"
    "注意：remaining_min 是系统的估算值，插电时系统通常不给估算（返回 null），这是正常的。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"percent": "电量%", "ac_online": "已插电", "has_battery": "有电池"},
    block="power",
)
def power_battery() -> dict:
    class _SPS(ctypes.Structure):                # SYSTEM_POWER_STATUS
        _fields_ = [("ACLineStatus", ctypes.c_byte), ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte), ("SystemStatusFlag", ctypes.c_byte),
                    ("BatteryLifeTime", wintypes.DWORD), ("BatteryFullLifeTime", wintypes.DWORD)]
    sps = _SPS()
    got = False
    try:
        got = bool(ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)))
    except Exception:
        got = False
    auth = _battery_state()                       # 权威来源（可能拿不到）
    if not got and auth is None:
        return {"ok": False, "has_battery": None,
                "note": "读不到电池状态（GetSystemPowerStatus 与 CallNtPowerInformation 都不可用）"}
    # 「有没有电池」以权威位为准；拿不到权威位时才退回 BatteryFlag 的 128 位
    if auth is not None:
        has_battery = auth["present"]
    else:
        has_battery = got and not (int(sps.BatteryFlag) & 128)
    if not has_battery:
        # 没有电池就到此为止 —— 不拿 ACLineStatus / BatteryFlag 的占位值去凑一个「看起来像数据」的东西
        return {"ok": True, "has_battery": False,
                "ac_online": (auth["ac_online"] if auth is not None
                              else (int(sps.ACLineStatus) == 1 if got else None)),
                "percent": None, "remaining_min": None,
                "note": "这台机器没有电池（台式机 / 无电池的设备），所以没有电量与剩余时间可报"}
    out: dict = {"ok": True, "has_battery": True}
    # 插电状态：两个来源都拿得到时以权威为准，只有一个时就用手上那个
    ac = auth["ac_online"] if auth is not None else (int(sps.ACLineStatus) == 1)
    out["ac_online"] = ac
    out["ac_status"] = _AC_STATUS.get(int(sps.ACLineStatus), "未知") if got else ("已插电（交流电）" if ac else "电池供电（未插电）")
    # 电量百分比：255 是「未知」占位值，必须挡掉，不能当成 255%
    if got and 0 <= int(sps.BatteryLifePercent) <= 100:
        out["percent"] = int(sps.BatteryLifePercent)
        out["percent_source"] = "GetSystemPowerStatus"
    elif auth is not None and auth["max_mwh"] > 0:
        out["percent"] = round(auth["remain_mwh"] * 100.0 / auth["max_mwh"], 1)
        out["percent_source"] = "由容量算得（剩余/满容量）"
    else:
        out["percent"] = None
    # 充/放电方向：**不照抄原生布尔位**。
    # ⚠️ 实测（2026-09-12，本机）：CallNtPowerInformation 的 Charging 与 Discharging
    # 会**同时为 1**（固件/驱动怪癖，插着电充电时也报 Discharging=1）。照抄就会返回
    # 「既在充电又在放电」这种自相矛盾的结论。改用物理意义明确的判据，按可靠性排序：
    #   ① Rate（mW）的符号：正=在充电、负=在放电 —— 这是能量流向本身，最可信
    #   ② BatteryFlag 的 8 位（充电中）
    #   ③ 交流电状态：插着电且没在放，就算「已接电源」
    rate = auth["rate_mw"] if auth is not None else None
    if rate:
        out["power_state"] = "charging" if rate > 0 else "discharging"
        out["power_state_source"] = "由充放电功率的符号判定"
    elif got and (int(sps.BatteryFlag) & 8):
        out["power_state"] = "charging"
        out["power_state_source"] = "由 BatteryFlag 的充电位判定"
    elif ac:
        out["power_state"] = "ac_idle"
        out["power_state_source"] = "接交流电、未在充放电"
    else:
        out["power_state"] = "discharging"
        out["power_state_source"] = "由「未插电」推定（拿不到功率读数）"
    out["power_state_name"] = {"charging": "正在充电", "discharging": "正在放电（用电池）",
                               "ac_idle": "已接电源"}[out["power_state"]]
    if auth is not None and auth["max_mwh"] > 0:
        out["design_mwh"], out["remain_mwh"] = auth["max_mwh"], auth["remain_mwh"]
        out["power_now_mw"] = rate or None
    # 剩余时间：0xFFFFFFFF 是「未知」占位值（插电时系统通常不给估算）
    secs = None
    if got and int(sps.BatteryLifeTime) != 0xFFFFFFFF:
        secs = int(sps.BatteryLifeTime)
    elif auth is not None and auth["estimated_s"] != 0xFFFFFFFF and auth["estimated_s"] > 0:
        secs = int(auth["estimated_s"])
    out["remaining_min"] = round(secs / 60.0, 1) if secs else None
    out["note"] = ("已插电" if ac else "未插电，用电池") + \
                  ("；" + out["power_state_name"] if out["power_state"] != "ac_idle" else "") + \
                  ("（插电与充放电方向是两个独立读数：插着电也可能瞬时在放电，"
                   "比如电池保护模式或适配器功率不够，不是矛盾）"
                   if ac and out["power_state"] == "discharging" else "") + \
                  ("；系统没给剩余时间估算（插电时正常）" if out["remaining_min"] is None else "")
    return out
