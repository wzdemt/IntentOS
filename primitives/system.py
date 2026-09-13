"""系统域原语 —— 平台 / 内存 / 运行时长 / 内存清理 / 内存详情 / 空闲时长 / 时区。

不依赖 psutil（环境未装）：用 stdlib + ctypes(Windows API) 实现，Windows 优先。
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_system，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import platform
import re
import struct
import subprocess
import time
import winreg

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output, is_admin


# ── 系统信息（stdlib + ctypes GlobalMemoryStatusEx，只读安全）─────────────────
def _mem_status() -> dict:
    """读取内存状态（只读，安全）。出错回退到平台信息。"""
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]
    try:
        m = MEMORYSTATUSEX()
        m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return {
            "load": m.dwMemoryLoad,
            "total_mb": m.ullTotalPhys // (1024 * 1024),
            "avail_mb": m.ullAvailPhys // (1024 * 1024),
        }
    except Exception:
        return {"load": -1, "total_mb": -1, "avail_mb": -1}


@declare_primitive(
    "system.info",
    "读这台机器的基础画像：操作系统平台 / CPU 架构 / 逻辑核数 / 物理内存总量、可用量、占用率。"
    "回答「这机器什么配置 / 内存还剩多少（只要一个百分比）」时用它 —— 本域**最轻**的一条"
    "（不查进程、不采样、毫秒级返回）。"
    "⚠️ 最容易混的三条，分工写清楚："
    "① 要 **CPU 忙不忙**（占用率）用 `system.load` —— 本条的 `load` 字段是**内存占用率**，"
    "两个都叫 load、都在 0-100，拿本条的 load 当 CPU 负载报给用户**不会有人察觉，别混**；"
    "② 要内存的**详细账目**（提交量 / 页面文件 / 内核池 / 进程·线程·句柄数）用 `system.memory`；"
    "③ 要 CPU 型号 / 物理核数 / 主频用 `system.hardware`。"
    "无参数。返回 {ok, platform, machine, cpu_count, total_mb, avail_mb, load}："
    "load 是**内存占用百分比**（不是 CPU），total_mb / avail_mb 单位是 MB。"
    "⚠️ 读不到内存状态时 ok=false，且 total_mb / avail_mb / load 全是 -1（不是「内存是 -1MB」）——"
    "看 ok 与 note，别把 -1 当数据。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"platform": "系统", "machine": "机器", "cpu_count": "CPU核数",
           "total_mb": "内存MB", "avail_mb": "可用MB", "load": "占用%"},
    block="process_system",
)
def system_info() -> dict:
    mem = _mem_status()
    out: dict = {"ok": True, "platform": platform.system(), "machine": platform.machine(),
                 "cpu_count": os.cpu_count(), **mem}
    if mem.get("load", -1) < 0:
        # 读失败时静默返回 -1 会让模型当成真实数字 → 补 ok/note 把结论说清楚
        out["ok"] = False
        out["note"] = ("内存状态读不到（GlobalMemoryStatusEx 不可用），"
                       "total_mb / avail_mb / load 均为 -1，不是真实数字")
    return out


# ── 进程枚举 / 工作集清理（ctypes，Mem Reduct 同款 Native API）─────────────
def _list_pids() -> list[int]:
    """枚举所有运行中的 PID（EnumProcesses），排除 0。"""
    try:
        size = ctypes.sizeof(ctypes.c_ulong) * 4096
        buf = (ctypes.c_ulong * (size // ctypes.sizeof(ctypes.c_ulong)))()
        needed = ctypes.c_ulong(size)
        if ctypes.windll.psapi.EnumProcesses(ctypes.byref(buf), size, ctypes.byref(needed)):
            n = needed.value // ctypes.sizeof(ctypes.c_ulong)
            return [int(buf[i]) for i in range(n) if buf[i] != 0]
        return []
    except Exception:
        return []


def _empty_working_set(pid: int) -> bool:
    """对指定 PID 进程清工作集（EmptyWorkingSet）。失败返回 False。"""
    try:
        PROCESS_QUERY_INFORMATION, PROCESS_SET_QUOTA = 0x0400, 0x0100
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
        if not handle:
            return False
        ok = ctypes.windll.psapi.EmptyWorkingSet(handle)
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok)
    except Exception:
        return False


@declare_primitive(
    "system.free_memory",
    "系统级内存**清理**——注意这**不是查询原语**：想查「内存还够不够用」请用 `system.memory`"
    "（名字里的 free 是动词「释放」，不是形容词「空闲的」；2026-09-12 实测有调用方据此选错，"
    "并在无人在场时撞上确认门）。本原语枚举进程释放工作集（EmptyWorkingSet，Mem Reduct 同款 Native API）。"
    "⚠️ 危险操作，需确认。"
    "⚠️ **参数 scope 默认 processes（所有非关键进程）—— 这是一个「省略参数就等于对全系统动手」的默认值**："
    "只传 dry_run=False、不写 scope 的调用，会去清掉**全机所有非关键进程**的工作集（跳过 PID 0/4）。"
    "只想清当前进程就显式传 scope=\"self\"（最安全）；想查「内存还够不够」请去 `system.memory`，不是这条。"
    "返回 {ok, freed_mb, scanned, preview, avail_mb, note}：freed_mb 是「清理前后可用内存之差」，"
    "可能为 0（清了但没释放出可测量的量）。"
    "⚠️ **预览时 freed_mb=null**：dry_run=True 这次调用一个字节都没清，此刻的可用内存与调用前之差"
    "只是机器自己在波动 —— 报成一个数字会被读成「已经释放了这么多」（2026-09-12 审计抓到，此前正是这么报的）。"
    "用 preview=true 区分「只看了看」和「真清了」；preview=true 时 avail_mb 是**当前**可用内存。"
    "⚠️ 是预览还是失败，看 `preview` 与 `note`。",
    {"type": "object",
     "properties": {
         "scope": {"type": "string", "enum": ["processes", "self"],
                   "description": "processes=所有非关键进程（**默认，省略即全机动手**）；self=仅当前进程（最安全）"},
         "dry_run": {"type": "boolean", "description": "True=只预览(只读)；False=实际清理"},
     },
     "required": [],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"freed_mb": "释放MB", "scanned": "扫描/清理进程数", "note": "说明"},
    block="process_system",
)
def system_free_memory(scope: str = "processes", dry_run: bool = True) -> dict:
    """系统级内存清理。默认 dry_run=True 只读预览（安全验证用）；真清理需 dry_run=False + 过确认。

    安全护栏：跳过系统关键进程（PID 0=System Idle、4=System）；单独进程失败不中断（容忍单点失败）。
    """
    try:
        before = _mem_status().get("avail_mb", -1)
        if scope == "self":
            # 对当前进程清工作集（最安全，只影响自己）—— 同样受 dry_run 闸门约束
            if not dry_run:
                ctypes.windll.psapi.EmptyWorkingSet(ctypes.windll.kernel32.GetCurrentProcess())
            scanned = 1
        else:
            pids = _list_pids()
            scanned = 0
            for pid in pids:
                if pid in (0, 4):  # 跳过系统关键进程
                    continue
                scanned += 1
                if not dry_run:
                    _empty_working_set(pid)
        if dry_run:
            # ⚠️ 预览**不报 freed_mb**：这一次什么都没清，此刻可用内存与调用前之差只是
            # 机器自己在波动。报成「已释放 X MB」是假数据（2026-09-12 审计抓到）。
            return {"ok": False, "freed_mb": None, "scanned": scanned, "preview": True,
                    "avail_mb": before,
                    "note": f"只读预览：本次**没有清理任何进程**，{before} MB 是此刻的可用内存、"
                            f"不是清理结果；扫到 {scanned} 个可清理的进程。"
                            f"要真清理请传 dry_run=False（需用户确认）"}
        after = _mem_status().get("avail_mb", -1)
        delta = max(0, after - before)
        return {"ok": True, "freed_mb": delta, "scanned": scanned, "preview": False,
                "avail_mb": after,
                "note": f"实际清理了 {scanned} 个进程的工作集（跳过系统关键进程 0/4），"
                        f"可用内存 {before} → {after} MB，净增 {delta} MB。"
                        f"⚠️ 这是**净变化** —— 期间别的进程也在申请/归还内存，"
                        f"所以它小于「被清进程原本占用的量」是正常的"}
    except Exception as e:
        return {"ok": False, "freed_mb": None, "scanned": 0, "preview": bool(dry_run),
                "avail_mb": None, "note": f"清理失败/不支持：{e}"}


# ── 运行时长（system.uptime）──────────────────────────────────────────────
def _uptime_ms() -> int:
    """系统启动至今的毫秒数；读不到返回 -1。

    用 Windows 的 `GetTickCount64` —— 它的语义**就是**「开机至今」。
    ⚠️ 不用 `time.monotonic()`：Python 文档里那个函数的起点写着「未指定」，
    在 Windows 上恰好等于开机时间，属于**撞上的巧合、不是承诺**（换平台就不一定）。
    """
    try:
        fn = ctypes.windll.kernel32.GetTickCount64
        fn.restype = ctypes.c_ulonglong   # ⚠️ 必须显式声明：默认按 32 位 int 取会被截断
        return int(fn())
    except Exception:
        return -1


@declare_primitive(
    "system.uptime",
    "查系统本次运行了多久（这台电脑开机多长）：返回运行分钟数 uptime_min 与开机时刻 boot_at。"
    "回答「开机多久了 / 是不是该重启了 / 上次什么时候重启的」时用它。"
    "⚠️ 别跟 `system.idle_time` 混：那个是「**用户**多久没动键鼠」（人在不在），本条是「**机器**开着多久」；"
    "在无人登录的会话里两者会**相等**（从开机起一直没人动键鼠），别把这个相等读成「用户一直在用」。"
    "无参数。返回 {ok, uptime_min, boot_at}：uptime_min 是分钟（保留 1 位小数），boot_at 是本地时间字符串。"
    "⚠️ 读不到时 ok=false、uptime_min=-1、boot_at=null（不是「运行了 -1 分钟」）—— 看 ok 判断。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"uptime_min": "运行分钟", "boot_at": "启动时刻"},
    block="process_system",
)
def system_uptime() -> dict:
    ms = _uptime_ms()
    if ms < 0:
        return {"ok": False, "uptime_min": -1, "boot_at": None,
                "note": "读不到系统运行时长（GetTickCount64 不可用），uptime_min=-1 不是真实数字"}
    boot_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - ms / 1000))
    return {"ok": True, "uptime_min": round(ms / 60000, 1), "boot_at": boot_at}


# ── 硬件画像（system.hardware）─────────────────────────────────────────────
# 为什么型号/主频读注册表而不是 WMI：这两个字段没有「便宜的」Win32 直读接口（WMI 得
# 起一个 PowerShell，几百毫秒起步），而 HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
# 是内核启动时自己写进去的 CPU 自述 —— 只读、零依赖、微秒级。
# 核数则相反，注册表没有权威字段，得走 API：
#   · 逻辑核数 = GetSystemInfo 的 dwNumberOfProcessors（**只算当前处理器组**，>64 逻辑核
#     会少算，所以再和 os.cpu_count() 取大值兜底）
#   · 物理核数 = GetLogicalProcessorInformationEx(RelationProcessorCore) 数记录条数
#     （一条记录 = 一个物理核）。它返回的是**变长结构数组**，没有元素个数可读，
#     只能按「关系类型(4B) + Size(4B)」逐条往后跳 —— Size 是唯一的步长依据。
_CPU_REG_KEY = r"HARDWARE\DESCRIPTION\System\CentralProcessor"


class _SYSTEM_INFO(ctypes.Structure):
    """GetSystemInfo 的出参。字段顺序照 Win32 头文件摆，不能省 —— 少一个就整体错位。"""
    _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_size_t),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)]


def _logical_cores() -> int:
    """逻辑核数（处理器数）。API 与 os.cpu_count() 取大值：前者漏算多处理器组，后者不会。"""
    n = 0
    try:
        si = _SYSTEM_INFO()
        fn = ctypes.windll.kernel32.GetSystemInfo
        fn.argtypes = [ctypes.POINTER(_SYSTEM_INFO)]
        fn(ctypes.byref(si))
        n = int(si.dwNumberOfProcessors)
    except Exception:
        n = 0
    return max(n, os.cpu_count() or 0)


def _physical_cores() -> int:
    """物理核数；读不到返回 -1（调用方转成 None，不编造数字）。"""
    try:
        fn = ctypes.windll.kernel32.GetLogicalProcessorInformationEx
        fn.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        fn.restype = wintypes.BOOL
        need = wintypes.DWORD(0)
        fn(0, None, ctypes.byref(need))        # 先空跑一次问长度（必失败，但 need 被填上）
        if not need.value:
            return -1
        buf = ctypes.create_string_buffer(need.value)
        if not fn(0, buf, ctypes.byref(need)):
            return -1
        raw, cores, off = buf.raw, 0, 0
        while off + 8 <= need.value:
            rel, size = struct.unpack_from("<II", raw, off)
            if size <= 8:                      # 步长为 0/负数会死循环，宁可当场收手
                break
            if rel == 0:                       # RelationProcessorCore
                cores += 1
            off += size
        return cores or -1
    except Exception:
        return -1


def _cpu_registry() -> dict:
    """从注册表取 CPU 型号/厂商/标称主频。

    子键 0..N-1 在老系统上**是每个逻辑处理器一个**（不是每个插槽一个），所以型号取第一份
    非空值即可；主频同理。整段失败不抛错 —— 硬件原语不该因为一个可选字段读不到就整体失败。
    """
    out: dict = {"name": None, "vendor": None, "base_mhz": None, "entries": 0}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CPU_REG_KEY, 0, winreg.KEY_READ) as parent:
            subs, i = [], 0
            while True:
                try:
                    subs.append(winreg.EnumKey(parent, i))
                except OSError:
                    break
                i += 1
        out["entries"] = len(subs)
        for sub in subs:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{_CPU_REG_KEY}\\{sub}",
                                    0, winreg.KEY_READ) as key:
                    if out["name"] is None:
                        out["name"] = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                    if out["vendor"] is None:
                        out["vendor"] = winreg.QueryValueEx(key, "VendorIdentifier")[0]
                    if out["base_mhz"] is None:
                        mhz = winreg.QueryValueEx(key, "~MHz")[0]
                        out["base_mhz"] = int(mhz) if isinstance(mhz, int) else None
            except OSError:
                continue                        # 单个子键缺字段/读不到 → 跳过，不中断
            if out["name"] and out["base_mhz"]:
                break
    except Exception as e:
        out["error"] = str(e)
    return out


@declare_primitive(
    "system.hardware",
    "查这台机器的 CPU 硬件画像：型号（如 Intel Core i7-9750H）、厂商、物理核数 / 逻辑核数、"
    "标称主频(MHz)。回答「我这电脑什么配置 / 几核几线程 / 能不能跑得动」时用它。"
    "⚠️ 跟同域两条的分工：只要「什么系统 / 多少内存 / 内存占用」用 `system.info`（更轻、毫秒级）；"
    "要「CPU 现在忙不忙（占用率）」用 `system.load`；本条只答**硬件是谁**，不答**现在多忙**。"
    "无参数。返回 {ok, cpu_name, vendor, physical_cores, logical_cores, base_mhz, note}："
    "physical_cores / logical_cores 读不到时为 null（**不编数字**）；base_mhz 是**标称**主频"
    "（注册表里的 ~MHz，不随睿频变化），不是当前实时频率。无副作用。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"cpu_name": "CPU", "physical_cores": "物理核", "logical_cores": "逻辑核"},
    block="process_system",
)
def system_hardware() -> dict:
    reg = _cpu_registry()
    phys = _physical_cores()
    logical = _logical_cores()
    notes: list[str] = []
    if phys < 0:
        notes.append("物理核数读不到（GetLogicalProcessorInformationEx 不可用）")
    if reg.get("name") is None:
        notes.append("CPU 型号读不到（注册表 CentralProcessor 键不可读，ARM 或精简体系统上可能如此）")
    if reg.get("base_mhz") is None:
        notes.append("标称主频无记录（注册表无 ~MHz 值）")
    return {"ok": True,
            "cpu_name": reg.get("name"),
            "vendor": reg.get("vendor"),
            "physical_cores": phys if phys > 0 else None,
            "logical_cores": logical or None,
            "base_mhz": reg.get("base_mhz"),
            "note": "；".join(notes)}


# ── CPU 占用率（system.load）───────────────────────────────────────────────
# GetSystemTimes 吐的是**开机以来的累计值**（idle/kernel/user 三条），单次调用算不出占用率，
# 必须「采样两次求差」。两个坑：
#   ① **kernel 时间包含 idle 时间** —— 直接 kernel+user 当分母、把 kernel 当「系统占用」
#      算出来会离谱（本机实测能超过 100%）。正解：total = kernel + user，busy = total - idle。
#   ② 采样窗口不能长（别把调用方卡住），也不能短到量不出（差值太小、噪声淹没信号），
#      所以参数留了默认 500ms 并夹在 100~3000ms —— 上限就是「别把窗口开到几秒」。
class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


def _filetime_ticks(ft: _FILETIME) -> int:
    """FILETIME → 100ns 单位的整数。高低位各 32 位，必须自己拼（结构体里没有 int64 视图）。"""
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


def _system_times() -> tuple[int, int, int] | None:
    """(idle, kernel, user) 累计 100ns；不可用返回 None。"""
    try:
        fn = ctypes.windll.kernel32.GetSystemTimes
        fn.argtypes = [ctypes.POINTER(_FILETIME)] * 3
        fn.restype = wintypes.BOOL
        i, k, u = _FILETIME(), _FILETIME(), _FILETIME()
        if not fn(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u)):
            return None
        return _filetime_ticks(i), _filetime_ticks(k), _filetime_ticks(u)
    except Exception:
        return None


@declare_primitive(
    "system.load",
    "查整机 CPU 忙不忙：两次采样 GetSystemTimes 求差，给出总占用率、用户态/内核态占比和空闲率(%)。"
    "想知道「现在系统卡不卡 / CPU 是不是跑满了」时用它。"
    "参数 sample_ms 是采样窗口（默认 500ms，夹在 100~3000ms）——**这个原语会真的等这么久**，"
    "调用方要接受一次 0.1~3 秒的耗时；想连续观察就隔几秒多调几次。"
    "⚠️ **同名不同义，最容易报错的一条**：本条的占用率是 **CPU**；`system.info` 返回里也有个叫 `load` 的字段，"
    "那是**内存**占用率 —— 两个都叫 load、都在 0-100，把 system.info 的 load 当 CPU 负载报给用户不会有人察觉。"
    "要 CPU 型号 / 核数 / 主频用 `system.hardware`；要内存的明细账目用 `system.memory`。"
    "返回 {ok, busy_pct, idle_pct, user_pct, kernel_pct, cores, sample_ms, elapsed_ms, note}："
    "⚠️ ok=false 表示这两次采样没成功（时间源不可用 / 窗口内没有有效时间差），此时不含 busy_pct，"
    "别把「没采到」当成「CPU 不忙」。",
    {"type": "object",
     "properties": {
         "sample_ms": {"type": "integer", "minimum": 100, "maximum": 3000,
                       "description": "采样窗口毫秒数，默认 500，允许 100~3000（越小越快但抖动越大）"},
     },
     "required": [],
     "additionalProperties": False},
    state={"busy_pct": "CPU占用%", "idle_pct": "空闲%"},
    block="process_system",
)
def system_load(sample_ms: int = 500) -> dict:
    try:
        win = max(100, min(int(sample_ms), 3000))
    except (TypeError, ValueError):
        win = 500
    t0 = _system_times()
    if t0 is None:
        return {"ok": False, "note": "读不到系统时间（GetSystemTimes 不可用）"}
    clock0 = time.perf_counter()
    time.sleep(win / 1000.0)                    # 唯一的等待点，窗口由参数决定、不放大
    t1 = _system_times()
    elapsed_ms = round((time.perf_counter() - clock0) * 1000, 1)
    if t1 is None:
        return {"ok": False, "note": "第二次采样失败（GetSystemTimes 不可用）"}
    d_idle = max(0, t1[0] - t0[0])
    # kernel 含 idle：先各自求差，再把 idle 从 kernel 里刨掉，剩下的才是真正的内核态忙时
    d_kernel = max(0, t1[1] - t0[1])
    d_user = max(0, t1[2] - t0[2])
    total = d_kernel + d_user
    if total <= 0:
        return {"ok": False, "sample_ms": win, "elapsed_ms": elapsed_ms,
                "note": "采样窗口内没拿到有效时间差（窗口太短？），把 sample_ms 调大再试"}
    idle = min(d_idle, total)                   # 极端情况下 idle 可能略大于 total，夹一下防负值
    busy = total - idle
    busy_pct = round(busy * 100.0 / total, 1)
    return {"ok": True,
            "busy_pct": busy_pct,
            "idle_pct": round(100.0 - busy_pct, 1),
            "user_pct": round(d_user * 100.0 / total, 1),
            "kernel_pct": round(max(0, d_kernel - idle) * 100.0 / total, 1),
            "cores": _logical_cores() or None,
            "sample_ms": win, "elapsed_ms": elapsed_ms,
            "note": f"{win}ms 窗口内 CPU 占用 {busy_pct}%"
                    + ("（快跑满了）" if busy_pct >= 85 else "（系统不忙）" if busy_pct <= 15 else "")}


# ── 内存详情（system.memory，只读）─────────────────────────────────────────
# 比 system.info 多一层账：system.info 只答「总量/可用/占用」，本原语还要答
#   · 提交量（commit）：进程「已认领」的虚拟内存 —— 它才是「内存够不够」的真指标，
#     物理内存被页面文件撑大后，光看物理占用率会误判（占用率不高但提交爆了一样会崩）
#   · 页面文件 / 系统缓存 / 内核分页与非分页池 / 进程·线程·句柄数
# 数据源：GlobalMemoryStatusEx（经 _mem_status 复用）+ GetPerformanceInfo（psapi）。
def _perf_info() -> dict | None:
    """GetPerformanceInfo 的原生计数（单位是「页」，要用 PageSize 换算）。

    ⚠️ 这个结构里混着 `DWORD cb` 和一堆 `SIZE_T`：**cb 是 DWORD、后面紧跟 8 字节的
    SIZE_T**，ctypes 会自然对齐到 8，所以字段照头文件顺序摆即可，别加 `_pack_`。
    """
    class PERFORMANCE_INFORMATION(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD),
                    ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                    ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                    ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                    ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                    ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                    ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD),
                    ("ThreadCount", wintypes.DWORD)]
    try:
        p = PERFORMANCE_INFORMATION()
        p.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
        if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(p), p.cb):
            return None
        return {k: int(getattr(p, k)) for k in
                ("CommitTotal", "CommitLimit", "CommitPeak", "PhysicalTotal",
                 "PhysicalAvailable", "SystemCache", "KernelTotal", "KernelPaged",
                 "KernelNonpaged", "PageSize", "HandleCount", "ProcessCount", "ThreadCount")}
    except Exception:
        return None


@declare_primitive(
    "system.memory",
    "查内存的**详细账目**：物理内存总量 / 可用 / 已用 / 占用率、提交量（commit：已提交 / 上限 / 峰值 / 占比）、"
    "页面文件大小、系统缓存、内核分页池与非分页池、进程 / 线程 / 句柄数。"
    "回答「内存够不够 / 是不是快爆了 / 为什么卡 / 要不要清内存」时用它；只要一个占用率就用 system.info（更轻）。"
    "⚠️ 别跟 `system.free_memory` 混：那条是**清理**内存（名字里的 free 是动词「释放」），是**写操作、需确认**；"
    "本条只读。真要清工作集才去调它，只是查账就用本条。"
    "⚠️ 要 **CPU** 忙不忙用 `system.load`（本原语只讲内存，不报 CPU 占用）。"
    "⚠️ 关注 `commit_pct` 而不只是 `used_pct`：物理内存占用不高但**提交量**逼近上限时，"
    "新程序一样会因为「提交失败」起不来（这时该加页面文件或关程序，清工作集没用）。"
    "⚠️ `pagefile_total_mb` 是从「提交上限 − 物理内存总量」推出来的（与任务管理器同一算法）；"
    "`commit_used_mb / commit_limit_mb` 才是权威值，别拿推出值当承诺。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"used_pct": "已用%", "commit_pct": "提交%", "avail_mb": "可用MB"},
    block="process_system",
)
def system_memory() -> dict:
    mem = _mem_status()
    total, avail = mem.get("total_mb", -1), mem.get("avail_mb", -1)
    if total is None or total < 0:
        return {"ok": False, "note": "读不到物理内存状态（GlobalMemoryStatusEx 不可用，"
                                    "本原语目前只在 Windows 上实现）"}
    used = max(0, total - avail)
    out: dict = {"ok": True,
                 "total_mb": total, "avail_mb": avail, "used_mb": used,
                 "used_pct": round(used * 100.0 / total, 1) if total else None}
    perf = _perf_info()
    if perf is None:
        out["note"] = "物理内存读到了，但提交量/页面文件读不到（GetPerformanceInfo 不可用）"
        return out
    page = perf["PageSize"] or 4096                 # 换算因子：计数 × 页大小 = 字节
    to_mb = lambda pages: pages * page // (1024 * 1024)   # noqa: E731
    commit_used, commit_limit = to_mb(perf["CommitTotal"]), to_mb(perf["CommitLimit"])
    out.update({
        "commit_used_mb": commit_used, "commit_limit_mb": commit_limit,
        "commit_peak_mb": to_mb(perf["CommitPeak"]),
        "commit_avail_mb": max(0, commit_limit - commit_used),
        "commit_pct": round(commit_used * 100.0 / commit_limit, 1) if commit_limit else None,
        # 页面文件 = 提交上限 − 物理内存（任务管理器同款推法）；权威值是上面那对
        "pagefile_total_mb": max(0, commit_limit - total),
        "pagefile_used_mb": max(0, commit_used - used),
        "system_cache_mb": to_mb(perf["SystemCache"]),
        "kernel_paged_mb": to_mb(perf["KernelPaged"]),
        "kernel_nonpaged_mb": to_mb(perf["KernelNonpaged"]),
        "handles": perf["HandleCount"], "processes": perf["ProcessCount"],
        "threads": perf["ThreadCount"],
    })
    notes = []
    if out["used_pct"] is not None and out["used_pct"] >= 90:
        notes.append("物理内存快满了")
    if out["commit_pct"] is not None and out["commit_pct"] >= 90:
        notes.append("提交量快顶到上限了（该加页面文件或关程序，清工作集救不了这个）")
    notes.append("pagefile_total_mb 为推导值，commit_* 为权威值")
    out["note"] = "；".join(notes)
    return out


# ── 空闲时长（system.idle_time，只读）─────────────────────────────────────
# 「用户多久没动键鼠了」不是一个孤立的好奇心指标 —— 它是**别的原语的判断依据**：
# 空闲久 = 用户不在，此时弹通知没人看、抢焦点会打断别的程序、做需要人回应的操作会卡住。
# 所以除了秒数，还直接给出 is_away 布尔位，省得每个调用方各写一遍阈值比较。
class _LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


@declare_primitive(
    "system.idle_time",
    "查用户已经多久没碰键盘鼠标了（当前交互会话）。**这是别的原语做判断的依据**："
    "idle_seconds 很大就说明人不在，此时不该弹通知、不该抢焦点、不该做需要人回应的操作；"
    "想知道「现在有没有人在」就调它。参数 away_seconds 是「算不算离开」的阈值（默认 300 秒 = 5 分钟），"
    "返回值里的 is_away 就是这个判定的结果，省得调用方自己比。"
    "⚠️ 跟 `system.uptime` 的分工：那个是「**机器**开了多久」，本条是「**用户**多久没动键鼠」；"
    "在无人登录 / 服务账户的会话里两者会**相等**（从开机起一直没人动键鼠），这不是「用户一直在用」的证据。"
    "⚠️ 只统计**当前交互会话**的键鼠输入：远程桌面或其它登录会话里的操作不算；"
    "在服务账户 / 无人登录的会话里这个值会一直等于「系统运行时长」，别当成有人。",
    {"type": "object",
     "properties": {
         "away_seconds": {"type": "integer", "minimum": 0, "maximum": 86400,
                          "description": "「算不算人离开了」的阈值秒数，默认 300（取 0~86400）"},
     },
     "required": [], "additionalProperties": False},
    state={"idle_seconds": "空闲秒", "is_away": "用户离开", "last_input_at": "最后操作时刻"},
    block="process_system",
)
def system_idle_time(away_seconds: int = 300) -> dict:
    try:
        thr = max(0, min(int(away_seconds), 86400))
    except (TypeError, ValueError):
        thr = 300
    try:
        li = _LASTINPUTINFO()
        li.cbSize = ctypes.sizeof(_LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li)):
            return {"ok": False, "note": "读不到用户输入时间（GetLastInputInfo 不可用）"}
        # ⚠️ 两个 tick 都必须是 **32 位**：GetLastInputInfo 吐的 dwTime 本身就是 32 位
        # （系统连续运行约 49.7 天后回绕一次）。拿 64 位的 GetTickCount64 直接去减它，
        # 开机满 49.7 天之后就会算出一个巨大的假空闲值 —— 同宽相减、再按 2^32 取模才自洽。
        gc = ctypes.windll.kernel32.GetTickCount
        gc.restype = wintypes.DWORD
        idle_ms = (int(gc()) - int(li.dwTime)) & 0xFFFFFFFF
    except Exception as e:
        return {"ok": False, "note": f"读不到用户空闲时长：{e}"}
    idle_s = round(idle_ms / 1000.0, 1)
    last_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - idle_s))
    return {"ok": True, "idle_seconds": idle_s, "idle_min": round(idle_s / 60.0, 1),
            "away_seconds_threshold": thr, "is_away": idle_s >= thr,
            "last_input_at": last_at,
            "note": (f"用户已离开（{idle_s} 秒没动键鼠，超过 {thr} 秒阈值）—— 别弹通知、别抢焦点"
                     if idle_s >= thr else
                     f"用户在场（{idle_s} 秒前还在操作）")
                    + "；只统计当前交互会话的键鼠"}


# ── 时区（time.zones）──────────────────────────────────────────────────────
# 为什么这条原语写在 system.py：本次改动只允许动 power.py / system.py 两个文件，而时区语义上
# 属于「时间域」。原语名照能力地图叫 time.zones —— **注册表按名字认、不按文件认**，
# 将来若新建 primitives/time.py，把这一节整体搬过去即可，注册名与状态表都不受影响。
#
# 看（get/list）用系统自带的 tzutil.exe，只读；换（set）也是 tzutil /s，但会**整体平移
# 这台机器上所有时间戳的含义** —— 日志、计划任务、文件时间、证书校验全跟着变，属系统级影响。
_TZUTIL = "tzutil"


def _tz_list() -> tuple[list[dict], str | None]:
    """跑 `tzutil /l`，返回 ([{id, display}], 错误说明)。只读。

    输出格式（实测）：一条目两行 —— 先显示名、再时区 ID，条目之间用空行分隔。形如
        (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi \\r\\n
        China Standard Time \\r\\n
        \\r\\n
    ⚠️ 显示名是**本地化文本**（中文系统上是中文、英文系统上是英文），所以只能按
    「空行分组、组内两行」这个**结构**来解析，绝不能按任何关键词去匹配。
    """
    try:
        r = subprocess.run([_TZUTIL, "/l"], capture_output=True, timeout=20)
    except Exception as e:
        return [], f"执行 {_TZUTIL} /l 失败：{e}"
    if r.returncode != 0:
        return [], f"{_TZUTIL} /l 返回 {r.returncode}：{decode_output(r.stderr or b'')[:200]}"
    zones: list[dict] = []
    for block in re.split(r"\r?\n\s*\r?\n", decode_output(r.stdout or b"").replace("\r", "")):
        lines = [l.strip() for l in block.split("\n") if l.strip()]
        if len(lines) >= 2:                    # 组内两行：显示名 + ID；多的行不认（不猜）
            zones.append({"id": lines[1], "display": lines[0]})
    return zones, None


def _tz_current() -> tuple[str | None, str | None]:
    """当前时区 ID。`tzutil /g` 的输出**不带换行**，必须 strip。返回 (id, 错误说明)。"""
    try:
        r = subprocess.run([_TZUTIL, "/g"], capture_output=True, timeout=20)
    except Exception as e:
        return None, f"执行 {_TZUTIL} /g 失败：{e}"
    if r.returncode != 0:
        return None, f"{_TZUTIL} /g 返回 {r.returncode}：{decode_output(r.stderr or b'')[:200]}"
    return (decode_output(r.stdout or b"").strip() or None), None


def _utc_offset_hours() -> float:
    """本地当前的 UTC 偏移（小时）。夏令时期间要用 altzone —— 用错会差一小时。"""
    if time.daylight and time.localtime().tm_isdst > 0:
        return round(-time.altzone / 3600.0, 2)
    return round(-time.timezone / 3600.0, 2)


def _fmt_offset(hours: float) -> str:
    """偏移小时数 → `UTC+08:00` 这种写法（负偏移的取整别把符号搞反）。"""
    sign = "+" if hours >= 0 else "-"
    total = int(round(abs(hours) * 60))
    return f"UTC{sign}{total // 60:02d}:{total % 60:02d}"


@declare_primitive(
    "time.zones",
    "**看**系统时区与当前时间。action=get（默认）返回当前时区（Windows 时区 ID / 本地化显示名 / "
    "UTC 偏移）**以及此刻的本地时间**（`local_time`，形如 `2026-09-12 20:58:11`，`tz_name` 是时区简称）"
    "—— 问「现在几点」「现在什么时间」就用它；"
    "action=list 列全部可用时区（约 139 个，可用 filter 按关键字过滤，中文界面名或英文 ID 都行）。"
    "⚠️ **要换时区用 `time.set_zone`**（那条会改系统状态、需确认），本原语只读、不改任何东西、**无需确认**。"
    "⚠️ 本原语报的是**这台机器当前的本地时间**；它不做时间同步、不查网络时间、也不接受时区参数"
    "（要看别的时区，先看当前 UTC 偏移自己换算，或换时区——但那是 system 级的操作）。",
    {"type": "object",
     "properties": {
         "action": {"type": "string", "enum": ["get", "list"],
                    "description": "动作，默认 get（看当前时区 + 当前时间）"},
         "filter": {"type": "string", "description": "仅 action=list 用：按关键字过滤（ID 或显示名子串）"},
     },
     "required": [], "additionalProperties": False},
    state={"zone_id": "当前时区"},
    block="process_system",
)
def time_zones(action: str = "get", filter: str | None = None) -> dict:
    action = (action or "get").lower()
    if action not in ("get", "list"):
        return {"ok": False, "action": action, "note": f"未知动作 {action!r}，可选：get/list"
                f"（要换时区请用 time.set_zone）"}
    if action == "get":
        zid, err = _tz_current()
        if err:
            return {"ok": False, "action": "get", "note": err}
        if not zid:
            return {"ok": False, "action": "get", "note": f"{_TZUTIL} /g 没返回时区 ID"}
        zones, _ = _tz_list()
        disp = next((z["display"] for z in zones if z["id"].lower() == zid.lower()), None)
        off = _utc_offset_hours()
        return {"ok": True, "action": "get", "zone_id": zid, "display": disp,
                "utc_offset_hours": off, "utc_offset": _fmt_offset(off),
                "local_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "tz_name": time.tzname[0],
                "note": f"当前时间 {time.strftime('%Y-%m-%d %H:%M:%S')}，"
                        f"时区 {disp or zid}（{zid}，{_fmt_offset(off)}）"
                        + ("；显示名没在 tzutil /l 清单里找到，可能清单读取失败" if disp is None else "")}
    # action == "list"
    zones, err = _tz_list()
    if err:
        return {"ok": False, "action": "list", "note": err}
    total = len(zones)
    kw = (filter or "").strip().lower()
    if kw:
        zones = [z for z in zones if kw in z["id"].lower() or kw in z["display"].lower()]
    cur, _ = _tz_current()
    return {"ok": True, "action": "list", "total": total, "matched": len(zones),
            "current": cur, "zones": zones,
            "note": f"可用时区共 {total} 个" + (f"，匹配 {kw!r} 的有 {len(zones)} 个" if kw else "")
                    + ("；结果为空，换个关键字试试" if kw and not zones else "")}


@declare_primitive(
    "time.set_zone",
    "**换**系统时区。zone 给时区 ID（如 China Standard Time），或能唯一命中的显示名片段（如 Beijing）——"
    "命中多个时会返回候选列表，要求给完整 ID，不猜。"
    "⚠️ 换时区会让**这台机器上所有时间戳的含义整体平移** —— 日志时间、计划任务的触发时刻、"
    "文件时间、证书有效期校验全都跟着变，是**系统级影响**。**需确认**（默认 dry_run=true 只预览）。"
    "⚠️ 换时区要进程令牌里有 SeTimeZonePrivilege —— 普通交互用户默认就有，**不需要管理员**；"
    "系统拒绝时会把原因翻成人话返回，不原样抛出。"
    "⚠️ **只是想看当前时区或当前时间，用 `time.zones`**（只读、无需确认），别用本原语 ——"
    "它是整个库里唯一会改变时间口径的操作。",
    {"type": "object",
     "properties": {
         "zone": {"type": "string",
                  "description": "时区 ID（如 China Standard Time / Pacific Standard Time），"
                                 "或能唯一命中的显示名片段（如 Beijing）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不切换（默认）；False=真切换（需过确认）"},
     },
     "required": ["zone"], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"zone_id": "切换后时区"},
    block="process_system",
)
def time_set_zone(zone: str = "", dry_run: bool = True) -> dict:
    q = (zone or "").strip()
    if not q:
        return {"ok": False, "action": "set", "note": "没给时区：action=set 需要 zone（时区 ID 或显示名片段）"}
    zones, err = _tz_list()
    if err:
        return {"ok": False, "action": "set", "note": err}
    target = next((z for z in zones if z["id"].lower() == q.lower()), None)
    how = "按 ID 精确命中"
    if target is None:                          # 退一步：按显示名/ID 子串找，且必须唯一
        hits = [z for z in zones if q.lower() in z["id"].lower() or q.lower() in z["display"].lower()]
        if len(hits) > 1:
            return {"ok": False, "action": "set", "requested": q, "candidates": hits[:10],
                    "note": f"{q!r} 命中了 {len(hits)} 个时区，请给完整的时区 ID 再试："
                            + "、".join(z["id"] for z in hits[:10])}
        target = hits[0] if hits else None
        how = "按名字片段唯一命中"
    if target is None:
        return {"ok": False, "action": "set", "requested": q, "total": len(zones),
                "note": f"tzutil 的时区清单里没有 {q!r}。先用 action=list 加 filter 查准确 ID"}
    cur, _ = _tz_current()
    out: dict = {"action": "set", "requested": q, "target_zone": target["id"],
                 "target_display": target["display"], "matched_by": how,
                 "current_zone": cur, "command": [_TZUTIL, "/s", target["id"]],
                 "is_admin": is_admin()}
    if cur and cur.lower() == target["id"].lower():
        out.update({"ok": True, "zone_id": cur, "note": f"当前已经是「{target['id']}」，无需切换"})
        return out
    # 关于权限：换时区要令牌里有 SeTimeZonePrivilege（普通交互用户默认就有，**不需要管理员**），
    # 所以这里不做硬性前置拦截 —— 探测那个特权需要遍历令牌，而那段代码在电源域（power.py）里，
    # 跨域 import 会让 power.py 被加载第二遍（见 _common.py 开头的说明），不值得。
    # 换时区失败没有任何破坏性后果，故改成「发出去 + 把失败原因翻成人话」，
    # 比按 is_admin() 硬拦更准 —— is_admin() 为 False 的普通账户其实是能换时区的。
    if dry_run:
        out.update({"ok": False, "dry_run": True,
                    "note": f"只读预览：未切换。真执行将运行 {_TZUTIL} /s \"{target['id']}\"，"
                            f"把时区从「{cur}」换成「{target['id']}」"
                            f"（{target['display']}）—— 注意这会让本机所有时间戳的含义整体平移"})
        return out
    try:
        r = subprocess.run([_TZUTIL, "/s", target["id"]], capture_output=True, timeout=20)
    except Exception as e:
        out.update({"ok": False, "note": f"执行失败：{e}"})
        return out
    if r.returncode != 0:
        err = decode_output(r.stderr or b"").strip()
        out.update({"ok": False, "returncode": r.returncode,
                    "note": f"系统拒绝切换（返回 {r.returncode}）：{err[:200]}"
                            + ("；当前不是管理员，若怀疑是权限问题可试以管理员身份运行"
                               if not is_admin() else "")})
        return out
    # 复核：命令返回 0 ≠ 真的换过去了（power.lock 的教训），再读一次 /g 才算数
    after, _ = _tz_current()
    verified = bool(after and after.lower() == target["id"].lower())
    off = _utc_offset_hours()
    out.update({"ok": True, "verified": verified, "zone_id": after,
                "utc_offset_hours": off, "utc_offset": _fmt_offset(off),
                "note": f"时区已切到「{target['id']}」（{_fmt_offset(off)}）" if verified
                        else f"命令返回成功，但复核当前时区是「{after}」，切换可能未生效"})
    return out
