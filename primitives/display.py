"""显示域原语 —— 分辨率 / 刷新率、显示器、当前显示模式、亮度（display.*）。

**四条全部只读** —— 不改任何状态，因此不需要 dry_run、也不需要确认。

零依赖：只用 `ctypes` 调系统 GDI / User32 / dxva2，不引任何第三方库。
亮度还有一条**系统 WMI** 的兜底（经 Windows 自带的 PowerShell 调用）—— 那不是第三方依赖，
PowerShell 是系统组件；走它的原因见文件末尾「亮度为什么有两条路」。

**三条「必须给人话、不许编数字」的约定**（显示域最容易糊弄，所以写死在注释里）：
  · **取不到就说取不到**。台式机 + 外接屏没有亮度接口是常态，不是错误；
    返回里 `supported=false` + 中文原因，绝不返回一个编出来的数字。
  · **「当前」只认 `ENUM_CURRENT_SETTINGS`**。模式列表里有成百条，谁在生效由系统说了算，
    不靠猜（不拿「列表里第一条」当当前）。
  · **装过的适配器 ≠ 正在用的屏**。实测本机 `EnumDisplayDevices` 枚举出 **30 个**显示适配器，
    其中只有 1 个 `StateFlags` 含 `ATTACHED_TO_DESKTOP`（其余是 Parsec / 向日葵之类的
    虚拟显卡驱动留下的僵尸条目）。只按 `EnumDisplayDevices` 出结果就会谎报「本机 30 块屏」，
    所以显示器一律以 `EnumDisplayMonitors`（只返回**真正挂在桌面上的**屏）为准。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_display，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import subprocess

from core.factory import declare_primitive  # type: ignore
from primitives._common import set_dpi_aware

_user32 = ctypes.windll.user32
_gdi32 = ctypes.windll.gdi32

# 显示适配器状态位（EnumDisplayDevices 的 StateFlags）
_ATTACHED_TO_DESKTOP = 0x1
_PRIMARY_DEVICE = 0x4
# EnumDisplaySettings 的两个特殊索引
_ENUM_CURRENT_SETTINGS = 0xFFFFFFFF
_ENUM_REGISTRY_SETTINGS = 0xFFFFFFFE
# GetDeviceCaps 的几个索引
_HORZSIZE, _VERTSIZE, _LOGPIXELSX = 4, 6, 88
# 模式枚举的硬上限（个别驱动会吐几百条，防撑爆上下文 / 死循环）
_MAX_SCAN = 4000
_MAX_RESOLUTIONS = 120


class _RECT(ctypes.Structure):
    _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG)]


class _MONITORINFOEXW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", _RECT), ("rcWork", _RECT),
                ("dwFlags", wintypes.DWORD), ("szDevice", wintypes.WCHAR * 32)]


class _DEVMODEW(ctypes.Structure):
    """DEVMODEW —— 字段顺序/对齐必须与 wingdi.h 完全一致，少一个都会读错位。"""
    _fields_ = [
        ("dmDeviceName", wintypes.WCHAR * 32), ("dmSpecVersion", wintypes.WORD),
        ("dmDriverVersion", wintypes.WORD), ("dmSize", wintypes.WORD),
        ("dmDriverExtra", wintypes.WORD), ("dmFields", wintypes.DWORD),
        ("dmOrientation", ctypes.c_short), ("dmPaperSize", ctypes.c_short),
        ("dmPaperLength", ctypes.c_short), ("dmPaperWidth", ctypes.c_short),
        ("dmScale", ctypes.c_short), ("dmCopies", ctypes.c_short),
        ("dmDefaultSource", ctypes.c_short), ("dmPrintQuality", ctypes.c_short),
        ("dmColor", ctypes.c_short), ("dmDuplex", ctypes.c_short),
        ("dmYResolution", ctypes.c_short), ("dmTTOption", ctypes.c_short),
        ("dmCollate", ctypes.c_short), ("dmFormName", wintypes.WCHAR * 32),
        ("dmLogPixels", wintypes.WORD), ("dmBitsPerPel", wintypes.DWORD),
        ("dmPelsWidth", wintypes.DWORD), ("dmPelsHeight", wintypes.DWORD),
        ("dmDisplayFlags", wintypes.DWORD), ("dmDisplayFrequency", wintypes.DWORD),
        ("dmICMMethod", wintypes.DWORD), ("dmICMIntent", wintypes.DWORD),
        ("dmMediaType", wintypes.DWORD), ("dmDitherType", wintypes.DWORD),
        ("dmReserved1", wintypes.DWORD), ("dmReserved2", wintypes.DWORD),
        ("dmPanningWidth", wintypes.DWORD), ("dmPanningHeight", wintypes.DWORD),
    ]


class _DISPLAY_DEVICEW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("DeviceName", wintypes.WCHAR * 32),
                ("DeviceString", wintypes.WCHAR * 128), ("StateFlags", wintypes.DWORD),
                ("DeviceID", wintypes.WCHAR * 128), ("DeviceKey", wintypes.WCHAR * 128)]


def _primary_device() -> str:
    """主屏的设备名（如 `\\\\.\\DISPLAY1`）。取不到返回空串。"""
    d = _DISPLAY_DEVICEW()
    d.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
    i = 0
    while _user32.EnumDisplayDevicesW(None, i, ctypes.byref(d), 0):
        if d.StateFlags & _ATTACHED_TO_DESKTOP and d.StateFlags & _PRIMARY_DEVICE:
            return d.DeviceName
        i += 1
        if i > 64:                       # 防御：枚举器理论上会自己停，但别赌
            break
    return ""


def _adapter_name(device: str) -> str:
    """设备名 → 显卡/适配器名（如 Intel(R) Iris(R) Xe Graphics）。

    ⚠️ **踩过的坑**：不能写成 `EnumDisplayDevicesW(device, 0, …)` —— 传了设备名进去，
    它返回的是**接在这块适配器上的显示器**，不是适配器本身（实测本机因此把显卡名读成了
    `BOE PnP Monitor`）。取适配器要枚举 `lpDevice=None` 那一层，再按 DeviceName 对上号。
    """
    want = (device or "").lower()
    if not want:
        return ""
    d = _DISPLAY_DEVICEW()
    d.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
    i = 0
    while _user32.EnumDisplayDevicesW(None, i, ctypes.byref(d), 0):
        if (d.DeviceName or "").lower() == want:
            return d.DeviceString
        i += 1
        if i > 64:                       # 实测本机 30 条，留足余量后硬停，防不死不活
            break
    return ""


def _monitor_model(device: str) -> str:
    """设备名 → 显示器型号（如 BOE PnP Monitor）。虚拟屏可能取不到，返回空串。"""
    d = _DISPLAY_DEVICEW()
    d.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
    if _user32.EnumDisplayDevicesW(device or None, 0, ctypes.byref(d), 0):
        return d.DeviceString
    return ""


def _monitor_dpi(hmonitor) -> tuple:
    """某块屏的 DPI。返回 (dpi, 来源说明)。shcore 在 Win8.1 以下没有，取不到返回 (None, 原因)。"""
    try:
        shcore = ctypes.windll.shcore
        dx, dy = wintypes.UINT(), wintypes.UINT()
        rc = shcore.GetDpiForMonitor(ctypes.c_void_p(hmonitor), 0,  # MDT_EFFECTIVE_DPI
                                     ctypes.byref(dx), ctypes.byref(dy))
        if rc == 0 and dx.value:
            return int(dx.value), ""
        return None, f"GetDpiForMonitor 返回 {rc}"
    except Exception as e:
        return None, f"取不到每屏 DPI：{e}"


def _monitors() -> list:
    """当前真正挂在桌面上的显示器（EnumDisplayMonitors 为准，不用 EnumDisplayDevices）。

    返回每项含 hmonitor / device / rect / work / primary / dpi。
    坐标为**物理像素**（前提：本进程是 DPI 感知的，见 set_dpi_aware）。
    """
    set_dpi_aware()
    out: list = []
    proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.HDC,
                              ctypes.POINTER(_RECT), wintypes.LPARAM)

    def _cb(hmon, hdc, lprc, data):
        mi = _MONITORINFOEXW()
        mi.cbSize = ctypes.sizeof(_MONITORINFOEXW)
        if not _user32.GetMonitorInfoW(ctypes.c_void_p(hmon), ctypes.byref(mi)):
            return True
        dpi, dpi_note = _monitor_dpi(hmon)
        out.append({
            "hmonitor": int(hmon),
            "device": mi.szDevice,
            "adapter": _adapter_name(mi.szDevice),
            "model": _monitor_model(mi.szDevice),
            "rect": {"left": mi.rcMonitor.left, "top": mi.rcMonitor.top,
                     "right": mi.rcMonitor.right, "bottom": mi.rcMonitor.bottom,
                     "width": mi.rcMonitor.right - mi.rcMonitor.left,
                     "height": mi.rcMonitor.bottom - mi.rcMonitor.top},
            "work_area": {"left": mi.rcWork.left, "top": mi.rcWork.top,
                          "width": mi.rcWork.right - mi.rcWork.left,
                          "height": mi.rcWork.bottom - mi.rcWork.top},
            "primary": bool(mi.dwFlags & 1),      # MONITORINFOF_PRIMARY
            "dpi": dpi,
            "dpi_note": dpi_note,
        })
        return True

    _user32.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _user32.EnumDisplayMonitors.argtypes = [ctypes.c_void_p, ctypes.c_void_p, proc,
                                            wintypes.LPARAM]
    try:
        _user32.EnumDisplayMonitors(None, None, proc(_cb), 0)
    except Exception:
        pass
    return out


def _scale_of(dpi) -> str:
    """DPI → 缩放比例的文字（120 → `125%`）。取不到返回空串。"""
    if not dpi:
        return ""
    pct = round(int(dpi) * 100 / 96)
    return f"{pct}%"


def _current_mode(device: str) -> dict:
    """当前生效的显示模式。device 为空则问系统默认（就是主屏）。"""
    dm = _DEVMODEW()
    dm.dmSize = ctypes.sizeof(_DEVMODEW)
    _user32.EnumDisplaySettingsW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                             ctypes.POINTER(_DEVMODEW)]
    _user32.EnumDisplaySettingsW.restype = wintypes.BOOL
    if not _user32.EnumDisplaySettingsW(device or None, _ENUM_CURRENT_SETTINGS,
                                        ctypes.byref(dm)):
        return {}
    return {"width": int(dm.dmPelsWidth), "height": int(dm.dmPelsHeight),
            "refresh_hz": int(dm.dmDisplayFrequency) or None,
            "bits_per_pel": int(dm.dmBitsPerPel) or None,
            "device": device or "(系统默认=主屏)"}


def _mode_text(mode: dict) -> str:
    """模式 → `1920x1200 @ 60Hz 32位色`。缺项就不写那一项，不留 `None`。"""
    if not mode:
        return "未知"
    t = f"{mode['width']}x{mode['height']}"
    if mode.get("refresh_hz"):
        t += f" @ {mode['refresh_hz']}Hz"
    if mode.get("bits_per_pel"):
        t += f" {mode['bits_per_pel']}位色"
    return t


@declare_primitive(
    "display.modes",
    "看屏幕**支持哪些分辨率与刷新率**，并标出当前正在用的那一档。"
    "什么时候用：回答「这台电脑最高能开到多少」「有没有 144Hz」这类**可选档位**的问题。"
    "什么时候别用：只想知道**现在是什么模式**用 display.info（更快，不必枚举几百条）；"
    "要看**接了几块屏、各屏位置与各自缩放**用 display.monitors（device 也从那里拿）。"
    "参数怎么填：device 给显示设备名（形如 `\\\\.\\DISPLAY1`，不给则查主屏）；"
    "include_registry_modes=True 会把「注册表里存着、当前驱动没上报」的模式也算上"
    "（默认 False —— 这类模式不一定真能切过去）。"
    "返回什么：current / current_text 是当前档位；resolutions 是**按分辨率分组**的列表，"
    "每项 {width, height, refresh_rates, bits, mode_count, current}（避免把几百条模式平铺出来，"
    "组里 current=true 的那组就是正在用的）；mode_count / resolution_count 是模式总数与分辨率档数；"
    "device / adapter 是设备名与显卡名；note 是中文摘要。"
    "⚠️ 陷阱与易混："
    "① 模式多寡**由显卡驱动上报**，虚拟显示器（Parsec / 远程桌面）也会有一套自己的模式；"
    "② truncated=true 表示分辨率档数被上限（120 档）截断、scan_truncated=true 表示枚举达到扫描上限"
    "（4000 条）—— 都是「还有更多」的意思，不是「只有这么多」；"
    "③ 「当前」认 resolutions 里 current=true 那组，**不靠猜**（不拿列表第一条当当前）；"
    "④ 与 display.info / display.monitors 配对：本原语讲「能选哪些」，那两条讲「现在是什么 / 有哪几块屏」。",
    {"type": "object",
     "properties": {
         "device": {"type": "string",
                    "description": "显示设备名，如 `\\\\.\\DISPLAY1`；不给则查主屏"},
         "include_registry_modes": {"type": "boolean",
                                    "description": "是否把「注册表里存着、当前驱动没上报」的模式也算上"
                                                   "（默认 False；这类模式不一定真能切换）"},
     },
     "required": [], "additionalProperties": False},
    state={"resolution_count": "分辨率档数", "mode_count": "模式总数"},
    block="display_ui",
)
def display_modes(device: str = "", include_registry_modes: bool = False) -> dict:
    set_dpi_aware()
    dev = (device or "").strip() or _primary_device()
    cur = _current_mode(dev)
    if not cur:
        return {"ok": False, "device": dev or "(主屏)", "mode_count": 0,
                "resolution_count": 0, "resolutions": [], "current": {},
                "note": f"取不到显示模式：{dev or '主屏'} 打不开或不是有效显示设备"
                        f"（设备名要形如 `\\\\.\\DISPLAY1`，可用 display.monitors 查）"}

    modes: set = set()
    scanned = 0
    idx = 0
    while idx < _MAX_SCAN:
        dm = _DEVMODEW()
        dm.dmSize = ctypes.sizeof(_DEVMODEW)
        if not _user32.EnumDisplaySettingsW(dev or None, idx, ctypes.byref(dm)):
            break
        scanned += 1
        modes.add((int(dm.dmPelsWidth), int(dm.dmPelsHeight),
                   int(dm.dmDisplayFrequency), int(dm.dmBitsPerPel)))
        idx += 1
    truncated_scan = idx >= _MAX_SCAN

    # 当前值可能不在枚举结果里（比如注册表模式和当前模式不同）——显式并进去，别让它缺席
    cur_key = (cur["width"], cur["height"], cur.get("refresh_hz") or 0,
               cur.get("bits_per_pel") or 0)
    modes.add(cur_key)

    grouped: dict = {}
    for w, h, hz, bpp in modes:
        g = grouped.setdefault((w, h), {"width": w, "height": h,
                                        "refresh_rates": set(), "bits": set(),
                                        "mode_count": 0})
        g["refresh_rates"].add(hz)
        g["bits"].add(bpp)
        g["mode_count"] += 1
    res = []
    for g in grouped.values():
        res.append({"width": g["width"], "height": g["height"],
                    "refresh_rates": sorted(r for r in g["refresh_rates"] if r),
                    "bits": sorted(g["bits"]),
                    "mode_count": g["mode_count"],
                    "current": g["width"] == cur["width"] and g["height"] == cur["height"]})
    # 从大到小：先按像素总数、再按高度 —— 「最大能开多少」是最常问的问题
    res.sort(key=lambda r: (r["width"] * r["height"], r["height"]), reverse=True)
    truncated = len(res) > _MAX_RESOLUTIONS
    if truncated:
        res = res[: _MAX_RESOLUTIONS]

    return {"ok": True, "device": dev or "(主屏)",
            "adapter": _adapter_name(dev),
            "current": cur, "current_text": _mode_text(cur),
            "mode_count": len(modes), "resolution_count": len(res),
            "resolutions": res, "truncated": truncated,
            "scan_truncated": truncated_scan,
            "note": f"{dev or '主屏'}：当前 {_mode_text(cur)}；"
                    f"驱动上报 {len(modes)} 种模式、{len(res)} 档分辨率"
                    + ("（列表已被上限截断，只给了最大的若干档）" if truncated else "")
                    + ("；枚举达到扫描上限，可能还有更多" if truncated_scan else "")}


@declare_primitive(
    "display.monitors",
    "看接了几块显示器：各自的位置、分辨率、工作区、DPI 缩放，以及哪块是主屏。"
    "什么时候用：多屏问题（哪块是主屏、副屏在哪、某块屏的 device 是什么、要截某一块屏）。"
    "什么时候别用：只想知道**主屏当前**的分辨率 / 系统缩放用 display.info（更快）；"
    "要看某块屏**支持哪些模式**用 display.modes（把这里的 device 直接喂给它的 device 参数）；"
    "要看**屏幕亮度**用 display.brightness（那条只报亮度，不报布局与缩放）。"
    "参数怎么填：无参数，直接调用。"
    "返回什么：count 是屏数、primary 是主屏设备名、monitors 是每块屏一项 "
    "{index, hmonitor, device, adapter, model, rect, work_area, primary, dpi, dpi_note, scale}、note 是中文摘要。"
    "device 形如 `\\\\.\\DISPLAY1`，可直接喂给 display.modes；rect 是这块屏在"
    "**虚拟桌面坐标系**里的位置（多屏时 x 可能为负 —— 主屏左边的副屏就是负的），"
    "要截某一块屏就把这个 rect 当 ui.screenshot 的 region。"
    "⚠️ 陷阱与易混："
    "① 每项里的 scale 是**这块屏自己的**缩放，而 display.info 的 scale 是**系统级**缩放 ——"
    "多屏且各屏缩放不同时两者**数字不一样**，问「某块屏缩放多少」认本条；"
    "② 只列**真正挂在桌面上**的屏（EnumDisplayMonitors）；机子里装过但没在用的虚拟显卡"
    "（Parsec / 远程桌面之类）会被排除 —— 否则会把「装过的适配器」谎报成「当前的显示器」（实测本机"
    "装过 30 个显示适配器、真正挂着的只有 1 块）；"
    "③ 与 display.info / display.modes 配对：本原语讲「有哪几块屏」，那两条讲「现在是什么 / 能选哪些」。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"count": "显示器数", "primary": "主屏设备"},
    block="display_ui",
)
def display_monitors() -> dict:
    mons = _monitors()
    if not mons:
        return {"ok": False, "count": 0, "monitors": [], "primary": "",
                "note": "一块显示器都没枚举到（会话可能是无头 / 未登录桌面 / 服务会话）"}
    primary = ""
    for i, m in enumerate(mons):
        m["index"] = i
        m["scale"] = _scale_of(m.get("dpi"))
        if m["primary"]:
            primary = m["device"]
    return {"ok": True, "count": len(mons), "primary": primary, "monitors": mons,
            "note": f"共 {len(mons)} 块显示器，主屏 {primary or '未标出'}"
                    + ("（坐标是虚拟桌面坐标系，副屏在主屏左侧时 left 为负）"
                       if len(mons) > 1 else "")}


@declare_primitive(
    "display.info",
    "当前显示状态的速览：**主屏**的分辨率 / 刷新率 / 色深 + 系统缩放比例 + 虚拟桌面总范围 + 物理尺寸。"
    "什么时候用：想知道「这台机器现在是什么显示状态」「分辨率多少 / 缩放多少」，用它一次拿全。"
    "什么时候别用：要看**全部可选模式**（能切成哪些分辨率）用 display.modes；"
    "要看**多屏各自的布局与缩放**用 display.monitors（本原语只报主屏的单档现状）；"
    "要看**屏幕亮度**用 display.brightness。"
    "参数怎么填：无参数，直接调用。"
    "返回什么：resolution 是形如 \"1920x1200\" 的字符串、current 是 {width, height, refresh_hz, "
    "bits_per_pel, device}、current_text 是人话模式串、scale 是系统缩放如 \"125%\"、dpi 是系统 DPI"
    "（96=100%）、logical_resolution 是缩放后的逻辑尺寸（如 \"1536x960\"）、"
    "device / adapter 是主屏设备名与显卡名、monitor_count 是屏数、"
    "virtual_desktop 是虚拟桌面总范围 {left, top, width, height}、primary_size 是主屏像素尺寸"
    "（{width, height}）、physical_size_mm 是物理尺寸（取不到为 null）、note 是中文摘要。"
    "⚠️ 陷阱与易混："
    "① **scale 是「系统级」缩放**，而 display.monitors 里每块屏的 scale 是**各屏自己的** —— "
    "多屏且各屏缩放不同时，这里的数字和那边**会不一样**；问「某块屏缩放多少」要用 display.monitors；"
    "② resolution 是**物理像素**，不是缩放后的逻辑尺寸：本机实测 1920x1200 + 125% 时，"
    "程序拿到的逻辑尺寸是 1536x960（就是 logical_resolution）——别把两者混着报给用户；"
    "③ 分辨率 / 物理尺寸都只讲**主屏**：多屏合计大小看 virtual_desktop，各屏明细看 display.monitors。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"resolution": "当前分辨率", "scale": "缩放"},
    block="display_ui",
)
def display_info() -> dict:
    set_dpi_aware()
    dev = _primary_device()
    cur = _current_mode(dev)
    dpi = None
    try:
        dpi = int(_user32.GetDpiForSystem())      # Win10 1607+
    except Exception:
        dpi = None
    if not dpi:
        hdc = _user32.GetDC(None)
        try:
            dpi = int(_gdi32.GetDeviceCaps(hdc, _LOGPIXELSX)) or None
        finally:
            _user32.ReleaseDC(None, hdc)
    scale = _scale_of(dpi)
    logical = ""
    if cur and dpi and dpi != 96:
        logical = (f"{round(cur['width'] * 96 / dpi)}x{round(cur['height'] * 96 / dpi)}")

    # 物理尺寸（毫米）：只看主屏；虚拟显示器 / 驱动不给就说取不到
    hdc = _user32.GetDC(None)
    try:
        mm_w = int(_gdi32.GetDeviceCaps(hdc, _HORZSIZE))
        mm_h = int(_gdi32.GetDeviceCaps(hdc, _VERTSIZE))
    finally:
        _user32.ReleaseDC(None, hdc)
    mons = _monitors()

    return {"ok": True,
            "resolution": f"{cur['width']}x{cur['height']}" if cur else "未知",
            "current": cur, "current_text": _mode_text(cur),
            "scale": scale, "dpi": dpi, "logical_resolution": logical,
            "device": dev or "(主屏)",
            "adapter": _adapter_name(dev),
            "monitor_count": len(mons),
            "virtual_desktop": {
                "left": _user32.GetSystemMetrics(76), "top": _user32.GetSystemMetrics(77),
                "width": _user32.GetSystemMetrics(78), "height": _user32.GetSystemMetrics(79)},
            "primary_size": {"width": _user32.GetSystemMetrics(0),
                             "height": _user32.GetSystemMetrics(1)},
            "physical_size_mm": {"width": mm_w, "height": mm_h} if mm_w and mm_h else None,
            "note": (f"当前 {_mode_text(cur)}，系统缩放 {scale or '未知'}"
                     + (f"（逻辑尺寸 {logical}）" if logical else "")
                     + f"；{len(mons)} 块显示器"
                     + (f"，虚拟桌面共 {_user32.GetSystemMetrics(78)}x"
                        f"{_user32.GetSystemMetrics(79)}" if len(mons) > 1 else "")
                     + ("" if mm_w and mm_h else "；物理尺寸取不到（虚拟/远程显示驱动常不报）"))}


# ============================================================================
# 亮度 —— display.brightness
# ============================================================================
# **亮度为什么有两条路**（实测本机得出，不是猜的）：
#   ① dxva2 的 `GetMonitorBrightness`（走 DDC/CI）—— 对**外接显示器**通常有效，
#      但实测本机内置屏（BOE 面板）返回 0：`GetMonitorCapabilities` 也是 0，
#      即这条通路对内置屏**根本不支持**。
#   ② 系统 WMI（`root\WMI` 的 `WmiMonitorBrightness`）—— 内置笔记本屏走的是它，
#      实测本机能拿到 CurrentBrightness=83。
#   所以两条都要留：只留 dxva2 会在笔记本上永远「取不到」，只留 WMI 则外接屏全瞎。
#
# ⚠️ 两条路都取不到时，返回 `supported=false` + 中文原因 —— **绝不编一个数字**。
#    台式机 + 外接屏没有亮度控制接口是常态，这是「这台机器没有这个能力」，
#    不是「原语坏了」。
_DXVA2 = None


def _wmi_brightness(timeout: int = 30) -> tuple:
    """走系统 WMI 读内置屏亮度。返回 (列表, 错误说明)。"""
    script = ("Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightness "
              "| Select-Object InstanceName,CurrentBrightness | ConvertTo-Json -Compress")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return [], "本机没有 PowerShell，取不到内置屏亮度"
    except subprocess.TimeoutExpired:
        return [], f"查询 WMI 超时（{timeout}s）"
    except Exception as e:
        return [], f"调用 PowerShell 失败：{e}"
    text = (p.stdout or b"").decode("utf-8", "replace").strip()
    if not text:
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        return [], f"WMI 没返回内容（{err[:120] or '可能是这台机器没有 WmiMonitorBrightness 类'}）"
    try:
        data = json.loads(text)
    except ValueError as e:
        return [], f"WMI 返回的不是合法 JSON：{e}"
    if isinstance(data, dict):
        data = [data]
    out = []
    for item in data if isinstance(data, list) else []:
        cur = item.get("CurrentBrightness")
        if cur is None:
            continue
        out.append({"instance": item.get("InstanceName") or "(未命名)",
                    "current": int(cur), "max": 100})
    return out, ("" if out else "WMI 里没有可读的亮度对象")


def _ddc_brightness() -> tuple:
    """走 dxva2（DDC/CI）读每块物理显示器亮度。返回 (列表, 错误说明)。"""
    global _DXVA2
    if _DXVA2 is None:
        try:
            _DXVA2 = ctypes.windll.dxva2
        except Exception as e:
            _DXVA2 = False
            return [], f"本机没有 dxva2.dll（{e}）"

    class _PHYSICAL_MONITOR(ctypes.Structure):
        _fields_ = [("hPhysicalMonitor", wintypes.HANDLE),
                    ("szPhysicalMonitorDescription", wintypes.WCHAR * 128)]

    out: list = []
    for m in _monitors():
        hm = ctypes.c_void_p(m["hmonitor"])
        n = wintypes.DWORD(0)
        try:
            if not _DXVA2.GetNumberOfPhysicalMonitorsFromHMONITOR(hm, ctypes.byref(n)) or not n.value:
                continue
            arr = (_PHYSICAL_MONITOR * n.value)()
            if not _DXVA2.GetPhysicalMonitorsFromHMONITOR(hm, n.value, arr):
                continue
        except Exception:
            continue
        for pm in arr:
            entry = {"device": m["device"], "model": m.get("model", ""),
                     "description": pm.szPhysicalMonitorDescription or "",
                     "source": "ddc", "supported": False}
            try:
                lo = wintypes.DWORD(); cur = wintypes.DWORD(); hi = wintypes.DWORD()
                rc = _DXVA2.GetMonitorBrightness(pm.hPhysicalMonitor, ctypes.byref(lo),
                                                 ctypes.byref(cur), ctypes.byref(hi))
                if rc:
                    entry.update({"supported": True, "current": int(cur.value),
                                  "min": int(lo.value), "max": int(hi.value),
                                  "percent": round(cur.value * 100 / hi.value) if hi.value else None})
                else:
                    entry["note"] = ("这块屏的驱动不支持 DDC/CI 亮度（程序化调节多用于外接屏，"
                                     "内置屏请走系统 WMI 那条路）")
            finally:
                try:
                    _DXVA2.DestroyPhysicalMonitor(pm.hPhysicalMonitor)
                except Exception:
                    pass
            out.append(entry)
    return out, ("" if out else "没有任何显示器响应 DDC/CI 亮度查询")


@declare_primitive(
    "display.brightness",
    "读屏幕**亮度**（百分比）。"
    "什么时候用：想知道笔记本当前亮度、排查「亮度是不是被人调过」时；它同时走两条通路并合并结果。"
    "什么时候别用：别的显示问题一律不归它 —— 分辨率 / 缩放 / 有几块屏用 display.info 或 "
    "display.monitors；本原语只报亮度、不报显示模式。"
    "参数怎么填：无参数，直接调用。"
    "返回什么：supported 说明这台机器**有没有可读的亮度接口**、percent 是主屏亮度百分比"
    "（取不到为 null）、count 是取到数值的屏数、screens 是每块屏一项 "
    "[{source, name, device, current, min, max, percent, note}]、"
    "ok 表示**这次查询本身**跑成功了没有（与 supported 是两件事）、note 是中文摘要。"
    "⚠️ 陷阱与易混："
    "① **只对笔记本内置屏稳定有效**：内置屏走系统 WMI，外接屏走 DDC/CI（很多外接屏 / 转接线不支持）；"
    "② 台式机 + 外接屏、虚拟显示器取不到是**常态** —— 这时 supported=false + 中文原因，"
    "**不会编一个数字给你**；"
    "③ ok=true 且 supported=false 是**很常见**的一种返回（查询成功、但这机器没有亮度接口），"
    "判「有没有亮度」看 supported，判「查询是否跑通」才看 ok；"
    "④ screens[].source 标明每项来自哪条通路：wmi=内置屏（current 就是百分比）、"
    "ddc=DDC/CI 外接屏（current 是原始值、percent 才是百分比、min/max 是范围）；"
    "⑤ 这条**只读**、不能改亮度 —— 本库没有设置亮度的原语，要调亮度得让用户自己来。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"percent": "亮度%"},
    block="display_ui",
)
def display_brightness() -> dict:
    screens: list = []
    notes: list = []

    wmi, wmi_err = _wmi_brightness()
    for w in wmi:
        screens.append({"source": "wmi", "name": w["instance"], "current": w["current"],
                        "max": w["max"], "percent": w["current"],
                        "note": "内置屏亮度（来源：系统 WMI 的 WmiMonitorBrightness）"})
    if wmi_err:
        notes.append(f"WMI 这条路：{wmi_err}")

    ddc, ddc_err = _ddc_brightness()
    for d in ddc:
        screens.append({"source": "ddc",
                        "name": d.get("model") or d.get("description") or d["device"],
                        "device": d["device"], "current": d.get("current"),
                        "min": d.get("min"), "max": d.get("max"),
                        "percent": d.get("percent"), "note": d.get("note", "")})
    if ddc_err:
        notes.append(f"DDC/CI 这条路：{ddc_err}")

    usable = [s for s in screens if s.get("percent") is not None]
    if not usable:
        # ⚠️ ok=True 表示「这次查询本身跑成功了」，supported=False 表示「这台机器没有亮度接口」——
        # 两件事分开说，别让调用方把「取不到」误读成「原语坏了」，更别让它去猜一个数字。
        return {"ok": True, "supported": False, "count": 0, "percent": None,
                "screens": screens,
                "note": "这台机器 / 这块屏取不到亮度：内置屏的 WMI 与外接屏的 DDC/CI 两条路"
                        "都没有给出数值。台式机 + 外接屏、虚拟显示器、或驱动不支持时都是这个结果 ——"
                        "**不是原语出错，也不代表亮度是 0**。"
                        + ("；" + "；".join(notes) if notes else "")}
    parts = []
    for s in usable:
        parts.append(f"{s['name']} {s['percent']}%（来源 {s['source']}）")
    return {"ok": True, "supported": True, "count": len(usable),
            "percent": usable[0]["percent"], "screens": screens,
            "note": "；".join(parts)
                    + ("；另有 " + str(len(screens) - len(usable)) + " 块屏取不到亮度"
                       if len(screens) > len(usable) else "")
                    + ("；" + "；".join(notes) if notes else "")}


# 说明：本文件不 import 任何别的域文件，也不 import _common —— 用不到那边的路径判定与
# 命令输出解码（显示域不碰文件系统、不解析命令行文本，全部走 ctypes 与结构化 JSON）。
