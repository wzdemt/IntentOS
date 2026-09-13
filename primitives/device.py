"""外设域原语 —— USB 设备清单 / 打印机清单（device.*）。**两条都是只读。**

零依赖：全部走 Windows 自带的**原生 API**（ctypes）——
  · `device.usb_list` —— SetupAPI（setupapi.dll）枚举设备树 + CfgMgr32 取设备状态
  · `device.printers` —— 打印后台（winspool.drv）的 EnumPrintersW
**刻意不用 PowerShell**：这两件事在 PowerShell 里要 3~6 秒（Get-PnpDevice + 逐设备取属性），
而原生 API 是毫秒级、且不用解码子进程输出。能快就别慢。

⚠️ **USB 那条的噪音问题**：设备树里 USB 相关的条目**一多半不是「插进来的设备」**——
根集线器、集线器、复合设备的接口子项（&MI_xx）、虚拟/远程 USB 设备。
默认只列**真实设备**，过滤掉的按类计数写进 note（要全看就传 include_filtered=True）。
「可移动」取的是设备的 CM_DEVCAP_REMOVABLE 能力位，**不是**猜的：
板载摄像头 / 蓝牙是 false，能拔的 U 盘和无线接收器是 true。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_device，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import platform

from core.factory import declare_primitive  # type: ignore

IS_WINDOWS = platform.system() == "Windows"

# ── 通用小工具 ──────────────────────────────────────────────────────────
# 系统给的厂商名常常是这种占位串（「标准系统设备」「(Standard system devices)」），
# 它不是厂商、是「驱动没报厂商」的意思。照原样吐给模型等于给了个假信息，所以判成空。
_MFG_PLACEHOLDER = ("(标准", "(standard", "标准系统设备", "standard system", "generic",
                    "microsoft", "winusb", "未知", "unknown", "n/a")


def _clean_text(value) -> str | None:
    """去掉首尾空白与内嵌 NUL，空串 / 纯占位符一律折成 None（宁可没有，不给假的）。"""
    if value is None:
        return None
    s = str(value).replace("\x00", "").strip()
    return s or None


def _clean_mfg(value) -> str | None:
    """厂商名：占位串判成 None（见 _MFG_PLACEHOLDER 的说明）。"""
    s = _clean_text(value)
    if s is None:
        return None
    low = s.lower()
    if any(low.startswith(p) or low == p for p in _MFG_PLACEHOLDER):
        return None
    return s


def _resolve_desc(value) -> str | None:
    """资源串形式的描述 → 人话。

    驱动 INF 里的写法是 `@usb.inf,%usb\\composite.devicedesc%;USB Composite Device`，
    分号**后面**那段才是显示名（分号前是「去哪个 INF 查、查哪一条」）。
    实测 SetupAPI 一般已经把中文解好了，这里只是兜底：有分号就取最后一段。
    """
    s = _clean_text(value)
    if s is None:
        return None
    if s.startswith("@") and ";" in s:
        s = s.rsplit(";", 1)[-1].strip()
    return s or None


# ── USB 设备枚举（SetupAPI + CfgMgr32）────────────────────────────────────
_DIGCF_PRESENT = 0x02
_DIGCF_ALLCLASSES = 0x04
_SPDRP_DEVICEDESC = 0x00
_SPDRP_SERVICE = 0x04
_SPDRP_CLASS = 0x07
_SPDRP_MFG = 0x0B
_SPDRP_FRIENDLYNAME = 0x0C
_SPDRP_LOCATION_INFORMATION = 0x0D
_SPDRP_CAPABILITIES = 0x0F
_CM_DEVCAP_REMOVABLE = 0x04          # CM_DEVCAP_* 位掩码里的「可从插槽拔出」
_DN_HASTROUBLE = 0x00000001          # 设备状态里的「有问题」，置位时问题码才有意义


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class _DEVPROPKEY(ctypes.Structure):
    _fields_ = [("fmtid", _GUID), ("pid", ctypes.c_ulong)]


class _SP_DEVINFO_DATA(ctypes.Structure):
    """SetupAPI 的设备信息节点。Reserved 必须是指针宽度，否则 64 位下结构体会错位。"""
    _fields_ = [("cbSize", wintypes.DWORD), ("ClassGuid", ctypes.c_ubyte * 16),
                ("DevInst", wintypes.DWORD), ("Reserved", ctypes.c_void_p)]


def _devpropkey(guid: str, pid: int) -> _DEVPROPKEY:
    """`'540b947e-...'` → DEVPROPKEY。手写出来比硬编码十六进制好核对。

    ⚠️ **前三段要按大端读**：GUID 的 `Data1/Data2/Data3` 是**数值**（文本里就是它本身），
    ctypes 写结构体时才按小端落到内存；只有 `Data4` 才是「就是那 8 个字节」。
    读反了不会报错 —— 只会让 `SetupDiGetDevicePropertyW` 一声不吭地返回失败，
    现象是「名字莫名其妙退回通用描述」，极难查（本文件就被这个坑咬过一次）。
    """
    raw = bytes.fromhex(guid.replace("{", "").replace("}", "").replace("-", ""))
    key = _DEVPROPKEY()
    key.fmtid.Data1 = int.from_bytes(raw[0:4], "big")
    key.fmtid.Data2 = int.from_bytes(raw[4:6], "big")
    key.fmtid.Data3 = int.from_bytes(raw[6:8], "big")
    for i in range(8):
        key.fmtid.Data4[i] = raw[8 + i]
    key.pid = pid
    return key


# DEVPKEY_Device_BusReportedDeviceDesc —— **这条最值钱**。
# 设备在 USB 总线上自报的产品名（"FHD Camera"、"ATK Mouse 1K Dongle"）。
# 没有它，一堆设备的名字都只是驱动给的通用描述「USB 复合设备 / USB 输入设备」，
# 调用方根本认不出插的是什么。
_PKEY_BUS_DESC = _devpropkey("540b947e-8b40-45bc-a8a2-6a0b894cbda2", 4)

# 常见 USB 厂商号（VID）→ 厂商。**这是兜底猜测**，只在设备自己没报厂商时才用，
# 所以返回值里字段叫 vendor_hint 而不是 manufacturer —— 别让模型把猜测当事实。
_VID_HINTS = {
    "8087": "Intel（英特尔）", "0408": "Quanta（广达）", "046D": "Logitech（罗技）",
    "04F2": "Chicony（群光）", "04F3": "Elan（义隆）", "0BDA": "Realtek（瑞昱）",
    "05AC": "Apple", "0951": "Kingston（金士顿）", "0781": "SanDisk（闪迪）",
    "13FE": "Kingston / Phison", "090C": "Silicon Motion", "1058": "Western Digital（西数）",
    "0BC2": "Seagate（希捷）", "152D": "JMicron", "174C": "ASMedia", "2109": "VIA Labs",
    "04E8": "Samsung（三星）", "18D1": "Google", "2717": "Xiaomi（小米）",
    "12D1": "Huawei（华为）", "05C6": "Qualcomm", "413C": "Dell（戴尔）", "0B05": "ASUS（华硕）",
    "1A2C": "China Resource Semico", "258A": "SINO WEALTH", "0C45": "Sonix / Microdia",
    "5986": "Bison（毕升）", "13D3": "IMC Networks",
}

# 集线器 / 主控的驱动服务名：它们是 USB 树的骨架，不是「插进来的设备」
# （⚠️ 别把 usbccgp 列进来 —— 那是复合设备的驱动，真设备都用它）
_HUB_SERVICES = {"usbhub3", "usbhub", "usbxhci"}
# 虚拟 / 远程 USB：看着像设备，其实没有硬件
_VIRTUAL_HINTS = ("virtual", "虚拟", "vmware", "virtualbox", "hyper-v", "remote usb",
                  "usbip", "usb over", "虚拟 usb")

# CM_PROB_* 问题码 → 人话（只翻常见的，别的一律「未知问题码 N」，不猜）
_PROBLEMS = {
    0: "无", 1: "设备未配置", 2: "设备加载器失败", 3: "内存不足", 4: "注册表项类型不对",
    5: "资源仲裁被占用", 6: "启动配置冲突", 7: "过滤驱动失败", 8: "找不到设备加载器",
    9: "上报的数据无效", 10: "启动失败", 12: "资源冲突", 14: "需要重启后才生效",
    16: "只识别出部分资源", 18: "需要重新安装", 19: "注册表信息损坏", 21: "设备正在被移除",
    22: "设备已被禁用", 24: "设备不存在（不在位）", 28: "没装驱动",
    29: "被固件 / BIOS 关掉了", 31: "加载驱动失败", 32: "驱动服务被禁用",
    37: "驱动入口失败", 39: "驱动加载失败", 43: "启动后失败", 45: "已拔出但残留的幽灵设备",
    48: "驱动被系统阻止加载", 52: "驱动未签名", 54: "设备被复位", 56: "需要配置设备类",
}


def _prop_str(sapi, h, did, code) -> str | None:
    """读设备的注册表属性（字符串型）。取不到返回 None —— 有些设备就是不报这项。"""
    typ, need = wintypes.DWORD(), wintypes.DWORD()
    buf = ctypes.create_unicode_buffer(1024)
    ok = sapi.SetupDiGetDeviceRegistryPropertyW(
        h, ctypes.byref(did), code, ctypes.byref(typ), buf, ctypes.sizeof(buf),
        ctypes.byref(need))
    return _clean_text(buf.value) if ok else None


def _prop_dw(sapi, h, did, code) -> int | None:
    """读设备的注册表属性（DWORD 型）。**注意别用字符串缓冲区接 DWORD**，会读出乱码。"""
    typ, need, val = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    ok = sapi.SetupDiGetDeviceRegistryPropertyW(
        h, ctypes.byref(did), code, ctypes.byref(typ), ctypes.byref(val),
        ctypes.sizeof(val), ctypes.byref(need))
    return val.value if ok else None


def _devprop_str(sapi, h, did, key) -> str | None:
    """按 DEVPROPKEY 取设备属性（注册表属性里没有的那些，比如总线自报的产品名）。"""
    typ, need = wintypes.DWORD(), wintypes.DWORD()
    buf = ctypes.create_unicode_buffer(512)
    ok = sapi.SetupDiGetDevicePropertyW(
        h, ctypes.byref(did), ctypes.byref(key), ctypes.byref(typ), buf,
        ctypes.sizeof(buf), ctypes.byref(need), 0)
    return _clean_text(buf.value) if ok else None


def _physical_key(inst: str) -> str:
    """复合设备的接口子项 → 它父设备的键。

    `USB\\VID_0408&PID_1060&MI_00\\6&14B4772A&0&0000` → `USB\\VID_0408&PID_1060`，
    和父设备 `USB\\VID_0408&PID_1060\\01.00.00` 的键一致 —— 靠它才知道子项该不该折叠。
    """
    parts = inst.split("\\")
    if len(parts) >= 2 and "&MI_" in parts[1].upper():
        parts = [parts[0], parts[1].upper().split("&MI_")[0]]
    return "\\".join(parts[:2]).upper()


def _vid_pid(inst: str) -> tuple[str | None, str | None]:
    """从设备实例路径里抠出 VID / PID（`USB\\VID_0408&PID_1060\\…`）。"""
    seg = inst.split("\\")[1].upper() if "\\" in inst else ""
    vid = pid = None
    for token in seg.split("&"):
        if token.startswith("VID_"):
            vid = "0x" + token[4:]
        elif token.startswith("PID_"):
            pid = "0x" + token[4:]
    return vid, pid


def _location_text(loc: str | None) -> str | None:
    """`Port_#0002.Hub_#0002` → 「2 号集线器上的 2 号端口」。

    另一种数字点分格式（`0000.0014.0000.007.…`，接口子项才有）这里不硬解 ——
    **猜错了比不猜更糟**，取不到人话就原样返回。
    """
    if not loc:
        return None
    if "Port_#" in loc and "Hub_#" in loc:
        try:
            port = int(loc.split("Port_#", 1)[1].split(".", 1)[0])
            hub = int(loc.split("Hub_#", 1)[1].split(".", 1)[0])
        except (ValueError, IndexError):
            return loc
        return f"{hub} 号集线器上的 {port} 号端口"
    return loc


def _noise_reason(inst: str, name: str, desc: str, cls: str, svc: str) -> str | None:
    """这条 USB 条目算不算「噪音」（不是插进来的真设备）。返回中文理由，算真设备则 None。"""
    low = f"{name} {desc}".lower()
    svc_low = (svc or "").lower()
    if inst.upper().startswith("USB\\ROOT_HUB") or "root hub" in low or "根集线器" in low:
        return "根集线器"
    if cls == "USB" and ("hub" in low or "集线器" in low):
        return "集线器"
    if cls == "USB" and svc_low in _HUB_SERVICES and "controller" in low:
        return "主控"
    for hint in _VIRTUAL_HINTS:
        if hint in low:
            return "虚拟 / 远程 USB"
    return None


def _usb_devices() -> tuple[list[dict], list[dict], str]:
    """枚举 USB 设备树。返回 (真实设备, 噪音条目, 错误说明)。

    ⚠️ **按「枚举器 = USB」取，不按设备类取**：`-Class USB` 那种取法会漏掉
    HID（键盘鼠标）、Bluetooth、Camera ——它们挂在 USB 总线上但类不是 USB。
    反过来，PCI 上的 xHCI 主控虽然类名是 USB，却**不在 USB 枚举器下**，天然不会混进来。
    """
    sapi = ctypes.WinDLL("setupapi", use_last_error=True)
    cfg = ctypes.WinDLL("cfgmgr32", use_last_error=True)
    sapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    sapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                          ctypes.c_void_p, wintypes.DWORD]
    sapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(_SP_DEVINFO_DATA)]
    sapi.SetupDiGetDeviceInstanceIdW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_SP_DEVINFO_DATA), ctypes.c_wchar_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    sapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_SP_DEVINFO_DATA), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    sapi.SetupDiGetDevicePropertyW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_SP_DEVINFO_DATA), ctypes.POINTER(_DEVPROPKEY),
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    sapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    cfg.CM_Get_DevNode_Status.argtypes = [ctypes.POINTER(wintypes.DWORD),
                                          ctypes.POINTER(wintypes.DWORD),
                                          wintypes.DWORD, wintypes.DWORD]

    h = sapi.SetupDiGetClassDevsW(None, "USB", None, _DIGCF_PRESENT | _DIGCF_ALLCLASSES)
    if not h or h == ctypes.c_void_p(-1).value:
        return [], [], "系统没给出 USB 设备树（SetupDiGetClassDevs 失败）"

    raw: list[dict] = []
    try:
        idx = 0
        while True:
            did = _SP_DEVINFO_DATA()
            did.cbSize = ctypes.sizeof(_SP_DEVINFO_DATA)
            if not sapi.SetupDiEnumDeviceInfo(h, idx, ctypes.byref(did)):
                break
            idx += 1
            sb = ctypes.create_unicode_buffer(512)
            ln = wintypes.DWORD(512)
            if not sapi.SetupDiGetDeviceInstanceIdW(h, ctypes.byref(did), sb, 512,
                                                    ctypes.byref(ln)):
                continue
            inst = _clean_text(sb.value)
            if not inst or not inst.upper().startswith("USB\\"):
                continue
            name = (_devprop_str(sapi, h, did, _PKEY_BUS_DESC)
                    or _prop_str(sapi, h, did, _SPDRP_FRIENDLYNAME)
                    or _resolve_desc(_prop_str(sapi, h, did, _SPDRP_DEVICEDESC))
                    or "（系统没报名字）")
            desc = _resolve_desc(_prop_str(sapi, h, did, _SPDRP_DEVICEDESC))
            cls = _prop_str(sapi, h, did, _SPDRP_CLASS) or ""
            svc = _prop_str(sapi, h, did, _SPDRP_SERVICE)
            caps = _prop_dw(sapi, h, did, _SPDRP_CAPABILITIES)
            stat, prob = wintypes.DWORD(), wintypes.DWORD()
            cfg.CM_Get_DevNode_Status(ctypes.byref(stat), ctypes.byref(prob), did.DevInst, 0)
            trouble = bool(stat.value & _DN_HASTROUBLE)
            vid, pid = _vid_pid(inst)
            loc = _prop_str(sapi, h, did, _SPDRP_LOCATION_INFORMATION)
            raw.append({
                "name": name, "desc": desc, "instance_id": inst, "class": cls or None,
                "service": svc, "vendor_id": vid, "product_id": pid,
                "manufacturer": _clean_mfg(_prop_str(sapi, h, did, _SPDRP_MFG)),
                "vendor_hint": _VID_HINTS.get((vid or "")[2:].upper().strip()),
                # CM_DEVCAP_REMOVABLE —— 板载设备是 false，能拔的是 true
                "removable": bool(caps & _CM_DEVCAP_REMOVABLE) if caps is not None else None,
                "location": loc, "location_text": _location_text(loc),
                "status": "OK" if not trouble else "有故障",
                "problem_code": prob.value if trouble else 0,
                "problem": _PROBLEMS.get(prob.value, f"未知问题码 {prob.value}") if trouble else "无",
                "present": True,
                "_key": _physical_key(inst),
                "_is_mi": "&MI_" in inst.upper(),
            })
    finally:
        sapi.SetupDiDestroyDeviceInfoList(h)

    keys_with_parent = {d["_key"] for d in raw if not d["_is_mi"]}
    kept, noise = [], []
    for d in raw:
        # 接口子项只在「它的父设备确实也在清单里」时才折叠 —— 不然会把真设备弄丢
        if d["_is_mi"] and d["_key"] in keys_with_parent:
            reason = "复合设备的接口子项（是父设备的一个功能，已随父设备列出）"
        else:
            reason = _noise_reason(d["instance_id"], d["name"], d["desc"] or "",
                                   d["class"] or "", d["service"] or "")
        if reason:
            d["filtered_reason"] = reason
            noise.append(d)
        else:
            kept.append(d)
    # 按设备实例路径排序：SetupAPI 的枚举顺序不保证稳定，排一下让两次调用结果一致
    kept.sort(key=lambda x: (x["instance_id"] or ""))
    return kept, noise, ""


def _strip_internal(items: list[dict]) -> list[dict]:
    """去掉内部用的 _key / _is_mi（它们只服务于上面的折叠逻辑，不该出现在返回值里）。"""
    for d in items:
        d.pop("_key", None)
        d.pop("_is_mi", None)
    return items


@declare_primitive(
    "device.usb_list",
    "看这台电脑**当前插着哪些 USB 设备**：名字（优先用设备在总线上自报的产品名）、"
    "设备类、厂商、VID/PID、是否可移动、插在哪个端口、状态与故障码。"
    "⚠️ **默认只列真实设备**：根集线器 / 集线器 / 复合设备的接口子项（&MI_xx）/ 虚拟·远程 USB "
    "都算噪音被滤掉，滤掉多少条按类写在 note 里（要连噪音一起看就传 include_filtered=True）。"
    "removable 来自设备的 CM_DEVCAP_REMOVABLE 能力位 —— **板载（焊死的）摄像头、蓝牙是 false，"
    "能拔的 U 盘 / 无线接收器是 true**，拿它区分「外接」还是「板载」比看名字可靠。"
    "manufacturer 是设备/驱动自己报的（占位串如「标准系统设备」会被折成 null，那表示它没报）；"
    "vendor_hint 是按 VID 查表猜的厂商，**只是线索、不是设备说的**。"
    "状态取自设备节点：OK 表示系统没报故障；「有故障」时 problem 给中文病因（如「设备已被禁用」）。"
    "注意这条只看**当前在位**的设备，历史上插过、现在拔了的不会出现。",
    {"type": "object",
     "properties": {
         "include_filtered": {"type": "boolean",
                              "description": "true=连被滤掉的噪音条目（集线器/接口子项/虚拟设备）"
                                             "一起列出来，每条带 filtered_reason。默认 false"},
     },
     "required": [],
     "additionalProperties": False},
    state={"count": "设备数", "removable": "可移动", "filtered": "已滤除"},
    block="device",
)
def device_usb_list(include_filtered: bool = False) -> dict:
    if not IS_WINDOWS:
        return {"ok": False, "available": False, "count": 0, "removable": 0, "filtered": 0,
                "devices": [], "filtered_detail": {},
                "note": f"这条原语目前只实现了 Windows（当前平台 {platform.system()}）："
                        f"取不到 USB 设备树，**不代表这台机器没有 USB 设备**"}
    try:
        kept, noise, err = _usb_devices()
    except Exception as e:
        return {"ok": False, "available": False, "count": 0, "removable": 0, "filtered": 0,
                "devices": [], "filtered_detail": {}, "note": f"枚举 USB 设备失败：{e}"}
    if err:
        return {"ok": False, "available": False, "count": 0, "removable": 0, "filtered": 0,
                "devices": [], "filtered_detail": {}, "note": err}

    by_reason: dict[str, int] = {}
    for d in noise:
        by_reason[d["filtered_reason"]] = by_reason.get(d["filtered_reason"], 0) + 1
    removable = [d for d in kept if d.get("removable")]
    removable_names = "、".join(d["name"] for d in removable[:5])

    if kept:
        brief = "；".join(
            f"{d['name']}" + (f"（{d['class']}）" if d.get("class") else "")
            + ("｜可移动" if d.get("removable") else "")
            + ("" if d["status"] == "OK" else f"｜⚠️{d['problem']}")
            for d in kept[:8])
    else:
        brief = "一个都没有"
    note = f"当前在位 {len(kept)} 个真实 USB 设备：{brief}"
    if len(kept) > 8:
        note += f"…（共 {len(kept)} 个，全量见 devices）"
    if removable:
        note += f"；其中可拔插的 {len(removable)} 个（{removable_names}）"
    broken = [d for d in kept if d["status"] != "OK"]
    if broken:
        note += f"；⚠️ 有 {len(broken)} 个报故障，需要留意"
    if noise:
        detail = "、".join(f"{k} {v} 条" for k, v in sorted(by_reason.items()))
        note += (f"；另有 {len(noise)} 条 USB 条目被当噪音滤掉（{detail}）—— "
                 f"它们是 USB 树的骨架或没有硬件的虚拟设备，不是插进来的设备")
    if not kept and noise:
        note += "；滤完就空了，如果确实想找插着的设备，可以先传 include_filtered=true 看看全貌"

    out = {"ok": True, "available": True, "count": len(kept), "devices": _strip_internal(kept),
           "removable": len(removable), "filtered": len(noise),
           "filtered_detail": by_reason, "note": note}
    if include_filtered:
        out["filtered_devices"] = _strip_internal(noise)
    return out


# ── 打印机清单（打印后台 EnumPrintersW）──────────────────────────────────
class _PRINTER_INFO_2W(ctypes.Structure):
    _fields_ = [("pServerName", ctypes.c_wchar_p), ("pPrinterName", ctypes.c_wchar_p),
                ("pShareName", ctypes.c_wchar_p), ("pPortName", ctypes.c_wchar_p),
                ("pDriverName", ctypes.c_wchar_p), ("pComment", ctypes.c_wchar_p),
                ("pLocation", ctypes.c_wchar_p), ("pDevMode", ctypes.c_void_p),
                ("pSepFile", ctypes.c_wchar_p), ("pPrintProcessor", ctypes.c_wchar_p),
                ("pDatatype", ctypes.c_wchar_p), ("pParameters", ctypes.c_wchar_p),
                ("pSecurityDescriptor", ctypes.c_void_p), ("Attributes", wintypes.DWORD),
                ("Priority", wintypes.DWORD), ("DefaultPriority", wintypes.DWORD),
                ("StartTime", wintypes.DWORD), ("UntilTime", wintypes.DWORD),
                ("Status", wintypes.DWORD), ("cJobs", wintypes.DWORD),
                ("AveragePPM", wintypes.DWORD)]

# Attributes 位 → 人话（只列对调用方有意义的，其余位忽略不报）
_PRINTER_ATTRS = {0x0001: "排队打印", 0x0002: "直接打印", 0x0004: "默认打印机",
                  0x0008: "已共享", 0x0010: "网络打印机", 0x0020: "已隐藏",
                  0x0040: "本地打印机", 0x0400: "离线（工作脱机）", 0x0800: "双向通信"}

# Status 位 → 人话。⚠️ 这是**后台程序报的异常标志**，全 0 只说明「没报异常」，
# 不等于「一定能打出来」：后台不会为了看一眼状态去唤醒一台休眠的网络打印机。
_PRINTER_STATUS = {
    0x00000001: "已暂停", 0x00000002: "错误", 0x00000004: "正在删除", 0x00000008: "卡纸",
    0x00000010: "缺纸", 0x00000020: "需要手动送纸", 0x00000040: "纸张问题", 0x00000080: "脱机",
    0x00000100: "正在传输数据", 0x00000200: "忙", 0x00000400: "正在打印",
    0x00000800: "出纸槽已满", 0x00001000: "不可用", 0x00002000: "等待中",
    0x00004000: "正在处理", 0x00008000: "正在初始化", 0x00010000: "正在预热",
    0x00020000: "碳粉不足", 0x00040000: "没有碳粉", 0x00080000: "无法分页",
    0x00100000: "需要人工干预", 0x00200000: "内存不足", 0x00400000: "盖板打开",
    0x00800000: "服务器未知", 0x01000000: "省电模式",
}

# 一眼能看出「这东西其实是把内容写进文件 / 传真，不接触纸」的线索
_VIRTUAL_PRINTER_HINTS = ("pdf", "xps", "onenote", "fax", "虚拟", "virtual",
                          "document writer", "打印到文件")


def _default_printer() -> tuple[str | None, str]:
    """默认打印机名（来自 HKCU 的 Device 值）。返回 (名字, 来源说明)。

    ⚠️ **为什么不能只信 EnumPrinters 的 DEFAULT 属性位**：实测（本机 win11 26200）
    装了 5 台打印机、系统明明有默认的那台，但 EnumPrintersW 返回的 Attributes 里
    **一台都没有 0x4 这个位**；而 HKCU 的 `Device` 值和 WMI 的 Win32_Printer.Default 都对上了。
    所以以注册表为准、属性位只当参考。
    """
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows NT\CurrentVersion\Windows") as k:
            value = winreg.QueryValueEx(k, "Device")[0]
    except OSError:
        return None, "none"
    except Exception:
        return None, "none"
    name = str(value or "").split(",")[0].strip()
    return (name or None), ("registry" if name else "none")


@declare_primitive(
    "device.printers",
    "看这台电脑装了哪些打印机：名字、默认是哪台、是否在打印作业、各自的状态与端口"
    "（端口 / 驱动 / 是否共享 / 是否离线 / 本地还是网络）。"
    "默认打印机取自 HKCU 的 Device 值，**比 EnumPrinters 的默认属性位可靠**"
    "（实测属性位会全都不是默认，见实现注释）。"
    "status 是打印后台报的**异常标志位解析**（卡纸 / 缺纸 / 脱机 / 暂停…）："
    "**空列表 = 没报异常，不等于一定能打出来** —— 后台不会为看一眼状态去唤醒休眠的网络打印机。"
    "virtual=true 是**从驱动 / 端口名推断**的（PDF / XPS / OneNote / 传真这类把内容写进文件、"
    "不接触纸的），只是线索。真正的物理打印机看 physical_count。"
    "注意：这里只列**已安装的打印机**（含从没连上的网络打印机）；打印队列里的作业不在本条范围内。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"count": "打印机数", "physical_count": "实体机", "jobs": "排队作业"},
    block="device",
)
def device_printers() -> dict:
    if not IS_WINDOWS:
        return {"ok": False, "available": False, "count": 0, "physical_count": 0, "jobs": 0,
                "printers": [], "default": None,
                "note": f"这条原语目前只实现了 Windows（当前平台 {platform.system()}）："
                        f"取不到打印机清单，**不代表这台机器没装打印机**"}
    try:
        spool = ctypes.WinDLL("winspool.drv", use_last_error=True)
        spool.EnumPrintersW.argtypes = [wintypes.DWORD, ctypes.c_wchar_p, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD),
                                        ctypes.POINTER(wintypes.DWORD)]
    except Exception as e:
        return {"ok": False, "available": False, "count": 0, "physical_count": 0, "jobs": 0,
                "printers": [], "default": None, "note": f"加载打印后台接口失败：{e}"}

    # EnumPrintersW 的老规矩：先问要多大缓冲区（返回 ERROR_INSUFFICIENT_BUFFER 是正常的），再取
    needed, returned = wintypes.DWORD(), wintypes.DWORD()
    spool.EnumPrintersW(2, None, 2, None, 0, ctypes.byref(needed), ctypes.byref(returned))
    if not needed.value:
        return {"ok": True, "available": True, "count": 0, "physical_count": 0, "jobs": 0,
                "default": None, "default_source": "none", "printers": [],
                "note": "这台机器上没装任何打印机"}
    buf = ctypes.create_string_buffer(needed.value)
    if not spool.EnumPrintersW(2, None, 2, buf, needed.value, ctypes.byref(needed),
                               ctypes.byref(returned)):
        return {"ok": False, "available": False, "count": 0, "physical_count": 0, "jobs": 0,
                "printers": [], "default": None,
                "note": f"枚举打印机失败（返回 {ctypes.get_last_error()}）："
                        f"打印后台服务（Spooler）可能没在运行"}

    default_name, default_source = _default_printer()
    rows = (_PRINTER_INFO_2W * returned.value).from_buffer(buf)
    printers: list[dict] = []
    for p in rows:
        attrs = p.Attributes or 0
        status = p.Status or 0
        name = _clean_text(p.pPrinterName) or "（无名）"
        port = _clean_text(p.pPortName)
        driver = _clean_text(p.pDriverName)
        network = bool(attrs & 0x10) or bool(port and port.startswith("\\\\"))
        local = bool(attrs & 0x40)
        virtual_hit = next((h for h in _VIRTUAL_PRINTER_HINTS
                            if h in f"{name} {driver or ''} {port or ''}".lower()), None)
        printers.append({
            "name": name,
            "default": bool(default_name) and name == default_name,
            "port": port,
            "driver": driver,
            "status_bits": [v for k, v in _PRINTER_STATUS.items() if status & k],
            "status_code": status,
            "jobs": p.cJobs,
            "connection": "network" if network else ("local" if local else "unknown"),
            "shared": bool(attrs & 0x8),
            "share_name": _clean_text(p.pShareName),
            "work_offline": bool(attrs & 0x400),
            "virtual": bool(virtual_hit),
            "virtual_hint": virtual_hit,
            # 保留原始位，方便调用方自己判我们没翻的那些位
            "attributes": [v for k, v in _PRINTER_ATTRS.items() if attrs & k],
            "comment": _clean_text(p.pComment),
            "location": _clean_text(p.pLocation),
        })
    # 默认的排前面，其余按名字，保证输出稳定
    printers.sort(key=lambda x: (not x["default"], x["name"]))
    physical = [x for x in printers if not x["virtual"]]

    if printers:
        brief = "；".join(
            f"{'★' if x['default'] else ''}{x['name']}"
            f"（端口 {x['port'] or '?'}｜{x['connection']}"
            + ("｜虚拟" if x["virtual"] else "")
            + ("｜" + "/".join(x["status_bits"]) if x["status_bits"] else "")
            + "）" for x in printers)
    else:
        brief = "一台都没有"
    note = f"共 {len(printers)} 台打印机：{brief}"
    if default_name:
        note += f"；默认打印机是「{default_name}」"
        if not any(x["default"] for x in printers):
            note += "——⚠️ 但它**不在已安装的打印机清单里**（注册表里记的还指向它，可能已被删除）"
    else:
        note += "；系统里没有设置默认打印机"
    if printers and len(physical) < len(printers):
        note += (f"；其中 {len(printers) - len(physical)} 台看着是虚拟打印机"
                 f"（把内容写进文件 / 传真，不接触纸），实体打印机 {len(physical)} 台")
    busy = [x for x in printers if x["jobs"]]
    if busy:
        note += f"；有 {len(busy)} 台队列里还有作业"
    note += ("；status_bits 为空 = 后台没报异常，**不等于一定能打出来**"
             "（后台不会为看一眼状态去唤醒休眠的网络打印机）")

    return {"ok": True, "available": True, "count": len(printers),
            "physical_count": len(physical), "default": default_name,
            "default_source": default_source, "jobs": sum(x["jobs"] for x in printers),
            "printers": printers, "note": note}
