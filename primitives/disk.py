"""磁盘与卷域原语 —— 容量 / 类型 / 卷标 / 用量 / 物理盘健康（disk.*）。

零依赖：Windows 走 ctypes(kernel32) 的接口，其他平台回退到 shutil.disk_usage。
Windows 上原来最顺手的 `wmic logicaldisk` 已被微软移除，所以这几条必须做成原语。
`disk.health` 例外地依赖**系统自带的** PowerShell Storage 模块（不是第三方库），
取不到时如实说「取不到」，绝不假装硬盘是好的。

**三层看磁盘，别混**：
  · `disk.list`   —— 这台机器上有哪些**卷**（盘符 / 类型 / 容量 / 文件系统）
  · `disk.usage`  —— **某个路径**落在哪个卷上、还剩多少（可用 vs 卷空闲要分清）
  · `disk.health` —— **那块硬件本身**健康吗、固态还是机械、什么总线

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_disk，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output

# GetDriveTypeW 的返回值 → 英文枚举（不返回本地化文本）
DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed",
               4: "remote", 5: "cdrom", 6: "ramdisk"}


def _volumes_windows() -> list[dict]:
    """枚举所有盘符 + 类型 + 卷标 + 文件系统 + 容量（GetLogicalDrives 系列）。"""
    k = ctypes.windll.kernel32
    k.GetLogicalDrives.restype = ctypes.c_uint
    mask = k.GetLogicalDrives()
    out: list[dict] = []
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        drive = f"{chr(65 + i)}:\\"
        label = ctypes.create_unicode_buffer(261)
        fsn = ctypes.create_unicode_buffer(261)
        vol_ok = bool(k.GetVolumeInformationW(drive, label, 261, None, None, None, fsn, 261))
        free = ctypes.c_ulonglong()
        total = ctypes.c_ulonglong()
        total_free = ctypes.c_ulonglong()
        space_ok = bool(k.GetDiskFreeSpaceExW(drive, ctypes.byref(free),
                                              ctypes.byref(total), ctypes.byref(total_free)))
        item = {
            "drive": drive,
            "type": DRIVE_TYPES.get(k.GetDriveTypeW(drive), "unknown"),
            "label": label.value if vol_ok else None,
            "filesystem": fsn.value if vol_ok else None,
            "ready": space_ok,                      # 空光驱/未插卡：无介质
        }
        if space_ok:
            total_v = max(0, total.value)
            free_v = max(0, free.value)
            item.update({
                "total_gb": round(total_v / 1073741824, 2),
                "free_gb": round(free_v / 1073741824, 2),
                "used_gb": round((total_v - free_v) / 1073741824, 2),
                "used_pct": round((total_v - free_v) / total_v * 100, 1) if total_v else 0.0,
            })
        out.append(item)
    return out


def _volumes_posix() -> list[dict]:
    """非 Windows 平台：至少给出根分区容量（可在此扩展 /proc/mounts 解析）。"""
    import shutil
    try:
        u = shutil.disk_usage(os.path.abspath(os.sep))
    except Exception:
        return []
    return [{"drive": os.sep, "type": "fixed", "label": None, "filesystem": None,
             "ready": True, "total_gb": round(u.total / 1073741824, 2),
             "free_gb": round(u.free / 1073741824, 2),
             "used_gb": round(u.used / 1073741824, 2),
             "used_pct": round(u.used / u.total * 100, 1) if u.total else 0.0}]


@declare_primitive(
    "disk.list",
    "列出本机所有卷（**盘符级**汇总）：盘符、类型（fixed / removable / cdrom / remote）、卷标、"
    "文件系统，以及每个卷的总容量 / 可用 / 占用百分比。"
    "什么时候用：想知道「这台机器上有几个盘、都是什么类型、卷标叫什么」。"
    "⚠️ **问「C 盘还剩多少」「D 盘够不够装东西」不要用这条** —— 它没有「某一个盘」的结论，"
    "free_gb / total_gb 是**所有就绪卷的求和**（= 整机总剩余），拿它答单盘问题是答非所问。"
    "**该用谁**：问某个盘 / 某个路径还剩多少 → 用 disk.usage（它按路径解析出所在卷，还给 "
    "available_gb 这个「当前用户真正能写」的数字）；问那块**硬盘本身**健不健康、是固态还是机械 → "
    "用 disk.health。"
    "参数怎么填：无参数，直接调。"
    "返回什么：ok；count 是卷数；volumes 是逐卷清单（每条含 drive / type / label / filesystem / "
    "ready / total_gb / free_gb / used_gb / used_pct —— 未就绪的卷**没有**后面四个容量字段）；"
    "free_gb / total_gb 是**所有就绪卷的求和**，只能用来回答「整机一共还剩多少」，"
    "**不能**当成某个盘的数字。"
    "⚠️ 陷阱：① ready=false 的卷（空光驱 / 没插卡的读卡器）不计入求和、也没有容量字段；"
    "② 读取失败时 ok=false、count=0 —— **别把 count=0 当成「本机没有磁盘」**（那只是读失败），"
    "先看 ok。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"count": "卷数", "free_gb": "可用GB"},
    block="disk",
)
def disk_list() -> dict:
    try:
        volumes = _volumes_windows() if platform.system() == "Windows" else _volumes_posix()
    except Exception as e:
        return {"ok": False, "count": 0, "volumes": [], "note": f"读取失败：{e}"}
    ready = [v for v in volumes if v.get("ready")]
    return {
        "ok": True,
        "count": len(volumes),
        "volumes": volumes,
        # 汇总只统计「就绪」的固定/远程盘，光驱空仓不算
        "free_gb": round(sum(v.get("free_gb", 0) for v in ready), 2),
        "total_gb": round(sum(v.get("total_gb", 0) for v in ready), 2),
    }


# ============================================================================
# disk.usage —— 指定路径所在卷的容量与剩余（只读）
# ============================================================================
# 与 disk.list 的分工：disk.list 回答「这台机器上有哪些盘」；disk.usage 回答
# 「**我要写的这个路径**落在哪个卷上、还剩多少」—— 后者才是动手前的那个问题，
# 因为路径未必和盘符一一对应（挂载点 / 卷挂载进目录 / UNC 都要靠系统去解析）。
#
# ⚠️ 两个必须分清的「剩余」：
#   · 可用（available）—— GetDiskFreeSpaceExW 的第一个参数，**调用方（当前用户）真正能写的字节数**，
#     配额（磁盘配额 / OneDrive 之类的占位文件）已经扣掉。
#   · 卷空闲（volume free）—— 该卷上未被占用的字节数，不管配额。
#   「我还能不能写进去」看**可用**；「这个盘是不是快满了」看**卷空闲**。两个都给，别混。

class _ULARGE_INTEGER(ctypes.Structure):
    """GetDiskFreeSpaceExW 要的三个 64 位出参。用 c_ulonglong 直接接也行，这里显式写出来免得
    在 32 位 Python 下被 ctypes 按 32 位传而截断。"""
    _fields_ = [("QuadPart", ctypes.c_ulonglong)]


def _free_space_windows(target: str) -> tuple:
    """Windows：返回 (数据字典, 错误说明)。数据字典含卷根 / 卷标 / 文件系统 / 三个容量。"""
    k = ctypes.windll.kernel32
    # GetVolumePathNameW 把「路径」解析成它所在的**卷根**（挂载点 / 卷挂载进目录都认）
    k.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    k.GetVolumePathNameW.restype = ctypes.c_int
    buf = ctypes.create_unicode_buffer(261)
    root = ""
    if k.GetVolumePathNameW(target, buf, 261):
        root = buf.value
    if not root:                                 # 保底：退回到盘符
        drive = os.path.splitdrive(os.path.abspath(target))[0]
        root = (drive + "\\") if drive else os.path.abspath(target)
    k.GetDiskFreeSpaceExW.argtypes = [ctypes.c_wchar_p,
                                      ctypes.POINTER(_ULARGE_INTEGER),
                                      ctypes.POINTER(_ULARGE_INTEGER),
                                      ctypes.POINTER(_ULARGE_INTEGER)]
    k.GetDiskFreeSpaceExW.restype = ctypes.c_int
    avail, total, vol_free = _ULARGE_INTEGER(), _ULARGE_INTEGER(), _ULARGE_INTEGER()
    if not k.GetDiskFreeSpaceExW(root, ctypes.byref(avail), ctypes.byref(total),
                                 ctypes.byref(vol_free)):
        return {}, f"取不到 {root} 的容量信息（盘符可能不存在或当前无权限访问）"
    label = ctypes.create_unicode_buffer(261)
    fsn = ctypes.create_unicode_buffer(261)
    ok = bool(k.GetVolumeInformationW(root, label, 261, None, None, None, fsn, 261))
    return {"volume_root": root,
            "label": label.value if ok else None,
            "filesystem": fsn.value if ok else None,
            "drive_type": DRIVE_TYPES.get(k.GetDriveTypeW(root), "unknown"),
            "available_bytes": int(avail.QuadPart),
            "total_bytes": int(total.QuadPart),
            "volume_free_bytes": int(vol_free.QuadPart)}, ""


def _free_space_posix(target: str) -> tuple:
    """非 Windows：shutil.disk_usage（给不了「卷空闲」与「可用」的区别，两个字段同值）。"""
    import shutil
    try:
        u = shutil.disk_usage(target)
    except Exception as e:
        return {}, f"取不到 {target} 的容量信息：{e}"
    return {"volume_root": os.path.abspath(target), "label": None, "filesystem": None,
            "drive_type": "unknown", "available_bytes": int(u.free),
            "total_bytes": int(u.total), "volume_free_bytes": int(u.free)}, ""


@declare_primitive(
    "disk.usage",
    "看**指定路径所在磁盘**的容量与剩余，并判断是不是快满了。"
    "什么时候用：动手写文件 / 装东西之前问「这个位置还剩多少、我还能不能写进去」；"
    "或者用户直接问「C 盘还剩多少」—— 这种问题用本条，别用 disk.list。"
    "和 disk.list 的区别：disk.list 说「机器上有哪些盘」且容量是**全部卷的求和**，"
    "这条说「我要写的这个路径落在哪个卷上、还剩多少」—— 路径未必和盘符一一对应"
    "（挂载点 / 卷挂载进目录 / UNC 都靠系统解析）。"
    "⚠️ 跟谁容易混：问「机器上有哪些盘 / 都是什么类型」用 disk.list；"
    "问「那块**物理硬盘**本身健不健康、是固态还是机械、什么总线」用 disk.health"
    "（一块物理盘可能分成多个卷）—— 本条只回答「这个位置还剩多少、能不能写进去」。"
    "参数怎么填：path 传要查的路径（文件 / 目录 / 盘符都行），**不给则用当前工作目录**；"
    "路径不存在时不报错，会自动往上找到最近的上级目录所在卷来算（note 里会说明）；"
    "warn_pct 是「快满了」的占用率阈值，默认 85，取值 0–100。"
    "返回什么：ok；volume_root / label / filesystem / drive_type 是这个路径落在哪个卷；"
    "total_gb / used_gb / used_pct / free_pct 是容量；available_gb 与 volume_free_gb 是两个不同的"
    "「剩余」—— available_gb 是**当前用户真正能写**的（配额已扣），volume_free_gb 是卷上未被占用的，"
    "「还能不能写进去」看前者、「这个盘是不是快满了」看后者；resolved_path 是实际拿去算的路径；"
    "status（ok / warning / critical）与 is_full 是结论；note 是人话总结。"
    "status 三档：ok / warning（占用 ≥ warn_pct 或可用 < 10GB）/ critical（占用 ≥ 95% 或可用 < 1GB）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string",
                  "description": "要查的路径（文件 / 目录 / 盘符都行），默认当前工作目录"},
         "warn_pct": {"type": "number", "minimum": 0, "maximum": 100,
                      "description": "占用率超过它就算「快满了」（warning），默认 85；取值 0–100"
                                     "（超出范围会被截到边界）"},
     },
     "required": [],
     "additionalProperties": False},
    state={"used_pct": "占用%", "available_gb": "可用GB", "status": "状态"},
    block="disk",
)
def disk_usage(path: str = "", warn_pct: float = 85.0) -> dict:
    target = (path or "").strip() or os.getcwd()
    try:
        warn = float(warn_pct)
    except (TypeError, ValueError):
        warn = 85.0
    warn = min(max(warn, 0.0), 100.0)

    # 路径不存在时往上找最近的上级目录（问「某个还没建的目录还剩多少空间」是常见需求，
    # 不该因为目录不存在就答不了）；找不到就如实说。
    probe, shifted = target, False
    if not os.path.exists(probe):
        cur = os.path.abspath(probe)
        while cur and not os.path.exists(cur):
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        if not os.path.exists(cur):
            return {"ok": False, "path": target, "status": "unknown",
                    "note": f"路径不存在、也找不到它最近的上级目录：{target}"}
        probe, shifted = cur, True

    try:
        data, err = (_free_space_windows(probe) if platform.system() == "Windows"
                     else _free_space_posix(probe))
    except Exception as e:
        data, err = {}, f"读取失败：{e}"
    if err:
        return {"ok": False, "path": target, "status": "unknown", "note": err}

    total = data["total_bytes"]
    avail = data["available_bytes"]
    vol_free = data["volume_free_bytes"]
    used = max(0, total - vol_free)               # 占用按「卷」算（不看配额）
    used_pct = round(used / total * 100, 1) if total else 0.0
    free_pct = round(vol_free / total * 100, 1) if total else 0.0
    gb = 1073741824

    if used_pct >= 95.0 or avail < 1 * gb:
        status, verdict = "critical", "几乎满了，随时可能因为空间不足写失败"
    elif used_pct >= warn or avail < 10 * gb:
        status, verdict = "warning", "空间偏紧，建议先清一清再做大动作"
    else:
        status, verdict = "ok", "空间充裕"

    out = {
        "ok": True, "path": target, "resolved_path": probe,
        "volume_root": data["volume_root"], "label": data.get("label"),
        "filesystem": data.get("filesystem"), "drive_type": data.get("drive_type"),
        "total_gb": round(total / gb, 2),
        "used_gb": round(used / gb, 2),
        "used_pct": used_pct, "free_pct": free_pct,
        # available = 当前用户能写的（配额已扣）；volume_free = 卷上未被占用
        "available_gb": round(avail / gb, 2),
        "volume_free_gb": round(vol_free / gb, 2),
        "warn_pct": warn, "status": status, "is_full": status != "ok",
    }
    label = f"（卷标 {out['label']}）" if out["label"] else ""
    note = (f"{out['volume_root']}{label} 共 {out['total_gb']}GB，已用 {out['used_gb']}GB"
            f"（{out['used_pct']}%），当前用户可用 {out['available_gb']}GB —— {verdict}")
    if shifted:
        note += f"；注意 {target} 不存在，是按最近的上级目录 {probe} 所在卷算的"
    if abs(avail - vol_free) > 512 * 1024 * 1024:
        note += (f"；该卷空闲 {out['volume_free_gb']}GB 大于你这个账户的可用 {out['available_gb']}GB，"
                 f"差额来自磁盘配额 / 占位文件")
    out["note"] = note
    return out


# ============================================================================
# disk.health —— 物理硬盘的健康 / 介质 / 总线（只读）
# ============================================================================
# **靠系统自带的 PowerShell Storage 模块**（Storage 模块是 Windows 8/2012 起随系统带的），
# 拿不到它就退回 WMI 的 Win32_DiskDrive —— 但那个来源只给「设备状态 OK」，
# **不是 SMART 健康度**，返回值里 health_reliable 会标出来，别把两者当一回事。
#
# ⚠️ 实测（本机 win11 build 26200）：
#   · `Get-PhysicalDisk` 可用，返回 MediaType / BusType / HealthStatus 都是**英文枚举**
#     （SSD / NVMe / Healthy），不受 UI 语言影响 —— 可以直接当机器可读字段用。
#   · `Get-StorageReliabilityCounter`（温度 / 磨损 / 通电小时）**需要管理员**，
#     非管理员报「Access to a CIM resource was not available to the client」。
#     所以那一块是「有就给、没有就说明」，不让整条原语失败。
#   · `ConvertTo-Json` 在 PowerShell 5.1 下对**单个对象**输出的是对象而不是数组，
#     必须 `-InputObject @(...)` 强制成数组，否则调用方会收到两种形状。

_PS_HEALTH = r"""
$ErrorActionPreference='SilentlyContinue'
$out=@{source='none'; items=@(); error=''}
try{
  if(Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue){
    $raw=@(Get-PhysicalDisk)
    if($raw.Count -gt 0){
      $items=@()
      foreach($d in $raw){
        $rel=$null
        try{ $rel=$d | Get-StorageReliabilityCounter -ErrorAction Stop |
             Select-Object Temperature,Wear,PowerOnHours,ReadErrorsTotal,WriteErrorsTotal,StartStopCycleCount }catch{}
        $items += [pscustomobject]@{
          device_id=[string]$d.DeviceId; name=$d.FriendlyName; media_type=$d.MediaType;
          bus_type=$d.BusType; health=$d.HealthStatus; operational=$d.OperationalStatus;
          size=$d.Size; spindle_rpm=$d.SpindleSpeed; serial=$d.SerialNumber; reliability=$rel }
      }
      $out.source='Get-PhysicalDisk'; $out.items=$items
    }
  }
  if($out.source -eq 'none' -and (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)){
    $out.source='Win32_DiskDrive'
    $out.items=@(Get-CimInstance Win32_DiskDrive |
                 Select-Object Index,Model,InterfaceType,MediaType,Status,Size,SerialNumber,Partitions)
  }
}catch{ $out.error=$_.Exception.Message }
ConvertTo-Json -InputObject $out -Depth 5 -Compress
"""

# 英文枚举 → 中文说明（只翻我们认得的那几个，别的一律原样给，不猜）
_MEDIA_CN = {"SSD": "固态（SSD）", "HDD": "机械（HDD）", "SCM": "存储级内存（SCM）",
             "UNSPECIFIED": "未知（系统没报介质类型）"}
_BUS_CN = {"NVME": "NVMe", "SATA": "SATA", "SAS": "SAS", "USB": "USB", "RAID": "RAID",
           "ISCSI": "iSCSI", "SCSI": "SCSI", "IDE": "IDE", "PCIE": "PCIe", "FC": "光纤通道",
           "MMC": "MMC", "SD": "SD", "FILEBACKEDVIRTUAL": "虚拟盘", "STORAGESPACES": "存储空间"}
_HEALTH_CN = {"HEALTHY": "健康", "WARNING": "警告", "UNHEALTHY": "不健康", "UNKNOWN": "未知"}


def _cn(mapping: dict, value, default: str = "未知") -> str:
    if value is None or value == "":
        return default
    return mapping.get(str(value).upper(), str(value))


def _run_health_ps() -> tuple:
    """跑 PowerShell 拿物理盘清单。返回 (数据字典, 错误说明)。"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_HEALTH],
                           capture_output=True, timeout=90)
    except FileNotFoundError:
        return {}, "这台机器上找不到 powershell（取不到物理硬盘信息）"
    except subprocess.TimeoutExpired:
        return {}, "PowerShell 查询超时（90 秒），取不到物理硬盘信息"
    except Exception as e:
        return {}, f"调用 PowerShell 失败：{e}"
    text = decode_output(r.stdout or b"")
    if not text.strip():
        tail = (decode_output(r.stderr or b"") or "").strip()[:200]
        return {}, f"PowerShell 没有输出（返回 {r.returncode}）：{tail}"
    try:
        return json.loads(text), ""
    except Exception as e:
        return {}, f"PowerShell 输出不是合法 JSON（{e}）：{text.strip()[:200]}"


@declare_primitive(
    "disk.health",
    "看**物理硬盘**的健康 / 介质 / 总线：是固态还是机械、什么总线（NVMe / SATA / RAID…）、"
    "系统报的健康状态、容量、序列号，管理员下还能带温度 / 磨损 / 通电小时。"
    "和 disk.list / disk.usage 的区别：那两条看的是**卷**（盘符 / 容量 / 文件系统 / 还剩多少），"
    "这条看的是**那块硬件本身**（一块物理盘可能分成多个卷）—— "
    "问剩余空间用 disk.usage，问机器上有哪些盘用 disk.list，"
    "只有问「盘本身健不健康、是固态还是机械、什么总线」才用本条。"
    "⚠️ **依赖系统自带的 PowerShell Storage 模块**：拿不到时会退回 WMI 的 Win32_DiskDrive ——"
    "那个来源只给「设备状态 OK」，**不是 SMART 健康度**，返回值里 health_reliable=false 标出来了，"
    "别据此认为硬盘一定健康。两路都取不到时 available=false，说明「这台机器上取不到」，"
    "**不是**「硬盘没问题」。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"count": "硬盘数", "attention": "需注意"},
    block="disk",
)
def disk_health() -> dict:
    if platform.system() != "Windows":
        return {"ok": False, "available": False, "count": 0, "disks": [],
                "note": f"这条原语目前只实现了 Windows（当前平台 {platform.system()}）："
                        f"取不到物理硬盘的健康与总线信息，**不代表硬盘没问题**"}
    data, err = _run_health_ps()
    if err:
        return {"ok": False, "available": False, "count": 0, "disks": [],
                "health_reliable": False,
                "note": f"这台机器上取不到物理硬盘信息：{err}。"
                        f"**取不到不代表硬盘一定是好的** —— 要确认得看机箱指示灯 / BIOS / "
                        f"厂商的硬盘工具"}
    source = data.get("source", "none")
    raw_items = data.get("items") or []
    if source == "none" or not raw_items:
        return {"ok": False, "available": False, "count": 0, "disks": [],
                "health_reliable": False, "source": source,
                "note": "这台机器上取不到物理硬盘信息（Storage 模块与 Win32_DiskDrive 都没给出结果）。"
                        "**取不到不代表硬盘一定是好的**"}
    physical = source == "Get-PhysicalDisk"
    gb = 1073741824
    disks: list[dict] = []
    rel_missing = False
    for it in raw_items:
        name = it.get("name") or it.get("Model") or ""
        media = it.get("media_type") or "Unspecified"
        bus = it.get("bus_type") or it.get("InterfaceType") or ""
        health = it.get("health") or it.get("Status") or ""
        rpm = it.get("spindle_rpm")
        size = it.get("size")
        d = {
            "device_id": str(it.get("device_id") if physical else it.get("Index", "")),
            "name": name,
            "size_gb": round(size / gb, 2) if isinstance(size, (int, float)) else None,
            "media_type": media,
            "media": _cn(_MEDIA_CN, media),
            "bus_type": bus,
            "bus": _cn(_BUS_CN, bus, str(bus)),
            "health": health,
            "health_cn": _cn(_HEALTH_CN, health),
            "operational": it.get("operational") or "",
            "serial": (it.get("serial") or "").strip() or None,
            "spindle_rpm": rpm,
        }
        # 机械 / 固态的判定：优先信系统给的 MediaType；它没报时用转速兜底（0 = 无转速 = 固态）
        if str(media).upper() == "SSD":
            d["is_ssd"] = True
        elif str(media).upper() == "HDD":
            d["is_ssd"] = False
        elif isinstance(rpm, (int, float)):
            d["is_ssd"] = rpm == 0
        else:
            d["is_ssd"] = None
        rel = it.get("reliability")
        if isinstance(rel, dict) and any(v is not None for v in rel.values()):
            d["reliability"] = {k: v for k, v in rel.items() if v is not None}
        elif physical:
            rel_missing = True
        if not physical:
            d["health_note"] = "这个状态来自 Win32_DiskDrive 的 Status（设备是否可用），不是 SMART 健康度"
        disks.append(d)

    attention = [d for d in disks if str(d["health"]).upper() not in ("HEALTHY", "OK", "")]
    brief = "；".join(
        f"{d['device_id']} {d['name']}（{d['media']} / {d['bus']} / {d['health_cn']}"
        + (f" / {d['size_gb']}GB" if d["size_gb"] else "") + "）" for d in disks)
    note = f"共 {len(disks)} 块物理硬盘（来源 {source}）：{brief}"
    if not physical:
        note += ("；⚠️ 这个来源**只有「设备状态」，不是 SMART 健康度**（health_reliable=false）——"
                 "别据此认为硬盘一定健康")
    elif rel_missing:
        note += "；温度 / 磨损 / 通电小时需要管理员权限，本次没取到"
    if attention:
        note += f"；⚠️ 有 {len(attention)} 块状态不是「健康」，建议尽快备份并进一步检查"
    return {"ok": True, "available": True, "source": source,
            "health_reliable": physical, "count": len(disks), "disks": disks,
            "attention": len(attention), "note": note}
