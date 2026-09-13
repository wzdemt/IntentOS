"""权限域原语 —— 看文件 / 目录的权限清单（acl.*）。

零依赖：Windows 走 `ctypes` 调 `advapi32`（GetNamedSecurityInfoW / GetAce / LookupAccountSidW），
不加任何第三方库，也不解析 `icacls` 的文本输出。

**为什么不用 `icacls`**：它的输出是**本地化**的 —— 中文系统上「已成功处理」「拒绝访问」这些
说明文字全变中文，而权限项本身（`NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`）又是稳定的。
一半稳定一半本地化，解析起来必然在某台机器上崩。直接问 API 拿结构化数据，再自己翻译成人话，
这条路没有任何本地化依赖。

**定位**：`acl.get` 只**读**，回答「谁能读、谁能改」。改权限（`acl.set`）不在本域 ——
那是能把自己的权限提上去的高危操作，按能力地图走 IR 模板，不进原语表。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_acl，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os

from core.factory import declare_primitive  # type: ignore

_advapi32 = ctypes.windll.advapi32

# ── GetNamedSecurityInfoW 的参数常量 ──
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004

# ── 安全描述符控制位（GetSecurityDescriptorControl 用）──
SE_DACL_PROTECTED = 0x1000          # 该 DACL **不再**从父级继承（就是「已切断继承」）
SE_DACL_AUTO_INHERITED = 0x0400

# ── ACE 类型 → (效果类别, 人话) ──
# 效果类别只有四种：allow / deny / audit / label；别的都是它们的变体（对象 / 回调）。
_ACE_TYPES = {
    0x00: ("allow", "允许"),
    0x01: ("deny", "拒绝"),
    0x02: ("audit", "审核（只记安全日志，不影响能不能访问）"),
    0x03: ("alarm", "警报"),
    0x05: ("allow", "允许（对象 ACE）"),
    0x06: ("deny", "拒绝（对象 ACE）"),
    0x07: ("audit", "审核（对象 ACE）"),
    0x08: ("alarm", "警报（对象 ACE）"),
    0x09: ("allow", "允许（回调 ACE：条件由系统回调判定）"),
    0x0A: ("deny", "拒绝（回调 ACE：条件由系统回调判定）"),
    0x0B: ("allow", "允许（回调对象 ACE）"),
    0x0C: ("deny", "拒绝（回调对象 ACE）"),
    0x0D: ("audit", "审核（回调 ACE）"),
    0x0E: ("alarm", "警报（回调 ACE）"),
    0x0F: ("audit", "审核（回调对象 ACE）"),
    0x10: ("alarm", "警报（回调对象 ACE）"),
    0x11: ("label", "完整性标签（强制完整性级别，不是普通权限）"),
    0x12: ("label", "资源属性（不是普通权限）"),
    0x13: ("label", "范围策略 ID（不是普通权限）"),
}
# 带 GUID 的对象 ACE：SID 之前多出 Flags + 两个可选 GUID（回调 ACE 后面还跟着一段应用数据，
# 我们只读到 SID 为止 —— 够回答「谁 + 能读还是能改」了）
_OBJECT_TYPES = frozenset({0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10})

# ── 权限位 → 人话 ──
_MASK_BITS = (
    (0x00000001, "读数据 / 列目录"),
    (0x00000002, "写数据 / 新建文件"),
    (0x00000004, "追加数据 / 新建子目录"),
    (0x00000008, "读扩展属性"),
    (0x00000010, "写扩展属性"),
    (0x00000020, "执行 / 遍历目录"),
    (0x00000040, "删除子项"),
    (0x00000080, "读属性"),
    (0x00000100, "写属性"),
    (0x00010000, "删除"),
    (0x00020000, "读权限（看得到这份 ACL）"),
    (0x00040000, "改权限（能改 ACL）"),
    (0x00080000, "改所有者"),
    (0x00100000, "同步（等待句柄，普通用户可以忽略）"),
)

# 常见「标准权限组合」→ 一个词。数字来自 Windows 的 FILE_GENERIC_* 组合，直接用常量比对，
# 不去逐位推算（逐位推算出来的「修改」在某些机器上会少一位而对不上）。
_STANDARD_LEVELS = (
    (0x001F01FF, "完全控制"),        # FILE_ALL_ACCESS
    (0x001301BF, "修改"),            # 读 + 写 + 执行 + 删除
    (0x001200A9, "读取和执行"),      # 读 + 执行
    (0x00120089, "读取"),
    (0x00120116, "写入"),
    (0x00000000, "无权限（列出来但什么都不给）"),
)
_GENERIC_ALL = 0x10000000

# ── ACE 标志（继承有关） ──
_ACE_FLAGS = (
    (0x10, "继承来的"),              # INHERITED_ACE
    (0x02, "目录继承（子目录也适用）"),
    (0x01, "文件继承（子文件也适用）"),
    (0x04, "不向下传播"),
    (0x08, "只对被继承的对象生效（本对象自己不受这条约束）"),
)

# ── 完整性级别（SID 的最后一个 RID → 人话）──
# 强完整性标签 ACE（0x11）的「掩码」位置放的是这个 RID，不是权限位，别混。
_INTEGRITY = {"0": "不受信任（Untrusted）", "4096": "低（Low）", "8192": "中（Medium）",
              "12288": "高（High）", "16384": "系统（System）"}

# ── Win32 错误码 → 人话 ──
_ERRORS = {
    2: "路径不存在",
    3: "路径不存在（中间某级目录也没有）",
    5: "拒绝访问：当前账户没有读这个对象权限清单的资格",
    32: "文件正被别的进程占用，暂时读不到",
    87: "路径写法不对（GetNamedSecurityInfoW 不接受这个写法）",
    1326: "登录凭据不对，取不到",
}


# ── 结构体 ──────────────────────────────────────────────────────────────
class _ACL(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort),
                ("Sbz2", ctypes.c_ushort)]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                ("AceSize", ctypes.c_ushort)]


# ── API 绑定（argtypes 全部写死：64 位上不写会被按 32 位传，指针直接截断） ──
_advapi32.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p)]
_advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
_advapi32.GetAce.restype = wintypes.BOOL
_advapi32.LookupAccountSidW.argtypes = [
    wintypes.LPWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int)]
_advapi32.LookupAccountSidW.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorControl.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(wintypes.DWORD)]
_advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
# 释放 API 分配的内存（ConvertSidToStringSidW / GetNamedSecurityInfoW 给的都是 LocalAlloc 出来的）
_kernel32 = ctypes.windll.kernel32
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p


def _sid_to_string(sid_ptr) -> str:
    """SID → `S-1-5-18` 这种字符串（账户名查不到时的兜底）。"""
    buf = wintypes.LPWSTR()
    if _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(buf)) and buf.value:
        text = buf.value
        _kernel32.LocalFree(buf)
        return text
    return ""


def _sid_name(sid_ptr) -> tuple:
    """SID → (账户名, SID 字符串)。账户名按当前机器解析，解析不了就只给 SID。

    ⚠️ 解析出来的「域\\名字」里，`NT AUTHORITY\\所有受限制的应用程序包` 这种是**本地化**的 ——
    这是好事（给人看），但**不能拿它做程序判断**，程序判断请用 sid 字段。
    """
    name = ctypes.create_unicode_buffer(256)
    domain = ctypes.create_unicode_buffer(256)
    nlen, dlen = wintypes.DWORD(256), wintypes.DWORD(256)
    use = ctypes.c_int()
    sid_str = _sid_to_string(sid_ptr)
    if _advapi32.LookupAccountSidW(None, sid_ptr, name, ctypes.byref(nlen),
                                   domain, ctypes.byref(dlen), ctypes.byref(use)):
        full = f"{domain.value}\\{name.value}" if domain.value else name.value
        return full, sid_str
    return "", sid_str


def _sid_offset(ace_type: int, ace_ptr: int) -> int:
    """SID 在 ACE 里的字节偏移。

    普通 ACE：Header(4) + Mask(4) → 8。对象 ACE 后面还跟着 Flags(4) 和最多两个 GUID(16×2)，
    偏移得按 Flags 现算 —— 写死 8 会在带对象 GUID 的 ACE 上读到错位的内存。
    """
    if ace_type not in _OBJECT_TYPES:
        return 8
    flags = ctypes.c_uint32.from_address(ace_ptr + 8).value
    off = 12
    if flags & 1:                    # ACE_OBJECT_TYPE_PRESENT
        off += 16
    if flags & 2:                    # ACE_INHERITED_OBJECT_TYPE_PRESENT
        off += 16
    return off


def _describe_mask(mask: int) -> tuple:
    """权限掩码 → (一档标准权限的人话, 明细列表)。返回 ('', [...]) 表示只能给明细。"""
    if mask & _GENERIC_ALL:
        return "完全控制", []
    for value, label in _STANDARD_LEVELS:
        if mask == value:
            return label, []
    return "", [text for bit, text in _MASK_BITS if mask & bit]


def _describe_flags(flags: int) -> str:
    """ACE 标志 → 继承相关的人话。"""
    return "、".join(text for bit, text in _ACE_FLAGS if flags & bit)


def _scope_cn(flags: int) -> str:
    """这条权限**管到谁** —— 一句话说清，因为同一个人常有多条 ACE（一条管自己、一条管子项），
    不写出作用范围的话，人话总结里会出现看着重复的两句话。"""
    if flags & 0x08:
        return "只对子项生效"
    parts = []
    if flags & 0x02:
        parts.append("子目录")
    if flags & 0x01:
        parts.append("子文件")
    return f"本对象 + {'与'.join(parts)}" if parts else "仅本对象"


def _normalize(path: str) -> tuple:
    """把调用方给的路径收成 API 要的写法。返回 (路径, 错误说明)。

    ⚠️ GetNamedSecurityInfoW 对写法挑剔：**除了盘符根（`C:\\`），别的路径不能带结尾反斜杠**，
    带了一般报 ERROR_INVALID_NAME。超长路径要加 `\\\\?\\` 前缀（API 自身不认 MAX_PATH 以外的）。
    """
    p = (path or "").strip().strip('"')
    if not p:
        return "", "路径不能为空"
    p = os.path.abspath(p)
    if len(p) == 3 and p[1:] == ":\\":           # 盘符根：保持 `C:\` 形态
        return p, ""
    p = p.rstrip("\\")
    if not p:
        return "", "路径不能为空"
    if len(p) >= 248 and not p.startswith("\\\\?\\"):
        p = "\\\\?\\" + p
    return p, ""


def _query(path: str) -> tuple:
    """取一个路径的所有者 + DACL。返回 (数据字典, 错误说明)。

    **DACL 为 NULL 是合法且极其危险的状态**（「没有 DACL」= 所有人都能完全访问），
    必须单独说明，不能当成「读不到」。
    """
    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    rc = _advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner_sid), None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if rc != 0:
        return {}, _ERRORS.get(rc, f"系统返回错误码 {rc}")
    try:
        detail = {"dacl_present": bool(dacl.value),
                  "dacl_null": not bool(dacl.value)}
        # 控制位：DACL 是不是「已切断继承」（SE_DACL_PROTECTED）
        ctrl, rev = ctypes.c_ushort(), wintypes.DWORD()
        if _advapi32.GetSecurityDescriptorControl(sd, ctypes.byref(ctrl), ctypes.byref(rev)):
            detail["dacl_protected"] = bool(ctrl.value & SE_DACL_PROTECTED)
            detail["dacl_auto_inherited"] = bool(ctrl.value & SE_DACL_AUTO_INHERITED)
        else:
            detail["dacl_protected"] = None
            detail["dacl_auto_inherited"] = None
        if owner_sid.value:
            own_name, own_sid = _sid_name(owner_sid)
            detail["owner"], detail["owner_sid"] = own_name, own_sid
        else:
            detail["owner"], detail["owner_sid"] = "", ""
        entries = []
        if dacl.value:
            acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
            detail["ace_total"] = acl.AceCount
            for i in range(acl.AceCount):
                ace = ctypes.c_void_p()
                if not _advapi32.GetAce(dacl, i, ctypes.byref(ace)) or not ace.value:
                    entries.append({"index": i, "unreadable": True})
                    continue
                header = ctypes.cast(ace, ctypes.POINTER(_ACE_HEADER)).contents
                kind, kind_cn = _ACE_TYPES.get(header.AceType, ("unknown", f"未知类型 0x{header.AceType:02x}"))
                item = {"index": i, "ace_type": f"0x{header.AceType:02x}", "effect": kind,
                        "effect_cn": kind_cn,
                        "inherited": bool(header.AceFlags & 0x10),
                        "applies_to": _scope_cn(header.AceFlags),
                        "flags": _describe_flags(header.AceFlags)}
                mask = ctypes.c_uint32.from_address(ace.value + 4).value
                item["mask"] = f"0x{mask:08x}"
                # 完整性标签 ACE 的 mask 不是权限掩码，是完整性级别的 RID —— 不能当权限翻
                who = sid = ""
                if kind != "label":
                    who, sid = _sid_name(ctypes.c_void_p(ace.value + _sid_offset(header.AceType, ace.value)))
                if kind == "label":
                    rid = sid.rsplit("-", 1)[-1] if sid else ""
                    item["level"] = (f"完整性标签：{_INTEGRITY.get(rid, rid) or '?'}"
                                     f"（强制级别，不是普通权限）")
                else:
                    level, rights = _describe_mask(mask)
                    item["level"] = level or "特殊权限"
                    if not level:
                        item["rights"] = rights
                if who or sid:
                    item["who"], item["sid"] = who or sid, sid
                entries.append(item)
        else:
            detail["ace_total"] = 0
        detail["entries"] = entries
        return detail, ""
    finally:
        if sd.value:
            _kernel32.LocalFree(sd)


def _summarize(entries: list, owner: str, detail: dict, filtered: bool) -> str:
    """把 ACL 翻成一段人话 —— 这才是这条原语真正要交付的东西。

    ⚠️ `entries` 是**要展示的那一页**（可能被 include_inherited 过滤、被 limit 截断），
    但「ACL 是不是空的」这个判断必须看**原始 ACL**（detail）—— 否则「刨掉继承项后一条不剩」
    会被说成「谁都访问不了」，那是两件完全不同的事。
    """
    raw: list = detail.get("entries", [])

    def who_level(e: dict) -> str:
        bits = []
        if e.get("applies_to"):
            bits.append(e["applies_to"])
        if e.get("inherited"):
            bits.append("继承")
        tail = f"（{'、'.join(bits)}）" if bits else ""
        return f"{e.get('who') or e.get('sid') or '?'} {e.get('level', '')}{tail}"

    allow = [e for e in entries if e.get("effect") == "allow"]
    deny = [e for e in entries if e.get("effect") == "deny"]
    parts = [who_level(e) for e in allow]
    seg = f"共 {len(entries)} 条权限项"
    if allow:
        seg += f"：允许 {'；允许 '.join(parts)}"
    if deny:
        dparts = [who_level(e) for e in deny]
        seg += f"。另有 {len(deny)} 条**拒绝**项（拒绝优先于允许）：拒绝 {'；拒绝 '.join(dparts)}"
    if not allow and not deny:
        seg += "，其中没有「允许 / 拒绝」这类访问项"
    if detail.get("dacl_null"):
        seg += ("。⚠️ 这个对象的 DACL 是**空的（NULL）**—— 等于**所有人都能完全访问**，"
                "这是「权限全开」的状态，不是「读不到权限」")
    elif not raw:
        seg += "。⚠️ ACL 存在但一条权限项都没有 —— 等于**谁都访问不了**（连读都不行）"
    elif not entries and filtered:
        seg += "。这个对象**自己没有单独设过权限**，现有的权限全是从父目录继承来的"
    if owner:
        seg += f"。所有者：{owner}"
        seg += "（所有者随时能改 ACL，所以「所有者是谁」本身就是权限的一部分）"
    if detail.get("dacl_protected"):
        seg += "；该 ACL **已切断继承**（不再随父目录变化）"
    elif any(e.get("inherited") for e in entries):
        seg += "；其中有继承自父目录的项，改父目录会跟着变"
    return seg


@declare_primitive(
    "acl.get",
    "看一个文件 / 目录的权限清单：**谁能读、谁能改**。"
    "什么时候用：① 某个文件 / 目录「拒绝访问」，想弄清是谁设的限制；"
    "② 接手一台机器 / 一份数据，想知道它现在对谁开放；③ 排查共享目录、Program Files 这类位置"
    "的权限有没有被人改过。"
    "⚠️ 什么时候**别**用它：想知道文件的只读 / 隐藏这类**文件属性**（那是属性不是权限 —— 看属性、"
    "改属性都用 fs.attrs，它还认识「重解析点」这类链接标记）；"
    "或者想确认「我这次到底能不能写进去」—— ACL 只是配置，实际能不能访问还受账户、完整性级别、"
    "共享设置等影响，最终要看真实的读写结果。"
    "参数怎么填：path 必填（文件或目录）；include_inherited 默认 True，"
    "想看「刨掉继承、这个对象**自己单独**设过什么」就传 False；"
    "limit 是最多返回多少条权限项（防超长 ACL 撑爆上下文），默认 100，上限 500。"
    "返回什么：ok；owner / owner_sid 是所有者（所有者随时能改 ACL，所以它本身就是权限的一部分）；"
    "entries 是翻好的**人话**权限项（每条含 index / effect（allow / deny / audit / label）/ "
    "effect_cn / who / sid / level 或 rights / inherited / applies_to / flags）；"
    "ace_count / ace_total_raw / returned / truncated 是条数（truncated=True 表示被 limit 截断）；"
    "allow_count / deny_count 是两类计数；dacl_null（DACL 为空）/ dacl_protected（已切断继承）是两个关键"
    "状态；note 是人话总结。"
    "⚠️ 需要**机器判断**时用 sid 字段，别用账户名字段 —— 账户名可能被本地化"
    "（中文系统上会是中文），拿它做程序判断会翻车。"
    "两种极端状态会明确说明：DACL 为空（= **所有人都能完全访问**，不是「读不到权限」）"
    "与 ACL 里一条项都没有（= **谁都访问不了**）。"
    "⚠️ 陷阱：**拒绝项优先于允许项** —— 同一个人既在「允许」又在「拒绝」里时，实际是拒绝生效。"
    "本原语只读；改权限（能把自己权限提上去的高危操作）不在原语表里，别指望拿它去修权限。",
    {"type": "object",
     "properties": {
         "path": {"type": "string",
                  "description": "文件或目录的路径（如 C:\\Program Files 或 D:/x/a.txt）"},
         "include_inherited": {"type": "boolean",
                               "description": "是否包含从父目录继承来的权限项，默认 True"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "最多返回多少条权限项（防超长 ACL 撑爆上下文），"
                                  "默认 100，上限 500"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"ace_count": "权限项", "deny_count": "拒绝项"},
    block="filesystem",
)
def acl_get(path: str, include_inherited: bool = True, limit: int = 100) -> dict:
    target, err = _normalize(path)
    if err:
        return {"ok": False, "path": path, "note": err}
    kind = ("directory" if os.path.isdir(target)
            else "file" if os.path.isfile(target) else "unknown")
    if kind == "unknown":
        return {"ok": False, "path": target, "exists": False,
                "note": f"路径不存在（或当前账户看不到它）：{target}"}
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 100

    detail, err = _query(target)
    if err:
        return {"ok": False, "path": target, "kind": kind,
                "note": f"取不到权限清单：{err}"}

    entries = detail.get("entries", [])
    all_entries = entries
    if not include_inherited:
        entries = [e for e in entries if not e.get("inherited")]
    total = len(entries)
    page = entries[:limit]
    more = total > limit
    deny_count = sum(1 for e in page if e.get("effect") == "deny")
    allow_count = sum(1 for e in page if e.get("effect") == "allow")

    out = {"ok": True, "path": target, "kind": kind, "exists": True,
           "owner": detail.get("owner", ""), "owner_sid": detail.get("owner_sid", ""),
           "dacl_null": detail.get("dacl_null", False),
           "dacl_protected": detail.get("dacl_protected"),
           "dacl_auto_inherited": detail.get("dacl_auto_inherited"),
           "ace_count": total, "ace_total_raw": detail.get("ace_total", 0),
           "returned": len(page), "truncated": more,
           "allow_count": allow_count, "deny_count": deny_count,
           "entries": page}
    out["note"] = _summarize(page, out["owner"], detail, filtered=not include_inherited)
    if not include_inherited and all_entries:
        dropped = len(all_entries) - total
        if dropped:
            out["note"] += (f"；已按要求刨掉 {dropped} 条继承来的项"
                            + ("（刨完一条不剩 = 这个对象自己没有单独设过权限，全靠父目录给的）"
                               if not total else ""))
    if more:
        out["note"] += f"；权限项已截断到前 {limit} 条，调大 limit 看全"
    return out
