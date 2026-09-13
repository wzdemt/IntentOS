"""原语共享层 —— 跨域复用的小工具与常量。

**为什么存在**：原语文件历来「各写各的」，理由是「原语文件之间不能互相 import」。
那个理由**只对了一半**（详见下节），代价却是同一种活在三四个文件里各抄一份 ——
一处改进了，别处不会跟着改，行为就悄悄分叉。

**为什么文件名以 `_` 开头**：`factory.load_primitives()` 扫描目录时会跳过下划线开头的
文件（`if p.name.startswith("_")`），所以本文件不会被当成原语文件加载 —— 它只是被引用的库，
不注册任何原语（因此也不影响进度统计）。

关于 import —— 2026-09-11 实测更正
────────────────────────────────────────────────────────────────────
旧说法「原语文件之间不能互相 import」**不准确**。真实情况是：

  · `load_primitives()` 用 `spec_from_file_location(f"prim_{p.stem}", p)` 加载，
    模块名是 `prim_fs` 这种临时名，而且 **`module_from_spec` 不写进 `sys.modules`**。
    → 所以 `import prim_fs` 必然失败（名册里没有、磁盘上也没有这个名字的文件）。
      那句旧说法就是从这儿来的。
  · 但 `primitives/` 是个**正常的包**（有 `__init__.py`），
    → `from primitives.xxx import ...` 走标准 import 机制，**完全可用**（已实测）。

⚠️ **但不要 `from primitives.其它域文件 import ...`** —— 那会让那个文件被加载**第二遍**
（一次叫 `prim_xxx`、一次叫 `primitives.xxx`），它所有的模块级代码都会跑两次。
登记表是「先到先得」，重复登记本身不出错，但白跑一遍，而且将来若有人在模块级写了
有副作用的代码，就会出真问题。

**正解：共享的东西放本文件，各域文件 `from primitives._common import ...`** —— 只加载一次。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import re
import stat
import winreg


# ── 外部命令输出解码 ────────────────────────────────────────────────────
def decode_output(data: bytes) -> str:
    """把外部命令（sc / schtasks / netstat…）吐出来的字节转成文字。

    先按 UTF-8 解，失败再按 GBK —— 中文系统的命令输出是本地化代码页，
    而同一台机器上不同命令吐的编码未必一致，两条都要留。最后「替换非法字节」兜底，
    保证一定拿得到字符串（拿不到的话，连错误信息都没人能读）。

    ⚠️ **别信命令返回内容里的编码声明**：`schtasks /query /xml` 每块 XML 都写着
    `encoding="UTF-16"`，那是**假声明**（实测是 UTF-8），按它解码只会得到一堆乱码。
    """
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


# ── 管理员权限探测 ──────────────────────────────────────────────────────
def is_admin() -> bool:
    """当前进程是否以管理员身份运行。

    需要管理员的能力（服务启停、写系统级环境变量…）在动手前先问这一句：
    不是管理员就直接给人话说明，而不是把系统报错原样丢给调用方。
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 注册表类型名 ────────────────────────────────────────────────────────
# winreg 的数值类型 → 可读类型名（不把裸数字交给模型）。
WINREG_TYPE_NAMES = {
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
    winreg.REG_NONE: "REG_NONE",
}


def winreg_type_name(typ) -> str:
    """winreg 类型常量 → 可读名。不认识的类型原样给数字（不猜）。"""
    return WINREG_TYPE_NAMES.get(typ, str(typ))


# ── 服务启动类型 ────────────────────────────────────────────────────────
# sc qc 的 START_TYPE 数字 → 类型名（不返回本地化文本）。
SERVICE_START_TYPES = {0: "BOOT_START", 1: "SYSTEM_START", 2: "AUTO_START",
                       3: "DEMAND_START", 4: "DISABLED"}


# ── 计划任务 XML ────────────────────────────────────────────────────────
# 任务定义的 XML 命名空间（schtasks /query /xml 每一块 Task 都用它）。
TASK_XML_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
# 「开机 / 登录就触发」的两种触发器 —— 判断一个任务算不算自启动，就看它有没有这两个。
BOOT_LOGON_TRIGGERS = frozenset({"BootTrigger", "LogonTrigger"})


def xml_text(node, path: str) -> str:
    """按 `A/B` 相对路径取 XML 文本（路径段自动补命名空间前缀），取不到返回空串。

    例：`xml_text(root, "RegistrationInfo/URI")` 取任务的完整路径名。
    路径按 `/` 分段、逐段往下找，比每次手写完整前缀写法更不容易出错。
    """
    cur = node
    for seg in path.split("/"):
        if cur is None:
            return ""
        cur = cur.find("t:" + seg, TASK_XML_NS)
    return (cur.text or "").strip() if cur is not None else ""


def xml_children(node, path: str = "") -> list:
    """取子元素列表（path 为空就取 node 自己的直接子元素）。取不到返回空列表。"""
    cur = node
    if path:
        for seg in path.split("/"):
            if cur is None:
                return []
            cur = cur.find("t:" + seg, TASK_XML_NS)
    return list(cur) if cur is not None else []


# ── 路径安全地基 ────────────────────────────────────────────────────────
# 所有会碰文件系统的原语共用的前置判定：路径先规范化，再判它是不是落在系统禁区里。
#
# ⚠️ **为什么必须是共用的一份**：这份判定原先在文件域、归档域、快捷方式域**各抄了一遍**
# （2026-09-11 下沉到这里）。三份拷贝的代价不是多打几个字，是**改一处忘了另两处就会
# 行为分叉** —— 而这是安全判定，分叉意味着有人能从一个域绕过去。
#
# ⚠️ **为什么必须「先规范化再判」**：只看字面量的话，靠 `..` 往上爬、8.3 短名、
# 长路径前缀、软链接/junction，四路都能把路径伪装成「看起来不在禁区里」。

SYSTEM_ROOTS = [os.environ.get("SystemRoot") or r"C:\Windows",
                os.environ.get("ProgramFiles") or r"C:\Program Files",
                os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
                os.environ.get("ProgramData") or r"C:\ProgramData"]


def normalize_path(path: str) -> str:
    """把路径整理干净：展开 %环境变量% / ~ → 绝对化 → 解析 `..` 与软链接 / junction。
    Windows 下顺带去掉长路径前缀。返回规范化后的绝对路径字符串。
    路径为空则抛 `ValueError`；其余异常回退到绝对路径（宁可给出可比较的路径，也不炸）。
    """
    if path is None or not str(path).strip():
        raise ValueError("路径不能为空")
    p = os.path.expandvars(os.path.expanduser(str(path).strip()))
    if p.startswith("\\\\?\\"):            # 长路径前缀 → 普通路径
        p = p[4:]
    p = p.replace("/", os.sep)
    p = os.path.abspath(p)
    try:
        p = os.path.realpath(p)            # 解析软链接 / junction：防「链接逃逸」
    except OSError:
        pass
    return os.path.normpath(p)


def is_within(path: str, roots: list[str]) -> bool:
    """path 是否落在 roots 里某个根目录**之内**（含子目录）。

    按目录边界比对，不会把 `C:\\ab` 误判成在 `C:\\a` 之内。roots 为空 → False（fail-closed）。
    """
    if not roots:
        return False
    target = os.path.normcase(normalize_path(path))
    for r in roots:
        try:
            root = os.path.normcase(normalize_path(r)).rstrip("\\/")
        except ValueError:
            continue
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def check_path(path: str, roots: list[str] | None = None) -> dict:
    """路径体检：规范化 + 穿越手法检测 + 是否落在允许根目录内。

    返回 `{"input","normalized","changed","traversal","link_resolved","inside_allowed",...}`：
      · `changed`        原始写法被改写过（字面 ≠ 规范化结果）
      · `traversal`      原始写法里出现了明显的穿越手法（`..` 段 / `%变量%` / `~` 家目录）
      · `link_resolved`  规范化时软链接 / junction 被解析，且落点与字面路径不同（可能是链接逃逸）
      · `inside_allowed` roots 为空时**恒为 True**（语义是「没给白名单就不判」）——
        调用方要 fail-closed 的话得自己再拦一道，别把它当「检查通过」。
    """
    raw = str(path or "")
    out = {"input": raw, "normalized": None, "changed": False, "traversal": False,
           "link_resolved": False, "inside_allowed": True,
           "allowed_roots": list(roots) if roots else None}
    try:
        norm = normalize_path(raw)
    except ValueError as e:
        out["note"] = str(e)
        out["inside_allowed"] = False
        return out
    out["normalized"] = norm
    # 穿越手法：字面量层面就能看出来的（.. 段 / 环境变量 / ~ 家目录）
    segs = [s for s in re.split(r"[\\/]+", raw) if s]
    out["traversal"] = (".." in segs) or ("%" in raw) or raw.strip().startswith("~")
    # 链接逃逸：字面绝对路径 vs 解析后的真实路径
    literal = os.path.normpath(os.path.abspath(os.path.expandvars(os.path.expanduser(raw))))
    out["link_resolved"] = os.path.normcase(literal) != os.path.normcase(norm)
    out["changed"] = out["traversal"] or out["link_resolved"] or raw != norm
    if roots:
        out["inside_allowed"] = is_within(norm, roots)
    return out


def system_zone_reason(norm: str, verb: str = "操作") -> str | None:
    """这个落点是不是系统禁区。返回中文理由，允许则 None。

    只拦盘根 + 系统目录（Windows / Program Files / ProgramData）——
    不拦家目录、不拦用户的工作盘。**删/改类动作可能想要更严的规则**，
    那是在这一层之上再加的，不塞进来。

    ⚠️ **源和目标都要判**：只判一侧等于没判（能往系统目录里塞东西、或从系统目录往外搬）。
    """
    if len(norm) <= 3 and norm[1:2] == ":":          # C:\ 这种盘根
        return f"盘根目录（整个分区）不允许{verb}"
    if is_within(norm, SYSTEM_ROOTS):
        return f"系统目录（Windows / Program Files / ProgramData）不允许{verb}"
    return None


def is_reparse_point(p: str) -> bool:
    """这个路径是不是重解析点（符号链接 / junction / 挂载点）。

    ⚠️ **必须有这个判定，`os.path.islink()` 顶不住**：实测（2026-09-11），
    junction 的 `islink()` 是 **False**，而 `os.walk(followlinks=False)` 也**不会**
    把它当链接跳过 —— 于是它被当普通目录递归进去。一个指回祖先的 junction
    能让遍历绕圈：轻则结果重复（同一个文件被数两遍），重则转到撞上文件数上限。

    **凡是遍历目录树的地方（数大小、复制、删除、打包、搜内容），都要拿它剪枝。**
    """
    try:
        return bool(os.lstat(p).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, AttributeError):
        return False


# ── 进程令牌特权 ────────────────────────────────────────────────────────
# 有些系统操作要求当前进程的令牌里带着特定特权 —— 关机要 SeShutdownPrivilege、
# 改时区要 SeTimeZonePrivilege。**动手前先查一下**，没有就给人话说明，
# 而不是把系统的「拒绝访问」原样丢给调用方。
#
# 为什么放在共享层：这份代码原先只住在电源域，时区域想用它就得再抄一遍 ——
# 而「不能 import 另一个域文件」这条约束让抄写成了唯一出路。跨域需求就该沉到这儿。
_TOKEN_QUERY = 0x0008
_TOKEN_PRIVILEGES_CLASS = 3

class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]


def token_privileges() -> set[str]:
    """枚举当前进程令牌里的特权名集合（如 {'SeShutdownPrivilege', ...}）。
    失败返回空集合（调用方按「探测不到」处理，不要当成「没有权限」的反面）。"""
    adv = ctypes.windll.advapi32
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.LookupPrivilegeNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_LUID),
                                         ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)]
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        return set()
    try:
        size = wintypes.DWORD(0)
        adv.GetTokenInformation(token, _TOKEN_PRIVILEGES_CLASS, None, 0, ctypes.byref(size))
        if not size.value:
            return set()
        buf = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, _TOKEN_PRIVILEGES_CLASS, buf, size.value,
                                       ctypes.byref(size)):
            return set()
        count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
        arr = (_LUID_AND_ATTRIBUTES * count).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))
        names: set[str] = set()
        for i in range(count):
            sb = ctypes.create_unicode_buffer(256)
            ln = wintypes.DWORD(256)
            if adv.LookupPrivilegeNameW(None, ctypes.byref(arr[i].Luid), sb, ctypes.byref(ln)):
                names.add(sb.value)
        return names
    except Exception:
        return set()
    finally:
        k.CloseHandle(token)


# ── 进程 DPI 感知 ───────────────────────────────────────────────────────
_dpi_done = False


def set_dpi_aware() -> None:
    """尽量让本进程按「每屏 DPI 感知」工作，只试一次。

    ⚠️ 不设的话，高分屏上拿到的是**被系统缩放过的逻辑坐标** —— 显示器位置、截图区域
    全会偏，而且偏得不明显（125% 缩放下 1920 变成 1536，看着像个正常数字，很难发现）。
    已经被宿主设过（manifest / 早先调用）时这个调用会失败，属正常，忽略即可。
    """
    global _dpi_done
    if _dpi_done:
        return
    _dpi_done = True
    try:
        u = ctypes.windll.user32
        fn = u.SetProcessDpiAwarenessContext
        fn.argtypes = [ctypes.c_void_p]
        fn.restype = wintypes.BOOL
        fn(ctypes.c_void_p(-4))          # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()   # 老系统的退路
        except Exception:
            pass
