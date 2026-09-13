"""交互域原语 —— 剪贴板 / 窗口 / 截屏 / 键盘输入 / 通知（ui.*）。

⚠️ **既有的两条剪贴板原语依赖 pywin32（win32clipboard）**。
交互域（剪贴板）没有可靠的跨平台 / 零第三方实现（要自己手搓 OpenClipboard /
GlobalAlloc / SetClipboardData 一整套内存所有权转移），按项目约定「交互域允许用已装的
pywin32」走这条路。本机 win32clipboard 实测可导入。
**本批新增的窗口 / 截屏 / 键盘输入 / 通知五条一律零依赖**（ctypes 调 user32 / gdi32，
通知走系统自带的 PowerShell）—— 既有那两条按原样不动，新代码不再扩大 pywin32 的依赖面。

**本域的安全重点是「打扰用户」而不是「毁数据」**，分级如下：
  · `ui.clipboard_get` / `ui.window_list` / 显示域全部 —— 只读，无 dry_run
  · `ui.window_activate` —— 会**抢焦点**（低危但会打断用户）→ 默认 dry_run=True
  · `ui.window_control` —— 含「关闭」（会丢未保存数据）→ **按最危险的那个定级**：
    默认 dry_run=True + requires_confirmation
  · `ui.screenshot` —— ⚠️ **隐私**（可能截到密码 / 聊天窗口）→ 默认 dry_run=True
  · `ui.type_text` —— ⚠️ **本域最高危**：模拟键盘 = 替用户打字 → 默认 dry_run=True +
    requires_confirmation；**只做纯文本**，不做组合键 / 快捷键 / 鼠标（那是另一类能力）
  · `ui.notify` —— 低危、不改变任何状态、不留痕，只是打扰一下 → **不做 dry_run、不需确认**

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_ui，注册进 factory.registry）。
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wintypes
import os
import struct
import subprocess
import time
import zlib

from core.factory import declare_primitive  # type: ignore
from primitives._common import set_dpi_aware, normalize_path, system_zone_reason

_OPEN_RETRIES = 10      # 剪贴板是全局独占资源，别的程序正开着时要重试
_OPEN_WAIT = 0.05


def _module():
    """返回 (win32clipboard 模块, 错误说明)。"""
    try:
        import win32clipboard  # pywin32
        return win32clipboard, None
    except Exception as e:
        return None, (f"需要 pywin32 的 win32clipboard 子模块（当前导入失败：{e}）；"
                      f"装法：pip install pywin32")


def _open(cb) -> bool:
    """带重试地打开剪贴板（被别的程序占用时 OpenClipboard 会失败）。"""
    for _ in range(_OPEN_RETRIES):
        try:
            cb.OpenClipboard()
            return True
        except Exception:
            time.sleep(_OPEN_WAIT)
    return False


@declare_primitive(
    "ui.clipboard_get",
    "读剪贴板里的**文本**（纯文本）。让 AI 能接住用户刚复制的内容。"
    "什么时候用：用户说「我刚复制的那段」「看一下剪贴板」时；或要把用户复制的内容交给别的原语处理前先取出来。"
    "什么时候别用：要把内容**写进**剪贴板请用 ui.clipboard_set —— 方向相反，两条是配对的。"
    "参数怎么填：无参数，直接调用。"
    "返回什么：text 是文本内容（没有文本时为 null）、length 是字符数、has_text 说明剪贴板里有没有文本、"
    "ok 表示这次读取**本身**跑成功了没有、note 是中文说明（读失败的原因都在这里）。"
    "⚠️ 陷阱与易混："
    "① 只认文本 —— 剪贴板里是图片 / 文件 / 空的时候 has_text=false、text=null，那不是出错；"
    "② ⚠️ **隐私**：剪贴板里可能有密码 / 验证码等敏感信息，读出来的内容别随口复述、别写进日志；"
    "③ 剪贴板是全局独占资源，别的程序正开着时可能读不到（note 会说「被占用」，可稍后重试）；"
    "④ 与 ui.clipboard_set（写剪贴板）配对，方向相反：读用本条，写用那条，别拿本条去改剪贴板。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"length": "字符数"},
    block="display_ui",
)
def ui_clipboard_get() -> dict:
    # ok = 「这次读取本身跑成功了没有」（与 display.brightness 的口径一致）：
    # 「剪贴板里没有文本」是读取成功、只是没有内容 → ok=True；读不了（占用 / 导入失败 / 异常）→ ok=False
    cb, err = _module()
    if err:
        return {"ok": False, "text": None, "length": 0, "has_text": False, "note": err}
    if not _open(cb):
        return {"ok": False, "text": None, "length": 0, "has_text": False,
                "note": "剪贴板被其他程序占用，打不开（不是没有内容，可稍后重试）"}
    try:
        if not cb.IsClipboardFormatAvailable(cb.CF_UNICODETEXT):
            return {"ok": True, "text": None, "length": 0, "has_text": False,
                    "note": "剪贴板里没有文本（可能是图片/文件，或为空）"}
        text = cb.GetClipboardData(cb.CF_UNICODETEXT)
        return {"ok": True, "text": text, "length": len(text), "has_text": True,
                "note": f"读到 {len(text)} 个字符的文本"}
    except Exception as e:
        return {"ok": False, "text": None, "length": 0, "has_text": False, "note": f"读剪贴板失败：{e}"}
    finally:
        try:
            cb.CloseClipboard()
        except Exception:
            pass


@declare_primitive(
    "ui.clipboard_set",
    "把文本写进剪贴板（把 AI 生成的内容交给用户的最省事途径：用户随手 Ctrl+V 就能用）。"
    "什么时候用：生成了一段要交给用户的**纯文本**（代码片段、命令、长文），希望用户直接粘贴；"
    "或先用 ui.window_activate 把目标窗口切到前台，再让用户自己粘贴。"
    "什么时候别用：只是要**读**剪贴板内容请用 ui.clipboard_get —— 方向相反，两条是配对的。"
    "⚠️ **需用户确认**（写剪贴板会覆盖用户原有内容、不可逆 —— 与同库所有「覆盖」操作同一道门）。"
    "参数怎么填：text 给要写入的文本（必填）。"
    "返回什么：ok 表示**是否真的写进去了**（预览时一定是 false）、length 是字符数、"
    "note 是中文说明（写失败的原因都在这里）；dry_run=True 的预览还会多给 dry_run 与 preview（前 100 字符）。"
    "⚠️ 陷阱与易混："
    "① ⚠️ **写入会覆盖用户原来复制的东西，不可撤销**（原内容找不回来）—— 这条**不是零副作用的**，"
    "所谓「零副作用」只指不落盘、不改文件；写之前最好让用户知道剪贴板会被替换（原生内容会被丢弃）；"
    "② 只支持**纯文本** —— 图片、文件（资源管理器里复制的文件）写不进去；"
    "③ 剪贴板是全局独占资源，别的程序正开着时会写不进去（note 会说「被占用」，可重试）；"
    "④ 与 ui.clipboard_get（读剪贴板）配对：写用本条，读用那条。",
    {"type": "object",
     "properties": {
         "text": {"type": "string", "description": "要写入剪贴板的文本"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不写剪贴板（默认）；False=真写入"},
     },
     "required": ["text"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"length": "字符数"},
    block="display_ui",
)
def ui_clipboard_set(text: str, dry_run: bool = True) -> dict:
    payload = "" if text is None else str(text)
    # ⚠️ 安全铁律：默认只预览。写剪贴板会覆盖用户原有内容（不可撤销）。
    if dry_run:
        return {"ok": False, "length": len(payload), "dry_run": True,
                "preview": payload[:100] + ("…" if len(payload) > 100 else ""),
                "note": f"只读预览：未写入剪贴板。真执行将用这 {len(payload)} 个字符"
                        f"覆盖当前剪贴板内容，需显式传 dry_run=False"}
    cb, err = _module()
    if err:
        return {"ok": False, "length": 0, "note": err}
    if not _open(cb):
        return {"ok": False, "length": 0,
                "note": "剪贴板被其他程序占用，打不开（可稍后重试）"}
    try:
        cb.EmptyClipboard()
        cb.SetClipboardText(payload, cb.CF_UNICODETEXT)
        return {"ok": True, "length": len(payload),
                "note": "已写入剪贴板（覆盖了原有内容）"}
    except Exception as e:
        return {"ok": False, "length": 0, "note": f"写剪贴板失败：{e}"}
    finally:
        try:
            cb.CloseClipboard()
        except Exception:
            pass


# ============================================================================
# 窗口 —— ui.window_list / ui.window_activate / ui.window_control
# ============================================================================
# **为什么新加的这几条走 ctypes 而不是 pywin32**：窗口能力只需要 EnumWindows 加几个
# 一问一答的查询，ctypes 十几行就够 —— 而且这样即使哪台机器上 pywin32 装不上，
# 窗口 / 截屏 / 输入 / 通知这些能力照样能用。既有那两条剪贴板原语仍按原样依赖 pywin32。
#
# ⚠️ **一个必踩的坑：句柄别当 32 位整数**。ctypes 不设 `restype = wintypes.HANDLE` 时，
# x64 上返回的句柄会被**截断成 int32**，于是「明明枚举到了却打不开」。本文件里所有
# 返回句柄的调用都显式声明了 restype。
_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.GetWindowThreadProcessId.restype = wintypes.DWORD
_user32.GetForegroundWindow.restype = wintypes.HWND
_user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
_user32.GetWindowTextLengthW.restype = ctypes.c_int
_user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
_user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
_user32.IsWindowVisible.argtypes = [wintypes.HWND]
_user32.IsWindowVisible.restype = wintypes.BOOL
_user32.IsWindow.argtypes = [wintypes.HWND]
_user32.IsWindow.restype = wintypes.BOOL
_user32.IsIconic.argtypes = [wintypes.HWND]
_user32.IsIconic.restype = wintypes.BOOL
_user32.IsZoomed.argtypes = [wintypes.HWND]
_user32.IsZoomed.restype = wintypes.BOOL
_user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.c_void_p]
_user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
_user32.ShowWindow.restype = wintypes.BOOL
_user32.SetForegroundWindow.argtypes = [wintypes.HWND]
_user32.SetForegroundWindow.restype = wintypes.BOOL
_user32.BringWindowToTop.argtypes = [wintypes.HWND]
_user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.GetCurrentThreadId.restype = wintypes.DWORD

_SW_MINIMIZE, _SW_MAXIMIZE, _SW_RESTORE = 6, 3, 9
_WM_CLOSE = 0x0010
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_DWMWA_CLOAKED = 14
_MAX_WINDOW_SCAN = 1000          # 枚举上限：有人开几百个窗口时不至于卡死

# 动作 → 中文（提示语里说人话，别把 minimize 直接塞进中文句子）
_ACTION_CN = {"minimize": "最小化", "maximize": "最大化",
              "restore": "还原", "close": "关闭"}

# 桌面外壳自己的窗口：有标题，但把它当「用户开的窗口」列出来纯属噪声
_SHELL_CLASSES = frozenset({"Progman", "WorkerW", "Shell_TrayWnd",
                            "Shell_SecondaryTrayWnd", "Windows.UI.Core.CoreWindow"})


class _RECT(ctypes.Structure):
    _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG)]


_EnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _exe_name(pid: int) -> str:
    """PID → 可执行文件名（如 `chrome.exe`）。取不到返回空串。

    取不到是**常态不是错误**：受保护进程 / 别的用户的进程会拒绝
    `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`，这时返回空串而不是抛错。
    """
    if not pid:
        return ""
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(32768)
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value) or buf.value
        return ""
    except Exception:
        return ""
    finally:
        _kernel32.CloseHandle(handle)


def _pid_of(hwnd) -> int:
    """窗口句柄 → 所属进程 PID（0 表示取不到）。"""
    pid = wintypes.DWORD(0)
    _user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid))
    return int(pid.value)


def _window_text(hwnd) -> str:
    """窗口标题（无标题返回空串）。"""
    n = _user32.GetWindowTextLengthW(wintypes.HWND(hwnd))
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    _user32.GetWindowTextW(wintypes.HWND(hwnd), buf, n + 1)
    return buf.value


def _class_name(hwnd) -> str:
    """窗口类名（`CabinetWClass` / `Chrome_WidgetWin_1` 之类）。"""
    buf = ctypes.create_unicode_buffer(256)
    _user32.GetClassNameW(wintypes.HWND(hwnd), buf, 256)
    return buf.value


_dwm_ready = False


def _is_cloaked(hwnd) -> bool:
    """UWP 的「幽灵窗口」判定。

    ⚠️ 只有 `IsWindowVisible()` 是不够的：一个 UWP 应用会在桌面上留下好几个
    「可见但根本看不见」的宿主窗口（后台/切换器用），DWM 才知道它们是 cloaked 的。
    不认这一层，窗口列表里就会冒出一堆同名的空壳。

    取不到（老系统没有 dwmapi）时返回 False —— 宁可多列几个，也不要凭空把真窗口滤掉。
    """
    global _dwm_ready
    try:
        dwm = ctypes.windll.dwmapi
        if not _dwm_ready:
            dwm.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD,
                                                  ctypes.c_void_p, wintypes.DWORD]
            dwm.DwmGetWindowAttribute.restype = ctypes.c_long
            _dwm_ready = True
        val = wintypes.DWORD(0)
        rc = dwm.DwmGetWindowAttribute(wintypes.HWND(hwnd), _DWMWA_CLOAKED,
                                       ctypes.byref(val), ctypes.sizeof(val))
        return rc == 0 and bool(val.value)
    except Exception:
        return False


def _window_entry(hwnd, names: dict) -> dict:
    """把一个句柄的当前状态读成一条记录（只读，不碰窗口）。"""
    pid = _pid_of(hwnd)
    if pid not in names:
        names[pid] = _exe_name(pid)
    r = _RECT()
    _user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(r))
    return {"hwnd": int(hwnd),
            "title": _window_text(hwnd),
            "pid": pid,
            "process": names.get(pid) or None,
            "class_name": _class_name(hwnd),
            "visible": bool(_user32.IsWindowVisible(wintypes.HWND(hwnd))),
            "cloaked": _is_cloaked(hwnd),
            "minimized": bool(_user32.IsIconic(wintypes.HWND(hwnd))),
            "maximized": bool(_user32.IsZoomed(wintypes.HWND(hwnd))),
            "foreground": _user32.GetForegroundWindow() == hwnd,
            "rect": {"left": r.left, "top": r.top, "width": r.right - r.left,
                     "height": r.bottom - r.top}}


def _enum_windows(include_hidden: bool = False,
                  include_untitled: bool = False) -> tuple:
    """枚举顶层窗口。返回 (记录列表, 是否被上限截断)。

    `EnumWindows` 是**按 z 序**回调的（最前 / 最上面的先出来），所以结果的天然顺序就是
    「越靠前越显眼」，不再额外排序。
    """
    out: list = []
    names: dict = {}                 # pid → exe 名：同一次枚举里一个进程只查一次
    stopped = False

    def _cb(hwnd, _lparam):
        nonlocal stopped
        if len(out) >= _MAX_WINDOW_SCAN:
            stopped = True
            return False             # 返回 False = 停止枚举
        cls = _class_name(hwnd)
        if cls in _SHELL_CLASSES:
            return True
        title = _window_text(hwnd)
        if not title and not include_untitled:
            return True              # 默认只列有标题的（无标题的绝大多数是辅助窗口）
        visible = bool(_user32.IsWindowVisible(wintypes.HWND(hwnd)))
        if not include_hidden and (not visible or _is_cloaked(hwnd)):
            return True
        out.append(_window_entry(hwnd, names))
        return True

    try:
        _user32.EnumWindows(_EnumProc(_cb), 0)
    except Exception:
        pass
    return out, stopped


def _resolve_window(hwnd: int = 0, title: str = "") -> tuple:
    """把「hwnd 或标题关键词」定位成一个具体窗口。返回 (hwnd, 记录, 错误说明)。

    优先用 hwnd（精确、无歧义）；只给 title 时取**第一个**匹配的可见顶层窗口，
    并把候选数一并报出来 —— 只给标题就有打错窗口的可能，这一点必须让调用方看见。
    """
    if hwnd:
        try:
            h = int(hwnd)
        except (TypeError, ValueError):
            return 0, {}, f"hwnd 不是整数：{hwnd!r}"
        if not _user32.IsWindow(wintypes.HWND(h)):
            return 0, {}, f"窗口句柄 {h} 无效（窗口可能已经关了；句柄会失效，请重新用 ui.window_list 取）"
        return h, _window_entry(h, {}), ""
    kw = (title or "").strip().lower()
    if not kw:
        return 0, {}, "必须给 hwnd 或 title 之一来指定窗口（hwnd 从 ui.window_list 取）"
    entries, _ = _enum_windows(include_hidden=False, include_untitled=False)
    hits = [e for e in entries if kw in (e["title"] or "").lower()]
    if not hits:
        return 0, {}, (f"没有标题含 {title!r} 的可见窗口。"
                       f"先用 ui.window_list 看看现在有哪些窗口（可能它被最小化到托盘 / 标题对不上）")
    hits[0]["matched_count"] = len(hits)
    return hits[0]["hwnd"], hits[0], ""


@declare_primitive(
    "ui.window_list",
    "看当前开了哪些窗口：标题 / 所属进程 / 是否可见 / 是否最小化·最大化 / 窗口位置，"
    "以及哪个是当前前台窗口。"
    "**拿到 hwnd 是后续一切窗口操作的前提** —— ui.window_activate / ui.window_control 都吃这个句柄。"
    "可按标题关键词（title_keyword）与进程名（process，如 `chrome.exe`）过滤，并用 limit 限条数。"
    "⚠️ 默认**只列「有标题的、可见的顶层窗口」**：系统里还有成堆无标题的辅助窗口和 UWP 的"
    "「幽灵窗口」（API 说可见、实际看不见），默认都滤掉；确需看它们请传 include_hidden / "
    "include_untitled。默认排序是**z 序**（最前面的先出），不是字母序。"
    "返回什么：windows 是窗口列表，每项 {hwnd, title, pid, process, class_name, visible, cloaked,"
    " minimized, maximized, foreground, rect}；另有 count（本次返回条数）、matched_total（过滤后匹配数）、"
    "total_toplevel（顶层窗口总数）、truncated（是否被 limit 截断）、foreground（当前前台窗口）与 note。"
    "⚠️ 陷阱与易混："
    "① 三条窗口原语的分工：本原语只**看**（拿 hwnd、看谁被最小化了）——"
    "要把窗口**切到前台并还给键盘焦点**用 ui.window_activate；要**最小化 / 最大化 / 还原 / 关闭**用 "
    "ui.window_control（它的 action=restore 也能还原最小化窗口，但抢不到焦点）；"
    "② 句柄会失效：窗口关掉之后旧 hwnd 就没用了，要重新 list 一次。",
    {"type": "object",
     "properties": {
         "title_keyword": {"type": "string",
                           "description": "按标题过滤（不区分大小写的子串匹配，如 `chrome`）"},
         "process": {"type": "string",
                     "description": "按进程名过滤（不区分大小写的子串匹配，如 `chrome.exe` 或 `chrome`）"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "最多返回多少条（默认 50，上限 500）—— 窗口可能有上百个，别一次全吐"},
         "include_hidden": {"type": "boolean",
                            "description": "是否连不可见的（含 UWP 幽灵窗口）一起列，默认 False"},
         "include_untitled": {"type": "boolean",
                              "description": "是否连没有标题的窗口一起列，默认 False"},
     },
     "required": [], "additionalProperties": False},
    state={"count": "窗口数"},        # 只放标量：面板的状态表是由值直接渲染的，塞 dict 不好看
    block="display_ui",
)
def ui_window_list(title_keyword: str = "", process: str = "", limit: int = 50,
                   include_hidden: bool = False, include_untitled: bool = False) -> dict:
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 50
    entries, scan_truncated = _enum_windows(bool(include_hidden), bool(include_untitled))

    kw = (title_keyword or "").strip().lower()
    pn = (process or "").strip().lower()
    matched = [e for e in entries
               if (not kw or kw in (e["title"] or "").lower())
               and (not pn or pn in (e["process"] or "").lower())]

    shown = matched[:limit]
    truncated = len(matched) > len(shown)
    fg = next((e for e in entries if e["foreground"]), None)
    return {"ok": True, "count": len(shown), "matched_total": len(matched),
            "total_toplevel": len(entries), "truncated": truncated,
            "filtered": bool(kw or pn),
            "foreground": {"hwnd": fg["hwnd"], "title": fg["title"],
                           "process": fg["process"]} if fg else None,
            "windows": shown,
            "note": (f"匹配 {len(matched)} 个窗口，返回 {len(shown)} 个"
                     + ("（已被 limit 截断，调大 limit 或收紧过滤条件）" if truncated else "")
                     + f"；顶层窗口共 {len(entries)} 个"
                     + ("；⚠️ 枚举达到上限，可能还有更多" if scan_truncated else "")
                     + ("" if matched else "；没有匹配的窗口（默认只列可见且有标题的）"))}


@declare_primitive(
    "ui.window_activate",
    "把某个窗口调到最前面并给它键盘焦点（先还原最小化的，再强行置顶）。"
    "目标用 hwnd（推荐，从 ui.window_list 拿）或 title（标题关键词，取第一个匹配的）。"
    "⚠️ **hwnd 与 title 至少要给一个** —— 两个都不给会直接失败返回（这条约束 JSON Schema 表达不了，"
    "所以写在描述里：**别两个都不传**）。"
    "什么时候用：要让**用户立刻看到**某个窗口（把结果窗口 / 报错窗口带到前台，或给 ui.type_text 备好焦点）。"
    "什么时候别用：只做最小化 / 最大化 / 关闭用 ui.window_control；只想看开了哪些窗口、拿 hwnd 用 ui.window_list。"
    "⚠️ **会抢用户焦点** —— 用户正在别处打字时会被硬生生打断，这是「低危但打扰」的动作，"
    "所以默认 dry_run=True 只报告「将会激活哪个窗口」。"
    "三条窗口原语都能对付「最小化窗口」：本原语是**唯一**会顺手把键盘焦点交给它的那条"
    "（ui.window_control 的 action=restore 只还原、不抢焦点）——要用户马上开始打字就用本条。"
    "返回什么：activated 是「调用是否成功」、verified 是**读回的前台窗口是否真的变成了它**、"
    "hwnd / title / process 是作用于哪个窗口、was_minimized 是此前是否最小化、"
    "foreground_after / state_after 是复核读回的状态、dry_run 标明这次是否只是预览、note 是中文说明："
    "Windows 对抢焦点有限制（前台锁定），失败时不一定报错，只能靠读回复核 —— activated 与 verified "
    "不一致时如实标出，不要当成成功（抢焦点被拦时可用 ui.notify 提醒用户自己切过去）。",
    {"type": "object",
     "properties": {
         "hwnd": {"type": "integer", "description": "窗口句柄（从 ui.window_list 拿，推荐）"},
         "title": {"type": "string",
                   "description": "标题关键词（hwnd 没给时用，取第一个匹配的可见窗口）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只报告将激活哪个窗口、不动焦点（默认）；False=真激活"},
     },
     "required": [], "additionalProperties": False},
    state={"activated": "已激活"},
    block="display_ui",
)
def ui_window_activate(hwnd: int = 0, title: str = "", dry_run: bool = True) -> dict:
    h, entry, err = _resolve_window(hwnd, title)
    if err:
        return {"ok": False, "activated": False, "verified": None, "hwnd": 0, "note": err}
    out = {"ok": False, "activated": False, "verified": None, "hwnd": h,
           "title": entry.get("title", ""), "process": entry.get("process"),
           "was_minimized": entry.get("minimized"), "dry_run": bool(dry_run)}
    # 只给标题就可能选错窗口：匹配到多个时如实标出「我挑的是哪一个」
    ambiguous = ""
    if entry.get("matched_count", 0) > 1:
        out["title_matched"] = entry["matched_count"]
        ambiguous = (f"；⚠️ 标题 {title!r} 匹配到 {entry['matched_count']} 个窗口，"
                     f"本次作用于最前面的那一个（要精确请改用 hwnd）")
    # ⚠️ 安全：抢焦点会打断用户（本批「会打扰但不破坏」的一条），默认只预览
    if dry_run:
        out.update({"would_activate": f"[{h}] {entry.get('title', '')}"
                                     f"（{entry.get('process') or '进程未知'}）",
                    "note": "只读预览：未改变焦点。真执行会把这个窗口还原并置顶、"
                            "把键盘焦点交给它 —— 用户正在别处打字会被打断，"
                            "需显式传 dry_run=False" + ambiguous})
        return out

    if entry.get("minimized"):
        _user32.ShowWindow(wintypes.HWND(h), _SW_RESTORE)
    ok = bool(_user32.SetForegroundWindow(wintypes.HWND(h)))
    if _user32.GetForegroundWindow() != h:
        # 系统只让「当前前台进程」抢焦点。AttachThreadInput 把本线程与前台线程的输入队列
        # 临时接到一起，就能绕过这条限制（通行做法；**不模拟按键**，那是另一类能力）。
        fg = _user32.GetForegroundWindow() or 0
        tid_fg = _user32.GetWindowThreadProcessId(wintypes.HWND(fg), None) if fg else 0
        tid_me = _kernel32.GetCurrentThreadId()
        attached = False
        try:
            if tid_fg:
                attached = bool(_user32.AttachThreadInput(tid_me, tid_fg, True))
            _user32.BringWindowToTop(wintypes.HWND(h))
            _user32.SetForegroundWindow(wintypes.HWND(h))
        except Exception:
            pass
        finally:
            if attached:
                try:
                    _user32.AttachThreadInput(tid_me, tid_fg, False)
                except Exception:
                    pass
    after = _user32.GetForegroundWindow()
    verified = after == h
    out.update({"activated": bool(ok), "verified": verified,
                "foreground_after": {"hwnd": int(after or 0),
                                     "title": _window_text(after) if after else ""},
                "state_after": {"minimized": bool(_user32.IsIconic(wintypes.HWND(h)))}})
    if verified:
        out["ok"] = True
        out["note"] = f"已激活 [{h}] {entry.get('title', '')}" + ambiguous
    elif not _user32.IsWindow(wintypes.HWND(h)):
        out["note"] = f"窗口 {h} 在激活过程中消失了（可能被关闭）"
    else:
        out["note"] = (f"调用返回 {'成功' if ok else '失败'}，但**读回的前台窗口不是它**"
                       f"（现在是 [{int(after or 0)}] {_window_text(after) if after else ''}）——"
                       f"系统前台锁定拦住了这次抢焦点。可稍后重试，或改用 ui.notify 提醒用户切过去"
                       + ambiguous)
    return out


@declare_primitive(
    "ui.window_control",
    "对某个窗口做最小化 / 最大化 / 还原 / 关闭。目标用 hwnd（推荐）或 title。"
    "⚠️ **hwnd 与 title 至少要给一个** —— 两个都不给会直接失败返回（这条约束 JSON Schema 表达不了，"
    "所以写在描述里：**别两个都不传**）。"
    "什么时候用：要把某个窗口**最小化 / 最大化 / 关掉**（关掉 = 发 WM_CLOSE 请求关闭，不是强杀）。"
    "什么时候别用：想把窗口**切到前台并还给键盘焦点**用 ui.window_activate —— 本原语的 action=restore "
    "只还原最小化、**不抢焦点**；只想看窗口列表 / 拿 hwnd 用 ui.window_list。"
    "⚠️ **按最危险的那个动作定级**：close（关闭）会让程序可能丢弃未保存的数据（不可逆），"
    "所以整条默认 dry_run=True 只预览、且需要用户确认。"
    "close 发的是 **WM_CLOSE**（正常关闭）而不是强杀 —— 程序可以弹「是否保存」并原地等你处理，"
    "所以返回里 closed 可能是 false 而窗口仍在，那是**程序在等用户**，不是失败。"
    "minimize / maximize / restore 是完全可逆的，但为了口径统一也走同一个 dry_run。"
    "返回什么：action 是实际动作、closed / verified 是关闭（或状态改变）有没有被读回复核通过、"
    "hwnd / title / process / pid 是作用到的窗口、state_before / state_after 是动作前后的状态、"
    "blocked=true 表示被拒绝操作（桌面 / 任务栏这类外壳窗口）、dry_run 标明这次是否只是预览、note 是中文说明。",
    {"type": "object",
     "properties": {
         "hwnd": {"type": "integer", "description": "窗口句柄（从 ui.window_list 拿，推荐）"},
         "title": {"type": "string",
                   "description": "标题关键词（hwnd 没给时用，取第一个匹配的可见窗口）"},
         "action": {"type": "string", "enum": ["minimize", "maximize", "restore", "close"],
                    "description": "minimize=最小化 / maximize=最大化 / restore=还原 / "
                                   "close=关闭（发 WM_CLOSE，可能丢未保存数据）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不动作（默认）；False=真执行（close 需用户确认）"},
     },
     "required": ["action"], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"action": "动作", "closed": "已关闭"},
    block="display_ui",
)
def ui_window_control(action: str, hwnd: int = 0, title: str = "", dry_run: bool = True) -> dict:
    act = (action or "").strip().lower()
    if act not in ("minimize", "maximize", "restore", "close"):
        return {"ok": False, "action": act,
                "note": f"未知 action {action!r}，可选：minimize / maximize / restore / close"}
    h, entry, err = _resolve_window(hwnd, title)
    if err:
        return {"ok": False, "action": act, "hwnd": 0, "note": err}
    out = {"ok": False, "action": act, "dry_run": bool(dry_run), "hwnd": h,
           "title": entry.get("title", ""), "process": entry.get("process"),
           "pid": entry.get("pid"),
           "state_before": {"minimized": entry.get("minimized"),
                            "maximized": entry.get("maximized"),
                            "visible": entry.get("visible")}}
    if entry.get("matched_count", 0) > 1:     # 只给标题就可能选错窗口，如实标出
        out["title_matched"] = entry["matched_count"]
    amb = (f"；⚠️ 标题 {title!r} 匹配到 {entry['matched_count']} 个窗口，"
           f"本次作用于最前面的那一个（要精确请改用 hwnd）"
           if entry.get("matched_count", 0) > 1 else "")

    def _done(note: str | None = None) -> dict:
        """统一出口：把「标题匹配到多个」这句一致地挂到每个分支的说明后面。"""
        if note is not None:
            out["note"] = note
        if amb:
            out["note"] = (out.get("note") or "") + amb
        return out

    # 外壳窗口（任务栏 / 桌面）不接这个操作：关掉桌面只会让用户一脸问号
    if entry.get("class_name") in _SHELL_CLASSES:
        out["blocked"] = True
        return _done(f"拒绝操作：{entry.get('class_name')} 是 Windows 桌面外壳的窗口"
                     f"（桌面 / 任务栏），不属于「某个程序的窗口」")

    # ⚠️ 安全铁律：默认只预览。close 不可逆（可能丢未保存的数据）
    if dry_run:
        if act == "close":
            out["would_do"] = (f"向 [{h}] {entry.get('title', '')}"
                               f"（{entry.get('process') or '进程未知'}）发送 WM_CLOSE")
            return _done("只读预览：未发送任何消息。真执行会**请求关闭**这个窗口 —— "
                         "目标程序可能因此丢弃未保存的数据（不可逆）。需用户确认，"
                         "并显式传 dry_run=False")
        out["would_do"] = f"对 [{h}] {entry.get('title', '')} 执行{_ACTION_CN[act]}"
        return _done(f"只读预览：未动作。真执行会把该窗口{_ACTION_CN[act]}（可逆），"
                     f"需显式传 dry_run=False")

    if act == "close":
        # PostMessage 而不是 SendMessage：不等对方处理完，避免对方卡死时把我们拖住
        if not _user32.PostMessageW(wintypes.HWND(h), _WM_CLOSE, 0, 0):
            return _done(f"发送 WM_CLOSE 失败（窗口 {h} 可能已经不存在）")
        gone = False
        for _ in range(15):              # 最多等 1.5 秒看它走没走
            time.sleep(0.1)
            if not _user32.IsWindow(wintypes.HWND(h)):
                gone = True
                break
        out.update({"ok": True, "closed": gone, "verified": gone})
        return _done(f"已向 [{h}] {entry.get('title', '')}"
                     f"（{entry.get('process') or '进程未知'}）发送 WM_CLOSE，"
                     + ("窗口已关闭" if gone else
                        "但 1.5 秒内窗口仍在 —— 大概率是**程序弹了「是否保存」在等用户处理**，"
                        "也可能它拒绝关闭。这不是失败，需要用户去看一眼那个窗口")
                     + "。⚠️ WM_CLOSE 是「请求关闭」不是强杀，程序有权不关")

    code = {"minimize": _SW_MINIMIZE, "maximize": _SW_MAXIMIZE, "restore": _SW_RESTORE}[act]
    called = bool(_user32.ShowWindow(wintypes.HWND(h), code))
    after = {"minimized": bool(_user32.IsIconic(wintypes.HWND(h))),
             "maximized": bool(_user32.IsZoomed(wintypes.HWND(h))),
             "visible": bool(_user32.IsWindowVisible(wintypes.HWND(h)))}
    # 读回校验：ShowWindow 对某些窗口会返回「上一次的状态」而不是成败，只能看结果
    expect = {"minimize": after["minimized"], "maximize": after["maximized"],
              "restore": not after["minimized"] and not after["maximized"]}[act]
    out.update({"ok": True, "state_after": after, "verified": bool(expect)})
    return _done(f"已对 [{h}] {entry.get('title', '')} 执行{_ACTION_CN[act]}"
                 f"（ShowWindow 返回 {called}）；复核："
                 + ("状态已符合预期" if expect else
                    "⚠️ 读回的状态**与预期不符**（有些窗口不接受程序化改变，"
                    "比如全屏程序 / 受保护窗口）"))


# ============================================================================
# 截屏 —— ui.screenshot
# ============================================================================
# 零依赖：全程 ctypes 调 GDI（CreateCompatibleDC / CreateDIBSection / BitBlt），
# PNG 由标准库 zlib 手工编码（PNG 的 IDAT 就是 zlib 流，几十行就够）。
#
# ⚠️ **两个关键点**：
#   · **DPI 感知必须先设**：不设的话高分屏上拿到的是被系统缩放过的逻辑坐标，
#     截出来的区域会偏（125% 缩放时 1920 变 1536），而且偏得不明显、很难发现。
#   · **alpha 通道不能信**：BitBlt 到 32 位 DIB 时不会去填 alpha（实测全是 0），
#     所以 PNG 按 **24 位真彩（色彩类型 2）** 编码、丢掉 alpha 通道 ——
#     照搬 BGRA 写成带 alpha 的 PNG，会得到一张「全透明」的图。
_CAPTUREBLT = 0x40000000          # 连分层窗口一起抓（不加会漏掉部分透明窗口）
_SRCCOPY = 0x00CC0020
_MAX_CAPTURE_PIXELS = 80_000_000  # 像素上限：4K 双屏也才 1.6 亿的一半，够用且能防住异常的巨大虚拟桌面
_PNG_SIG = b"\x89PNG\r\n\x1a\n"


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


def _virtual_screen() -> dict:
    """整个虚拟桌面（多屏加起来）的范围。"""
    return {"left": _user32.GetSystemMetrics(76), "top": _user32.GetSystemMetrics(77),
            "width": _user32.GetSystemMetrics(78), "height": _user32.GetSystemMetrics(79)}


def _capture_bgra(x: int, y: int, w: int, h: int) -> tuple:
    """从屏幕抓一块，返回 (是否成功, BGRA 字节, 错误说明)。字节是**自上而下**的。"""
    gdi = ctypes.windll.gdi32
    gdi.CreateCompatibleDC.restype = wintypes.HDC
    gdi.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi.CreateDIBSection.restype = wintypes.HBITMAP
    gdi.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
                                     ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE,
                                     wintypes.DWORD]
    gdi.SelectObject.restype = wintypes.HGDIOBJ
    gdi.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi.DeleteDC.argtypes = [wintypes.HDC]
    gdi.BitBlt.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                           ctypes.c_int, wintypes.HDC, ctypes.c_int, ctypes.c_int,
                           wintypes.DWORD]
    _user32.GetDC.restype = wintypes.HDC
    _user32.GetDC.argtypes = [wintypes.HWND]
    _user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]

    screen = _user32.GetDC(None)
    if not screen:
        return False, b"", "取不到屏幕 DC"
    mem = None
    hbmp = None
    old = None
    try:
        mem = gdi.CreateCompatibleDC(screen)
        if not mem:
            return False, b"", "创建内存 DC 失败"
        bi = _BITMAPINFO()
        bi.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        bi.bmiHeader.biWidth = w
        bi.bmiHeader.biHeight = -h          # 负高度 = 自上而下，省得再翻一次行
        bi.bmiHeader.biPlanes = 1
        bi.bmiHeader.biBitCount = 32
        bi.bmiHeader.biCompression = 0      # BI_RGB
        bits = ctypes.c_void_p()
        hbmp = gdi.CreateDIBSection(mem, ctypes.byref(bi), 0, ctypes.byref(bits), None, 0)
        if not hbmp or not bits:
            return False, b"", "创建 DIB 位图失败（尺寸可能超出显卡支持）"
        old = gdi.SelectObject(mem, hbmp)
        if not gdi.BitBlt(mem, 0, 0, w, h, screen, x, y, _SRCCOPY | _CAPTUREBLT):
            return False, b"", "BitBlt 抓图失败（区域可能不完整 / 处于安全桌面）"
        return True, ctypes.string_at(bits, w * h * 4), ""
    except Exception as e:
        return False, b"", f"抓图异常：{e}"
    finally:
        try:
            if mem and old:
                gdi.SelectObject(mem, old)
            if hbmp:
                gdi.DeleteObject(hbmp)
            if mem:
                gdi.DeleteDC(mem)
        finally:
            _user32.ReleaseDC(None, screen)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    """一个 PNG 数据块：长度 + 类型 + 数据 + CRC32（PNG 的块格式）。"""
    body = tag + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)


def _write_png(path: str, w: int, h: int, bgra: bytes) -> int:
    """BGRA 原始像素 → 24 位 PNG 文件，返回写出的字节数。

    ⚠️ BGRA→RGB 用**切片赋值**而不是逐像素循环：实测 1920x1200 下
    逐像素 0.73s、切片 0.012s（60 倍差距，结果逐字节一致）—— 这种「整行同构」的搬运
    交给 C 层做，Python 层一个像素一个像素地搬纯属自找。
    """
    rows = []
    stride = w * 4
    for y in range(h):
        seg = bgra[y * stride:(y + 1) * stride]
        rgb = bytearray(w * 3)
        rgb[0::3] = seg[2::4]                 # R（Windows 是 BGRA，PNG 要 RGB）
        rgb[1::3] = seg[1::4]                 # G
        rgb[2::3] = seg[0::4]                 # B
        rows.append(b"\x00" + bytes(rgb))     # 每行前置 filter 类型 0（None）
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)   # 8 位 / 色彩类型 2 = 真彩 RGB
    blob = (_PNG_SIG + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(b"".join(rows), 6))
            + _png_chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(blob)
    return len(blob)


@declare_primitive(
    "ui.screenshot",
    "截屏存成 PNG 文件。默认抓整个虚拟桌面（多屏一起），也可只抓一块区域。"
    "region 给 {left, top, width, height}（虚拟桌面坐标系，可用 display.monitors 的 rect 直接当 region）；"
    "不给 region 时按 all_screens 决定：True=全部屏（默认）、False=只有主屏。"
    "⚠️ **隐私**：屏幕内容可能包含密码、聊天记录、私人邮件 —— 截出来的图会**落盘**。"
    "⚠️ **需用户确认**（与 fs.write / net.download / archive.create 等所有落盘操作同一道门）："
    "默认 dry_run=True 只报告「将会截多大一块、存到哪」。"
    "零依赖实现（ctypes 调 GDI + 标准库 zlib 编码 PNG），不依赖 Pillow。"
    "返回值里 width/height 是像素尺寸、bytes 是文件大小、verified 是写完后读回文件头复核的结果。",
    {"type": "object",
     "properties": {
         "path": {"type": "string",
                  "description": "保存路径（如 D:\\\\shot.png）。不给扩展名会自动补 .png；"
                                 "目录必须已存在；不允许写进系统目录"},
         "region": {"type": "object",
                    "description": "只截这一块：{left, top, width, height}（虚拟桌面坐标）。"
                                   "不给则按 all_screens 决定",
                    "properties": {"left": {"type": "integer"}, "top": {"type": "integer"},
                                   "width": {"type": "integer"}, "height": {"type": "integer"}},
                    "additionalProperties": False},
         "all_screens": {"type": "boolean",
                         "description": "没给 region 时：True=整个虚拟桌面（默认），False=只主屏"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不截屏（默认）；False=真截"},
     },
     "required": ["path"], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"bytes": "文件字节"},
    block="display_ui",
)
def ui_screenshot(path: str, region: dict | None = None, all_screens: bool = True,
                  dry_run: bool = True) -> dict:
    set_dpi_aware()
    raw = str(path or "").strip().strip('"')
    if not raw:
        return {"ok": False, "note": "path 不能为空"}
    if not os.path.splitext(raw)[1]:
        raw += ".png"
    if os.path.splitext(raw)[1].lower() != ".png":
        ext = os.path.splitext(raw)[1]
        raw = os.path.splitext(raw)[0] + ".png"
        ext_note = f"（扩展名 {ext} 不是 PNG，已改成 .png —— 本原语只输出 PNG）"
    else:
        ext_note = ""
    try:
        target = normalize_path(raw)
    except ValueError as e:
        return {"ok": False, "note": f"路径不可用：{e}"}
    bad = system_zone_reason(target, "写入")
    if bad:
        return {"ok": False, "path": target,
                "note": f"拒绝写入：目标是{bad}（截图不该往系统目录里放）"}
    parent = os.path.dirname(target) or "."
    if not os.path.isdir(parent):
        return {"ok": False, "path": target, "note": f"目录不存在：{parent}"}

    # ── 算几何 ──
    if region:
        if not isinstance(region, dict):
            return {"ok": False, "path": target,
                    "note": f"region 必须是 {{left, top, width, height}} 这样的对象，"
                            f"收到 {type(region).__name__}"}
        try:
            x = int(region.get("left", 0))
            y = int(region.get("top", 0))
            w = int(region.get("width", 0))
            h = int(region.get("height", 0))
        except (TypeError, ValueError):
            return {"ok": False, "path": target,
                    "note": "region 必须是 {left, top, width, height} 四个整数"}
        if w <= 0 or h <= 0:
            return {"ok": False, "path": target,
                    "note": f"region 的 width/height 必须为正数，收到 {w}x{h}"}
        src = "region"
    elif all_screens:
        vs = _virtual_screen()
        x, y, w, h, src = vs["left"], vs["top"], vs["width"], vs["height"], "all_screens"
    else:
        x, y = 0, 0
        w, h, src = _user32.GetSystemMetrics(0), _user32.GetSystemMetrics(1), "primary"
    if w * h > _MAX_CAPTURE_PIXELS:
        return {"ok": False, "path": target, "width": w, "height": h,
                "note": f"拒绝截屏：{w}x{h} 超过像素上限 {_MAX_CAPTURE_PIXELS} —— "
                        f"用 region 指定一小块再截"}

    out = {"ok": False, "dry_run": bool(dry_run), "path": target, "source": src,
           "width": w, "height": h, "region": {"left": x, "top": y, "width": w, "height": h},
           "estimated_bytes": w * h * 3 + 4096, "note": ""}
    # ⚠️ 安全铁律：默认只预览。截图会落盘、内容可能含隐私
    if dry_run:
        out["note"] = (f"只读预览：未截屏、未写文件。真执行会抓 {'整个虚拟桌面' if src == 'all_screens' else ('主屏' if src == 'primary' else '指定区域')} "
                       f"{w}x{h}（左上角 {x},{y}）并存成 {target}"
                       + (f"；{ext_note}" if ext_note else "")
                       + "。⚠️ 屏幕内容可能含密码 / 私聊，落盘前请确认路径合适。"
                         "需显式传 dry_run=False")
        return out

    ok, bgra, err = _capture_bgra(x, y, w, h)
    if not ok:
        out["note"] = err
        return out
    try:
        n = _write_png(target, w, h, bgra)
    except OSError as e:
        out["note"] = f"写文件失败：{e}"
        return out
    except Exception as e:
        out["note"] = f"编码 PNG 失败：{e}"
        return out
    # 读回复核：文件真的在、且头是 PNG 签名 —— 写完不复核等于谎报
    try:
        with open(target, "rb") as f:
            head = f.read(8)
        verified = head == _PNG_SIG and os.path.getsize(target) == n
    except OSError:
        verified = False
    out.update({"ok": True, "bytes": n, "verified": bool(verified)})
    out["note"] = (f"已截屏 {w}x{h}（{'整个虚拟桌面' if src == 'all_screens' else src}）"
                   f"存到 {target}（{n} 字节）"
                   + ("" if verified else "；⚠️ 读回复核没通过，请检查文件")
                   + (f"；{ext_note}" if ext_note else ""))
    return out


# ============================================================================
# 键盘输入 —— ui.type_text（本域最高危的一条）
# ============================================================================
# ⚠️ **为什么它是最高危的**：它模拟键盘，等于「替用户打字」。文字进的是**当前焦点窗口**，
# 而用户此刻可能正在别的地方输入 —— 于是可能出现「用户打着打着，文字跑到别的窗口/别处」。
# 更糟的是它可能把内容打进聊天框、密码框、命令行。所以：默认 dry_run + 必须用户确认。
#
# ⚠️ **只做纯文本，这是有意的边界**：
#   · 不做组合键（Ctrl+C 之类）—— 那是「发命令」不是「打字」，是另一类能力
#   · 不做鼠标、不做窗口定位 —— 同上
#   · 不做「先激活某窗口再输入」的连招 —— 那等于把抢焦点和打字打包成一个动作，
#     风险叠加且用户没法在中途喊停；调用方要的话自己分两步调（先 window_activate，再 type_text）
# 快捷键 / 鼠标这类能力**明确不做**，不在本原语的参数里留口子。
_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_UNICODE = 0x0004
_VK_RETURN = 0x0D
_VK_TAB = 0x09
_INPUT_KEYBOARD = 1
_MAX_TEXT_CHARS = 20000          # 上限：防一次灌几百万字符进去
_SEND_CHUNK = 256                # 每次 SendInput 最多塞多少事件


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_void_p)]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_void_p)]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", _KEYBDINPUT), ("mi", _MOUSEINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


def _key_event(kind: str, code: int, keyup: bool) -> _INPUT:
    """一个键盘事件。kind='vk' 走虚拟键（回车/制表），kind='uni' 走 Unicode 扫描码。"""
    inp = _INPUT()
    inp.type = _INPUT_KEYBOARD
    ki = inp.u.ki
    if kind == "vk":
        ki.wVk = code
        ki.wScan = 0
        ki.dwFlags = _KEYEVENTF_KEYUP if keyup else 0
    else:
        ki.wVk = 0
        ki.wScan = code
        ki.dwFlags = _KEYEVENTF_UNICODE | (_KEYEVENTF_KEYUP if keyup else 0)
    return inp


def _events_for(chunk: str) -> tuple:
    """一段文本 → 键盘事件列表。返回 (事件列表, 无法发送的字符数)。

    · `\\n` / `\\r` 换成**回车键**、`\\t` 换成**制表键** —— 直接把这两个码点当 Unicode 字符发，
      多数程序收不到换行（它们等的是按键消息）。
    · 超出 BMP 的字符（emoji 等）会编码成**代理对**两个码元，实测**多数程序收不到**，
      所以计入 skipped 如实报出来，不假装发出去了。
    """
    events: list = []
    skipped = 0
    for ch in chunk:
        if ch in "\r\n":
            events.append(_key_event("vk", _VK_RETURN, False))
            events.append(_key_event("vk", _VK_RETURN, True))
            continue
        if ch == "\t":
            events.append(_key_event("vk", _VK_TAB, False))
            events.append(_key_event("vk", _VK_TAB, True))
            continue
        cp = ord(ch)
        if cp > 0xFFFF:
            skipped += 1
            continue
        events.append(_key_event("uni", cp, False))
        events.append(_key_event("uni", cp, True))
    return events, skipped


def _send_inputs(events: list) -> int:
    """把事件发出去，返回系统实际接受的事件数。分批发，防止一次塞太多被拒。"""
    _user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    _user32.SendInput.restype = wintypes.UINT
    sent = 0
    for i in range(0, len(events), _SEND_CHUNK):
        batch = events[i:i + _SEND_CHUNK]
        arr = (_INPUT * len(batch))(*batch)
        sent += int(_user32.SendInput(len(batch), arr, ctypes.sizeof(_INPUT)))
    return sent


@declare_primitive(
    "ui.type_text",
    "把一段**纯文本**打进当前焦点窗口（模拟键盘输入）。⚠️ **本域最高危的一条**："
    "它等于「替用户打字」，文字会进**当前焦点窗口**，而用户此刻可能正在别处输入 —— "
    "结果可能是「打着打着，字跑到聊天框 / 密码框 / 命令行里去了」，也可能覆盖用户正在打的内容。"
    "所以：**默认 dry_run=True 只预览，且需要用户确认**；"
    "真打字前**务必先用 ui.window_activate 把目标窗口切到前台并让用户确认**（本原语不会替你抢焦点）。"
    "**只做纯文本**：不做组合键（Ctrl+C 等）、不做快捷键、不做鼠标 —— 这些是另一类能力，"
    "本原语的参数里**有意不留口子**。`\\n` 会按回车键发、`\\t` 按制表键发；"
    "emoji 等超出 BMP 的字符会编码成代理对，多数程序收不到，返回值里 skipped 如实报出。"
    "返回的 sent 是**系统实际接受的事件数**（不是字符数），chars 是字符数。",
    {"type": "object",
     "properties": {
         "text": {"type": "string", "maxLength": 20000,
                  "description": "要输入的纯文本（上限 20000 字符，超了会被拒、需分批）。\\n=回车、\\t=制表符"},
         "interval_ms": {"type": "integer", "minimum": 0, "maximum": 5000,
                         "description": "每个字符之间的间隔毫秒数，默认 0（尽快，上限 5000，超了会被夹到 5000）。"
                                        "往反应慢的程序里打字可以设 20~50，减少丢字"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览要打什么、不打（默认）；False=真打字（需用户确认）"},
     },
     "required": ["text"], "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"chars": "字符数"},
    block="display_ui",
)
def ui_type_text(text: str, interval_ms: int = 0, dry_run: bool = True) -> dict:
    payload = "" if text is None else str(text)
    n_chars = len(payload)
    focused = _user32.GetForegroundWindow()
    focus_info = {"hwnd": int(focused or 0),
                  "title": _window_text(focused) if focused else "",
                  "process": _exe_name(_pid_of(focused)) if focused else None}
    out = {"ok": False, "dry_run": bool(dry_run), "chars": n_chars,
           "focus": focus_info, "note": ""}

    if not payload:
        out["note"] = "text 为空，没有可输入的内容"
        return out
    if n_chars > _MAX_TEXT_CHARS:
        out["note"] = (f"文本过长：{n_chars} 字符超过上限 {_MAX_TEXT_CHARS}，"
                       f"请分批输入（一次灌太多也更容易被目标程序丢字）")
        return out

    # ⚠️ 安全铁律：默认只预览。模拟键盘可能把文字打到处处，且不可撤销（只能让用户自己删）
    if dry_run:
        events, skipped = _events_for(payload)
        out.update({"preview": payload[:120] + ("…" if n_chars > 120 else ""),
                    "event_count": len(events), "skipped": skipped,
                    "would_type_into": focus_info,
                    "note": f"只读预览：没有发送任何键盘输入。真执行会把 {n_chars} 个字符"
                            f"打进**当前焦点窗口** [{focus_info['hwnd']}] "
                            f"{focus_info['title'] or '（无标题）'}"
                            f"（{focus_info['process'] or '进程未知'}）—— "
                            f"⚠️ 用户此刻可能正在别处打字，文字会跑到焦点窗口里去。"
                            f"需用户确认，并显式传 dry_run=False；"
                            f"建议先用 ui.window_activate 把目标窗口切到前台"})
        return out

    if not _user32.IsWindow(wintypes.HWND(focus_info["hwnd"])):
        out["note"] = "当前没有前台焦点窗口（或焦点在系统界面上），打字没有安全的目标"
        return out

    try:
        interval = max(0, min(int(interval_ms), 5000)) / 1000.0
    except (TypeError, ValueError):
        interval = 0.0

    sent = 0
    skipped = 0
    if interval > 0:
        # 逐字符发 + 间隔：往慢程序里打字时不容易丢字（代价是慢）
        for ch in payload:
            evs, sk = _events_for(ch)
            skipped += sk
            sent += _send_inputs(evs)
            time.sleep(interval)
    else:
        evs, skipped = _events_for(payload)
        sent = _send_inputs(evs)

    after = _user32.GetForegroundWindow()
    out.update({"ok": sent > 0, "sent": sent, "skipped": skipped,
                "focus_after": {"hwnd": int(after or 0),
                                "title": _window_text(after) if after else ""}})
    parts = [f"已向焦点窗口 [{focus_info['hwnd']}] "
             f"{focus_info['title'] or '（无标题）'} 发送 {n_chars} 个字符"
             f"（系统接受 {sent} 个键盘事件）"]
    if skipped:
        parts.append(f"⚠️ {skipped} 个字符（emoji 等超出 BMP 的字符）收不到，已跳过")
    if after != focused:
        parts.append("⚠️ 输入过程中**焦点窗口变了**（现在是 "
                     f"[{int(after or 0)}] {_window_text(after) if after else ''}）——"
                     "部分文字可能打进了另一个窗口，请核对")
    if interval > 0:
        parts.append(f"字符间隔 {int(interval * 1000)}ms")
    parts.append("⚠️ 已真实输入，无法撤回（要撤销只能由用户自己删）")
    out["note"] = "；".join(parts)
    return out


# ============================================================================
# 系统通知 —— ui.notify
# ============================================================================
# 低危、不改变任何状态、不留痕，只是打扰一下 —— 所以**不做 dry_run、不需确认**。
#
# **怎么发的**：走 Windows 自带的「Toast 通知」（WinRT 的
# `Windows.UI.Notifications.ToastNotificationManager`）。WinRT 在 Python 里没有标准库绑定，
# 但**系统自带的 PowerShell 5.1 能直接调 WinRT** —— 于是本原语起一个 PowerShell 子进程发通知。
# 这不是第三方依赖（PowerShell 是 Windows 组件，不是 pip 装的库），也没有更"纯"的零依赖做法：
# 剩下的路是 `Shell_NotifyIcon` 的托盘气泡，那要求本进程长期持有窗口和消息循环，
# 对一个「无状态工具」来说代价太大。
#
# ⚠️ **两点如实说明**：
#   · 通知**能不能弹出来不由我们说了算** —— 系统的勿扰 / 专注助手 / 通知设置会吞掉它，
#     `Show()` 返回成功 ≠ 用户一定看见了。返回值里 shown 只代表「已交给系统」。
#   · 文本走**环境变量 + Base64** 传给 PowerShell，不拼进脚本 —— 标题里有引号 / 反引号 /
#     换行也不会把脚本搞坏（更不会变成注入）。
_NOTIFY_APPID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"

_NOTIFY_PS = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null
$title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:INTENTOS_NOTIFY_TITLE))
$msg   = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:INTENTOS_NOTIFY_MSG))
$tpl = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$txt = $tpl.GetElementsByTagName("text")
$txt.Item(0).AppendChild($tpl.CreateTextNode($title)) | Out-Null
$txt.Item(1).AppendChild($tpl.CreateTextNode($msg)) | Out-Null
$n = [Windows.UI.Notifications.ToastNotification]::new($tpl)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:INTENTOS_NOTIFY_APPID).Show($n)
Write-Output "shown"
"""


@declare_primitive(
    "ui.notify",
    "给用户弹一条系统通知（Windows 通知中心的气泡）。低危、不改任何状态、不留痕，"
    "所以**不做 dry_run** —— 它是「主动告诉用户一件事」的标准手段。"
    "什么时候用：任务跑完了 / 有个原语失败要人来看一眼 / 需要用户去某个窗口处理"
    "（例如 ui.window_activate 抢焦点被系统拦住时，改用通知请用户自己切过去）。"
    "什么时候别用：只是想让机器**出个声**、不需要看到文字时用 sound.beep（更轻、不占通知中心）；"
    "要用户**立刻看到某个窗口**用 ui.window_activate。也别拿它做高频广播（会烦人，用户会直接关掉通知）。"
    "参数怎么填：title 一行短标题、message 正文 —— 两个都必填。"
    "**title 超过 120 字按 120 截断、message 超过 400 字按 400 截断**（首尾空白会先去掉），"
    "真正发出去的就是截断后的内容；title 为空时会自动填成「IntentOS」，两个都空则直接返回失败、不发。"
    "返回什么：shown 表示**已成功交给系统**、ok 与 shown 同值、title / message 是实际发出去的（已截断）、"
    "note 是中文说明（失败原因、以及「用户到底看没看见本原语管不了」都在这里）。"
    "⚠️ 陷阱与易混："
    "① **能不能真弹出来不由本原语决定**：系统「勿扰 / 专注助手 / 通知设置」会把它吞掉，"
    "所以 shown=true 只表示**已成功交给系统**，不代表用户一定看见了 —— 关键事情别只靠通知；"
    "② 与 sound.beep 的分工：要**给用户看到文字**用本条（系统通知气泡，带标题与正文）；"
    "只要一声响、不需要文字用 sound.beep —— 两者都会打扰用户，本条更重。",
    {"type": "object",
     "properties": {
         "title": {"type": "string", "description": "通知标题（一行短句，超长会截断）"},
         "message": {"type": "string", "description": "通知正文（超长会截断）"},
     },
     "required": ["title", "message"],
     "additionalProperties": False},
    state={"shown": "已下发"},
    block="display_ui",
)
def ui_notify(title: str, message: str) -> dict:
    t = ("" if title is None else str(title)).strip()[:120]
    m = ("" if message is None else str(message)).strip()[:400]
    if not t and not m:
        return {"ok": False, "shown": False, "note": "title 和 message 都是空的，没什么可通知的"}
    if not t:
        t = "IntentOS"
    env = dict(os.environ)
    env["INTENTOS_NOTIFY_TITLE"] = base64.b64encode(t.encode("utf-8")).decode("ascii")
    env["INTENTOS_NOTIFY_MSG"] = base64.b64encode(m.encode("utf-8")).decode("ascii")
    env["INTENTOS_NOTIFY_APPID"] = _NOTIFY_APPID
    enc = base64.b64encode(_NOTIFY_PS.encode("utf-16-le")).decode("ascii")
    out = {"ok": False, "shown": False, "title": t, "message": m}
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-EncodedCommand", enc],
                           capture_output=True, timeout=45, env=env)
    except FileNotFoundError:
        out["note"] = "本机没有 PowerShell，发不了系统通知（没有做托盘气泡的退路）"
        return out
    except subprocess.TimeoutExpired:
        out["note"] = "发通知超时（45s）—— 通知服务可能卡住了"
        return out
    except Exception as e:
        out["note"] = f"发通知失败：{e}"
        return out
    shown = b"shown" in (p.stdout or b"")
    err = (p.stderr or b"").decode("utf-8", "replace").strip()
    out["shown"] = shown
    out["ok"] = shown
    if shown:
        out["note"] = (f"通知已交给系统：{t} —— {m}。"
                       f"⚠️ 用户是否真看见取决于系统通知设置 / 勿扰模式（本原语管不了）")
    else:
        out["note"] = (f"通知没发出去（PowerShell 返回 {p.returncode}）"
                       + (f"：{err[:200]}" if err else "")
                       + "。可能是通知服务被禁用 / 系统策略阻止 WinRT 通知")
    return out
