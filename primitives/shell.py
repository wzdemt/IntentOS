"""Shell 域原语 —— 快捷方式与回收站（shell.*）。

⚠️ **依赖：pywin32 / 系统 COM**（`win32com.client` 走 `WScript.Shell` 与 `Shell.Application`）。
`.lnk` 是二进制复合文档格式，手搓解析器等于重写一遍 shell 链接格式（几百行且版本多），
读出来的还可能不是系统认的那个语义；回收站的**还原**动作更是只有 shell 自己提供的动词
才做得对（要同时维护 $I/$R 两份元数据）。按项目约定「该域本就无法零依赖时不硬撑」，
本域走已装的 pywin32 + ctypes(shell32)，与 `ui.py` 的取舍一致。

**安全分级**
  · `shell.shortcut_read` —— 只读，无 dry_run。
  · `shell.shortcut_write`—— 会改状态：`dry_run` 默认 True + **需确认**。
    ⚠️ **一律禁止写到「启动」文件夹**（用户级 + 系统级都拦）：往那里放快捷方式 = 装开机自启动，
    是持久化手法（恶意软件的标准起手式）。本域**明确不提供**这个能力，不是「要确认就能做」。
  · `shell.recycle`       —— 看（只读）/ 清空 / 还原 / 删进回收站。会改状态的动作带
    `dry_run` 默认 True；**清空回收站不可逆，整条原语带 requires_confirmation**（见文末说明）。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_shell，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import os
import re

from core.factory import declare_primitive  # type: ignore
from primitives._common import system_zone_reason


# ══════════════════════════════════════════════════════════════════════════
# 路径安全地基（按 fs.py 的思路自备一份：规范化 + 系统禁区）
# ══════════════════════════════════════════════════════════════════════════
def _norm(path: str) -> str:
    """展开 %变量%/~ → 绝对化 → 解析 .. 与软链接/junction。空路径抛 ValueError。"""
    if path is None or not str(path).strip():
        raise ValueError("路径不能为空")
    p = os.path.expandvars(os.path.expanduser(str(path).strip()))
    if p.startswith("\\\\?\\"):                 # \\?\C:\... → C:\...
        p = p[4:]
    p = os.path.abspath(p.replace("/", os.sep))
    try:
        p = os.path.realpath(p)                 # 解析软链接 / junction：防「链接逃逸」
    except OSError:
        pass
    return os.path.normpath(p)


def _inside(child: str, root: str) -> bool:
    """child 是否落在 root 之内（含相等）。按目录边界比对。"""
    c = os.path.normcase(os.path.normpath(child)).rstrip("\\/")
    r = os.path.normcase(os.path.normpath(root)).rstrip("\\/")
    return c == r or c.startswith(r + os.sep)


# ══════════════════════════════════════════════════════════════════════════
# 「启动」文件夹 —— 本文件里唯一一条**无条件硬拒**的红线
# ══════════════════════════════════════════════════════════════════════════
# 为什么不是「需确认就能做」：往启动文件夹放快捷方式 = 装开机自启动，这是**持久化**手法。
# 一旦放进去，之后每次登录都会执行，而调用方早就走了 —— 用户那次点的「确认」覆盖不了
# 「以后每次都偷偷跑」这件事。所以这里给的是**能力层面的拒绝**，不是确认层面的限制。
# （只看不改是允许的：`startup.list` 读取启动项是刚需，`shell.shortcut_read` 也会标出来。）
def _startup_dirs() -> list[str]:
    """已知的启动文件夹（用户级 + 系统级）。返回规范化后的绝对路径列表。"""
    appdata = os.environ.get("APPDATA") or ""
    progdata = os.environ.get("ProgramData") or ""
    profile = os.environ.get("USERPROFILE") or ""
    cands = [
        os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(progdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Startup"),
        os.path.join(profile, "Start Menu", "Programs", "Startup"),
    ]
    out = []
    for c in cands:
        if not c:
            continue
        try:
            out.append(_norm(c))
        except ValueError:
            continue
    return out


# 字面量规则：光比对已知目录不够 —— 启动文件夹可能被组策略 / OneDrive 重定向到别处。
# 名字里出现 `\Start Menu\Programs\Startup\` 或 `\Start Menu\Startup\` 一律拒绝。
_STARTUP_PAT = re.compile(r"\\start menu\\(programs\\)?startup(\\|$)", re.IGNORECASE)


def _startup_reason(norm: str) -> str | None:
    """要把快捷方式写到这里吗？是则返回中文理由，否则 None。"""
    if _STARTUP_PAT.search(norm.replace("/", "\\")):
        return "「启动」文件夹（名字里出现 Start Menu\\Programs\\Startup）"
    for d in _startup_dirs():
        if _inside(norm, d):
            return f"「启动」文件夹：{d}"
    return None


# ══════════════════════════════════════════════════════════════════════════
# COM 入口
# ══════════════════════════════════════════════════════════════════════════
def _com(prog_id: str):
    """取一个 COM 对象。返回 (对象, 中文错误理由)。"""
    try:
        import pythoncom
        import win32com.client
    except Exception as e:
        return None, (f"需要 pywin32（当前导入失败：{e}）；装法：pip install pywin32")
    try:
        pythoncom.CoInitialize()          # 已初始化会返回 S_FALSE，不报错
    except Exception:
        pass
    try:
        return win32com.client.Dispatch(prog_id), None
    except Exception as e:
        return None, f"无法创建 COM 对象 {prog_id}（当前失败：{e}）"


def _wscript():
    return _com("WScript.Shell")


# ══════════════════════════════════════════════════════════════════════════
# ① shell.shortcut_read —— 读快捷方式（只读）
# ══════════════════════════════════════════════════════════════════════════
@declare_primitive(
    "shell.shortcut_read",
    "读一个快捷方式（.lnk）指向哪里：目标程序、命令行参数、起始目录、图标、描述、运行方式。"
    "什么时候用：看到一个 .lnk 想知道它到底启动什么（桌面图标、开始菜单项、"
    "别人发来的快捷方式），或者想确认某个快捷方式是不是指向可疑位置。"
    "要看「这台机器**开机都自动跑什么**」的全景（启动文件夹是其中一类，那条只列 .lnk 的文件名、"
    "不解析它指向哪）用 startup.list —— 在那边看到可疑的 .lnk，再回到本原语看它到底指向什么。"
    "参数怎么填：path 传 .lnk 文件的绝对路径。"
    "返回什么：target 是目标程序路径（环境变量已展开，另外给 target_raw 是原样字符串）；"
    "arguments / working_dir / icon / description / window_style 是各字段；"
    "target_exists 说明目标文件现在还在不在（快捷方式指向已卸载的程序时会 False）；"
    "in_startup_folder 表示**这个 .lnk 自己**是否位于「启动」文件夹（True 就是在开机自启动）；"
    "target_in_startup_folder 表示它指向的目标是否落在启动文件夹里。"
    "注意：解析走系统 COM（WScript.Shell），拿到的是 Windows 认可的语义；"
    "目标路径里的环境变量会展开，所以 target 和 target_raw 可能不一样。"
    "⚠️ 与 shell.shortcut_write 是配对的两条：本原语只**读**（看现有 .lnk 指向哪、是不是开机自启）；"
    "要创建 / 修改快捷方式用 shell.shortcut_write —— 想改之前先确认现状，就用本原语读一遍。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": ".lnk 快捷方式文件的绝对路径"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "快捷方式", "target": "指向"},
    block="recycle_shortcut",
)
def shell_shortcut_read(path: str) -> dict:
    try:
        target = _norm(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "文件不存在（路径已规范化）"}
    if os.path.isdir(target):
        return {"ok": False, "path": target, "note": "这是一个目录，不是快捷方式文件"}
    if not target.lower().endswith(".lnk"):
        return {"ok": False, "path": target,
                "note": "不是 .lnk 快捷方式（.url 是纯文本 INI，直接读文件内容即可；"
                        "本原语只解析 Windows 的 .lnk）"}

    sh, err = _wscript()
    if err:
        return {"ok": False, "path": target, "note": err}
    try:
        lnk = sh.CreateShortcut(target)
        raw_target = lnk.TargetPath or ""
        args = lnk.Arguments or ""
        wd = lnk.WorkingDirectory or ""
        icon = lnk.IconLocation or ""
        desc = lnk.Description or ""
        style = int(lnk.WindowStyle or 1)
    except Exception as e:
        return {"ok": False, "path": target,
                "note": f"解析快捷方式失败：{e}（文件可能已损坏，或不是标准的 .lnk）"}

    expanded = os.path.expandvars(raw_target)
    # 环境变量展开 + 规范化；目标可能不存在，normalize 失败时退回展开后的原样
    try:
        tgt_norm = _norm(expanded) if expanded else ""
    except ValueError:
        tgt_norm = expanded
    tgt_exists = bool(tgt_norm) and os.path.exists(tgt_norm)

    in_startup = _startup_reason(target) is not None
    tgt_startup = bool(tgt_norm) and _startup_reason(tgt_norm) is not None

    notes = [f"指向 {raw_target or '（空）'}"]
    if not tgt_exists:
        notes.append("⚠️ 目标文件当前不存在（程序可能已卸载或移动，快捷方式已失效）")
    if in_startup:
        notes.append("⚠️ 这个快捷方式位于「启动」文件夹 —— 每次登录都会自动运行")
    if args:
        notes.append(f"带启动参数：{args}")
    return {"ok": True, "path": target,
            "target": tgt_norm or raw_target, "target_raw": raw_target,
            "arguments": args, "working_dir": wd,
            "icon": icon, "icon_expanded": os.path.expandvars(icon) if icon else "",
            "description": desc, "window_style": style,
            "target_exists": tgt_exists,
            "in_startup_folder": in_startup,
            "target_in_startup_folder": tgt_startup,
            "note": "；".join(notes)}


# ══════════════════════════════════════════════════════════════════════════
# ② shell.shortcut_write —— 建/改快捷方式（会改状态：dry_run 默认 True + 需确认）
# ══════════════════════════════════════════════════════════════════════════
_WINDOW_STYLES = {1: "常规窗口", 3: "最大化", 7: "最小化"}


@declare_primitive(
    "shell.shortcut_write",
    "创建或修改一个快捷方式（.lnk）：指定它指向哪个程序、带什么参数、用什么图标。"
    "什么时候用：给某个程序/文档在桌面或开始菜单建个入口，或改掉现有快捷方式的指向与参数。"
    "⚠️ 会写文件，且**需用户确认**。"
    "🚫 **禁止写入「启动」文件夹**（用户级和系统级都拦）—— 往那里放快捷方式等于装开机自启动，"
    "是持久化手法，本原语不提供这个能力（要确认也不行）。"
    "参数怎么填：path 传要创建/修改的 .lnk 路径；target 传它指向的目标（程序或文档的绝对路径）；"
    "arguments / working_dir / icon（形如 'C:\\a\\b.exe,0'）/ description / window_style"
    "（1=常规 3=最大化 7=最小化）按需给。"
    "**修改已有快捷方式时**：只传了的字段才会被改，没传的字段（空字符串）保留原值；"
    "创建新快捷方式时没给的字段就是空。"
    "返回什么：预览给 action（create / update）、每个字段的旧值 → 新值、will_create_dirs；"
    "真写给 written=True 与最终的 target；refused=True 表示被拦下（note 是中文理由）。"
    "⚠️ 与 shell.shortcut_read 是配对的两条：本原语只**写**（创建 / 修改）；"
    "要**看**现有 .lnk 指向哪、是不是开机自启用 shell.shortcut_read ——"
    "改之前先读一遍，能确认自己改的是不是想改的那个。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "要创建/修改的 .lnk 文件的绝对路径"},
         "target": {"type": "string", "description": "快捷方式指向的目标（程序或文档的绝对路径）"},
         "arguments": {"type": "string", "description": "可选：启动参数（命令行），默认不改动/为空"},
         "working_dir": {"type": "string", "description": "可选：起始目录，默认不改动/为空"},
         "icon": {"type": "string",
                  "description": "可选：图标，形如 'C:\\\\a\\\\b.exe,0' 或 '%windir%\\\\system32\\\\imageres.dll,-114'"},
         "description": {"type": "string", "description": "可选：备注/描述文本"},
         "window_style": {"type": "integer",
                          "description": "可选：运行方式 1=常规窗口（默认）3=最大化 7=最小化"},
         "create_dirs": {"type": "boolean",
                         "description": ".lnk 所在目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真写入"},
     },
     "required": ["path", "target"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"path": "快捷方式", "target": "指向"},
    block="recycle_shortcut",
)
def shell_shortcut_write(path: str, target: str, arguments: str = "", working_dir: str = "",
                         icon: str = "", description: str = "", window_style: int = 0,
                         create_dirs: bool = False, dry_run: bool = True) -> dict:
    try:
        lnk_path = _norm(path)
    except ValueError as e:
        return {"written": False, "refused": True, "path": str(path), "note": f"路径无效：{e}"}
    if not lnk_path.lower().endswith(".lnk"):
        return {"written": False, "refused": True, "path": lnk_path,
                "note": "path 必须以 .lnk 结尾（这是要创建的快捷方式文件，不是它指向的目标）"}
    # ⚠️ 落点先过系统禁区（与 fs.* / archive.* 同一套判定，走共享层）
    reason = system_zone_reason(lnk_path, "写入")
    if reason:
        return {"written": False, "refused": True, "path": lnk_path, "note": f"拒绝写入：{reason}"}
    if not str(target or "").strip():
        return {"written": False, "refused": True, "path": lnk_path, "note": "target 不能为空"}
    try:
        tgt = _norm(target)
    except ValueError as e:
        return {"written": False, "refused": True, "path": lnk_path,
                "note": f"target 无效：{e}"}

    # 🚫 红线：启动文件夹。**原语自己拦**，不靠 PolicyGate —— 这条是能力层面的禁止。
    why = _startup_reason(lnk_path)
    if why:
        return {"written": False, "refused": True, "path": lnk_path, "target": tgt,
                "note": f"拒绝写入：{why}。往「启动」文件夹放快捷方式 = 装开机自启动，"
                        f"属于持久化手法，本原语明确不提供这个能力（即使是用户确认也不行）。"
                        f"如果这确实是你要的，请自己在资源管理器里手动创建。"}
    if window_style and window_style not in _WINDOW_STYLES:
        return {"written": False, "refused": True, "path": lnk_path,
                "note": f"window_style 只能是 1（常规）/ 3（最大化）/ 7（最小化），收到 {window_style}"}

    exists = os.path.exists(lnk_path)
    if exists and os.path.isdir(lnk_path):
        return {"written": False, "refused": True, "path": lnk_path,
                "note": "该路径是一个目录，不能当快捷方式文件"}
    parent = os.path.dirname(lnk_path)
    need_mkdir = bool(parent) and not os.path.isdir(parent)
    if need_mkdir and not create_dirs:
        return {"written": False, "refused": True, "path": lnk_path,
                "note": f"所在目录不存在：{parent}（需要时传 create_dirs=True）"}

    # 修改模式：先把旧值读出来，好让预览显示「旧 → 新」，也决定哪些字段该保留
    old: dict = {}
    if exists:
        sh, err = _wscript()
        if err:
            return {"written": False, "path": lnk_path, "note": err}
        try:
            cur = sh.CreateShortcut(lnk_path)
            old = {"target": cur.TargetPath or "", "arguments": cur.Arguments or "",
                   "working_dir": cur.WorkingDirectory or "", "icon": cur.IconLocation or "",
                   "description": cur.Description or "", "window_style": int(cur.WindowStyle or 1)}
        except Exception as e:
            return {"written": False, "path": lnk_path,
                    "note": f"读取现有快捷方式失败，为免误改已放弃：{e}"}

    # 没传的字段：修改时保留旧值，新建时为空
    def pick(new, key):
        if new not in ("", None) and new != 0:
            return new
        return old.get(key, "") if exists else new

    final = {"target": tgt, "arguments": pick(arguments, "arguments"),
             "working_dir": pick(working_dir, "working_dir"),
             "icon": pick(icon, "icon"), "description": pick(description, "description"),
             "window_style": window_style or (old.get("window_style", 1) if exists else 1)}
    action = "update" if exists else "create"

    if dry_run:
        return {"written": False, "dry_run": True, "path": lnk_path, "action": action,
                "target": tgt, "old": old or None, "new": final,
                "will_create_dirs": need_mkdir,
                "note": f"只读预览：未写入。真执行会{'修改' if exists else '创建'}快捷方式 "
                        f"{lnk_path} → {tgt}"
                        + (f"（原指向 {old.get('target')}）" if exists and old.get("target") != tgt else "")
                        + ("，并自动创建所在目录" if need_mkdir else "")
                        + "，需显式传 dry_run=False"}

    sh, err = _wscript()
    if err:
        return {"written": False, "path": lnk_path, "note": err}
    try:
        if need_mkdir:
            os.makedirs(parent, exist_ok=True)
        lnk = sh.CreateShortcut(lnk_path)
        lnk.TargetPath = tgt
        lnk.Arguments = final["arguments"]
        lnk.WorkingDirectory = final["working_dir"]
        if final["icon"]:
            lnk.IconLocation = final["icon"]
        lnk.Description = final["description"]
        lnk.WindowStyle = int(final["window_style"])
        lnk.Save()
    except Exception as e:
        return {"written": False, "path": lnk_path, "note": f"写入快捷方式失败：{e}"}
    return {"written": True, "dry_run": False, "path": lnk_path, "action": action,
            "target": tgt, "new": final,
            "note": f"已{'修改' if action == 'update' else '创建'}快捷方式：{lnk_path} → {tgt}"}


# ══════════════════════════════════════════════════════════════════════════
# ③ shell.recycle —— 回收站：看 / 清空 / 还原 / 删进去
# ══════════════════════════════════════════════════════════════════════════
# ⚠️ **requires_confirmation 是按原语声明的静态开关，core 现在看不到参数**（见
# docs/os-primitives.md「写侧的边界」一节里那条取舍的记录）。所以「清空回收站」
# 要确认这件事，只能挂在整条 shell.recycle 上 —— 副作用是 `action=list`（只读）也会过确认门：
# 交互式场景就是多问一句，非交互场景会被执行门拒掉。
# 这是**故意选的失败方向**：宁可让只读的看也被多问一句，也不能让「清空」漏过去。
# 真嫌烦的话，正解是把只读的看拆成独立原语（如 shell.recycle_list），
# 但那要动原语清单，不属于本次范围。
class _SHFILEOPSTRUCTW(ctypes.Structure):
    """shell32 SHFileOperationW 的入参结构（64 位布局，ctypes 自动对齐）。"""
    _fields_ = [
        ("hwnd", ctypes.c_void_p),
        ("wFunc", ctypes.c_uint),
        ("pFrom", ctypes.c_wchar_p),
        ("pTo", ctypes.c_wchar_p),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", ctypes.c_int),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", ctypes.c_wchar_p),
    ]


_FO_DELETE = 0x0003
_FOF_SILENT = 0x0004
_FOF_NOCONFIRMATION = 0x0010
_FOF_ALLOWUNDO = 0x0040          # ← 关键：走回收站而不是永久删除
_FOF_NOERRORUI = 0x0400

# SHEmptyRecycleBinW 的 flags
_SHERB_NOCONFIRMATION = 0x0001
_SHERB_NOPROGRESSUI = 0x0002
_SHERB_NOSOUND = 0x0004


def _to_recycle_bin(path: str) -> tuple[bool, str]:
    """把文件/目录移入回收站（SHFileOperationW + FOF_ALLOWUNDO）。返回 (成功?, 中文说明)。"""
    try:
        op = _SHFILEOPSTRUCTW()
        op.wFunc = _FO_DELETE
        op.pFrom = path + "\0\0"   # pFrom 是「双 null 结尾」的多字符串，必须补两个 \0
        op.pTo = None
        op.fFlags = _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_SILENT | _FOF_NOERRORUI
        rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if rc != 0:
            return False, f"回收站操作失败（SHFileOperationW 错误码 {rc}）"
        if op.fAnyOperationsAborted:
            return False, "系统中止了回收站操作"
        return True, "已移入回收站"
    except Exception as e:
        return False, f"回收站调用失败：{e}"


def _original_path(item_path: str) -> str | None:
    """从回收站的 $R 文件推出它原来的位置：同目录下配对的 $I 元数据里存着原始路径。

    $I 是二进制小文件：前 8 字节版本、8 字节大小、8 字节删除时间，之后是 UTF-16LE 的原始路径。
    实测（Windows 11 / $I 版本 2）路径前面还跟了 2 字节的长度字段，各版本布局略有出入 ——
    所以这里不按固定偏移切，而是解出文本后**找盘符**（`X:\\`）来定位路径起点，稳一些。
    """
    if not item_path:
        return None
    d = os.path.dirname(item_path)
    base = os.path.basename(item_path)
    if not base.startswith("$R"):
        return None
    ip = os.path.join(d, "$I" + base[2:])
    try:
        with open(ip, "rb") as f:
            blob = f.read()
    except OSError:
        return None
    if len(blob) < 26:
        return None
    txt = blob[24:].decode("utf-16-le", "replace")
    m = re.search(r"[A-Za-z]:\\", txt)
    if not m:
        return None
    return txt[m.start():].rstrip("\x00").strip()


def _recycle_items(limit: int) -> tuple[list[dict], int, str, str]:
    """枚举回收站。返回 (条目列表, 总数, 错误理由, 降级说明)。"""
    sh, err = _com("Shell.Application")
    if err:
        n, size, e2 = _query_bin()
        if e2:
            return [], 0, f"{err}；退路也不可用：{e2}", ""
        return [], n, "", (f"{err}；已降级为只报总量：{n} 项、约 {_fmt_size(size)}"
                           f"（拿不到文件名与原始位置）")
    try:
        items = sh.Namespace(10).Items()          # 10 = ssfBITBUCKET（回收站）
        total = int(items.Count)
        out: list[dict] = []
        for i in range(min(total, limit)):
            it = items.Item(i)
            try:
                size = int(it.Size)
            except Exception:
                size = None
            p = it.Path or ""
            item = {"name": it.Name, "path": p, "size": size,
                    "original_path": _original_path(p)}
            if item["size"] is None:
                item.pop("size")
            out.append(item)
        return out, total, "", ""
    except Exception as e:
        return [], 0, f"枚举回收站失败：{e}", ""


def _fmt_size(nbytes: int) -> str:
    """人话的体积：小于 1 MB 就报 KB / 字节 —— 回收站里常常只有几个小文件，
    一律按 MB 四舍五入会全部显示成「0.00 MB」，看着像坏了。"""
    n = int(nbytes or 0)
    if n >= 1048576:
        return f"{n / 1048576:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} 字节"


def _query_bin() -> tuple[int, int, str]:
    """ctypes 退路：SHQueryRecycleBinW 只给「几项、共多少字节」，不给名字。"""
    try:
        class _SHQUERYRBINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong),
                        ("i64NumItems", ctypes.c_longlong)]
        info = _SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
        rc = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        if rc != 0:
            return 0, 0, f"SHQueryRecycleBinW 返回错误码 {rc}"
        return int(info.i64NumItems), int(info.i64Size), ""
    except Exception as e:
        return 0, 0, f"查询回收站失败：{e}"


def _find_verb(item, keywords: tuple[str, ...]) -> str | None:
    """在条目的右键动词里找一个匹配的（回收站的「还原」在中文系统上叫「还原(&E)」，
    英文系统上是「Restore」—— 所以按关键词模糊找，不写死本地化字符串）。"""
    try:
        verbs = item.Verbs()
        names = [verbs.Item(j).Name for j in range(verbs.Count)]
    except Exception:
        return None
    for name in names:
        flat = (name or "").replace("&", "")
        low = flat.lower()
        for kw in keywords:
            if kw.lower() in low:
                return name
    return None


@declare_primitive(
    "shell.recycle",
    "回收站：看里面有什么 / 清空 / 还原某一项 / 把一个文件删进回收站。"
    "action=list（只读）列出回收站里的项目（名字、原位置、大小）；"
    "action=empty 清空整个回收站（**不可逆**，需用户确认）；"
    "action=restore 还原指定项目到它原来的位置（用 path 指定，见下）；"
    "action=delete 把 path 指向的文件/目录**移进回收站**（不是永久删除，可再捞回来）。"
    "⚠️ empty / restore / delete 会改状态。"
    "参数怎么填：action 选动作；path 在 restore 时传回收站里那一项的名字（用 action=list 看到的 "
    "name，或它原来的完整路径，或列表里的 path）；在 delete 时传要删的文件的绝对路径；"
    "keyword 可选，只看名字/原位置含它的项目；limit 控制 list 最多列多少条。"
    "返回什么：list 给 count 与 items；预览给这次会动到哪些东西；"
    "restore 若匹配到多项会拒绝并列出候选（请改用列表里的 path，它是唯一的）；"
    "refused=True 表示被拦下（note 是中文理由）。"
    "注意：本原语整条带 requires_confirmation —— 因为「清空」不可逆，这是有意选的失败方向。"
    "⚠️ 与 fs.delete 的分工（**两条都能把东西删进回收站**）：只删**某个文件 / 目录**、"
    "不关心回收站本身，用 fs.delete（它是「按路径删一个东西」的通用入口，还能 permanent=True 永久删）；"
    "本原语除了 action=delete，还管**回收站本身** —— 看里面有什么（list）、清空（empty）、"
    "把之前的项捞回来（restore）。要还原 / 清空只能用它，fs.delete 做不到。",
    {"type": "object",
     "properties": {
         "action": {"type": "string", "enum": ["list", "empty", "restore", "delete"],
                    "description": "动作：list=看 / empty=清空 / restore=还原 / delete=删进回收站"},
         "path": {"type": "string",
                  "description": "restore 时=回收站里那一项（name / 原路径 / 列表里的 path）；delete 时=要删的文件绝对路径"},
         "keyword": {"type": "string", "description": "可选：list 时只看名字或原位置含该关键词的项"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 1000,
                   "description": "list 最多返回多少条，默认 100，上限 1000"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不执行（默认）；False=真做（仅 empty/restore/delete 有意义）"},
     },
     "required": ["action"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"action": "动作", "count": "项数"},
    block="recycle_shortcut",
)
def shell_recycle(action: str, path: str = "", keyword: str = "", limit: int = 100,
                  dry_run: bool = True) -> dict:
    act = (action or "").strip().lower()
    if act not in ("list", "empty", "restore", "delete"):
        return {"ok": False, "count": 0,
                "note": f"action 只能是 list / empty / restore / delete，收到 {action!r}"}
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 100

    # ── action=list：只读，不需要 dry_run ──
    if act == "list":
        items, total, err, degraded = _recycle_items(limit)
        if err:
            return {"ok": False, "count": 0, "items": [], "note": err}
        if keyword:
            kw = keyword.lower()
            items = [i for i in items
                     if kw in (i.get("name") or "").lower()
                     or kw in (i.get("original_path") or "").lower()]
        note = f"回收站共 {total} 项"
        if keyword:
            note += f"，其中匹配 {keyword!r} 的有 {len(items)} 项"
        if degraded:
            note += "；" + degraded
        if total > limit:
            note += f"；只列了前 {limit} 条"
        return {"ok": True, "action": "list", "count": total, "items": items,
                "has_more": total > limit, "degraded": bool(degraded),
                # 只是「本次列出的这些项」的大小之和 —— 不是回收站总占用（有 limit 截断，
                # 且目录项在系统里报 0）。总占用是另一个数，要看就得整站扫，不值当。
                "listed_usage_mb": round(sum(i.get("size") or 0 for i in items) / 1048576, 2),
                "note": note}

    # ── action=empty：清空（不可逆）──
    if act == "empty":
        # 项数用 SHQueryRecycleBinW（一次调用、跨所有盘，是系统自己的口径）；
        # 它偶尔只给项数不给体积（实测本机 size=0），这时用 COM 逐条求和补上。
        n, size, err = _query_bin()
        if err or (n and not size):
            items, total, e2, _ = _recycle_items(1000)
            if e2 and err:
                return {"ok": False, "action": "empty", "count": 0,
                        "note": f"无法确认回收站状态：{err}；{e2}"}
            if err:
                n = total
            if not size:
                size = sum(i.get("size") or 0 for i in items)
        if n == 0:
            return {"ok": True, "action": "empty", "count": 0, "dry_run": bool(dry_run),
                    "note": "回收站已经是空的，无需清空"}
        if dry_run:
            return {"ok": False, "action": "empty", "dry_run": True, "count": int(n),
                    "usage_bytes": int(size), "usage_mb": round(size / 1048576, 2),
                    "note": f"只读预览：未清空。真执行会把回收站里全部 {n} 项"
                            f"（约 {_fmt_size(size)}）**永久删除，不可恢复**，"
                            f"需显式传 dry_run=False + 过确认"}
        try:
            flags = _SHERB_NOCONFIRMATION | _SHERB_NOPROGRESSUI | _SHERB_NOSOUND
            rc = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
            if rc != 0:
                return {"ok": False, "action": "empty", "count": int(n),
                        "note": f"清空失败（SHEmptyRecycleBinW 错误码 {rc}）；可能权限不足"}
        except Exception as e:
            return {"ok": False, "action": "empty", "count": int(n),
                    "note": f"清空失败：{e}"}
        return {"ok": True, "action": "empty", "dry_run": False, "count": int(n),
                "note": f"⚠️ 已清空回收站（{n} 项永久删除，不可恢复）"}

    # ── action=restore：还原 ──
    if act == "restore":
        if not str(path or "").strip():
            return {"ok": False, "action": "restore",
                    "note": "restore 需要 path（回收站里那一项的名字 / 原完整路径 / 列表里的 path）"}
        items, total, err, degraded = _recycle_items(limit)
        if err:
            return {"ok": False, "action": "restore", "note": err}
        if degraded:
            return {"ok": False, "action": "restore",
                    "note": f"无法还原：{degraded}。还原需要拿到条目的动词，COM 不可用时做不到"}
        want = str(path).strip()
        try:
            want_norm = os.path.normcase(_norm(want))
        except ValueError:
            want_norm = ""
        hits = []
        for it in items:
            name = it.get("name") or ""
            p = it.get("path") or ""
            orig = it.get("original_path") or ""
            if want == name or want == p or (orig and os.path.normcase(orig) == want_norm):
                hits.append(it)
        if not hits:
            return {"ok": False, "action": "restore", "path": want,
                    "note": f"回收站里没有匹配 {want!r} 的项"
                            f"（名字、原完整路径、或列表里的 path 三选一；"
                            f"要还原同名项请用列表里的 path，它是唯一的）"}
        if len(hits) > 1:
            return {"ok": False, "action": "restore", "path": want,
                    "ambiguous": True, "candidates": [h.get("path") for h in hits[:10]],
                    "note": f"匹配到 {len(hits)} 项，无法确定还原哪一个 —— "
                            f"请改用 candidates 里的 path 精确指定"}
        target_item = hits[0]
        orig = target_item.get("original_path") or "（未知，$I 元数据读不到）"
        if dry_run:
            return {"ok": False, "action": "restore", "dry_run": True,
                    "item": target_item,
                    "note": f"只读预览：未还原。真执行会把 {target_item.get('name')!r} "
                            f"还原到 {orig}，需显式传 dry_run=False"}
        sh, cerr = _com("Shell.Application")
        if cerr:
            return {"ok": False, "action": "restore", "note": cerr}
        try:
            items2 = sh.Namespace(10).Items()
            hit = None
            for i in range(items2.Count):
                it = items2.Item(i)
                if (it.Path or "") == target_item.get("path"):
                    hit = it
                    break
            if hit is None:
                return {"ok": False, "action": "restore",
                        "note": "再次定位该条目失败（回收站可能刚被别的程序改动过），请重试"}
            verb = _find_verb(hit, ("还原", "restore", "复原"))
            if not verb:
                return {"ok": False, "action": "restore", "item": target_item,
                        "note": "找不到该条目的「还原」动词（系统语言/外壳扩展可能不支持），"
                                "请在资源管理器里手动还原"}
            hit.InvokeVerb(verb)
        except Exception as e:
            return {"ok": False, "action": "restore", "item": target_item,
                    "note": f"调用还原失败：{e}"}
        return {"ok": True, "action": "restore", "dry_run": False,
                "item": target_item, "restored_to": target_item.get("original_path"),
                "note": f"已还原 {target_item.get('name')!r} 到 {orig}（用的是系统的「{verb}」动作）"}

    # ── action=delete：把文件移进回收站 ──
    try:
        target = _norm(path)
    except ValueError as e:
        return {"ok": False, "action": "delete", "refused": True,
                "note": f"路径无效：{e}"}
    if not os.path.exists(target):
        return {"ok": False, "action": "delete", "path": target,
                "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    reason = system_zone_reason(target, "删除")
    if reason:
        return {"ok": False, "action": "delete", "refused": True, "path": target,
                "note": f"拒绝移入回收站：{reason}"}
    is_dir = os.path.isdir(target)
    n_files, n_bytes = (1, os.path.getsize(target)) if not is_dir else _dir_size(target)
    if dry_run:
        return {"ok": False, "action": "delete", "dry_run": True, "path": target,
                "type": "dir" if is_dir else "file",
                "file_count": n_files, "total_bytes": int(n_bytes),
                "total_mb": round(n_bytes / 1048576, 2),
                "note": f"只读预览：未删除。真执行会把{'目录' if is_dir else '文件'} {target} "
                        f"移入回收站（{n_files} 个文件 / {_fmt_size(n_bytes)}，"
                        f"可再从回收站还原），需显式传 dry_run=False"}
    ok, msg = _to_recycle_bin(target)
    return {"ok": ok, "action": "delete", "dry_run": False, "path": target,
            "type": "dir" if is_dir else "file", "file_count": n_files,
            "note": msg + "（可从回收站还原）" if ok else msg}


_MAX_SCAN_FILES = 200000        # 数目录大小时最多数这么多文件，防超大树把预览卡死


def _dir_size(root: str) -> tuple[int, int]:
    """目录快照：(文件数, 总字节)。数不到大小的按 0 计，不中断整次扫描。"""
    files = 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            files += 1
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
            if files >= _MAX_SCAN_FILES:
                return files, total
    return files, total


__all__ = ["shell_shortcut_read", "shell_shortcut_write", "shell_recycle"]
