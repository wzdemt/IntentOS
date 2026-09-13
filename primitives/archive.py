"""归档域原语 —— 看压缩包里有什么 / 解压 / 打包（archive.*）。

零依赖：只用 stdlib（zipfile / tarfile / os / shutil），不装任何第三方库。

**三个动作的安全分级**
  · `archive.list`   —— 只读：只看目录，**不解压一个字节**（zip 读中央目录、tar 读头）。
  · `archive.extract`—— **本批安全增量最大的一条**：解压会把「压缩包里的名字」变成
    「磁盘上的路径」，而压缩包是不可信输入。两道防线见下面「解压的两道防线」。
  · `archive.create` —— 会写盘：`dry_run` 默认 True。

**跟 Bandizip / 7-Zip 比，做得到与做不到的**
  · 做得**比 Bandizip 对**：中文名不乱码 —— 自动在 UTF-8 / GBK 之间挑（见下节）。
  · 做得**跟 Bandizip 一样**：智能解压 `auto_folder`，语义与它的 `-target:auto` 实测对齐。
  · **明确不做**（是「不做」，不是「还没做」—— 零依赖只用 stdlib 是硬约束）：
    7z / rar / iso / zipx / lzh、分卷包、加密解密。但**认得出**，会直接告诉调用方
    该拿什么工具开，而不是丢一句「无法判断格式」。

**路径判定来自共享层**
  系统禁区判定（`system_zone_reason`）从 `primitives/_common.py` 取（2026-09-11 下沉）——
  **判定只存在一处**，不会出现「改了文件域、忘了压缩域」的分叉。
  ⚠️ 但**不要 `from primitives.fs import ...`**：那会让 fs.py 被加载第二遍
  （一次叫 `prim_fs`、一次叫 `primitives.fs`），模块级代码跑两次。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_archive，注册进 factory.registry）。
"""
from __future__ import annotations

import fnmatch
import os
import re
import sys
import tarfile
import time
import zipfile

from core.factory import declare_primitive  # type: ignore
from primitives._common import system_zone_reason


# ══════════════════════════════════════════════════════════════════════════
# 路径安全地基（按 fs.py 的思路自备一份：规范化 + 目录边界 + 系统禁区）
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
    """child 是否落在 root 之内（含相等）。按目录边界比对，不会把 C:\\ab 当成在 C:\\a 里。"""
    c = os.path.normcase(os.path.normpath(child)).rstrip("\\/")
    r = os.path.normcase(os.path.normpath(root)).rstrip("\\/")
    return c == r or c.startswith(r + os.sep)


# 系统级禁区：盘根 + 系统目录（解压/打包的落点不接受这些位置）
# ══════════════════════════════════════════════════════════════════════════
# 格式识别
# ══════════════════════════════════════════════════════════════════════════
# 后缀 → 规范格式名。长后缀必须排在短后缀前面（.tar.gz 要先于 .gz 匹配上）。
_SUFFIX_FORMATS = ((".tar.gz", "tar.gz"), (".tgz", "tar.gz"),
                   (".tar.bz2", "tar.bz2"), (".tbz2", "tar.bz2"), (".tbz", "tar.bz2"),
                   (".tar.xz", "tar.xz"), (".txz", "tar.xz"),
                   (".zip", "zip"), (".tar", "tar"),
                   # jar / apk 本质就是 zip 容器，顺手认掉 —— 不然问「这个 jar 里有什么」
                   # 会得到一句「无法判断格式」，那太蠢了
                   (".jar", "zip"), (".apk", "zip"))

# 本库做不了的常见格式 —— 认得出来**就直接说清楚**，别只回一句「无法判断格式」：
# 那句话既没告诉调用方「是什么」，也没告诉它「接下来该用什么」。
# 零依赖只用 stdlib 是这个项目的硬约束，所以这些格式是**明确不做**，不是「还没做」。
_UNSUPPORTED_FORMATS = ((".7z", "7z"), (".rar", "RAR"), (".iso", "ISO 光盘镜像"),
                        (".cab", "CAB"), (".lzh", "LZH"), (".zst", "Zstandard"),
                        (".zipx", "ZIPX"), (".ace", "ACE"), (".arj", "ARJ"))

# 分卷压缩包的后缀：.z01/.z02（zip 分卷）、.001/.002（通用分卷）、.part1（rar 分卷）。
# 单拿一卷出来是解不开的 —— 文件内容是断的，报错还会是「损坏」这种误导性说法。
_VOLUME_SUFFIX = re.compile(r"\.(z\d{2}|part\d+|\d{3})$", re.IGNORECASE)

_FORMAT_ALIASES = {"zip": "zip", "tar": "tar", "tar.gz": "tar.gz", "tgz": "tar.gz",
                   "gzip": "tar.gz", "tar.bz2": "tar.bz2", "tbz2": "tar.bz2",
                   "tar.xz": "tar.xz", "txz": "tar.xz"}


def _fmt_size(nbytes: int) -> str:
    """人话的体积：小于 1 MB 就报 KB / 字节 —— 小归档一律按 MB 四舍五入会全成「0.00 MB」。"""
    n = int(nbytes or 0)
    if n >= 1048576:
        return f"{n / 1048576:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} 字节"


def _detect_format(path: str, fmt: str = "") -> tuple[str, str]:
    """返回 (规范格式名, 中文错误理由)。fmt 给了就用它，否则按后缀认。"""
    if fmt and str(fmt).strip():
        key = str(fmt).strip().lower().lstrip(".")
        got = _FORMAT_ALIASES.get(key)
        if not got:
            return "", (f"不支持的格式 {fmt!r}；可用：zip / tar / tar.gz / tar.bz2 / tar.xz")
        return got, ""
    low = str(path).lower()
    for suf, name in _SUFFIX_FORMATS:
        if low.endswith(suf):
            return name, ""
    base = os.path.basename(str(path))
    # ⚠️ 顺序有讲究：先判分卷。分卷包的后缀（.001 / .z01）本身不指向任何格式，
    # 拿单卷去解会得到「文件已损坏」这种**误导性**结论 —— 而真相是「你只拿到了一卷」。
    if _VOLUME_SUFFIX.search(low):
        return "", (f"{base} 看着是**分卷压缩包的一卷** —— 单卷拿出来内容是断的、解不开，"
                    f"本库不支持分卷。请用 7-Zip / Bandizip 把整组分卷放在一起解开")
    for suf, name in _UNSUPPORTED_FORMATS:
        if low.endswith(suf):
            return "", (f"本库不支持 {name} 格式（{base}）。它零依赖、只用 Python 标准库，"
                        f"能做的是 zip / tar / tar.gz / tar.bz2 / tar.xz；"
                        f"要处理这个包请用 7-Zip / Bandizip")
    return "", (f"无法从文件名判断格式：{base}；"
                f"请用 format 参数指定（zip / tar / tar.gz / tar.bz2 / tar.xz）")


def _tar_mode(fmt: str, writing: bool) -> str:
    """tarfile 的 mode 串。读侧一律用 r:*（自动识别压缩），写侧按格式显式指定。"""
    if not writing:
        return "r:*"
    return {"tar": "w", "tar.gz": "w:gz", "tar.bz2": "w:bz2", "tar.xz": "w:xz"}[fmt]


def _archive_stem(path: str) -> str:
    """压缩包的名字（去掉已知后缀）—— 给「自动套文件夹」当目录名用。

    `.tar.gz` 这种要吃两层后缀，所以得按 `_SUFFIX_FORMATS` 的顺序（长后缀在前）匹配；
    都匹配不上（后缀被改过）就退到「去掉最后一段扩展名」。
    """
    base = os.path.basename(path)
    low = base.lower()
    for suf, _ in _SUFFIX_FORMATS:
        if low.endswith(suf):
            return base[: -len(suf)]
    return os.path.splitext(base)[0]


# ══════════════════════════════════════════════════════════════════════════
# 成员名的编码还原 —— 中文包乱码的解药
# ══════════════════════════════════════════════════════════════════════════
# **问题**：zip 规范要求「文件名含非 ASCII 就设 UTF-8 标志位」（general purpose
# bit 11），但现实里一堆包不设 —— 于是 Python 一律按 cp437 解，中文名全成
# 「▒¿╕µ.txt」，**看目录看不懂，解出来落盘也是乱码名**。
#
# **两类包都不设标志位，存的编码还不一样**（实测）：
#   · 老工具（旧版 WinRAR、部分国产软件）—— 存 GBK 字节
#   · Bandizip 7.37 —— 存 **UTF-8** 字节
# 所以「无标志」时要在这两者之间猜，而猜错的代价比不猜更大（把好名字改成坏的）。
#
# **判据不能是「解得通」**：GBK 几乎什么字节都能解（`fs.read` 里那条经验在这
# 同样成立）—— 「报告」的 UTF-8 字节按 GBK 解是「鎶ュ叡」，解得通、但是错的。
# 做法是两种都解一遍，用 `_name_score` 挑「**更像正常文件名**」的那个；
# **并把「保持原样」也列为一个候选** —— 默认的 cp437 本来就对时不该乱动。
#
# 顺带一提：Bandizip 自己解 GBK 包也认不出来（实测解出 `���ı���.txt`），
# 它按 UTF-8 硬解到底。所以这条不是「追平 Bandizip」，是**比它做得对**。
_NAME_CANDIDATES = ("utf-8", "gbk")


def _name_score(text: str) -> int:
    """这个名字有多像正常文件名。用来在几个候选编码之间挑优。

    cp437 把高位字节解出来的字符很有辨识度 —— 画框、方块、希腊字母、数学符号，
    正常文件名几乎不会用；而**解对了的汉字是强正信号**。
    """
    s = 0
    for ch in text:
        o = ord(ch)
        if o == 0xFFFD:                                        # 替换字符：铁定解错
            s -= 10
        elif 0x2500 <= o <= 0x257F or 0x2580 <= o <= 0x259F:   # ─│┌┐ ░▒▓█
            s -= 3
        elif 0x2200 <= o <= 0x22FF or 0x0390 <= o <= 0x03C9:   # ∞≡  αßΓπ
            s -= 2
        elif 0x00A0 <= o <= 0x00FF:                            # ¡¢£¤¥
            s -= 1
        elif 0x4E00 <= o <= 0x9FFF:                            # 汉字
            s += 2
    return s


def _raw_zip_name(info: zipfile.ZipInfo) -> bytes | None:
    """把「没设 UTF-8 标志」的成员名还原成归档里存的**原始字节**。

    Python 按 cp437 解出来的每个字符都对应一个字节，编回去就是原样。
    编不回去（含 cp437 表外的字符）返回 None —— 那种名字本来就没被误解码。
    """
    try:
        return info.filename.encode("cp437")
    except UnicodeEncodeError:
        return None


def _pick_name_encoding(infos: list) -> tuple[str, str]:
    """这个 zip 的成员名该按什么编码解。返回 (编码名, 人话说明)。

    编码名 "" 有两种含义 ——「默认的 cp437 就够好」与「判不出来」。两者都不改行为，
    区别在说明里：判不出来时会写清楚，好让调用方知道名字可能是坏的、可以手动指定。
    """
    raws: list[bytes] = []
    shown: list[str] = []                   # 可疑成员「按默认解出来的名字」
    for info in infos:
        if info.flag_bits & 0x800:          # 已声明 UTF-8，本来就是对的
            continue
        raw = _raw_zip_name(info)
        if raw is None or all(b < 128 for b in raw):
            continue                        # 纯 ASCII：哪种编码解出来都一样
        raws.append(raw)
        shown.append(info.filename)
    if not raws:
        return "", ""
    # 「保持原样」也进候选 —— 只有**明显更优**才值得动手。
    # 同分时 max 取先出现的那个，也就是保持原样（故意把它排在第一个）。
    cands: list[tuple[str, int]] = [("", sum(_name_score(n) for n in shown))]
    for enc in _NAME_CANDIDATES:
        total = 0
        for raw in raws:
            try:
                total += _name_score(raw.decode(enc))
            except UnicodeDecodeError:
                total = None
                break                       # 有一个解不通，整包就不认这个编码
        if total is not None:
            cands.append((enc, total))
    enc, _score = max(cands, key=lambda c: c[1])
    if not enc:
        return "", (f"有 {len(raws)} 个成员名疑似乱码（压缩工具没按规范写编码），"
                    f"自动判断不出该用哪种，保持原样")
    return enc, ""


def _open_zip(path: str, name_encoding: str = "auto"):
    """打开 zip，并尽量把中文成员名还原成可读的。

    name_encoding 传 "auto"（默认）自动判；也可强制 "utf-8" / "gbk"，
    或传 "cp437" / "none" 表示**不还原**（要原样字节时用）。

    返回 `(ZipFile 或 None, meta, 错误理由)`。meta 含 `name_encoding`（实际用的编码，
    "" = 没动）与 `name_note`（人话说明，顺利时为空）。**调用方负责关闭 zf。**
    """
    meta = {"name_encoding": "", "name_note": ""}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        return None, meta, f"不是有效的 zip 文件（可能已损坏或被改过后缀）：{e}"
    except FileNotFoundError:
        return None, meta, f"压缩包不存在：{path}"
    except PermissionError:
        return None, meta, f"没有读取权限：{path}"
    except OSError as e:
        return None, meta, f"打开压缩包失败：{e}"

    want = str(name_encoding or "auto").strip().lower()
    if want in ("", "auto"):
        enc, note = _pick_name_encoding(zf.infolist())
        meta["name_note"] = note
    elif want in ("cp437", "none", "raw"):
        enc = ""                            # 调用方明确要求保持原样
    else:
        enc = want
    if not enc:
        return zf, meta, ""
    if sys.version_info < (3, 11):
        # metadata_encoding 是 3.11 才加的。低版本只能改 ZipInfo.filename，
        # 但那样 zf.open(名字) 会在内部字典里查不到（键没跟着改），得连带维护
        # 私有索引 —— 不值当。**宁可名字是乱的，也不能让解压功能坏掉。**
        meta["name_note"] = (f"名字可能是乱码：识别出该用 {enc} 还原，但那需要 Python 3.11+，"
                             f"当前是 {sys.version_info.major}.{sys.version_info.minor}")
        return zf, meta, ""
    zf.close()                              # metadata_encoding 只能在构造时给 → 重开一次
    try:
        zf = zipfile.ZipFile(path, metadata_encoding=enc)
    except Exception as e:
        return None, meta, f"按 {enc} 重新打开压缩包失败：{e}"
    meta["name_encoding"] = enc
    return zf, meta, ""


# ══════════════════════════════════════════════════════════════════════════
# 压缩包成员清单（list 与 extract 共用）—— 统一成同一种「成员档案」
# ══════════════════════════════════════════════════════════════════════════
class _Entry:
    """压缩包里的一个成员（zip / tar 归一化后的统一视图）。"""
    __slots__ = ("name", "size", "packed", "is_dir", "is_link", "mtime", "encrypted")

    def __init__(self, name: str, size: int, packed: int, is_dir: bool,
                 is_link: bool = False, mtime: float | None = None,
                 encrypted: bool = False):
        self.name = name
        self.size = size                    # 解压后大小（**声明值**，不可全信）
        self.packed = packed                # 压缩后大小（tar 无此项，按归档总大小摊）
        self.is_dir = is_dir
        self.is_link = is_link              # 符号链接 / 硬链接成员（解压时一律拒绝）
        self.mtime = mtime
        self.encrypted = encrypted


_MAX_SCAN_MEMBERS = 200000      # 清单阶段最多读这么多条，防超长归档把扫描卡死


def _zip_mtime(info: zipfile.ZipInfo) -> float | None:
    """zip 的 date_time 是本地时间元组 → 时间戳。字段不合法（有些写入器给 1980-0-0）就返回 None，
    解压时只是少还原一个时间戳，不值得让它抛异常。"""
    try:
        return time.mktime(tuple(info.date_time) + (0, 0, -1))
    except (ValueError, OverflowError, TypeError):
        return None


def _read_entries(path: str, fmt: str, name_encoding: str = "auto"
                  ) -> tuple[list[_Entry], dict, str]:
    """把压缩包读成 _Entry 列表。**不解压内容**：zip 读中央目录、tar 只读头部。

    返回 `(成员列表, meta, 中文错误理由)`。meta 见 `_open_zip`。
    """
    entries: list[_Entry] = []
    meta: dict = {"name_encoding": "", "name_note": ""}
    if fmt == "zip":
        zf, meta, err = _open_zip(path, name_encoding)
        if err:
            return [], meta, err
        try:
            for info in zf.infolist():
                entries.append(_Entry(
                    name=info.filename,
                    size=int(info.file_size or 0),
                    packed=int(info.compress_size or 0),
                    is_dir=info.is_dir(),
                    # unix 权限位高 16 位里 S_IFLNK 置位 = 符号链接成员
                    is_link=(info.external_attr >> 16) & 0xF000 == 0xA000,
                    mtime=_zip_mtime(info),
                    encrypted=bool(info.flag_bits & 0x1),
                ))
                if len(entries) >= _MAX_SCAN_MEMBERS:
                    break
        finally:
            zf.close()
        return entries, meta, ""
    # tar 侧没有编码问题：tarfile 按 UTF-8 / pax 处理，中文名读出来就是对的（实测）
    try:
        with tarfile.open(path, _tar_mode(fmt, False)) as tf:
            for info in tf:
                entries.append(_Entry(
                    name=info.name,
                    size=int(info.size or 0),
                    packed=0,
                    is_dir=info.isdir(),
                    is_link=bool(info.issym() or info.islnk()),
                    mtime=info.mtime,
                ))
                if len(entries) >= _MAX_SCAN_MEMBERS:
                    break
    except tarfile.TarError as e:
        return [], meta, f"不是有效的 tar 归档（可能已损坏或被改过后缀）：{e}"
    except FileNotFoundError:
        return [], meta, f"压缩包不存在：{path}"
    except PermissionError:
        return [], meta, f"没有读取权限：{path}"
    except OSError as e:
        return [], meta, f"打开压缩包失败：{e}"
    return entries, meta, ""


def _scan(entries: list[_Entry], root: str) -> dict:
    """安全体检：算总量 + 逐条判路径穿越 + 判压缩炸弹。list / extract 共用同一套判定。

    root 为 None 表示「还没有落点」（list 用），此时只做穿越**手法**的静态识别，
    不判「会不会逃出目标目录」（没有目标目录可判）。
    """
    files = [e for e in entries if not e.is_dir]
    total = sum(e.size for e in files)
    unsafe: list[dict] = []            # 路径穿越 / 链接类成员
    for e in entries:
        if e.is_link:
            why = "符号链接/硬链接成员（可在解压后把后续文件引到目标目录之外）"
        elif root:
            _, why = _member_dest(root, e.name)          # 有落点 → 按**规范化后的真实落点**判
        else:
            why = _traversal_hint(e.name)                # 没落点 → 只按字面量识别穿越手法
        if why:
            unsafe.append({"name": e.name, "reason": why})
    return {"files": files, "dirs": [e for e in entries if e.is_dir],
            "total_bytes": total, "unsafe": unsafe}


def _traversal_hint(name: str) -> str:
    """没有落点时，仅按名字字面量识别穿越手法（.. 段 / 绝对路径 / 盘符 / 冒号）。"""
    raw = (name or "").replace("\\", "/")
    segs = [s for s in raw.split("/") if s not in ("", ".")]
    if raw.startswith("/"):
        return "绝对路径成员（Unix 风格，解压会跑到目标目录之外）"
    if re.match(r"^[A-Za-z]:", raw):
        return "带盘符的绝对路径成员"
    if any(s == ".." for s in segs):
        return "含 .. 的路径穿越成员"
    if ":" in raw:
        return "名字里含冒号（Windows 下会写成 NTFS 数据流，隐藏内容）"
    return ""


def _member_dest(root: str, name: str) -> tuple[str, str]:
    """把成员名解析成落点绝对路径，并确认它落在 root 之内。

    返回 (落点路径, 中文拒绝理由)。**这是路径穿越的唯一收口** —— 无论压缩包里的名字
    写成 `..\\..\\Windows\\x`、`/etc/passwd`、`C:\\x` 还是 `a/../../b`，都在这里被规范化
    之后按**真实落点**判定，而不是按字面量猜。
    """
    raw = (name or "").replace("\\", "/")           # ⚠️ 先把反斜杠当分隔符：`..\..\` 是常见攻击写法
    if not raw.strip("/"):
        return "", "成员名为空或只有分隔符"
    if raw.startswith("/"):
        return "", "绝对路径成员（Unix 风格，解压会跑到目标目录之外）"
    if re.match(r"^[A-Za-z]:", raw):
        return "", "带盘符的绝对路径成员"
    segs = [s for s in raw.split("/") if s not in ("", ".")]
    if any(s == ".." for s in segs):
        return "", "含 .. 的路径穿越成员"
    if ":" in raw:
        return "", "名字里含冒号（Windows 下会写成 NTFS 数据流，隐藏内容）"
    dest = os.path.normpath(os.path.join(root, *segs)) if segs else root
    if os.path.normcase(dest) == os.path.normcase(root) or not _inside(dest, root):
        return "", f"规范化后落在目标目录之外（{dest}）"
    return dest, ""


def _bomb_reasons(snap: dict, packed_bytes: int, max_files: int,
                  max_total_mb: int, max_ratio: int) -> list[str]:
    """压缩炸弹判定。返回中文理由列表（空 = 没发现）。

    ⚠️ 用的是**声明大小**（zip 中央目录 / tar 头里的 file_size）—— 这正是要防的东西：
    一个几 KB 的包可以声明解出来有几十 GB。真实解压时还会再按实际写出的字节数兜一次。
    """
    reasons: list[str] = []
    n = len(snap["files"])
    total = snap["total_bytes"]
    if n > max_files:
        reasons.append(f"文件数 {n} 超过上限 {max_files}")
    if total > max_total_mb * 1048576:
        reasons.append(f"解压后总体积约 {total / 1048576:.1f} MB，"
                       f"超过上限 {max_total_mb} MB")
    # 压缩比：小文件天然压得狠（几个字节→1 个字节，比值上千），所以只在体量大了之后才认它
    if packed_bytes > 0 and total > 32 * 1048576:
        ratio = total / packed_bytes
        if ratio > max_ratio:
            reasons.append(f"压缩比 {ratio:.0f}:1 异常偏高（压缩后 {packed_bytes / 1048576:.2f} MB "
                           f"→ 解压后 {total / 1048576:.1f} MB，上限 {max_ratio}:1），疑似压缩炸弹")
    return reasons


# ══════════════════════════════════════════════════════════════════════════
# ① archive.list —— 只看不解压（只读，无 dry_run）
# ══════════════════════════════════════════════════════════════════════════
@declare_primitive(
    "archive.list",
    "查看压缩包里都有哪些文件（**不解压**，只读）。什么时候用：手上有一个 zip / tar / tar.gz，"
    "想知道里面装了什么、有多大，判断要不要解压。"
    "⚠️ **该用谁**：本条只读、**不解压一个字节**；确定要把包解开、落到磁盘上 → 用 archive.extract"
    "（那才是会写盘的那条，默认只预览、真解压需确认）；反过来，要把一批文件收成一个包 → 用 "
    "archive.create。一条链是「看 → 解 → 打包」，本条是链头。"
    "参数怎么填：path 传压缩包路径；格式一般不用管（按后缀自动识别），后缀被改过时可用 format "
    "强制指定（zip / tar / tar.gz / tar.bz2 / tar.xz）；limit 控制最多列出多少条（默认 200）。"
    "返回什么：file_count / dir_count 是文件与目录数；total_bytes / total_mb 是**解压出来总共会有多大**"
    "（这是判断该不该解压的关键数字）；packed_bytes 是压缩包本身大小，ratio 是压缩比；"
    "entries 是成员清单（每条含 name / size / is_dir；目录成员也列出）。"
    "安全提示（重点看这两项）：unsafe_members 列出**路径穿越**嫌疑成员（名字里带 .. 或写成绝对路径，"
    "解压后会跑到目标目录外面），has_traversal=True 时别急着解压；"
    "suspicious=True 表示体积或压缩比像压缩炸弹，suspicion_reasons 说明原因。"
    "注意：本原语返回的 size 是压缩包里**声明**的大小，不可全信（构造过的包会撒谎），"
    "真正的兜底在 archive.extract 里按实际写出的字节数再判一次。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "压缩包绝对路径（zip / tar / tar.gz 等）"},
         "format": {"type": "string",
                    "description": "可选：强制指定格式 zip / tar / tar.gz / tar.bz2 / tar.xz；不给则按后缀认"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 5000,
                   "description": "最多列出多少条成员，默认 200，上限 5000"},
         "name_encoding": {"type": "string",
                           "description": "成员名编码，默认 auto 自动判；判错时可强制 utf-8 / gbk"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "file_count": "文件数", "total_mb": "解压后 MB"},
    block="archive",
)
def archive_list(path: str, format: str = "", limit: int = 200,
                 name_encoding: str = "auto") -> dict:
    try:
        target = _norm(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.isfile(target):
        return {"ok": False, "path": target, "note": "不是文件或不存在（路径已规范化）"}
    fmt, err = _detect_format(target, format)
    if err:
        return {"ok": False, "path": target, "note": err}
    try:
        limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        limit = 200

    entries, meta, err = _read_entries(target, fmt, name_encoding)
    if err:
        return {"ok": False, "path": target, "format": fmt, "note": err}
    packed = os.path.getsize(target)
    snap = _scan(entries, None)
    total = snap["total_bytes"]
    reasons = _bomb_reasons(snap, packed, 10000, 1024, 500)

    shown = []
    for e in entries[:limit]:
        item = {"name": e.name, "size": e.size,
                "is_dir": e.is_dir, "type": "dir" if e.is_dir else "file"}
        if e.is_link:
            item["type"] = "link"
        if e.encrypted:
            item["encrypted"] = True
        shown.append(item)

    unsafe = snap["unsafe"]
    enc_n = sum(1 for e in entries if e.encrypted)
    note = (f"共 {len(snap['files'])} 个文件 + {len(snap['dirs'])} 个目录，"
            f"解压后约 {_fmt_size(total)}（压缩包自身 {_fmt_size(packed)}）")
    if meta["name_encoding"]:
        note += (f"；成员名按 {meta['name_encoding']} 还原"
                 f"（原包没按规范标编码位，不还原的话是乱码）")
    if meta["name_note"]:
        note += "；" + meta["name_note"]
    if enc_n:
        note += (f"；⚠️ 有 {enc_n} 个成员**是加密的** —— 本库只列表不解密，"
                 f"要看内容请用 7-Zip / Bandizip 输密码")
    if len(entries) > limit:
        note += f"；成员清单只列了前 {limit} 条"
    if unsafe:
        note += f"；⚠️ 有 {len(unsafe)} 个成员路径可疑（见 unsafe_members），解压前请留意"
    if reasons:
        note += "；⚠️ " + "；".join(reasons)
    return {"ok": True, "path": target, "format": fmt,
            "file_count": len(snap["files"]), "dir_count": len(snap["dirs"]),
            "total_bytes": total, "total_mb": round(total / 1048576, 2),
            "packed_bytes": packed, "packed_mb": round(packed / 1048576, 2),
            "ratio": round(total / packed, 1) if packed else None,
            "entries": shown,
            "name_encoding": meta["name_encoding"],
            "encrypted_count": enc_n,
            "entries_truncated": len(entries) > limit or len(entries) >= _MAX_SCAN_MEMBERS,
            "has_traversal": bool(unsafe),
            "unsafe_members": unsafe[:20],
            "unsafe_truncated": len(unsafe) > 20,
            "suspicious": bool(reasons),
            "suspicion_reasons": reasons,
            "note": note}


# ══════════════════════════════════════════════════════════════════════════
# ② archive.extract —— 解压（会改状态：dry_run 默认 True + 需确认）
# ══════════════════════════════════════════════════════════════════════════
# 解压的两道防线（这是本批安全增量最大的一条，两道都必须有）
# ─────────────────────────────────────────────────────────────────────────
# ① **路径穿越**：压缩包是不可信输入，成员名可以是 `..\..\Windows\System32\x.dll`、
#    `/etc/passwd`、`C:\x`、`a/../../b` —— 直接拼路径解压就会写到目标目录之外（覆盖系统文件、
#    往启动目录塞东西）。**每一条成员**都先 `_member_dest()` 规范化，确认落点在目标目录**之内**
#    才放行；任一条不合法就**整包拒绝**并指名道姓说清是哪一条（不做「跳过坏的、解好的」——
#    那种「部分成功」最难排查）。符号链接 / 硬链接成员一律拒绝：它能把后续成员引到目录外。
# ② **压缩炸弹**：几 KB 的包解出来几十 GB，撑爆磁盘。两道数字上限 —— 解压后**总体积**
#    （max_total_mb）与**文件数**（max_files），超了就中止并说明；另加压缩比异常检测。
#    ⚠️ 判定用的是成员**声明**的大小，所以**真解压时还按实际写出的字节数再兜一次**
#    （有包会谎报大小）：一旦写出量超过上限，立刻停手并清掉半个文件。
@declare_primitive(
    "archive.extract",
    "解压压缩包到指定目录（zip / tar / tar.gz 等）。什么时候用：先把压缩包解开才能看/用里面的"
    "文件。⚠️ 会往磁盘写文件，且**需用户确认**。"
    "⚠️ **该用谁**：只想看看包里有什么、还没决定要不要解压 → 用 archive.list"
    "（只读、不解压一个字节，且能提前看到路径穿越 / 压缩炸弹的嫌疑成员）；"
    "要把一批文件收成一个包 → 用 archive.create。本条是会真的往磁盘写的那条。"
    "参数怎么填：path 传压缩包路径；target 传解压到哪个目录（不存在会自动创建）；"
    "只想解一部分就传 members（成员名列表，名字用 archive.list 拿到）；"
    "目标位置已有同名文件时默认**拒绝**，确认要覆盖传 overwrite=True。"
    "安全（两道防线，都会在返回里说明）：① 路径穿越 —— 压缩包里带 .. 或写成绝对路径的成员会被拦下，"
    "**整包拒绝**并告诉你是哪一条，不会「跳过坏的解好的」；符号链接成员一律拒绝。"
    "② 压缩炸弹 —— 解压后总体积超过 max_total_mb、或文件数超过 max_files、或压缩比异常偏高，"
    "一律中止。"
    "返回什么：预览给 file_count / dir_count / total_mb / 会不会覆盖 / will_create_target；"
    "refused=True 表示被安全规则拦下（note 里是中文理由，blocked_members 列出问题成员）；"
    "真解压给 extracted_files / extracted_bytes，partial=True 表示中途停手（note 说明原因）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "压缩包绝对路径"},
         "target": {"type": "string", "description": "解压到哪个目录（绝对路径，不存在会自动创建）"},
         "members": {"type": "array", "items": {"type": "string"},
                     "description": "可选：只解这些成员（名字用 archive.list 拿到的原样名字）"},
         "format": {"type": "string",
                    "description": "可选：强制指定格式；不给则按后缀认"},
         "overwrite": {"type": "boolean",
                       "description": "目标位置已有同名文件时是否允许覆盖，默认 False（拒绝）"},
         "max_total_mb": {"type": "integer", "minimum": 1, "maximum": 102400,
                          "description": "解压后总体积上限（MB），默认 1024，上限 102400（100GB）"},
         "max_files": {"type": "integer", "minimum": 1, "maximum": 1000000,
                       "description": "解压文件数上限，默认 10000，上限 1000000"},
         "auto_folder": {"type": "boolean",
                         "description": "包内顶层项 ≥2 个时，自动在 target 下建一层与包同名的"
                                        "目录再解（避免散文件糊满目标目录），默认 False"},
         "name_encoding": {"type": "string",
                           "description": "成员名编码，默认 auto 自动判；判错时可强制 utf-8 / gbk"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真解压"},
     },
     "required": ["path", "target"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"path": "压缩包", "target": "目标目录", "extracted_files": "已解出文件数"},
    block="archive",
)
def archive_extract(path: str, target: str, members: list | None = None, format: str = "",
                    overwrite: bool = False, max_total_mb: int = 1024,
                    max_files: int = 10000, auto_folder: bool = False,
                    name_encoding: str = "auto", dry_run: bool = True) -> dict:
    try:
        src = _norm(path)
    except ValueError as e:
        return {"extracted": False, "refused": True, "path": str(path), "note": f"路径无效：{e}"}
    try:
        dst = _norm(target)
    except ValueError as e:
        return {"extracted": False, "refused": True, "target": str(target),
                "note": f"目标路径无效：{e}"}
    if not os.path.isfile(src):
        return {"extracted": False, "path": src, "target": dst,
                "note": "压缩包不存在（路径已规范化，可能原写法被改写过）"}
    reason = system_zone_reason(dst, "解压")
    if reason:
        return {"extracted": False, "refused": True, "path": src, "target": dst,
                "note": f"拒绝解压：{reason}"}
    fmt, err = _detect_format(src, format)
    if err:
        return {"extracted": False, "refused": True, "path": src, "target": dst, "note": err}
    try:
        max_total_mb = max(1, min(int(max_total_mb), 102400))
    except (TypeError, ValueError):
        max_total_mb = 1024
    try:
        max_files = max(1, min(int(max_files), 1000000))
    except (TypeError, ValueError):
        max_files = 10000

    entries, meta, err = _read_entries(src, fmt, name_encoding)
    if err:
        return {"extracted": False, "path": src, "target": dst, "format": fmt, "note": err}

    # 加密成员数：本库**不解密**，但得在预览阶段就说清楚，别等真解压炸了才提
    enc_n = sum(1 for e in entries if e.encrypted)

    # ── 自动套文件夹（Bandizip「智能解压」的语义，实测确认）──
    # 包内只有**一个顶层目录**时照常展开（那个目录自己就是一层）；否则在目标下再建一层
    # 与包同名的目录 —— 免得一堆散文件直接糊满目标目录。
    # ⚠️ 必须在 members 过滤**之前**判：顶层结构是整个包的性质，与「只解哪几个」无关。
    folded = ""
    if auto_folder:
        tops = {e.name.replace("\\", "/").strip("/").split("/")[0] for e in entries}
        tops.discard("")
        # 规则很朴素（照 Bandizip 实测）：顶层项只有 1 个就不套、2 个及以上才套 ——
        # **不看它是文件还是目录**。单文件包也不套（解出来就一个文件躺在目标目录里，
        # 再套一层纯属多余）。
        # ⚠️ 别想当然判「有目录条目才算目录」：很多包**不写目录条目**，目录靠路径隐式
        # 表示 —— 那样判会把「只有一个目录」误判成需要套壳（写这版时踩过这个坑）。
        if len(tops) != 1:
            folded = _archive_stem(src) or "解压结果"
            dst = os.path.join(dst, folded)
            # ⚠️ 落点变了就**重新过一次禁区判定** —— 不能拿旧落点的结论当数
            reason = system_zone_reason(dst, "解压")
            if reason:
                return {"extracted": False, "refused": True, "path": src, "target": dst,
                        "note": f"拒绝解压：{reason}"}

    # 只解指定成员时，先确认名字都对得上（写错名字直接告诉调用方，别默默解出个空目录）
    if members:
        want = {str(m).replace("\\", "/") for m in members}
        have = {e.name.replace("\\", "/") for e in entries}
        missing = sorted(want - have)
        if missing:
            return {"extracted": False, "refused": True, "path": src, "target": dst,
                    "note": f"members 里有压缩包中不存在的名字：{missing[:5]}"
                            f"（名字要和 archive.list 给的一模一样）"}
        entries = [e for e in entries if e.name.replace("\\", "/") in want]

    # ── 防线①：逐条成员规范化后确认落在目标目录内（不合法就整包拒绝）──
    plan: list[tuple[_Entry, str]] = []
    blocked: list[dict] = []
    for e in entries:
        if e.is_link:
            blocked.append({"name": e.name,
                            "reason": "符号链接/硬链接成员（可把后续文件引到目标目录之外）"})
            continue
        dest, why = _member_dest(dst, e.name)
        if why:
            blocked.append({"name": e.name, "reason": why})
            continue
        plan.append((e, dest))
    if blocked:
        return {"extracted": False, "refused": True, "path": src, "target": dst, "format": fmt,
                "dry_run": bool(dry_run), "blocked_members": blocked[:20],
                "blocked_count": len(blocked),
                "note": f"拒绝解压：压缩包里有 {len(blocked)} 个成员的名字会落到目标目录之外"
                        f"（疑似路径穿越攻击），第一个是 {blocked[0]['name']!r} —— "
                        f"{blocked[0]['reason']}。整包已拒绝，未解出任何文件。"}

    files = [p for p in plan if not p[0].is_dir]
    dirs = [p for p in plan if p[0].is_dir]
    total = sum(e.size for e, _ in files)

    # ── 防线②：压缩炸弹（体积 / 文件数 / 压缩比）──
    packed = os.path.getsize(src)
    snap = {"files": [e for e, _ in files], "dirs": [e for e, _ in dirs],
            "total_bytes": total, "unsafe": []}
    reasons = _bomb_reasons(snap, packed, max_files, max_total_mb, 500)

    # 同名冲突：默认拒绝，绝不默默覆盖用户文件
    conflicts = [d for _, d in plan if os.path.exists(d) and not os.path.isdir(d)]
    if reasons:
        return {"extracted": False, "refused": True, "path": src, "target": dst, "format": fmt,
                "dry_run": bool(dry_run), "total_mb": round(total / 1048576, 2),
                "suspicion_reasons": reasons,
                "note": "拒绝解压（疑似压缩炸弹）：" + "；".join(reasons)
                        + "。整包已拒绝，未解出任何文件；确有需要请调大 max_total_mb / max_files"}
    if conflicts and not overwrite:
        return {"extracted": False, "refused": True, "path": src, "target": dst, "format": fmt,
                "dry_run": bool(dry_run), "conflicts": conflicts[:20],
                "conflict_count": len(conflicts),
                "note": f"目标位置已存在 {len(conflicts)} 个同名文件：{conflicts[:3]}。"
                        f"不会默默覆盖 —— 确认要覆盖请显式传 overwrite=True"}

    will_mkdir = not os.path.isdir(dst)
    mb = round(total / 1048576, 2)

    if dry_run:
        return {"extracted": False, "dry_run": True, "path": src, "target": dst, "format": fmt,
                "file_count": len(files), "dir_count": len(dirs),
                "total_bytes": total, "total_mb": mb,
                "overwrite": bool(overwrite), "will_create_target": will_mkdir,
                "conflicts": conflicts[:20], "conflict_count": len(conflicts),
                "name_encoding": meta["name_encoding"],
                "folded": folded,
                "encrypted_count": enc_n,
                "top_level": sorted({e.name.replace("\\", "/").split("/")[0] for e, _ in plan})[:10],
                "note": f"只读预览：未解压。真执行会把 {len(files)} 个文件 + {len(dirs)} 个目录"
                        f"（解压后约 {_fmt_size(total)}）解到 {dst}"
                        + ("（目录不存在，会先创建）" if will_mkdir else "")
                        + (f"（{len(conflicts)} 个同名文件将被覆盖）" if conflicts else "")
                        + (f"；已按包名自动套了一层目录 {folded}" if folded else "")
                        + (f"；⚠️ 有 {enc_n} 个成员**是加密的**，真解压会失败 —— 本库不解密，"
                           f"要内容请用 7-Zip / Bandizip 输密码" if enc_n else "")
                        + (f"；成员名按 {meta['name_encoding']} 还原（原包没标编码位）"
                           if meta["name_encoding"] else "")
                        + "，需显式传 dry_run=False"}

    # ── 真解压：逐条写，边写边按**实际字节数**再兜一次上限 ──
    written = 0
    written_bytes = 0
    limit_bytes = max_total_mb * 1048576
    # 目录先建：否则后面建文件时会把目录的 mtime 顶掉，解出来的目录时间戳全是「刚刚」
    plan.sort(key=lambda p: not p[0].is_dir)
    try:
        if will_mkdir:
            os.makedirs(dst, exist_ok=True)
        if fmt == "zip":
            # ⚠️ 必须跟读清单时用**同一个**编码 —— zf.open() 认的是 metadata_encoding 那套
            # 名字，两边不一致就会出现「名单是好的、落盘的名字是乱的」这种最难查的不一致。
            zf, _m2, zerr = _open_zip(src, name_encoding)
            if zerr:
                return {"extracted": False, "path": src, "target": dst, "format": fmt,
                        "dry_run": False, "note": f"重新打开压缩包失败：{zerr}"}
            try:                                             # 开一次、复用，别每个成员开一遍
                for e, dest in plan:
                    if e.is_dir:
                        os.makedirs(dest, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(dest) or dst, exist_ok=True)
                    try:
                        stream = zf.open(e.name)
                    except RuntimeError as ex:               # 加密包会在这里炸
                        raise OSError(f"成员 {e.name!r} 打不开（包被加密了？本库不解密，"
                                      f"请用 7-Zip / Bandizip 输密码）：{ex}")
                    with stream:
                        got = _write_stream(stream, dest, limit_bytes - written_bytes, e.name)
                    written += 1
                    written_bytes += got
                    _touch_mtime(dest, e.mtime)
            finally:
                zf.close()
        else:
            with tarfile.open(src, _tar_mode(fmt, False)) as tf:
                by_name = {m.name: m for m in tf.getmembers()}   # 建索引：getmember 是线性扫
                for e, dest in plan:
                    if e.is_dir:
                        os.makedirs(dest, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(dest) or dst, exist_ok=True)
                    member = by_name.get(e.name)
                    stream = tf.extractfile(member) if member is not None else None
                    if stream is None:                       # 设备文件 / FIFO 之类，没有内容
                        continue
                    with stream:
                        got = _write_stream(stream, dest, limit_bytes - written_bytes, e.name)
                    written += 1
                    written_bytes += got
                    _touch_mtime(dest, e.mtime)
    except _BombAbort as e:
        return {"extracted": False, "refused": True, "partial": True, "path": src,
                "target": dst, "format": fmt, "dry_run": False,
                "extracted_files": written, "extracted_bytes": written_bytes,
                "note": f"解压中途停手：{e}。已解出的 {written} 个文件留在 {dst}，请自行清理"}
    except Exception as e:
        return {"extracted": False, "partial": True, "path": src, "target": dst, "format": fmt,
                "dry_run": False, "extracted_files": written,
                "note": f"解压失败（已解出 {written} 个文件）：{e}"}
    return {"extracted": True, "dry_run": False, "path": src, "target": dst, "format": fmt,
            "extracted_files": written, "extracted_dirs": len(dirs),
            "extracted_bytes": written_bytes, "total_mb": round(written_bytes / 1048576, 2),
            "overwrote": bool(conflicts), "will_create_target": will_mkdir,
            "name_encoding": meta["name_encoding"], "folded": folded,
            "note": f"已解压 {written} 个文件 + {len(dirs)} 个目录到 {dst}"
                    f"（共 {_fmt_size(written_bytes)}）"
                    + (f"；已按包名自动套了一层目录 {folded}" if folded else "")
                    + (f"；成员名按 {meta['name_encoding']} 还原（原包没标编码位）"
                       if meta["name_encoding"] else "")}


class _BombAbort(Exception):
    """解压中途发现实际写出的字节数超过上限 —— 用它把控制流从写循环里抛出来。"""


def _write_stream(stream, dest: str, budget: int, member_name: str) -> int:
    """把成员流写到 dest，返回写出的字节数。

    ⚠️ 按**实际写出的字节数**封顶（budget 是剩余额度）：成员的声明大小可以撒谎，
    所以不能只看 _bomb_reasons 那一关 —— 一边写一边数，超了立刻抛 _BombAbort。
    """
    chunk = 1024 * 1024
    got = 0
    with open(dest, "wb") as out:
        while True:
            blk = stream.read(chunk)
            if not blk:
                break
            got += len(blk)
            if got > budget:
                out.close()                     # Windows 上要先关掉才能删
                _cleanup_half(dest)
                raise _BombAbort(f"成员 {member_name!r} 解出来的实际体积已超出总量上限")
            out.write(blk)
    return got


def _cleanup_half(dest: str) -> None:
    """清掉写了一半的文件 —— 别在磁盘上留个「看着像完整文件」的残骸。"""
    try:
        os.unlink(dest)
    except OSError:
        pass


def _touch_mtime(dest: str, mtime: float | None) -> None:
    """把归档里记的修改时间还回去（失败就算了，时间戳不值得让整次解压失败）。"""
    if not mtime:
        return
    try:
        os.utime(dest, (mtime, mtime))
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════════
# ③ archive.create —— 打包（会写盘：dry_run 默认 True）
# ══════════════════════════════════════════════════════════════════════════
def _match_any(rel: str, name: str, patterns: list[str]) -> str | None:
    """rel（相对路径）或 name（文件名）命中任一 glob 模式则返回该模式，否则 None。"""
    for pat in patterns:
        p = str(pat)
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p):
            return p
        # `*.log` 这类模式按 fnmatch 匹配不上 `sub/a.log` —— 补一条「任一层级」的匹配
        if p.startswith("*") and fnmatch.fnmatch(rel, "*" + p):
            return p
    return None


def _collect(sources: list[str], exclude: list[str], include: list[str]
             ) -> tuple[list[tuple[str, str]], dict, str]:
    """把 sources 展开成 [(源绝对路径, 归档内名字)]。返回 (清单, 统计, 错误理由)。"""
    items: list[tuple[str, str]] = []
    stats = {"skipped_excluded": 0, "skipped_not_included": 0, "dirs": 0, "bytes": 0}
    for s in sources:
        raw = str(s)
        try:
            abs_src = _norm(raw)
        except ValueError as e:
            return [], stats, f"源路径无效 {raw!r}：{e}"
        if not os.path.exists(abs_src):
            return [], stats, f"源路径不存在：{abs_src}"
        base = os.path.dirname(abs_src)
        if os.path.isfile(abs_src):
            name = os.path.basename(abs_src)
            if exclude and _match_any(name, name, exclude):
                stats["skipped_excluded"] += 1
                continue
            if include and not _match_any(name, name, include):
                stats["skipped_not_included"] += 1
                continue
            items.append((abs_src, name))
            stats["bytes"] += os.path.getsize(abs_src)
            continue
        for dirpath, dirnames, filenames in os.walk(abs_src):
            for fn in sorted(filenames):
                fp = os.path.join(dirpath, fn)
                rel = os.path.relpath(fp, base)              # 归档内名字：保留最外层目录名
                arc = rel.replace(os.sep, "/")
                if exclude and _match_any(rel, fn, exclude):
                    stats["skipped_excluded"] += 1
                    continue
                if include and not _match_any(rel, fn, include):
                    stats["skipped_not_included"] += 1
                    continue
                items.append((fp, arc))
                try:
                    stats["bytes"] += os.path.getsize(fp)
                except OSError:
                    pass                                    # 数不到大小按 0 计，别中断整次打包
            stats["dirs"] += len(dirnames)
    return items, stats, ""


@declare_primitive(
    "archive.create",
    "把一个或多个文件/目录打包成压缩包（zip / tar / tar.gz）。什么时候用：把一批文件收成一个包"
    "方便传走、备份、归档。**方向别搞反**：本原语是「打包」方向；解开一个包用 archive.extract；"
    "只看包里有什么、还没决定要不要解压用 archive.list。"
    "⚠️ **会往磁盘写文件，而且要过用户确认**：它一次能写出大批文件，与 fs.write / "
    "fs.copy / net.download 等所有落盘操作同一道门。"
    "参数怎么填：sources 传要打包的路径列表（每个文件/目录一项，目录会递归打包，归档里保留最外层"
    "目录名）；target 传输出的压缩包路径（格式按后缀认，也可用 format 强制指定 zip / tar / tar.gz "
    "/ tar.bz2 / tar.xz）；exclude 传要排除的 glob 模式列表（如 ['*.log', 'node_modules', "
    "'__pycache__', '*.tmp']，按文件名和相对路径都匹配）；include 可选，给了就只打包匹配的"
    "（白名单）。"
    "返回什么：预览给 file_count / total_mb / skipped_excluded 排除了几个 / sample 抽样前 20 条；"
    "target 已存在时默认拒绝，要覆盖得显式传 overwrite=True；refused=True 表示被拦下（note 是中文理由）。"
    "注意：空目录不会被打进包（zip/tar 都不记录空目录），别拿它当「空目录也能保真」的备份工具。",
    {"type": "object",
     "properties": {
         "sources": {"type": "array", "items": {"type": "string"},
                     "description": "要打包的文件/目录路径列表（至少一个）"},
         "target": {"type": "string", "description": "输出的压缩包路径（如 D:\\备份\\a.zip）"},
         "format": {"type": "string",
                    "description": "可选：zip / tar / tar.gz / tar.bz2 / tar.xz；不给则按 target 后缀认"},
         "exclude": {"type": "array", "items": {"type": "string"},
                     "description": "可选：排除的 glob 模式列表，如 ['*.log', '__pycache__']"},
         "include": {"type": "array", "items": {"type": "string"},
                     "description": "可选：只打包匹配这些 glob 的文件（白名单）"},
         "overwrite": {"type": "boolean",
                       "description": "target 已存在时是否允许覆盖，默认 False（拒绝）"},
         "create_dirs": {"type": "boolean",
                         "description": "target 的父目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真打包"},
     },
     "required": ["sources", "target"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"target": "压缩包", "file_count": "打包文件数"},
    block="archive",
)
def archive_create(sources: list, target: str, format: str = "",
                   exclude: list | None = None, include: list | None = None,
                   overwrite: bool = False, create_dirs: bool = False,
                   dry_run: bool = True) -> dict:
    if not sources:
        return {"created": False, "refused": True, "note": "sources 不能为空，至少给一个要打包的路径"}
    try:
        out = _norm(target)
    except ValueError as e:
        return {"created": False, "refused": True, "target": str(target),
                "note": f"目标路径无效：{e}"}
    # ⚠️ 落点先过系统禁区：打包是把一堆文件写到一个新位置，落点必须是允许写的地方
    reason = system_zone_reason(out, "打包")
    if reason:
        return {"created": False, "refused": True, "target": out, "note": f"拒绝打包：{reason}"}
    fmt, err = _detect_format(out, format)
    if err:
        return {"created": False, "refused": True, "target": out, "note": err}
    exclude = [str(x) for x in (exclude or [])]
    include = [str(x) for x in (include or [])]

    items, stats, err = _collect(list(sources), exclude, include)
    if err:
        return {"created": False, "refused": True, "target": out, "note": err}
    if not items:
        return {"created": False, "refused": True, "target": out,
                "note": "没有任何文件会进包（都被 exclude/include 排除了，或目录是空的）"}

    existed = os.path.exists(out)
    if existed and not overwrite:
        return {"created": False, "refused": True, "target": out, "target_exists": True,
                "file_count": len(items),
                "note": f"目标已存在：{out}。不会默默覆盖 —— 确认要覆盖请显式传 overwrite=True"}
    parent = os.path.dirname(out)
    need_mkdir = bool(parent) and not os.path.isdir(parent)
    if need_mkdir and not create_dirs:
        return {"created": False, "refused": True, "target": out,
                "note": f"目标的父目录不存在：{parent}（需要时传 create_dirs=True）"}
    total = stats["bytes"]
    mb = round(total / 1048576, 2)

    if dry_run:
        return {"created": False, "dry_run": True, "target": out, "format": fmt,
                "file_count": len(items), "dir_count": stats["dirs"],
                "total_bytes": total, "total_mb": mb,
                "sample": [arc for _, arc in items[:20]],
                "skipped_excluded": stats["skipped_excluded"],
                "skipped_not_included": stats["skipped_not_included"],
                "overwrite": bool(existed and overwrite), "will_create_dirs": need_mkdir,
                "note": f"只读预览：未打包。真执行会把 {len(items)} 个文件（约 {_fmt_size(total)}）"
                        f"打成 {fmt} 格式的 {out}"
                        + (f"（已存在，将被覆盖）" if existed else "")
                        + (f"；排除了 {stats['skipped_excluded']} 个文件" if stats["skipped_excluded"] else "")
                        + ("；会先自动创建父目录" if need_mkdir else "")
                        + "，需显式传 dry_run=False"}

    try:
        if need_mkdir:
            os.makedirs(parent, exist_ok=True)
        if fmt == "zip":
            # ⚠️ 必须显式传 ZIP_DEFLATED：不然 zipfile 默认 ZIP_STORED（只打包不压缩）
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for src_path, arc in items:
                    zf.write(src_path, arc)
        else:
            with tarfile.open(out, _tar_mode(fmt, True)) as tf:
                for src_path, arc in items:
                    tf.add(src_path, arcname=arc, recursive=False)
    except Exception as e:
        return {"created": False, "target": out, "note": f"打包失败：{e}"}
    return {"created": True, "dry_run": False, "target": out, "format": fmt,
            "file_count": len(items), "packed_bytes": os.path.getsize(out),
            "packed_mb": round(os.path.getsize(out) / 1048576, 2),
            "source_bytes": total, "overwrote": bool(existed),
            "skipped_excluded": stats["skipped_excluded"],
            "note": f"已打包 {len(items)} 个文件（源共 {_fmt_size(total)}）到 {out}"
                    f"（压缩后 {_fmt_size(os.path.getsize(out))}）"}


__all__ = ["archive_list", "archive_extract", "archive_create"]
