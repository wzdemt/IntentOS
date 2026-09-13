"""文件与存储域原语 —— 目录视图 / 内容读写 / 生命周期 / 路径安全地基（fs.*）。

不依赖第三方库：用 stdlib(pathlib/os/tempfile) + ctypes(shell32 回收站) 实现，跨平台。
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_fs，注册进 factory.registry）。

本文件含一个**工具函数组（fs.path）而不是原语**：路径规范化 + 穿越检测是「白名单能否成立」
的前提，但它不该被当成一个可供 AI 随意调用的动作暴露出去（它没有副作用，暴露也只是噪音）。
供同域写/删类原语复用；策略层若要接白名单，可直接 import 这三个函数。
"""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from core.factory import declare_primitive  # type: ignore
from primitives._common import (SYSTEM_ROOTS, check_path, is_reparse_point, is_within,
                                normalize_path, system_zone_reason)


# ── 文件系统（stdlib pathlib，跨平台）────────────────────────────────────
@declare_primitive(
    "fs.list",
    "列出目录**第一层**的条目（每条只有名字 + 是文件还是目录）。什么时候用：想知道一个文件夹里"
    "有什么，一层就够、不需要每条的大小和时间时，用它最省。什么时候别用：要每条的**大小和修改"
    "时间**用 fs.entries（一次全给，省得再逐条 fs.size）；要按**文件名**递归找某类文件用 fs.search；"
    "按**文件内容**找用 fs.grep；要看目录的层级结构用 fs.tree；要看单个文件/目录的详情用 fs.stat；"
    "要**读某个文件的内容**用 fs.read（二进制文件用 fs.read_bytes）。"
    "参数怎么填：path 传目录绝对路径（必填）；limit 是本次最多给几条（默认 200，0=不限）；"
    "offset 从第几条开始给（默认 0）—— limit + offset 就是**翻页**。"
    "返回什么：entries 是列表，每条给 name（名字）和 type（dir/file）；"
    "⚠️ **total 才是目录里的真实条目数**，count 是**本次给了几条** —— 两者不同，别混；"
    "truncated=true 表示还有没给的，取下一批传 offset=offset+count（返回按名字排序，翻页才稳定）。"
    "出错时 ok=False（路径不存在 / 不是目录 / 没权限），这时 count 也是 0 —— "
    "⚠️ 所以**光看 count=0 分不清「这是个空目录」和「根本没列成」**，必须看 ok，"
    "note 里是中文原因。"
    "⚠️ **默认有条数上限（200 条）**：大目录整份返回会撑满上下文（node_modules 这种），"
    "但**总数照样给你** —— 看 `total`，别把 `count` 当总数。"
    "只列一层、不递归、不给大小/时间，也不区分链接。"
    "隐藏条目（. 开头的）照样列出 —— 这里**不查 Windows 隐藏属性**"
    "（那个属性要看/改用 fs.attrs）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目录绝对路径"},
         "limit": {"type": "integer", "minimum": 0,
                   "description": "本次最多返回多少条，默认 200；0=不限（大目录会撑满上下文）"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "从第几条开始返回（默认 0），配合 limit 翻页"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"count": "本次条数"},
    block="filesystem",
)
def fs_list(path: str, limit: int = 200, offset: int = 0) -> dict:
    try:
        limit = max(0, int(limit))
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        limit, offset = 200, 0
    try:
        p = Path(path)
        if not p.is_dir():
            return {"ok": False, "total": 0, "count": 0, "offset": 0, "truncated": False,
                    "entries": [], "note": f"不是目录：{path}"}
        rows = sorted([{"name": e.name, "type": "dir" if e.is_dir() else "file"}
                       for e in p.iterdir()], key=lambda e: e["name"])
        total = len(rows)
        # 排完整份再切页：不只是为了翻页稳定，也因为 **total 要的是真实总数**，
        # 排序本身就得看全量。省的是**返回量**（不把几万条塞进上下文），不是内存。
        page = rows[offset:] if limit == 0 else rows[offset:offset + limit]
        cut = offset + len(page) < total
        out = {"ok": True, "total": total, "count": len(page), "offset": offset,
               "truncated": cut, "entries": page}
        if cut:
            out["note"] = (f"目录里共 {total} 条，本次从第 {offset} 条起给了 {len(page)} 条 ——"
                           f" **total 才是总数**；要下一批传 offset={offset + len(page)}")
        elif offset:
            out["note"] = (f"目录里共 {total} 条，本次是从第 {offset} 条起的 {len(page)} 条"
                           f"（已到末尾）")
        return out
    except Exception as e:
        return {"ok": False, "total": 0, "count": 0, "offset": 0, "truncated": False,
                "entries": [], "note": str(e)}


@declare_primitive(
    "fs.entries",
    "列目录，**每条都带大小和修改时间** —— 「这目录里都是什么文件、各多大、什么时候改的」"
    "一次答完。什么时候用：要一份带大小/时间的清单，或想看「谁最占地方」"
    "（sort=size + desc=true）。什么时候别用：只要名字、不要大小时间时用 fs.list 更省"
    "（fs.list 只给名字和类型）；要单个条目的完整元信息（链接指向哪、只读位、创建时间）用 "
    "fs.stat；要**读某个文件的内容**用 fs.read（二进制用 fs.read_bytes）；"
    "要按**文件名**递归找某类文件用 fs.search（按**文件内容**搜用 fs.grep）；"
    "要目录的总体大小用 fs.size、要类型分布用 fs.stats。默认按名字排。无副作用。"
    "返回什么：entries 是列表，每条给 name / type(dir·file) / size_bytes / size_human / "
    "mtime（YYYY-MM-DD HH:MM）/ is_reparse（是不是 junction 或软链接）；count 是条目数；"
    "被 limit 截断时 note 会说明「共 N 条只返回前 limit 条」。"
    "出错时 ok=False（路径不存在 / 不是目录 / 读不到目录），这时 count=0 且 entries=[] —— "
    "⚠️ 与「空目录」同形，靠 ok 区分；note 里是中文原因。"
    "注意：子目录的 size_bytes 给 **null 而不是递归求和** —— 对每个子目录递归会让大目录卡死；"
    "某个条目读不到属性时那条只给 name / type / note，不会毁掉整次列举；"
    "要看**目录的层级结构**用 fs.tree；这里**不查 Windows 隐藏属性**（要查/改用 fs.attrs）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目录绝对路径"},
         "sort": {"type": "string", "enum": ["name", "size", "mtime"],
                  "description": "排序依据，默认 name"},
         "desc": {"type": "boolean",
                  "description": "是否降序（sort=size + desc=true 就是「谁最大」），默认 False"},
         "limit": {"type": "integer", "minimum": 0,
                   "description": "返回条数上限，0=不限（默认）；大于 0 时最多返回这么多条"},
         "include_dirs": {"type": "boolean", "description": "是否包含子目录，默认 True"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"count": "条目数"},
    block="filesystem",
)
def fs_entries(path: str, sort: str = "name", desc: bool = False,
               limit: int = 0, include_dirs: bool = True) -> dict:
    if sort not in ("name", "size", "mtime"):
        return {"ok": False, "count": 0, "entries": [],
                "note": f"未知 sort={sort!r}；可选 name / size / mtime"}
    try:
        norm = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "count": 0, "entries": [], "note": str(e)}
    if not Path(norm).is_dir():
        return {"ok": False, "count": 0, "entries": [], "note": f"不是目录：{path}"}

    rows: list[dict] = []
    try:
        # scandir 比 iterdir + 逐个 stat 省一次系统调用；**一律 follow_symlinks=False** ——
        # 跟着链接走会让 junction 指回祖先（2026-09-11 踩过），取属性同理，一律不跟。
        with os.scandir(norm) as it:
            for e in it:
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                    st = e.stat(follow_symlinks=False)
                    size = None if is_dir else int(st.st_size)
                    rows.append({
                        "name": e.name,
                        "type": "dir" if is_dir else "file",
                        "size_bytes": size,
                        "size_human": _human_size(size) if size is not None else None,
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "is_reparse": is_reparse_point(e.path),
                    })
                except OSError as ex:
                    # 单个条目读不到属性（权限 / 刚好被删）不该毁掉整次列举
                    rows.append({"name": e.name, "type": "?", "note": f"读不到属性：{ex}"})
    except OSError as e:
        return {"ok": False, "count": 0, "entries": [], "note": f"读取目录失败：{e}"}

    if not include_dirs:
        rows = [r for r in rows if r.get("type") == "file"]
    key = {"name": lambda r: str(r.get("name", "")).lower(),
           "size": lambda r: r.get("size_bytes") or 0,
           "mtime": lambda r: str(r.get("mtime") or "")}[sort]
    rows.sort(key=key, reverse=bool(desc))

    total = len(rows)
    out = {"ok": True, "count": total, "path": norm, "sort": sort, "entries": rows}
    if limit and limit > 0 and limit < total:
        out["entries"] = rows[:limit]
        out["note"] = f"共 {total} 条，按 limit={limit} 只返回前 {limit} 条"
    return out


@declare_primitive(
    "fs.search",
    "按**文件名**通配符在目录下递归搜文件，只给匹配到的完整路径。什么时候用：找某类文件，"
    "如某目录下所有 *.md、所有 test_*.py。什么时候别用：按**文件内容**找某段文字/函数名/配置项"
    "用 fs.grep；只想知道某一层有什么、不需要递归，用 fs.list（要大小时间用 fs.entries）；"
    "要看目录结构长什么样用 fs.tree；要知道某个文件多大、什么时候改的用 fs.stat。"
    "参数怎么填：pattern 传通配符（**/*.md 表示跨层递归找 .md，*.md 只匹配当前这一层）；"
    "path 传搜索根目录的绝对路径；两个都必填。"
    "limit 是本次最多给几条（默认 50，0=不限）；offset 从第几条开始给（默认 0）—— 两者合起来翻页。"
    "返回什么：matches 是匹配到的**完整路径字符串**列表；"
    "⚠️ **total 是真正匹配到的总数**，count 是**本次给了几条**；truncated=true 表示还有没给的，"
    "取下一批传 offset=offset+count。列表里只有路径，**没有大小 / 时间 / 类型**"
    "（要这些改用 fs.entries / fs.size / fs.stat）。"
    "⚠️ 两条陷阱：① **默认只给 50 条**（防撑爆上下文）—— 但**总数在 total 里**，"
    "看到 truncated=true 就说明还有，**别把 count 当总数**，翻页或缩小 path / 用更具体的 pattern；"
    "② 出错时 ok=False（note 里是中文原因），此时 count 也是 0。"
    "注意：⚠️ **path 不存在时本原语不报错**，只是 total=0、count=0、ok=True、没有 note，"
    "与「真的没有匹配」完全同形 —— 拿不准先用 fs.stat 确认目录在不在。",
    {"type": "object",
     "properties": {"pattern": {"type": "string",
                                "description": "通配符模式，如 **/*.md（** 表示跨层递归，*.md 只匹配一层）"},
                    "path": {"type": "string", "description": "搜索根目录绝对路径"},
                    "limit": {"type": "integer", "minimum": 0,
                              "description": "本次最多返回多少条，默认 50；0=不限"},
                    "offset": {"type": "integer", "minimum": 0,
                               "description": "从第几条开始返回（默认 0），配合 limit 翻页"}},
     "required": ["pattern", "path"],
     "additionalProperties": False},
    state={"count": "本次匹配数"},
    block="filesystem",
)
def fs_search(pattern: str, path: str, limit: int = 50, offset: int = 0) -> dict:
    try:
        limit = max(0, int(limit))
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        limit, offset = 50, 0
    try:
        root = Path(path)
        # glob 是惰性的：**必须走完才能拿到 total**，但只把该页的路径转成字符串 ——
        # 以前是 `[...][:50]`，先把全部物化成列表再砍，超限时白占一份内存（2026-09-12 审计）。
        total = 0
        page: list[str] = []
        end = (offset + limit) if limit else None
        for p in root.glob(pattern):
            total += 1
            if total > offset and (end is None or total <= end):
                page.append(str(p))
        cut = offset + len(page) < total
        cut = offset + len(page) < total
        out = {"ok": True, "total": total, "count": len(page), "offset": offset,
               "truncated": cut, "matches": page}
        if cut:
            out["note"] = (f"共匹配到 {total} 条，本次从第 {offset} 条起给了 {len(page)} 条 ——"
                           f" **total 才是总数**；要下一批传 offset={offset + len(page)}，"
                           f"或缩小 path / 用更具体的 pattern")
        return out
    except Exception as e:
        return {"ok": False, "total": 0, "count": 0, "offset": 0, "truncated": False,
                "matches": [], "note": str(e)}


# ══════════════════════════════════════════════════════════════════════════
# fs.path —— 路径安全地基（工具函数，**不是原语**，不注册进 registry）
# ══════════════════════════════════════════════════════════════════════════
# 路径安全地基（normalize_path / is_within / check_path / system_zone_reason）
# **已下沉到 `primitives/_common.py`**（2026-09-11）—— 归档域、快捷方式域也在用它，
# 各抄一份的代价是「改一处忘两处」；而这是安全判定，分叉意味着有人能从一个域绕过去。
#
# 为什么不注册成原语：它们没有副作用、也不是「让 AI 干一件事」的动作，而是所有写/删
# 动作共用的前置判定。做成原语只会给模型多一个无用的动作，还可能诱导它自己
# 「先规范化再写」，绕过真正的判定。所以只暴露成函数。
#
# 为什么必须「先规范化再判」：只看字面量的话，靠 `..` 爬升、8.3 短名、长路径前缀、
# 软链接 / junction 四路都能把路径伪装成「看起来不在禁区里」。


def _forbidden_reason(norm: str) -> str | None:
    """删除前的禁区判定。返回中文理由，允许则返回 None。"""
    if len(norm) <= 3 and norm[1:2] == ":":          # C:\ 这种盘根
        return "盘根目录不允许删除"
    for r in SYSTEM_ROOTS + [os.path.expanduser("~")]:
        try:
            if os.path.normcase(norm) == os.path.normcase(os.path.normpath(r)):
                return f"系统/家目录本身不允许删除：{r}"
        except Exception:
            continue
    if is_within(norm, SYSTEM_ROOTS):
        return "系统目录（Windows / Program Files / ProgramData）不允许删除"
    if is_within(os.getcwd(), [norm]):               # 别把当前工作目录的祖先删了
        return "该目录是当前工作目录的上级，不允许删除"
    return None


# ══════════════════════════════════════════════════════════════════════════
# 内容读写（fs.write / fs.append）
# ══════════════════════════════════════════════════════════════════════════
def _prepare_target(path: str, create_dirs: bool, dry_run: bool = False
                    ) -> tuple[str, str | None, bool]:
    """写操作共用的目标预检。返回 (规范化路径, 中文错误理由, 父目录是否会被创建)。

    dry_run=True 时**绝不建目录**（预检本身也是副作用，预览阶段一个字节都不能落盘）；
    此时若父目录不存在且 create_dirs=True，只把「真执行会建目录」这个事实报给调用方。
    """
    try:
        target = normalize_path(path)
    except ValueError as e:
        return "", str(e), False
    p = Path(target)
    if p.exists() and p.is_dir():
        return target, "目标是一个目录，拒绝写入", False
    will_mkdir = False
    if not p.parent.exists():
        if not create_dirs:
            return target, f"父目录不存在：{p.parent}（需要时传 create_dirs=True）", False
        if dry_run:
            will_mkdir = True              # 预览：只声明，不真建
        else:
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                return target, f"创建父目录失败：{e}", False
    return target, None, will_mkdir


@declare_primitive(
    "fs.write",
    "把一个文本文件**整体写入**（新建或覆盖；原子写：先写同目录临时文件再替换，不会留下写到一半"
    "的坏文件）。什么时候用：生成或重写一个文件（配置、脚本、报告）。什么时候别用：只想**在末尾"
    "加内容**（日志、流水记录）用 fs.append —— 它不覆盖原有内容，本原语会覆盖；要临时产物用 "
    "fs.temp；要照搬已有文件用 fs.copy；要**删掉**文件用 fs.delete（把内容写成空串只留下一个空"
    "文件，不等于删掉它）；二进制内容写不了（本原语按文本编码写入）。"
    "参数怎么填：path 传目标文件绝对路径；content 是要写的文本；encoding 默认 utf-8；"
    "父目录不存在时传 create_dirs=True。"
    "返回什么：written=True 才算真写了；path 是规范化后的落点；bytes 是写入字节数；"
    "overwrote=True 表示**覆盖了原有文件**（原内容不可恢复）；encoding 是实际用的编码；"
    "预览时给 dry_run=True、will_create_dirs，written 仍是 False（**别把预览当写成功**）；"
    "失败时 written=False，note 里是中文原因。"
    "安全：**需用户确认**（覆盖不可逆）；路径会先规范化（展开变量、解析 .. 与"
    "软链接）再落盘。注意：写的是**一个文件**，不追加、不合并。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目标文件绝对路径"},
         "content": {"type": "string", "description": "要写入的文本内容"},
         "encoding": {"type": "string", "description": "文本编码，默认 utf-8"},
         "create_dirs": {"type": "boolean", "description": "父目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真写入"},
     },
     "required": ["path", "content"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"written": "是否写入", "path": "路径", "bytes": "字节数"},
    block="filesystem",
)
def fs_write(path: str, content: str, encoding: str = "utf-8",
             create_dirs: bool = False, dry_run: bool = True) -> dict:
    target, err, will_mkdir = _prepare_target(path, create_dirs, dry_run)
    if err:
        return {"written": False, "path": target or path, "bytes": 0, "note": err}
    try:
        data = str(content).encode(encoding)
    except Exception as e:
        return {"written": False, "path": target, "bytes": 0, "note": f"编码失败：{e}"}
    existed = os.path.exists(target)
    # ⚠️ 安全铁律：默认只预览。预览连父目录都不建（预检的副作用也不许发生）。
    if dry_run:
        return {"written": False, "path": target, "bytes": len(data), "dry_run": True,
                "overwrote": existed, "encoding": encoding,
                "will_create_dirs": will_mkdir,
                "note": f"只读预览：未写入。真执行将{'覆盖原文件' if existed else '新建文件'}"
                        f"（{len(data)} 字节）"
                        + ("，并自动创建父目录" if will_mkdir else "")
                        + "，需显式传 dry_run=False"}
    try:
        # 原子写：临时文件落在同一目录（保证 os.replace 是同盘原子操作）
        fd, tmp = tempfile.mkstemp(dir=str(Path(target).parent), prefix=".intentos_", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, target)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        return {"written": False, "path": target, "bytes": 0,
                "note": f"写入失败：{e}"}
    return {"written": True, "path": target, "bytes": len(data),
            "overwrote": existed, "encoding": encoding,
            "note": "已覆盖原文件" if existed else "新建文件"}


@declare_primitive(
    "fs.append",
    "往文件**末尾追加**文本（原有内容不动；文件不存在则新建）。什么时候用：写日志、往清单/记录里"
    "加一行、多次调用累积内容。什么时候别用：要**整体重写或新建**一个文件用 fs.write"
    "（fs.write 覆盖原内容，本原语不覆盖）；要临时产物用 fs.temp。"
    "参数怎么填：path 传目标文件绝对路径；content 是要追加的文本；encoding 默认 utf-8；"
    "父目录不存在时传 create_dirs=True。"
    "返回什么：appended=True 才算真追加了；bytes 是本次追加的字节数；created=True 表示文件是"
    "这次新建的（原来没有）；size_after 是追加后文件的总字节数；预览时给 dry_run=True 与"
    "预估的 size_after，appended 仍是 False（**别把预览当追加成功**）；失败时 appended=False，"
    "note 里是中文原因。"
    "安全：**需用户确认**。注意：只往末尾加，不插入、不覆盖；"
    "**不会自动补换行**（要换行请自己把 \\n 放进 content）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目标文件绝对路径"},
         "content": {"type": "string", "description": "要追加的文本内容"},
         "encoding": {"type": "string", "description": "文本编码，默认 utf-8"},
         "create_dirs": {"type": "boolean", "description": "父目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真追加"},
     },
     "required": ["path", "content"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"appended": "是否已追加", "path": "路径", "bytes": "字节数"},
    block="filesystem",
)
def fs_append(path: str, content: str, encoding: str = "utf-8",
              create_dirs: bool = False, dry_run: bool = True) -> dict:
    target, err, will_mkdir = _prepare_target(path, create_dirs, dry_run)
    if err:
        return {"appended": False, "path": target or path, "bytes": 0, "note": err}
    try:
        data = str(content).encode(encoding)
    except Exception as e:
        return {"appended": False, "path": target, "bytes": 0, "note": f"编码失败：{e}"}
    existed = os.path.exists(target)
    # ⚠️ 安全铁律：默认只预览。预览连父目录都不建（预检的副作用也不许发生）。
    if dry_run:
        try:
            size_now = os.path.getsize(target) if existed else 0
        except OSError:
            size_now = 0
        return {"appended": False, "path": target, "bytes": len(data), "dry_run": True,
                "created": not existed, "will_create_dirs": will_mkdir,
                "size_after": size_now + len(data),
                "note": f"只读预览：未追加。真执行将{'创建文件' if not existed else '往文件末尾追加'}"
                        f"（{len(data)} 字节），追加后约 {size_now + len(data)} 字节"
                        + ("，并自动创建父目录" if will_mkdir else "")
                        + "，需显式传 dry_run=False"}
    try:
        with open(target, "ab") as f:
            f.write(data)
    except Exception as e:
        return {"appended": False, "path": target, "bytes": 0, "note": f"追加失败：{e}"}
    return {"appended": True, "path": target, "bytes": len(data),
            "created": not existed, "size_after": os.path.getsize(target)}


# ══════════════════════════════════════════════════════════════════════════
# 生命周期（fs.delete）—— 默认进回收站 + dry_run 预览
# ══════════════════════════════════════════════════════════════════════════
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


def _recycle(path: str) -> tuple[bool, str]:
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


def _preview(target: str) -> tuple[list[dict], int, int]:
    """预览要删什么。返回 (条目列表[最多50], 文件总数, 总字节)。"""
    if os.path.isfile(target):
        return [{"path": target, "type": "file", "bytes": os.path.getsize(target)}], 1, os.path.getsize(target)
    items: list[dict] = []
    n_files = 0
    n_bytes = 0
    for dirpath, dirnames, filenames in os.walk(target):
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                sz = 0
            n_files += 1
            n_bytes += sz
            if len(items) < 50:
                items.append({"path": fp, "type": "file", "bytes": sz})
        if len(items) < 50:
            for name in dirnames:
                items.append({"path": os.path.join(dirpath, name), "type": "dir"})
    return items, n_files, n_bytes


@declare_primitive(
    "fs.delete",
    "删除文件或目录。什么时候用：清理不要的文件/目录、删中间产物、删 fs.temp 建出来的临时文件。"
    "什么时候别用：要**改名或搬位置、给别处留一份**用 fs.move / fs.copy（不是「删了再拷」）；"
    "只想清空内容、留下空文件用 fs.write 写空串；**删之前想先看清有什么、哪最占地方**，"
    "先用 fs.size / fs.stats 摸清；要**看回收站里有什么 / 还原被删的 / 清空整个回收站**用 "
    "shell.recycle（本原语只会删，既不能还原也不能清空整站 —— 删除走回收站时它俩是一对）。"
    "参数怎么填：path 要删的路径；删**非空目录**必须 recursive=True（否则直接拒绝）；"
    "默认走**回收站**（可以从回收站还原），要彻底销毁才传 permanent=True。"
    "返回什么：deleted=True 才算删了；method 是 preview / recycle_bin / permanent；"
    "file_count 是涉及的文件数；预览时给 dry_run=True、type、file_count、total_mb、"
    "items（列出的要删条目**最多 50 条，只是抽样不是全量**）；"
    "失败/被拒时 deleted=False，note 里是中文原因（路径不存在、目录非空、拒绝删除：盘根 / "
    "Windows·Program Files·ProgramData / 家目录本身 / 当前工作目录的上级）。"
    "安全：**需用户确认**。⚠️ 注意：默认方式 **deleted=True 也只是「移进回收站」，"
    "文件还能捞回来** —— 要真正销毁必须 permanent=True。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "要删除的文件或目录路径"},
         "recursive": {"type": "boolean", "description": "目录非空时是否递归删除，默认 False"},
         "dry_run": {"type": "boolean", "description": "True=只预览不执行（默认）；False=真删"},
         "permanent": {"type": "boolean", "description": "True=永久删除（不进回收站），默认 False"},
     },
     "required": ["path"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"deleted": "是否已删除", "path": "路径", "method": "方式"},
    block="filesystem",
)
def fs_delete(path: str, recursive: bool = False, dry_run: bool = True,
              permanent: bool = False) -> dict:
    try:
        target = normalize_path(path)
    except ValueError as e:
        return {"deleted": False, "path": path, "note": str(e)}
    if not os.path.exists(target):
        return {"deleted": False, "path": target, "note": "路径不存在（可能是写法被规范化后变了）"}
    reason = _forbidden_reason(target)
    if reason:
        return {"deleted": False, "path": target, "note": f"拒绝删除：{reason}"}
    is_dir = os.path.isdir(target)
    if is_dir and not recursive and os.listdir(target):
        return {"deleted": False, "path": target,
                "note": "目录非空，需 recursive=True 才递归删除"}
    items, n_files, n_bytes = _preview(target)
    if dry_run:
        return {"deleted": False, "path": target, "dry_run": True,
                "method": "preview", "type": "dir" if is_dir else "file",
                "file_count": n_files, "total_mb": round(n_bytes / 1048576, 2),
                "items": items, "note": "只读预览，未删除；真删需 dry_run=False + 过确认"}
    if permanent:
        try:
            if is_dir:
                shutil.rmtree(target)
            else:
                os.remove(target)
        except Exception as e:
            return {"deleted": False, "path": target, "note": f"永久删除失败：{e}"}
        return {"deleted": True, "path": target, "dry_run": False, "method": "permanent",
                "file_count": n_files, "note": "⚠️ 已永久删除（不进回收站）"}
    ok, msg = _recycle(target)
    return {"deleted": ok, "path": target, "dry_run": False, "method": "recycle_bin",
            "file_count": n_files, "note": msg + "（可从回收站还原）" if ok else msg}


# ══════════════════════════════════════════════════════════════════════════
# 本节新增：读（fs.read / fs.read_bytes）· 临时区（fs.temp）· 搬运（fs.copy / fs.move）
#
# 本节统一的安全边界：
#   · 读（fs.read / fs.read_bytes）→ **只读，不带 dry_run**。读侧不设限：读没有破坏性，
#     本域已有的 fs.list / fs.search 也是全盘可读，越权交给操作系统权限兜底（读不到就是
#     PermissionError）。
#   · 写/搬（fs.temp / fs.copy / fs.move）→ 会改状态，一律带 dry_run 且**默认 True**。
#   · 路径边界统一交**系统禁区**（system_zone_reason）：盘根、Windows / Program Files /
#     ProgramData 一律拒绝，其余位置放行。
#     ⚠️ **这里试过一版「可写白名单」，又撤掉了**（2026-09-11 定）。撤的三条理由：
#       ① 前面已经有 dry_run（防误触）和确认机制（管越权）两道，白名单拦不住任何它们
#          没拦住的 —— 它就是叠在两道关卡后面的第三道，防的却是同一件事；
#       ② 它连「源」也管，而源只是被**读**。可 fs.read 本来就能读任意位置，限源一点安全性
#          都没增加，只是让原语在真实场景里直接没法用（项目目录里的文件当源都被拒）；
#       ③ 硬拒没有商量余地，碰上「确实要操作别处」就彻底没辙。
#     真要更严，该做的是让白名单变成「需确认的边界」而不是「禁止名单」—— 那需要 core 支持
#     「按参数决定要不要确认」，为这点收益动安全内核不值当。
#   · copy / move **带** requires_confirmation（2026-09-11 定）：搬运会动用户的文件，
#     让用户点个头不亏。另外「覆盖已存在的目标」还有 overwrite 默认 False 兜着 ——
#     「默认拒绝」比「弹确认框」更省事，也更难被模型诱导着点下去。
# ══════════════════════════════════════════════════════════════════════════
import base64
import codecs
import hashlib


def _resolve_path(raw: str, what: str) -> tuple[str, str | None]:
    """搬运类原语共用的路径体检：**只做规范化**，不判白名单。

    返回 (规范化后的真实路径, 中文拒绝理由)。解析不出来 → 拒绝，不往下走。
    ⚠️ 必须先规范化再判禁区：只看字面量的话，靠 `..` 往上爬、8.3 短名、长路径前缀、
    符号链接这四路都能把路径伪装成「看起来不在禁区里」。
    """
    info = check_path(raw)          # 不传 roots → check_path 不判「在不在白名单内」
    norm = info.get("normalized") or ""
    if not norm:
        return "", f"{what}无效：{info.get('note') or str(raw)!r}"
    return norm, None


_MAX_SCAN_FILES = 200000        # 目录快照最多数这么多文件，防超大树把预览卡死


def _scan_tree(root: str) -> dict:
    """目录快照：{files, dirs, bytes, complete}。给复制/移动的预览与体检用。

    complete=False 表示文件太多没数完（预览的数字是「至少这么多」），不影响真执行。
    """
    files = dirs = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # ⚠️ 先剪掉重解析点（符号链接 / junction）—— `os.walk` **不会**自动跳过它们：
        # 实测（2026-09-11）junction 的 `islink()` 是 False，walk 照样递归进去。
        # 不剪的话，数出来的大小会把链接指向的内容重复算一遍；而一个指回祖先的 junction
        # 还能让扫描绕圈。这一步同时保护了 fs.size 和 copy/move 的预览。
        dirnames[:] = [d for d in dirnames
                       if not is_reparse_point(os.path.join(dirpath, d))]
        dirs += len(dirnames)
        for name in filenames:
            files += 1
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass                        # 数不到大小（被占用 / 没权限）就按 0 计，别中断整个扫描
            if files >= _MAX_SCAN_FILES:
                return {"files": files, "dirs": dirs, "bytes": total, "complete": False}
    return {"files": files, "dirs": dirs, "bytes": total, "complete": True}


def _is_inside(child: str, parent: str) -> bool:
    """child 是否在 parent 目录**内部**（不含相等的子目录）。按目录边界比对，规范化后判。"""
    c = os.path.normcase(os.path.normpath(child)).rstrip("\\/")
    p = os.path.normcase(os.path.normpath(parent)).rstrip("\\/")
    return c.startswith(p + os.sep)


# ══════════════════════════════════════════════════════════════════════════
# 读文本（fs.read）—— 只读，无副作用
# ══════════════════════════════════════════════════════════════════════════
# 编码识别为什么这么排：BOM 是文件自己声明的，最可信 → 先认；
# 再试 utf-8（严格），失败才退到 gbk。顺序不能反：GBK 几乎什么字节都能解，
# 先试 gbk 会把 utf-8 文本解成乱码。反过来也有残留风险 —— 少数 GBK 字节序列
# 恰好也是合法 utf-8，那种文件会被判成 utf-8 并解出乱码，光看字节没法根治
#（真正的编码识别要靠统计模型，不是本原语的事）。
_TEXT_BOMS = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32"),        # ⚠️ 必须排在 UTF-16 LE 之前：
    (codecs.BOM_UTF32_BE, "utf-32"),        #    UTF-32 LE 的 BOM 以 FF FE 开头，先匹配 UTF-16 就判错了
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _decode_text(data: bytes, partial: bool = False) -> tuple[str, str, bool]:
    """bytes → (文本, 实际用的编码, 是否出现了替换字符)。

    ⚠️ 踩过的坑（实测抓到）：partial=True 表示 data 只是文件的**前一段**（后面还有），
    这时末尾很可能把一个多字节字符切成两半 —— 用 data.decode('utf-8') 严格解会直接抛
    UnicodeDecodeError，于是整段被判成「不是 utf-8」，退到 gbk，最后落到 utf-8(replace)：
    一个纯 utf-8 的中文文件被报成「编码 utf-8(replace) + 有无法解码的字节」，全是误报。
    解法：用**增量解码器**且不 final（decode(data, False)），末尾那半个字符留在缓冲区里
    不输出，也不算错；真·非法字节序列照样当场抛错，不影响 gbk 兜底。
    """
    final = not partial
    for bom, enc in _TEXT_BOMS:
        if data.startswith(bom):
            try:
                return codecs.getincrementaldecoder(enc)().decode(data, final), enc, False
            except (UnicodeDecodeError, LookupError):
                break                       # BOM 认了但内容不合法 → 退回当普通文本试
    for enc in ("utf-8", "gbk"):
        try:
            return codecs.getincrementaldecoder(enc)().decode(data, final), enc, False
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace"), "utf-8(replace)", True


def _looks_binary(head: bytes) -> bool:
    """含 NUL 字节就当二进制 —— 但带 UTF-16/32 BOM 的文本文件本身全是 NUL，要先排掉。"""
    if any(head.startswith(bom) for bom, _ in _TEXT_BOMS):
        return False
    return b"\x00" in head[:8192]


@declare_primitive(
    "fs.read",
    "读文本文件的内容。什么时候用：想知道某个文本文件里写了什么，或者只关心"
    "其中几行。参数怎么填：path 传文件绝对路径；只想看一部分就传 offset（从第几行开始，从 1 数）"
    "和 limit（最多几行，0=不限行数）；编码一般不用管，会自动认（BOM → utf-8 → gbk 兜底），"
    "确有需要可用 encoding 强制指定；文件很大时用 max_bytes 控制单次最多读多少字节。"
    "返回什么：content 是文本内容（多个行用 \\n 连接），line_from / line_to 是本次返回的行号区间"
    "（接着往下读就把 offset 设成 line_to+1），lines_returned 是本次给了几行，"
    "truncated=True 表示没读全，truncated_reason 说明是行数被 limit 截了还是字节被 max_bytes 截了。"
    "读目录会提示改用 fs.list（要每条的**大小和时间**用 fs.entries），"
    "读二进制文件会提示改用 fs.read_bytes。"
    "⚠️ 与 fs.read_bytes 的 offset **同名不同义**：本原语的 offset 是**行号（从 1 数）**，"
    "那条的 offset 是**字节偏移（从 0 数）**，别把行号传给那条。"
    "只想算文件指纹（不关心内容）用 fs.hash 更直接。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "文件绝对路径"},
         "offset": {"type": "integer", "minimum": 1,
                    "description": "从第几行开始读（**行号，从 1 数**），默认 1；"
                                   "注意 fs.read_bytes 的 offset 是字节偏移（从 0 数），两者不同义"},
         "limit": {"type": "integer", "minimum": 0, "maximum": 100000,
                   "description": "最多返回多少行，默认 1000，上限 100000；传 0 表示不限行数"},
         "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 8388608,
                       "description": "单次最多从文件里读多少字节（超出部分本次不读），默认 262144（256KB），"
                                      "**下限 1024，上限 8MB**（超出会被夹到边界值）"},
         "encoding": {"type": "string",
                      "description": "可选：强制指定编码（如 utf-8 / gbk）；不给则自动识别"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "lines": "返回行数", "truncated": "是否截断"},
    block="filesystem",
)
def fs_read(path: str, offset: int = 1, limit: int = 1000,
            max_bytes: int = 262144, encoding: str = "") -> dict:
    try:
        target = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "文件不存在（路径已规范化，可能原写法被改写过）"}
    if os.path.isdir(target):
        return {"ok": False, "path": target, "note": "这是一个目录，看里面有什么请用 fs.list"}
    try:
        offset = max(1, int(offset))
    except (TypeError, ValueError):
        offset = 1
    try:
        limit = max(0, min(int(limit), 100000))
    except (TypeError, ValueError):
        limit = 1000
    try:
        max_bytes = max(1024, min(int(max_bytes), 8 * 1024 * 1024))
    except (TypeError, ValueError):
        max_bytes = 262144

    size = os.path.getsize(target)
    try:
        # 只读前面的 max_bytes —— 再大的文件也不会整读进内存（模型上下文也放不下）
        with open(target, "rb") as f:
            head = f.read(max_bytes)
    except PermissionError:
        return {"ok": False, "path": target, "size_bytes": size,
                "note": "没有读取权限（系统文件或别的账户的文件）"}
    except OSError as e:
        return {"ok": False, "path": target, "note": f"读取失败：{e}"}

    if _looks_binary(head):
        return {"ok": False, "path": target, "size_bytes": size,
                "note": "这看起来是二进制文件（内容含 NUL 字节），用 fs.read_bytes 读它"}

    byte_cut = size > len(head)         # 文件比本次读的窗口大 → 后面还有内容没读
    if encoding:
        try:
            # 截断时末位可能是半个字符，同样按「非最终」解，别把它算成解码失败
            text = codecs.getincrementaldecoder(encoding)().decode(head, not byte_cut)
            enc, replaced = encoding, False
        except (UnicodeDecodeError, LookupError) as e:
            return {"ok": False, "path": target, "size_bytes": size,
                    "note": f"用 {encoding} 解码失败：{e}（不给 encoding 时是自动识别的）"}
    else:
        text, enc, replaced = _decode_text(head, partial=byte_cut)
    lines = text.splitlines()
    # 尾部被 max_bytes 砍断时，最后一行多半是半截 —— 丢掉它，别把半行内容当完整行给出去
    if byte_cut and lines and not text.endswith(("\n", "\r")):
        lines = lines[:-1]
    window = lines[offset - 1: offset - 1 + limit] if limit else lines[offset - 1:]
    window_to = offset + len(window) - 1 if window else offset - 1
    cut_lines = (offset - 1 + len(window)) < len(lines)
    truncated = cut_lines or byte_cut

    reasons: list[str] = []
    if cut_lines:
        reasons.append(f"行数被 limit={limit} 截断")
    if byte_cut:
        reasons.append(f"只读了文件前 {len(head)} 字节（max_bytes={max_bytes}），后面还没读")

    if window:
        note = f"已读第 {offset}-{window_to} 行，共 {len(window)} 行"
    else:
        note = (f"第 {offset} 行起没有内容可返回（本次在字节窗口内只看到 {len(lines)} 行）"
                if lines else "文件是空的")
    if cut_lines:
        note += f"；还有更多行，继续读用 offset={window_to + 1}"
    if byte_cut:
        note += "；文件比 max_bytes 大，想看后面请调大 max_bytes 或改用 fs.read_bytes 按字节读"
    if replaced:
        note += "；有无法解码的字节，已用替换字符 U+FFFD 代替"

    return {"ok": True, "path": target, "size_bytes": size, "encoding": enc,
            "line_from": offset if window else None, "line_to": window_to if window else None,
            "lines_returned": len(window),
            "total_lines": None if truncated else len(lines),
            "has_more": truncated,
            "truncated": truncated, "truncated_reason": "；".join(reasons),
            "decode_replaced": replaced,
            "content": "\n".join(window),
            "note": note}


# ══════════════════════════════════════════════════════════════════════════
# 读字节（fs.read_bytes）—— 只读，无副作用
# ══════════════════════════════════════════════════════════════════════════
# 为什么单独一条而不是给 fs.read 加 binary 开关：二进制文件要的是「按字节定位 + 指纹」，
# 文本要的是「按行 + 编码」—— 混成一个原语，schema 会长出一堆只在某一半生效的参数，
# 模型更容易填错。
_HASH_MAX_BYTES = 512 * 1024 * 1024      # 超过这个大小就不算整文件指纹（要读完整个文件，太慢）


def _hash_file(target: str, chunk: int = 1048576) -> tuple[str, str]:
    """分块算整个文件的 (sha256, md5)。分块是重点：几百 MB 的文件不能一次读进内存。"""
    h_sha = hashlib.sha256()
    h_md5 = hashlib.md5()
    with open(target, "rb") as f:
        while True:
            blk = f.read(chunk)
            if not blk:
                break
            h_sha.update(blk)
            h_md5.update(blk)
    return h_sha.hexdigest(), h_md5.hexdigest()


@declare_primitive(
    "fs.read_bytes",
    "读二进制文件（或其中一段），并算出校验指纹。什么时候用：文件不是纯文本"
    "（图片 / 压缩包 / exe / 字体 / 数据库文件），或只想看开头几个字节（认文件头）、或只想要"
    "文件的哈希（校验有没有被改过、比对两个文件是否相同）。"
    "什么时候别用：**纯文本**文件（代码、配置、日志、md）用 fs.read —— 那条按行给内容、自动认"
    "编码、给行号区间；本原语给的是按字节切的 base64，读文本既难读又对不齐行。"
    "**只想要指纹、不要内容**用 fs.hash（算法可选：md5 / sha1 / sha256 / blake2b 等）。"
    "要看一个**目录**里有什么（不是读某个文件）用 fs.list / fs.entries。"
    "参数怎么填：path 传路径；只读一段就传 offset（起始字节，从 0 数）和 length（读多少字节，"
    "0=读到文件尾，但单次最多 max_read）；hash_scope 决定指纹算在什么范围 —— whole=整个文件"
    "（默认，适合「校验文件有没有被改过」）、slice=本次读到的这一段、none=不算；"
    "读到的内容超过 inline_limit 字节就不返回内容只给指纹（防止把大块二进制塞进上下文）。"
    "返回什么：sha256 / md5 是按 hash_scope 算的指纹，sha256_slice / md5_slice 一律是本次读到"
    "那一段的指纹；bytes_read 是本次读了多少字节；data_base64 是读到的内容（base64 编码，因为"
    "不是文本）；magic_hex 是开头 16 字节的十六进制（认文件头用）；eof=True 表示已读到文件尾，"
    "没读完就用 next_offset 接着读。注意：算整文件指纹要把文件从头读到尾，大文件会慢"
    "（超过 512MB 会自动降级成只算这一段，返回里会说明）。"
    "⚠️ 与 fs.read 的 offset **同名不同义**：本原语的 offset 是**字节偏移（从 0 数）**，"
    "那条的 offset 是**行号（从 1 数）**，两条的 offset 不能互相套用。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "文件绝对路径"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "起始字节偏移（**从 0 数**），默认 0；"
                                   "注意 fs.read 的 offset 是行号（从 1 数），两者不同义"},
         "length": {"type": "integer", "minimum": 0,
                    "description": "读多少字节，默认 0 = 读到文件尾（仍受 max_read 限制）"},
         "max_read": {"type": "integer", "minimum": 1, "maximum": 8388608,
                      "description": "单次最多读多少字节，默认 65536（64KB），上限 8MB"},
         "hash_scope": {"type": "string", "enum": ["whole", "slice", "none"],
                        "description": "指纹算在什么范围：whole=整个文件（默认）/ slice=本次这一段 / none=不算"},
         "inline_limit": {"type": "integer", "minimum": 0,
                          "description": "读到的字节不超过这个数才随返回带内容（base64），默认 4096；超过只给指纹"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "bytes_read": "读取字节", "sha256": "指纹"},
    block="filesystem",
)
def fs_read_bytes(path: str, offset: int = 0, length: int = 0, max_read: int = 65536,
                  hash_scope: str = "whole", inline_limit: int = 4096) -> dict:
    try:
        target = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "文件不存在（路径已规范化，可能原写法被改写过）"}
    if os.path.isdir(target):
        return {"ok": False, "path": target, "note": "这是一个目录，看里面有什么请用 fs.list"}
    size = os.path.getsize(target)
    try:
        offset = max(0, min(int(offset), size))
    except (TypeError, ValueError):
        offset = 0
    try:
        max_read = max(1, min(int(max_read), 8 * 1024 * 1024))
    except (TypeError, ValueError):
        max_read = 65536
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = 0
    try:
        inline_limit = max(0, int(inline_limit))
    except (TypeError, ValueError):
        inline_limit = 4096

    scope = (hash_scope or "whole").strip().lower()
    if scope not in ("whole", "slice", "none"):
        scope = "whole"
    downgraded = False
    if scope == "whole" and size > _HASH_MAX_BYTES:
        scope, downgraded = "slice", True        # 别为了一个指纹把几百 MB 从头读一遍

    # 要读多少：length<=0 表示读到尾，但仍受 max_read 封顶（防止一次把整个大文件读进内存）
    want = size - offset if length <= 0 else min(length, size - offset)
    want = max(0, min(want, max_read))
    try:
        with open(target, "rb") as f:
            if offset:
                f.seek(offset)
            blob = f.read(want)
    except PermissionError:
        return {"ok": False, "path": target, "size_bytes": size, "note": "没有读取权限"}
    except OSError as e:
        return {"ok": False, "path": target, "size_bytes": size, "note": f"读取失败：{e}"}

    sha_slice = hashlib.sha256(blob).hexdigest()
    md5_slice = hashlib.md5(blob).hexdigest()
    sha = md5 = None
    if scope == "whole":
        try:
            sha, md5 = _hash_file(target)
        except OSError as e:
            return {"ok": False, "path": target, "size_bytes": size,
                    "note": f"算文件指纹时读取失败：{e}"}
    elif scope == "slice":
        sha, md5 = sha_slice, md5_slice

    eof = (offset + len(blob)) >= size
    data_b64 = None
    if blob and len(blob) <= inline_limit:
        data_b64 = base64.b64encode(blob).decode("ascii")
    notes = [f"读了第 {offset}–{offset + len(blob)} 字节（共 {len(blob)} 字节）"]
    if not blob:
        notes = [f"这一段是空的（文件 {size} 字节，offset={offset}）"]
    if scope == "none":
        notes.append("按 hash_scope=none 要求，没算指纹")
    if downgraded:
        notes.append(f"文件超过 {_HASH_MAX_BYTES // 1048576}MB，整文件指纹已降级为「只算这一段」")
    if not eof:
        notes.append(f"还没读完，接着读用 offset={offset + len(blob)}"
                     + (f"；单次上限 max_read={max_read}，要一次多读就调大它" if want >= max_read else ""))
    if blob and data_b64 is None:
        notes.append(f"内容 {len(blob)} 字节超过 inline_limit={inline_limit}，未随返回携带"
                     f"（本原语不返回大块二进制；要取内容请用 offset/length 分段读）")
    return {"ok": True, "path": target, "size_bytes": size,
            "offset": offset, "bytes_read": len(blob),
            "eof": eof, "has_more": not eof, "next_offset": offset + len(blob),
            "hash_scope": scope, "sha256": sha, "md5": md5,
            "sha256_slice": sha_slice, "md5_slice": md5_slice,
            "magic_hex": blob[:16].hex() if offset == 0 and blob else None,
            "data_base64": data_b64,
            "note": "；".join(notes)}


# ══════════════════════════════════════════════════════════════════════════
# 临时区（fs.temp）—— 会落盘：dry_run 默认 True
# ══════════════════════════════════════════════════════════════════════════
# 为什么落在系统临时目录而不是项目目录：临时目录是**每用户独立**的（Windows 上是
# %LOCALAPPDATA%\Temp），不是全盘可写点；名字带随机串，不会撞名，也不会有人去翻。
# 为什么仍需 dry_run：它毕竟会落盘 —— 「预览不落盘」是本项目的统一约定，
# 谁也不能例外，否则「模型顺手建一堆临时文件」没人拦得住。
@declare_primitive(
    "fs.temp",
    "在系统临时目录里建一个临时文件或临时目录，返回它的绝对路径（用完自己删）。"
    "什么时候用：需要一块临时地方放中间产物、导出文件、下载落地的位置，或者需要一批互不干扰的"
    "临时工作目录。什么时候别用：**要落在指定位置**（不是系统临时目录）用 fs.write；"
    "往**已有文件**末尾追加用 fs.append；要**复制**已有文件用 fs.copy（本原语只新建空的文件/目录）。"
    "⚠️ 会落盘。"
    "参数怎么填：kind 选 file（默认）或 dir；prefix/suffix 控制文件名前后缀（如 prefix='报告_'、"
    "suffix='.txt'，dir 忽略 suffix）；content 可选，给临时文件写一段初始文本。"
    "返回什么：path 是建好的路径（dry_run 时给的是示例路径，真执行的名字带随机串、与示例不同）；"
    "parent 是它所在的临时根目录。临时文件不会被自动清理，用完请用 fs.delete 删（默认进回收站）。"
    "注意：落点固定在系统临时目录内，不支持指定别的位置 —— "
    "要把文件放到指定位置请用 fs.write。",
    {"type": "object",
     "properties": {
         "kind": {"type": "string", "enum": ["file", "dir"],
                  "description": "建临时文件还是临时目录，默认 file"},
         "prefix": {"type": "string", "description": "文件名前缀，默认 intentos_"},
         "suffix": {"type": "string", "description": "文件名后缀（仅 kind=file），默认 .tmp"},
         "content": {"type": "string", "description": "可选：临时文件建好后写入的初始文本，默认空"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不创建（默认）；False=真创建"},
     },
     "required": [],
     "additionalProperties": False},
    state={"path": "临时路径", "kind": "类型"},
    block="filesystem",
)
def fs_temp(kind: str = "file", prefix: str = "intentos_", suffix: str = ".tmp",
            content: str = "", dry_run: bool = True) -> dict:
    kind = (kind or "file").strip().lower()
    if kind not in ("file", "dir"):
        return {"created": False, "kind": kind, "note": f"kind 只能是 file 或 dir，收到 {kind!r}"}
    prefix = prefix or "intentos_"
    if kind == "file" and not suffix:
        suffix = ".tmp"
    root = tempfile.gettempdir()
    try:
        root = normalize_path(root)
    except ValueError as e:
        return {"created": False, "note": f"系统临时目录不可用：{e}"}
    # 落点是代码自己选的系统临时目录（不是调用方传进来的路径），不需要再过路径边界判定；
    # 上面那次 normalize_path 已经够了。
    parent = root
    payload = str(content).encode("utf-8")
    sample = os.path.join(parent, f"{prefix}<随机串>{'' if kind == 'dir' else suffix}")
    dir_ignores = "（kind=dir，传入的 content 会被忽略）" if (kind == "dir" and content) else ""

    if dry_run:
        what = (f"临时目录（前缀 {prefix!r}，名字带随机串）" if kind == "dir"
                else f"临时文件（前缀 {prefix!r}，后缀 {suffix!r}，名字带随机串）")
        extra = f"，并写入 {len(payload)} 字节初始内容" if kind == "file" else ""
        return {"created": False, "dry_run": True, "kind": kind, "path": None,
                "parent": parent, "sample_path": sample,
                "content_bytes": len(payload) if kind == "file" else 0,
                "note": f"只读预览：未创建。真执行会在 {parent} 下建一个{what}{extra}"
                        f"{dir_ignores}，需显式传 dry_run=False"}

    try:
        if kind == "dir":
            path = tempfile.mkdtemp(prefix=prefix, dir=parent)
            return {"created": True, "dry_run": False, "kind": "dir", "path": path,
                    "parent": parent, "content_bytes": 0,
                    "note": f"已创建临时目录：{path}{dir_ignores}；"
                            f"不会被自动清理，用完请用 fs.delete 删掉"}
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=parent)
        try:
            with os.fdopen(fd, "wb") as f:      # fdopen 接管 fd，with 退出时自动关闭
                f.write(payload)
        except Exception as e:
            try:
                os.close(fd)                    # fdopen 已接管并关闭时会报「坏的文件描述符」，忽略
            except OSError:
                pass
            try:
                os.unlink(path)                 # 写了一半的临时文件别留下
            except OSError:
                pass
            return {"created": False, "kind": "file", "path": path,
                    "note": f"创建临时文件失败，已清理：{e}"}
    except Exception as e:
        return {"created": False, "kind": kind, "note": f"创建失败：{e}"}
    return {"created": True, "dry_run": False, "kind": "file", "path": path,
            "parent": parent, "content_bytes": len(payload),
            "note": f"已创建临时文件：{path}（{len(payload)} 字节）；"
                    f"不会被自动清理，用完请用 fs.delete 删掉"}


# ══════════════════════════════════════════════════════════════════════════
# 搬运（fs.copy / fs.move）—— 会改状态：dry_run 默认 True
# ══════════════════════════════════════════════════════════════════════════
# 两条统一约定（都是为了「不要有惊喜」）：
#   ① **target 一律按「最终路径」理解** —— 不做 cp/mv 那种「目标是已存在的目录就拷进去」
#      的隐式推断。隐式规则在命令行里很方便，但交给模型时是个陷阱：它以为在改名，
#      实际把文件塞进了某个目录（或反之），而返回里看不出区别。要放进目录就自己写全
#      <目录>/<文件名>；真传了个已存在的目录，原语会拒绝并把这个写法直接回给调用方。
#   ② **目标已存在 → 默认拒绝**，必须显式 overwrite=True。绝不默默覆盖用户文件。
#      （overwrite 也只覆盖**文件**；已存在的目录一律拒绝 —— 目录覆盖是「删掉一整棵树」，
#        该走 fs.delete 让用户自己确认，不该藏在复制/移动里。）
@declare_primitive(
    "fs.copy",
    "复制文件或整个目录（默认保留修改时间等元信息）。什么时候用：备份一份、把文件拷到别处、"
    "整个目录复制一份副本（**源会原样留着**）。什么时候别用：要**移动或改名**（源不再保留）用 "
    "fs.move —— 本原语做不到「搬走」，只会留下源文件；要写一段新内容用 fs.write；要临时产物用 "
    "fs.temp；要删东西用 fs.delete。"
    "⚠️ 会写盘。"
    "**需用户确认**（搬运会动用户的文件）。"
    "参数怎么填：source 传源路径（目录会递归整棵复制）；target 一律按**最终路径**理解"
    "（不做「目标是目录就拷进去」的隐式推断 —— 要拷进某个目录请自己写全 <目录>/<文件名>）；"
    "目标已存在时必须显式 overwrite=True，否则直接拒绝（只覆盖文件，不覆盖已存在的目录）；"
    "preserve=True（默认）连修改时间一起保留，False 则只拷内容；父目录不存在时传 create_dirs=True 自动建。"
    "安全：**需用户确认**（搬运会动用户的文件）；源和目标都不许是盘根或系统目录"
    "（Windows / Program Files / ProgramData），其余位置放行。"
    "返回什么：预览给 type / file_count / total_bytes / 会不会覆盖；真复制给 file_count / bytes_copied；"
    "refused=True 表示被安全规则或「目标已存在」拦下（note 里是中文理由）。"
    "注意：目标是已存在的目录且 overwrite=True 时按**合并**处理，目标里多出来的文件不会被删（不做镜像）。",
    {"type": "object",
     "properties": {
         "source": {"type": "string", "description": "源文件或目录的绝对路径"},
         "target": {"type": "string",
                    "description": "目标的**最终路径**（不是「放到哪个目录」），如 D:\\备份\\a.txt"},
         "overwrite": {"type": "boolean",
                       "description": "目标已存在时是否允许覆盖，默认 False（拒绝，不默默覆盖）"},
         "preserve": {"type": "boolean",
                      "description": "是否保留修改时间等元信息，默认 True"},
         "create_dirs": {"type": "boolean",
                         "description": "目标的父目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不落盘（默认）；False=真复制"},
     },
     "required": ["source", "target"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"copied": "是否复制", "source": "源", "target": "目标"},
    block="filesystem",
)
def fs_copy(source: str, target: str, overwrite: bool = False,
            preserve: bool = True, create_dirs: bool = False, dry_run: bool = True) -> dict:
    src, err = _resolve_path(source, "源路径")
    if err:
        return {"copied": False, "refused": True, "source": str(source),
                "target": str(target), "note": err}
    dst, err = _resolve_path(target, "目标路径")
    if err:
        return {"copied": False, "refused": True, "source": src,
                "target": str(target), "note": err}
    if not os.path.exists(src):
        return {"copied": False, "source": src, "target": dst,
                "note": "源路径不存在（路径已规范化，可能原写法被改写过）"}
    # 源和目标都判系统禁区 —— 白名单撤掉之后，目标是靠这道判定兜着的，漏判就能往系统目录塞
    for path, role in ((src, "源"), (dst, "目标")):
        reason = system_zone_reason(path, "复制")
        if reason:
            return {"copied": False, "refused": True, "source": src, "target": dst,
                    "note": f"拒绝复制（{role}）：{reason}"}
    if os.path.normcase(src) == os.path.normcase(dst):
        return {"copied": False, "source": src, "target": dst, "note": "源和目标相同，无需复制"}

    is_dir = os.path.isdir(src)
    if is_dir and _is_inside(dst, src):
        return {"copied": False, "refused": True, "source": src, "target": dst,
                "note": "拒绝复制：目标在源目录内部，等于把目录复制进它自己（无限递归）"}
    dst_exists = os.path.exists(dst)
    if dst_exists and os.path.isdir(dst) and not is_dir:
        return {"copied": False, "refused": True, "source": src, "target": dst,
                "note": f"目标是一个已存在的目录：{dst}。本原语把 target 当最终路径，"
                        f"不做「拷进目录」的隐式推断 —— 要拷进去请传 "
                        f"target={os.path.join(dst, os.path.basename(src))}"}
    if dst_exists and not overwrite:
        extra = "（目录按合并处理，目标里多出来的文件不会被删）" if is_dir else ""
        return {"copied": False, "refused": True, "source": src, "target": dst,
                "target_exists": True,
                "note": f"目标已存在：{dst}。不会默默覆盖 —— 确认要覆盖请显式传 overwrite=True{extra}"}
    parent = os.path.dirname(dst)
    need_mkdir = bool(parent) and not os.path.isdir(parent)
    if need_mkdir and not create_dirs:
        return {"copied": False, "source": src, "target": dst,
                "note": f"目标的父目录不存在：{parent}（需要时传 create_dirs=True）"}

    snap = _scan_tree(src) if is_dir else {
        "files": 1, "dirs": 0, "bytes": os.path.getsize(src), "complete": True}
    mb = round(snap["bytes"] / 1048576, 2)
    if dry_run:
        what = (f"整个目录（含子目录，递归，共 {snap['files']} 个文件 / {mb} MB）" if is_dir
                else f"文件（{mb} MB）")
        return {"copied": False, "dry_run": True, "source": src, "target": dst,
                "type": "dir" if is_dir else "file",
                "file_count": snap["files"], "total_bytes": snap["bytes"], "total_mb": mb,
                "overwrite": bool(dst_exists and overwrite), "will_create_dirs": need_mkdir,
                "scan_complete": snap["complete"], "preserve": bool(preserve),
                "note": f"只读预览：未复制。真执行会把{what}复制到 {dst}"
                        + ("（目标已存在，将被覆盖）" if (dst_exists and overwrite) else "")
                        + ("，并自动创建父目录" if need_mkdir else "")
                        + "，需显式传 dry_run=False"}

    try:
        if need_mkdir:
            os.makedirs(parent, exist_ok=True)
        if is_dir:
            # copytree 默认用 copy2（保留时间戳）；dirs_exist_ok 只在 overwrite=True 时开合并
            shutil.copytree(src, dst, dirs_exist_ok=bool(overwrite))
        elif preserve:
            shutil.copy2(src, dst)
        else:
            shutil.copyfile(src, dst)
    except Exception as e:
        return {"copied": False, "source": src, "target": dst, "note": f"复制失败：{e}"}
    return {"copied": True, "dry_run": False, "source": src, "target": dst,
            "type": "dir" if is_dir else "file",
            "file_count": snap["files"], "bytes_copied": snap["bytes"],
            "overwrote": bool(dst_exists),
            "note": (f"已复制整个目录（{snap['files']} 个文件 / {mb} MB）到 {dst}；源目录原样留在 {src}"
                     if is_dir else
                     f"已复制文件（{mb} MB）到 {dst}；源文件原样留在 {src}")}


@declare_primitive(
    "fs.move",
    "移动或重命名文件/目录（**源会被搬走，不留副本**）。什么时候用：给文件改名、把文件挪到别的"
    "目录、把目录整体搬到别处。什么时候别用：要**留下源文件、只要一份副本**用 fs.copy"
    "（本原语会把源移走，不是复制）；要删掉不要的东西用 fs.delete。"
    "⚠️ 会改状态且会动源文件。"
    "**需用户确认**（搬运会动源文件）。"
    "参数怎么填：source 传源路径；target 一律按**最终路径**理解 —— 改名就把 target 写成"
    "「同目录下的新名字」，搬到别的目录就把 target 写成「<目录>/<文件名>」（不做「目标是目录就"
    "搬进去」的隐式推断，真传了已存在的目录会拒绝并把正确写法回给你）；目标已存在时必须显式 "
    "overwrite=True，否则拒绝（只覆盖文件；不会覆盖已存在的目录）。"
    "安全：**需用户确认**（搬运会动源文件）；源和目标都不许是盘根或系统目录，"
    "目录不能移动进它自己的子目录。"
    "返回什么：预览会告诉你 cross_volume（是否跨盘）—— 同盘移动等于改名，瞬间完成；"
    "跨盘移动实际是「复制 + 删源」，中途失败可能留下半成品（源还在，目标不完整）。"
    "注意：路径会先规范化（解析软链接 / junction），所以对软链接本身操作会作用到它指向的真实对象。",
    {"type": "object",
     "properties": {
         "source": {"type": "string", "description": "源文件或目录的绝对路径"},
         "target": {"type": "string",
                    "description": "目标的**最终路径**（改名就写新名字，搬走就写 <目录>/<文件名>）"},
         "overwrite": {"type": "boolean",
                       "description": "目标已存在时是否允许覆盖，默认 False（拒绝，不默默覆盖）"},
         "create_dirs": {"type": "boolean",
                         "description": "目标的父目录不存在时是否自动创建，默认 False"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不执行（默认）；False=真移动"},
     },
     "required": ["source", "target"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"moved": "是否移动", "source": "源", "target": "目标"},
    block="filesystem",
)
def fs_move(source: str, target: str, overwrite: bool = False,
            create_dirs: bool = False, dry_run: bool = True) -> dict:
    src, err = _resolve_path(source, "源路径")
    if err:
        return {"moved": False, "refused": True, "source": str(source),
                "target": str(target), "note": err}
    dst, err = _resolve_path(target, "目标路径")
    if err:
        return {"moved": False, "refused": True, "source": src,
                "target": str(target), "note": err}
    if not os.path.exists(src):
        return {"moved": False, "source": src, "target": dst,
                "note": "源路径不存在（路径已规范化，可能原写法被改写过）"}
    # 源和目标都判系统禁区（同 fs.copy：撤掉白名单后目标是靠它兜着的）
    for path, role in ((src, "源"), (dst, "目标")):
        reason = system_zone_reason(path, "移动")
        if reason:
            return {"moved": False, "refused": True, "source": src, "target": dst,
                    "note": f"拒绝移动（{role}）：{reason}"}
    if os.path.normcase(src) == os.path.normcase(dst):
        return {"moved": False, "source": src, "target": dst,
                "note": "源和目标相同，无需移动（改名请让 target 与 source 不同）"}

    is_dir = os.path.isdir(src)
    if is_dir and _is_inside(dst, src):
        return {"moved": False, "refused": True, "source": src, "target": dst,
                "note": "拒绝移动：目标在源目录内部，等于把目录搬进它自己（无限递归）"}
    dst_exists = os.path.exists(dst)
    if dst_exists and os.path.isdir(dst):
        return {"moved": False, "refused": True, "source": src, "target": dst,
                "note": f"目标是一个已存在的目录：{dst}。本原语把 target 当最终路径，"
                        f"不做「搬进目录」的隐式推断 —— 要搬进去请传 "
                        f"target={os.path.join(dst, os.path.basename(src))}"}
    if dst_exists and is_dir:
        # 覆盖一个已存在的目录 = 删掉一整棵树，不该藏在 move 里
        return {"moved": False, "refused": True, "source": src, "target": dst,
                "note": f"目标已存在且是目录：{dst}。本原语不覆盖已存在的目录 —— "
                        f"要先删掉它（fs.delete）或换个名字"}
    if dst_exists and not overwrite:
        return {"moved": False, "refused": True, "source": src, "target": dst,
                "target_exists": True,
                "note": f"目标已存在：{dst}。不会默默覆盖 —— 确认要覆盖请显式传 overwrite=True"}
    parent = os.path.dirname(dst)
    need_mkdir = bool(parent) and not os.path.isdir(parent)
    if need_mkdir and not create_dirs:
        return {"moved": False, "source": src, "target": dst,
                "note": f"目标的父目录不存在：{parent}（需要时传 create_dirs=True）"}

    # 跨盘：shutil.move 会退化成「复制 + 删源」，非原子 —— 先说清楚，别让调用方以为它和改名一样
    cross = os.path.splitdrive(src)[0].lower() != os.path.splitdrive(dst)[0].lower()
    snap = _scan_tree(src) if is_dir else {
        "files": 1, "dirs": 0, "bytes": os.path.getsize(src), "complete": True}
    mb = round(snap["bytes"] / 1048576, 2)
    if dry_run:
        what = (f"整个目录（含子目录，共 {snap['files']} 个文件 / {mb} MB）" if is_dir
                else f"文件（{mb} MB）")
        if cross:
            how = (f"跨盘移动（{os.path.splitdrive(src)[0]} → {os.path.splitdrive(dst)[0]}）："
                   f"实际是先把这 {snap['files']} 个文件复制过去、再删源；"
                   f"中途失败会留下半成品（源还在，目标不完整）")
        else:
            how = "同盘移动（等于改名，瞬间完成，不做数据搬运）"
        return {"moved": False, "dry_run": True, "source": src, "target": dst,
                "type": "dir" if is_dir else "file", "cross_volume": cross,
                "file_count": snap["files"], "total_bytes": snap["bytes"], "total_mb": mb,
                "overwrite": bool(dst_exists and overwrite), "will_create_dirs": need_mkdir,
                "note": f"只读预览：未移动。真执行将把{what}从 {src} 移到 {dst}；{how}"
                        + ("；目标已存在，将被覆盖" if (dst_exists and overwrite) else "")
                        + ("；会先自动创建父目录" if need_mkdir else "")
                        + "。需显式传 dry_run=False"}

    try:
        if need_mkdir:
            os.makedirs(parent, exist_ok=True)
        if dst_exists and overwrite:
            try:
                os.replace(src, dst)        # 同盘：原子替换，不会出现「旧的删了、新的没写成」
            except OSError:
                shutil.move(src, dst)       # 跨盘：os.replace 不支持，退化成复制 + 删源
        else:
            shutil.move(src, dst)
    except Exception as e:
        return {"moved": False, "source": src, "target": dst, "note": f"移动失败：{e}"}
    return {"moved": True, "dry_run": False, "source": src, "target": dst,
            "type": "dir" if is_dir else "file", "cross_volume": cross,
            "file_count": snap["files"], "bytes_moved": snap["bytes"],
            "overwrote": bool(dst_exists),
            "note": f"已{'移动目录' if is_dir else '移动文件'}：{src} → {dst}"
                    + ("（跨盘，走的是复制 + 删源）" if cross else "（同盘改名）")}


# ══════════════════════════════════════════════════════════════════════════
# 本节新增：查询元信息（fs.stat / fs.hash / fs.tree / fs.size / fs.stats / fs.grep）
#           + 会改状态的三条（fs.mkdir / fs.attrs / fs.link）
#
# 安全分级（本节统一，对齐 README「原语安全分级」）：
#   · **只读六条**（stat / hash / tree / size / stats / grep）→ 不带 dry_run。
#     和 fs.read 一样，读侧不设位置限制：读没有破坏性，越权交给操作系统权限兜底
#     （读不到就是 PermissionError）。真正的约束在**算力与上下文**这一侧 ——
#     一个目录可能几十万个文件、一个文件可能几个 GB，塞进模型上下文就废了。
#     所以这六条每条都带「条目 / 字节 / 深度」上限，**截断了必须说清楚**
#     （truncated + 中文理由 + 续读办法），绝不悄悄给一半数据还装作是全的。
#   · **会改状态三条**（mkdir / attrs / link）→ 一律带 dry_run 且**默认 True**。
#     路径边界统一交**系统禁区**（system_zone_reason：盘根 + Windows / Program Files /
#     ProgramData 一律拒绝）—— 与 fs.copy / fs.move 用同一道判定，不另起一套。
#   · 三条里**只有 fs.link 额外带 requires_confirmation**：软链接是路径判定的绕行工具。
#     本文件的判定全部建立在「规范化（解析软链接）之后的真实路径」上，但那只能保证
#     **判定当时**看得穿 —— 链接一旦建好就是一个新的落点，能把后续操作引到别处去。
#     所以既要用户点头，**链接目标与链接路径两侧也都要判禁区**（只判一侧等于没判）。
#     mkdir / attrs 不加确认：建目录、改属性都可逆（改回去即可），破坏性远不如
#     fs.write / fs.delete —— 那两条本来就有确认，不重复叠第三道。
#
# 复用（铁律 2，一个字节都不重抄）：normalize_path / check_path / _resolve_path /
#   system_zone_reason / _scan_tree / _decode_text / _looks_binary 全部取自本文件已有实现。
# ══════════════════════════════════════════════════════════════════════════
import fnmatch
import heapq
import stat
import time
from datetime import datetime


# ── 本节共用的小工具 ──────────────────────────────────────────────────────
def _human_size(n) -> str:
    """字节数 → 人读的大小。给模型的数字别动不动就是 8 位裸字节（它算不过来）。"""
    try:
        size = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def _fmt_time(ts) -> str | None:
    """时间戳 → 'YYYY-MM-DD HH:MM:SS'。拿不到（0 / 越界 / 文件系统不记录）返回 None。

    ⚠️ 不给「1970-01-01」这种假时间：有些文件系统（尤其 FAT/网络盘）不记录创建时间，
    这时 st_ctime 会回 0 —— 把它渲染成 1970 年会让模型当成真的。宁可给 None。
    """
    try:
        ts = float(ts)
        if ts <= 0:
            return None
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _literal_path(raw: str) -> str:
    """只做「字面规范化」：展开 %变量%/~ → 绝对化 → 解析 .. ，**但不解析软链接**。

    为什么单独要一个：normalize_path() 末尾会调 realpath() 把链接解析掉，
    于是拿它的结果去 os.path.islink() 永远是 False —— 链接检测就废了。
    检测链接必须看**没被解析过**的那条路径，所以这里把 normalize_path 的前半段抄成一份
    （就一行表达式，和 check_path() 内部算 literal 的那行同源）。
    """
    p = os.path.expandvars(os.path.expanduser(str(raw).strip()))
    if p.startswith("\\\\?\\"):
        p = p[4:]
    return os.path.normpath(os.path.abspath(p.replace("/", os.sep)))


# 重解析点（reparse point）标签 → 人话。junction 不是符号链接，但同样能把路径引到别处，
# 所以 fs.stat 要能区分「真符号链接」和「junction」，不能一句 islink() 糊过去。
_REPARSE_TAGS = {
    0xA0000003: "MOUNT_POINT（目录 junction）",
    0xA000000C: "SYMLINK（符号链接）",
}


def _reparse_name(flags: int, st) -> str | None:
    """是不是重解析点；是就返回人话名字（认不出的标签给十六进制）。"""
    if not (flags & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        return None
    tag = getattr(st, "st_reparse_tag", None) if st is not None else None
    if tag is None:
        return "未知重解析点"
    return _REPARSE_TAGS.get(tag, f"未知重解析点（tag=0x{tag:08X}）")


def _clean_link_target(t: str | None) -> str | None:
    """把 os.readlink() 给的链接目标整理成人能读的样子。

    ⚠️ 实测：Windows 上 junction 的链接目标带 `\\\\?\\` 前缀（如
    `\\\\?\\D:\\...\\src`），直接返回会让模型以为路径里真有这几个字符。
    UNC 写法（`\\\\?\\UNC\\server\\share`）要还原成 `\\\\server\\share`。
    """
    if not t:
        return t
    if t.startswith("\\\\?\\UNC\\"):
        return "\\\\" + t[8:]
    if t.startswith("\\\\?\\"):
        return t[4:]
    return t


# ══════════════════════════════════════════════════════════════════════════
# 文件元信息（fs.stat）—— 只读
# ══════════════════════════════════════════════════════════════════════════
# 与 fs.list 的分工：fs.list 回答「这个目录条目有哪些」，fs.stat 回答「这一个条目的
# 具体信息」。也是「一个文件占多大、什么时候改的」这类问题的标准落点。
@declare_primitive(
    "fs.stat",
    "查单个文件/目录的元信息：大小、创建/修改/访问时间、是不是只读、是不是链接（软链接/"
    "junction，以及它指向哪）。什么时候用：想知道一个文件多大、什么时候改过、是不是被人"
    "改成了只读、是不是一个指到别处的链接；或者只是想确认某个路径到底存不存在、是文件还是目录。"
    "什么时候别用（改用哪条）：**一个目录里有哪些条目**用 fs.list（只要名字类型）或 fs.entries"
    "（要大小和时间，一次全给）；**「整个目录多大」只想要一个数**用 fs.size；"
    "**目录里都是些什么文件**（扩展名分布、最大的几个）用 fs.stats；"
    "**目录的层级结构**用 fs.tree；**要按文件名找**某类文件用 fs.search（按内容找用 fs.grep）；"
    "**要算指纹**（校验文件有没有被改过）用 fs.hash；**要改只读/隐藏这些属性**用 fs.attrs"
    "（本原语只能看，不能改）。"
    "参数怎么填：path 传路径即可，没有别的开关。"
    "返回什么：type=file/dir/other；size_bytes 与 size_human 是大小；created/modified/accessed "
    "是三个时间（格式 YYYY-MM-DD HH:MM:SS，文件系统不记录时是 null，**别把 null 当 1970 年**）；"
    "readonly=True 是文件属性里的只读位（不是「当前账号能不能写」），writable 才是实测能否写入；"
    "is_symlink/reparse_point/link_target 描述链接（junction 不是 is_symlink，会在 reparse_point 里）；"
    "path 是规范化后的真实路径，resolved_from_link=True 表示原写法是个链接、已被解析到目标。"
    "注意：路径先规范化（解析软链接），所以对链接查的是**它指向的目标**；要看链接本身靠 is_symlink 那组字段。"
    "⚠️ 目录的 size_bytes 是**递归总和**（为它多做一次目录扫描），只想拿一个总大小用 fs.size 更直白；"
    "readonly 是属性位、writable 才是「当前账号能不能写」，两者不一致时 note 会说明 —— "
    "要**改**这两位用 fs.attrs。",
    {"type": "object",
     "properties": {"path": {"type": "string", "description": "文件或目录的路径"}},
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "size_bytes": "大小", "modified": "修改时间"},
    block="filesystem",
)
def fs_stat(path: str) -> dict:
    raw = str(path or "")
    try:
        norm = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "path": raw, "note": f"路径无效：{e}"}
    literal = _literal_path(path)
    # 链接检测看字面路径（normalize_path 已把链接解析掉了，拿 norm 去 islink 恒为 False）
    is_symlink = os.path.islink(literal)
    st_l = None
    try:
        st_l = os.lstat(literal)
    except OSError:
        pass
    lflags = int(getattr(st_l, "st_file_attributes", 0) or 0) if st_l is not None else 0
    reparse = _reparse_name(lflags, st_l)
    link_target = None
    if is_symlink or reparse:
        try:
            link_target = _clean_link_target(os.readlink(literal))
        except OSError:
            link_target = None
    resolved_from_link = os.path.normcase(literal) != os.path.normcase(norm)

    try:
        st = os.stat(norm)
    except OSError:
        # 不只是「不存在」：断链（链接在、目标没了）也走这里，要分开说
        if is_symlink or reparse:
            return {"ok": False, "path": norm, "literal_path": literal,
                    "is_symlink": is_symlink, "reparse_point": reparse,
                    "link_target": link_target, "broken": True,
                    "note": f"这是一个链接，但它指向的目标不存在（断链）：{link_target!r}"}
        return {"ok": False, "path": norm,
                "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    flags = int(getattr(st, "st_file_attributes", 0) or lflags)
    if os.path.isdir(norm):
        kind = "dir"
    elif os.path.isfile(norm):
        kind = "file"
    else:
        kind = "other"
    # 目录的话 st_size 只是「目录条目自己」的大小（几十字节，毫无意义），
    # 想知道「这目录占多大」得递归数 —— 数一次就够，别为了两个字段跑两遍扫描。
    if kind == "dir":
        size_val = _scan_tree(norm)["bytes"]
    else:
        size_val = st.st_size
    out = {
        "ok": True, "path": norm, "literal_path": literal, "type": kind,
        "size_bytes": size_val,
        "size_human": _human_size(size_val),
        "created": _fmt_time(getattr(st, "st_ctime", 0)),
        "modified": _fmt_time(getattr(st, "st_mtime", 0)),
        "accessed": _fmt_time(getattr(st, "st_atime", 0)),
        "readonly": bool(flags & stat.FILE_ATTRIBUTE_READONLY),
        "writable": os.access(norm, os.W_OK),
        "is_symlink": is_symlink,
        "reparse_point": reparse,
        "link_target": link_target,
        "resolved_from_link": resolved_from_link,
    }
    notes = []
    if kind == "dir":
        notes.append("size_bytes 是目录递归总和（= 目录本身占位大小没算，那是文件系统元数据）")
        try:
            out["entry_count"] = len(os.listdir(norm))
        except OSError:
            out["entry_count"] = None
    if reparse and not is_symlink:
        notes.append("这是个 junction/mount point（目录重解析点），不是符号链接")
    if resolved_from_link:
        notes.append(f"原写法经过链接/junction 解析，真实落点是 {norm}"
                     f"（链接检测只对**这一层**生效；父目录是链接时这里不会标出来）")
    if "created" in out and out["created"] is None:
        notes.append("文件系统没记录创建时间（如 FAT / 某些网络盘），created 为 null")
    if out["readonly"] and out["writable"]:
        notes.append("带只读属性但仍可写（属主/管理员可改属性），readonly 与 writable 不是一回事")
    out["note"] = "；".join(notes) if notes else "查询完成"
    return out


# ══════════════════════════════════════════════════════════════════════════
# 文件指纹（fs.hash）—— 只读
# ══════════════════════════════════════════════════════════════════════════
# 与 fs.read_bytes 的分工：那条是「读一段 + 顺带算指纹」，本条的定位是**只算指纹**，
# 且算法可选（md5 快、sha256 稳、blake2b 更快）。要校验一致性时用它。
# ⚠️ 分块读是硬要求（不是优化）：几百 MB 的文件一次 read() 进来，内存和耗时都不可接受。
_HASH_ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s")
_HASH_CHUNK = 1048576                    # 1MB 一块
_HASH_MAX_DEFAULT = 4 * 1024 ** 3        # 默认最多算 4GB，超出只算前 4GB 并如实标注


@declare_primitive(
    "fs.hash",
    "算一个文件的指纹（哈希）。什么时候用：校验文件有没有被改动过、比对两个文件是不是同一份、"
    "给文件做唯一标识（如缓存键、去重）。分块读取，多大的文件都不会把它整读进内存。"
    "什么时候别用：**要读文件内容**（文本要看内容用 fs.read；二进制要分段读、认文件头用 "
    "fs.read_bytes —— 那条顺带也给 sha256/md5）；只要大小/时间等元信息用 fs.stat；"
    "**目录没有指纹**，要目录统计用 fs.stats（本原语对目录会直接拒绝）。"
    "参数怎么填：path 传文件路径；algorithm 选算法，默认 sha256（校验一致性用它；只想快速比对"
    "用 md5；要更快用 blake2b）；chunk_bytes 是每块大小，默认 1MB，一般不用改；"
    "max_bytes 是本次最多算多少字节，默认 4GB，文件超过它就只算**前 max_bytes 个字节**"
    "（返回里 complete=False 会明确告诉你这不是整文件指纹，别拿它当整文件校验用）；"
    "⚠️ max_bytes **传 0 或负数 = 不限**（整个文件都算，哪怕超过 4GB）—— 这是「我清楚在干什么」"
    "才用的写法，别当成默认。"
    "返回什么：digest 是十六进制指纹，algorithm 是实际用的算法，size_bytes 是文件大小，"
    "bytes_hashed 是实际算进去的字节数，complete=True 才代表这是**整文件**指纹，"
    "chunk_bytes 是实际分块大小，elapsed_ms 是耗时。"
    "注意：算大文件指纹要读完整个文件，几 GB 的文件会慢，属正常。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "文件绝对路径"},
         "algorithm": {"type": "string",
                       "description": "哈希算法：md5 / sha1 / sha256(默认) / sha512 / blake2b / blake2s"},
         "chunk_bytes": {"type": "integer", "minimum": 4096, "maximum": 8388608,
                         "description": "分块大小（字节），默认 1048576（1MB），下限 4096、上限 8MB"},
         "max_bytes": {"type": "integer",
                       "description": "最多算多少字节，默认 4294967296（4GB）；超过只算前这么多字节；"
                                      "**传 0 或负数 = 不限**（算完整个文件）"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "algorithm": "算法", "digest": "指纹"},
    block="filesystem",
)
def fs_hash(path: str, algorithm: str = "sha256", chunk_bytes: int = _HASH_CHUNK,
            max_bytes: int = _HASH_MAX_DEFAULT) -> dict:
    try:
        target = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "文件不存在（路径已规范化，可能原写法被改写过）"}
    if os.path.isdir(target):
        return {"ok": False, "path": target,
                "note": "这是一个目录，目录没有指纹。要目录统计用 fs.stats，要单文件大小用 fs.stat"}
    algo = (algorithm or "sha256").strip().lower()
    if algo not in _HASH_ALGOS and algo not in hashlib.algorithms_available:
        return {"ok": False, "path": target, "algorithm": algo,
                "note": f"不支持的算法 {algorithm!r}；常用的是：{' / '.join(_HASH_ALGOS)}"}
    try:
        chunk = max(4096, min(int(chunk_bytes), 8 * 1024 * 1024))
    except (TypeError, ValueError):
        chunk = _HASH_CHUNK
    try:
        cap = int(max_bytes)
    except (TypeError, ValueError):
        cap = _HASH_MAX_DEFAULT
    if cap <= 0:
        cap = None                          # 传 0 / 负数 = 不限（自己清楚在干什么再用）
    size = os.path.getsize(target)
    limit = size if cap is None else min(size, cap)
    h = hashlib.new(algo)
    done = 0
    t0 = time.perf_counter()
    try:
        with open(target, "rb") as f:
            while done < limit:
                blk = f.read(min(chunk, limit - done))
                if not blk:                 # 文件被截短了（和 stat 时的大小对不上）
                    break
                h.update(blk)
                done += len(blk)
    except PermissionError:
        return {"ok": False, "path": target, "size_bytes": size,
                "note": "没有读取权限（系统文件或别的账户的文件）"}
    except OSError as e:
        return {"ok": False, "path": target, "size_bytes": size, "note": f"读取失败：{e}"}
    ms = int((time.perf_counter() - t0) * 1000)
    complete = done >= size
    note = f"{_human_size(done)} 已算完，耗时 {ms} ms"
    if not complete:
        note += (f"；⚠️ 文件共 {_human_size(size)}，超过 max_bytes 上限，"
                 f"**只算了前 {_human_size(done)}**，这不是整文件指纹（要整文件指纹请调大 max_bytes）")
    return {"ok": True, "path": target, "algorithm": algo, "digest": h.hexdigest(),
            "size_bytes": size, "bytes_hashed": done, "complete": complete,
            "chunk_bytes": chunk, "elapsed_ms": ms, "note": note}


# ══════════════════════════════════════════════════════════════════════════
# 目录树（fs.tree）—— 只读，带深度 / 条目双上限
# ══════════════════════════════════════════════════════════════════════════
# 为什么必须有上限：目录树是「一次调用就能撑爆上下文」的典型 —— 一个 node_modules
# 能画出十万行。默认 max_depth=3 + max_entries=500 已经能覆盖「看清结构」这个用途；
# 想看更深就自己调大，代价自己担（返回里会说明被截断）。
# ⚠️ 不跟随链接：跟随的话，一个指回父目录的链接就能让递归无限转圈。
_TREE_MAX_DEPTH = 10
_TREE_MAX_ENTRIES = 5000


@declare_primitive(
    "fs.tree",
    "把一个目录画成树（带缩进的文本树，目录带 /、链接带 @、文件带大小）。什么时候用：想一眼看清"
    "目录结构、项目分层、某个文件夹里到底怎么组织的 —— 比 fs.list 一层层翻快得多。"
    "什么时候别用（改用哪条）：只要**某一层**有什么用 fs.list（要大小时间用 fs.entries）；"
    "只要目录**总大小**用 fs.size；要看**目录里都是些什么文件**（扩展名分布、最大的几个）用 "
    "fs.stats；要**按文件名找**某类文件用 fs.search（按内容找用 fs.grep）；"
    "要看的是**单个文件**（它多大、什么时候改的）用 fs.stat —— 本原语只画目录，"
    "path 给了文件会被拒绝。"
    "参数怎么填：path 传目录路径；max_depth 限制往下画几层（默认 3，上限 10；根目录本身算第 0 层，"
    "⚠️ 传 0 或负数会被当成**最少的一层（1）**—— 本原语的 0 不是「不限」，别跟 fs.stats 的 "
    "max_depth 混（那个 0 = 不限））；"
    "max_entries 限制一共画多少个条目（默认 500，上限 5000，防大目录把上下文撑爆）；"
    "include_files=False 只画目录骨架；include_hidden=False 跳过 . 开头的条目。"
    "返回什么：tree 是画好的多行文本；dirs/files/links 是实际画出来的目录/文件/链接数量；"
    "max_depth/max_entries 是**本次实际生效**的上限；truncated=True 表示"
    "**被截断了**，truncated_reason 说明是深度到底了还是条目到上限了（这时树是不完整的，"
    "别当成全貌，要看全某一支请把 path 指过去）。"
    "注意：不跟随链接（避免链接绕圈），符号链接与 junction 都标成 name@；"
    "隐藏与否只看名字是否以 . 开头，**不查 Windows 隐藏属性**（那个用 fs.attrs）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目录绝对路径"},
         "max_depth": {"type": "integer", "minimum": 1, "maximum": 10,
                       "description": "往下画几层，默认 3，上限 10；最小 1（只画根目录的直接子项）——"
                                      "传 0 或负数会被当成 1；注意 fs.stats 的 max_depth 是 0=不限，两者不同义"},
         "max_entries": {"type": "integer", "minimum": 1, "maximum": 5000,
                         "description": "最多画多少个条目，默认 500，上限 5000"},
         "include_files": {"type": "boolean", "description": "是否画出文件，默认 True；False 只画目录"},
         "include_hidden": {"type": "boolean",
                            "description": "是否包含 . 开头的隐藏条目，默认 True"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"dirs": "目录数", "files": "文件数", "truncated": "是否截断"},
    block="filesystem",
)
def fs_tree(path: str, max_depth: int = 3, max_entries: int = 500,
            include_files: bool = True, include_hidden: bool = True) -> dict:
    try:
        norm = normalize_path(path)
    except ValueError as e:
        return {"ok": False, "path": str(path), "note": f"路径无效：{e}"}
    if not os.path.exists(norm):
        return {"ok": False, "path": norm, "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    if not os.path.isdir(norm):
        return {"ok": False, "path": norm, "note": "这不是目录；看单个文件的信息请用 fs.stat"}
    try:
        # 下限收到 1：传 0 的话连根目录的直接子项都画不出来（等于一次废调用），
        # 与其返回一棵空树让人以为「这目录是空的」，不如按「至少画一层」理解。
        depth_cap = max(1, min(int(max_depth), _TREE_MAX_DEPTH))
    except (TypeError, ValueError):
        depth_cap = 3
    try:
        entry_cap = max(1, min(int(max_entries), _TREE_MAX_ENTRIES))
    except (TypeError, ValueError):
        entry_cap = 500

    lines = [norm + os.sep]
    stats = {"dirs": 0, "files": 0, "links": 0}
    cut = {"entries": False, "depth": False}

    def walk(d: str, prefix: str, depth: int) -> None:
        if cut["entries"]:
            return
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError as e:                # 没权限的目录不该中断整棵树的绘制
            lines.append(prefix + f"[无法读取：{e}]")
            return
        # 目录在前、文件在后，各自按名字排（模型的阅读习惯；不排的话输出顺序随文件系统乱跳）
        entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
        shown = []
        for e in entries:
            if not include_hidden and e.name.startswith("."):
                continue
            # junction 的 is_symlink() 是 False，但它是目录 —— 不额外判重解析点就会递归进去
            is_link = e.is_symlink() or is_reparse_point(e.path)
            is_dir = e.is_dir(follow_symlinks=False) if not is_link else False
            if not include_files and not is_dir:
                continue
            shown.append((e, is_link, is_dir))
        if depth >= depth_cap:
            if shown:
                cut["depth"] = True         # 还有内容但深度到底了 —— 必须说，不然像「这就是全部」
            return
        for i, (e, is_link, is_dir) in enumerate(shown):
            if len(lines) - 1 >= entry_cap:     # 减 1：第一行是根，不算条目
                cut["entries"] = True
                return
            last = (i == len(shown) - 1)
            if is_link:
                stats["links"] += 1
                label = e.name + "@"            # 链接用 @ 标出（不跟随，避免链接绕圈）
            elif is_dir:
                stats["dirs"] += 1
                label = e.name + os.sep
            else:
                stats["files"] += 1
                try:
                    label = f"{e.name} ({_human_size(e.stat().st_size)})"
                except OSError:
                    label = e.name
            lines.append(prefix + ("└── " if last else "├── ") + label)
            if is_dir:
                walk(e.path, prefix + ("    " if last else "│   "), depth + 1)
                if cut["entries"]:
                    return

    walk(norm, "", 0)
    reasons = []
    if cut["depth"]:
        reasons.append(f"还有更深的层级没画（max_depth={depth_cap}）")
    if cut["entries"]:
        reasons.append(f"还有更多条目没画（max_entries={entry_cap}）")
    truncated = bool(reasons)
    note = (f"共画出 {stats['dirs']} 个目录、{stats['files']} 个文件"
            + (f"、{stats['links']} 个链接" if stats["links"] else ""))
    if truncated:
        note += "；⚠️ 已截断：" + "；".join(reasons) + "（这是一部分，不是全貌；要看清某支请直接把 path 指过去）"
    else:
        note += "；未截断，这就是完整结构"
    return {"ok": True, "path": norm, "tree": "\n".join(lines),
            "dirs": stats["dirs"], "files": stats["files"], "links": stats["links"],
            "truncated": truncated, "truncated_reason": "；".join(reasons),
            "max_depth": depth_cap, "max_entries": entry_cap, "note": note}


# ══════════════════════════════════════════════════════════════════════════
# 目录大小（fs.size）—— 只读，复用 _scan_tree 的文件数上限
# ══════════════════════════════════════════════════════════════════════════
@declare_primitive(
    "fs.size",
    "算一个目录总共占多大（递归所有子目录），或单个文件的大小。什么时候用：想知道某个目录吃掉了"
    "多少空间、清理前先看有多大、看看哪个文件夹最占地方（后者配合对子目录逐个调用即可）。"
    "什么时候别用（改用哪条）：**想知道里面都是些什么文件**（扩展名分布、最大的几个）用 fs.stats"
    "（它列出的 largest 可直接拿去 fs.delete）；要按**文件名**找某类文件用 fs.search；"
    "**要看每个条目各自多大**用 fs.entries；只是想知道**一个文件**的大小、还想要时间与链接信息，"
    "用 fs.stat；只看**某一层有什么**、不需要大小用 fs.list；要看目录的层级结构用 fs.tree。"
    "本原语只回答「一共多大」这一个数。"
    "参数怎么填：path 传路径即可，文件或目录都行。"
    "返回什么：type 是 file/dir；total_bytes 与 total_human 是总大小；file_count/dir_count 是"
    "文件与子目录数；complete=False 表示**文件太多没数完**（超过扫描上限），这时 total 是"
    "「至少这么多」而不是准确值；scan_limit 是那个上限。"
    "注意：只统计文件内容的字节数，不含目录条目本身占的元数据开销；"
    "扫描前会**剪掉重解析点（符号链接 / junction / mount point）**，不跟进去、也不计它们，"
    "所以**同一批文件不会被算两遍、不会绕圈，数字是准的**（链接指向别处的内容不会被算进本目录）。",
    {"type": "object",
     "properties": {"path": {"type": "string", "description": "文件或目录路径"}},
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "total_bytes": "总大小", "file_count": "文件数"},
    block="filesystem",
)
def fs_size(path: str) -> dict:
    target, err = _resolve_path(path, "路径")
    if err:
        return {"ok": False, "path": str(path), "note": err}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    if os.path.isfile(target):
        size = os.path.getsize(target)
        return {"ok": True, "path": target, "type": "file",
                "file_count": 1, "dir_count": 0,
                "total_bytes": size, "total_human": _human_size(size),
                "complete": True, "scan_limit": _MAX_SCAN_FILES,
                "note": f"文件大小 {_human_size(size)}（{size} 字节）"}
    snap = _scan_tree(target)
    note = (f"共 {snap['files']} 个文件、{snap['dirs']} 个子目录，"
            f"合计 {_human_size(snap['bytes'])}（{snap['bytes']} 字节）")
    if not snap["complete"]:
        note += (f"；⚠️ 文件数达到扫描上限 {_MAX_SCAN_FILES}，**没数完** —— "
                 f"上面的数字是「至少这么多」，不是准确值")
    return {"ok": True, "path": target, "type": "dir",
            "file_count": snap["files"], "dir_count": snap["dirs"],
            "total_bytes": snap["bytes"], "total_human": _human_size(snap["bytes"]),
            "complete": snap["complete"], "scan_limit": _MAX_SCAN_FILES, "note": note}


# ══════════════════════════════════════════════════════════════════════════
# 目录统计（fs.stats）—— 只读，看「都是些什么文件、最大的几个是啥」
# ══════════════════════════════════════════════════════════════════════════
# 与 fs.size 的分工：fs.size 只回答「多大」，本原语回答「里面都是些什么」——
# 类型分布 + 最大的几个文件。清理磁盘、判断一个目录的性质（代码库 / 素材库 / 日志堆）时用它。
_STATS_MAX_FILES = 200000
_STATS_TOP_EXT = 25                       # 扩展名榜最多给这么多种，防长尾把返回撑爆

# 扩展名 → 大类。判断「这目录是干什么的」时，粗粒度分类比一长串扩展名有用。
_EXT_CATEGORY = (
    ("文档", frozenset({".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                        ".rtf", ".odt", ".csv", ".epub", ".log"})),
    ("代码/配置", frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".c",
                             ".h", ".hpp", ".cpp", ".cc", ".cs", ".go", ".rs", ".rb", ".php",
                             ".swift", ".kt", ".scala", ".sh", ".bash", ".bat", ".cmd", ".ps1",
                             ".html", ".htm", ".css", ".scss", ".vue", ".json", ".xml", ".yml",
                             ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sql", ".ipynb"})),
    ("图片", frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico",
                        ".tif", ".tiff", ".heic", ".raw", ".psd"})),
    ("音视频", frozenset({".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma",
                          ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm", ".flv", ".m4v"})),
    ("压缩包", frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso"})),
    ("可执行/库", frozenset({".exe", ".dll", ".msi", ".sys", ".com", ".so", ".dylib", ".jar",
                             ".pyc", ".pyd", ".lib", ".obj", ".o"})),
)


def _category_of(ext: str) -> str:
    for name, exts in _EXT_CATEGORY:
        if ext in exts:
            return name
    return "其他"


@declare_primitive(
    "fs.stats",
    "统计一个目录里都是些什么文件：多少文件、多少子目录、按扩展名的分布、按大类的分布、"
    "最大的几个文件是谁。什么时候用：想清理磁盘先弄清一个目录的性质（代码库？素材库？日志堆？）、"
    "判断空间被哪类文件吃掉了、找出最占地方的那几个文件。"
    "什么时候别用（改用哪条）：**只要一个总大小**用 fs.size（更快，也不会被扩展名榜的截断影响）；"
    "要**每个条目各自多大、什么时候改的**用 fs.entries；要**单个文件/目录的元信息**用 fs.stat；"
    "要某个文件的**指纹**用 fs.hash；要看**树形结构**用 fs.tree。"
    "参数怎么填：path 传目录；top_n 控制「最大的几个」列几条（默认 10，上限 100）；"
    "top_dirs 控制「各顶层子目录各占多大」列几条（默认 0 = 不列，上限 100）——"
    "想看**空间是被哪个子目录吃掉的**（比如「C 盘怎么突然少了 20G」）就打开它；"
    "它跟 largest 的分工：largest 给的是单个**文件**，它给的是整个**子目录**的累计；"
    "max_files 是扫描文件数上限（默认 200000，防超大目录卡死）——"
    "⚠️ 它要**遍历整棵目录树**，十几万文件的目录得十几到几十秒，对盘根这种量级先想清楚再调，"
    "或先用 max_depth / max_files 探一下；"
    "max_depth=0（默认）表示**不限深度（递归到底）**，传 1 就只看这个目录本身、不进子目录；"
    "⚠️ 它的 0 = 不限，而 fs.tree 的 max_depth 传 0 会被当成**最少一层** —— 同名不同义，别混。"
    "返回什么：file_count/dir_count/total_human 是总量；by_extension 是扩展名榜"
    f"（按文件数排，最多 {_STATS_TOP_EXT} 种，kind=\"其他\" 表示没有扩展名）；by_category 是大类分布"
    "（文档 / 代码配置 / 图片 / 音视频 / 压缩包 / 可执行库 / 其他）；largest 是最大的几个文件"
    "（每条给 path / bytes / human，可直接拿去 fs.delete）；extension_count 是扩展名总种数；"
    "top_dirs>0 时另有 by_subdir（各顶层子目录各占多大，按大小降序，每条 name / files / bytes / human）；"
    "complete=False 表示文件太多没数完，统计是「至少」值；"
    "ok=False 表示统计没跑成（路径不存在 / 不是目录），note 里是中文原因。"
    "注意：符号链接与 junction 都不跟随（不会绕圈、不会重复计数），文件大小按内容字节算。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "目录绝对路径"},
         "top_n": {"type": "integer", "minimum": 1, "maximum": 100,
                   "description": "最大的几个文件，默认 10，上限 100"},
         "max_files": {"type": "integer", "minimum": 1,
                       "description": "最多扫描多少个文件，默认 200000"},
         "max_depth": {"type": "integer", "minimum": 0,
                       "description": "递归深度，0=不限（默认），1=只统计本目录不进子目录；"
                                      "注意 fs.tree 的 max_depth 传 0 是「最少一层」，两者不同义"},
         "top_dirs": {"type": "integer", "minimum": 0, "maximum": 100,
                      "description": "列出「各顶层子目录各占多大」的前几条，默认 0（不列）"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"file_count": "文件数", "dir_count": "子目录数", "total_human": "总大小"},
    block="filesystem",
)
def fs_stats(path: str, top_n: int = 10, max_files: int = _STATS_MAX_FILES,
             max_depth: int = 0, top_dirs: int = 0) -> dict:
    target, err = _resolve_path(path, "路径")
    if err:
        return {"ok": False, "path": str(path), "note": err}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    if not os.path.isdir(target):
        return {"ok": False, "path": target, "note": "这不是目录；单个文件的信息请用 fs.stat"}
    try:
        top_n = max(1, min(int(top_n), 100))
    except (TypeError, ValueError):
        top_n = 10
    try:
        max_files = max(1, int(max_files))
    except (TypeError, ValueError):
        max_files = _STATS_MAX_FILES
    try:
        max_depth = max(0, int(max_depth))
    except (TypeError, ValueError):
        max_depth = 0
    try:
        top_dirs = max(0, min(int(top_dirs), 100))
    except (TypeError, ValueError):
        top_dirs = 0

    root = target.rstrip("\\/") or target
    files = dirs = 0
    total = 0
    complete = True
    by_ext: dict[str, dict] = {}
    by_cat: dict[str, dict] = {}
    # 各**顶层子目录**各占多大 —— 回答「空间被哪个子目录吃掉了」。
    # largest 只给单个文件，答不了「哪个目录最胖」；而查「C 盘突然少了 20G」要的正是后者。
    # 同一趟遍历里顺带归并，不额外走一遍目录树。
    by_subdir: dict[str, dict] = {}
    largest: list[tuple[int, str]] = []      # 小顶堆，只留最大的 top_n 个（不把全量路径堆在内存里）

    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        # 链接目录（含 junction）不往下走也不计入：os.walk 不认 junction 是链接，
        # 跟着走会把同一批文件数两遍，甚至绕成环（见 is_reparse_point 的说明）
        dirnames[:] = [d for d in dirnames if not is_reparse_point(os.path.join(dirpath, d))]
        dirs += len(dirnames)
        if max_depth and depth + 1 >= max_depth:
            dirnames[:] = []                 # 不再往下走（子目录本身已经数过了）
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                sz = 0                       # 被占用 / 没权限：按 0 计，别中断整个统计
            files += 1
            total += sz
            # 归到**顶层**那一段（rel 的第一段）；根目录下的散文件单独一档
            top = "(本目录下的散文件)" if rel == "." else rel.split(os.sep)[0]
            dslot = by_subdir.setdefault(top, {"count": 0, "bytes": 0})
            dslot["count"] += 1
            dslot["bytes"] += sz
            ext = os.path.splitext(name)[1].lower() or "(无扩展名)"
            slot = by_ext.setdefault(ext, {"count": 0, "bytes": 0})
            slot["count"] += 1
            slot["bytes"] += sz
            cat = _category_of(ext if ext != "(无扩展名)" else "")
            cslot = by_cat.setdefault(cat, {"count": 0, "bytes": 0})
            cslot["count"] += 1
            cslot["bytes"] += sz
            if len(largest) < top_n:
                heapq.heappush(largest, (sz, fp))
            elif sz > largest[0][0]:
                heapq.heappushpop(largest, (sz, fp))
            if files >= max_files:
                complete = False
                break
        if not complete:
            break

    ext_list = sorted(({"ext": k, "count": v["count"], "bytes": v["bytes"],
                        "human": _human_size(v["bytes"])} for k, v in by_ext.items()),
                      key=lambda d: (-d["count"], -d["bytes"]))
    top_files = [{"path": p, "bytes": s, "human": _human_size(s)}
                 for s, p in sorted(largest, key=lambda t: -t[0])]
    note = (f"共 {files} 个文件、{dirs} 个子目录，合计 {_human_size(total)}；"
            f"扩展名 {len(by_ext)} 种")
    if len(ext_list) > _STATS_TOP_EXT:
        note += f"（只列前 {_STATS_TOP_EXT} 种）"
    if not complete:
        note += f"；⚠️ 文件数达到上限 {max_files}，**没扫完** —— 以上都是「至少」值"
    out = {"ok": True, "path": target,
           "file_count": files, "dir_count": dirs,
           "total_bytes": total, "total_human": _human_size(total),
           "by_extension": ext_list[:_STATS_TOP_EXT], "extension_count": len(by_ext),
           "by_category": sorted(({"category": k, "count": v["count"], "human": _human_size(v["bytes"])}
                                  for k, v in by_cat.items()), key=lambda d: -d["count"]),
           "largest": top_files, "top_n": top_n, "max_depth": max_depth,
           "complete": complete, "note": note}
    if top_dirs > 0:
        out["by_subdir"] = sorted(
            ({"name": k, "files": v["count"], "bytes": v["bytes"],
              "human": _human_size(v["bytes"])} for k, v in by_subdir.items()),
            key=lambda d: -d["bytes"])[:top_dirs]
        # ⚠️ max_depth>0 时只扫了前几层，这些数字是「至少」—— 可它长得像「谁最占地方」，
        # 失真会**极其误导**：实测同一个目录，只扫两层报 1.34 GB，扫全树是 15.17 GB，
        # 连「谁排第一」都不一样（浅扫时说 ClassIn 最大，实际是 models 以 5.51 GB 遥遥领先）。
        # 所以必须显式标出来，绝不能让一个残缺答案看起来是完整的。
        out["by_subdir_partial"] = max_depth > 0
        if max_depth > 0:
            out["note"] += (f"；⚠️ by_subdir 只统计了前 {max_depth} 层，**不是完整大小**，"
                            f"连排名都可能是错的 —— 要看真实占比请用 max_depth=0")
    return out


# ══════════════════════════════════════════════════════════════════════════
# 内容搜索（fs.grep）—— 只读
# ══════════════════════════════════════════════════════════════════════════
# 与 fs.search 的分工：fs.search 按**文件名**找，fs.grep 按**文件内容**找。
# 三道上限是必须的（不是可选项）：文件数、单文件字节、结果条数 —— 少任何一道，
# 一条命令就能把整个盘读一遍再把上下文塞满。
_GREP_MAX_RESULTS = 1000
_GREP_MAX_FILES = 50000
_GREP_MAX_FILE_BYTES = 2 * 1024 * 1024


def _grep_ext_match(name: str, patterns: list[str]) -> bool:
    """文件名是否命中 include 过滤。patterns 为空 = 全收。"""
    if not patterns:
        return True
    low = name.lower()
    return any(fnmatch.fnmatch(low, p) for p in patterns)


@declare_primitive(
    "fs.grep",
    "在文件**内容**里搜关键词，返回「哪个文件、第几行、那行写了什么」。什么时候用：找某段文字/"
    "某个函数名/某个配置项在哪些文件里出现过（**按文件名**找用 fs.search，只想知道某一层有什么"
    "用 fs.list / fs.entries，想看结构用 fs.tree，要看**单个文件**多大/什么时候改的用 fs.stat —— "
    "本原语是按**内容**找，且只给命中行、不给文件大小时间）。"
    "参数怎么填：path 传目录（递归搜）或单个文件；pattern 是要找的内容，默认按纯文本匹配；"
    "要找模式就传 use_regex=True（正则语法，写错了会明确报错）；include 限定文件类型，"
    "逗号分隔，如 \"*.py,*.md\"（写 .py 也行，自动补成 *.py），不传则所有文本文件都搜；"
    "case_sensitive=False（默认）忽略大小写；max_results 限制返回多少条（默认 100，上限 1000）；"
    "max_file_bytes 是单文件最多读多少字节（默认 2MB，超过的文件会被跳过并计数）。"
    "返回什么：matches 是命中列表（path 是文件完整路径，line 是行号从 1 数，text 是那一行内容）；"
    "match_count 是命中条数、file_count 是命中的文件数；skipped_binary/skipped_large 分别是被"
    "跳过的二进制与大文件数；truncated=True 表示**结果被上限截断**，别当成只有这些。"
    "注意：二进制文件（含 NUL 字节的，如 exe/图片/压缩包）自动跳过；编码自动识别（BOM → utf-8 → gbk）。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "要搜索的目录（递归）或单个文件的路径"},
         "pattern": {"type": "string", "description": "要找的内容（纯文本，或用 use_regex 时的正则）"},
         "include": {"type": "string",
                     "description": "只搜匹配的文件，逗号分隔的通配符，如 \"*.py,*.md\"；不给=全部"},
         "use_regex": {"type": "boolean", "description": "按正则表达式匹配，默认 False（纯文本）"},
         "case_sensitive": {"type": "boolean", "description": "区分大小写，默认 False"},
         "max_results": {"type": "integer", "minimum": 1, "maximum": 1000,
                         "description": "最多返回多少条命中，默认 100，上限 1000"},
         "max_file_bytes": {"type": "integer", "minimum": 1,
                            "description": "单个文件最多读多少字节，默认 2097152（2MB）"},
         "max_files": {"type": "integer", "minimum": 1,
                       "description": "最多扫描多少个文件，默认 50000"},
         "max_line_chars": {"type": "integer", "minimum": 40,
                            "description": "每行最多返回多少字符（超长行截断），默认 300，下限 40"},
     },
     "required": ["path", "pattern"],
     "additionalProperties": False},
    state={"match_count": "命中数", "file_count": "命中文件数", "truncated": "是否截断"},
    block="filesystem",
)
def fs_grep(path: str, pattern: str, include: str = "", use_regex: bool = False,
            case_sensitive: bool = False, max_results: int = 100,
            max_file_bytes: int = _GREP_MAX_FILE_BYTES, max_files: int = _GREP_MAX_FILES,
            max_line_chars: int = 300) -> dict:
    target, err = _resolve_path(path, "路径")
    if err:
        return {"ok": False, "path": str(path), "note": err}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    pat = "" if pattern is None else str(pattern)
    if not pat:
        return {"ok": False, "path": target, "note": "pattern 不能为空"}
    try:
        max_results = max(1, min(int(max_results), _GREP_MAX_RESULTS))
    except (TypeError, ValueError):
        max_results = 100
    try:
        max_file_bytes = max(1, int(max_file_bytes))
    except (TypeError, ValueError):
        max_file_bytes = _GREP_MAX_FILE_BYTES
    try:
        max_files = max(1, int(max_files))
    except (TypeError, ValueError):
        max_files = _GREP_MAX_FILES
    try:
        max_line_chars = max(40, int(max_line_chars))
    except (TypeError, ValueError):
        max_line_chars = 300
    # include 解析：逗号/分号/空白都当分隔符；纯扩展名（.py）自动补成 *.py
    patterns: list[str] = []
    for tok in re.split(r"[,;\s]+", (include or "").strip()):
        tok = tok.strip().lower()
        if not tok:
            continue
        if "*" not in tok and "?" not in tok and tok.startswith("."):
            tok = "*" + tok
        patterns.append(tok)

    rx = None
    if use_regex:
        try:
            rx = re.compile(pat, 0 if case_sensitive else re.IGNORECASE)
        except re.error as e:
            return {"ok": False, "path": target, "pattern": pat,
                    "note": f"正则写错了：{e}（不想用正则就别传 use_regex）"}
    needle = pat if case_sensitive else pat.lower()

    def hit(text: str) -> bool:
        return bool(rx.search(text)) if rx is not None else (needle in (text if case_sensitive else text.lower()))

    matches: list[dict] = []
    hit_files: set[str] = set()
    scanned = skipped_binary = skipped_large = 0
    truncated = False

    def scan_file(fp: str) -> None:
        nonlocal scanned, skipped_binary, skipped_large, truncated
        if truncated:
            return
        try:
            size = os.path.getsize(fp)
        except OSError:
            return
        if size > max_file_bytes:
            skipped_large += 1
            return
        try:
            with open(fp, "rb") as f:
                blob = f.read(max_file_bytes)
        except (PermissionError, OSError):
            return
        if _looks_binary(blob):             # 复用本文件的二进制判定（认 BOM、看 NUL）
            skipped_binary += 1
            return
        scanned += 1
        text, _enc, _rep = _decode_text(blob, partial=(size > len(blob)))
        for i, line in enumerate(text.splitlines(), 1):
            if not hit(line):
                continue
            body = line.rstrip("\r\n")
            if len(body) > max_line_chars:
                body = body[:max_line_chars] + "…（本行已截断）"
            matches.append({"path": fp, "line": i, "text": body.strip()})
            hit_files.add(fp)
            if len(matches) >= max_results:
                truncated = True
                return

    if os.path.isfile(target):
        scan_file(target)
    else:
        for dirpath, dirnames, filenames in os.walk(target):
            # 同 fs.stats：junction 会被 os.walk 当普通目录跟进去（islink 认不出它），
            # 结果就是同一个文件被搜两遍 —— 剪掉
            dirnames[:] = [d for d in dirnames if not is_reparse_point(os.path.join(dirpath, d))]
            for name in filenames:
                if scanned + skipped_binary + skipped_large >= max_files:
                    truncated = True
                    break
                if not _grep_ext_match(name, patterns):
                    continue
                scan_file(os.path.join(dirpath, name))
                if truncated:
                    break
            if truncated:
                break

    notes = [f"命中 {len(matches)} 条，分布在 {len(hit_files)} 个文件"]
    if truncated:
        notes.append(f"⚠️ 结果被上限截断（max_results={max_results} 或 max_files={max_files}）—— "
                     f"这只是其中一部分，缩小范围（指更具体的 path 或 include）再搜")
    if skipped_binary:
        notes.append(f"跳过 {skipped_binary} 个二进制文件")
    if skipped_large:
        notes.append(f"跳过 {skipped_large} 个超过 max_file_bytes={_human_size(max_file_bytes)} 的文件"
                     f"（要搜它们请调大 max_file_bytes）")
    if not matches:
        notes.append("没找到 —— 换个关键词，或用 include 放宽文件类型试试")
    return {"ok": True, "path": target, "pattern": pat, "use_regex": bool(use_regex),
            "case_sensitive": bool(case_sensitive), "include": patterns,
            "match_count": len(matches), "file_count": len(hit_files),
            "matches": matches, "truncated": truncated,
            "files_scanned": scanned, "skipped_binary": skipped_binary,
            "skipped_large": skipped_large, "note": "；".join(notes)}


# ══════════════════════════════════════════════════════════════════════════
# 建目录（fs.mkdir）—— 会改状态：dry_run 默认 True
# ══════════════════════════════════════════════════════════════════════════
# 为什么只带 dry_run、不带 requires_confirmation：建目录是**可逆**的（删掉即可，
# 而且删的是个空目录），破坏性远低于 fs.write / fs.delete —— 那两条本来就有确认。
# 在这上面再叠一道确认，只是让「建个目录」这种高频小事也弹框，人会疲劳，
# 疲劳之后那道确认就等于没有（参考「喊狼来了」）。
@declare_primitive(
    "fs.mkdir",
    "新建目录（默认一次把缺失的父级目录都建好）。什么时候用：要一个存放产物的目录、"
    "写文件前先备好目录。⚠️ 会改状态。"
    "参数怎么填：path 传目录路径；parents=True（默认）会把缺失的上级目录一并建出来"
    "（如 C:\\a\\b\\c 里 a、b 都没有，会一次建齐）；parents=False 则要求父目录已存在，"
    "否则拒绝（更保险，适合「只准在这一层建」的场景）。"
    "返回什么：created=True 表示真建了；existed=True 表示本来就有（不算错，也不会重复建）；"
    "dry_run 预览会给 will_create 列表（真执行会新建哪几层）和 create_count；"
    "refused=True 表示被安全规则拦下（note 里是中文理由）。"
    "安全：盘根与系统目录（Windows / Program Files / ProgramData）一律拒绝；已有同名文件时拒绝。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "要创建的目录路径"},
         "parents": {"type": "boolean",
                     "description": "父目录缺失时是否一并创建，默认 True"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不创建（默认）；False=真创建"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"created": "是否创建", "path": "路径"},
    block="filesystem",
)
def fs_mkdir(path: str, parents: bool = True, dry_run: bool = True) -> dict:
    target, err = _resolve_path(path, "路径")
    if err:
        return {"created": False, "refused": True, "path": str(path), "note": err}
    reason = system_zone_reason(target, "创建目录")
    if reason:
        return {"created": False, "refused": True, "path": target, "note": f"拒绝创建：{reason}"}
    if os.path.isdir(target):
        return {"created": False, "existed": True, "path": target,
                "note": "目录已存在，无需创建（不会报错，也不算新建）"}
    if os.path.exists(target):
        return {"created": False, "path": target, "note": "同名文件已存在，无法在这里建目录"}
    # 往上找最近的已存在祖先，算出「真执行会新建哪几层」—— 预览和返回都用它
    missing: list[str] = []
    p = target
    while p and not os.path.exists(p):
        missing.append(p)
        parent = os.path.dirname(p)
        if parent == p:                     # 到头了（盘根），防死循环
            break
        p = parent
    missing.reverse()
    # ⚠️ 踩过的坑（实测抓到）：`...\hello.txt\sub` 这种「路径中间夹着个已存在的**文件**」，
    # 上面的往上找会在 hello.txt 处停下（它 exists），于是 missing 只有一层、看着一切正常，
    # 预览会说「能建」—— 真跑 makedirs 必然 NotADirectoryError。必须在预览前就拆穿。
    if os.path.exists(p) and not os.path.isdir(p):
        return {"created": False, "refused": True, "path": target,
                "note": f"路径中间的 {p} 是一个已存在的文件，不可能在它下面建目录"}
    if len(missing) > 1 and not parents:
        return {"created": False, "refused": True, "path": target,
                "note": f"父目录不存在：{os.path.dirname(target)}；"
                        f"要一次把父级都建好请传 parents=True（现在是 False）"}
    if dry_run:
        return {"created": False, "dry_run": True, "path": target, "existed": False,
                "will_create": missing, "create_count": len(missing),
                "note": f"只读预览：未创建。真执行会新建 {len(missing)} 层目录："
                        f"{' → '.join(missing)}，需显式传 dry_run=False"}
    try:
        if parents:
            os.makedirs(target, exist_ok=False)
        else:
            os.mkdir(target)
    except Exception as e:
        return {"created": False, "path": target, "note": f"创建失败：{e}"}
    return {"created": True, "dry_run": False, "path": target, "existed": False,
            "created_dirs": missing, "create_count": len(missing),
            "note": f"已创建目录：{target}" + (f"（含 {len(missing)} 层）" if len(missing) > 1 else "")}


# ══════════════════════════════════════════════════════════════════════════
# 文件属性（fs.attrs）—— 不给新值 = 读（无需 dry_run）；给了新值 = 改（dry_run 默认 True）
# ══════════════════════════════════════════════════════════════════════════
# 为什么做成「一条原语两种模式」而不是拆成 fs.attrs_get / fs.attrs_set：
# 看属性和改属性在**人类语境里是同一件事**（右键 → 属性 → 勾选只读），拆两条会让模型
# 为了「看一眼」多挑一次工具。靠参数有无自然分流，语义清楚且不会误触发 ——
# 不传新值就绝不可能改到东西。
_ATTR_BITS = {
    "readonly": stat.FILE_ATTRIBUTE_READONLY,
    "hidden": stat.FILE_ATTRIBUTE_HIDDEN,
    "system": stat.FILE_ATTRIBUTE_SYSTEM,
    "archive": stat.FILE_ATTRIBUTE_ARCHIVE,
}



def _get_attrs(target: str) -> int | None:
    """取文件的属性位。ctypes GetFileAttributesW 为主（它连重解析点等都能给），失败退 os.stat。"""
    try:
        rc = ctypes.windll.kernel32.GetFileAttributesW(str(target))
        # ⚠️ 返回类型是 DWORD，ctypes 默认按 c_int 收 → 0xFFFFFFFF 会变成 -1，两种都要认
        if rc not in (0xFFFFFFFF, -1):
            return int(rc)
    except Exception:
        pass
    try:
        return int(os.stat(target).st_file_attributes)
    except (OSError, AttributeError):
        return None


def _attrs_view(flags: int) -> dict:
    """属性位 → 可读视图（只翻我们管得着的四位，外加目录/重解析点两个提示位）。"""
    view = {k: bool(flags & bit) for k, bit in _ATTR_BITS.items()}
    view["directory"] = bool(flags & stat.FILE_ATTRIBUTE_DIRECTORY)
    view["reparse_point"] = bool(flags & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return view


@declare_primitive(
    "fs.attrs",
    "看或改文件的属性（只读 / 隐藏 / 系统 / 存档）——**不传新值就是看，传了才改**。"
    "什么时候用：想知道某文件是不是被标了隐藏/只读；或者要把它改成隐藏、去掉只读锁。"
    "什么时候别用（改用哪条）：要看**大小 / 三个时间 / 是不是链接、指向哪**用 fs.stat"
    "（本原语只看这四个属性位，不给时间和链接）；要看**目录的层级结构**用 fs.tree"
    "（fs.list / fs.entries 的隐藏判定只看名字是否以 . 开头，不查本原语管的这条属性）；"
    "要看**权限**（谁能读、谁能改）用 acl.get —— 属性 ≠ 权限，是两回事。"
    "参数怎么填：path 必填；readonly / hidden / system / archive 各传 true（置上）或 false（去掉），"
    "**一个都不传就是只读查看**（这时不碰系统、不看 dry_run）；只想改其中一个就只传那一个，"
    "其余保持不变。⚠️ 给了新值就会改状态。"
    "返回什么：mode=read 是查看（attributes 给四个属性 + directory/reparse_point 两个提示）；"
    "mode=preview 是预览（would_change 列出真执行会变的项、从什么变成什么）；"
    "真改完 mode=apply，applied=False 表示本来就是目标状态、没动它。"
    "安全：盘根与系统目录（Windows / Program Files / ProgramData）拒绝修改；"
    "只读属性不等于「当前账号不能写」（属主仍可改属性、可写；要查「当前账号能不能写」用 fs.stat 的 "
    "writable）。注意：**Windows 隐藏属性只有本原语看得见** —— fs.list / fs.entries / fs.tree 的"
    "隐藏判定只看名字是否以 . 开头，**不查这条属性**；"
    "system 属性被系统用在关键文件上，给普通文件置上它没有实际收益，多半只是让杀软多看两眼。",
    {"type": "object",
     "properties": {
         "path": {"type": "string", "description": "文件或目录路径"},
         "readonly": {"type": "boolean", "description": "只读属性：true=置上，false=去掉；不传=不改"},
         "hidden": {"type": "boolean", "description": "隐藏属性：true=置上，false=去掉；不传=不改"},
         "system": {"type": "boolean", "description": "系统属性：true=置上，false=去掉；不传=不改"},
         "archive": {"type": "boolean", "description": "存档属性：true=置上，false=去掉；不传=不改"},
         "dry_run": {"type": "boolean",
                     "description": "只在给了新值时有效：True=只预览（默认）；False=真改"},
     },
     "required": ["path"],
     "additionalProperties": False},
    state={"path": "路径", "mode": "模式"},
    block="filesystem",
)
def fs_attrs(path: str, readonly: bool | None = None, hidden: bool | None = None,
             system: bool | None = None, archive: bool | None = None,
             dry_run: bool = True) -> dict:
    target, err = _resolve_path(path, "路径")
    if err:
        return {"ok": False, "refused": True, "path": str(path), "note": err}
    if not os.path.exists(target):
        return {"ok": False, "path": target, "note": "路径不存在（路径已规范化，可能原写法被改写过）"}
    cur = _get_attrs(target)
    if cur is None:
        return {"ok": False, "path": target, "note": "读不到文件属性（路径不可访问）"}
    view = _attrs_view(cur)
    want = {"readonly": readonly, "hidden": hidden, "system": system, "archive": archive}
    changes = {k: bool(v) for k, v in want.items() if v is not None}

    # ① 只读模式：一个新值都没给 → 绝不碰系统，也不看 dry_run
    if not changes:
        return {"ok": True, "path": target, "mode": "read",
                "attributes": view, "flags": f"0x{cur:08X}",
                "note": "只读查看（没传任何新值，未做任何修改）："
                        + "、".join(f"{k}={'是' if v else '否'}"
                                    for k, v in view.items() if k in _ATTR_BITS)}

    reason = system_zone_reason(target, "修改属性")
    if reason:
        return {"ok": False, "refused": True, "path": target, "mode": "refuse",
                "attributes": view, "flags": f"0x{cur:08X}", "note": f"拒绝修改属性：{reason}"}

    new = cur
    for k, v in changes.items():
        new = (new | _ATTR_BITS[k]) if v else (new & ~_ATTR_BITS[k])
    delta = {k: {"from": view[k], "to": changes[k]}
             for k in changes if view[k] != changes[k]}
    if dry_run:
        if not delta:
            return {"ok": True, "path": target, "mode": "preview", "dry_run": True,
                    "attributes": view, "flags": f"0x{cur:08X}", "would_change": {},
                    "note": "只读预览：请求的属性本来就是当前状态，真执行也不会改动任何东西"}
        desc = "、".join(f"{k} {d['from']}→{d['to']}" for k, d in delta.items())
        return {"ok": True, "path": target, "mode": "preview", "dry_run": True,
                "attributes": view, "would_change": delta,
                "flags": f"0x{cur:08X}", "flags_after": f"0x{new:08X}",
                "note": f"只读预览：未修改。真执行会改：{desc}，需显式传 dry_run=False"}
    if not delta:
        return {"ok": True, "path": target, "mode": "apply", "applied": False,
                "attributes": view, "flags": f"0x{cur:08X}",
                "note": "属性本来就是目标状态，未做修改"}
    # 只改我们管的四位，其余位（目录 / 重解析点 / 别的标记）原样保留
    try:
        ok = ctypes.windll.kernel32.SetFileAttributesW(str(target), ctypes.c_uint32(new))
    except Exception as e:
        return {"ok": False, "path": target, "mode": "apply",
                "note": f"设置属性失败：{e}"}
    if not ok:
        return {"ok": False, "path": target, "mode": "apply",
                "note": "设置属性失败：多半是权限不足（系统保护的文件）或文件正被占用"}
    after = _get_attrs(target)
    return {"ok": True, "path": target, "mode": "apply", "applied": True,
            "attributes": _attrs_view(after) if after is not None else _attrs_view(new),
            "flags": f"0x{(after if after is not None else new):08X}",
            "changed": delta,
            "note": "已修改：" + "、".join(f"{k} {d['from']}→{d['to']}" for k, d in delta.items())}


# ══════════════════════════════════════════════════════════════════════════
# 链接（fs.link）—— 会改状态 + **需确认**：dry_run 默认 True，且 policy 带 requires_confirmation
# ══════════════════════════════════════════════════════════════════════════
# 为什么三条改状态的里只有它要确认：**链接是路径判定的绕行工具**。
# 本文件所有判定都建立在「规范化后的真实路径」上 —— 那是判定**当时**看得穿；
# 而链接一旦落地，它自己就成了新的落点：一个指向系统目录的软链接，就是个看着人畜无害的
# 普通路径。所以：① 要用户点头；② **目标与链接路径两侧都判禁区**（只判链接路径的话，
# 目标指向 C:\Windows 照样建得出来）；③ 拒绝覆盖已存在的任何东西。
# Windows 上建符号链接需要「开发者模式」或管理员权限（os.symlink 会抛权限错误），
# 硬链接不需要 —— 失败时把这条出路写在错误信息里，别让调用方猜。
@declare_primitive(
    "fs.link",
    "给已有文件创建链接：硬链接（hard）或符号链接（soft）。什么时候用：**同一个文件要在多处出现、"
    "又不想复制多份**（省空间、改一处处处同步）；或给一个长路径挂个好记的别名。"
    "⚠️ **需用户确认**。"
    "参数怎么填：source 是**已存在的目标文件**（链接指向它，必须存在）；link_path 是**新链接自己的"
    "路径**（必须还不存在，本原语绝不覆盖已有东西）；kind=soft（默认，符号链接，可跨盘）或 hard"
    "（硬链接，只能同盘、不能给目录建）。"
    "返回什么：created=True 表示建好了；refused=True 表示被安全规则拦下（note 里是中文理由）。"
    "两种链接的区别：硬链接与源**共用同一份数据**（删掉源文件链接里的内容还在，改一处两边都变；"
    "只在同一个分区内可用）；符号链接是**指向源的一条路径**（源没了链接就断，能跨盘，"
    "但 Windows 上需要开发者模式或管理员权限才能建）。"
    "安全：链接目标和链接路径**两侧都**不许落在盘根或系统目录（Windows / Program Files / ProgramData）；"
    "链接路径已存在时拒绝。",
    {"type": "object",
     "properties": {
         "source": {"type": "string", "description": "链接指向的目标文件（必须已存在）"},
         "link_path": {"type": "string", "description": "要创建的链接自己的路径（必须不存在）"},
         "kind": {"type": "string", "enum": ["soft", "hard"],
                  "description": "soft=符号链接（默认，可跨盘）；hard=硬链接（同盘、仅文件）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不创建（默认）；False=真创建"},
     },
     "required": ["source", "link_path"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"created": "是否创建", "link": "链接路径", "kind": "类型"},
    block="filesystem",
)
def fs_link(source: str, link_path: str, kind: str = "soft", dry_run: bool = True) -> dict:
    k = (kind or "soft").strip().lower()
    if k in ("soft", "symbolic", "symlink", "符号链接"):
        k = "soft"
    elif k in ("hard", "hardlink", "硬链接"):
        k = "hard"
    else:
        return {"created": False, "refused": True, "source": str(source),
                "link": str(link_path), "note": f"kind 只能是 soft 或 hard，收到 {kind!r}"}
    src, err = _resolve_path(source, "链接目标")
    if err:
        return {"created": False, "refused": True, "source": str(source),
                "link": str(link_path), "note": err}
    lnk, err = _resolve_path(link_path, "链接路径")
    if err:
        return {"created": False, "refused": True, "source": str(source),
                "link": str(link_path), "note": err}
    # 两侧都判：只判链接路径的话，链接指向 C:\Windows 里照样建得出来（那就是个绕行通道）
    for p, role in ((src, "链接目标"), (lnk, "链接路径")):
        reason = system_zone_reason(p, "创建链接")
        if reason:
            return {"created": False, "refused": True, "source": src, "link": lnk,
                    "note": f"拒绝创建链接（{role}）：{reason}"}
    if not os.path.exists(src):
        return {"created": False, "source": src, "link": lnk,
                "note": "链接目标不存在（链接指向的目标必须已经存在，本原语不建断链）"}
    if os.path.normcase(src) == os.path.normcase(lnk):
        return {"created": False, "source": src, "link": lnk, "note": "链接路径和目标相同，无法创建"}
    if os.path.exists(lnk) or os.path.islink(lnk):
        return {"created": False, "refused": True, "source": src, "link": lnk,
                "note": f"链接路径已存在：{lnk}（本原语不覆盖任何已有文件/目录，请换个名字）"}
    is_dir = os.path.isdir(src)
    if k == "hard" and is_dir:
        return {"created": False, "refused": True, "source": src, "link": lnk,
                "note": "硬链接不能用于目录（会造出环）；给目录建链接请用 kind=soft（符号链接）"}
    if k == "hard" and os.path.splitdrive(src)[0].lower() != os.path.splitdrive(lnk)[0].lower():
        return {"created": False, "refused": True, "source": src, "link": lnk,
                "note": "硬链接不能跨盘（它共用同一份数据，数据只能在同一个卷上）；跨盘请用 kind=soft"}
    size = os.path.getsize(src)
    if dry_run:
        what = ("符号链接（指向源的一条路径，源没了链接就断；Windows 上建它需要开发者模式或管理员权限）"
                if k == "soft" else
                "硬链接（与源共用同一份数据，删源不删数据，改一处两边都变）")
        return {"created": False, "dry_run": True, "source": src, "link": lnk,
                "kind": k, "target_type": "dir" if is_dir else "file",
                "target_bytes": size,
                "note": f"只读预览：未创建。真执行会在 {lnk} 建一个{what}，指向 {src}"
                        f"；本操作**需用户确认**，且需显式传 dry_run=False"}
    try:
        if k == "hard":
            os.link(src, lnk)
        else:
            os.symlink(src, lnk, target_is_directory=is_dir)
    except NotImplementedError:
        return {"created": False, "source": src, "link": lnk,
                "note": "当前系统/文件系统不支持创建链接（如 FAT32 上的符号链接）"}
    except OSError as e:
        extra = ("" if k == "hard" else
                 "（Windows 建符号链接需要「开发者模式」或管理员权限；"
                 "没有权限时可以改用 kind=hard 建硬链接，或直接用 fs.copy 复制一份）")
        return {"created": False, "source": src, "link": lnk, "kind": k,
                "note": f"创建失败：{e}{extra}"}
    return {"created": True, "dry_run": False, "source": src, "link": lnk, "kind": k,
            "target_type": "dir" if is_dir else "file",
            "note": (f"已创建{'硬链接' if k == 'hard' else '符号链接'}：{lnk} → {src}"
                     + ("；它与源共用同一份数据，改一处两边都变" if k == "hard"
                        else "；源文件被删/移走后链接会断"))}
