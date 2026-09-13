"""进程域原语 —— 枚举 / 详情 / 结束（process.*）。

不依赖 psutil（环境未装）：用 stdlib(subprocess 调 tasklist/taskkill) + ctypes 实现，Windows 优先。
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_process，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import os
import subprocess
import sys
import time

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output

# 想拿别的进程信息，最低限度只需要这个权限（普通用户即可拿到大多数进程的路径）
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TH32CS_SNAPPROCESS = 0x00000002


# ── 进程（subprocess 调 tasklist / taskkill，Windows）──────────────────────
@declare_primitive(
    "process.list",
    "列出当前运行的进程：进程名 / PID / 内存占用，按 tasklist 的输出顺序返回前 limit 条。"
    "查「这台机器都在跑什么 / 某个程序起没起来」时用它。"
    "⚠️ 别拿它当查找工具：只知道名字片段要找 PID 用 `process.find`（精准，且不必自己拉全量再筛）；"
    "看某个进程的内存 / IO / 句柄**明细**（查句柄泄漏、谁在狂读磁盘）用 `process.stats`；"
    "判断它是不是系统程序、该不该关它用 `process.info`。"
    "参数 limit：返回条数上限，默认 20，**无硬上限**（调大就多返回）；"
    "sort_by 排序依据：mem（默认，内存从大到小）/ name / pid。"
    "detail=True 会额外给**每个进程的可执行路径、父进程、命令行**（走一次 CIM 全量查询，"
    "约 0.7s，进程再多也不额外变慢）—— 判断一个进程「可不可疑」靠的就是路径和父进程，"
    "需要时打开它。"
    "返回 {ok, count, processes:[{name, pid, mem, mem_bytes}]}；detail=True 时每条另有 "
    "path / parent_pid / parent_name / cmdline，并多给一个 total（系统进程总数）。"
    "⚠️ count 是**本次返回条数**、不是系统总进程数；mem 是 tasklist 原样的字符串"
    "（如 \"12,345 K\"），**要排序或比较请用 mem_bytes**（数字、单位为字节）。"
    "⚠️ 失败时返回 {ok: false, count: 0, note} —— 这个 count=0 与「系统里一个进程都没有」结构上完全一样，"
    "必须看 ok 才判断得出。",
    {"type": "object",
     "properties": {
         "limit": {"type": "integer", "minimum": 1,
                   "description": "返回条数上限，默认 20，无硬上限"},
         "detail": {"type": "boolean",
                    "description": "是否附带每个进程的可执行路径 / 父进程 / 命令行。"
                                   "默认 False（tasklist，约 0.4s）；True 走一次 CIM 全量查询，约 0.7s"},
         "sort_by": {"type": "string", "enum": ["mem", "name", "pid"],
                     "description": "排序依据，默认 mem（内存从大到小）"},
     },
     "required": [],
     "additionalProperties": False},
    state={"count": "进程数"},
    block="process_system",
)
def process_list(limit: int = 20, detail: bool = False, sort_by: str = "mem") -> dict:
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 20
    sorter = {"mem": lambda x: -x["mem_bytes"],
              "name": lambda x: (x.get("name") or "").lower(),
              "pid": lambda x: int(x["pid"]) if str(x["pid"]).isdigit() else 0
              }.get((sort_by or "mem").strip().lower())
    if sorter is None:
        return {"ok": False, "count": 0,
                "note": f"未知 sort_by={sort_by!r}；可选 mem / name / pid"}

    if detail:
        rows, err = _proc_all_cim()
        if rows is None:
            return {"ok": False, "count": 0, "note": err}
        names = {r["pid"]: r["name"] for r in rows}
        items = [{"name": r["name"], "pid": r["pid"],
                  "mem": _kb_text(r["mem_bytes"]), "mem_bytes": r["mem_bytes"],
                  "path": r["path"], "parent_pid": r["parent_pid"],
                  "parent_name": names.get(r["parent_pid"]),
                  "cmdline": _clip_cmdline(r["cmdline"])}
                 for r in rows]
        items.sort(key=sorter)
        return {"ok": True, "count": len(items[:limit]), "total": len(items),
                "processes": items[:limit],
                "note": f"系统共 {len(items)} 个进程，按 {sort_by} 排序，"
                        f"返回前 {min(limit, len(items))} 条"}

    # 快路：tasklist 只给名字 / PID / 内存，但毫秒级 —— 只要概览时用它。
    # 这里读全量再自己排序（原来是一到 limit 就 break）：排序要看到全部才准，
    # 而 tasklist 的输出解析很快，这点开销换一个确定的排序语义是划算的。
    try:
        raw = subprocess.check_output("tasklist /fo csv /nh", text=True,
                                      encoding="utf-8", errors="replace")
    except Exception as e:
        return {"ok": False, "count": 0, "note": f"读取失败：{e}"}
    rows = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 2:
            rows.append({"name": parts[0], "pid": parts[1], "mem": parts[-1],
                         "mem_bytes": _mem_text_to_bytes(parts[-1])})
    rows.sort(key=sorter)
    return {"ok": True, "count": len(rows[:limit]), "processes": rows[:limit]}


@declare_primitive(
    "process.find",
    "按**片段**查找进程：给定一段文字（如 'rag-daemon.py'），返回匹配的 PID / 进程名 / 命令行。"
    "回答「那个 XX 在不在跑、PID 是多少」时用它 —— 比 process.list 精准，不必先拉全量再自己筛。"
    "by=name 走系统快照（毫秒级）；by=cmdline / both 要读命令行，走**一次** WMI/CIM 全量查询"
    "（约 0.5-1s，进程数再多也不额外变慢）。无副作用。"
    "注意：查询词若写在调用方的命令行里（shell 脚本原文、或命令行参数），执行这次查询的 shell 自身"
    "也会被命中 —— 它的命令行**确实含**这个词，属于真匹配而非误报。排除办法：把查询词从命令行挪走"
    "（从文件或 stdin 读入），或用 exclude 参数排掉调用方。"
    "⚠️ 拿到 PID 之后的去向：看它是什么程序 / 装在哪 / 该不该关用 `process.info`；"
    "看它的内存 / IO / 句柄明细用 `process.stats`；要结束它用 `process.kill`（需确认）；"
    "只想把系统在跑什么列一遍用 `process.list`。"
    "返回 {ok, count, pattern, by, processes:[{pid, name, cmdline}], note}：⚠️ count 是**命中总数**"
    "（limit 只截断返回条数、不改 count）；ok=false 表示查询本身没成功（参数错 / 命令行读不到），"
    "与「没匹配到」是两回事。",
    {"type": "object",
     "properties": {
         "pattern": {"type": "string", "description": "要匹配的片段（子串匹配）"},
         "by": {"type": "string", "enum": ["cmdline", "name", "both"],
                "description": "匹配哪一项：cmdline=启动命令行（默认）/ name=进程名 / both=两者任一命中"},
         "limit": {"type": "integer", "minimum": 0,
                   "description": "返回条数上限，0=不限（默认）"},
         "ignore_case": {"type": "boolean", "description": "是否忽略大小写，默认 True"},
         "exclude": {"type": "string",
                     "description": "排除片段：命令行含它的进程不返回。查命令行时常用它排掉调用方自己"},
     },
     "required": ["pattern"],
     "additionalProperties": False},
    state={"count": "匹配数"},
    block="process_system",
)
def process_find(pattern: str, by: str = "cmdline", limit: int = 0,
                 ignore_case: bool = True, exclude: str = "") -> dict:
    pat = (pattern or "").strip()
    by = (by or "cmdline").strip().lower() or "cmdline"
    # 返回结构在所有分支里保持一致（都带 processes）—— 调用方按固定形状取值，
    # 不能因为「参数不对」就少一个键，那样脚本会在 KeyError 上崩而不是拿到错误说明。
    def _empty(note: str) -> dict:
        return {"ok": False, "count": 0, "pattern": pat, "by": by, "processes": [], "note": note}

    if not pat:
        return _empty("pattern 不能为空 —— 空片段会匹配所有进程，那不是查找")
    if by not in ("cmdline", "name", "both"):
        return _empty(f"未知 by={by!r}；可选 cmdline / name / both")

    if by == "name":
        # 快路：系统快照自带进程名，不必去读命令行（毫秒级）
        rows = [{"pid": str(pid), "name": e.get("name"), "cmdline": None}
                for pid, e in _snapshot_procs().items()]
    else:
        rows, err = _cmdline_all()
        if rows is None:
            return _empty(f"读取进程命令行失败：{err}")

    own_pids = _ancestor_pids()
    # 自己的身份特征 —— 用来排掉「为跑这次查询而起的包装层」。
    #
    # 为什么不能只靠 _ancestor_pids：Git Bash(MSYS) 的 fork 在 Windows 层的父子关系
    # 与 shell 的逻辑嵌套**并不一致**，实测管道里的子 shell 压根不在祖先链上，
    # 于是它（命令行里嵌着整条脚本、自然含查询词）就被当成命中搜了出来。
    #
    # 换个不依赖进程关系的判据：**父 shell 的命令行里嵌着子进程的命令行原文**。
    # 所以「命令行包含我这条命令」的进程 = 包装层，一律排掉。
    own_cmd = ""
    for r in rows:
        if r.get("pid") == str(os.getpid()):
            own_cmd = (r.get("cmdline") or "").strip()
            break
    own_argv = " ".join(sys.argv[1:]).strip()   # 不含解释器路径，更贴近命令原文
    if len(own_argv) < 12:
        # 太短的特征会误伤一大片（只有一个 "x" 的话，几乎任何命令行都含它）
        own_argv = ""

    needle = pat.lower() if ignore_case else pat
    excl = ((exclude or "").strip().lower() if ignore_case else (exclude or "").strip())
    hits: list[dict] = []
    for r in rows:
        # ① 排掉整条调用链（本进程 + 祖先，能排多少算多少）
        if r.get("pid") in own_pids:
            continue
        # ② 排掉命令行里嵌着「我这条命令」的包装层（绕开 PID 关系的那条路）
        cl_raw = r.get("cmdline") or ""
        if cl_raw and ((own_cmd and own_cmd in cl_raw)
                       or (own_argv and own_argv in cl_raw)):
            continue
        fields = []
        if by in ("cmdline", "both"):
            fields.append(r.get("cmdline") or "")
        if by in ("name", "both"):
            fields.append(r.get("name") or "")
        norm = [f.lower() if ignore_case else f for f in fields]
        if excl and any(excl in f for f in norm):
            continue
        if any(needle in f for f in norm):
            hits.append({"pid": r.get("pid"), "name": r.get("name"),
                         "cmdline": r.get("cmdline")})

    hits.sort(key=lambda x: int(x["pid"]) if str(x.get("pid", "")).isdigit() else 0)
    total = len(hits)
    if limit and limit > 0:
        hits = hits[:limit]
    out = {"ok": True, "count": total, "pattern": pat, "by": by, "processes": hits}
    if total == 0:
        out["note"] = "没有匹配的进程（换个片段试试，或 by=both 同时匹配进程名）"
    elif len(hits) < total:
        out["note"] = f"共匹配 {total} 条，按 limit={limit} 只返回前 {len(hits)} 条"
    return out


@declare_primitive(
    "process.kill",
    "结束指定 PID 的进程（高危，需用户确认，且会丢未保存数据）。"
    "⚠️ pid 必须是**数字**（PID 从 process.list / process.find 拿）—— 本原语按 PID 定点、不认进程名；"
    "按名字找 PID 请先用 process.find。系统关键 PID（0 / 4）一律硬拒。"
    "⚠️ 动手前先用 process.info 确认这个 PID 到底是什么程序：杀毒 / 输入法 / 资源管理器被杀会让"
    "桌面或系统异常，杀掉一个父进程还可能连带关掉整个程序。"
    "⚠️ 返回值看两个字段：killed 是结论、verified 是**读回复核**（执行后重新取一次系统快照，"
    "确认进程是否真的消失）—— taskkill 返回成功不代表进程没了，权限不足或受保护进程都可能这样。"
    "killed=false 有两种含义，看 dry_run 字段：dry_run=true 是「没真杀、只是预览」；"
    "dry_run=false 才是真失败（note 给原因）。",
    {"type": "object",
     "properties": {
         "pid": {"type": "string",
                 "description": "进程 PID，必须是数字（从 process.list / process.find 拿）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不结束进程（默认）；False=真结束（还需用户确认）"},
     },
     "required": ["pid"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"killed": "是否已结束"},
    block="process_system",
)
def process_kill(pid: str, dry_run: bool = True) -> dict:
    # ① PID 必须是数字 —— 与 process.info / stats / set_priority 同一套校验。
    #    这里此前把字符串**直接拼进** taskkill 命令行（还带 shell=True）：模型给的
    #    `"1 & 别的命令"` 能顺带执行别的命令。而确认框把它显示成 `pid = 1 & 别的命令`，
    #    普通用户看不出那是条命令。现在「数字校验 + argv 列表（shell=False）」两道一起上。
    try:
        pid_i = int(str(pid).strip())
    except (TypeError, ValueError):
        return {"killed": False, "pid": pid, "dry_run": bool(dry_run),
                "note": f"PID 必须是数字，收到 {pid!r}（PID 从 process.list / process.find 拿）"}

    # ② 系统关键 PID 硬拒（复用 process.set_priority 那份名单，不另抄一份）
    if pid_i in _PROTECTED_PIDS:
        return {"killed": False, "pid": pid_i, "dry_run": bool(dry_run), "blocked": True,
                "note": f"拒绝结束 PID {pid_i}（{_PROTECTED_PIDS[pid_i]}）—— 系统关键进程，"
                        f"结束它会让系统异常。这一条是硬拒，没有绕过的参数"}

    argv = ["taskkill", "/pid", str(pid_i), "/f"]
    display = " ".join(argv)          # 只用于展示与确认界面，不参与执行

    # ③ 默认只预览 —— 杀进程会丢未保存数据、可能连带关掉整个程序。
    if dry_run:
        # 预览顺带做只读的进程体检——让「该不该关」有依据（这才是 process.info 的用处）
        info = process_info(str(pid_i), cmdline=False)
        found = bool(info.get("found"))
        out = {"killed": False, "pid": pid_i, "dry_run": True, "command": display,
               "found": found, "name": info.get("name"), "path": info.get("path"),
               "note": f"只读预览：未结束进程。真执行将运行 {display}，需显式传 dry_run=False"
                       + ("" if found else "（⚠️ 该 PID 当前不存在，真执行会失败）")}
        if not found:
            out["target_note"] = info.get("note", "进程不存在（可能已退出）")
        return out

    # ④ 真执行：argv 列表 + shell=False —— 字符串拼接这条路已经关掉
    try:
        r = subprocess.run(argv, capture_output=True, timeout=10)
    except Exception as e:
        return {"killed": False, "pid": pid_i, "dry_run": False, "command": display,
                "note": f"执行失败：{e}"}

    # ⑤ 读回复核 —— **动作发出去了 ≠ 进程真没了**。
    #    此前这里不看 taskkill 返回码、也不复核，直接 return killed=True：
    #    权限不足或 PID 写错时照样报「已杀掉」。那正是「把失败报成成功」。
    #
    #    ⚠️ 复核要分**三种**结局，不能只看「现在还在不在」：对一个**本来就不存在**的
    #    PID，taskkill 会失败、复核也显示「不在」—— 只看复核就会把「它压根没存在过」
    #    报成「已成功杀掉」。所以先记下执行前它在不在，两个信号一起看。
    existed_before = _pid_alive(pid_i)
    alive = existed_before
    for _ in range(6):                # taskkill 返回后，进程可能还差一瞬间才从快照消失
        if not alive:
            break
        time.sleep(0.12)
        alive = _pid_alive(pid_i)

    detail = decode_output(r.stdout or r.stderr or b"").strip()
    out = {"killed": existed_before and not alive, "pid": pid_i, "dry_run": False,
           "command": display, "returncode": r.returncode, "verified": not alive,
           "existed_before": existed_before}
    if not existed_before:
        out["note"] = (f"**没有结束任何进程**：PID {pid_i} 在执行前就不存在"
                       f"（可能已经退出，或 PID 写错了）。taskkill 返回码 {r.returncode}"
                       + (f"，输出：{detail}" if detail else ""))
    elif not alive:
        out["note"] = (f"已结束 PID {pid_i}（taskkill 返回码 {r.returncode}；"
                       f"读回复核：进程已从系统快照消失）")
    else:
        out["note"] = (f"**没有结束** PID {pid_i}：读回复核显示进程仍在。"
                       f"taskkill 返回码 {r.returncode}"
                       + (f"，输出：{detail}" if detail else "")
                       + "（常见原因：权限不足、受保护进程、或该进程正在退出中）")
    return out


# ── 进程详情（ctypes Toolhelp / psapi / kernel32，只读）────────────────────
class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def _snapshot_procs() -> dict[int, dict]:
    """Toolhelp 快照 → {pid: {name, parent_pid, threads}}。失败返回空表。"""
    k = ctypes.windll.kernel32
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    out: dict[int, dict] = {}
    snap = k.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap in (None, -1) or not snap:
        return out
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out[int(entry.th32ProcessID)] = {"name": entry.szExeFile,
                                             "parent_pid": int(entry.th32ParentProcessID),
                                             "threads": int(entry.cntThreads)}
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    except Exception:
        pass
    finally:
        k.CloseHandle(snap)
    return out


def _exe_path(pid: int) -> str | None:
    """QueryFullProcessImageNameW 取可执行文件全路径。权限不足返回 None（不报错）。"""
    k = ctypes.windll.kernel32
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    handle = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(32768)
        if k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value or None
        return None
    finally:
        k.CloseHandle(handle)


def _cmdline_cim(pid: int, timeout: int = 10) -> tuple[str | None, str | None]:
    """命令行只能走 WMI/CIM（ctypes 侧要未文档化接口，内核不碰）。
    返回 (命令行, 失败说明)。约 0.5-1s。"""
    ps = (f"Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" | "
          "Select-Object -ExpandProperty CommandLine | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=timeout)
    except Exception as e:
        return None, f"命令行读取超时/失败：{e}"
    text = r.stdout.decode("utf-8", "replace").strip()
    if not text or text == "null":
        return None, "命令行不可读（可能属于其他用户或受保护进程）"
    try:
        return json.loads(text), None
    except Exception:
        return text, None


def _cmdline_all(timeout: int = 20) -> tuple[list[dict] | None, str | None]:
    """一次取回**全部**进程的 PID / 名称 / 命令行，返回 (行列表, 失败说明)。

    为什么是「全量一次」而不是逐进程查：命令行只能走 WMI/CIM，而单条查询约 0.5-1s ——
    逐个查几百个进程就是分钟级。一次拉回来在本地筛，这条开销就摊薄到零了。
    """
    # [Console]::OutputEncoding 必须显式设成 UTF-8：PowerShell 5.1 默认的控制台编码不是
    # UTF-8，命令行里带中文路径（本机很常见）的进程会读成乱码。
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
          "Get-CimInstance Win32_Process | "
          "Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=timeout)
    except Exception as e:
        return None, f"命令行读取失败：{e}"
    text = r.stdout.decode("utf-8", "replace").strip()
    if not text:
        return None, (r.stderr.decode("utf-8", "replace").strip() or "PowerShell 返回空")
    try:
        data = json.loads(text)
    except Exception as e:
        return None, f"命令行输出解析失败：{e}"
    if isinstance(data, dict):      # 只有一个进程时 ConvertTo-Json 给的是对象，不是数组
        data = [data]
    rows = [{"pid": str(d.get("ProcessId")), "name": d.get("Name"),
             "cmdline": d.get("CommandLine")}
            for d in data if isinstance(d, dict)]
    return rows, None


def _proc_all_cim(timeout: int = 20) -> tuple[list[dict] | None, str | None]:
    """一次取回**全部**进程的 PID / 父 PID / 名称 / 可执行路径 / 内存 / 命令行。

    为什么也是「全量一次」：这几个字段都只能走 WMI/CIM，单条查询约 0.5-1s，逐个查几百个
    进程就是分钟级。实测一次全量约 0.7s（本机 307 个进程），摊到每个进程几乎为零。
    （与 `_cmdline_all` 同一条思路，只是多取了几列。）

    ⚠️ `ExecutablePath` 对系统进程（System Idle Process / System / 受保护进程）是**空值**，
    不是「读失败」—— 如实给 None，别伪造一个路径出来。
    """
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
          "Get-CimInstance Win32_Process | "
          "Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, "
          "WorkingSetSize, CommandLine | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=timeout)
    except Exception as e:
        return None, f"进程详情读取失败：{e}"
    text = r.stdout.decode("utf-8", "replace").strip()
    if not text:
        return None, (r.stderr.decode("utf-8", "replace").strip() or "PowerShell 返回空")
    try:
        data = json.loads(text)
    except Exception as e:
        return None, f"进程详情输出解析失败：{e}"
    if isinstance(data, dict):      # 只有一个进程时 ConvertTo-Json 给的是对象，不是数组
        data = [data]
    rows = [{"pid": str(d.get("ProcessId")),
             "parent_pid": str(d.get("ParentProcessId")),
             "name": d.get("Name"),
             "path": d.get("ExecutablePath") or None,
             "mem_bytes": int(d.get("WorkingSetSize") or 0),
             "cmdline": d.get("CommandLine")}
            for d in data if isinstance(d, dict)]
    return rows, None


# ── process.list 用的小工具（内存字段双向转换 + 命令行截断）──────────────
def _mem_text_to_bytes(text: str) -> int:
    """tasklist 的内存字段（如 "12,345 K"）→ 字节数。

    解析不出来就给 0 —— 排序时垫底就行，不值得为一个数字让整次列表失败。
    """
    digits = "".join(ch for ch in str(text or "") if ch.isdigit())
    return int(digits) * 1024 if digits else 0


def _kb_text(nbytes: int) -> str:
    """字节数 → tasklist 那种 "12,345 K" 的写法（让 mem 字段的口径始终一致）。"""
    return f"{int(nbytes) // 1024:,} K"


def _clip_cmdline(cmd, max_len: int = 300):
    """命令行截断 —— 有些包装脚本会把它撑到几千字符，原样返回会把调用方的上下文塞满。"""
    if not cmd or len(cmd) <= max_len:
        return cmd
    return cmd[:max_len] + f"…（共 {len(cmd)} 字符，已截断）"


def _ancestor_pids() -> set[str]:
    """本进程 + 它的祖先链 PID（字符串形式），用于「查命令行时排掉调用方自己」。

    ⚠️ **为什么不是只排 `os.getpid()`**：查询命令的**命令行里就带着查询词**，而带着它的
    往往不是本进程（python），而是**启动它的那一层** —— 例如
    `bash -c "… python probe-find.py"`。只排自己，实测会把 3 个 bash 当成命中搜出来。

    这个坑 proc-find.sh 第一版踩过一次（当时靠 `-notlike "*proc-find.sh*"` 按名字排掉）。
    换成按 PID 排除后**换个形态又踩了一次** —— 说明要排的粒度不是「自己」，
    而是「**整条调用链**」。
    """
    snap = _snapshot_procs()
    out: set[str] = set()
    cur = os.getpid()
    for _ in range(64):                     # 防御：链异常时别转圈
        out.add(str(cur))
        parent = (snap.get(cur) or {}).get("parent_pid")
        if not parent or parent == cur or str(parent) in out:
            break
        cur = parent
    return out


@declare_primitive(
    "process.info",
    "查某个进程的详情：可执行文件完整路径 / 启动命令行 / 父进程（PID 与名字）/ 线程数 / 句柄数 / "
    "内存占用（工作集 / 峰值工作集 / 私有内存 MB）。"
    "回答「这个程序是什么、装在哪、该不该关它」时用它 —— System32 下的要拦、用户自己装的才放行，"
    "`process.kill` 动手前也该先用它确认目标。"
    "⚠️ 别跟这几条混：只知道名字片段要找 PID 用 `process.find`；只要内存 / IO 的**数字明细**"
    "（查句柄泄漏、谁在狂读磁盘）用 `process.stats`；把整机在跑什么列一遍用 `process.list`。"
    "参数 pid 必填（**数字**，从 process.list / process.find 拿）；cmdline=True（默认）时额外取启动命令行"
    "（走 PowerShell CIM，慢约 0.5-1s），不需要命令行就传 False 提速。"
    "返回 {ok, found, pid, name, parent_pid, parent_name, threads, working_set_mb, peak_working_set_mb, "
    "private_mb, handles, path, cmdline}。⚠️ ok/found=false 表示没查到（进程不存在，或权限不足看不到）；"
    "path 与 cmdline 可能为 null 并另给 path_note / cmdline_note 说明原因（受保护进程、其他用户的进程），"
    "那是权限问题、不代表这个进程有问题。",
    {"type": "object",
     "properties": {
         "pid": {"type": "string", "description": "进程 PID（数字，从 process.list / process.find 拿）"},
         "cmdline": {"type": "boolean", "description": "是否取启动命令行（走 PowerShell CIM，慢约 0.5-1s），默认 True"},
     },
     "required": ["pid"],
     "additionalProperties": False},
    state={"name": "进程名", "path": "可执行路径"},
    block="process_system",
)
def process_info(pid: str, cmdline: bool = True) -> dict:
    try:
        pid_i = int(str(pid).strip())
    except (TypeError, ValueError):
        return {"ok": False, "found": False, "pid": pid, "note": f"PID 不是数字：{pid!r}"}
    procs = _snapshot_procs()
    entry = procs.get(pid_i)
    if entry is None:
        return {"ok": False, "found": False, "pid": pid_i,
                "note": "进程不存在（可能已退出；也可能是权限不足看不到）"}
    out: dict = {"ok": True, "found": True, "pid": pid_i, "name": entry["name"],
                 "parent_pid": entry["parent_pid"],
                 "parent_name": procs.get(entry["parent_pid"], {}).get("name"),
                 "threads": entry["threads"], "path": None, "cmdline": None}
    out["path"] = _exe_path(pid_i)
    if out["path"] is None:
        out["path_note"] = "路径不可读（受保护/其他用户进程，普通权限拿不到）"
    k = ctypes.windll.kernel32
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    handle = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid_i)
    if handle:
        try:
            pmc = _PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                out["working_set_mb"] = round(pmc.WorkingSetSize / 1048576, 1)
                out["peak_working_set_mb"] = round(pmc.PeakWorkingSetSize / 1048576, 1)
                out["private_mb"] = round(pmc.PagefileUsage / 1048576, 1)
            hc = wintypes.DWORD()
            if k.GetProcessHandleCount(handle, ctypes.byref(hc)):
                out["handles"] = int(hc.value)
        except Exception as e:
            out["stats_note"] = f"资源占用读取失败：{e}"
        finally:
            k.CloseHandle(handle)
    else:
        out["stats_note"] = "资源占用不可读（打不开进程句柄）"
    if cmdline:
        cl, err = _cmdline_cim(pid_i)
        out["cmdline"] = cl
        if err:
            out["cmdline_note"] = err
    return out


# ── 资源画像 / 前台程序 / 优先级（ctypes，只读为主）────────────────────────
# 这一片共用同一个底座：**拿一个有查询权限的进程句柄**。
#   · OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) 是 Vista+ 的「低权限查询」口子，
#     普通账户也能查大多数进程；查不到就是查不到（受保护/别的用户），**只标注、不报错**。
#   · 只有真改优先级才需要 PROCESS_SET_INFORMATION —— 那一步单独走 process.set_priority
#     的三道门（dry_run 默认 True + requires_confirmation + 关键 PID 黑名单）。
# ⚠️ 句柄是 64 位指针：凡是要把句柄传回 API 的地方都得先声明 argtypes，
#    否则 ctypes 按默认的 32 位 int 传参会截断（现有 process_info 里就属于「靠运气」的写法）。
_PROCESS_SET_INFORMATION = 0x0200

# 常见 Win32 错误码 → 人话。系统报错原文（"Access is denied."）对模型没有信息量，
# 而「为什么失败、怎么办」才是它下一步决策需要的。
_WIN32_ERRORS = {5: "拒绝访问（权限不足）", 6: "句柄无效", 87: "参数无效",
                 3: "路径不存在", 1168: "找不到元素"}


class _IO_COUNTERS(ctypes.Structure):
    """GetProcessIoCounters 的出参：累计读写字节数与操作次数（进程启动至今，不重置）。"""
    _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong)]


def _kernel32():
    """取一份带 use_last_error 的 kernel32 —— 只有它能可靠地读到 GetLastError()。

    `ctypes.windll.kernel32` 那份默认 use_last_error=False：错误码存在线程的 LastError 里，
    但 ctypes 自己内部的调用会把它冲掉，读出来基本是 0。取不到就退回 windll（只影响报错文案）。
    """
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception:
        return ctypes.windll.kernel32


def _last_error() -> int:
    try:
        return int(ctypes.get_last_error() or 0)
    except Exception:
        return 0


def _open_process(pid: int, access: int):
    """OpenProcess 包装：统一 argtypes/restype，失败返回 None（不抛）。"""
    k = _kernel32()
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    return k.OpenProcess(access, False, pid) or None


def _close(handle) -> None:
    try:
        k = _kernel32()
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle(handle)
    except Exception:
        pass


def _pid_alive(pid: int) -> bool:
    """PID 还在不在系统快照里 —— 用来区分「进程不存在」与「进程在、但打不开」。"""
    return pid in _snapshot_procs()


@declare_primitive(
    "process.stats",
    "查某个进程的资源占用明细：工作集 / 峰值工作集 / 私有内存(MB)、句柄数、线程数、"
    "累计读写字节数与读写次数。回答「谁在吃内存 / 是不是它在狂读磁盘 / 这进程是不是句柄泄漏」时用它。"
    "无副作用。"
    "注意：读写字节数是**进程启动至今的累计值**，不重置也不等于瞬时速率 —— 要看速度得隔几秒调两次自己求差。"
    "权限不足（受保护进程 / 其他用户的进程）时只给能读到的部分，并在 note 里说明缺哪块。"
    "⚠️ 跟 `process.info` 的分工：要「这程序是什么、装在哪、该不该关」用 process.info（那个取路径与命令行）；"
    "要「它吃了多少资源」用本条（不取路径与命令行）。查之前先用 `process.find` 拿 PID，"
    "要「整机都在跑什么」用 `process.list`。",
    {"type": "object",
     "properties": {"pid": {"type": "string", "description": "进程 PID"}},
     "required": ["pid"],
     "additionalProperties": False},
    state={"name": "进程名", "working_set_mb": "内存MB"},
    block="process_system",
)
def process_stats(pid: str) -> dict:
    try:
        pid_i = int(str(pid).strip())
    except (TypeError, ValueError):
        return {"ok": False, "pid": pid, "note": f"PID 不是数字：{pid!r}"}
    snap = _snapshot_procs()
    entry = snap.get(pid_i)
    if entry is None:
        return {"ok": False, "pid": pid_i,
                "note": "进程不存在（可能已退出；也可能是权限不足看不到）"}
    # 线程数直接取快照的 cntThreads —— 这条**不需要打开进程**，所以在权限不足时依然有效
    out: dict = {"ok": True, "pid": pid_i, "name": entry["name"],
                 "threads": entry["threads"], "handles": None,
                 "working_set_mb": None, "peak_working_set_mb": None, "private_mb": None,
                 "read_bytes": None, "write_bytes": None,
                 "read_ops": None, "write_ops": None, "other_bytes": None, "note": ""}
    handle = _open_process(pid_i, _PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        out["ok"] = False
        out["note"] = ("打不开进程句柄：权限不足或进程受保护（其他用户/更高权限的进程）。"
                       "内存与 IO 读不到；线程数来自系统快照，仍然有效"
                       + (f"（{_err_text(_last_error())}）" if _last_error() else ""))
        return out
    k = _kernel32()
    psapi = ctypes.windll.psapi
    try:
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,
                                               ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
                                               wintypes.DWORD]
        pmc = _PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            out["working_set_mb"] = round(pmc.WorkingSetSize / 1048576, 1)
            out["peak_working_set_mb"] = round(pmc.PeakWorkingSetSize / 1048576, 1)
            out["private_mb"] = round(pmc.PagefileUsage / 1048576, 1)   # 私有提交 = 任务管理器「提交大小」
        k.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        hc = wintypes.DWORD()
        if k.GetProcessHandleCount(handle, ctypes.byref(hc)):
            out["handles"] = int(hc.value)
        k.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IO_COUNTERS)]
        io = _IO_COUNTERS()
        if k.GetProcessIoCounters(handle, ctypes.byref(io)):
            out["read_bytes"] = int(io.ReadTransferCount)
            out["write_bytes"] = int(io.WriteTransferCount)
            out["other_bytes"] = int(io.OtherTransferCount)
            out["read_ops"] = int(io.ReadOperationCount)
            out["write_ops"] = int(io.WriteOperationCount)
    except Exception as e:
        out["ok"] = False
        out["note"] = f"资源读取失败：{e}"
    finally:
        _close(handle)
    if out["ok"]:
        missing = [n for n in ("working_set_mb", "handles", "read_bytes") if out[n] is None]
        out["note"] = ("部分指标读不到：" + "、".join(missing)) if missing else ""
    return out


@declare_primitive(
    "process.foreground",
    "看用户此刻正在用哪个程序：返回前台窗口所属进程的 PID / 进程名 / 可执行路径 / 窗口标题 / 窗口类名。"
    "回答「我现在在用什么软件 / 当前开着什么窗口」时用它。无副作用、不打扰用户。"
    "边界：锁屏、或本进程不在交互式桌面会话里时没有前台窗口 → ok=False 并说明，不是报错。"
    "注意：① 标题取的是窗口自己的 caption，个别窗口（某些浏览器/Electron 的顶层窗口）它就是空的，"
    "此时 title=null 不代表出错；② 路径对以更高权限运行的进程可能读不到（只给 name）。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"name": "前台进程", "title": "窗口标题"},
    block="process_system",
)
def process_foreground() -> dict:
    user32 = ctypes.windll.user32
    try:
        # ⚠️ HWND 是 64 位指针：不声明 restype 就按 c_int 截断，拿到的句柄当场作废
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextW.argtypes = [wintypes.HWND, ctypes.c_wchar_p, ctypes.c_int]
        user32.GetClassNameW.argtypes = [wintypes.HWND, ctypes.c_wchar_p, ctypes.c_int]
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return {"ok": False, "hwnd": 0, "pid": None, "name": None, "title": None,
                    "note": "当前没有前台窗口：可能已锁屏，或本进程不在交互式桌面会话里"
                            "（服务/计划任务里跑就会这样）"}
        pid = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_i = int(pid.value)
        # GetWindowText 对**别的进程**的窗口不会发 WM_GETTEXT（读的是内核缓存的标题），
        # 所以目标窗口卡死时这里也不会跟着卡住 —— 跨进程取标题就该用它。
        n = int(user32.GetWindowTextLengthW(hwnd))
        buf = ctypes.create_unicode_buffer(n + 2)
        user32.GetWindowTextW(hwnd, buf, n + 2)
        cls = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cls, 256)
    except Exception as e:
        return {"ok": False, "note": f"读取前台窗口失败：{e}"}
    if pid_i == 0:
        return {"ok": False, "hwnd": int(hwnd), "pid": 0, "title": buf.value,
                "note": "前台窗口不属于任何进程（系统桌面/锁屏界面）"}
    snap = _snapshot_procs().get(pid_i, {})
    path = _exe_path(pid_i)
    out = {"ok": True, "hwnd": int(hwnd), "pid": pid_i,
           "name": snap.get("name"), "path": path,
           "title": buf.value or None, "window_class": cls.value or None,
           "threads": snap.get("threads"), "note": ""}
    if out["name"] is None:
        out["note"] = "拿到了 PID 但进程名不可读（进程可能刚退出，或权限不足）"
    if path is None and out["name"]:
        out["path_note"] = "可执行路径不可读（受保护/其他用户进程，普通权限拿不到）"
    return out


# ── 优先级（process.set_priority）─────────────────────────────────────────
# 唯一会改状态的一条，所以按 README 的三道门来：dry_run 默认 True + requires_confirmation
# + 自己的黑名单。黑名单分两类，都不是「问一句」而是「不给这个能力」：
#   ① **PID 0 / 4**（System Idle / System）—— 内核态进程，改它们的优先级等于动调度器
#   ② **realtime** —— 实时优先级会盖过系统关键线程，轻则输入丢失、重则整机卡死
# 优先级取值用「规范名 + 别名」两段：模型爱写 low / belownormal / high，
# 全收；只认真实存在的 5 档（不含 realtime，见上）。
_PRIORITY_CLASSES = {           # 规范名 → (SetPriorityClass 常量, 中文说明)
    "idle": (0x00000040, "空闲（最低，只在别人都闲着时才跑）"),
    "below_normal": (0x00004000, "低于正常（适合后台备份/下载）"),
    "normal": (0x00000020, "正常（系统默认）"),
    "above_normal": (0x00008000, "高于正常（前台交互程序用）"),
    "high": (0x00000080, "高（会明显抢 CPU，慎用）"),
}
_PRIORITY_ALIASES = {
    "low": "idle", "idle": "idle", "very_low": "idle", "lowest": "idle",
    "below_normal": "below_normal", "belownormal": "below_normal", "below": "below_normal",
    "normal": "normal", "medium": "normal", "default": "normal",
    "above_normal": "above_normal", "abovenormal": "above_normal", "above": "above_normal",
    "high": "high", "highest": "high", "higher": "high",
}
_CODE_TO_NAME = {0x40: "idle", 0x4000: "below_normal", 0x20: "normal",
                 0x8000: "above_normal", 0x80: "high", 0x100: "realtime"}
_PROTECTED_PIDS = {0: "System Idle Process（系统空闲进程，内核态）",
                   4: "System（内核态进程）"}


def _err_text(code: int) -> str:
    return _WIN32_ERRORS.get(code, f"Win32 错误 {code}")


def _priority_name(pid: int, access: int):
    """读当前优先级（只读）。返回 (句柄, 规范名)；打不开句柄返回 (None, None)。"""
    handle = _open_process(pid, access)
    if not handle:
        return None, None
    try:
        k = _kernel32()
        k.GetPriorityClass.argtypes = [wintypes.HANDLE]
        k.GetPriorityClass.restype = wintypes.DWORD
        code = int(k.GetPriorityClass(handle))
        return handle, _CODE_TO_NAME.get(code, f"未知({code})")
    except Exception:
        return handle, None


@declare_primitive(
    "process.set_priority",
    "调整某个进程的 CPU 优先级（idle / below_normal / normal / above_normal / high）。"
    "排队调度场景用：把后台备份/下载降到 below_normal 别抢前台，或给卡顿的编辑器临时提到 above_normal。"
    "会改变系统状态：**预览时会顺带报出当前优先级**，真改需过用户确认。"
    "拒绝执行：① 系统关键进程 PID 0/4；② 优先级 realtime（实时优先级会抢占系统线程，可能整机卡死）；"
    "③ 优先级取值非法。权限不足（改别的用户/更高权限的进程）返回中文说明而不是系统原文。",
    {"type": "object",
     "properties": {
         "pid": {"type": "string", "description": "进程 PID"},
         "priority": {"type": "string",
                      "enum": ["idle", "below_normal", "normal", "above_normal", "high"],
                      "description": "目标优先级，默认 normal（别名 low/belownormal/abovenormal 也认）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不修改（默认）；False=真修改"},
     },
     "required": ["pid"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"pid": "PID", "priority": "优先级"},
    block="process_system",
)
def process_set_priority(pid: str, priority: str = "normal", dry_run: bool = True) -> dict:
    try:
        pid_i = int(str(pid).strip())
    except (TypeError, ValueError):
        return {"ok": False, "pid": pid, "note": f"PID 不是数字：{pid!r}"}
    raw = (priority or "normal").strip().lower().replace("-", "_").replace(" ", "_")
    if raw == "realtime" or raw.startswith("real"):
        return {"ok": False, "pid": pid_i, "priority": raw, "blocked": True,
                "note": "拒绝设置 realtime（实时优先级）：它会盖过系统关键线程的调度，"
                        "轻则输入/音频丢失，重则整机卡死。这个能力不开放。"}
    name = _PRIORITY_ALIASES.get(raw)
    if name is None:
        return {"ok": False, "pid": pid_i, "priority": priority,
                "note": f"未知优先级 {priority!r}；可选：{' / '.join(_PRIORITY_CLASSES)}"}
    if pid_i in _PROTECTED_PIDS:
        return {"ok": False, "pid": pid_i, "priority": name, "blocked": True,
                "note": f"拒绝操作 PID {pid_i}（{_PROTECTED_PIDS[pid_i]}）：系统关键进程的优先级由内核管，"
                        f"不允许调整。"}
    if not _pid_alive(pid_i):
        return {"ok": False, "pid": pid_i, "priority": name,
                "note": "进程不存在（可能已退出；也可能是权限不足看不到）"}
    code, cn = _PRIORITY_CLASSES[name]
    out: dict = {"pid": pid_i, "priority": name, "priority_code": code, "dry_run": bool(dry_run),
                 "priority_before": None, "priority_after": None, "changed": False}
    # ① 只读探测当前优先级（用查询权限，**不是**设置权限）—— 预览和真改都需要它做对比
    handle, before = _priority_name(pid_i, _PROCESS_QUERY_LIMITED_INFORMATION)
    if before is not None:
        out["priority_before"] = before
        # 规范名 → 中文说明（realtime 这类不在表里的给 None，不编）
        out["priority_before_desc"] = (_PRIORITY_CLASSES.get(before) or (None, None))[1]
    if handle:
        _close(handle)
    # ② dry_run：到此为止，一个字节的状态都没改
    if dry_run:
        out.update({"ok": False, "dry_run": True,
                    "note": f"只读预览：未做任何修改。真执行将把 PID {pid_i}"
                            + (f"（当前 {out['priority_before']}）" if before else "")
                            + f"，优先级设为 {name}（{cn}）；需显式传 dry_run=False 并过用户确认。"})
        if before is None:
            out["permission_note"] = ("当前连『读优先级』的权限都没有，真改大概率也会被拒"
                                      "（该进程可能属于其他用户或更高权限）")
        return out
    # ③ 真改：需要 PROCESS_SET_INFORMATION（查询权限不够）
    handle = _open_process(pid_i, _PROCESS_SET_INFORMATION)
    if not handle:
        err = _last_error()
        out.update({"ok": False,
                    "note": f"打不开进程句柄，无法调整优先级：{_err_text(err)}。"
                            f"普通用户只能改**自己启动的**进程；要改系统/其他用户的进程，"
                            f"需以管理员身份运行本程序。"})
        return out
    try:
        k = _kernel32()
        k.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.SetPriorityClass.restype = wintypes.BOOL
        ok = bool(k.SetPriorityClass(handle, code))
        err = _last_error()
    except Exception as e:
        out.update({"ok": False, "note": f"设置失败：{e}"})
        return out
    finally:
        _close(handle)
    if not ok:
        out.update({"ok": False,
                    "note": f"系统拒绝修改优先级：{_err_text(err)}。"
                            f"常见原因：该进程属于其他用户 / 以更高权限运行（Protected Process）。"
                            f"以管理员身份重开可解决多数情况；本原语不做提权。"})
        return out
    # ④ 回读确认（只读）—— 不假设系统一定照做
    _, after = _priority_name(pid_i, _PROCESS_QUERY_LIMITED_INFORMATION)
    out.update({"ok": True, "priority_after": after, "changed": after == name,
                "note": f"PID {pid_i} 优先级 {before or '?'} → {after or name}"
                        + ("" if after == name else "（回读与请求不一致，可能被系统策略改写）")})
    return out
