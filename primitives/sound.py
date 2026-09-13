"""声音域原语 —— 提示音与 wav 播放（sound.*）。

零依赖：只用**标准库的 winsound**（Windows 自带，不是第三方库），非 Windows 退化为终端响铃。

⚠️ **这条原语会真的发出声音** —— 它不破坏任何数据、不改变系统状态，但**会打扰正在用电脑的人**。
所以它的安全分级跟 `power.lock` 一样是「低危高频」：**不做 dry_run、不需确认**
（真加一道确认，它就没法当提示音用了），代价是 description 里必须把「会出声」写明白。

为什么它没有 dry_run：dry_run 是给「做错了会留下后果」的动作踩刹车的。
这里最坏的结果就是响一声 / 吵到人，多问一句只会让人烦 —— 分寸不在流程上，在「什么时候用」上。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_sound，注册进 factory.registry）。
"""
from __future__ import annotations

import os
import platform
import struct
import sys

from core.factory import declare_primitive  # type: ignore
from primitives._common import normalize_path

# 播放 wav 时「多久以内就等它播完」的阈值（秒）。
# 见 sound_beep 里 wait=None 的自动判定：短视频等它播完（不然调用方一退出声音就被掐断），
# 长音频改成异步（不能为了播首歌把 Agent 卡住几分钟）。
_SYNC_WAIT_LIMIT_S = 10.0

# WAVE 的格式码 → 人话（只翻认得的，别的一律原样给，不猜）
_WAVE_FORMATS = {1: "PCM（未压缩）", 3: "IEEE float", 6: "A-law", 7: "μ-law",
                 0x55: "MP3", 0xFFFE: "WAVE_FORMAT_EXTENSIBLE（扩展格式）"}


# ── wav 体检：读文件头 ──────────────────────────────────────────────────
def _wav_info(path: str) -> tuple[dict, str]:
    """只读文件头，判断「是不是 wav」并算出时长。返回 (信息字典, 错误说明)。

    ⚠️ **为什么不直接把路径丢给 PlaySound 就完事**：PlaySound 对「不是 wav / 文件不存在」
    只会抛一句 `Failed to play sound`，调用方根本不知道是路径写错了、还是文件格式不对、
    还是声卡被占了。这里先把文件头读一遍，就能给出人话说明。
    顺带把时长算出来 —— 它是「要不要等它播完」的判据（见 wait 参数）。

    ⚠️ **只认标准 RIFF/WAVE**：RF64 / WAVE64（超大文件的变体）这里判成「不是标准 wav」，
    如实说，不假装能播。
    """
    # 目录要先挡住：Windows 上 `open(目录, 'rb')` 抛的是 PermissionError 而不是
    # IsADirectoryError，不先判就会把「这是个目录」说成「权限不够」，误导人。
    if os.path.isdir(path):
        return {}, f"这是个目录，不是 wav 文件：{path}"
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return {}, f"文件不存在：{path}"
    except OSError as e:
        return {}, f"读不到这个文件（{e}）：{path}"
    if size < 44:
        return {}, f"文件太小（{size} 字节），不可能是一个 wav：{path}"

    try:
        with open(path, "rb") as f:
            head = f.read(12)
            if len(head) < 12 or head[:4] != b"RIFF" or head[8:12] != b"WAVE":
                magic = head[:12]
                hint = ""
                if magic[:4] == b"RF64":
                    hint = "（这是 RF64 变体，本原语只认标准 RIFF/WAVE）"
                elif magic[:4] in (b"ID3\x04", b"ID3\x03") or magic[:2] == b"\xff\xfb":
                    hint = "（看着像 mp3 —— PlaySound 只吃 wav）"
                elif magic[:4] == b"OggS":
                    hint = "（这是 ogg）"
                return {}, f"不是 wav 文件：文件头是 {magic!r}，不是 RIFF/WAVE{hint}"

            fmt: dict = {}
            data_bytes = None
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                cid = hdr[:4]
                csize = struct.unpack("<I", hdr[4:])[0]
                if cid == b"fmt ":
                    body = f.read(csize)
                    if len(body) < 16:
                        return {}, f"wav 的 fmt 块不完整（只有 {len(body)} 字节）：{path}"
                    afmt, ch, rate, byterate, _align, bits = struct.unpack("<HHIIHH", body[:16])
                    fmt = {"format_code": afmt,
                           "format": _WAVE_FORMATS.get(afmt, f"未知格式码 {afmt}"),
                           "channels": ch, "sample_rate": rate, "bits": bits,
                           "byte_rate": byterate}
                    if csize & 1:                       # 块长为奇数时后面有 1 字节补齐
                        f.seek(1, 1)
                elif cid == b"data":
                    data_bytes = csize
                    f.seek(csize + (csize & 1), 1)
                else:
                    f.seek(csize + (csize & 1), 1)      # 跳过不关心的块（LIST / fact / id3…）
                if fmt and data_bytes is not None:
                    break
    except OSError as e:
        return {}, f"读取 wav 文件头失败（{e}）：{path}"

    if not fmt:
        return {}, f"这是个 wav，但里面找不到 fmt 块（文件可能损坏）：{path}"

    info = {"path": path, "size_bytes": size, **fmt}
    # 时长 = 数据字节 / 每秒字节。0xFFFFFFFF 是「流式未知长度」的哨兵值，别拿它算除法。
    br = fmt.get("byte_rate") or 0
    if data_bytes in (None, 0xFFFFFFFF) or br <= 0:
        info["duration_s"] = None
        info["duration_note"] = "算不出时长（长度字段缺失，或是流式写入的 wav）"
    else:
        info["duration_s"] = round(data_bytes / br, 2)
    return info, ""


# ── 响一声 ──────────────────────────────────────────────────────────────
def _posix_fallback(what: str) -> dict:
    """非 Windows：退化为终端响铃（BEL）。写 stderr 并立刻 flush —— 写 stdout 会被缓冲掉。"""
    try:
        sys.stderr.write("\a")
        sys.stderr.flush()
    except Exception:
        pass
    return {"ok": False, "kind": "bell", "verified": None,
            "note": f"当前平台是 {platform.system()}，没有 winsound。已向终端写了一个响铃字符（BEL）——"
                    f"{what}；很多终端 / 无 tty 的环境下这个是静音的，**不代表机器会出声**"}


@declare_primitive(
    "sound.beep",
    "让这台电脑**发出声音**：响一声系统提示音（默认）/ 按指定频率鸣一声 / 播放一个 wav 文件。"
    "用于「干完了提醒一声」「需要人来看一眼」这类信号。"
    "⚠️ **它会真的出声、会打扰正在用电脑的人** —— 不破坏数据也不改系统状态，"
    "所以**不做 dry_run**（跟锁屏同级的低危高频），但**别用它做无意义的循环打扰**。"
    "kind 默认 ding（Windows 信息提示音，跟随系统「声音方案」和音量；系统静音时安静地什么都不发生）；"
    "kind=tone 是按 frequency 赫兹鸣 duration_ms 毫秒的方波（蜂鸣器音，不受提示音方案影响）;"
    "kind=wav 或**直接给 file 参数**则播放该 wav（只读该文件，不限路径）。"
    "返回的 verified 恒为 None —— **有没有真的响，本原语无法复核**（静音 / 没声卡 / 没配声音方案都会安静地成功）。"
    "⚠️ 与 ui.notify 的分工：**要给用户看到文字**（任务跑完了 / 有个失败要人来看一眼）用 ui.notify "
    "（系统通知气泡，带标题与正文，但可能被系统勿扰吞掉）；本原语只**出声**、不带文字，"
    "适合「用户就在电脑前，响一声就够」。两者都会打扰用户 —— 需要文字才用通知，否则用本条更轻。",
    {"type": "object",
     "properties": {
         "kind": {"type": "string", "enum": ["ding", "tone", "wav"],
                  "description": "出声方式：ding=系统提示音（默认）；tone=按频率鸣叫；wav=播放文件。"
                                 "给了 file 参数时自动按 wav 处理"},
         "file": {"type": "string",
                  "description": "要播放的 wav 文件路径（给这一项就等价于 kind=wav）。只读该文件"},
         "frequency": {"type": "number", "minimum": 37, "maximum": 32767,
                       "description": "kind=tone 时的频率赫兹，37~32767，默认 800（超出会被夹到区间内）"},
         "duration_ms": {"type": "integer", "minimum": 1, "maximum": 10000,
                         "description": "kind=tone 时的时长毫秒，默认 300（最长 10 秒，超出会被夹到上限）"},
         "wait": {"type": "boolean",
                  "description": "播放 wav 时是否等它播完再返回。不给则自动：10 秒以内等，"
                                 "超过 10 秒异步返回（不阻塞 Agent）"},
     },
     "required": [],
     "additionalProperties": False},
    state={"kind": "方式", "ok": "已出声"},
    block="display_ui",
)
def sound_beep(kind: str = "ding", file: str = "", frequency: float = 800,
               duration_ms: int = 300, wait: bool | None = None) -> dict:
    # 给了 file 参数 → 一律按 wav 走（调用方给了文件，意图已经不用猜了）。
    # ⚠️ 判据是「**原值非空**」而不是「strip 后非空」：传了个空格的路径是**写错了**，
    # 该报「路径不能为空」；若按 strip 后判，就会悄悄退化成响一声提示音 —— 那就成了
    # 「报错变成了副作用」，比报错更糟。
    raw_file = "" if file is None else str(file)
    target = raw_file.strip()
    mode = (kind or "ding").strip().lower()
    if raw_file:
        mode = "wav"
    if mode not in ("ding", "tone", "wav"):
        return {"ok": False, "kind": mode, "verified": None,
                "note": f"不认识的 kind={kind!r}，可选 ding / tone / wav"}

    if platform.system() != "Windows":
        return _posix_fallback(f"想做的其实是 kind={mode}")

    try:
        import winsound
    except ImportError:
        return _posix_fallback("这台机器上没有 winsound 模块")

    # ① 系统提示音 —— 最省事的一声「叮」。跟随系统声音方案，静音时就是没声音。
    if mode == "ding":
        try:
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception as e:
            return {"ok": False, "kind": "ding", "verified": None, "note": f"发出提示音失败：{e}"}
        return {"ok": True, "kind": "ding", "verified": None,
                "note": "已下发系统提示音（Windows 的「信息」提示音）。它跟随系统的声音方案与音量 —— "
                        "系统静音、或没配声音方案时，会**安静地什么都不发生**；"
                        "**到底有没有真的响，本原语无法复核**"}

    # ② 方波鸣叫 —— 蜂鸣器式的一声。这个走的是系统音频设备，提示音方案管不到它。
    if mode == "tone":
        try:
            freq = int(round(float(frequency)))
            ms = int(duration_ms)
        except (TypeError, ValueError):
            return {"ok": False, "kind": "tone", "verified": None,
                    "note": f"frequency / duration_ms 得是数字，收到 {frequency!r} / {duration_ms!r}"}
        freq_raw, ms_raw = freq, ms
        freq = min(max(freq, 37), 32767)        # Windows Beep 的合法区间是 37~32767 Hz
        ms = min(max(ms, 1), 10000)             # 上限 10 秒：别让它变成卡住调用方的噪音
        try:
            winsound.Beep(freq, ms)             # 同步调用，响完才返回
        except Exception as e:
            return {"ok": False, "kind": "tone", "frequency": freq, "duration_ms": ms,
                    "verified": None, "note": f"鸣叫失败：{e}"}
        note = f"已用 {freq}Hz 鸣了 {ms}ms（同步，响完才返回）"
        if (freq, ms) != (freq_raw, ms_raw):
            note += f"；注意请求的是 {freq_raw}Hz/{ms_raw}ms，已被夹到合法区间"
        return {"ok": True, "kind": "tone", "frequency": freq, "duration_ms": ms,
                "waited": True, "verified": None, "note": note}

    # ③ 播放 wav —— 先体检再播，把「文件不存在 / 不是 wav」讲成人话
    # 路径规范化走共享层的那一份（跟 fs 域的读一致：展开 %变量%/~、解析软链接，
    # 但**不做系统禁区判定** —— 读侧不设路径限制，播一个在系统目录里的 wav 是正当需求）
    try:
        path = normalize_path(target)
    except ValueError:
        return {"ok": False, "kind": "wav", "file": target, "verified": None,
                "note": "文件路径不能为空"}
    info, err = _wav_info(path)
    if err:
        return {"ok": False, "kind": "wav", "file": path, "verified": None, "note": err}

    dur = info.get("duration_s")
    # wait 没给就自动判定：短视频等它播完（否则调用方一退出，声音会被掐断），长音频异步返回
    sync = wait if isinstance(wait, bool) else (dur is not None and dur <= _SYNC_WAIT_LIMIT_S)
    flags = winsound.SND_FILENAME | winsound.SND_NODEFAULT | (0 if sync else winsound.SND_ASYNC)
    try:
        winsound.PlaySound(path, flags)
    except Exception as e:
        return {"ok": False, "kind": "wav", "file": path, "verified": None,
                "note": f"播放失败（文件是合法 wav，但系统放不出来 —— "
                        f"可能是格式的解码器缺失或声卡被占用）：{e}"}

    brief = f"已播放 {path}"
    if dur is not None:
        brief += (f"（{dur} 秒 / {info.get('sample_rate')}Hz / "
                  f"{info.get('channels')} 声道 / {info.get('format')}）")
    if sync:
        brief += "；已等它播完"
    else:
        brief += ("；异步播放、不等它播完 —— **本进程若在播完前退出，声音会被截断**"
                  "（要确保放完就传 wait=true）")
    if info.get("duration_note"):
        brief += f"；{info['duration_note']}"
    return {"ok": True, "kind": "wav", "file": path, "waited": sync,
            "duration_s": dur, "audio": {k: info[k] for k in
                                         ("format", "channels", "sample_rate", "bits") if k in info},
            "verified": None, "note": brief}
