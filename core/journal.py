"""调用日志 —— 记「什么时候动了系统」，给 agent 回看自己做过什么。

**它不是原语，是中间层自己的记录** —— 原语是「OS 能力」（进程 / 文件 / 网络），
而这里记的是 IntentOS 自己的调用历史。做成原语会有三个问题：概念上混（模型的工具表里
出现一条「查我自己的日志」，还会跟 OS 的 `event.query` 撞车）、占描述预算、
分块时归哪一块都不对。形态跟 `core/blocks.py` 一样：**给函数 + CLI 子命令，
接入方自己决定要不要给模型看、怎么看**。

**为什么「agent 优先」是这条日志的设计前提**：第一读者是模型自己
（「我刚才做过什么」），不是人、也不是合规审计。所以**只记元数据、不记返回结果** ——
一条 `fs.read` 读个 1MB 文件，若把返回也记下来，日志会按 GB 涨，
而模型要的其实只是「我读过它」。要完整回放是另一个需求，**不该由这一层扛**。

**写在哪**：`<项目根>/logs/journal-YYYY-MM-DD.jsonl`，一行一条，**按天切**。
按天而不是按「块」或「域」切 —— 一次操作常跨块，按它切会让时间线碎掉；
而**日志是历史，不该跟着会变的分类走**（块归属本身还改过两次）。

**挂载点**：`core/interpreter.ToolRegistry.execute` —— 所有走这个入口的调用
都会经过那里（IR / CLI / 面板 / 直调）。⚠️ 但**直抓函数对象调用绕不过去**
（测试脚本、或将来图省事的适配器），这是「尽力而为」不是「不可绕过」，
跟 ExecutionGate 是同一个性质。
"""
from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path

# 单个参数值最多记多少字符 —— escape 的 code / command 可能是一整段程序
_MAX_VAL = 200
# 每类自由文本字段（error / note）的上限
_MAX_TEXT = 400
# 查询时最多回看几个日志文件（按天切，7 个 = 一周）
_MAX_FILES = 7

_ENABLED = os.environ.get("INTENTOS_JOURNAL", "1").strip().lower() not in ("0", "false", "no", "off")
_WARNED = False          # 写失败只喊一次，别每次调用都刷屏


def set_enabled(on: bool) -> None:
    """开 / 关记录（测试里常关掉，免得噪音淹了真正的断言）。"""
    global _ENABLED
    _ENABLED = bool(on)


def is_enabled() -> bool:
    return _ENABLED


def log_dir() -> Path:
    """日志目录 —— 项目根下的 `logs/`（已被 .gitignore 排除，是运行时产物）。"""
    return Path(__file__).resolve().parent.parent / "logs"


def _day_path(day: str | None = None) -> Path:
    day = day or datetime.date.today().isoformat()
    return log_dir() / f"journal-{day}.jsonl"


def _clip(v):
    """把参数值收成一行能放下的大小。数字 / 布尔原样留，其余转字符串再截。"""
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    s = str(v)
    if len(s) > _MAX_VAL:
        return s[:_MAX_VAL] + f"…（共 {len(s)} 字符）"
    return s


def _clip_args(args) -> dict:
    try:
        return {str(k): _clip(v) for k, v in (args or {}).items()}
    except Exception:
        return {"<参数无法记录>": str(args)[:_MAX_VAL]}


def _append(rec: dict) -> None:
    global _WARNED
    try:
        path = _day_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        # ⚠️ 吞掉是**故意的**：日志写不进去，绝不能把原语本身拖失败。
        # 但只喊一次 —— 每次调用都喊会把 stderr 刷爆，反而盖住真正的问题。
        if not _WARNED:
            _WARNED = True
            print(f"[journal] 写日志失败（不影响原语执行）：{e}", file=sys.stderr)


def record(name: str, args=None, *, ok: bool = True, denied: bool = False,
           error=None, elapsed_ms=None, note: str = "") -> None:
    """记一条调用。**绝不该抛异常** —— 调用方在热路径上，日志不能反噬主流程。

    被拒的（denied=True）尤其要记 —— 那是「AI 想干、但没让干」的唯一证据，
    事后追查「它有没有试图删那个目录」靠的就是这一条。
    """
    if not _ENABLED:
        return
    rec: dict = {"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "name": name, "args": _clip_args(args), "ok": bool(ok)}
    if denied:
        rec["denied"] = True
    # 把 dry_run 提到顶层：一眼分清「这次是真动手还是只看了一眼」
    if isinstance(args, dict) and "dry_run" in args:
        rec["dry_run"] = bool(args["dry_run"])
    if error:
        rec["error"] = str(error)[:_MAX_TEXT]
    if note:
        rec["note"] = str(note)[:_MAX_TEXT]
    if elapsed_ms is not None:
        try:
            rec["elapsed_ms"] = round(float(elapsed_ms), 1)
        except (TypeError, ValueError):
            pass
    _append(rec)


def recent(limit: int = 50, since: str = "", name: str = "",
           denied_only: bool = False) -> list[dict]:
    """最近的调用记录，**按时间倒序**（最新的在最前）。

    limit        最多返回多少条
    since        只看这个时刻之后的，形如 "2026-09-12" 或 "2026-09-12 20:00"
                 （字符串前缀比较，所以给到哪一级就卡到哪一级）
    name         只看某个原语，支持片段匹配（"fs." 能捞出整个文件域）
    denied_only  只看被执行门拒掉的

    读不到日志（一次都没调用过 / 目录不存在）返回空列表，**不报错** ——
    「没有记录」和「记录读取失败」在这里不值得让调用方分叉处理。
    """
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 50
    files = sorted(log_dir().glob("journal-*.jsonl"), reverse=True)[:_MAX_FILES]
    hits: list[dict] = []
    for p in files:
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue                  # 半截行（写到一半被打断）跳过，不毁掉整次查询
            ts = str(rec.get("ts", ""))
            if since and ts < since:
                continue
            if name and name not in str(rec.get("name", "")):
                continue
            if denied_only and not rec.get("denied"):
                continue
            hits.append(rec)
    hits.reverse()                        # 文件是旧的在前，整体倒过来 = 最新在前
    return hits[:limit]


def render(records) -> str:
    """把记录渲染成**给模型读的紧凑文本**（参考实现，不是唯一正解 —— 接入方可自己写）。

    一行一条：时间 原语 结果 耗时 参数。失败/被拒的把原因缀在最后。
    """
    if not records:
        return "（没有记录）"
    width = max((len(str(r.get("name", ""))) for r in records), default=10)
    out = []
    for r in records:
        ts = str(r.get("ts", ""))[-8:]                     # 只留 HH:MM:SS
        name = str(r.get("name", "")).ljust(width)
        if r.get("denied"):
            state = "被拒"
        elif r.get("error"):
            state = "异常"
        elif r.get("ok"):
            state = "ok  "
        else:
            state = "失败"
        ms = r.get("elapsed_ms")
        line = f"{ts}  {name}  {state}  {f'{ms}ms' if ms is not None else ''}".rstrip()
        args = r.get("args")
        if args:
            line += "  " + json.dumps(args, ensure_ascii=False)
        tail = r.get("error") or r.get("note")
        if tail and r.get("denied"):
            tail = r.get("note") or tail
        if tail:
            line += f"  — {tail}"
        out.append(line)
    return "\n".join(out)


def render_recent(limit: int = 30, **kw) -> str:
    """`recent()` + `render()` 的便捷组合。"""
    return render(recent(limit=limit, **kw))


def stats(days: int = 7) -> dict:
    """粗看一眼日志有多少 —— 给「要不要清理」做判断用，不做清理本身。"""
    files = sorted(log_dir().glob("journal-*.jsonl"), reverse=True)[:max(1, int(days))]
    total, per_day = 0, {}
    for p in files:
        try:
            n = sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
        except OSError:
            continue
        per_day[p.stem.replace("journal-", "")] = n
        total += n
    size = sum(p.stat().st_size for p in files if p.exists())
    return {"files": len(files), "records": total, "bytes": size, "per_day": per_day}
