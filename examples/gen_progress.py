"""能力进度生成器 —— 把「实际注册的原语」和「能力地图」对起来，算出落地进度。

跑一次，刷新两个出口（同一份数据、两个看法）：
    docs/os-progress.md    树形进度图（给人看 / 能分享）
    docs/os-progress.json  同一份数据（panel 网页读它渲染）

用法：
    python examples/gen_progress.py

**为什么不手写进度文档**：手写的会跟代码脱节 —— 文档说做了、代码里没有，人眼看不出来。
这里让两边自动对账，顺带能查出「写了代码但没登记进地图」的漏网原语。

数据流：
    primitives/ 实际注册的原语 ─┐
                                ├─→ build_progress() ─┬─→ os-progress.md
    docs/os-capability-map.md ──┘                     └─→ os-progress.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from core import factory  # type: ignore

# 能力地图已归档（2026-09-11）：它是 09-10 的一次性调研产出，使命完成后移进 archive/。
# 进度图仍在用它当**数据源**（那份 204 条清单是唯一权威），只是位置变了 ——
# 人平时不用看它，实现新原语时才翻。
MAP_MD = _BASE / "docs" / "archive" / "os-capability-map.md"
OUT_MD = _BASE / "docs" / "os-progress.md"
OUT_JSON = _BASE / "docs" / "os-progress.json"

# 已实现、但不以「原语」形式注册的（工具函数等）—— 手工确认，否则进度会显示成「没做」
DONE_MANUAL = {
    "fs.path": "工具函数（PolicyGate 辅助，不注册为原语）",
}

# 地图里的规划名 → 代码里当前实际的名字
#   fs.find      —— 地图规划把 fs.search 增强并改名为 fs.find，代码里仍叫 fs.search
#   reg.get /    —— 与已有的 registry.read 是**同一个能力**：地图是从两条不同路径盘点出来的
#   reg.list          （一条走「系统配置」、一条走「文件与存储」），落地时是同一件事
#   reg.set      —— 与 registry.write 是同一个能力
# 不登记成别名的话，这几条会永远挂在「没做」栏，进度数字就是假的。
_ALIASES = {
    "fs.find": "fs.search",
    "reg.get": "registry.read",
    "reg.list": "registry.read",
    "reg.set": "registry.write",
}

# 地图归档（2026-09-11）之后新增的原语 —— 地图里注定没有它们，别让对账器一直报警。
# ⚠️ 加新原语时若地图里也没有，**先想清楚是「漏登记」还是「真属于新类别」**再决定放哪：
#    漏登记 → 补地图；新类别 → 加到这儿。
_POST_MAP_ADDITIONS = {
    "escape": "逃生舱（地图归档后新增，见 os-primitives.md 的安全约定）",
    # 地图里那条「内存总量/可用/占用」**没有写原语名**（只写了描述），脚本按名字匹配不上 ——
    # 实现时给它起了 system.memory，在这里登记，免得对账提示一直挂着。
    "system.memory": "内存详细账目（地图里那条没写原语名）",
}

# 地图里有条目、但**第一列没写原语名**（只写了中文描述）—— 按描述对上实现名。
# 目前只有一条：「内存总量/可用/占用」，实现时起名 system.memory。
_LABEL_TO_TOOL = {
    "内存总量/可用/占用": "system.memory",
}

_BAR_CELLS = 20

# `### 3.1 进程与系统资源域（77 条）`
_DOMAIN_RE = re.compile(r"^###\s+3\.\d+\s+(.+?)\s*[（(]\s*\d+\s*条\s*[)）]")
# `**A. 进程**`
_GROUP_RE = re.compile(r"^\*\*(.+?)\*\*$")
# 反引号里的「域.动作」，如 `process.info`
_ID_RE = re.compile(r"`([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)`")


def _bar(done: int, total: int) -> str:
    """画一条进度条（比例取整，分母为 0 时给空条）。"""
    if total <= 0:
        return "░" * _BAR_CELLS
    filled = round(_BAR_CELLS * done / total)
    return "█" * filled + "░" * (_BAR_CELLS - filled)


def parse_capability_map(md_path: Path) -> list[dict]:
    """解析地图的三张能力表 → [{name, groups:[{name, items:[...]}]}]。

    只认「### 3.x 域（N 条）」标题底下的表格：表格里的 `**A. 进程**` 这类行开一个新组。
    跨域重复盘点的能力（地图总览里自己标了 3 处）**以首次出现为准**，后面重复的跳过。
    """
    domains: list[dict] = []
    cur_domain: dict | None = None
    cur_group: dict | None = None
    seen: set[str] = set()
    for line in md_path.read_text(encoding="utf-8").splitlines():
        line = line.rstrip()
        m = _DOMAIN_RE.match(line)
        if m:
            cur_domain = {"name": m.group(1).strip(), "groups": [], "raw": 0}
            domains.append(cur_domain)
            cur_group = None
            continue
        if cur_domain is None or not line.startswith("|"):
            continue
        # markdown 表格用 `\|` 表示字面竖线（如 `shutdown /s\|/r\|/l`）——
        # 直接按 | 切列会让整行错位，先换占位符、切完再还原
        cells = [c.strip().replace("\x00", "|")
                 for c in line.replace("\\|", "\x00").strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        first = cells[0]
        if not first or set(first) <= set("-: "):     # 表头下的分隔行 |---|---|
            continue
        if first.startswith("原语"):                   # 表头行
            continue
        g = _GROUP_RE.match(first)
        if g:                                          # 分组标题行
            cur_group = {"name": g.group(1).strip(), "items": []}
            cur_domain["groups"].append(cur_group)
            continue
        if cur_group is None:
            continue
        advice = cells[3]
        if "✅" in advice:
            verdict = "primitive"
        elif "⚠️" in advice:
            verdict = "template"
        elif "❌" in advice:
            verdict = "exec"
        else:
            verdict = "unknown"
        ids = _ID_RE.findall(first)
        cid = ids[0] if ids else None
        cur_domain["raw"] += 1                         # 逐行数（含重复），用于跟地图总盘对账
        if cid:
            if cid in seen:                            # 同一能力被列多次 → 以首次出现为准
                continue
            seen.add(cid)
        label = _ID_RE.sub("", first).replace("**", "").strip().strip("（）()").strip()
        if not label:
            # 地图里有些行第一列只有反引号名字、没有中文说明 —— 从「作用」列取个短标签，
            # 否则标签会退化成 id，显示成 `process.info` process.info 这种左右重复
            desc = re.split(r"[。：:]", cells[1])[0].strip()
            if len(desc) > 18:                        # 太长才断，优先断在标点处
                m = re.match(r"^(.{4,18}?)[，,、；;（(]", desc)
                desc = m.group(1) if m else desc[:17] + "…"
            label = desc
        cur_group["items"].append({
            "id": cid,
            "label": label or (cid or first),
            "verdict": verdict,
            "star": "★" in cells[4],
        })
    return domains


def build_progress() -> dict:
    """算出当前进度（panel 直接用这个函数返回的 dict，也可序列化进 JSON）。"""
    factory.load_primitives(str(_BASE / "primitives"))
    registered = set(factory.registry._tools.keys())
    domains = parse_capability_map(MAP_MD)

    out_domains: list[dict] = []
    total_planned = total_done = total_items = 0
    for dom in domains:
        groups: list[dict] = []
        d_planned = d_done = 0
        for grp in dom["groups"]:
            items = []
            for it in grp["items"]:
                planned = it["verdict"] == "primitive"
                actual = (_ALIASES.get(it["id"], it["id"]) if it["id"]
                          else _LABEL_TO_TOOL.get(it["label"]))
                done = bool(actual) and (actual in registered or it["id"] in DONE_MANUAL)
                if planned:
                    d_planned += 1
                    if done:
                        d_done += 1
                items.append({**it, "planned": planned, "done": done})
            groups.append({"name": grp["name"], "items": items})
        total_planned += d_planned
        total_done += d_done
        total_items += sum(len(g["items"]) for g in groups)
        out_domains.append({"name": dom["name"], "planned": d_planned,
                            "done": d_done, "groups": groups})

    # 对账：代码里有、地图里没列的原语（漏登记，会当场露馅）
    mapped = {_ALIASES.get(it["id"], it["id"])
              for d in domains for g in d["groups"] for it in g["items"] if it["id"]}
    unmapped = sorted(n for n in registered
                      if n not in mapped and n not in _POST_MAP_ADDITIONS)

    raw_total = sum(d.get("raw", 0) for d in domains)
    return {"summary": {"planned": total_planned, "done": total_done,
                        "all": total_items, "all_raw": raw_total},
            "domains": out_domains, "unmapped": unmapped}


def render_markdown(p: dict) -> str:
    """渲染成给人看的进度图。已落地 / 待落地列成勾选框，其余（IR模板 / exec）折叠收起。"""
    s = p["summary"]
    L: list[str] = [
        "# IntentOS 能力落地进度",
        "",
        "> ⚙️ **本文件由脚本生成 —— 手改会在下次刷新时被覆盖。** 刷新命令：`python examples/gen_progress.py`",
        "> 数据源：`primitives/` 实际注册的原语 × `docs/os-capability-map.md` 的能力清单。",
        "",
        "## 总览",
        "",
        f"**已落地 {s['done']} / {s['planned']}** 条「建议做原语」的能力",
        "",
        f"（地图逐行清点共 {s.get('all_raw', s['all'])} 条，其中同一能力被重复列举的已合并"
        f"—— 落地时它们是同一个原语的参数，去重后 **{s['all']}** 条。）",
        "",
        "```",
    ]
    for d in p["domains"]:
        L.append(f"{d['name']}  {_bar(d['done'], d['planned'])}  {d['done']} / {d['planned']}")
    L += ["```", "", "## 能力树", ""]

    for d in p["domains"]:
        L.append(f"### {d['name']} —— {d['done']} / {d['planned']}")
        L.append("")
        for g in d["groups"]:
            L.append(f"**{g['name']}**")
            L.append("")
            for it in g["items"]:
                if not it["planned"]:
                    continue                      # ⚠️/❌ 的折叠到下面，主区只列要做的
                mark = "x" if it["done"] else " "
                star = " ★首批" if it["star"] else ""
                name = f"`{it['id']}`" if it["id"] else ""
                L.append(f"- [{mark}] {name} {it['label']}{star}".rstrip())
            L.append("")

    # 非原语项（IR 模板 / 留给 exec）：折叠，作参考
    for verdict, title in (("template", "⚠️ IR 模板（拼好的现成套路，不单独做原语）"),
                           ("exec", "❌ 留给通用命令")):
        rows = [(d["name"], it) for d in p["domains"] for g in d["groups"]
                for it in g["items"] if it["verdict"] == verdict]
        if not rows:
            continue
        L += ["<details>", f"<summary>{title} —— {len(rows)} 条</summary>", ""]
        for dname, it in rows:
            name = f"`{it['id']}`" if it["id"] else ""
            L.append(f"- {name} {it['label']}  ·{dname}·".replace("  ", " ").rstrip())
        L += ["", "</details>", ""]

    if p["unmapped"]:
        L += ["## ⚠️ 对账提示", "",
              f"以下 {len(p['unmapped'])} 个原语**已在代码里注册，但能力地图没登记**"
              f"（要么补进地图，要么它们是漏网的非原语）：", ""]
        L += [f"- `{n}`" for n in p["unmapped"]]
        L.append("")

    return "\n".join(L)


def main() -> None:
    p = build_progress()
    OUT_MD.write_text(render_markdown(p), encoding="utf-8")
    OUT_JSON.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")
    s = p["summary"]
    print(f"✅ 进度已刷新：{s['done']} / {s['planned']}（地图总盘 {s['all']} 条）")
    print(f"   {OUT_MD}")
    print(f"   {OUT_JSON}")
    if p["unmapped"]:
        print(f"⚠️  有 {len(p['unmapped'])} 个已注册原语没在能力地图里：{', '.join(p['unmapped'])}")


if __name__ == "__main__":
    main()
