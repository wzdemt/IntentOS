"""工具分块 —— 把原语按「操作对象」归成 13 块，供接入方按需展开。

**要解决的问题**：97 条原语的完整说明书约 66889 字符 ≈ 33K tokens，是每轮对话的
固定开销。分块后接入方只把「块目录」常驻（约 1000 tokens），用到哪块展开哪块
—— 实测典型场景省 75% 以上（只碰文件 8.4K、网络排查 7.2K）。

**为什么按「操作对象」分，不照搬现有的「域」**：
  · `fs` / `process` / `display` / `power` / `disk` 这类域**天然就是对象**，直接成块
  · 但 `net`（14 条）含网卡 / 连接 / 端口 / 路由 / 防火墙，排查网络时
    ping → dns → tcp_check → routes 是一条链，**拆开反而割裂**；
    `system` 与 `process` 讲的都是「这台机器现在怎么样」，拆开会来回横跳
  · 于是**保留语义完整的块，只把真正跨对象的挪位**：
    `acl.get` → 文件与目录（「谁能读这文件」是文件问题）、
    `time.zones` → 进程与系统资源、`sound.beep` → 显示与界面（与 `ui.notify` 是一对）

**设计要点（两条，都是踩过的）**：
  1. **块内是该对象下所有原语的完整说明，不是压缩成一句话** ——
     `fs.list` / `fs.entries` / `fs.tree` 展开时三条完整描述一起看到，
     不会出现「知道 `fs.list`、不知道 `fs.entries`」。
     **它把「谁跟谁容易混」从描述里的文字，变成了结构上的物理相邻。**
  2. **块归属在原语声明里显式写**（`@declare_primitive(..., block="filesystem")`），
     **不靠名字前缀猜** —— `time.zones` 住在 `system.py`、`acl.get` 住在 `acl.py`，
     靠文件名或前缀猜，以后加原语迟早猜错。

**本模块只定义「块是什么」+ 怎么导出**，不含任何「什么时候加载哪块」的逻辑 ——
README 那条「中间层不预设任何 LLM，怎么转格式是接入方自己的事」管着这件事，
而**分块加载正是「转格式」的一部分**。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Block:
    """一个块 = 一类「操作对象」下所有原语的集合。

    title / summary 是**给模型看的那句话**，写法有两条硬规矩（两轮盲测换来的）：
      · 用「**用户会问的问题**」，不用「能力名」——
        写「文件关联（双击用什么打开）」，不写「注册表」
      · 边界要说「**不覆盖什么**」并给出路 ——
        写「只管动手，查为什么重启的去事件日志」
    """

    id: str
    title: str
    summary: str
    always_on: bool = False


# 顺序 = 块目录里的展示顺序，也 = 导出顺序（固定下来，接入方渲染结果才稳定）
BLOCKS: tuple[Block, ...] = (
    Block("filesystem", "文件与目录",
          "读写删改文件、按名字找/按内容搜、看大小/时间/属性/谁能读谁能改"),
    Block("network", "网络",
          "网卡与 IP、路由、连接、端口被谁占、通不通、防火墙、下载文件、网卡流量统计"),
    Block("display_ui", "显示与界面",
          "屏幕与窗口、截屏、剪贴板、模拟输入、弹通知/提示音"),
    Block("process_system", "进程与系统资源",
          "进程列表/查找/结束、内存、CPU、当前时间/时区、开机多久（不含取进程的输出）"),
    Block("service_task", "服务与计划任务",
          "后台服务、定时任务、开机都自动跑什么"),
    Block("config", "系统配置",
          "注册表、环境变量、文件关联（双击用什么打开）—— 只能看当前值，不记录是谁改的"),
    Block("power", "电源",
          "关机/重启/注销/锁屏/睡眠、电源计划、电池（只管动手，查「为什么重启的」去事件日志）"),
    Block("disk", "磁盘",
          "按盘算容量（有几个盘、某个路径还剩多少空间）、硬盘健康"
          "（不含磁盘读写速度 / IO 性能）"),
    Block("event", "事件日志",
          "查系统日志（含上次为什么重启/关机）、看有哪些日志、清日志"),
    Block("archive", "压缩包",
          "看包内容、解压、打包"),
    Block("recycle_shortcut", "回收站与快捷方式",
          "回收站内文件的查看/还原/清空（不含彻底删除的恢复）、.lnk 快捷方式读写"),
    Block("device", "外设",
          "只能列出打印机、USB 设备。要判断「U 盘能不能安全拔出」（设备占用）"
          "本库没有，走逃生舱"),
    # 逃生舱**必须常驻**（不进按需列表）：它是「最后手段」这个约束本身，
    # 模型得随时知道它在，否则会当通用 shell 滥用。这 563 tokens 不能省。
    # summary 里那句「当某组说明明确写了不含时直接走它」同样重要 ——
    # 没有它，模型会逐组试过去（测试实测过）。
    Block("escape", "逃生舱",
          "执行以上都没覆盖的操作（最后手段，需确认）。"
          "**当某块的说明明确写了「不含 / 不能」某类需求时，直接走它，不必逐块试**",
          always_on=True),
)

_BY_ID: dict[str, Block] = {b.id: b for b in BLOCKS}
BLOCK_IDS: tuple[str, ...] = tuple(b.id for b in BLOCKS)

# ── 全库通用约定 ──
# **所有原语都适用，所以各条描述里不再重复**。这一段是 2026-09-12 扫描 97 条描述
# 量出来的账：描述总量里约 11% 的篇幅花在**重复解释这些框架行为**上
# （「dry_run 默认 True」「确认门按原语挂」「预览时 ok 是什么」…），
# 抽到这里写一次，其余各条删掉重复部分。
#
# ⚠️ **改这里比改 97 条描述安全得多，但改之前必须核实**：每一条都得确认它对
# **全库**成立，否则就是把一个错误答案写进了所有读取方都会看的地方。
# **当天（2026-09-12）的核实依据记在这里，不写进 CONVENTIONS** ——
# 那是给维护者看的，模型不需要，写进去就是白占常驻 token：
#   · 第 1 条：35/35 条带 dry_run 的原语默认值都是 True
#   · 第 2 条：预览时 ok=False 22 条 / ok=True 1 条（fs.attrs）/ 无该字段 12 条 ——
#             **正因为不统一，才要统一说「看 dry_run 不看 ok」**
#   · 第 3 条：PolicyRule 只有 op / allow / requires_confirmation / allowed_paths 四个字段，
#             无参数维度；执行门的「无人可问」分支是 fail-closed
#   · 第 6 条：执行门里「没登记策略、或策略没标需确认」一律直接放行
CONVENTIONS = """【本库通用约定】—— 所有原语都适用，各条描述里不再重复

1. 写操作默认只预览：带 dry_run 的原语默认都是 true，不传就是「只看不动」，
   真执行必须显式传 dry_run=false。

2. 判断「这次有没有真的动手」看 dry_run 字段，别只看 ok —— ok 的含义**因原语而异**
   （有的表示「调用跑通了」、有的表示「握手成功」，个别原语根本不带这个字段）。

3. 确认门**按原语挂、不看参数**：声明了需确认的原语，**它的所有调用**都要过确认门 ——
   包括只读动作（列出 / 查询 / 读取）。这是机制决定的，不是 bug。
   唯一例外是**纯预览**（传了 dry_run=true）：它一个字节都不改，所以免确认。

4. **取不到 ≠ 没有问题**：读不到数据时返回 null / 空列表并配 note 说明原因
   （权限不足、驱动不支持、设备不在位…），那是「**读不到**」而不是「**没有**」——
   别把 count=0 或 null 当成否定结论。

5. 没做成时**原因在 note 里**（中文），别只看 ok 或业务字段。

6. **没声明「需确认」的原语直接执行**，不会弹确认；声明了的都要过门（见第 3 条）。"""


def export_conventions() -> str:
    """全库通用约定 —— 接入方该跟块目录一起常驻的那段。

    它是「所有原语共用」的说明，所以**接入方注入一次就够**，
    不必（也不该）在每条工具说明里重复。
    """
    return CONVENTIONS


def get_block(block_id: str) -> Block | None:
    """按 id 取块定义；id 不认识返回 None（调用方据此报错，别静默吞掉）。"""
    return _BY_ID.get(block_id)


def is_valid_block(block_id: str) -> bool:
    return block_id in _BY_ID


# ── 导出接口 ──
# ⚠️ 下面三个函数要读 factory 的登记表（BLOCK_OF / registry），而 factory 又要
# import 本模块拿块定义。**在函数体内延迟 import** 解掉这个环 —— 顶层 import
# 会让两边互相等，加载顺序一变就炸。


def export_catalog() -> list[dict]:
    """块目录 —— 那份该常驻接入方上下文的清单。

    返回 [{id, title, summary, always_on, count, primitives}, ...]，**结构化**，
    不替接入方决定怎么渲染（要现成的可读文本用 `render_catalog()`）。
    """
    from core.factory import BLOCK_OF, registry

    names = set(registry.list_tools())
    out: list[dict] = []
    for b in BLOCKS:
        members = sorted(n for n, bid in BLOCK_OF.items() if bid == b.id and n in names)
        out.append({"id": b.id, "title": b.title, "summary": b.summary,
                    "always_on": b.always_on, "count": len(members),
                    "primitives": members})
    return out


def export_block(block_id: str) -> dict:
    """某块下所有原语的**完整声明**（名称 / 说明 / schema / 策略 / 是否需确认）。

    这是「展开一块」该拿的东西 —— 接入方拿到后自己转成自家 LLM 的工具格式。
    block_id 不认识时返回 {"ok": False, "note": ...}，不抛异常
    （接入方的参数可能来自模型，报错比崩掉好）。
    """
    from core.factory import BLOCK_OF, POLICY, registry

    b = _BY_ID.get(block_id)
    if b is None:
        return {"ok": False, "block": block_id,
                "note": f"没有这个块：{block_id}；可选：{' / '.join(BLOCK_IDS)}"}
    tools = registry.list_tools()
    items: list[dict] = []
    for name in sorted(n for n, bid in BLOCK_OF.items() if bid == block_id):
        t = tools.get(name)
        if not t:                              # 登记了块但原语没加载成功
            continue
        pol = POLICY.get(name) or {}
        items.append({"name": name,
                      "description": t.get("description", ""),
                      "schema": t.get("schema"),
                      "requires_confirmation": bool(pol.get("requires_confirmation")),
                      "source": t.get("source", "native")})
    return {"ok": True, "block": b.id, "title": b.title, "summary": b.summary,
            "always_on": b.always_on, "count": len(items), "primitives": items}


def render_catalog(with_conventions: bool = True) -> str:
    """把块目录渲染成可读文本 —— **参考实现，不是唯一正解**。

    默认**连「全库通用约定」一起给** —— 那才是接入方该常驻的完整一份；
    只要目录就传 `with_conventions=False`。
    接入方可以直接拿去用，也可以自己写渲染（它只是格式，不是协议）。
    """
    from core.factory import BLOCK_OF, registry

    names = set(registry.list_tools())
    lines: list[str] = []
    if with_conventions:
        lines.extend([CONVENTIONS, ""])
    for b in BLOCKS:
        members = sorted(n for n, bid in BLOCK_OF.items() if bid == b.id and n in names)
        tag = "【常驻】" if b.always_on else ""
        lines.append(f"· {tag}{b.title}（{len(members)}）── {b.summary}")
        if members:
            lines.append("    " + " ".join(members))
    return "\n".join(lines)


def check_coverage() -> dict:
    """校验块归属的完整性 —— 给「以后加原语忘了写 block」上一道门。

    返回三类问题，全空表示覆盖完整：
      · missing        —— 原语存在但没声明 block（新增原语最容易漏这个）
      · stale          —— 声明了 block 却没这条原语（改名字 / 删原语后的残留）
      · unknown_block  —— block id 不在 BLOCKS 里（拼错了）
    """
    from core.factory import BLOCK_OF, registry

    names = set(registry.list_tools())
    declared = set(BLOCK_OF)
    unknown = sorted({v for v in BLOCK_OF.values() if v not in _BY_ID})
    missing = sorted(names - declared)
    bad = sorted(n for n, v in BLOCK_OF.items() if v in _BY_ID and n not in names)
    return {"missing": missing, "stale": bad, "unknown_block": unknown,
            "ok": not (missing or bad or unknown)}
