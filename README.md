# IntentOS — AI 意图的语义执行层

**中文** | [English](README.en.md)

> Agent 操作本机，现在是「说一句 → 等一个工具 → 再说一句」。
> IntentOS 让它**把一串操作一次写出来**（一段 IR，本质是一小段程序），交过来本地执行——
> 校验、并行、过安全闸，一次跑完，返回结构化结果。

类比：**MCP 是 USB 接口（定义怎么连设备），IntentOS 是 CPU 指令集（定义怎么执行意图）**。
它不是又一个 Agent 框架，而是**任何 Agent 都能嵌入的执行引擎**。

**它把三件事收进一个层里：**

- **稳定的接口** —— 同一套原语，底下是 PowerShell / ctypes / CIM，调用方不用管；系统的坑在层内消化
- **内建的安全** —— 路径禁区、高危确认、`dry_run` 默认只预览，全部**硬编码在解释器里**，不靠模型自觉
- **一次交一批** —— DAG 并行执行，省掉反复过模型的往返

**零依赖**：核心只用 Python 标准库。唯一的外部依赖 `pywin32` 只被剪贴板 / COM 相关的少数原语用到——不装也不影响其余原语。

> ⚠️ **平台现状（如实说）**：内核（IR 协议 / 解释器 / Policy Gate）与平台无关，
> **当前实现的原语是 Windows 版**（进程 / 服务 / 注册表 / 计划任务等）。
> 扩展路径就藏在这套设计里 —— 加一套对应平台的 `primitives/`，内核一行不用改。

---

## 30 秒看效果

```bash
python core/interpreter.py
```

不烧任何 API、不需要任何配置。跑完你会看到：

```
✅ ok=True   结果都落在寄存器里: ['sys', 'disks', 'svc']
   system.info  → Windows AMD64 · 内存 16110MB 总 / 5691MB 可用
   service.list → 运行中 3 条
   disk.list    → {'ok': True, 'count': 2, ...}

🚫 {'ok': False, 'errors': ["指令[0] 依赖 'never_defined' 未定义"]}
   ✅ 拦住：高危原语 fs.delete 无人可确认，已拒绝。
```

三条只读原语**并行**跑完、非法 IR 在**执行前**就被静态校验拦下、高危操作在**无人可确认**时被拒绝——
这就是这个项目在做的事。

---

## 快速开始

```bash
git clone <repo-url> && cd intentos
pip install pywin32          # 只有 Windows 需要；不装也不影响大多数原语

# ① 核心演示 —— 不烧任何 API（IntentOS 是工具，里面没有 LLM）
python core/interpreter.py

# ② 命令行入口 —— 给脚本和命令行用（list / describe / call / run / blocks / journal）
python adapters/cli.py list process
python adapters/cli.py call process.find --args '{"pattern": "python.exe"}'

# ③ 接进你自己的 Agent（自带三个假工具，克隆下来直接能跑）
python adapters/example_agent.py

# ④ 网页面板（HTTP + dashboard）
python adapters/panel.py     # 然后浏览器看 http://127.0.0.1:8898

# ⑤ 跑一遍案例测试（126 个用例）
python tests/smoke_test.py
```

## 核心概念

### IR —— 一次交一批

IR 是一段**受控的指令序列**，描述「要做哪几件事、谁依赖谁」。它只有三个操作码：`call` / `ask` / `finish`。

```json
{
  "instructions": [
    {"op": "call", "tool": "system.info", "args": {}, "out": "sys",  "depends_on": []},
    {"op": "call", "tool": "fs.list",     "args": {"path": "./"}, "out": "dir", "depends_on": []},
    {"op": "call", "tool": "disk.list",   "args": {}, "out": "disks", "depends_on": []},
    {"op": "finish", "args": {}, "depends_on": ["sys", "dir", "disks"]}
  ]
}
```

前三条**互不依赖 → 并行执行**；`finish` 等三条全部回来才收尾。

**谁生成这段 IR 是调用方的事** —— 用 LLM 生成、模板拼、手写都行，IntentOS 不掺和。
引用前一步的结果写 `"$寄存器名.字段名"`（细节见 `docs/os-primitives.md`）。

### 原语 —— 一套可组合的 OS 能力

目前 **98 条**，按「域」分成 19 个文件（进程 / 文件 / 网络 / 注册表 / 计划任务 …）。
加一条能力不需要碰内核：

```python
from core.factory import declare_primitive

@declare_primitive("disk.usage", "查询磁盘占用", {...schema...}, state={"used_pct": "占用%"})
def disk_usage() -> dict:
    return {"used_pct": ...}
```

`load_primitives()` 扫描目录即自动登记 —— 注册表、状态表、网页面板、安全策略全部跟上，**core 零改动**。

### 安全门 —— 两道，都在解释器里

| 关卡 | 管什么 |
|---|---|
| **Policy Gate** | 执行前把整批「要动东西」的操作**一次问清**，点一次头全批放行；拒绝时不整段中止，只读的照做 |
| **执行门** | 挂在 `ToolRegistry.execute` 这个**唯一入口**上 —— IR / CLI / 面板 / 脚本，谁调都得先过 |

外加一条默认值约定：**会改状态的原语一律带 `dry_run` 且默认 `True`** —— 默认只预览，要动手得显式说出来。

## 用法

### 命令行

```bash
python adapters/cli.py list [域]                 # 册子里有什么
python adapters/cli.py describe <原语>            # 一条原语怎么调
python adapters/cli.py call <原语> --args JSON    # 调一条
python adapters/cli.py run <ir.json 或 ->         # 跑一段 IR（一次交一批）
python adapters/cli.py blocks [块]                # 工具分块
python adapters/cli.py journal [--limit N]        # 调用日志：刚才做过什么
```

**输出契约（给脚本用）**：stdout **只放结果 JSON**（可直接接 `jq`），错误与提示一律走 stderr。

退出码：`0` 成功 / `1` 执行失败 / `2` 用法错误 / **`3` 被安全门拒绝**。
`3` 单独拎出来是有意的 —— 脚本必须分得清「**没查到**」和「**被拦住**」。

### 接进你的 Agent

只有三件事要做，`adapters/example_agent.py` 是完整可跑的例子：

1. **把你的工具注册进来**（`source="agent"`，同名时优先于内置原语 —— 你原生做得更好的能力可以覆盖掉）
2. **让你的 Agent 产出一段 IR** 交给解释器
3. **注入两个钩子**（可选）：确认器（高危操作问用户）、提问器（IR 里的 `ask` 谁来问）——
   读终端的、发 IM 的、等网页点击的，各传各的。**不装也能跑**，只是无人在场时 fail-closed 拒绝

> 契约：**无状态**。它不持有你的 session、凭据、状态 —— 需要的上下文当纯数据传进来。

### 给 Agent 一份说明书

上面那节是自己写代码接；如果你只是想让**手边的 Agent**（Claude Code、Cursor 之类）会用这套能力，
`docs/agent-guide.md` 就是给它准备的 —— 一份告诉它「有哪些能力、怎么调、什么时候该用」的说明书。

Claude Code 用户在仓库根跑一次，之后在任何项目里都能用：

```bash
# Windows（Git Bash）—— 用 $(pwd -W) 取 Windows 风格路径：$PWD 是 /d/... 形式，Python 认不得
mkdir -p ~/.claude/skills/intentos
sed "s|<INTENTOS>|$(pwd -W)|g" docs/agent-guide.md > ~/.claude/skills/intentos/SKILL.md

# macOS / Linux
mkdir -p ~/.claude/skills/intentos
sed "s|<INTENTOS>|$PWD|g" docs/agent-guide.md > ~/.claude/skills/intentos/SKILL.md
```

其他 Agent：把那份文件交给它读即可。

### 工具分块（省 token）

98 条原语的完整说明书约 **33K tokens**，全量注入是每轮对话的固定开销。
按「操作对象」归成 **13 块**后，接入方只把块目录常驻（约 1K tokens），用到哪块展开哪块 ——
只碰文件省 75%、网络排查省 78%。

块内保留**该对象下所有原语的完整说明**：展开 `fs.list` 时会连 `fs.entries` / `fs.tree` 一起看到，
不会出现「知道一条、不知道旁边还有一条」。**它把「谁跟谁容易混」从描述里的文字，变成了结构上的物理相邻。**

### 调用日志

「谁动了系统」「AI 是不是试图删那个目录」「这一步为什么失败」—— 靠它回答。

挂在**所有调用必经的那个入口**上，98 条原语一条都不用改。**只记元数据、不记返回结果**
（第一读者是模型自己，它要的是「我做过什么」，不是文件内容），按天切在 `logs/`（已 gitignore）。

**三种结果都记**：成功 / 失败 / **被安全门拒掉**。最后一种尤其要紧 —— 那是「AI 想干、但没让干」的唯一证据。

## 按自己的需要改造

这套东西**按「加东西不碰内核」设计的** —— 下面这些改动都不需要动 `core/`：

| 想做什么 | 在哪做 | 会怎样 |
|---|---|---|
| **加一条 OS 能力** | `primitives/` 里加个 `@declare_primitive` 声明 | 自动进注册表 / 状态表 / 面板 / 策略。**core 零改动**（步骤见 `CONTRIBUTING.md`）|
| **删掉用不上的能力** | 把那个 `.py` 移出 `primitives/`（或自建一个只含所需文件的目录传给 `load_primitives`）| 它的原语直接不存在 —— 模型看不到、也调不着 |
| **把几条原语拼成「一件事」** | `skills/` 放个模块，导出 `detect()` / `run()` | 一次调用拿结论，不用每次重想判据。见 `skills/README.md` |
| **用自己的工具盖掉内置的** | 注册时写 `source="agent"`，**同名即优先** | 你原生已经做得更好的能力（比如已有的 Read / Grep）可以直接覆盖 |
| **只给模型看一部分工具** | 组装 prompt 时只取要用的块 | **块目录既是分块、也是暴露边界** —— 不列就等于没暴露，省 token |
| **换平台** | 加一套对应平台的 `primitives/`（如 Linux 版）| IR 协议、解释器、安全门都平台无关，内核不用改 |
| **改安全策略** | 原语声明里的 `policy` 参数 | 哪条需要用户点头，由声明决定；判定始终在 core 的 PolicyGate 里 |

**为什么能这么随意改**：`core/` 只认 IR，不认谁在调它、也不认下面挂着什么能力。
内核 / 外设分离，加能力这件事就永远不碰地基。

> **现成的例子**：`skills/proc_detective.py`（「谁在偷跑」）——
> 把进程、自启项、网络连接三条原语交叉成一份身份档案，一次调用给结论。
> 它不是「查进程」的另一个入口，而是**把「怎么判断一个进程的来历」这套判据固化下来**，
> 让调用方不必每次重想。

## 目录结构

```
intentos/
├── core/                  # 【内核】与平台无关的语义层
│   ├── interpreter.py     # IR 协议 + 语义解释器（静态校验 / DAG 并行 / $引用传值）+ Policy Gate + 工具注册表
│   ├── factory.py         # 原语工厂 —— 声明式注册，自动进注册表+状态表，目录扫描自动加载
│   ├── blocks.py          # 工具分块 —— 98 条按「操作对象」归成 13 块，供接入方按需展开（只导出，不加载）
│   └── journal.py         # 调用日志 —— 记「什么时候动了系统」，挂在 execute 上（一处挂钩覆盖全库）
├── primitives/            # 【外设】可插拔的原语，按「域」分文件
│   ├── system.py          # 系统域：平台 / 内存 / 清理
│   ├── process.py         # 进程域：枚举 / 详情 / 结束
│   ├── service.py         # 服务域：枚举 / 详情 / 启停
│   ├── power.py           # 电源域：锁屏 / 关机重启
│   ├── event.py           # 事件日志：结构化 JSON 查询
│   ├── fs.py              # 文件域：读 / 写 / 删 / 搬 + 元信息 / 搜内容（20 条）
│   ├── disk.py            # 磁盘域：卷与容量
│   ├── net.py             # 网络域：端口 / 连通性 / 防火墙 / 出网（14 条）
│   ├── ui.py              # 交互域：剪贴板 / 窗口 / 截屏 / 模拟输入（8 条）
│   ├── registry.py        # 注册表域：读写配置 + 文件关联
│   ├── startup.py         # 系统配置域：开机自启动清单
│   ├── env.py             # 环境变量域：读 / 写
│   ├── task.py            # 计划任务域：任务清单与详情
│   ├── archive.py         # 归档域：压缩包的看 / 解 / 打
│   ├── shell.py           # Shell 域：快捷方式 · 回收站
│   ├── acl.py             # 权限域：权限清单
│   ├── display.py         # 显示域：分辨率 / 多屏 / 亮度
│   ├── sound.py           # 声音域：提示音
│   ├── device.py          # 外设域：USB 设备 / 打印机
│   ├── _common.py         # 共享层：跨域复用的小工具与路径判定
│   └── escape.py          # 逃生舱：册子外的操作（独立子进程 + 每次确认）
├── adapters/              # 【接入层】谁在用 IntentOS
│   ├── cli.py             # 命令行入口（list/describe/call/run/blocks/journal）
│   ├── example_agent.py   # 接入示例 —— 把你的工具注册进来，与内置原语混在同一条 IR 里跑
│   └── panel.py           # 网页面板 —— 原语注册 + 状态注册表 + HTTP /status + dashboard
├── examples/              # 【工具】能力进度生成器
├── docs/                  # 【文档】原语手册 / 进度看板 / 设计札记 / 历史归档
└── skills/                # 【能力目录】组合原语的端到端能力
    └── proc_detective.py  # 示例能力：进程侦探 —— 回答「谁在偷跑」
```

## 文档导航

| 文档 | 是什么 |
|---|---|
| `docs/os-primitives.md` | ★ **原语手册** —— 现役原语、怎么调、安全约定。**唯一需要人维护的** |
| `docs/os-progress.md` | **能力全貌** —— 98 条能力按域分组的清单（脚本生成，手改会被覆盖）|
| `docs/design-notes.md` | **设计札记** —— 为什么边界划这么紧、为什么不做成 MCP、试过什么又撤了 |
| `docs/agent-guide.md` | **给 Agent 的说明书** —— 交给你的 Agent，它就知道怎么调（Claude Code 用户装一次即可）|
| `CONTRIBUTING.md` | **贡献指南** —— 目录规范、加原语的步骤、命名规范、安全分级 |
| `docs/archive/` | **历史区** —— 完成使命的文档（实现新原语时来翻能力地图） |

## 能力边界（哪些事不在射程内）

一句话：**IntentOS 的能力面 = 本机 × 单次 × 无状态 × 不解释语义。**
这不是「还没做」，而是**按设计不打算覆盖** —— 超出这四维的需求，请由上层自己补。

| 维度 | 做得到 | 不做 |
|---|---|---|
| **本机** | 进程 / 文件 / 端口 / 窗口 / 服务 / 注册表 … | 云盘同步、发邮件、调第三方 API |
| **单次** | 一次调用进出，答「此刻是什么」 | 累计、趋势、历史、「上次同步到哪了」 |
| **无状态** | 不持有会话 / 凭据 / 调度 | 登录态、双向同步、长任务编排 |
| **不解释语义** | 取字节、写字节、算哈希 | 读懂 xlsx / PDF / 图片里写了什么 |

另有一类是**有意焊死的门**：注册表自启动类键禁写、`startup` 只给看不给改、
`archive.extract` 拒符号链接 —— 功能上离得很近却做不成，是**风险分级的结果**。
碰到这类需求，走 `escape` 或交由上层，通常比在原语里放开权限更稳妥。

> 完整的论证（为什么划这么紧、「关掉自启动项」为什么评估后决定不做）见 `docs/design-notes.md`。

## License

[MIT](LICENSE)
