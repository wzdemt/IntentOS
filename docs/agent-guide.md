---
name: intentos
description: 用 IntentOS 做**系统层**操作 —— 进程、服务、端口、网络、注册表、电源、事件日志、磁盘、外设、窗口界面。用户问「谁占了某个端口」「开机都自动跑什么」「有没有什么可疑进程在偷偷跑」「内存够不够」「昨天为什么重启的」「C 盘还剩多少」这类**关于这台机器本身**的问题时用它。**一次要连做几件**（有先后依赖）时更要想到它 —— 一批交出去比来回多次快。**不要**用它读写文件或搜代码 —— 那些用你原生的工具更好。
---

# IntentOS —— Agent 操作指南

**这份文件是给 Agent 读的。** 把它交给你的 Agent，它就知道这台机器上有一套现成的**系统层**操作能力（98 条原语）可以直接调 —— 不用每次现拼 PowerShell / CIM，也不用为了「查个端口再查那个进程」来回好几轮。

## 装到你的 Agent 上

**Claude Code** —— 在 IntentOS 仓库根目录执行一次（装到用户级，之后在任何项目里都能用）：

```bash
# Windows（Git Bash）—— 用 $(pwd -W) 取 Windows 风格路径：$PWD 是 /d/... 形式，Python 认不得
mkdir -p ~/.claude/skills/intentos
sed "s|<INTENTOS>|$(pwd -W)|g" docs/agent-guide.md > ~/.claude/skills/intentos/SKILL.md

# macOS / Linux
mkdir -p ~/.claude/skills/intentos
sed "s|<INTENTOS>|$PWD|g" docs/agent-guide.md > ~/.claude/skills/intentos/SKILL.md
```

**其他 Agent** —— 把这份文件交给它读，或让它自己读这个文件。

> 文中 `<INTENTOS>` 指 IntentOS 仓库的绝对路径。开头那两行 `name` / `description` 是 Claude Code 用来判断「什么时候该用」的触发信息，其他 Agent 可以忽略，也可以照抄进自己的工具描述里。

---

系统能力的执行层。98 条原语、13 块，走命令行调用。

## 怎么调

```bash
# 展开某一块的**完整说明与参数 schema**（如 network、filesystem、power）
python <INTENTOS>/adapters/cli.py blocks network

# 调一条原语 —— 参数写进 JSON 文件（**推荐**，见下）
python <INTENTOS>/adapters/cli.py call net.port_owner --args-file args.json

# 看「刚才做过什么」（只读，可查被安全门拒掉的）
python <INTENTOS>/adapters/cli.py journal --limit 20
```

- **stdout 只有结果 JSON**，提示与错误在 stderr
- **退出码**：0 成功 / 1 执行失败 / 2 用法错误 / **3 被安全门拒绝**（需用户确认而无人应答）——
  脚本必须分得清「**没查到**」和「**被拦住**」，别混成一个「失败」
- **参数尽量用 `--args-file`**：参数写在命令行里时，`process.find` 会把「正在执行这次查询的 shell」也一并搜出来（它命令行里带着那个词）
- **别加 `--pretty`**：压紧的 JSON 一样能读，缩进纯属白花 token

## 一次交一批（run）—— 主场在这

题目里**几件事有先后依赖**时，写一段 IR 一次交出去 —— 比来回多次快。IR 就是一个 JSON 文件（写到临时目录就行）：

```json
{
  "instructions": [
    {"op": "call", "tool": "system.info", "args": {}, "out": "sys"},
    {"op": "call", "tool": "disk.list", "args": {}, "out": "d"},
    {"op": "call", "tool": "process.list", "args": {"limit": 5}, "out": "p"}
  ]
}
```

```bash
python <INTENTOS>/adapters/cli.py run <ir.json 的路径>
```

- **`op` 只有三个**：`call`（调原语）/ `ask`（问用户）/ `finish`（收尾）
- **`out` 是寄存器名** —— 后面的指令用 `$名字` 取它
- **同一层里没写 `depends_on` 的指令是并行的** —— 有依赖必须显式声明
- 输出里 `results` 和 `workspace` 内容相同（首次执行必然如此），**看 `results` 就够**

### `$引用` 的四条硬规则

1. **整串必须就是引用本身** —— `"磁盘剩 $d.free_gb GB"` 这种嵌在句子里的**不会被解析**，会原样当字符串传进去
2. **有依赖就必须写 `depends_on`** —— 同层是并行的，不声明就会在寄存器写入**之前**执行，**静默取到 `None`**
3. **只能按字段取，取不了数组下标** —— `$d.free_gb` 行，`$d.volumes[0].drive` **不行**
4. **取不到就是 `None`，不报错** —— 字段名写错、依赖漏声明，结果都是 `None`

> 第 2、4 条合起来最坑：**写错了没有任何报错，只是悄悄拿不到值**。所以串起来用之前，先看一眼上游到底返回了什么。

## 任务级能力（skill）—— 能用就用

`skill` 把几条原语**交叉**起来回答「一件事」，一次调用直接给结论。
不用你先展开块、再自己挑原语、再自己拼。**问题对得上就先试它，比逐条调省得多。**

| 名字 | 回答什么 |
|---|---|
| `proc_detective` | **谁在偷跑** —— 进程 × 自启项 × 网络连接交叉成「身份档案」（路径 / 父进程 / 是否自启 / 联网数），按「来历说不说得清」排序 |

```bash
python <INTENTOS>/adapters/cli.py skill                     # 列出全部
python <INTENTOS>/adapters/cli.py skill proc_detective --args '{"limit": 30}'
```

## 有哪些能力

> **下面这份块目录就是最新的，不用再跑 `blocks --text` 去取**（它由 `cli.py blocks --text` 生成后原样贴在这里）。
> 想知道块 id，跑 `python <INTENTOS>/adapters/cli.py blocks`（不带参数）拿 JSON 版 —— 展开某块时用的是 id，不是中文标题。
>
> **具体某条原语怎么用、参数填什么、返回值什么意思，要先 `blocks <块id>` 展开那一块** ——
> 每条都有它自己的口径和坑，光看名字会踩。

块 id：`filesystem` · `network` · `display_ui` · `process_system` · `service_task` · `config` · `power` · `disk` · `event` · `archive` · `recycle_shortcut` · `device` · `escape`

```
【本库通用约定】—— 所有原语都适用，各条描述里不再重复

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

6. **没声明「需确认」的原语直接执行**，不会弹确认；声明了的都要过门（见第 3 条）。

· 文件与目录（21）── 读写删改文件、按名字找/按内容搜、看大小/时间/属性/谁能读谁能改
    acl.get fs.append fs.attrs fs.copy fs.delete fs.entries fs.grep fs.hash fs.link fs.list fs.mkdir fs.move fs.read fs.read_bytes fs.search fs.size fs.stat fs.stats fs.temp fs.tree fs.write
· 网络（14）── 网卡与 IP、路由、连接、端口被谁占、通不通、防火墙、下载文件、网卡流量统计
    net.connections net.dns_resolve net.download net.firewall_rules net.firewall_status net.http_get net.interfaces net.io_stats net.ip_config net.ping net.port_owner net.routes net.tcp_check net.wifi_status
· 显示与界面（13）── 屏幕与窗口、截屏、剪贴板、模拟输入、弹通知/提示音
    display.brightness display.info display.modes display.monitors sound.beep ui.clipboard_get ui.clipboard_set ui.notify ui.screenshot ui.type_text ui.window_activate ui.window_control ui.window_list
· 进程与系统资源（16）── 进程列表/查找/结束、内存、CPU、当前时间/时区、开机多久（不含取进程的输出）
    process.find process.foreground process.info process.kill process.list process.set_priority process.stats system.free_memory system.hardware system.idle_time system.info system.load system.memory system.uptime time.set_zone time.zones
· 服务与计划任务（9）── 后台服务、定时任务、开机都自动跑什么
    service.control service.info service.list startup.list task.control task.create task.delete task.info task.list
· 系统配置（5）── 注册表、环境变量、文件关联（双击用什么打开）—— 只能看当前值，不记录是谁改的
    env.get env.set reg.assoc registry.read registry.write
· 电源（5）── 关机/重启/注销/锁屏/睡眠、电源计划、电池（只管动手，查「为什么重启的」去事件日志）
    power.battery power.lock power.plan power.shutdown power.sleep
· 磁盘（3）── 按盘算容量（有几个盘、某个路径还剩多少空间）、硬盘健康（不含磁盘读写速度 / IO 性能）
    disk.health disk.list disk.usage
· 事件日志（3）── 查系统日志（含上次为什么重启/关机）、看有哪些日志、清日志
    event.channels event.clear event.query
· 压缩包（3）── 看包内容、解压、打包
    archive.create archive.extract archive.list
· 回收站与快捷方式（3）── 回收站内文件的查看/还原/清空（不含彻底删除的恢复）、.lnk 快捷方式读写
    shell.recycle shell.shortcut_read shell.shortcut_write
· 外设（2）── 只能列出打印机、USB 设备。要判断「U 盘能不能安全拔出」（设备占用）本库没有，走逃生舱
    device.printers device.usb_list
· 【常驻】逃生舱（1）── 执行以上都没覆盖的操作（最后手段，需确认）。**当某块的说明明确写了「不含 / 不能」某类需求时，直接走它，不必逐块试**
    escape
```
