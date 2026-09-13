# IntentOS OS 能力地图

> 这是 IntentOS 能给 AI 用的「操作系统操作能力」总清单。三路并盘点出来的 204 条能力全在这里，
> 每条都标了「建议怎么用」——直接做成内置动作（原语）、还是拼成现成套路（IR 模板）、还是干脆交给通用命令（exec）。
> 用法：先看「一、总览」和「四、首批落地建议」了解要做什么；想知道某条具体怎么回事，去「三、完整能力清单」查。
>
> 📅 生成日期：2026-09-10 ｜ 来源：三域并行盘点（进程与系统资源 / 文件与存储 / 网络与交互）

---

## 〇、怎么读这份文档

### 三个建议标记

盘点时只问一个问题：**让 AI 直接跑一条命令就能做到的事，为什么还要专门做成一个内置动作？**

| 标记 | 大白话解释 |
|---|---|
| **✅ 原语** | **值得做成内置动作**。做出来以后，系统能做三件「随便跑命令」做不到的事：① **能管**——写文件、关机这类危险动作，系统能在执行前拦一下、问一句、挡在允许范围外；② **能说清**——返回的是规整的数据（比如"还剩 8 GB"这样的数字），不是一串要 AI 自己去猜的中文文字；③ **能串联**——结果可以直接喂给下一步，比如"查到占 8080 端口的程序 → 把它关掉"。 |
| **⚠️ IR 模板** | **不做成单独动作，而是拼好的「现成套路」**。这类能力通常是一串动作的组合，或者可调参数太多、太杂（比如"同步两个文件夹"）。做成模板：一次写好、反复使用、还能被审查。 |
| **❌ exec** | **留给通用命令**。要么是太冷门、用不上几次；要么是危险到不该给一个方便按钮（比如"创建系统服务"——那是安装后门的标准手法）；要么是系统里根本没有可靠的接口。 |

### 两个补充概念

- **★【首批】**：表格「首批」列里带 ★ 的，是**第一轮要落地的范围**，一共 13 个能力。
  挑它的标准是「安全价值高 × 用得上 × 做起来不贵」。选完就可以先动手，不用等整张地图全做完。
- **域.动作 命名**：所有能力都用「域.动作」两段式命名，比如 `fs.write`（文件域.写）、`power.lock`（电源域.锁屏）。
  三段式（如 `fs.dir.list`）是**故意不用**的——名字一长，写套路脚本时就容易写错。
- **⚠️ 待验证**：报告里标注「待验证」的，意思是**这条接口在调研机器上没能实测确认**，属于不确定项，不要当成承诺。
  这类项在文档里保持原样标注，并汇总在「六、待验证清单」。

---

## 一、总览

| 域 | 能力条数 | ✅ 建议做原语 | ⚠️ 建议做 IR 模板 | ❌ 留给 exec | 首批 |
|---|---:|---:|---:|---:|---:|
| 一、进程与系统资源域 | 77 | 40 | 27 | 10 | 6 |
| 二、文件与存储域 | 68 | 34 | 23 | 11 | 5 |
| 三、网络与交互域 | 59 | 32 | 16 | 11 | 5 |
| **合计** | **204** | **106** | **66** | **32** | **16 处** |

> **关于「首批」计数**：★ 共 16 处，对应 **13 个能力**。多出来的 3 处是**跨域重复盘点**——同一个能力在两个域的表里各出现了一次，正式落地时是同一个动作：
> `disk.list`（进程域 F6 + 文件域 F 组各一次）、`power.lock` 与 `power.shutdown`（进程域 D 组 + 网络交互域 E 组各一次）。
>
> **关于 204 与原始报告自报数字的出入**：三份报告结尾自报的条目数是 58 / 68 / 58（合计 184），但按报告表格逐行清点，
> 实际是 **77 / 68 / 59（合计 204）**。本合并文档以**逐行清点为准**（宁多勿漏），同时把出入原样记在这里，供后续核对。
> 具体差异：第一份报告正文表格共 77 行（其结尾写"58 条"）；第三份报告正文表格共 59 行（其结尾统计里"网络 24 + 交互 34 = 58"，实际交互类为 35 行）。

---

## 二、树形分类骨架

把所有能力按「域.动作」组织成一棵两层的树。**顶层 18 个域**，每个域下面是具体动作：

```
IntentOS OS 能力地图
│
├── 【进程与系统资源域】
│   ├── process.*   进程        枚举 / 详情★ / 查找 / 启动 / 结束(强杀·优雅) / 优先级 /
│   │                           亲和性 / 挂起恢复 / 等待退出 / 进程树 / 资源占用 /
│   │                           CPU占用 / 线程 / 模块 / 前台程序 / 文件占用者 / 互斥体 / 环境块
│   ├── service.*   后台服务    枚举 / 详情 / 启停★ / 依赖 / 失败恢复 / 创建删除
│   ├── task.*      计划任务    枚举 / 详情 / 创建 / 删除 / 运行停止
│   ├── power.*     电源        关机★ / 锁屏★ / 睡眠 / 休眠 / 息屏 / 防休眠 /
│   │                           电源计划 / 电池 / 睡眠能力 / 唤醒原因 / 唤醒锁
│   ├── event.*     事件日志    通道枚举 / 查询★ / 实时订阅 / 清空 / 配置 / 写入
│   ├── system.*    系统信息    版本 / CPU / 内存 / 运行时长 / 负载 / 网卡(→net) /
│   │                           装机清单 / 页面文件 / 开关机历史 / 空闲时长(→net域建议)
│   ├── disk.*      磁盘        盘符容量★ / IO健康
│   ├── env.*       环境变量    读(进程/用户/系统) / 写(用户/系统) / 删
│   └── config.*    系统配置    registry 读写 / startup 清单 / time 时区 / 安全中心 / DPI / 区域语言
│
├── 【文件与存储域】
│   ├── fs.*        文件与目录
│   │   ├── 目录视图   fs.list · fs.tree · fs.size · fs.stats
│   │   ├── 内容读写   fs.read · fs.write★ · fs.append★ · fs.read_bytes · fs.write_bytes · fs.patch · fs.touch · fs.temp
│   │   ├── 生命周期   fs.copy · fs.move · fs.delete★ · fs.mkdir · fs.sync · fs.link
│   │   ├── 元数据     fs.stat · fs.hash · fs.attrs · fs.path★ · fs.owner · fs.compressed_size · fs.ads · fs.long_path
│   │   └── 检索       fs.find · fs.grep · fs.dupes · fs.bigfiles · fs.changed_since
│   ├── disk.*      磁盘与卷   disk.list★ · disk.usage · disk.health · disk.partition ·
│   │                          disk.reliability · disk.io · disk.optimize · disk.chkdsk · disk.mount · disk.quota · disk.vss
│   ├── archive.*   压缩归档   list / extract / create / info / single / 7z / encrypted / stream
│   ├── acl.*       权限属主   acl.get / acl.set / acl.owner
│   ├── reg.*       注册表     reg.get / reg.set / reg.list / reg.delete / reg.assoc / reg.autoruns / reg.export_import
│   └── shell.*     外壳集成   快捷方式读 / 快捷方式写 / 回收站 / 默认程序打开 / 定位文件 / 剪贴板 / 文件类型
│
└── 【网络与交互域】
    ├── net.*       网络       interfaces / ip_config / port_owner★ / connections / routes / dns_resolve /
    │                          tcp_check / ping / io_stats / http_get / download / firewall_status /
    │                          firewall_rules / wifi_status / 监听端口 / 路由追踪 / 综合诊断 / ARP / 公网IP / 防火墙开关 /
    │                          WiFi连接 / 代理 / hosts / 抓包
    ├── ui.*        界面交互   window_list / window_activate / window_control / screenshot /
    │                          clipboard_get★ / clipboard_set★ / notify / type_text
    ├── display.*   显示       modes / monitors / brightness
    ├── sound.*     声音       beep / speak(TTS)
    ├── device.*    外设       usb_list / printers
    └── 会话电源 shell.* / power.* / system.idle_time
```

**跨域复用的「底座」能力**（做一条省一片，建议优先）：

- `fs.path`（路径规范化）← 所有写文件动作的安全前提，不做它，白名单形同虚设
- `process.info`（进程详情）← 「该不该关这个程序」的判断依据，也是资源占用、优先级调整的共同前置
- `registry.read` ← 环境变量、自启动清单、系统版本、装机清单都能复用
- `event.query` ← 开关机历史、错误排查、登录审计都能复用
- `disk.list` ← 任何文件操作前的「还有多少空间」前置检查

---

## 三、完整能力清单

> 说明：「建议」列**照抄原始报告的判断**，未做任何改动；「首批」列的 ★ 为项目主人圈定范围。
> 加粗的 `**A. 进程**` 这类行是分组标题，不是能力条目。

### 3.1 进程与系统资源域（77 条）

| 原语/能力名 | 作用（大白话） | OS 接口 | 建议 | 首批 |
|---|---|---|---|:--:|
| **A. 进程** | | | | |
| 进程枚举 `process.list` | 看电脑里都在跑哪些程序，各自占多少内存 | `tasklist /fo csv /nh`；`EnumProcesses`；`Get-CimInstance Win32_Process` | ✅原语（已有 `process.list`，建议换原生枚举 + 补字段） | |
| `process.info` | 看某个程序的底细：装在哪个文件、启动时带了什么参数、是谁把它启动的 | `QueryFullProcessImageNameW`；`Win32_Process.CommandLine/ParentProcessId` | ✅原语 | ★ |
| 进程查找 | 按名字、路径、端口或所属用户，筛出想要的进程 | `tasklist /fi`；`Win32_Process -Filter`；`Get-NetTCPConnection -OwningProcess` | ⚠️IR模板（做成 `process.list` 的 filter 参数即可） | |
| 进程启动 | 起一个新程序 | `subprocess.Popen`；`CreateProcessW`；`Start-Process` | ❌exec（`exec` 已能做，无安全增量） | |
| `process.kill`（强杀） | 强制干掉一个卡死的程序 | `taskkill /f /pid`；`TerminateProcess`；`Stop-Process` | ✅原语（已有 `process.kill`） | |
| `process.kill`（优雅） | 客气地请程序自己退出，给它保存数据的机会 | `taskkill /pid`（无 `/f`）；`PostMessage(WM_CLOSE)` | ✅原语（并入 `process.kill` 的 `mode=graceful\|force`） | |
| `process.set_priority` | 调整某个程序抢 CPU 的优先级 | `GetPriorityClass`/`SetPriorityClass` | ✅原语 | |
| CPU 亲和性 | 指定某个程序只许在哪几个 CPU 核心上跑 | `GetProcessAffinityMask`/`SetProcessAffinityMask` | ⚠️IR模板（窄需求，可并入 `process.set_priority`） | |
| 进程挂起/恢复 | 把程序冻住，过会儿再解冻 | `NtSuspendProcess`/`NtResumeProcess`（**未文档化 API**） | ❌exec（未文档化 API 不进内核） | |
| 等待进程退出 | 一直等到某个程序结束再往下走 | `WaitForSingleObject`；`Wait-Process` | ⚠️IR模板（是"动作+等待"组合） | |
| 进程树 | 看谁启动了谁，理清程序的父子关系 | `th32ParentProcessID` 递归；`Win32_Process.ParentProcessId` | ⚠️IR模板（在 `process.info` 上递归组合） | |
| `process.stats` | 看某个程序吃了多少内存、多少句柄、多少线程、读写量多大 | `GetProcessMemoryInfo`；`GetProcessHandleCount`；`GetProcessIoCounters` | ✅原语 | |
| 进程 CPU 占用率 | 看某个程序此刻占了多少 CPU | `GetProcessTimes` 两次采样求差 | ⚠️IR模板（需要采样间隔，有状态倾向） | |
| 进程线程列表 | 看某个程序内部开了多少条线程 | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`；`Win32_Thread` | ⚠️IR模板（排障场景，长尾） | |
| 进程模块(DLL)列表 | 看某个程序加载了哪些 DLL 库文件 | `EnumProcessModules`/`GetModuleFileNameEx` | ❌exec（长尾排障） | |
| `system.free_memory` | 清一下内存，把闲置占用的物理内存释放掉 | `EmptyWorkingSet`（**已有** `system.free_memory`） | ✅原语（已有） | |
| `process.foreground` | 看用户此刻正在用哪个程序（哪个窗口在最前面） | `GetForegroundWindow`+`GetWindowThreadProcessId`+`GetWindowTextW` | ✅原语 | |
| 文件占用者查询 | 文件删不掉时，查出是哪个程序锁着它 | Restart Manager API（**待验证**）；`handle.exe`（外部工具） | ⚠️IR模板（需求真实高频，但 API 调用链长） | |
| 单实例/互斥体探测 | 判断某个程序是不是已经在运行了 | `CreateMutexW`+`GetLastError==ERROR_ALREADY_EXISTS` | ❌exec（按名查找已能覆盖多数场景） | |
| 进程环境变量 | 看某个程序启动时拿到的环境变量（接口未公开） | `NtQueryInformationProcess`（**未文档化，待验证**） | ❌exec（**待验证**，不建议进内核） | |
| **B. 后台服务** | | | | |
| `service.list` | 看电脑里有哪些后台服务在跑、都是什么状态 | `sc query type= service state= all`；`Get-Service`；`EnumServicesStatusExW` | ✅原语 | |
| `service.info` | 看某个服务是不是开机自动启动、用什么账户跑、程序文件在哪 | `sc qc <名>`；`Win32_Service.StartMode/DelayedAutoStart/StartName/PathName` | ✅原语 | |
| `service.control` | 启动 / 停止 / 重启某个后台服务（需要管理员权限） | `sc start\|stop <名>`；`Start-Service`/`Stop-Service` | ✅原语（`requires_confirmation` + 前置权限探测） | ★ |
| 服务依赖关系 | 看某个服务依赖谁、又被谁依赖 | `sc enumdepend <名>`；`Win32_DependentService` | ⚠️IR模板（在 `service.info` 上组合） | |
| 服务失败恢复策略 | 看服务崩了以后系统会怎么处理（自动重启 / 跑个程序） | `sc qfailure <名>` | ⚠️IR模板（参数空间大） | |
| 服务创建/删除 | 注册或注销一个系统服务 | `sc create` / `sc delete` | ❌exec（参数空间大 + 典型持久化后门，**明确不给原语**） | |
| **C. 计划任务** | | | | |
| `task.list` | 看电脑里设了哪些定时任务、下次什么时候跑 | `schtasks /query /fo csv /nh`；`Get-ScheduledTask` | ✅原语 | |
| `task.info` | 看某个定时任务的详细配置：什么时候触发、跑什么程序、用哪个账户 | `schtasks /query /tn <名> /xml`；`Get-ScheduledTaskInfo` | ✅原语（XML → 结构化） | |
| `task.create` | 新建一个定时任务 | `schtasks /create`；`Register-ScheduledTask` | ✅原语（**`requires_confirmation`**，参数用结构化对象） | |
| `task.delete` | 删掉一个定时任务 | `schtasks /delete /tn <名> /f` | ✅原语（**`requires_confirmation`**） | |
| `task.control` | 让定时任务马上跑一次、中止它、或者启用/停用 | `schtasks /run\|/end\|/change /enable\|/disable` | ✅原语 | |
| **D. 电源** | | | | |
| `power.shutdown` | 关机 / 重启 / 注销（最高危） | `shutdown /s\|/r\|/l /t <秒>`；`ExitWindowsEx` | ✅原语（**`requires_confirmation` 必填，带 `delay` 可撤销窗口**） | ★ |
| `power.lock` | 立刻锁屏 | `LockWorkStation`；`rundll32 user32.dll,LockWorkStation` | ✅原语（低危高频，**无需确认**） | ★ |
| 休眠 `power.sleep` | 让电脑把内存写进硬盘后彻底断电 | `shutdown /h`；`SetSuspendState(TRUE,...)` | ✅原语（并入 `power.sleep`） | |
| `power.sleep` | 让电脑睡一会儿（低功耗待机） | `SetSuspendState`；`rundll32 powrprof.dll,SetSuspendState 0,1,0` | ✅原语（**`requires_confirmation`**） | |
| 关闭显示器 | 只熄屏，不睡觉 | `SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)` | ⚠️IR模板（可并入 `power.lock`） | |
| 防休眠/保持唤醒 | 让电脑这段时间别自动睡、别熄屏 | `SetThreadExecutionState(ES_CONTINUOUS\|...)` | ⚠️IR模板（**有状态**：需配对释放，建议做成带 token 的会话） | |
| `power.plan` | 看/换电源计划（节能 / 平衡 / 性能） | `powercfg /getactivescheme`；`powercfg /list`；`powercfg /setactive` | ✅原语（查询免确认，切换需确认） | |
| `power.battery` | 看电池电量、是不是插着电 | `GetSystemPowerStatus`；`Win32_Battery` | ✅原语（或并入 `system.info`） | |
| 睡眠能力探测 | 看这台电脑支持哪些睡眠方式 | `powercfg /a` | ⚠️IR模板（并入 `system.info`） | |
| 唤醒定时器/上次唤醒原因 | 查是谁、什么时候把电脑唤醒的 | `powercfg /waketimers`、`powercfg /lastwake` | ⚠️IR模板 | |
| 唤醒锁占用者 | 查是谁在拦着电脑不让它睡 | `powercfg /requests`（**需管理员**） | ❌exec（非管理员环境不可用） | |
| **E. 事件日志** | | | | |
| `event.channels` | 看系统里都有哪几本「日志本」（系统 / 应用 / 安全…） | `wevtutil el`；`EvtOpenChannelEnum` | ✅原语（可并入 `event.query`） | |
| `event.query` | 按时间、级别、编号查系统事件日志 | `wevtutil qe System /q:... /c:N /f:xml`；`EvtQuery`/`EvtNext`/`EvtRender` | ✅原语 | ★ |
| 事件实时订阅 | 让日志一有新事件就主动推给你 | `EvtSubscribe`；`Get-WinEvent -Wait` | ❌exec（**有状态长连接，与无状态原语模型根本冲突**） | |
| `event.clear` | 清空某本日志（等于抹证据） | `wevtutil cl <通道>`；`Clear-EventLog` | ✅原语（**`requires_confirmation` + 审计留痕**；也可判定为 ❌exec） | |
| 日志配置/容量 | 改日志本的大小上限、写满了怎么办 | `wevtutil sl`；`Win32_NTEventlogFile.MaxFileSize` | ⚠️IR模板 | |
| 写入自定义事件 | 往日志里手写一条记录 | `eventcreate`；`EvtWrite` | ❌exec（长尾） | |
| **F. 系统信息** | | | | |
| `system.info` | 看这台电脑是什么系统、什么版本 | `platform`；`RtlGetVersion`；`Win32_OperatingSystem` | ✅原语（**已有**，建议补 build / edition / display_version） | |
| `system.hardware` | 看 CPU 型号、几个核、主频多少 | `Win32_Processor`；`GetSystemInfo` | ✅原语（或并入 `system.info`） | |
| 内存总量/可用/占用 | 看这台电脑有多少内存、还剩多少可用 | `GlobalMemoryStatusEx`；`GetPerformanceInfo` | ✅原语（**已有** `system.info`） | |
| `system.uptime` | 看这台电脑开机多久了 | `GetTickCount64`；`Win32_OperatingSystem.LastBootUpTime` | ✅原语（**已有** `system.uptime`） | |
| `system.load` | 看整台电脑此刻 CPU 忙不忙 | `GetSystemTimes` 两次采样求差 | ✅原语（瞬时值需两次采样，建议给 500ms 采样窗口） | |
| `disk.list` | 看有几个盘、每个盘还剩多少空间、什么文件系统 | `GetLogicalDrives`+`GetDiskFreeSpaceExW`；`Win32_LogicalDisk`；`Get-Volume` | ✅原语 | ★ |
| 磁盘 IO/健康 | 看硬盘读写速度和健康状态 | `Win32_PerfFormattedData_PerfDisk_LogicalDisk`；`Get-PhysicalDisk` | ⚠️IR模板（SMART 细节支持不稳，**待验证**） | |
| 主板/BIOS/显卡 | 看主板、BIOS、显卡的型号信息 | `Win32_BaseBoard`/`Win32_BIOS`/`Win32_VideoController`（仅 CIM 可得） | ⚠️IR模板（一次性装机信息，长尾） | |
| 内存条/插槽 | 看每条内存多大、多快、什么牌子 | `Win32_PhysicalMemory` | ⚠️IR模板 | |
| 温度/风扇转速 | 读温度传感器和风扇转速 | `MSAcpi_ThermalZoneTemperature`（**支持极不稳定**）；`Win32_Fan` | ❌exec（**待验证**，不是可靠能力） | |
| `display.info` | 看屏幕分辨率、刷新率、接了几块屏、缩放比例 | `GetSystemMetrics`+`EnumDisplayMonitors`；`Win32_VideoController` | ✅原语（AI 做截图/看屏幕前必知） | |
| 网络接口/连接 | 看有哪些网卡、IP 是多少、正在连谁（**属网络域**） | `Get-NetIPConfiguration`、`Get-NetTCPConnection`、`netstat -ano` | ⚠️留给网络域调研（此处仅列，避免重复盘点） | |
| 已安装软件清单 | 看这台电脑装了哪些软件 | 注册表 `HKLM\...\Uninstall\*` + `HKCU\...\Uninstall\*` | ⚠️IR模板（读注册表组合动作；**`Win32_Product` 禁用**） | |
| 页面文件配置 | 看虚拟内存（页面文件）多大、用了多少 | `Win32_PageFileUsage`；`GetPerformanceInfo` | ⚠️IR模板 | |
| 开关机历史 | 看这台电脑什么时候开的机、什么时候关的机 | 事件日志 System 通道 EventID 6005/6006/6008/1074 | ⚠️IR模板（用 `event.query` + System 通道模板） | |
| **G. 环境变量** | | | | |
| `env.get`（进程级） | 看当前程序能看到的环境变量 | `os.environ` | ✅原语（scope=process） | |
| `env.get`（用户/系统级） | 看用户级 / 系统级设置的永久环境变量 | 注册表 `HKCU\Environment` / `HKLM\...\Session Manager\Environment` | ✅原语（scope=user\|system） | |
| `env.set`（用户级） | 永久设置一个用户环境变量 | `setx <名> <值>`；注册表写 + 广播 `WM_SETTINGCHANGE` | ✅原语（`requires_confirmation`；**必须广播才对新进程生效**） | |
| `env.set`（系统级） | 永久设置全机器都生效的环境变量（需管理员） | `setx /M`；注册表 `HKLM\...\Environment` | ✅原语（scope=system，`requires_confirmation` + 权限探测） | |
| 删除环境变量 | 删掉一个用户 / 系统环境变量 | `setx`（空值）或 `reg delete` | ⚠️IR模板（并入 `env.set`，用 `value=null` 表达删除） | |
| **H. 系统配置** | | | | |
| `registry.read` | 读注册表里的配置项 | `winreg.OpenKey/QueryValueEx/EnumValue/EnumKey` | ✅原语（**根键 + 路径白名单**） | |
| `registry.write` | 写注册表配置项 | `winreg.CreateKeyEx/SetValueEx` | ✅原语（**白名单路径 + `requires_confirmation` + 审计**；白名单外 ❌exec 或直接拒绝） | |
| 注册表删除 | 删注册表的键或值 | `winreg.DeleteKey/DeleteValue` | ⚠️IR模板 / ❌exec（并入 `registry.write` 的 `op=delete`，走同一白名单） | |
| `startup.list` | 一次性看到「这台电脑开机都自动启动了啥」 | `HKCU/HKLM\...\Run`、`RunOnce`、`shell:startup` 文件夹、服务、任务 | ✅原语（**组合 A/B/C/H 但语义极清晰**，安全价值高） | |
| 自启动项增删 | 加 / 删开机自启动项 | `winreg` 写 Run 键；启动文件夹放快捷方式 | ⚠️IR模板（用 `registry.write` + `fs.*` 组合） | |
| `time.zones` | 看时区、改时区（改系统时间更敏感） | `GetTimeZoneInformation`；`tzutil /g`/`/s`；`SetSystemTime`（**需特权，待验证**） | ✅原语（读免确认；写时间 `requires_confirmation`） | |
| 安全中心/Defender 状态 | 看杀毒软件和防火墙开没开 | `Get-MpComputerStatus`；`Get-NetFirewallProfile` | ⚠️IR模板（只读，安全域更合适） | |
| 显示缩放/DPI 设置 | 改屏幕文字和图标的缩放比例 | 注册表 `HKCU\Control Panel\Desktop\LogPixels` | ⚠️IR模板（改完需重登，**待验证**） | |
| 区域/语言设置 | 看系统的区域、语言、输入法设置 | `Get-WinSystemLocale`、`Get-WinUserLanguageList` | ⚠️IR模板（长尾） | |

### 3.2 文件与存储域（68 条）

| 原语/能力名 | 作用（大白话） | OS 接口 | 建议 | 首批 |
|---|---|---|---|:--:|
| **A. 文件内容读写** | | | | |
| `fs.read` | 读文本文件内容（自动识别编码、可只读某几行、太大自动截断） | `Path.read_text` / `open(encoding=)` / `GetFileAttributesW` 预检 | ✅原语 | |
| `fs.write` | 写 / 覆盖一个文本文件（先写临时文件再替换，避免写坏） | `Path.write_text` / `os.replace` / `WriteFileW` | ✅原语 | ★ |
| `fs.append` | 往文件末尾追加内容（写日志常用） | `open('a')` | ✅原语 | ★ |
| `fs.read_bytes` | 读二进制文件、或只读其中一段，并算出校验指纹 | `open('rb')` + `seek` | ✅原语 | |
| `fs.write_bytes` | 写二进制文件（比如下载下来的图片或生成的文件） | `open('wb')` | ⚠️IR模板（长尾，且 `fs.write` 可加 `binary` 参数覆盖） | |
| `fs.patch` | 把文件里某段文字替换掉（可按正则匹配） | `re.sub` + 原子写 | ⚠️IR模板（必须确认，文本内容不可预期） | |
| `fs.touch` | 创建一个空文件 / 只更新文件的时间戳 | `os.utime` / `Path.touch` / `SetFileTime` | ⚠️IR模板（并入 `fs.write` 的空内容 + mtime 参数） | |
| `fs.temp` | 建一个临时文件或临时目录（放在受控沙箱里） | `tempfile.mkstemp/mkdtemp` | ✅原语（沙箱基建） | |
| **B. 文件/目录生命周期** | | | | |
| `fs.copy` | 复制文件或整个目录（保留时间等元信息） | `shutil.copy2` / `shutil.copytree` / `CopyFileExW` | ✅原语 | |
| `fs.move` | 移动或重命名文件 / 目录 | `shutil.move` / `os.replace` / `MoveFileExW` | ✅原语 | |
| `fs.delete` | 删除文件或目录（默认进回收站，可先预览要删什么） | `os.remove` / `shutil.rmtree` / `SHFileOperationW(FOF_ALLOWUNDO)` | ✅原语（★高危首选：确认 + `dry_run` 预览 + **默认走回收站**） | ★ |
| `fs.mkdir` | 新建目录（可以一次把父级目录也建好） | `Path.mkdir(parents=True)` / `CreateDirectoryW` | ✅原语 | |
| `fs.sync` | 目录树镜像 / 增量同步（把两个目录做成一样） | `robocopy` `/MIR /XO /E /XD /XF` | ⚠️IR模板（`/MIR` 会**删除目标多余文件** → 必须确认 + 建议首版禁用 `/MIR`） | |
| `fs.link` | 建硬链接 / 软链接（软链接可被用来绕过白名单） | `os.link` / `os.symlink` / `mklink` | ✅原语（高危，需确认；link 目标也走白名单） | |
| **C. 元数据与路径** | | | | |
| `fs.stat` | 查文件的大小、创建/修改时间、是不是只读、是不是链接 | `os.stat` / `Path.stat` / `GetFileInformationByHandleEx` | ✅原语 | |
| `fs.hash` | 算文件的指纹（校验文件有没有被改过、找重复文件） | `hashlib` + 分块读 / `Get-FileHash` | ✅原语 | |
| `fs.attrs` | 看 / 改文件的只读、隐藏、系统、存档等属性 | `GetFileAttributesW` / `SetFileAttributesW` | ✅原语 | |
| `fs.path` | 把路径统一整理好，并判断它是不是在允许读写的范围内（**安全地基**） | `os.path.expandvars/expanduser/abspath` + `Path.resolve` | ✅原语（**强烈推荐，作为 PolicyGate 的辅助原语**） | ★ |
| `fs.owner` | 看文件属于哪个用户（把编号翻译成用户名） | `win32security` / `GetNamedSecurityInfoW` | ⚠️IR模板（并入 `acl.get`） | |
| `fs.compressed_size` | 看文件实际占了多少磁盘（压缩/稀疏文件和表面大小不同） | `GetCompressedFileSizeW` | ⚠️IR模板 | |
| `fs.ads` | 查文件里藏着的隐藏数据流（经典的藏毒手法） | `FindFirstStreamW` / `GetFileInformationByHandleEx` | ⚠️IR模板（安全审计场景可提为原语） | |
| `fs.long_path` | 处理超过 260 字符的超长路径 | `\\?\` 前缀 | ❌exec（并入 `fs.path`） | |
| **D. 目录视图** | | | | |
| `fs.list`（**已有**） | 列出一个目录里有什么 | `os.scandir` / `Path.iterdir` | ✅原语（增强现有实现：大小 / 时间 / 隐藏 / 递归深度 / 过滤 / 排序） | |
| `fs.tree` | 把整个目录结构画成一棵树返回（有深度和数量上限） | `os.walk` / `Path.rglob` | ✅原语 | |
| `fs.size` | 算一个目录总共占多大 | `os.scandir` 递归 / `GetCompressedFileSizeW` | ✅原语 | |
| `fs.stats` | 目录统计：多少文件、多少子目录、都是什么类型、最大的几个是啥 | `os.scandir` + `collections.Counter` + `heapq.nlargest` | ✅原语 | |
| **E. 检索** | | | | |
| `fs.find`（`fs.search` 增强） | 按名字 / 通配符 / 大小 / 时间 / 扩展名找文件 | `Path.rglob` / `os.walk` + `fnmatch`/`re` | ✅原语（增强现有 `fs.search`） | |
| `fs.grep` | 在文件内容里搜关键词，返回「哪个文件、第几行」 | Python `re` 遍历 / `findstr` / `Select-String` | ✅原语 | |
| `fs.dupes` | 找出内容完全相同的重复文件 | `os.scandir` + `hashlib` + `st_nlink` | ⚠️IR模板（组合动作，建议做成**预置模板**） | |
| `fs.bigfiles` | 找出占空间最大的文件（磁盘占用排行） | `os.scandir` + `heapq.nlargest` | ⚠️IR模板（`fs.stats` 已含 Top-N，可合并） | |
| `fs.changed_since` | 列出最近几小时内改动过的文件 | `os.walk` + `st_mtime` | ⚠️IR模板（`fs.find` 的时间过滤已覆盖） | |
| **F. 磁盘与存储** | | | | |
| `disk.list` | 看有几个盘、什么类型、卷标、文件系统、还剩多少空间 | `GetLogicalDrives`+`GetDriveTypeW`+`GetVolumeInformationW`+`GetDiskFreeSpaceExW` | ✅原语 | ★ |
| `disk.usage` | 看指定路径所在磁盘的容量和剩余（并判断是不是快满了） | `shutil.disk_usage` | ✅原语（可与 `disk.list` 合并为同一原语的 `path` 参数） | |
| `disk.health` | 看物理硬盘健不健康、是固态还是机械、什么总线 | `Get-PhysicalDisk` | ✅原语（依赖 PowerShell Storage 模块） | |
| `disk.partition` | 看硬盘分区情况（分区号、大小、GPT 还是 MBR） | `Get-Partition` / `Get-Disk` | ⚠️IR模板 | |
| `disk.reliability` | 看硬盘的寿命预测、温度、通电时长、读写错误计数 | `Get-StorageReliabilityCounter`（**待验证**） | ⚠️IR模板（待验证） | |
| `disk.io` | 看磁盘读写速度、排队长度、响应时间 | `Get-Counter '\PhysicalDisk(*)\*'` | ⚠️IR模板 | |
| `disk.optimize` | 磁盘碎片整理 / TRIM / 重删（很慢，几分钟到几小时） | `Optimize-Volume` / `defrag` | ⚠️IR模板（需异步/后台语义） | |
| `disk.chkdsk` | 检查并修复磁盘错误 | `chkdsk` | ❌exec | |
| `disk.mount` | 改盘符、挂载/卸载、格式化、改分区表（可能丢整盘数据） | `mountvol` / `diskpart` / `Format-Volume` | ❌exec（原则上永不做原语） | |
| `disk.quota` | 磁盘配额（限制某用户能用多少空间） | `fsutil quota` | ❌exec | |
| `disk.vss` | 卷影副本 / 历史版本恢复 | `vssadmin` | ❌exec | |
| **G. 压缩与归档** | | | | |
| `archive.list` | 看压缩包里都有哪些文件（不用解压） | `zipfile.ZipFile.infolist` / `tarfile.getmembers` | ✅原语 | |
| `archive.extract` | 解压文件（带路径穿越和压缩炸弹防护） | `zipfile.extractall` / `tarfile.extractall` / `tar.exe` | ✅原语（本域安全增量最大的一个） | |
| `archive.create` | 把文件或目录打包成 zip / tar / tar.gz | `shutil.make_archive` / `zipfile.ZipFile.write` | ✅原语 | |
| `archive.info` | 判断这个文件是不是压缩包、是什么格式 | `zipfile.is_zipfile` / magic bytes | ⚠️IR模板（并入 `archive.list`） | |
| `archive.single` | 单文件压缩 / 解压（gz / bz2 / xz） | `gzip` / `bz2` / `lzma` | ⚠️IR模板 | |
| `archive.7z` | 读 / 写 7z 压缩包 | 无 7z 命令行；`tar.exe`（libarchive）可**读**，**写待验证**；`py7zr` 未装 | ❌exec（读取可复用 `archive.extract` 走 bsdtar） | |
| `archive.encrypted` | 带密码的压缩包（读需要密码、写加密包） | `zipfile.ZipFile.setpassword` 仅支持读；**写加密不支持（待验证）** | ❌exec / ⚠️待验证（密码不应经 agent 明文传参） | |
| `archive.stream` | 边压边传的流式压缩（不落盘） | ❌ | ❌exec | |
| **H. 权限与属主** | | | | |
| `acl.get` | 看一个文件/目录的权限清单：谁能读、谁能改 | `win32security.GetNamedSecurityInfo` / `GetNamedSecurityInfoW` / `icacls` | ✅原语（读） | |
| `acl.set` | 改权限清单（能把自己的权限提上去，风险很高） | `SetNamedSecurityInfoW` / `icacls /grant /deny` | ⚠️IR模板（高危；**首版建议 ❌exec**） | |
| `acl.owner` | 单独改文件的属主（改属主是改权限的前置） | `takeown` / `SetNamedSecurityInfoW` | ❌exec | |
| `fs.chmod` | 改 POSIX 权限位（在 Windows 上基本没意义，只影响只读位） | `os.chmod` | ⚠️IR模板（**语义不等价**，建议统一走 `fs.attrs`） | |
| **I. 注册表（用户配置类）** | | | | |
| `reg.get` | 读注册表里的配置值 | `winreg.QueryValueEx` / `RegGetValueW` | ✅原语（**白名单是核心增量**） | |
| `reg.set` | 写 / 新建注册表值（可能被用来做持久化后门） | `winreg.SetValueEx` | ✅原语（高危白名单版：严格键白名单 + **默认禁写自启动类键**） | |
| `reg.list` | 列出某个注册表键下面有哪些子键和值 | `winreg.EnumKey` / `EnumValue` | ✅原语 | |
| `reg.delete` | 删注册表的键或值（删错了程序可能起不来） | `winreg.DeleteKey` / `DeleteValue` | ⚠️IR模板（首版可不做） | |
| `reg.assoc` | 查文件关联：双击 `.txt` 会用哪个程序打开 | `winreg` 读 `HKCR` | ✅原语（读） | |
| `reg.autoruns` | 审计自启动项（Run 键、启动目录的快捷方式、服务） | `winreg` + `fs.list` | ⚠️IR模板（跨 `reg.*` + `shell.shortcut` 的组合，适合预置模板） | |
| `reg.export_import` | 导入 / 导出 `.reg` 注册表文件 | `reg export` / `reg import` | ❌exec | |
| **J. 快捷方式与外壳集成** | | | | |
| `shell.shortcut_read` | 读快捷方式指向哪、带什么参数（也能用来审计启动目录） | `WScript.Shell.CreateShortcut`（win32com） | ✅原语 | |
| `shell.shortcut_write` | 创建 / 修改快捷方式（写到「启动」目录 = 持久化） | `WScript.Shell.CreateShortcut` + `.Save()` | ✅原语（需确认；必须禁写「启动」目录） | |
| `shell.recycle` | 回收站：看里面有什么、清空、还原、把文件删进回收站 | `Shell.Application` COM / `SHFileOperationW(FOF_ALLOWUNDO)` | ✅原语（与 `fs.delete` 互为搭档） | |
| `shell.open` | 用默认程序打开文件或网址（等于执行任意文件，风险高） | `os.startfile` / `ShellExecuteW` | ⚠️IR模板（高危：严格扩展名白名单 + 确认，或干脆不做） | |
| `shell.reveal` | 在资源管理器里定位并选中某个文件 | `explorer /select,<path>` | ⚠️IR模板 | |
| `shell.clipboard` | 读 / 写剪贴板（更适合归到交互域） | `win32clipboard`（pywin32 已装，**导入待验证**） | ⚠️IR模板（归属「输入输出域」更合适） | |
| `shell.filetype` | 查文件类型的描述和图标 | `SHGetFileInfoW` | ❌exec | |

### 3.3 网络与交互域（59 条）

| 原语/能力名 | 作用（大白话） | OS 接口 | 建议 | 首批 |
|---|---|---|---|:--:|
| **A. 网络** | | | | |
| `net.interfaces` | 看这台电脑有哪些网卡、什么状态、什么速率、MAC 地址 | `Get-NetAdapter`；`ipconfig /all`；`GetAdaptersAddresses` | ✅原语 | |
| `net.ip_config` | 看本机的 IP、网关、DNS 服务器 | `Get-NetIPConfiguration`；ctypes `GetAdaptersAddresses` | ✅原语（建议与 `net.interfaces` 合并为一个，返回结构里分 `adapters[]`） | |
| `net.port_owner` | 查是哪个程序占用了某个端口 | `netstat -ano` + `tasklist` 映 PID→进程名；`Get-NetTCPConnection -LocalPort N` | ✅原语 | ★ |
| `net.connections` | 看当前所有网络连接（谁跟谁在连、什么状态、哪个进程） | `netstat -ano`；`Get-NetTCPConnection`；`GetExtendedTcpTable` | ✅原语 | |
| `net.routes` | 看路由表（去不同网段该走哪个网关） | `route print`；`Get-NetRoute`；`GetIpForwardTable2` | ✅原语 | |
| `net.dns_resolve` | 把域名翻译成 IP 地址 | `socket.getaddrinfo`；`nslookup`；`Resolve-DnsName` | ✅原语 | |
| `net.ping` | 测目标通不通、延迟多少、丢包多少 | `ping -n N host` | ✅原语（`ping` 输出是中文，需归一解析） | |
| `net.tcp_check` | 测某个端口能不能连上 | `socket.create_connection` | ✅原语（只读，⚠️可被滥用为端口扫描） | |
| `net.io_stats` | 看每块网卡收发了多少流量、丢了多少包 | `Get-NetAdapterStatistics`；`GetIfEntry2`；`/proc/net/dev` | ✅原语 | |
| `net.http_get` | 发一个 HTTP 请求取回响应（要挂域名白名单） | `urllib.request`；`requests`；`curl.exe` | ✅原语（⚠️**SSRF/任意出网**，本域安全增量最大） | |
| `net.download` | 从网上下载文件到本地 | `urllib.request.urlretrieve`；`curl -o` | ✅原语（⚠️任意下载落盘） | |
| `net.firewall_status` | 看防火墙各个配置档开没开 | `netsh advfirewall show allprofiles state`；`Get-NetFirewallProfile` | ✅原语 | |
| `net.firewall_rules` | 看防火墙的规则列表（本机 981 条，得分页） | `Get-NetFirewallRule`；`netsh advfirewall firewall show rule` | ✅原语（量大需分页） | |
| `net.wifi_status` | 看当前连的 WiFi 是哪个、信号多强、附近有哪些网络 | `netsh wlan show interfaces` / `show networks` | ✅原语（可选） | |
| 监听端口列表 | 看本机都在哪些端口上等着别人来连 | `netstat -an`；`Get-NetTCPConnection -State Listen` | ⚠️并入 `net.connections`（filter） | |
| 路由追踪 | 看数据包走到目标经过了哪些跳 | `tracert -d` | ⚠️IR模板（需解析文本；很多网络会屏蔽 ICMP） | |
| 综合诊断 | 把 ping、DNS、端口探测串起来做一次「网络体检」 | 组合上述原语 | ⚠️IR模板 | |
| ARP/邻居表 | 看局域网里都有哪些设备的 MAC 地址 | `arp -a`；`Get-NetNeighbor` | ❌exec | |
| 公网 IP 查询 | 看自己对外显示的公网 IP 是多少 | 需外部服务（api.ipify.org 等） | ❌exec（⚠️第三方外呼） | |
| 防火墙开关 | 开 / 关防火墙 | `netsh advfirewall set allprofiles state off` | ⚠️IR模板（**高危 + 需管理员**，管理员 + 确认） | |
| WiFi 连接 | 连接指定的 WiFi（要带密码） | `netsh wlan connect` | ⚠️IR模板（⚠️含密码参数） | |
| 代理设置 | 看 / 改系统代理、WinHTTP 代理 | 注册表 `Internet Settings`；`netsh winhttp show proxy` | ⚠️IR模板 | |
| hosts 文件读写 | 改 hosts 文件（把域名指向指定 IP） | `fs.*` + 需管理员 | ❌exec | |
| 抓包 | 抓取原始网络流量 | npcap / WinPcap | ❌插件（需装内核驱动，重且高危） | |
| **B. 界面交互** | | | | |
| `ui.window_list` | 看当前开了哪些窗口、标题是什么、属于哪个程序 | ctypes `EnumWindows`+`GetWindowText`；`win32gui` | ✅原语（拿到 hwnd 是后续一切窗口操作的句柄） | |
| `ui.window_activate` | 把某个窗口调到最前面 | `SetForegroundWindow`；`ShowWindow(SW_RESTORE)` | ✅原语（⚠️抢焦点，低危） | |
| `ui.window_control` | 最小化 / 最大化 / 关闭某个窗口 | `ShowWindow(SW_MINIMIZE/MAXIMIZE)`；`PostMessage(WM_CLOSE)` | ✅原语（⚠️关窗可能丢数据 → 确认） | |
| `ui.screenshot` | 截屏存成图片（agent 的「眼睛」） | `PIL.ImageGrab.grab()`；ctypes `BitBlt`(GDI) | ✅原语（⚠️隐私；建议零依赖 GDI 为基线） | |
| `ui.clipboard_get` | 读剪贴板里的文字 | `win32clipboard`；ctypes `OpenClipboard`+`GetClipboardData` | ✅原语（⚠️隐私，可能含密码） | ★ |
| `ui.clipboard_set` | 把文字写进剪贴板 | `win32clipboard.SetClipboardText`；ctypes `SetClipboardData` | ✅原语（⚠️会覆盖用户剪贴板） | ★ |
| `ui.notify` | 弹一个系统通知给用户 | PowerShell WinRT Toast；`NotifyIcon` 气泡；`winsound` | ✅原语（低危，打扰用户） | |
| `ui.type_text` | 往当前焦点窗口里输入一段纯文字 | ctypes `SendInput`(`KEYEVENTF_UNICODE`) | ✅原语（收敛为纯文本；⚠️**高危**，不暴露组合键） | |
| **C. 显示** | | | | |
| `display.modes` | 看屏幕支持哪些分辨率和刷新率 | ctypes `EnumDisplaySettings` | ✅原语（本机 38 种模式） | |
| `display.monitors` | 看接了几块显示器、各自位置、哪个是主屏 | ctypes `EnumDisplayMonitors`+`GetMonitorInfo` | ✅原语 | |
| `display.brightness` | 看屏幕亮度（只对笔记本内置屏有效） | WMI `WmiMonitorBrightness` | ✅原语（本机读=83；**必须处理"不支持"分支**） | |
| 当前显示模式 | 看当前分辨率 / 刷新率 / 色深 | `EnumDisplaySettings(ENUM_CURRENT)` | ⚠️并入 `display.modes` | |
| 区域/窗口截图 | 只截屏幕的一块区域或某个窗口 | `ImageGrab.grab(bbox=)`；`PrintWindow` | ⚠️并入 `ui.screenshot`（region 参数） | |
| 改分辨率/刷新率 | 改屏幕显示模式（可能黑屏） | `ChangeDisplaySettingsEx` | ⚠️IR模板（⚠️可能黑屏/不支持 → 确认） | |
| 亮度设置 | 调屏幕亮度 | WMI `WmiMonitorBrightnessMethods` | ⚠️IR模板（⚠️仅内置屏） | |
| **D. 声音** | | | | |
| `sound.beep` | 响一声提示音 / 播放一段 wav | `winsound.Beep`/`PlaySound`/`MessageBeep` | ✅原语（低副作用） | |
| TTS 朗读 | 把文字读出来 | `win32com` SAPI.SpVoice；PowerShell SpeechSynthesizer | ⚠️慎（项目已有 ZiYin，功能重叠） | |
| **E. 会话与电源（跨域归属，此处列出交互域视角）** | | | | |
| `power.lock` | 立即锁屏 | ctypes `LockWorkStation`；`rundll32 user32.dll,LockWorkStation` | ✅原语（低危高频） | ★ |
| `power.shutdown` | 关机 / 重启 / 睡眠 | `shutdown.exe /s /t N /r`；`rundll32 powrprof.dll,SetSuspendState` | ✅原语 + 需确认（⚠️**高危**） | ★ |
| `system.idle_time` | 看用户多久没动键盘鼠标了 | ctypes `GetLastInputInfo` | ✅原语（建议归入既有 `system.*`） | |
| `shell.open` | 用默认程序打开文件或网址 | `os.startfile`；`ShellExecute` | ✅原语（低危，用户体验） | |
| `shell.*`（窗口置顶） | 让某个窗口始终显示在最前面 | `SetWindowPos(HWND_TOPMOST)` | ⚠️并入 `ui.window_control` | |
| **F. 外设** | | | | |
| `device.usb_list` | 看这台电脑插了哪些 USB 设备 | `Get-PnpDevice -Class USB` | ✅原语（可选；本机 6 个） | |
| `device.printers` | 看装了哪些打印机 | `Get-Printer`；`win32print` | ✅原语（可选；本机 2 台） | |
| 蓝牙设备 | 看蓝牙设备和它们的状态 | `Get-PnpDevice -Class Bluetooth` | ❌exec（配对长尾） | |
| 打印作业 | 发送一个打印任务 | `win32print.StartDocPrinter` | ❌exec（⚠️有副作用） | |
| 剪贴板图片 | 读 / 写剪贴板里的图片 | `CF_DIB` + PIL | ⚠️IR模板 | |
| 暗色模式/主题 | 看 / 改系统是深色还是浅色主题 | 注册表 `AppsUseLightTheme` | ⚠️IR模板 | |
| 鼠标控制 | 移动鼠标、点击、滚轮 | ctypes `SendInput` / `mouse_event` | ⚠️IR模板（⚠️**高危**，坐标难结构化） | |
| 音量查询/设置/静音 | 调系统主音量 | `winmm.waveOutSetVolume`（**待验证**）；可靠方案需 `pycaw` | ⚠️**待验证** | |
| 快捷键/组合键 | 发送 `Ctrl+C` 这类组合键 | `SendInput` + VK 码 | ❌exec / ⚠️需确认（⚠️**高危**） | |
| UI 自动化（找控件） | 找到界面上的按钮并点击它 | `uiautomation`/`pywinauto`（未装）；UIAutomationCore.dll | ❌exec / 插件（⚠️**高危** + 依赖重） | |
| 录音 | 用麦克风录音 | `sounddevice`/`pyaudio`（未装） | ❌插件（⚠️隐私） | |
| 媒体控制 | 控制音乐播放 / 暂停 / 切歌 | WinRT `GlobalSystemMediaTransportControls` | ❌插件（依赖重） | |
| 全局键盘钩子 | 记录用户的所有按键 | `SetWindowsHookEx` | ❌**不做**（⚠️键盘记录器语义） | |

---

## 四、首批落地建议

首批共 **13 个能力**（表中 16 处 ★，其中 `disk.list`、`power.lock`、`power.shutdown` 因跨域重复盘点各占两处）。
挑选逻辑：**安全价值高 × 用得上 × 做起来不贵**。下面逐条说明为什么选它、做起来难不难、有没有前置依赖。

### 文件与存储域（5 个）

**1. `fs.path` —— 路径规范化（工具函数，不是给 AI 用的动作）**
- **为什么选**：这是**安全地基**。所有「允许写哪些目录」的判断，都得先把路径整理干净。
  否则 `C:\可写目录\..\..\Windows\System32\` 这种写法、`PROGRA~1` 这种缩写、软链接，全都能绕过限制。
- **难度**：低。用 Python 标准库就能做。
- **依赖**：无。**必须在其他写操作之前先做**——它是前提，不是可选项。

**2. `fs.write` / `fs.append` —— 写文件 / 追加内容**
- **为什么选**：**管理写文件的唯一入口**。如果只能让 AI 跑通用命令去写文件，系统根本看不到它往哪写、写了什么，「可写目录」就成了摆设。有了它，每次写都能被看见、被拦住、被记录。
- **难度**：低。建议用「先写临时文件再替换」的方式，避免写到一半崩溃留下坏文件。
- **依赖**：`fs.path`（路径判定）。

**3. `fs.delete` —— 删除（默认进回收站 + 先预览）**
- **为什么选**：破坏性最强的动作，也最该被管。做了它，系统能提供通用命令给不了的三件事：
  ① 先列出「打算删什么」让人过目；② **默认删到回收站**而不是永久删除，删错了还能捞回来；③ 递归删除时限制范围（不许删盘根、不许删系统目录）。
- **难度**：中。回收站接口要走系统底层调用（现成的第三方小库没装）。
- **依赖**：`fs.path`。

**4. `disk.list` —— 看磁盘还剩多少空间**
- **为什么选**：① 纯只读，天然安全；② **Windows 上原来最常用的那条命令（`wmic`）已经被微软删掉了**，AI 在通用命令里做这事会静默失败；③ 每台电脑都能用，跨平台也最干净。
- **难度**：低。四个系统接口拼一下就行。
- **依赖**：无。

### 进程与系统资源域（5 个）

**5. `process.info` —— 进程详情（程序装在哪个文件、什么参数、父进程是谁）**
- **为什么选**：**安全价值被严重低估的一条**。系统要判断「能不能关掉这个程序」，必须先知道**它的路径**——`C:\Windows\System32\` 下的要拦，用户自己装的可以放行。没有它，「关闭程序」只能盲目地弹一句确认。
- **难度**：低。系统接口直接给数据。
- **依赖**：无。但它是「关闭程序」「资源占用」「调优先级」的共同前提。

**6. `event.query` —— 事件日志查询**
- **为什么选**：结构化增量最大的一条。系统日志在中文 Windows 上输出的是**中文本地化的人话**，AI 自己解析非常痛苦；做成动作后直接返回规整的时间、级别、来源、内容。而且是只读的，天然安全。
- **难度**：低。
- **依赖**：无。

**7. `power.lock` —— 锁屏**
- **为什么选**：**低危高频**。「我离开一下，帮我锁屏」是最合理的日常请求，它不破坏任何数据，可以免确认直接放行——正好和下面那条形成对照，是权限分级的样板。
- **难度**：极低，一行系统调用。
- **依赖**：无。

**8. `power.shutdown` —— 关机 / 重启 / 注销**
- **为什么选**：**最典型的「必须被管」的动作**。AI 直接跑关机命令是完全黑盒；做成动作后可以强制确认、可以要求「延时 30 秒」留出反悔窗口。
- **难度**：低。
- **依赖**：无。需配 `requires_confirmation`（必填）与可撤销延时。

**9. `service.control` —— 服务启停**
- **为什么选**：关掉杀毒服务、把安全服务设成禁用，是**典型的攻击动作**。做成动作后系统能按「服务名」分级（关键服务全拦、普通服务需确认、无关服务放行）。通用命令里这一点完全拦不住。
- **难度**：中。**需要先探测有没有管理员权限**，没有就直接拒绝，而不是把一段中文报错丢给 AI。
- **依赖**：`service.list`（枚举）、`service.info`（详情）。建议三条一起做。

### 网络与交互域（3 个）

**10. `ui.clipboard_get` / `ui.clipboard_set` —— 读 / 写剪贴板**
- **为什么选**：交互域里**性价比最高**的一条——实现极简、语义清晰。
  写剪贴板是「把 AI 生成的内容交给用户」的零副作用交付手段（本项目场景里高频使用）；读剪贴板则让 AI 能接住用户复制的内容。
  唯一注意的是两者都涉及隐私：读可能拿到密码，写会覆盖用户原有的剪贴板。
- **难度**：低。
- **依赖**：无。建议不必依赖第三方库（系统底层调用即可）。

**11. `net.port_owner` —— 谁占用了这个端口**
- **为什么选**：这是「端口被占用」这类问题的**唯一最短路径**。查询本身零风险，但要把「进程编号」翻译成「进程名字」——这正是 AI 不该自己动手去解析的那类枯燥活。建议和「进程枚举」共用同一套进程名解析逻辑。
- **难度**：低。
- **依赖**：建议复用 `process.list` 的进程名解析。

---

## 五、明确不做的（负面清单）

以下是三份报告**都判断「不做原语」**的项，汇总在这里，每条附一句理由。

| 能力 | 归属域 | 不做的理由 |
|---|---|---|
| 服务创建 / 删除 `sc create`/`sc delete` | 进程与系统资源 | 参数空间大，且是**典型的持久化后门手法**，不该给一个方便按钮 |
| 进程挂起 / 恢复 | 进程与系统资源 | 依赖系统**未公开**的接口，内核不碰未文档化的东西 |
| 事件实时订阅（长连接推送） | 进程与系统资源 | 是「一直挂着的有状态服务」，与「无状态的一次性动作」定位根本冲突 |
| 防休眠 / 保持唤醒 | 进程与系统资源 | **需要配对释放**（开了要记得关），有状态，原语模型容不下；除非做成带凭证的会话 |
| 温度 / 风扇转速 | 进程与系统资源 | 系统接口支持极不稳定（**待验证**），不是可靠能力 |
| 用 `Win32_Product` 查装机清单 | 进程与系统资源 | 会触发软件安装包自修复、极慢、有副作用——**已知陷阱，禁用** |
| 注册表无限制读写 | 进程与系统资源 | 必须限定白名单，不限制等于把注册表交给 AI，安全上是负收益 |
| 进程模块(DLL) 列表 / 单实例探测 / 进程启动 | 进程与系统资源 | 长尾排障场景，通用命令已能做，无安全增量 |
| 唤醒锁占用者查询 `powercfg /requests` | 进程与系统资源 | 非管理员环境下直接不可用 |
| 磁盘挂载/改盘符/格式化/改分区表 | 文件与存储 | **极危**，可导致整盘数据丢失；原则上永不做原语 |
| 磁盘检查修复 `chkdsk` / 配额 `fsutil quota` / 卷影副本 `vssadmin` | 文件与存储 | 需管理员、纯文本输出、使用频率低 |
| 改文件属主 `takeown` | 文件与存储 | 高危——改属主是改权限的前置动作 |
| `.reg` 文件导入导出 | 文件与存储 | 导入是高危操作，且完全绕过了白名单 |
| 流式压缩（不落盘的管道式压缩） | 文件与存储 | 无可靠实现路径 |
| 长路径 `\\?\` 前缀 | 文件与存储 | 薄封装，已并入 `fs.path` |
| 文件类型/图标查询 | 文件与存储 | 输出简单，无结构化增量 |
| 全局键盘钩子 | 网络与交互 | **能力与键盘记录器无区别**，与恶意软件语义相同 |
| 抓包（npcap / WinPcap） | 网络与交互 | 需装内核驱动，重，且高危 |
| 麦克风录音 | 网络与交互 | 重依赖 + 隐私，留给插件 |
| 媒体控制（播放/暂停/切歌） | 网络与交互 | 依赖重、参数空间大、收益低 |
| 鼠标控制 / 快捷键组合键 | 网络与交互 | 副作用大、坐标难结构化，留给通用命令；如必须，也只做「需确认的 IR 模板」 |
| UI 自动化（找控件并点击） | 网络与交互 | 依赖重（相关库本机全未装），且高危，留给插件 |
| ARP / 邻居表、公网 IP 查询、hosts 文件读写、蓝牙设备、打印作业 | 网络与交互 | 长尾或需外部服务 / 管理员，使用频率低 |
| 音量控制 | 网络与交互 | 现有接口**实测可疑**（返回值异常），可靠方案需额外装库；**验证通过前不做原语** |
| 改分辨率 / 刷新率 | 网络与交互 | 可能黑屏或直接失败（接虚拟显示器/远程桌面时），高危，不进内核 |

---

## 六、待验证清单

以下项在调研机器上**没能实测确认**，报告中明确标注为「待验证」。**落地前必须先验证**，不要当成已确认的能力。

**进程与系统资源域**

| 待验证项 | 说明 |
|---|---|
| 文件占用者查询（Restart Manager） | `RmStartSession`/`RmRegisterResources`/`RmGetList` 所在库名与调用签名，仅凭记忆，未实测；也没有外部工具兜底 |
| 温度 / 风扇转速 | `MSAcpi_ThermalZoneTemperature` 在本机是否真的可查 |
| 读进程环境块 | `NtQueryInformationProcess`（未文档化接口） |
| 改系统时间所需特权 | `SetSystemTime` 需要什么权限，未确认 |
| SMART 健康状态可靠性 | `Win32_DiskDrive.Status` 上读健康的可靠性 |
| 改 DPI 后是否需重登 | 注册表 `LogPixels` 修改后的生效条件 |
| Linux 侧对应接口形态 | 本次只查了 Windows，跨平台一栏是**语义推断**，未实测 |

**文件与存储域**

| 待验证项 | 说明 |
|---|---|
| 硬盘寿命/温度读数 | `Get-StorageReliabilityCounter` 是否可用、是否需管理员、是否所有盘都支持 |
| 7z 写入能力 | 系统自带 `tar.exe`（libarchive）读 7z 可行，**写 7z 待验证**；`py7zr` 未装 |
| 加密压缩包写入 | `zipfile` 官方不支持写加密包，需 `pyzipper`（未装） |
| 剪贴板库导入 | `win32clipboard` 子模块能否成功导入（主库已装，该子模块未单独测） |
| junction（目录联接）识别 | Python 3.11 没有现成属性，需靠属性位再分辨，**具体分辨方式待验证** |
| 一批可选第三方库 | `py7zr`、`pyzipper`、`python-magic`、`chardet`、`watchdog` 均未装、未验证 |
| 系统版本字段 | 注册表 `ProductName` 在本机**误报为 Windows 10**（实际是 Windows 11），判断版本**不能信这个字段** |

**网络与交互域**

| 待验证项 | 说明 |
|---|---|
| 音量控制 | `winmm.waveOutSetVolume` 实测返回成功但读到的值异常（现代 Windows 上该接口常年不生效） |
| 系统通知弹出效果 | WinRT Toast 与 `NotifyIcon` 的类型**可以加载**，但**未实际弹窗验证** |
| 亮度不支持分支 | 亮度只对笔记本内置屏有效，外接屏/台式机返回空，需实测处理 |
| 抓包 / UI 自动化 / 录音 / 媒体控制 | 依赖的库全部未装，能力未验证（已归入不做/插件） |

---

## 七、报告来源

三份域调研报告 —— 进程与系统资源域 / 文件与存储域 / 网络与交互域，结论已并入本图。

**三份报告的调研环境（一致）**：Windows 11 家庭版中文版（DisplayVersion 25H2 / CurrentBuild 26200，AMD64），
**非管理员账户**，PowerShell 5.1（无 PowerShell 7），Python 3.11.8。
所有接口均在本机**实机只读探测**，未做任何写操作；未实测项一律标注「待验证」，未做推测性断言。

**判定标准（三份一致）**：原语增量四标准 —— **安全 / 跨平台 / 结构化 / 可组合**，其中安全权重最高。

**相关文档**：`docs/os-primitives.md`（原语清单与四标准）、`primitives/`（实现风格；原单文件 `os.py` 已按域拆为 `system/process/fs/disk/event/power/service/net/ui.py`，并落地了本图的首批 13 个能力）。
