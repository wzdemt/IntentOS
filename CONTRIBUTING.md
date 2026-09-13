# 贡献指南

> 这份讲**怎么改这个项目**。想用它 → 读 README；想懂它为什么这么设计 → 读 `docs/design-notes.md`。

## 提交前

跑一遍案例测试套件：

```bash
python tests/smoke_test.py
```

它覆盖：只读原语真调、写类原语只预览、四道安全门、98 条原语与 13 个块的完整性、CLI 各子命令。

**126 个用例全绿再提交。** 测试里发现的问题**照实报告** —— 不要为了让结果好看而放宽断言、跳过用例或注释掉失败项。发现 bug 是好事。

## 目录规范（哪一层放什么）

分层的唯一依据是「**与平台 / 使用方是否相关**」—— 内核只认 IR，不认谁在调它。

| 目录 | 放什么 | 不放什么 |
|---|---|---|
| `core/` | IR 协议、解释器调度、Policy Gate 安全规则、工具注册表、原语工厂 | 具体原语实现、**任何 LLM / Agent 相关的东西**、`import` 任何 `adapters/` 或 `primitives/` |
| `primitives/` | 原语实现（`@declare_primitive` 声明 + 函数），按「域」分文件 | 调度逻辑、安全策略实现（策略只声明，判定在 core 的 PolicyGate）|
| `adapters/` | 接入某个使用方（你的 Agent / 面板 / CLI）的粘合代码 | 通用能力 —— 能被别人复用的东西应下沉到 `core/` 或 `primitives/` |
| `examples/` | 可运行示例、一次性工具脚本 | 被生产路径 import 的模块 |
| `docs/` | 设计文档、原语清单 | 代码 |
| `tests/` | 案例测试 | —— |

### 一条铁律：加能力不碰 core

`core/` 是内核，`primitives/` 是外设。**加 / 改 / 删一个 OS 能力，永远只动 `primitives/`，一行 core 都不用改** —— 这是「内核 / 外设分离」的验收标准。

若某次加能力被迫改了 `core/`，说明这个能力的通用部分该沉到 core，或 core 里混进了不该有的东西。

## 新增一个 OS 原语

**第一步**，在 `primitives/` 下**按域建文件**。已有的域：
`system.py` / `process.py` / `fs.py` / `disk.py` / `event.py` / `power.py` / `service.py` /
`net.py` / `ui.py` / `registry.py` / `startup.py` / `env.py` / `task.py` / `archive.py` /
`shell.py` / `acl.py` / `display.py` / `sound.py` / `device.py`。新增域就再建一个。

**第二步**，用声明式注册，**别碰 core**：

```python
from core.factory import declare_primitive

@declare_primitive("disk.usage", "查询磁盘占用", {...schema...}, state={"used_pct": "占用%"})
def disk_usage() -> dict:
    return {"used_pct": ...}
```

**就这两步。** `load_primitives` 扫描即自动进注册表 / 状态表 / 面板 / 策略 —— **core 零改动**。

## 命名规范

- **原语名用「域.动作」两段式**：`system.info`、`process.kill`、`fs.list`、`disk.usage`。域是名词，动作是动词。
- **文件名用小写**：`system.py` / `disk.py`；多个单词用下划线。文件名以 `_` 开头的会被 `load_primitives` 跳过（`__init__.py` 因此不会被误当原语加载）。
- 原语名带点（`system.info`）。有些接入方的工具名不允许点号 —— 注册表内置了 `sanitize_name()`（点号换下划线）和宽容的 `resolve_name()`，两种写法都认。

## 原语安全分级（加原语必须遵守）

| 类型 | 要求 |
|---|---|
| **会改变系统状态** | 一律带 `dry_run` 参数，**默认 `True`**（只预览）。真执行需显式传 `dry_run=False` |
| 其中**数据破坏 / 不可逆**的（删文件、关机、停服务） | **额外**加 `policy={"requires_confirmation": True}`，过 PolicyGate 确认 |
| **只读原语** | 无需 `dry_run` |

⚠️ **设计和开发阶段不真实调用接口** —— 一律 `dry_run=True` / mock / 模拟返回。

只有两种情况才允许真实执行：

1. 用户**明确要求**测某个具体操作
2. 该操作**只读、无副作用**

> **由来**：2026-09-10，`power.lock`（当时无 `dry_run` 保护）在测试中被真实调用，
> 导致用户屏幕被锁。此后定为铁律。

## 工具分块：新原语别忘了写归属

98 条原语按「操作对象」归成 **13 块**，供接入方按需展开（省 token）。新原语要在声明里写上块名：

```python
@declare_primitive(..., block="network")
```

**归属写在声明里，不靠名字前缀猜** —— `time.zones` 住在 `system.py`、`acl.get` 住在 `acl.py`，靠文件名猜迟早猜错。

漏写不会报错，但 `load_primitives()` 结束时会当场警告，`blocks.check_coverage()` 能列出全部漏网的。
