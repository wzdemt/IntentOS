"""环境变量域原语 —— 读写 Windows 环境变量（env.*）。

零依赖：Python 标准库 `winreg` / `os` / `ctypes` / `re`，不加任何第三方库。

**为什么这个域值得单列**：环境变量是「程序怎么找到东西」的第一手信息 ——
排查「命令明明装了却找不到」「JAVA_HOME 指向哪个版本」「谁把 PATH 改乱了」都从它起手，
而它偏偏同时存在三个互不相干的地方（本进程、HKCU、HKLM），平时得分别去翻。
这里统一成 `scope` 三选一：
  · process —— 当前进程可见的（`os.environ`，含接入方运行时注入的临时变量）
  · user    —— 用户级永久变量，`HKCU\\Environment`
  · system  —— 系统级永久变量，`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`

**安全边界（读宽写严）**：
  1. **读**（`env.get`）无副作用，不需要 dry_run；但名字像凭据的（TOKEN / SECRET / PASSWORD /
     API_KEY…）值**默认打码** —— 环境变量是凭据最容易顺出来的地方，而读出来的东西会直接进
     模型的上下文。要看原文得显式传 `mask_secrets=False`。
  2. **写**（`env.set`）只认 user / system 两个 scope，且 **system 先探管理员**：
     非管理员直接拒绝并给人话说明，不把 `winreg` 的「拒绝访问」原样丢出去。
  3. **名字 / 值都校验**：拒绝含 `= % \\ / ; "` 或控制字符的名字（这些要么是隐藏盘符变量、
     要么会破坏变量展开、要么是注入路径），值限长。
  4. **系统级关键变量黑名单**：SystemRoot / windir / ComSpec / SystemDrive 写坏 = 系统起不来。
  5. **默认 `dry_run=True` + `requires_confirmation`**：真写要显式 `dry_run=False` 且过确认。

**两个容易踩的坑（都写在函数注释里）**：
  · **写注册表 ≠ 生效** —— 注册表只是「新进程的初值」，写完必须广播 `WM_SETTINGCHANGE`，
    见 `_broadcast_change()`。
  · **`Path` 是追加语义，别的变量不是** —— `env.set` 默认**覆盖**；要往 Path 后面加，
    用 `mode=append`（只对分号分隔的列表型变量开放，且会去重），见 `_merge_list()`。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_env，注册进 factory.registry）。
"""
from __future__ import annotations

import ctypes
import os
import re
import winreg

from core.factory import declare_primitive  # type: ignore
from primitives._common import is_admin, winreg_type_name

# 读写都显式指定 64 位视图：环境变量本身只有一份（不像 HKLM\SOFTWARE 分两个视图），
# 但写上标志能免掉「哪天在 32 位 Python 下被 WOW64 重定向到别处、读出来是空」这种玄学。
_VIEW = getattr(winreg, "KEY_WOW64_64KEY", 0)
_R = winreg.KEY_READ | _VIEW
_W = winreg.KEY_READ | winreg.KEY_SET_VALUE | _VIEW

# scope → (根键, 子路径, 给人看的路径名)
_SCOPES: dict[str, tuple] = {
    "user": (winreg.HKEY_CURRENT_USER, r"Environment", r"HKCU\Environment"),
    "system": (winreg.HKEY_LOCAL_MACHINE,
               r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
               r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
}

# 系统级写不得的变量：写坏了系统起不来或命令解释器失效（不是「危险」，是「不可挽回」）
_CRITICAL_VARS = {
    "systemroot": "系统目录（大量系统组件靠它定位）",
    "windir": "Windows 目录",
    "comspec": "命令解释器路径（cmd.exe 靠它启动）",
    "systemdrive": "系统盘符",
    "processor_architecture": "处理器架构（WOW64 重定向靠它判断）",
    "processor_architew6432": "处理器架构（32 位进程下的备用值）",
}

# 名字像凭据的：值默认打码。宁可多打一点，也别把 token 顺进模型上下文。
_SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWD|PASSWORD|CREDENTIAL|APIKEY|API_?KEY|PRIVATE_KEY|ACCESS_KEY|_KEY$)",
    re.I)

# 名字里的危险字符：`=` 是隐藏盘符变量（`=C:`）的写法；`%` 会让变量名本身被展开；
# `\\ / ;` 与引号会破坏 Path 这类变量；其余是命令行/注入面的字符。
_BAD_NAME_CHARS = set('=%\\/;"\'<>|&^!*?,:()[]{}$\t\n\r\x00')
_NAME_MAX = 255
_VALUE_MAX = 32767            # Windows 单个环境变量的上限

# 值里不许出现控制字符（除 Tab）：正常路径/参数永远用不上换行，
# 而换行是「往环境变量里塞第二条记录」的经典手法。
_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

# 「分号分隔的列表型」变量 —— 只有这类变量追加才有语义。
# 别的变量（JAVA_HOME 之类）追加没有意义，硬拼个 `;` 进去只会把值弄坏 → 拒绝。
_LIST_VARS = frozenset({
    "path", "pathext", "psmodulepath", "lib", "include", "libpath", "classpath",
    "node_path", "pythonpath", "pkg_config_path", "manpath", "ld_library_path",
})


def _open(scope: str, write: bool = False):
    """打开某个 scope 的环境变量键。返回 (key 或 None, 路径名, 人话错误说明)。"""
    hive, sub, label = _SCOPES[scope]
    try:
        return winreg.OpenKey(hive, sub, 0, _W if write else _R), label, ""
    except FileNotFoundError:
        return None, label, f"这个 scope 下没有环境变量键：{label}（系统版本可能不同）"
    except PermissionError:
        return None, label, f"拒绝访问 {label}：当前账户权限不足（写系统级变量需要管理员）"
    except OSError as e:
        return None, label, f"打开 {label} 失败：{e}"


def _has_var_pattern(value: str) -> bool:
    """值里有没有 `%XXX%` 这种变量引用（决定新变量该存成 REG_SZ 还是 REG_EXPAND_SZ）。"""
    return bool(re.search(r"%[^%]+%", value or ""))


def _expand(value):
    """展开 `%VAR%`。

    只对 REG_EXPAND_SZ 展开：那类值存的就是「模板」（如 `%SystemRoot%\\system32`），
    原样返回会让调用方误以为路径真长这样；REG_SZ 保持原样 —— 有些程序就是故意把
    `%XXX%` 当字面量存的。
    """
    if isinstance(value, str):
        return os.path.expandvars(value)
    return value


def _mask(value) -> str:
    """给凭据值打码，只留长度信息（不留头尾片段 —— 有些 token 头部就是有效信息）。"""
    n = len(value) if isinstance(value, str) else len(str(value))
    return f"<已脱敏，共 {n} 字符>"


def _short(value, n: int = 120) -> str:
    """长值（PATH 动辄上千字符）在提示语里截断，完整值仍放在 before / after 字段。"""
    s = "" if value is None else str(value)
    return s if len(s) <= n else s[:n] + f"…（共 {len(s)} 字符）"


def _entry(name: str, value, typ, mask_secrets: bool) -> dict:
    """把一条变量规整成 {name, value, type, expanded?, sensitive}。"""
    item = {"name": name, "type": winreg_type_name(typ) if not isinstance(typ, str) else typ}
    secret = bool(_SECRET_NAME.search(name or ""))
    item["sensitive"] = secret
    if mask_secrets and secret:
        item["value"] = _mask(value)
        item["masked"] = True
        return item
    item["value"] = value
    if winreg_type_name(typ) == "REG_EXPAND_SZ":
        exp = _expand(value)
        if exp != value:
            item["expanded"] = exp      # 只有真有区别才多给一个字段，省上下文
    if isinstance(value, bytes):
        item["value"] = {"hex": value.hex(), "size": len(value)}   # 二进制值没法直接 JSON 化
    return item


def _query(key, name: str):
    """读一个值。返回 (值 或 None, 类型)；不存在 / 读不了都返回 (None, None)。"""
    try:
        data, typ = winreg.QueryValueEx(key, name)
        return data, typ
    except OSError:
        return None, None


def _enum(key) -> list[tuple[str, object, int]]:
    """枚举一个键下全部变量（环境变量这个键不会有几万条，不需要分页）。"""
    out: list[tuple[str, object, int]] = []
    i = 0
    while True:
        try:
            name, data, typ = winreg.EnumValue(key, i)
        except OSError:
            break
        i += 1
        out.append((name or "(默认)", data, typ))
    return out


def _broadcast_change() -> tuple[bool, str]:
    """广播 `WM_SETTINGCHANGE`，让**之后新启动的进程**读到新环境。

    ⚠️ **写注册表 ≠ 生效**：注册表里那份只是「新进程的初值」。已经跑着的进程（含
    explorer、各种终端）都还揣着启动那一刻的老副本 —— 不广播的话，连开始菜单里新起的
    程序都读不到新值，只有注销重登或重启才认。所以写完必须广播一次。
    ⚠️ **为什么不用 setx**：`setx` 把值拼进命令行（值里带引号 / `&` / `^` 就崩），
    还有自己的 1024 字符截断，而且它同样会广播一次 —— 既然要稳，就直接写注册表 + 自己广播。

    返回 (是否成功, 说明)。广播失败**不算写失败**：值已经落盘，只是别的进程可能要重登才看到。
    """
    HWND_BROADCAST = 0xFFFF          # 发给所有顶层窗口
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002        # 有窗口卡住就放弃，别把原语挂在这儿
    try:
        user32 = ctypes.windll.user32
        user32.SendMessageTimeoutW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_ulong)]
        user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
        result = ctypes.c_ulong(0)
        ret = user32.SendMessageTimeoutW(
            ctypes.c_void_p(HWND_BROADCAST), WM_SETTINGCHANGE, ctypes.c_void_p(0),
            ctypes.c_wchar_p("Environment"), SMTO_ABORTIFHUNG, 5000, ctypes.byref(result))
    except Exception as e:
        return False, f"广播 WM_SETTINGCHANGE 失败：{e}"
    if not ret:
        return False, "广播 WM_SETTINGCHANGE 未收到应答（超时），部分已开的程序可能仍读到旧值"
    return True, "ok"


def _check_name(name) -> str:
    """校验变量名，返回错误说明（空串 = 通过）。"""
    if not isinstance(name, str) or not name.strip():
        return "变量名不能为空"
    n = name.strip()
    if len(n) > _NAME_MAX:
        return f"变量名过长（{len(n)} 字符，上限 {_NAME_MAX}）"
    if n.startswith("="):
        return ("拒绝：以 `=` 开头的是「隐藏盘符变量」（如 `=C:`），不是普通环境变量，"
                "不通过 env.set 暴露")
    bad = sorted({c for c in n if c in _BAD_NAME_CHARS})
    if bad:
        return (f"拒绝：变量名里不能有 {' '.join(repr(c) for c in bad)} —— "
                f"它们会破坏变量展开或污染 Path 这类列表型变量")
    return ""


def _check_value(value) -> str:
    """校验变量值，返回错误说明（空串 = 通过）。"""
    if not isinstance(value, str):
        return f"值必须是字符串（收到 {type(value).__name__}）；删除变量请传空串或 null"
    if len(value) > _VALUE_MAX:
        return f"值过长（{len(value)} 字符，Windows 单个环境变量上限 {_VALUE_MAX}）"
    m = _BAD_VALUE.search(value)
    if m:
        return (f"拒绝：值里含控制字符 {m.group(0)!r}（正常路径 / 参数用不上换行与不可见字符，"
                f"而它们常被用来往变量里夹带第二条记录）")
    return ""


def _split_list(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(";") if p.strip()]


def _list_key(entry: str) -> str:
    """去重比较用的归一化形式：去引号、去尾部反斜杠、统一小写。"""
    return entry.strip().strip('"').strip("'").strip().rstrip("\\").strip().lower()


def _merge_list(old: str, new: str, mode: str) -> tuple[str, int, int]:
    """把 new 追加 / 前插进 old（都是 `;` 分隔的条目串）。

    返回 (合并结果, 新增条数, 因已存在而跳过的条数)。
    ⚠️ 这是**重写整条值**，不是字符串拼接：空条目会被丢掉（本机用户 Path 里就有 3 个 `;;`
    铸成的空条目，一次 append 顺手清掉了），所以合并后的值可能比原来短 —— 这是好事，
    但必须在返回里说清楚，别让调用方以为「追加把 PATH 弄丢了」。
    ⚠️ 去重按「忽略大小写 + 忽略引号与尾部反斜杠」比较 —— 否则 `C:\\Tools\\` 与 `c:\\tools`
    会被当成两条，PATH 就是这么一次次装工具、越用越长、最后撞上长度上限的。
    """
    parts = _split_list(old)
    have = {_list_key(p) for p in parts}
    add: list[str] = []
    skipped = 0
    for entry in _split_list(new):
        k = _list_key(entry)
        if k in have:
            skipped += 1
            continue
        have.add(k)
        add.append(entry)
    merged = add + parts if mode == "prepend" else parts + add
    return ";".join(merged), len(add), skipped


@declare_primitive(
    "env.get",
    "读环境变量。scope 三选一：process=当前进程可见的（os.environ，含运行时注入的临时变量）；"
    "user=用户级永久变量（HKCU\\Environment）；system=系统级永久变量（HKLM，同系统属性里那份）。"
    "排查「命令找不到 / JAVA_HOME 指向哪 / 谁把 PATH 改乱了 / 装机查环境」都从它起手。"
    "⚠️ 要**改**环境变量用 env.set（写操作、需确认）。**注意两边默认 scope 不一样**："
    "本原语默认看 `process`（进程级、退出即失），env.set 默认写 `user`（永久、进 HKCU）——"
    "读完要写请**显式对齐 scope**，否则会「读的是临时那份、写的是永久那份」。"
    "给 name 只查一个变量（查不到返回 ok=False + 说明）；"
    "给 name_contains 做子串过滤（不区分大小写）；limit 防 PATH 这类超长值刷屏。"
    "⚠️ 名字像凭据的（TOKEN / SECRET / PASSWORD / API_KEY…）值默认打码，"
    "要看原文得显式传 mask_secrets=False —— 想清楚再传。",
    {"type": "object",
     "properties": {
         "scope": {"type": "string", "enum": ["process", "user", "system"],
                   "description": "看哪一份，默认 process（当前进程可见的）"},
         "name": {"type": "string",
                  "description": "可选：只查这一个变量（不区分大小写），如 JAVA_HOME"},
         "name_contains": {"type": "string",
                           "description": "可选：变量名包含该子串才返回（不区分大小写）"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 2000,
                   "description": "最多返回多少条，默认 500，上限 2000"},
         "mask_secrets": {"type": "boolean",
                          "description": "名字像凭据的变量是否打码，默认 True（建议保持）"},
     },
     "required": [],
     "additionalProperties": False},
    block="config",
)
def env_get(scope: str = "process", name: str = "", name_contains: str = "",
            limit: int = 500, mask_secrets: bool = True) -> dict:
    scope = (scope or "process").strip().lower()
    if scope not in _SCOPES and scope != "process":
        return {"ok": False, "scope": scope,
                "note": f"未知 scope {scope!r}，可选：process / user / system"}
    try:
        limit = max(1, min(int(limit), 2000))
    except (TypeError, ValueError):
        limit = 500
    mask = bool(mask_secrets)

    if scope == "process":
        label = r"os.environ（当前进程可见）"
        items = [_entry(k, v, "PROCESS", mask)
                 for k, v in sorted(os.environ.items(), key=lambda kv: kv[0].lower())]
    else:
        key, label, err = _open(scope)
        if key is None:
            return {"ok": False, "scope": scope, "note": err}
        with key:
            items = [_entry(n, d, t, mask) for n, d, t in
                     sorted(_enum(key), key=lambda x: x[0].lower())]

    total_all = len(items)
    # 单一变量：直接返回那一条（查不到就是 ok=False，而不是「空列表，你自己猜」）
    if name and name.strip():
        want = name.strip().lower()
        hit = [it for it in items if it["name"].lower() == want]
        if not hit:
            hint = ("（进程里看不到不代表没有永久变量，可换 scope=user / system 再查）"
                    if scope == "process" else "（换个 scope 也查一遍，或确认有没有拼错）")
            return {"ok": False, "scope": scope, "source": label, "name": name,
                    "note": f"{label} 里没有名为 {name!r} 的变量{hint}"}
        it = hit[0]
        out = {"ok": True, "scope": scope, "source": label, "exists": True, "found": True}
        out.update(it)
        if it.get("masked"):
            out["note"] = f"{name} 的值看起来是凭据，已脱敏；要看原文传 mask_secrets=False"
        return out

    needle = (name_contains or "").strip().lower()
    if needle:
        items = [it for it in items if needle in it["name"].lower()]
    matched = len(items)
    page = items[:limit]
    more = matched > limit
    note = f"{label} 共 {total_all} 个变量"
    if needle:
        note += f"，按 {name_contains!r} 过滤后 {matched} 个"
    note += f"，本次返回 {len(page)} 个"
    if more:
        note += f"；还有 {matched - len(page)} 个，调大 limit 或用 name_contains 缩小范围"
    masked = [it["name"] for it in page if it.get("masked")]
    if masked:
        note += f"；其中 {len(masked)} 个凭据类变量已脱敏（{'、'.join(masked[:3])}…）"
    return {"ok": True, "scope": scope, "source": label, "total": matched,
            "total_all": total_all, "returned": len(page), "truncated": more,
            "variables": page, "note": note}


@declare_primitive(
    "env.set",
    "写 / 删环境变量（需确认）。scope 只收 user（用户级）/ system（系统级）——"
    "process 级不给：只影响当前进程、进程退出即失，改它没有意义。"
    "⚠️ **删除必须显式**：传 mode=delete 才删，**省略 value 不再等于删除**（会直接被拒绝）——"
    "删除不可逆，不该由「少填一个参数」触发，要删就把它写出来。"
    "写完想核对，用 env.get（注意它默认看 process 级，要核对刚写的那一级请显式传同一个 scope）。"
    "⚠️ 默认是**覆盖**语义；要往 Path 这类变量后面加一条，用 mode=append（会自动去重，"
    "只对 Path / PATHEXT / PSModulePath 等分号分隔的列表型变量开放，别的变量追加没有语义会被拒）。"
    "追加是**重写整条值**：会顺带清掉空条目与完全重复的条目（PATH 只会变短或不变，不会变长）。"
    "system scope 需要管理员：先探权限，不是管理员直接拒绝（本原语不做提权）。"
    "写完后自动广播 WM_SETTINGCHANGE，新启动的进程就能读到（已经开着的进程仍需自己重读）。"
    "返回值里 action / before / after / broadcasted 说明到底做了什么。",
    {"type": "object",
     "properties": {
         "name": {"type": "string", "description": "变量名，如 JAVA_HOME 或 Path"},
         "value": {"type": "string",
                   "description": "变量值。**省略它不等于删除**（会被拒绝）——"
                                  "要删除请显式传 mode=delete"},
         "scope": {"type": "string", "enum": ["user", "system"],
                   "description": "写哪一级，默认 user；system 需要管理员"},
         "mode": {"type": "string", "enum": ["replace", "append", "prepend", "delete"],
                  "description": "覆盖（默认）/ 追加到末尾 / 插到最前 / **删除该变量**；"
                                 "append 与 prepend 只对分号分隔的列表型变量有效（Path 用 append）"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不写（默认）；False=真写"},
     },
     "required": ["name"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="config",
)
def env_set(name: str, value=None, scope: str = "user", mode: str = "replace",
            dry_run: bool = True) -> dict:
    scope = (scope or "user").strip().lower()
    mode = (mode or "replace").strip().lower()
    out: dict = {"scope": scope, "name": name, "mode": mode,
                 "dry_run": bool(dry_run), "is_admin": is_admin()}
    # ① scope 白名单（process 明确不提供写）
    if scope == "process":
        out.update({"ok": False,
                    "note": "scope=process 不提供写：进程级变量只影响当前进程、退出即失，"
                            "改它没有意义。要改永久的用 user / system；"
                            "要临时改本进程的环境，用 escape 跑一段 python。"})
        return out
    if scope not in _SCOPES:
        out.update({"ok": False, "note": f"未知 scope {scope!r}，可选：user / system"})
        return out
    if mode not in ("replace", "append", "prepend", "delete"):
        out.update({"ok": False,
                    "note": f"未知 mode {mode!r}，可选：replace / append / prepend / delete"})
        return out
    # ② 名字校验 + 系统级关键变量黑名单
    err = _check_name(name)
    if err:
        out.update({"ok": False, "note": err})
        return out
    name = name.strip()
    if scope == "system" and name.lower() in _CRITICAL_VARS:
        out.update({"ok": False, "blocked": True,
                    "note": f"拒绝写入：{name} 是关键系统变量（{_CRITICAL_VARS[name.lower()]}），"
                            f"写错会让系统无法启动或命令解释器失效"})
        return out
    # ③ 删除必须**显式**（mode=delete）—— 不再由「省略 value」触发。
    #    删除是不可逆的，不该由「少填一个参数」引起；同族的 registry.write 用的也是显式
    #    action（set / delete_value / delete_key），两条相似的写原语该用同一套口径。
    #    2026-09-12 审计实测：此前 `env.set(name="Path")`（只给名字）就会删掉用户的 PATH。
    do_delete = mode == "delete"
    if not do_delete:
        if value is None:
            out.update({"ok": False,
                        "note": "没有给 value：**本原语不再把「省略 value」当成删除**。"
                                "要删除该变量请显式传 mode=delete；要写值请传 value"})
            return out
        err = _check_value(value)
        if err:
            out.update({"ok": False, "note": err})
            return out
    # ④ 系统级先探权限 —— 放在读旧值之前，非管理员没必要往下走
    #   （这正是 service.control 的样板：先给结论，别把注册表原始报错丢出去）
    if scope == "system" and not out["is_admin"]:
        out.update({"ok": False, "requires_admin": True,
                    "note": "当前会话不是管理员，无法写系统级环境变量（HKLM 需要管理员权限）。"
                            "只想改当前用户的变量请用 scope=user；本原语不做提权。"})
        return out
    # ⑤ 打开键：dry_run 时用只读权限打开 —— 预览这条路**物理上写不了**
    key, label, oerr = _open(scope, write=not dry_run)
    if key is None:
        out.update({"ok": False, "note": oerr})
        return out
    out["registry_path"] = label
    with key:
        before, before_type = _query(key, name)
        out["exists_before"] = before_type is not None

        if do_delete:
            if before_type is None:
                out.update({"ok": True, "action": "noop",
                            "note": f"{label} 里本来就没有 {name}，无需删除"})
                return out
            if dry_run:
                out.update({"ok": False, "dry_run": True, "action": "delete",
                            "before": _short(before),
                            "would_do": f"删除 {label} 下的变量 {name}",
                            "note": f"只读预览：未执行。真执行将删除 {name}"
                                    f"（原值 {_short(before)}）"})
                return out
            try:
                winreg.DeleteValue(key, name)
            except OSError as e:
                out.update({"ok": False, "note": f"删除失败：{e}"})
                return out
            return _finish_delete(out, name, label, before)

        # ⑥ 算出新值（覆盖 / 追加 / 前插）
        new = value
        added = skipped = 0
        if mode != "replace":
            if name.lower() not in _LIST_VARS:
                out.update({"ok": False,
                            "note": f"{name} 不是分号分隔的「列表型」变量，append / prepend 对它"
                                    f"没有语义（会被当成新值的一部分，反而弄坏原值）。"
                                    f"要整个换掉请用 mode=replace。"})
                return out
            if before_type is None or not isinstance(before, str) or not before:
                new = value                       # 原本没有 / 不是字符串 —— 直接当首次设置
            else:
                new, added, skipped = _merge_list(before, value, mode)
        # ⑦ 类型：沿用原类型（别把 REG_DWORD 之类的变量改成字符串）；新建的按值里有没有
        #   `%XXX%` 选 REG_EXPAND_SZ / REG_SZ。
        if before_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            wtype = before_type
        elif before_type is None:
            wtype = winreg.REG_EXPAND_SZ if _has_var_pattern(new) else winreg.REG_SZ
        else:
            wtype = winreg.REG_SZ
        out["registry_type"] = winreg_type_name(wtype)
        # ⑧ dry_run 预览
        if dry_run:
            warn = ""
            if mode != "replace":
                warn = f"；会新增 {added} 条、跳过已存在 {skipped} 条"
            elif name.lower() in _LIST_VARS:
                # 覆盖 Path 是这类原语最危险的一步：模型以为在「加一条」，实际把整条 PATH 换掉了
                warn = (f"；⚠️ mode=replace 是**覆盖整条值**（不是追加），原值里的其他条目会消失；"
                        f"只想加一条请改用 mode=append")
            out.update({"ok": False, "dry_run": True, "action": "set", "before": _short(before),
                        "after": _short(new),
                        "would_do": f"把 {label} 的 {name} 设为（{mode}）{_short(new)}",
                        # 值里全是反斜杠，用 !r 会 double 成 `C:\\Users\\…`，模型读着别扭 → 用引号包
                        "note": f"只读预览：未执行。真执行将把 {name} 从 '{_short(before)}' "
                                f"改成 '{_short(new)}'（mode={mode}）{warn}"})
            return out
        # ⑨ 真写 + 读回校验（写成功 ≠ 写对了：类型、展开都可能出意外）
        try:
            winreg.SetValueEx(key, name, 0, wtype, new)
        except OSError as e:
            out.update({"ok": False, "note": f"写入失败：{e}"})
            return out
        back, back_type = _query(key, name)

    # ⑩ 生效路径：广播 + 同步当前进程
    ok_bc, bc_msg = _broadcast_change()
    os.environ[name] = _expand(back) if isinstance(back, str) else str(back)
    out.update({"ok": True, "action": "set", "before": _short(before), "after": _short(back),
                "verified": back == new, "broadcasted": ok_bc})
    verb = {"replace": "覆盖", "append": "追加", "prepend": "前插"}[mode]
    msg = f"{label} 的 {name} 已写入（{verb}语义，类型 {winreg_type_name(back_type or wtype)}）"
    if mode != "replace":
        msg += (f"；本次新增 {added} 条、按去重规则跳过 {skipped} 条"
                f"（追加是重写整条值：顺带清掉了空条目与完全重复的条目）")
    if not out["verified"]:
        msg += "；⚠️ 读回的值与写入不一致，请用 env.get 复核"
    if wtype == winreg.REG_SZ and _has_var_pattern(new):
        msg += "；⚠️ 值里有 %XXX% 但该变量是 REG_SZ，系统不会展开它（要展开需先删掉再重设）"
    msg += "；" + ("已广播变化，新启动的进程即可见" if ok_bc else f"⚠️ {bc_msg}")
    msg += "；当前进程的 os.environ 已同步"
    out["note"] = msg
    return out


def _finish_delete(out: dict, name: str, label: str, before) -> dict:
    """删除成功后的收尾（广播 + 同步当前进程 + 说明）。"""
    ok_bc, bc_msg = _broadcast_change()
    removed = os.environ.pop(name, None)      # 删了就别让当前进程还留着一份幻影
    out.update({"ok": True, "action": "delete", "before": _short(before), "after": None,
                "broadcasted": ok_bc, "removed_from_process": removed is not None})
    msg = f"{label} 的 {name} 已删除（原值 {_short(before)}）"
    msg += "；" + ("已广播变化" if ok_bc else f"⚠️ {bc_msg}")
    out["note"] = msg
    return out
