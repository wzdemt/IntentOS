"""注册表域原语 —— 读取系统配置（registry.*）。

零依赖：Python 标准库 `winreg`，不加任何第三方库。
**安全设计（三道门）**：
  1. **根键白名单**：只认 HKLM / HKCU / HKCR / HKU / HKCC 五类根键（别名与全名都收），
     别的一律不认 —— 防止用奇怪写法绕到别的 hive
  2. **敏感路径黑名单**：SAM / SECURITY / 密钥存储一律拒绝 —— 即使当前账户本来就读不到，
     也不给 AI 一个「碰碰运气」的通道
  3. **写侧另有一整套门**：`registry.write` 走「根键白名单 + 敏感区硬拒 + 自启动键/值硬拒
     + 非 HKCU 探管理员 + dry_run 默认 True + requires_confirmation + 审计」，见文件下半部分的说明。
     读侧（`registry.read`）仍是纯只读。

**底座价值**：环境变量（env.*）、自启动清单（startup.list）这些能力都建在同一层 winreg 底座上 ——
做这一条，上面几个就不用各自去碰 winreg。⚠️ 本库**没有**「已装软件清单」原语（这句曾写成有），
别照着找。文件关联（`reg.assoc`）现在也住在本文件里，
按上面那五层优先级读 HKCR / HKCU\…\FileExts。

**加载：由 factory.load_primitives() 动态加载**（模块名 prim_registry，注册进 factory.registry）。
"""
from __future__ import annotations

import os
import winreg

from core.factory import declare_primitive  # type: ignore
from primitives._common import is_admin, winreg_type_name

# 根键别名 → (winreg 常量, 规范名)。别名和全名都收，避免调用方写法不同就失败。
_HIVES: dict[str, tuple] = {
    "HKLM": (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
    "HKEY_LOCAL_MACHINE": (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
    "HKCU": (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    "HKEY_CURRENT_USER": (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    "HKCR": (winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
    "HKEY_CLASSES_ROOT": (winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
    "HKU": (winreg.HKEY_USERS, "HKEY_USERS"),
    "HKEY_USERS": (winreg.HKEY_USERS, "HKEY_USERS"),
    "HKCC": (winreg.HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
    "HKEY_CURRENT_CONFIG": (winreg.HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
}

# 敏感区域：等于该路径或在其子树下一律拒绝（前缀匹配，全大写比较）
_SENSITIVE = (
    "SAM",                                                      # 本地账户数据库
    "SECURITY",                                                 # 安全策略 / LSA 密钥
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SECRETS",  # 密钥存储
)

# winreg 的数值类型 → 可读类型名（不返回裸数字）
def _split_path(path: str) -> tuple:
    """把 `HKLM\\SOFTWARE\\X` 拆成 (hive 常量, 规范根键名, 子路径, 错误信息)。

    调用方写法可能五花八门（正/反斜杠、带不带前缀斜杠、别名还是全名），这里统一收干净。
    出错时前三项为 None/空串，第四项是给人看的中文说明。
    """
    p = (path or "").strip().replace("/", "\\").strip("\\")
    if not p:
        return None, "", "", "注册表路径不能为空"
    head, _, rest = p.partition("\\")
    alias = head.strip().upper()
    if alias not in _HIVES:
        return None, "", "", (f"不支持的根键 {head!r}；可用别名 HKLM / HKCU / HKCR / HKU / HKCC"
                              f"（也可写全名 HKEY_LOCAL_MACHINE 等）")
    hive, canon = _HIVES[alias]
    return hive, canon, rest.strip("\\"), ""


def _is_sensitive(subpath: str) -> str | None:
    """命中敏感区域则返回命中的那条规则（供报错说明用），否则 None。"""
    up = (subpath or "").upper().strip("\\")
    if not up:
        return None
    for rule in _SENSITIVE:
        if up == rule or up.startswith(rule + "\\"):
            return rule
    return None


def _render(data) -> object:
    """把值转成能安全 JSON 化的形式。

    REG_BINARY 出来的是 bytes —— 直接塞进结果会在序列化给模型时炸，所以转成 hex 字符串。
    """
    if isinstance(data, bytes):
        return {"hex": data.hex(), "size": len(data)}
    return data


def _has_more(enum_fn, key, idx: int) -> bool:
    """再探一条：能枚举出来说明被 limit 截断了，枚举完则说明没有更多。"""
    try:
        enum_fn(key, idx)
        return True
    except OSError:
        return False


@declare_primitive(
    "registry.read",
    "读 Windows 注册表：给定键路径，返回该键下的值（名字 / 类型 / 数据）与子键列表；"
    "给 name 则只读那一个值。不碰任何键。"
    "什么时候用：想查某个配置项的**原始值**（系统版本、某个软件装的路径、某个功能的开关）。"
    "⚠️ **该用谁**：问「双击某扩展名会用哪个程序打开」用 reg.assoc（它已经把 UserChoice / "
    "Classes / HKCR 五层优先级和 AppX 占位符都判好了，**别自己翻 HKCR 猜**）；"
    "改 / 删注册表用 registry.write（会改状态、需确认、默认只预览）—— 本条只读。"
    "参数怎么填：path 必填，形如 HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    "（根键支持 HKLM / HKCU / HKCR / HKU / HKCC，别名与全名都收）；"
    "name 可选，只读这一个值（如 ProductName），不给则返回该键下全部值与子键；"
    "limit 是值与子键**各**最多返回多少条，默认 500，上限 2000。"
    "返回什么：ok；path 是规范化后的全名；只读单个值时给 name / type / data；"
    "全量时给 value_count / subkey_count / values（每条含 name / type / data）/ subkeys / "
    "values_truncated / subkeys_truncated（被 limit 截断时为 true）/ note。"
    "⚠️ 陷阱：① 敏感区域（SAM / SECURITY / 密钥存储）**硬拒**，即使当前账户本来读得到也不开这个口子；"
    "② REG_BINARY 的 data 是 {\"hex\", \"size\"} 而不是原始字节；"
    "③ 本库**没有**「已装软件清单」这条原语（这是常见误解，模块注释里也专门标了）—— "
    "想列已装程序只能自己遍历 HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall，"
    "本条只给原始键值、不给现成清单。",
    {"type": "object",
     "properties": {
         "path": {"type": "string",
                  "description": "注册表键路径，如 HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"},
         "name": {"type": "string",
                  "description": "可选：只读这个值名（如 ProductName）；不给则返回该键下全部值和子键"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 2000,
                   "description": "值和子键各最多返回多少条（防超大键撑爆上下文），"
                                  "默认 500，上限 2000"},
     },
     "required": ["path"],
     "additionalProperties": False},
    block="config",
)
def registry_read(path: str, name: str = "", limit: int = 500) -> dict:
    hive, canon, sub, err = _split_path(path)
    if err:
        return {"ok": False, "path": path, "note": err}
    bad = _is_sensitive(sub)
    if bad:
        return {"ok": False, "path": path,
                "note": f"拒绝读取：{bad} 属于敏感区域（账户库 / 安全策略 / 密钥存储），"
                        f"不在 registry.read 的允许范围内"}
    try:
        limit = max(1, min(int(limit), 2000))
    except (TypeError, ValueError):
        limit = 500
    full = canon + ("\\" + sub if sub else "")
    try:
        key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return {"ok": False, "path": full, "note": f"注册表路径不存在：{full}"}
    except PermissionError:
        return {"ok": False, "path": full, "note": f"拒绝访问：{full}（当前账户权限不足）"}
    except OSError as e:
        return {"ok": False, "path": full, "note": f"打开失败：{e}"}
    with key:
        # ① 只读某一个值
        if name:
            try:
                data, typ = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                return {"ok": False, "path": full, "name": name, "note": f"值不存在：{name}"}
            except OSError as e:
                return {"ok": False, "path": full, "name": name, "note": f"读取失败：{e}"}
            return {"ok": True, "path": full, "name": name,
                    "type": winreg_type_name(typ), "data": _render(data), "note": ""}
        # ② 全量：值 + 子键（各受 limit 约束）
        values: list[dict] = []
        i = 0
        while len(values) < limit:
            try:
                vname, data, typ = winreg.EnumValue(key, i)
            except OSError:
                break
            values.append({"name": vname or "(默认)",
                           "type": winreg_type_name(typ),
                           "data": _render(data)})
            i += 1
        subkeys: list[str] = []
        i = 0
        while len(subkeys) < limit:
            try:
                subkeys.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
        v_more = _has_more(winreg.EnumValue, key, len(values))
        s_more = _has_more(winreg.EnumKey, key, len(subkeys))
        return {"ok": True, "path": full,
                "value_count": len(values), "subkey_count": len(subkeys),
                "values": values, "subkeys": subkeys,
                "values_truncated": v_more, "subkeys_truncated": s_more,
                "note": f"共 {len(values)} 个值、{len(subkeys)} 个子键"
                        + ("（已被 limit 截断，调大 limit 或换更具体的路径）" if (v_more or s_more) else "")}


# ============================================================================
# 文件关联 —— reg.assoc（只读）
# ============================================================================
# 一个「双击 .txt 会用啥打开」的问题，答案散在五处，且**优先级不同**：
#   ① HKCU\…\Explorer\FileExts\.txt\UserChoice\ProgId  ← Win10/11 里真正生效的是它
#   ② HKCU\…\Explorer\FileExts\.txt\OpenWithList       ← 「打开方式」里候选的 exe 列表（含 MRU 顺序）
#   ③ HKCU\Software\Classes\.txt 默认值                ← 用户级覆盖
#   ④ HKCR\.txt 默认值                                 ← 机器级默认 ProgID（HKCR 是 HKLM\SOFTWARE\Classes
#                                                        与 HKCU\SOFTWARE\Classes 的合并视图）
#   ⑤ HKCR\<ProgID>\shell\open\command                 ← ProgID 解析到「谁 + 什么参数」
#
# ⚠️ **实测过的两个坑（本机 win11 build 26200）**：
#   · `.txt` 的 HKCR 默认 ProgID 是 `txtfilelegacy` —— **该 ProgID 下压根没有 shell\open\command**。
#     它是「交给系统/用户选择」的占位符，**不是**一个能启动的程序；照着 ProgID 报「用 xxx 打开」是错的。
#   · `.txt` 的 UserChoice\ProgId 是 `AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw` —— AppX（UWP）应用的
#     占位标识，**在注册表里没有传统命令行**（真实程序由包承载，要 COM/PowerShell 才解析得出来）。
#   两种情况都必须给人话，而不是把 ProgID 原样丢出去当答案。

# 「打开方式」候选里那些不是普通 ProgID 的前缀/标记
_APPX_PREFIX = "APPX"


def _default_value(key) -> tuple[object, object]:
    """读一个键的默认值（名字为空串那个值）。返回 (数据, 类型)，没有则 (None, None)。"""
    try:
        data, typ = winreg.QueryValueEx(key, "")
        return data, typ
    except OSError:
        return None, None


def _read_default(root, subpath: str):
    """打开 root\\subpath 读它的默认值。打不开 / 没有默认值都返回 (None, None, 说明)。"""
    try:
        key = winreg.OpenKey(root, subpath, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None, None, "键不存在"
    except PermissionError:
        return None, None, "拒绝访问（当前账户权限不足）"
    except OSError as e:
        return None, None, f"打开失败：{e}"
    with key:
        data, typ = _default_value(key)
        return data, typ, ""


def _progid_command(progid: str):
    """ProgID → (打开命令, shell\\open 下的 DelegateExecute, 说明)。

    DelegateExecute 非空 = 这个 ProgID 是包（UWP）委托，命令行只是形式，真实程序另在别处。
    """
    if not progid:
        return "", "", "ProgID 为空"
    # `Applications\foo.exe` 是「按 exe 注册」的写法，往下一样有 shell\open\command
    for base in (progid,):
        cmd, _t, err = _read_default(winreg.HKEY_CLASSES_ROOT,
                                     base + r"\shell\open\command")
        if not err and cmd:
            delegate, _dt, _e = _read_default(winreg.HKEY_CLASSES_ROOT,
                                              base + r"\shell\open\DelegateExecute")
            return (cmd if isinstance(cmd, str) else str(cmd),
                    delegate if isinstance(delegate, str) else "", "")
    # 没有命令行：区分「ProgID 根本不在 HKCR」和「在、但没有 open 命令」
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, progid, 0, winreg.KEY_READ):
            return "", "", f"ProgID {progid} 在注册表里，但它下面没有 shell\\open\\command"
    except OSError:
        return "", "", f"ProgID {progid} 在注册表里查不到（关联已失效或是 AppX 占位标识）"


def _program_of(command: str) -> str:
    """从命令行里抠出可执行文件：`"C:\\…\\Code.exe" "%1"` → `Code.exe`。"""
    if not command:
        return ""
    c = command.strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        exe = c[1:end] if end > 0 else c[1:]
    else:
        exe = c.split(" ")[0]
    return os.path.basename(exe.rstrip("\\")) or exe


def _enum_values(root, subpath: str) -> dict:
    """枚举一个键下的全部值（名 → 数据）。打不开就返回空字典。"""
    try:
        key = winreg.OpenKey(root, subpath, 0, winreg.KEY_READ)
    except OSError:
        return {}
    out: dict = {}
    with key:
        i = 0
        while True:
            try:
                n, d, _t = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            out[n] = d
    return out


def _normalize_ext(raw: str) -> tuple[str, str]:
    """把调用方给的「扩展名 / 文件名 / 路径」收成 `.ext`。返回 (扩展名, 错误说明)。"""
    s = (raw or "").strip().strip('"').strip()
    if not s:
        return "", "扩展名不能为空"
    # 不含路径分隔符 → 整体就当扩展名（`.txt` / `txt` / `.TXT` 都认）
    if "/" not in s and "\\" not in s:
        cand = s.strip().lstrip(".").strip()
        if cand and "." not in cand:
            return "." + cand.lower(), ""
    base = os.path.basename(s)                 # 传整个路径 / 文件名也认
    if "." not in base:
        return "", (f"{raw!r} 里没有扩展名（要点：传 `.txt`、`txt`、`report.TXT` 或完整路径都行）")
    tail = base.rsplit(".", 1)[1].strip()
    if not tail:
        return "", f"{raw!r} 里没有有效的扩展名"
    return "." + tail.lower(), ""


@declare_primitive(
    "reg.assoc",
    "查文件关联：双击某个扩展名的文件，实际会用哪个程序打开。不改任何关联。"
    "什么时候用：想知道「.pdf / .txt / .mp4 这类文件双击会被谁打开」，或者要确认某个关联是不是被改到了"
    "可疑程序上。"
    "ext 传 `.txt` / `txt` / `report.TXT` / 完整路径都行（不区分大小写）。"
    "返回什么：program 是打开它的可执行文件名、command 是完整命令行（这两个是最终答案）；"
    "prog_id 与 force_level 说明结论来自哪一层（user_choice 用户选择 / hkcu_classes 用户级覆盖 / "
    "hkcr_default 机器级默认）；另有 user_choice / hkcu_classes / hkcr_default / open_with_progids / "
    "open_with_list 是各层原始取值、方便核对；placeholder / appx = true 表示下面那种「其实没有可执行程序」"
    "的情况；exists=false 表示这个扩展名压根没关联。"
    "本条的优先级判定已经做完：Win10/11 里真正生效的是用户选择（UserChoice），其次用户级 Classes 覆盖，"
    "最后才是机器级 HKCR 默认 ProgID。"
    "⚠️ 两种「看着有关联其实没有」的情况会明确说明：① 关联指向的 ProgID 没有 shell\\open\\command"
    "（占位符，双击通常会弹「打开方式」让你选）；② 关联指向 AppX / UWP 应用的占位标识"
    "（注册表里没有传统命令行，真实程序由包承载）。"
    "⚠️ **该用谁**：只想看注册表里的**原始键值**（不解读关联语义）用 registry.read —— "
    "本条已经帮你把优先级和这两种坑判好了，一般不需要自己去翻 HKCR；"
    "要**改**关联请走 registry.write（会改状态、需确认）。",
    {"type": "object",
     "properties": {
         "ext": {"type": "string",
                 "description": "扩展名（`.txt` 或 `txt`），也可以是文件名或完整路径（自动取扩展名）"},
     },
     "required": ["ext"],
     "additionalProperties": False},
    state={"ext": "扩展名", "program": "关联程序"},
    block="config",
)
def reg_assoc(ext: str) -> dict:
    want, err = _normalize_ext(ext)
    if err:
        return {"ok": False, "ext": ext, "note": err}

    out: dict = {"ok": True, "ext": want}
    # ⚠️ 这里必须补一个反斜杠：want 自己带点（`.txt`），`FileExts\.txt` 才是对的写法
    fe = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" + "\\" + want

    # ① 用户选择（Win10+ 真正生效的一层）
    user_choice = _enum_values(winreg.HKEY_CURRENT_USER, fe + r"\UserChoice").get("ProgId")
    user_choice = user_choice if isinstance(user_choice, str) else None
    # ② 用户级 Classes 覆盖
    hkcu_classes, _t, _e = _read_default(winreg.HKEY_CURRENT_USER,
                                         r"Software\Classes" + want)
    hkcu_classes = hkcu_classes if isinstance(hkcu_classes, str) else None
    # ③ 机器级 HKCR 默认 ProgID
    hkcr, hkcr_type, hkcr_err = _read_default(winreg.HKEY_CLASSES_ROOT, want)
    hkcr = hkcr if isinstance(hkcr, str) else None
    # ④ 「打开方式」候选
    open_with_progids = sorted(k for k, _v in
                               _enum_values(winreg.HKEY_CLASSES_ROOT, want + r"\OpenWithProgids").items())
    open_with_list_raw = _enum_values(winreg.HKEY_CURRENT_USER, fe + r"\OpenWithList")
    open_with_list = [v for k, v in sorted(open_with_list_raw.items(), key=lambda kv: str(kv[0]).lower())
                      if k != "MRUList" and isinstance(v, str) and v]

    out.update({"user_choice": user_choice, "hkcu_classes": hkcu_classes,
                "hkcr_default": hkcr, "open_with_progids": open_with_progids,
                "open_with_list": open_with_list})

    if not (user_choice or hkcu_classes or hkcr or open_with_progids or open_with_list):
        out.update({"ok": False, "exists": False, "program": "", "force_level": "none",
                    "note": f"{want} 没有关联任何程序：HKCR 下没有这个扩展名的键，"
                            f"「打开方式」候选也是空的。双击这类文件会弹「你要如何打开这个文件？」"
                            f"让你现场选一个。要建立关联得往 HKCR / HKCU\\Software\\Classes 写 ProgID，"
                            f"或走系统设置的「默认应用」。"})
        return out

    # 有效 ProgID：按真实优先级取第一个非空的
    level, progid = "none", ""
    for lv, cand in (("user_choice", user_choice), ("hkcu_classes", hkcu_classes),
                     ("hkcr_default", hkcr)):
        if cand:
            level, progid = lv, cand
            break
    out["force_level"] = level
    out["prog_id"] = progid

    note_parts: list[str] = []
    if not progid:
        # 只有「打开方式」候选，没有默认 ProgID
        out.update({"program": "", "command": "",
                    "note": f"{want} 没有默认关联程序，但「打开方式」里有 {len(open_with_list)} 个候选"
                            f"（{'、'.join(open_with_list[:5])}）。双击会弹「你要如何打开这个文件？」。"})
        return out

    # AppX / UWP 占位标识
    if progid.upper().startswith(_APPX_PREFIX):
        out.update({"program": "", "command": "", "appx": True, "placeholder": True,
                    "note": f"{want} 的关联（{level}）指向 AppX / UWP 应用的占位标识 `{progid}` —— "
                            f"这是一个「包标识」，注册表里**没有**传统命令行，双击由对应的商店应用接管。"
                            f"要看清到底是哪个应用，得查 AppX 包清单（本原语给不出，"
                            f"可以看「打开方式」候选：{'、'.join(open_with_list[:5]) or '（空）'}）。"})
        return out

    command, delegate, cerr = _progid_command(progid)
    program = _program_of(command) if command else ""
    type_name, _tt, _te = _read_default(winreg.HKEY_CLASSES_ROOT, progid)
    out.update({"program": program, "command": command,
                "type_name": type_name if isinstance(type_name, str) else "",
                "delegate_execute": delegate})

    if command:
        out["note"] = (f"双击 {want} 会用 `{program}` 打开"
                       f"（结论来自 {level}，ProgID `{progid}`）；完整命令行：{command}")
        if delegate:
            note_parts.append("这条 ProgID 带 DelegateExecute（真实程序由包/委托处理器接管，"
                              "命令行只是形式）")
    else:
        out.update({"placeholder": True})
        out["note"] = (f"⚠️ {want} 看着有关联，但**没有可用的打开命令**：{cerr}。"
                       f"（结论来自 {level}，ProgID `{progid}`）这种情况双击通常会弹"
                       f"「你要如何打开这个文件？」让你选；「打开方式」候选："
                       f"{'、'.join(open_with_progids or open_with_list) or '（空）'}。"
                       f"别把 ProgID 当成能启动的程序。")
    if isinstance(type_name, str) and type_name.startswith("@"):
        note_parts.append("类型名的默认值是个「间接字符串」（@DLL,-ID 形式，要在资源里查表才有显示名），"
                          "原样给出")
    if hkcr_err and hkcr_err != "键不存在":
        note_parts.append(f"HKCR 那层读取有问题：{hkcr_err}")
    if note_parts:
        out["note"] += "；" + "；".join(note_parts)
    return out


# ============================================================================
# 写侧 —— registry.write（本域最危险的一条）
# ============================================================================
# 为什么最危险：**写注册表是持久化后门的经典手法** —— 塞一个 Run 键就是开机自启，
# 改一个 IFEO Debugger 就能劫持别的程序，改 Winlogon 的 Shell 就能顶掉用户界面。
# 所以这里的把关不是「问一句」，而是**硬拒 + 确认 + 默认只预览**三层叠：
#
#   ① 根键白名单        —— 与 registry.read 同一套（_split_path）
#   ② 敏感区域硬拒      —— 与 registry.read **同一份名单、同一个函数**（_is_sensitive），
#                          不另写一份（两份名单必然有一天会分叉）
#   ③ 自启动类键硬拒    —— Run / RunOnce / RunServices 家族及其各视图，一律不给
#   ④ 自启动 / 劫持类「值」硬拒 —— Winlogon 的 Shell / Userinit、AppInit_DLLs、IFEO 的 Debugger
#   ⑤ 非 HKCU 先探管理员 —— 不是管理员直接给人话，不把 winreg 的「拒绝访问」原样丢出去
#   ⑥ dry_run 默认 True —— 且预览这条路**用只读权限打开键**，物理上写不了
#   ⑦ requires_confirmation —— 真写要用户点头
#
# 类型：显式指定 value_type，否则沿用现有值的类型，新建时按 Python 类型推断 ——
# 并且**数值型变量不会被写成字符串**（`"1"` 会先转成 `1`，且返回里如实标出）。
# 审计：返回里带 registry_path / action / before / after / type_before / type_after，
# 调用方能逐项核对「改了哪个键、原来是什么、现在是什么」。

# 自启动类键（大写比较）：Run / RunOnce / RunServices 家族 —— 一律禁写。
# WOW6432Node 的两份要显式列出：那是 32 位视图，路径里写全了就不受视图重定向影响。
_AUTORUN_PREFIXES = (
    r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
    r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
    r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICES",
    r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICESONCE",
    r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
    r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
    r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
    r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNSERVICES",
    r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
)

# 自启动 / 劫持类「值」：键本身是合法的系统键，但其中某几个值是持久化落点，按名字禁写。
_AUTORUN_VALUES = {
    r"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON":
        {"SHELL", "USERINIT", "APPSETUP", "TASKMAN", "GINADLL"},
    r"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS":
        {"APPINIT_DLLS", "LOADAPPINIT_DLLS"},
    r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS":
        {"APPINIT_DLLS", "LOADAPPINIT_DLLS"},
}
_IFEO = r"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS"

# value_type 白名单：只认这几种（别的一律拒，不猜）
_TYPES = {
    "REG_SZ": winreg.REG_SZ,
    "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
    "REG_DWORD": winreg.REG_DWORD,
    "REG_QWORD": winreg.REG_QWORD,
    "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
    "REG_BINARY": winreg.REG_BINARY,
}
_NUMERIC = (winreg.REG_DWORD, winreg.REG_QWORD)
_ACTIONS = ("set", "delete_value", "delete_key")


def _autorun_key(subpath: str) -> str | None:
    """命中自启动类键则返回命中的规则（供说明用），否则 None。"""
    up = (subpath or "").upper().strip("\\")
    if not up:
        return None
    for rule in _AUTORUN_PREFIXES:
        if up == rule or up.startswith(rule + "\\"):
            return rule
    return None


def _autorun_value(subpath: str, name: str) -> str | None:
    """命中自启动 / 劫持类「值」则返回说明，否则 None（只在写值时判）。"""
    up = (subpath or "").upper().strip("\\")
    nm = (name or "").upper().strip()
    if not nm:
        return None
    if up in _AUTORUN_VALUES and nm in _AUTORUN_VALUES[up]:
        return f"{up} 下的 {nm}"
    if (up == _IFEO or up.startswith(_IFEO + "\\")) and nm == "DEBUGGER":
        return f"{up} 下的 Debugger（劫持别的程序的经典手法）"
    return None


def _display(value, n: int = 200) -> str:
    """值在提示语里的写法：**保留类型观感**（数字是 42 而不是 '42'），过长才截断。

    用 repr 而不是 str：`str([1,2])` 和 `repr([1,2])` 一样，但 int / str 的差别只有 repr
    看得出来 —— 而「新值到底是 1 还是 '1'」正是调用方最该核对的东西。
    """
    r = repr(_render(value))
    return r if len(r) <= n else r[:n] + f"…（共 {len(r)} 字符）"


def _infer_type(value) -> int:
    """新建值时按 Python 类型推断注册表类型。"""
    if isinstance(value, bool):
        return winreg.REG_DWORD                 # bool 是 int 的子类，必须先判
    if isinstance(value, int):
        return winreg.REG_DWORD if -(2 ** 31) <= value < 2 ** 32 else winreg.REG_QWORD
    if isinstance(value, (list, tuple)):
        return winreg.REG_MULTI_SZ
    if isinstance(value, dict) and "hex" in value:
        return winreg.REG_BINARY
    return winreg.REG_SZ


def _coerce(value, wtype: int) -> tuple[bool, object, str]:
    """把调用方给的值转成该类型该有的 Python 形态。返回 (是否成功, 数据, 错误说明)。

    ⚠️ 这里是「别把数值型变量写成字符串」那句的落点：类型定为 REG_DWORD / REG_QWORD 时，
    值**必须是整数**（数字串会被转过来并如实标注），别的一律报错退回，不猜。
    """
    if wtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        if value is None:
            return False, None, "字符串类型的值不能为空（要删除请用 action=delete_value）"
        if isinstance(value, (list, tuple, dict)):
            return False, None, (f"{winreg_type_name(wtype)} 只收字符串，"
                                 f"收到 {type(value).__name__}（列表请用 REG_MULTI_SZ）")
        return True, str(value), ""
    if wtype in _NUMERIC:
        if isinstance(value, bool):
            return True, int(value), "布尔值按 1/0 写入"
        if isinstance(value, int):
            pass
        elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
            value = int(value.strip())
            if not (-(2 ** 31) <= value < 2 ** 32) and wtype == winreg.REG_DWORD:
                return False, None, f"{value} 超出 REG_DWORD 范围（0 ~ 4294967295），要用 REG_QWORD"
            return True, value, f"数字串已按 {winreg_type_name(wtype)} 转成整数 {value}"
        else:
            return False, None, (f"{winreg_type_name(wtype)} 是数值型，值必须是整数，"
                                 f"收到 {value!r}（{type(value).__name__}）—— 硬塞字符串会把值写坏")
        if wtype == winreg.REG_DWORD and not (-(2 ** 31) <= value < 2 ** 32):
            return False, None, f"{value} 超出 REG_DWORD 范围（0 ~ 4294967295），要用 REG_QWORD"
        return True, value, ""
    if wtype == winreg.REG_MULTI_SZ:
        if isinstance(value, str):
            return True, [value], ""
        if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
            return True, list(value), ""
        return False, None, "REG_MULTI_SZ 的值必须是字符串列表（或单个字符串）"
    if wtype == winreg.REG_BINARY:
        raw = value.get("hex") if isinstance(value, dict) else value
        if not isinstance(raw, str):
            return False, None, "REG_BINARY 的值请用 hex 字符串（或 {'hex': '...'}）"
        try:
            return True, bytes.fromhex(raw.replace(" ", "").replace("\\x", "").removeprefix("0x")), ""
        except ValueError as e:
            return False, None, f"hex 解析失败：{e}"
    return True, value, ""


@declare_primitive(
    "registry.write",
    "写 / 新建 / 删除注册表的值或键 —— **本域最危险的一条**（写注册表是持久化后门的经典手法）。"
    "需用户确认，且默认只预览。"
    "action=set 写值（默认）/ delete_value 删某个值 / delete_key 删键（**只删空键**，"
    "下面还有子键就拒绝 —— 递归删除本原语不提供）。"
    "**硬拒（不是问一句，是根本不给）**：① 根键白名单（HKLM/HKCU/HKCR/HKU/HKCC）；"
    "② 敏感区域：SAM / SECURITY / 密钥存储（与 registry.read 同一份名单）；"
    "③ **自启动类键一律禁写**：Run / RunOnce / RunServices / RunServicesOnce 及 WOW6432Node 与"
    "组策略各视图 —— 往那里写等于装自启动；"
    "④ **自启动 / 劫持类值禁写**：Winlogon 的 Shell / Userinit / AppSetup / Taskman / GinaDLL、"
    "AppInit_DLLs、IFEO 的 Debugger。"
    "⑤ 非 HKCU 的写入先探管理员，不是管理员直接拒（本原语不做提权）。"
    "类型：value_type 显式指定，或用现有值的类型（新建时按值推断），返回值里 type_source 说明用了哪种；"
    "**数值型不会被写成字符串**（数字串会先转成整数并标注）。"
    "默认 create_key=False：键不存在时拒绝，确认要新建键请显式传 create_key=True。"
    "返回里带完整审计：registry_path / action / before / after / type_before / type_after，"
    "调用方据此逐项核对「改了哪个键、原来是什么、现在是什么」。"
    "⚠️ **该用谁**：只想**看**注册表（不打算改）用 registry.read；"
    "问「双击某扩展名用什么程序打开」用 reg.assoc —— 本条只负责写 / 删，不负责解读。"
    "写之前想看原值、写完之后想复核，也用 registry.read。",
    {"type": "object",
     "properties": {
         "path": {"type": "string",
                  "description": "注册表键路径，如 HKCU\\Software\\MyApp"
                                 "（根键支持 HKLM / HKCU / HKCR / HKU / HKCC）"},
         "action": {"type": "string", "enum": list(_ACTIONS),
                    "description": "set=写值（默认）/ delete_value=删值 / delete_key=删键（只删空键）"},
         "name": {"type": "string",
                  "description": "值名；不给或空串 = 该键的「默认」值。action=delete_key 时忽略"},
         "value": {"type": ["string", "integer", "boolean", "array", "object", "null"],
                   "description": "新值。REG_SZ/REG_EXPAND_SZ 给字符串；REG_DWORD/REG_QWORD 给整数；"
                                  "REG_MULTI_SZ 给字符串列表；REG_BINARY 给 hex 字符串。"
                                  "action=delete_value / delete_key 时忽略"},
         "value_type": {"type": "string", "enum": sorted(_TYPES),
                        "description": "显式指定注册表类型；不给则沿用现有值的类型，"
                                       "新建时按值推断。别把数值型写成字符串，这一项就是给它的兜底"},
         "create_key": {"type": "boolean",
                        "description": "键不存在时是否新建它，默认 False（拒绝）。"
                                       "新建键会让「哪里冒出来一个持久化落点」更难追"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不写（默认）；False=真写（需确认）"},
     },
     "required": ["path"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    block="config",
)
def registry_write(path: str, action: str = "set", name: str = "", value=None,
                   value_type: str = "", create_key: bool = False,
                   dry_run: bool = True) -> dict:
    action = (action or "set").strip().lower()
    dry = bool(dry_run)
    out: dict = {"action": action, "dry_run": dry, "is_admin": is_admin(), "ok": False}
    if action not in _ACTIONS:
        out["note"] = f"未知 action {action!r}，可选：{' / '.join(_ACTIONS)}"
        return out

    # ① 根键白名单 + 路径清洗（与 registry.read 同一个函数）
    hive, canon, sub, err = _split_path(path)
    if err:
        out.update({"path": path, "note": err})
        return out
    if not sub:
        out.update({"path": canon, "blocked": True,
                    "note": f"拒绝：不允许对整个根键 {canon} 操作 —— 根键不是能整体写/删的对象"})
        return out
    full = canon + "\\" + sub
    out.update({"path": full, "registry_path": full, "name": name or "(默认)"})

    # ② 敏感区域硬拒 —— **复用 registry.read 的那份名单与判断**，不另写一份
    bad = _is_sensitive(sub)
    if bad:
        out.update({"blocked": True,
                    "note": f"拒绝写入：{bad} 属于敏感区域（账户库 / 安全策略 / 密钥存储），"
                            f"不在 registry.write 的允许范围内 —— 这一条是硬拒，没有绕过的参数"})
        return out

    # ③ 自启动类键硬拒
    hit = _autorun_key(sub)
    if hit:
        out.update({"blocked": True,
                    "note": f"拒绝写入：{full} 属于**自启动类键**（命中规则 {hit}）—— "
                            f"往这里写东西等于装开机自启 / 持久化后门。这一条是硬拒，"
                            f"本原语不提供写自启动的任何参数。"
                            f"要看现在有哪些自启动项用 startup.list（只读）"})
        return out

    # ④ 自启动 / 劫持类「值」硬拒（只在涉及值名时判）
    if action in ("set", "delete_value"):
        hv = _autorun_value(sub, name)
        if hv:
            out.update({"blocked": True,
                        "note": f"拒绝写入：{hv} 是**自启动 / 劫持类的值**，"
                                f"写它等于换掉登录壳、注入全局 DLL 或劫持别的程序。"
                                f"这一条是硬拒，没有绕过的参数"})
            return out

    # ⑤ 非 HKCU 先探管理员（先给结论，别把 winreg 的「拒绝访问」原样丢出去）
    if hive != winreg.HKEY_CURRENT_USER and not out["is_admin"]:
        out.update({"requires_admin": True,
                    "note": f"当前会话不是管理员，无法写 {canon}（HKLM / HKCR / HKU / HKCC 需要管理员权限）。"
                            f"只想改当前用户的配置请用 HKCU\\…；本原语不做提权"})
        return out

    # ⑥ action=delete_key：删键是不可逆的，先把「里面有什么」数清楚放进审计
    if action == "delete_key":
        return _delete_key(hive, canon, sub, full, out, dry)

    # ⑦ 打开键要用的权限：**dry_run 时只读** —— 预览这条路物理上写不了（同 env.set 的样板）
    access = winreg.KEY_READ if dry else (winreg.KEY_READ | winreg.KEY_SET_VALUE)

    # ⑧ 打开键：dry_run 只读打开 —— 预览这条路物理上写不了（同 env.set 的样板）
    created = False
    try:
        key = winreg.OpenKey(hive, sub, 0, access)
    except FileNotFoundError:
        if not create_key:
            out.update({"create_key": False,
                        "note": f"键不存在：{full}。默认不新建键（create_key=False）—— "
                                f"确认要新建它请显式传 create_key=True"})
            return out
        if dry:
            out.update({"create_key": True, "would_create": full,
                        "key_existed": False, "existed_before": False,
                        "audit": {"existed_before": False, "action": action,
                                  "registry_path": full, "name": name or "(默认)"},
                        "note": f"只读预览：未执行。真执行会**新建键** {full}，"
                                f"并在其中{'写' if action == 'set' else '删'}值 {(name or '(默认)')}"})
            return out
        try:
            key = winreg.CreateKeyEx(hive, sub, 0, access)
            created = True
        except PermissionError:
            out["note"] = f"拒绝访问：无法新建 {full}（当前账户权限不足）"
            return out
        except OSError as e:
            out["note"] = f"新建键失败：{e}"
            return out
    except PermissionError:
        out["note"] = f"拒绝访问：{full}（当前账户权限不足）"
        return out
    except OSError as e:
        out["note"] = f"打开失败：{e}"
        return out

    # ⚠️ key_existed 与 existed_before 是两件事：前者说「这个键在不在」，
    # 后者说「这个**值**在不在」。混用一个字段会让调用方以为值已经存在。
    out["key_existed"] = True
    with key:
        before, before_type = None, None
        try:
            before, before_type = winreg.QueryValueEx(key, name)
        except OSError:
            pass

        # ── 删值 ──
        if action == "delete_value":
            out.update({"existed_before": before_type is not None,
                        "before": _render(before) if before_type is not None else None,
                        "type_before": winreg_type_name(before_type) if before_type is not None else None})
            if before_type is None:
                out.update({"ok": True, "action": "noop",
                            "after": None, "type_after": None,
                            "note": f"{full} 下本来就没有值 {(name or '(默认)')}，无需删除"})
                return out
            if dry:
                out.update({"would_do": f"删除 {full} 的值 {name or '(默认)'}",
                            "audit": _audit(full, name, "delete_value", before, before_type,
                                            None, None, dry=True),
                            "note": f"只读预览：未执行。真执行将删除 {full} 的值 {name or '(默认)'}"
                                    f"（原值：{_display(before)}）。⚠️ 删除值不可逆"})
                return out
            try:
                winreg.DeleteValue(key, name)
            except OSError as e:
                out["note"] = f"删除失败：{e}"
                return out
            out.update({"ok": True, "after": None, "type_after": None,
                        "audit": _audit(full, name, "delete_value", before, before_type, None, None, dry=False),
                        "note": f"已删除 {full} 的值 {name or '(默认)'}（原值：{_display(before)}）"})
            return out

        # ── 写值 ──
        # 类型：显式 > 沿用现有 > 按值推断
        if value_type:
            wt = value_type.strip().upper()
            if wt not in _TYPES:
                out["note"] = f"未知 value_type {value_type!r}，可选：{' / '.join(sorted(_TYPES))}"
                return out
            wtype, tsrc = _TYPES[wt], "explicit"
        elif before_type is not None:
            wtype, tsrc = before_type, "existing"
        else:
            wtype, tsrc = _infer_type(value), "inferred"

        ok, data, cwarn = _coerce(value, wtype)
        if not ok:
            out.update({"type_before": winreg_type_name(before_type) if before_type is not None else None,
                        "note": cwarn})
            return out

        out.update({"existed_before": before_type is not None,
                    "type_before": winreg_type_name(before_type) if before_type is not None else None,
                    "type_after": winreg_type_name(wtype), "type_source": tsrc,
                    "before": _render(before) if before_type is not None else None,
                    "after": _render(data)})
        if dry:
            out.update({"would_do": f"把 {full} 的值 {name or '(默认)'} 写成 {_display(data)}",
                        "audit": _audit(full, name, "set", before, before_type, data, wtype, dry=True),
                        "note": f"只读预览：未执行。真执行将把 {full} 的 {name or '(默认)'} "
                                f"从{_display(before) if before_type is not None else '（原本没有这个值）'}"
                                f"改成 {_display(data)}"
                                f"（类型 {winreg_type_name(wtype)}，来源 {tsrc}）"
                                + (f"；{cwarn}" if cwarn else "")})
            return out
        # 真写 + 读回校验（写成功 ≠ 写对了）
        try:
            winreg.SetValueEx(key, name, 0, wtype, data)
        except OSError as e:
            out["note"] = f"写入失败：{e}"
            return out
        try:
            back, back_type = winreg.QueryValueEx(key, name)
        except OSError as e:
            out.update({"ok": True, "verified": False,
                        "note": f"已写入，但读回校验失败：{e}；请用 registry.read 复核"})
            return out

    out.update({"ok": True, "verified": back == data,
                "audit": _audit(full, name, "set", before, before_type, back, back_type,
                                dry=False, created_key=created)})
    msg = (f"已写入 {full} 的值 {name or '(默认)'}："
           f"{_display(before) if before_type is not None else '（原本没有）'} → {_display(back)}"
           f"（类型 {winreg_type_name(back_type)}，来源 {tsrc}）")
    if created:
        msg += "；⚠️ 该键原本不存在，本次**新建了它**"
    if not out["verified"]:
        msg += "；⚠️ 读回的值与写入的不一致，请用 registry.read 复核"
    if cwarn:
        msg += f"；{cwarn}"
    out["note"] = msg
    return out


def _audit(full: str, name: str, action: str, before, before_type,
           after, after_type, dry: bool, created_key: bool = False) -> dict:
    """审计块：改了哪个键、原来是什么、新值是什么 —— 调用方据此逐项核对。"""
    return {
        "registry_path": full,
        "value_name": name or "(默认)",
        "action": action,
        "dry_run": dry,
        "existed_before": before_type is not None,
        "type_before": winreg_type_name(before_type) if before_type is not None else None,
        "before": _render(before) if before_type is not None else None,
        "type_after": winreg_type_name(after_type) if after_type is not None else None,
        "after": None if after is None else _render(after),
        "created_key": created_key,
    }


def _count_children(hive, sub: str) -> tuple[int, int, list[str]]:
    """数一个键下有多少值 / 子键，并给出前几个子键名（删键前的「里面有什么」）。"""
    try:
        key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
    except OSError:
        return 0, 0, []
    values = subkeys = 0
    names: list[str] = []
    with key:
        while True:
            try:
                winreg.EnumValue(key, values)
            except OSError:
                break
            values += 1
        while True:
            try:
                n = winreg.EnumKey(key, subkeys)
            except OSError:
                break
            if len(names) < 5:
                names.append(n)
            subkeys += 1
    return values, subkeys, names


def _delete_key(hive, canon: str, sub: str, full: str, out: dict, dry: bool) -> dict:
    """删键。**只删空键** —— 下面还有子键就拒绝（递归删除本原语不提供）。"""
    vcount, kcount, names = _count_children(hive, sub)
    if not vcount and not kcount:
        # 再确认一次键是否真的存在（空键数出来的也是 0/0）
        try:
            winreg.OpenKey(hive, sub, 0, winreg.KEY_READ).Close()
        except FileNotFoundError:
            out.update({"ok": True, "action": "noop", "existed_before": False,
                        "note": f"{full} 本来就不存在，无需删除"})
            return out
        except OSError as e:
            out.update({"note": f"打开失败：{e}"})
            return out
    audit = {"registry_path": full, "action": "delete_key", "dry_run": dry,
             "value_count": vcount, "subkey_count": kcount, "subkeys_sample": names}
    if kcount:
        out.update({"ok": False, "blocked": True, "audit": audit,
                    "note": f"拒绝删除：{full} 下面还有 {kcount} 个子键"
                            f"（{('、'.join(names))}{'…' if kcount > len(names) else ''}）—— "
                            f"DeleteKey 只能删**空键**，递归删除本原语不提供"
                            f"（那是一次抹掉一整棵子树，太容易误伤）。"
                            f"确需删除请逐个删子键，或先确认再无子键"})
        return out
    if dry:
        out.update({"ok": False, "audit": audit,
                    "would_do": f"删除空键 {full}",
                    "note": f"只读预览：未执行。真执行将删除空键 {full}"
                            f"（键内有 {vcount} 个值，会一并消失）。⚠️ 删键不可逆"})
        return out
    try:
        winreg.DeleteKey(hive, sub)
    except OSError as e:
        out["note"] = f"删除失败：{e}"
        return out
    # 读回校验：删掉之后应该打不开了
    gone = False
    try:
        winreg.OpenKey(hive, sub, 0, winreg.KEY_READ).Close()
    except FileNotFoundError:
        gone = True
    except OSError:
        gone = False
    out.update({"ok": True, "verified": gone, "audit": audit,
                "note": f"已删除空键 {full}（原有 {vcount} 个值）"
                        + ("" if gone else "；⚠️ 读回仍能打开该键，请复核")})
    return out
