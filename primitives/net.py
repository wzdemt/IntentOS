"""网络域原语 —— 端口占用 / 只读网络查询 / 连通性与出网（net.*）。

零依赖：`netstat -ano` 拿 PID，`tasklist` 把 PID 翻译成进程名（复用 process.list 的同款解析）。
这是「端口被占用」这类问题的最短路径——查询本身零风险，但把数字 PID 翻成人看得懂的名字，
正是 AI 不该自己动手去解析的那类枯燥活。只读。

**这一域的设计取向：能用结构化接口的，绝不解析本地化文本。**
`ipconfig` / `netstat` / `route` 的输出在中文系统上是本地化文本（列名「默认网关」、
网关列的「在链路上」、状态「已建立」「侦听」），按英文列名写的解析换台机器就废。
所以网卡与 IP 配置走 ctypes 调 `iphlpapi.GetAdaptersAddresses` 拿结构体链表、
域名解析走 `socket.getaddrinfo`，都与显示语言无关；只有路由表没有现成的结构化接口，
退化为「**只认行形状、不认列名**」的解析（见 `_route_rows`）。
**安全边界（两档，别混）**：
  · **只读的**（查端口占用、查网卡、查 IP 配置、查连接、查路由、解析域名、ping、
    端口连通性、网卡流量、防火墙状态与规则、无线状态）—— 只是读内核里的表、向系统 DNS
    发一次查询、跟目标握一次手，不改任何系统状态 → **不带 dry_run、不需确认**。
  · **出网的两条**（`net.http_get` / `net.download`）—— **会主动对外通信**，后者还会落盘，
    是本域安全增量最大的一档：**两道保护都上**（默认 `dry_run=True` 只预览 + `requires_confirmation`
    要用户点头）。理由很直白：它们能把本机数据发到任意外部地址、也能把外部的东西写进本地磁盘，
    一旦被诱导就是数据外泄 / 落地恶意文件两条路。
真要改网络状态（启用/禁用网卡、改 DNS、改路由、释放/续租 DHCP）属于「会改变系统状态」，
按 README 的安全规范必须另开原语、默认 `dry_run=True` 并过确认，不在本文件现有范围内。
**加载：由 factory.load_primitives() 动态加载**（模块名 prim_net，注册进 factory.registry）。
"""
from __future__ import annotations

import base64
import ctypes
import gzip
import hashlib
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request

from core.factory import declare_primitive  # type: ignore
from primitives._common import decode_output


def _pid_names() -> dict[str, str]:
    """tasklist → {pid: 进程名}。取不到时返回空表（名称留 None，不影响主结果）。"""
    out: dict[str, str] = {}
    try:
        raw = subprocess.check_output("tasklist /fo csv /nh", text=True,
                                      encoding="utf-8", errors="replace")
        for line in raw.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                out[parts[1].strip()] = parts[0]
    except Exception:
        pass
    return out


def _netstat() -> tuple[list[dict], str | None]:
    """跑 netstat -ano 并解析成结构化行。返回 (行列表, 错误说明)。"""
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=60)
    except Exception as e:
        return [], f"调用 netstat 失败：{e}"
    if r.returncode != 0:
        return [], f"netstat 返回 {r.returncode}"
    try:
        text = r.stdout.decode("utf-8")
    except UnicodeDecodeError:
        text = r.stdout.decode("gbk", "replace")
    rows: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        # TCP 行 5 列：协议 本地 外部 状态 PID；UDP 行 4 列：协议 本地 外部 PID
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto = parts[0].upper()
        local, foreign, pid = parts[1], parts[2], parts[-1]
        if not pid.isdigit():
            continue
        rows.append({
            "protocol": proto,
            "local_address": local,
            "foreign_address": foreign,
            "state": parts[3] if proto == "TCP" and len(parts) >= 5 else None,
            "pid": pid,
            "local_port": int(local.rsplit(":", 1)[-1]) if local.rsplit(":", 1)[-1].isdigit() else None,
        })
    return rows, None


@declare_primitive(
    "net.port_owner",
    "查**本机**某个端口被谁占用：返回占用进程的 PID + 进程名 + 协议 + 连接状态。只读。"
    "⚠️ 只查本机（数据来自本机 `netstat -ano`），**查不了远端主机** —— 要判断「某台机器上的"
    "服务端口通不通」请用 net.tcp_check（它是真的对着目标握手）；要列本机全部连接（不限定"
    "某个端口）请用 net.connections。"
    "什么时候用：用户问「谁占了 8080」「服务起不来是不是端口冲突」「这个端口被哪个进程占了」"
    "用这个 —— 它已经把 PID 翻成了进程名，不必自己再跑 tasklist。"
    "参数：port 必填（1-65535）；protocol 可选 any（默认，TCP 与 UDP 都看）/ tcp / udp。"
    "返回：ok、port、protocol、count（占用者数）、owners 数组（每项 pid / name / protocol / "
    "state / local_address / foreign_address）、note。"
    "⚠️ 坑：① owners[].name 为 null 只表示「这个 PID 查不到进程名」（进程刚退出或权限不足），"
    "不代表没有占用者；② 只有 state=LISTENING 的那条才是「正在监听该端口的服务」，"
    "ESTABLISHED 只是某条已建立的连接；③ 拿它查远端端口只会得到 count=0 的误导答案。",
    {"type": "object",
     "properties": {
         "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                  "description": "本机端口号（1-65535）"},
         "protocol": {"type": "string", "enum": ["any", "tcp", "udp"],
                      "description": "只看某协议，默认 any（TCP/UDP 都看）"},
     },
     "required": ["port"],
     "additionalProperties": False},
    state={"count": "占用者数", "port": "端口"},
    block="network",
)
def net_port_owner(port, protocol: str = "any") -> dict:
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "port": port, "count": 0, "owners": [],
                "note": f"端口不是数字：{port!r}"}
    if not (0 < port_i < 65536):
        return {"ok": False, "port": port_i, "count": 0, "owners": [],
                "note": "端口必须在 1-65535 之间"}
    proto = (protocol or "any").lower()
    if proto not in ("any", "tcp", "udp"):
        return {"ok": False, "port": port_i, "count": 0, "owners": [],
                "note": f"protocol 只能是 any/tcp/udp，收到 {protocol!r}"}
    rows, err = _netstat()
    if err:
        return {"ok": False, "port": port_i, "count": 0, "owners": [], "note": err}
    names = _pid_names()
    owners: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        if row["local_port"] != port_i:
            continue
        if proto != "any" and row["protocol"].lower() != proto:
            continue
        key = (row["pid"], row["protocol"], row["state"], row["local_address"])
        if key in seen:
            continue
        seen.add(key)
        owners.append({
            "pid": row["pid"],
            "name": names.get(row["pid"]),
            "protocol": row["protocol"],
            "state": row["state"],
            "local_address": row["local_address"],
            "foreign_address": row["foreign_address"],
        })
    result = {"ok": True, "port": port_i, "protocol": proto, "count": len(owners),
              "owners": owners}
    if not owners:
        result["note"] = "该端口当前无人占用（程序可能没启动，或已释放）"
    elif any(o["name"] is None for o in owners):
        result["note"] = "部分 PID 查不到进程名（进程可能刚退出，或权限不足）"
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 只读网络查询（net.interfaces / net.ip_config / net.connections / net.routes / net.dns_resolve）
#
# 全是只读：读内核里的网卡 / 连接 / 路由表，向系统解析器发一次域名查询。
# 不改任何系统状态 → 不带 dry_run、不要确认（README「只读原语」一档）。
# ═══════════════════════════════════════════════════════════════════════════════

# ── 小工具 ──

def _text(data: bytes) -> str:
    """命令输出解码 —— 转交共享层的 `decode_output`（同一套 utf-8 → gbk → 替换 兜底）。

    这里原先自己抄了一份实现。共享层 `_common` 的存在就是为了终结这种复制 ——
    两份留着的唯一后果是「一处改进了别处不跟着改」，所以改成一行转交，行为完全一致。
    """
    return decode_output(data)


def _is_ipv4(s: str) -> bool:
    """是不是 IPv4 点分十进制（用于路由表的「行形状」判断，不依赖任何列名）。"""
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def _is_literal_ip(s: str) -> bool:
    """输入本身是不是 IP 字面量（用户直接传 IP 给 dns_resolve 时，用来说明「没走 DNS」）。"""
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except (OSError, ValueError):
            continue
    return False


def _ip_kind(ip: str, family: str) -> str:
    """地址性质：loopback / link_local / global。

    标出来是因为 fe80::* 和 169.254.* 是自动私有地址 —— 看着像 IP，实际不能当有效地址用，
    不标出来模型很容易把噪声当答案。
    """
    if family == "ipv4":
        if ip.startswith("127."):
            return "loopback"
        return "link_local" if ip.startswith("169.254.") else "global"
    low = ip.lower()
    if low == "::1":
        return "loopback"
    return "link_local" if low.startswith("fe80") else "global"


def _prefix_to_mask(prefix) -> str | None:
    """前缀长度 → IPv4 点分掩码（24 → 255.255.255.0）。越界返回 None。"""
    try:
        n = int(prefix)
    except (TypeError, ValueError):
        return None
    if not (0 <= n <= 32):
        return None
    bits = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
    return ".".join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))


def _split_addr(addr: str) -> tuple[str, int | None]:
    """netstat 的地址列 → (IP, 端口)。`192.168.2.100:443` / `[::1]:135` / `*:*` 都要认。"""
    a = (addr or "").strip()
    if not a:
        return "", None
    if a.startswith("["):                      # IPv6 写成 [::1]:135，冒号得从右往左切
        host, _, port = a.rpartition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = a.rpartition(":")
    return host, int(port) if port.isdigit() else None


# ── 网卡 / IP 配置：ctypes 调 iphlpapi.GetAdaptersAddresses ──
# 走这条而不是解析 `ipconfig`：返回的是结构体链表，与系统显示语言无关。
# 结构体布局照抄 Windows SDK 的 iptypes.h（IP_ADAPTER_ADDRESSES_LH 等），
# 前几个联合体字段（Alignment/Length/IfIndex）摊平写，x64 上布局一致。

_AF_UNSPEC = 0
_GAA_FLAG_INCLUDE_PREFIX = 0x0010
_GAA_FLAG_INCLUDE_GATEWAYS = 0x0080        # 不加这个标志 FirstGatewayAddress 恒为空
_ERROR_BUFFER_OVERFLOW = 111
_MAX_ADAPTER_ADDRESS_LENGTH = 8

# IF_OPER_STATUS → 英文状态名（不把本地化状态词透出去，模型按 UP/DOWN 判断最省事）
_OPER_STATUS = {1: "UP", 2: "DOWN", 3: "TESTING", 4: "UNKNOWN",
                5: "DORMANT", 6: "NOT_PRESENT", 7: "LOWER_LAYER_DOWN"}
# IANA ifType：只映射确定的几个，其余原样返回数字 —— 猜错类型比不猜更误导
_IF_TYPE_NAMES = {6: "ethernet", 23: "ppp", 24: "loopback", 71: "wifi", 131: "tunnel"}

# 「未知」的哨兵值（全 1）：断开的适配器速率、回环网卡的 MTU 都会返回这个，不是真值
_UNKNOWN_SPEED = 0xFFFFFFFFFFFFFFFF
_UNKNOWN_U32 = 0xFFFFFFFF
# Windows 预置的 IPv6 占位 DNS（fec0:0:0:ffff::1/2/3）不是用户配的真实服务器，
# ipconfig 也不显示它们 —— 留着只会让「DNS 服务器是谁」得到错误答案，过滤掉。
_PLACEHOLDER_DNS = ("fec0:0:0:ffff::",)


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _UNICAST(ctypes.Structure):                     # IP_ADAPTER_UNICAST_ADDRESS_LH
    pass


_UNICAST._fields_ = [
    ("Length", ctypes.c_ulong), ("Flags", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_UNICAST)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int), ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_ulong), ("PreferredLifetime", ctypes.c_ulong),
    ("LeaseLifetime", ctypes.c_ulong),
    ("OnLinkPrefixLength", ctypes.c_uint8),
]


class _DNS_SERVER(ctypes.Structure):                  # IP_ADAPTER_DNS_SERVER_ADDRESS_XP
    pass


_DNS_SERVER._fields_ = [
    ("Length", ctypes.c_ulong), ("Reserved", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_DNS_SERVER)),
    ("Address", _SOCKET_ADDRESS),
]


class _GATEWAY(ctypes.Structure):                     # IP_ADAPTER_GATEWAY_ADDRESS_LH
    pass


_GATEWAY._fields_ = [
    ("Length", ctypes.c_ulong), ("Reserved", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_GATEWAY)),
    ("Address", _SOCKET_ADDRESS),
]


class _ADAPTER(ctypes.Structure):                     # IP_ADAPTER_ADDRESSES_LH（截到网关为止）
    pass


_ADAPTER._fields_ = [
    ("Length", ctypes.c_ulong), ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_ADAPTER)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_UNICAST)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.POINTER(_DNS_SERVER)),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", ctypes.c_ulong),
    ("ZoneIndices", ctypes.c_ulong * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_ulonglong),
    ("ReceiveLinkSpeed", ctypes.c_ulonglong),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(_GATEWAY)),
]


def _sockaddr_ip(sa) -> str | None:
    """SOCKET_ADDRESS → IP 字符串。只认 IPv4/IPv6，别的地址族返回 None（不猜）。"""
    if not sa.lpSockaddr or not sa.iSockaddrLength:
        return None
    fam = ctypes.cast(sa.lpSockaddr, ctypes.POINTER(ctypes.c_ushort))[0]
    try:
        # sockaddr_in：family(2)+port(2) 后是 4 字节地址；sockaddr_in6 多 4 字节 flowinfo
        if fam == socket.AF_INET:
            return socket.inet_ntop(socket.AF_INET, ctypes.string_at(sa.lpSockaddr, 16)[4:8])
        if fam == socket.AF_INET6:
            return socket.inet_ntop(socket.AF_INET6, ctypes.string_at(sa.lpSockaddr, 28)[8:24])
    except (OSError, ValueError):
        return None
    return None


def _list_sockaddrs(head) -> list[str]:
    """把单向链表里的地址全取出来（链表以 Next 相连，取到空指针为止）。"""
    out: list[str] = []
    node = head
    while node:
        ip = _sockaddr_ip(node.contents.Address)
        if ip:
            out.append(ip)
        node = node.contents.Next
    return out


def _adapters() -> tuple[list[dict], str | None]:
    """读本机全部网卡（结构化）。返回 (网卡列表, 错误说明)。

    ⚠️ 调用约定：GetAdaptersAddresses 要调用方先给缓冲区，不够就返回 111
    （ERROR_BUFFER_OVERFLOW）并把所需大小写回 size —— 所以必须循环重试，
    一次调用拿不到东西（这点和大多数 Win32 API 不一样）。
    """
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")           # 写死库名，非 Windows 上会在这里明确报错
    except (AttributeError, OSError) as e:
        return [], (f"本机拿不到 GetAdaptersAddresses（{e}）：net.interfaces / net.ip_config "
                    f"只能在 Windows 上跑")
    size = ctypes.c_ulong(15 * 1024)
    flags = _GAA_FLAG_INCLUDE_PREFIX | _GAA_FLAG_INCLUDE_GATEWAYS
    buf = None
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetAdaptersAddresses(_AF_UNSPEC, flags, None, buf, ctypes.byref(size))
        if ret == 0:
            break
        if ret != _ERROR_BUFFER_OVERFLOW:
            return [], f"GetAdaptersAddresses 失败（错误码 {ret}）"
    else:
        return [], "GetAdaptersAddresses 缓冲区反复不足，放弃"

    out: list[dict] = []
    node = ctypes.cast(buf, ctypes.POINTER(_ADAPTER))
    while node:
        a = node.contents
        mac = "-".join(f"{b:02X}" for b in a.PhysicalAddress[:a.PhysicalAddressLength])
        addresses = []
        u = a.FirstUnicastAddress
        while u:
            ip = _sockaddr_ip(u.contents.Address)
            if ip:
                addresses.append({"ip": ip, "prefix_length": int(u.contents.OnLinkPrefixLength)})
            u = u.contents.Next
        out.append({
            "index": int(a.IfIndex),
            "name": a.FriendlyName or "",
            "description": a.Description or "",
            "adapter_name": (a.AdapterName or b"").decode("ascii", "replace"),
            "status": _OPER_STATUS.get(int(a.OperStatus), f"CODE_{int(a.OperStatus)}"),
            "type": _IF_TYPE_NAMES.get(int(a.IfType), str(int(a.IfType))),
            "mtu": None if a.Mtu == _UNKNOWN_U32 else int(a.Mtu),
            "mac": mac or None,
            "speed_mbps": (None if not a.TransmitLinkSpeed or a.TransmitLinkSpeed == _UNKNOWN_SPEED
                           else round(int(a.TransmitLinkSpeed) / 1_000_000, 1)),
            "addresses": addresses,                    # 原始顺序：IPv6 在前、IPv4 在后
            "dns_servers": [ip for ip in _list_sockaddrs(a.FirstDnsServerAddress)
                            if not ip.lower().startswith(_PLACEHOLDER_DNS)],
            "gateways": _list_sockaddrs(a.FirstGatewayAddress),
            "dns_suffix": a.DnsSuffix or "",
        })
        node = a.Next
    return out, None


@declare_primitive(
    "net.interfaces",
    "列出本机全部网卡：名称 / 描述 / 状态(UP/DOWN) / 类型 / 速率(Mbps) / MTU / MAC 地址 / IP 地址。"
    "只读。"
    "什么时候用：回答「本机有几张网卡」「网线插着没」「无线还是有线」「这块网卡 MAC 是多少」"
    "用这个；要看「我的 IP / 网关 / DNS 是多少」用 net.ip_config（它按网卡分组、还直接给你"
    "默认出口那条）；要看每块网卡收发了多少流量、有没有丢包用 net.io_stats；要看路由表"
    "（默认网关走哪张网卡、有没有多条默认路由）用 net.routes；要看无线链路（连着哪个 WiFi、"
    "信号多强）用 net.wifi_status。"
    "参数：family 只影响每张网卡 IP 列表的取舍，取值 all（默认，v4/v6 都给）/ ipv4 / ipv6 ——"
    "**不影响网卡条目本身**（断开的网卡照样返回）。"
    "返回：ok、count、up_count、family、adapters 数组（每项 index / name / description / type / "
    "status / is_up / speed_mbps / mtu / mac / addresses；addresses 里每项 ip / family / "
    "prefix_length / kind）、note。"
    "⚠️ 坑：① kind=link_local（fe80::* / 169.254.*）是自动私有地址，看着像 IP 但不能当有效地址"
    "用；② 断开或未插网线的网卡 status=DOWN、is_up=false，速率与 MTU 是 null（系统给的是"
    "「未知」哨兵值，不是 0）；③ 回环网卡（type=loopback）也在列表里，别把它当成一张真实网卡。",
    {"type": "object",
     "properties": {
         "family": {"type": "string", "enum": ["all", "ipv4", "ipv6"],
                    "description": "只影响每张网卡的 IP 列表，默认 all（v4/v6 都给）。"
                                   "（本域同名参数另写作 any / auto，含义相同：不限协议族。）"},
     },
     "required": [],
     "additionalProperties": False},
    block="network",
)
def net_interfaces(family: str = "all") -> dict:
    fam = (family or "all").strip().lower()
    if fam not in ("all", "ipv4", "ipv6"):
        return {"ok": False, "count": 0, "adapters": [],
                "note": f"family 只能是 all/ipv4/ipv6，收到 {family!r}"}
    adapters, err = _adapters()
    if err:
        return {"ok": False, "count": 0, "adapters": [], "note": err}
    if not adapters:
        return {"ok": False, "count": 0, "adapters": [], "note": "没读到任何网卡（系统返回了空列表）"}
    out: list[dict] = []
    for a in adapters:
        ips = []
        for item in a["addresses"]:
            af = "ipv6" if ":" in item["ip"] else "ipv4"
            if fam != "all" and af != fam:
                continue
            ips.append({"ip": item["ip"], "family": af,
                        "prefix_length": item["prefix_length"],
                        "kind": _ip_kind(item["ip"], af)})
        out.append({"index": a["index"], "name": a["name"], "description": a["description"],
                    "type": a["type"], "status": a["status"], "is_up": a["status"] == "UP",
                    "speed_mbps": a["speed_mbps"], "mtu": a["mtu"], "mac": a["mac"],
                    "addresses": ips})
    up = [a for a in out if a["is_up"]]
    return {"ok": True, "count": len(out), "up_count": len(up), "family": fam, "adapters": out,
            "note": f"共 {len(out)} 张网卡，其中 {len(up)} 张已启用（UP）"}


def _pick_primary(groups: list[dict], want_ip: str | None) -> dict | None:
    """从分组里挑「我的 IP」。

    want_ip 是路由表给的默认路由接口 IP：有它就只认那张网卡（正确做法 —— 只看网卡顺序会挑错，
    VPN 虚拟网卡同样带默认网关，但跃点很高、并不真正出网）；没有就退回
    「第一张已启用且有网关的网卡」，再退回「第一张有全局 IP 的已启用网卡」。
    """
    def scan(only_with_gateway: bool):
        for g in groups:
            if not g["is_up"]:
                continue
            if want_ip is not None and want_ip not in [i["ip"] for i in g["ipv4"]]:
                continue
            if want_ip is None and only_with_gateway and not g["gateways"]:
                continue
            hit = next((i for i in g["ipv4"] if i["kind"] == "global"), None)
            if hit:
                return {"ip": hit["ip"], "mask": hit["mask"], "adapter": g["name"],
                        "gateway": g["gateways"][0] if g["gateways"] else None,
                        "dns_servers": g["dns_servers"]}
        return None
    if want_ip is not None:
        return scan(False)
    return scan(True) or scan(False)


@declare_primitive(
    "net.ip_config",
    "本机 IP 配置，按网卡分组：每组给 IPv4 / IPv6 地址（含 prefix_length 与点分 mask）、默认网关、"
    "DNS 服务器、DNS 后缀，外加网卡状态与 MAC。只读，不修改任何网络配置。"
    "什么时候用：回答「我的 IP 是多少」「网关 / DNS 是哪个」用这个 —— 顶层 primary_ipv4 就是"
    "默认出口那条，省得自己从多张网卡里挑；只看网卡的名称 / 类型 / 速率 / MAC / 是不是 UP 用 "
    "net.interfaces；问「默认路由走哪张网卡、跃点多少、有没有多条默认路由」用 net.routes"
    "（本原语的 primary_ipv4 正是拿路由表跃点最小的那条定的）；要看每块网卡收发了多少流量、"
    "有没有丢包用 net.io_stats。"
    "参数：include_down（默认 false 只给已启用的网卡；想看断开/未插网线的那些传 true）。"
    "返回：ok、count、primary_ipv4（含 ip / mask / adapter / gateway / dns_servers，有路由表时"
    "多一个 route_metric）、adapters 数组（每项 name / description / status / is_up / mac / "
    "ipv4（ip / prefix_length / mask / kind）/ ipv6（ip / prefix_length / kind）/ gateways / "
    "dns_servers / dns_suffix）、note。"
    "⚠️ 坑：① kind=link_local（169.254.* / fe80::*）是自动私有地址，不能当有效 IP 用；"
    "② Windows 预置的占位 DNS（fec0:0:0:ffff::*）已过滤，不会混进 dns_servers；"
    "③ 多张网卡都有地址时，**别拿 adapters 的第一条当「我的 IP」** —— 虚拟网卡（VPN / WSL）也在"
    "里面，以 primary_ipv4 为准（取不到路由表时 note 里会说明它是按网卡顺序推测的）；"
    "④ 判断当前网络位置对应的防火墙防护，配合 net.firewall_status / net.wifi_status。",
    {"type": "object",
     "properties": {
         "include_down": {"type": "boolean",
                          "description": "true=连状态非 UP 的网卡也返回，默认 false（只给已启用的）"},
     },
     "required": [],
     "additionalProperties": False},
    block="network",
)
def net_ip_config(include_down: bool = False) -> dict:
    adapters, err = _adapters()
    if err:
        return {"ok": False, "count": 0, "adapters": [], "note": err}
    groups: list[dict] = []
    for a in adapters:
        if not include_down and a["status"] != "UP":
            continue
        v4, v6 = [], []
        for item in a["addresses"]:
            ip = item["ip"]
            if ":" in ip:
                v6.append({"ip": ip, "prefix_length": item["prefix_length"],
                           "kind": _ip_kind(ip, "ipv6")})
            else:
                v4.append({"ip": ip, "prefix_length": item["prefix_length"],
                           "mask": _prefix_to_mask(item["prefix_length"]),
                           "kind": _ip_kind(ip, "ipv4")})
        groups.append({"name": a["name"], "description": a["description"],
                       "status": a["status"], "is_up": a["status"] == "UP", "mac": a["mac"],
                       "ipv4": v4, "ipv6": v6, "gateways": a["gateways"],
                       "dns_servers": a["dns_servers"], "dns_suffix": a["dns_suffix"]})
    # 主 IPv4：以**路由表里跃点最小的默认路由**为准（它的接口 IP 才是真正出网的那个）。
    # 取不到路由表时退回按网卡挑，并在 note 里说清楚这是推测 —— 不装确定。
    want_ip, metric = _default_interface_ip()      # 实现见下面「路由表」段
    primary = _pick_primary(groups, want_ip)
    if primary is not None and metric is not None:
        primary["route_metric"] = metric
    up_n = sum(1 for g in groups if g["is_up"])
    note = (f"网卡 {len(groups)} 张（其中已启用 {up_n} 张）" if groups
            else "没有已启用的网卡（可用 include_down=true 看全部）")
    if primary:
        note += f"；默认出口 {primary['ip']}（{primary['adapter']}"
        note += f"，网关 {primary['gateway']}）" if primary["gateway"] else "）"
    if primary and want_ip is None:
        note += "；未取到路由表，默认出口是按网卡顺序推测的"
    return {"ok": bool(groups), "count": len(groups), "primary_ipv4": primary,
            "adapters": groups, "note": note}


# ── 连接表：复用上面的 netstat 解析，补上状态归一与分页 ──
# netstat 的状态列在中文系统上是本地化文本（「已建立」「侦听」）。这里把已知写法归一到英文
# 规范名；**映射不全也不影响过滤** —— 过滤时原始文本也参与匹配（见 _conn_state_match），
# 所以照抄界面上的中文状态词一样能筛出来。归一只是为了让 by_state 的键稳定、好看。
_STATE_ALIASES = {
    "ESTABLISHED": "ESTABLISHED", "已建立": "ESTABLISHED", "已建立连接": "ESTABLISHED",
    "LISTENING": "LISTENING", "侦听": "LISTENING", "监听": "LISTENING", "正在侦听": "LISTENING",
    "CLOSE_WAIT": "CLOSE_WAIT", "关闭等待": "CLOSE_WAIT",
    "TIME_WAIT": "TIME_WAIT", "时间等待": "TIME_WAIT",
    "SYN_SENT": "SYN_SENT", "同步已发送": "SYN_SENT",
    "SYN_RECEIVED": "SYN_RECEIVED", "同步已接收": "SYN_RECEIVED",
    "FIN_WAIT_1": "FIN_WAIT_1", "FIN_WAIT_2": "FIN_WAIT_2", "LAST_ACK": "LAST_ACK",
    "CLOSING": "CLOSING", "DELETE_TWA": "DELETE_TWA",
}


def _canon_state(raw: str | None) -> str | None:
    """状态原始文本 → 规范名。中文键不受 .upper() 影响，所以一次查表两种写法都覆盖。"""
    if not raw:
        return None
    s = raw.strip()
    return _STATE_ALIASES.get(s.upper(), s.upper())


def _conn_state_match(raw: str | None, canon: str | None, want: str) -> bool:
    """状态过滤：want 与「原始文本」「规范名」都做双向子串匹配。

    双向子串是为了好用：want="wait" 能命中 TIME_WAIT / CLOSE_WAIT，want="listen" 命中 LISTENING，
    中文系统上 want="侦听" 直接命中（原始文本参与匹配）。
    ⚠️ 空串要挡掉 —— `"" in x` 恒为 True，不挡就等于「过滤条件形同虚设」。
    """
    w = (want or "").strip().upper()
    if not w:
        return True
    r = (raw or "").upper()
    c = (canon or "").upper()
    return bool((r and (w in r or r in w)) or (c and (w in c or c in w)))


@declare_primitive(
    "net.connections",
    "当前网络连接表（netstat -ano 的语义化版）：本地地址 / 远端地址 / 状态 / 协议 / 所属进程(PID+进程名)。"
    "只读。"
    "什么时候用：回答「谁连着 3306」「本机有没有连到某个外网 IP」「这个进程开了哪些端口」用这个。"
    "只想知道**某一个端口被谁占用**（不是列全部连接）用 net.port_owner —— 它更直接；"
    "本原语适合「按状态 / 协议筛一批连接」这种全局视角。"
    "⚠️ 连接数常有上百条，**不要一次全拉**：先用 state 过滤，再用 limit/offset 分页。"
    "参数：state（默认 all；英文与本地化写法都认，且是子串匹配 —— established / listening / wait / "
    "syn 都行，中文系统上直接写「已建立」「侦听」也认）；protocol（any 默认 / tcp / udp）；"
    "limit（默认 100，上限 500）；offset（默认 0，翻页用）。"
    "返回：ok、total_all、matched（过滤后条数）、returned（本次返回条数）、offset、truncated、"
    "by_state（过滤后的状态计数）、connections 数组（每项 protocol / local_address / local_ip / "
    "local_port / remote_address / remote_ip / remote_port / state / state_canonical / pid / "
    "process）、note。"
    "⚠️ 坑：① UDP 行没有状态（协议本身无连接），会被状态过滤排除 —— 要看 UDP 请传 protocol=udp "
    "并把 state 留 any；② process 为 null 只表示这个 PID 查不到进程名（进程刚退出或权限不足），"
    "不代表该连接没有主人；③ 先看 by_state 再决定翻哪一页，别盲翻。",
    {"type": "object",
     "properties": {
         "state": {"type": "string",
                   "description": "状态过滤，默认 all；支持子串匹配，如 established / listening / wait / 侦听"},
         "protocol": {"type": "string", "enum": ["any", "tcp", "udp"],
                      "description": "协议过滤，默认 any"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "最多返回条数，默认 100，上限 500"},
         "offset": {"type": "integer", "minimum": 0, "description": "跳过前 N 条（翻页用），默认 0"},
     },
     "required": [],
     "additionalProperties": False},
    block="network",
)
def net_connections(state: str = "all", protocol: str = "any",
                    limit: int = 100, offset: int = 0) -> dict:
    proto = (protocol or "any").strip().lower()
    if proto not in ("any", "tcp", "udp"):
        return {"ok": False, "total_all": 0, "matched": 0, "returned": 0, "connections": [],
                "note": f"protocol 只能是 any/tcp/udp，收到 {protocol!r}"}
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    rows, err = _netstat()                     # 复用本文件已有的 netstat 解析
    if err:
        return {"ok": False, "total_all": 0, "matched": 0, "returned": 0, "connections": [],
                "note": err}
    names = _pid_names()                       # 复用已有的 PID → 进程名
    want_all = (state or "all").strip().lower() in ("all", "", "*")
    items: list[dict] = []
    for row in rows:
        if proto != "any" and row["protocol"].lower() != proto:
            continue
        canon = _canon_state(row["state"])
        if not want_all and not _conn_state_match(row["state"], canon, state):
            continue
        local_ip, local_port = _split_addr(row["local_address"])
        remote_ip, remote_port = _split_addr(row["foreign_address"])
        items.append({"protocol": row["protocol"],
                      "local_address": row["local_address"], "local_ip": local_ip,
                      "local_port": local_port,
                      "remote_address": row["foreign_address"], "remote_ip": remote_ip,
                      "remote_port": remote_port,
                      "state": row["state"], "state_canonical": canon,
                      "pid": row["pid"], "process": names.get(row["pid"])})
    matched = len(items)
    page = items[offset:offset + limit]
    more = offset + len(page) < matched
    by_state: dict[str, int] = {}
    for it in items:
        key = it["state_canonical"] or it["state"] or "(无状态/UDP)"
        by_state[key] = by_state.get(key, 0) + 1
    note = (f"连接共 {len(rows)} 条，过滤后 {matched} 条，本次返回 {len(page)} 条"
            + (f"；还有 {matched - offset - len(page)} 条，用 offset={offset + len(page)} 继续取"
               if more else ""))
    return {"ok": True, "total_all": len(rows), "matched": matched, "returned": len(page),
            "offset": offset, "truncated": more, "by_state": by_state,
            "connections": page, "note": note}


# ── 路由表：`route print -4`，只认行形状不认列名 ──

def _route_rows(text: str) -> tuple[list[dict], list[dict]]:
    """从 `route print -4` 的输出里挑出路由行，返回 (活动路由, 持久路由)。

    为什么靠「行形状」而不是列名：中文系统上表头是「网络目标 网络掩码 网关 接口 跃点数」、
    网关列的「在链路上」也变中文，按列名写解析换台机器就废。而行的形状是语言无关的：
      活动路由 5 列 —— 目标(v4) 掩码(v4) 网关(IP 或本地化文本) 接口(v4) 跃点(整数)
      持久路由 4 列 —— 目标(v4) 掩码(v4) 网关(v4) 跃点(整数)     ← 没有接口列，天然区分
    顺带把 IPv6 段也挡在外面（IPv6 行没有掩码列，形状对不上）。
    """
    active: list[dict] = []
    persistent: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if (len(parts) == 5 and _is_ipv4(parts[0]) and _is_ipv4(parts[1])
                and _is_ipv4(parts[3]) and parts[4].isdigit()):
            gw = parts[2]
            active.append({"destination": parts[0], "netmask": parts[1],
                           "gateway": gw if _is_ipv4(gw) else None, "gateway_text": gw,
                           "on_link": not _is_ipv4(gw),
                           "interface": parts[3], "metric": int(parts[4])})
        elif (len(parts) == 4 and _is_ipv4(parts[0]) and _is_ipv4(parts[1])
                and _is_ipv4(parts[2]) and parts[3].isdigit()):
            persistent.append({"destination": parts[0], "netmask": parts[1],
                               "gateway": parts[2], "metric": int(parts[3])})
    return active, persistent


def _default_interface_ip() -> tuple[str | None, int | None]:
    """默认路由（0.0.0.0/0）里跃点最小的那条的 (接口 IP, 跃点)。取不到返回 (None, None)。

    给 net.ip_config 判断「哪个 IP 真正出网」用的（见 net_ip_config 里的注释）。
    定义在这里是因为它靠 `_route_rows`；模块是先整体加载再执行的，所以上面的原语调用它没问题。
    """
    try:
        r = subprocess.run(["route", "print", "-4"], capture_output=True, timeout=30)
        if r.returncode != 0:
            return None, None
        active, _ = _route_rows(_text(r.stdout))
    except Exception:
        return None, None
    cands = [row for row in active
             if row["destination"] == "0.0.0.0" and row["netmask"] == "0.0.0.0"]
    if not cands:
        return None, None
    best = min(cands, key=lambda x: x["metric"])     # 多默认路由时跃点小的生效
    return best["interface"], best["metric"]


@declare_primitive(
    "net.routes",
    "本机 IPv4 路由表：每条给目标网段 / 掩码 / 网关 / 接口 / 跃点数，另附持久路由。只读。"
    "什么时候用：回答「默认网关走哪张网卡」「为什么某个网段走 VPN」「是不是有多个默认路由」"
    "用这个。要「我的 IP / 网关 / DNS 是多少」用 net.ip_config（它已经把默认出口那条挑好了）；"
    "看网卡的名称 / 状态 / 速率用 net.interfaces；判断通不通请配合 net.ping / net.tcp_check ——"
    "路由表只说明「本该往哪走」，不代表那条路真的通。"
    "参数：无（不接受任何参数）。"
    "返回：ok、count（活动路由条数）、persistent_count、default_route_count、routes 数组"
    "（每项 destination / netmask / gateway / gateway_text / on_link / interface / "
    "interface_name / metric / is_default）、persistent_routes 数组"
    "（每项 destination / netmask / gateway / metric / is_default）、note。"
    "⚠️ 坑：① 只覆盖 IPv4 —— 本原语调的是 `route print -4`，IPv6 路由表不在返回里；"
    "② is_default=true（0.0.0.0/0）会有多条（多张网卡各一条），**跃点数 metric 最小的那条才生效**；"
    "③ on_link=true 时 gateway 为 null（同网段直连、不经网关），gateway_text 保留系统原文"
    "（中文系统上是「在链路上」）；④ interface_name 是尽力把接口 IP 翻成网卡名，取不到为 null，"
    "null 不代表这张网卡不存在。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    block="network",
)
def net_routes() -> dict:
    try:
        r = subprocess.run(["route", "print", "-4"], capture_output=True, timeout=30)
    except Exception as e:
        return {"ok": False, "count": 0, "routes": [], "note": f"调用 route 失败：{e}"}
    if r.returncode != 0:
        return {"ok": False, "count": 0, "routes": [],
                "note": f"route print 返回 {r.returncode}：{_text(r.stdout + r.stderr)[:200]}"}
    active, persistent = _route_rows(_text(r.stdout))
    if not active and not persistent:
        return {"ok": False, "count": 0, "routes": [],
                "note": "没解析出任何路由行（系统输出格式与预期不符，可能不是 IPv4 路由表）"}
    ip_to_name = {}
    for a in (_adapters()[0] or []):           # 尽力：接口 IP → 网卡名。拿不到就留 null
        for item in a["addresses"]:
            ip_to_name.setdefault(item["ip"], a["name"])
    for row in active:
        row["is_default"] = row["destination"] == "0.0.0.0" and row["netmask"] == "0.0.0.0"
        row["interface_name"] = ip_to_name.get(row["interface"])
    for row in persistent:
        row["is_default"] = row["destination"] == "0.0.0.0" and row["netmask"] == "0.0.0.0"
    defaults = [row for row in active if row["is_default"]]
    return {"ok": True, "count": len(active), "persistent_count": len(persistent),
            "default_route_count": len(defaults), "routes": active,
            "persistent_routes": persistent,
            "note": f"共 {len(active)} 条活动路由（含 {len(defaults)} 条默认路由）、"
                    f"{len(persistent)} 条持久路由"}


# ── 域名解析：socket.getaddrinfo（走系统解析器，与浏览器同一套 hosts + DNS） ──
# 错误码说明：负数是 getaddrinfo 的 EAI_*，11001+ 是 Windows 的 WSA* 老码 —— 两套都翻成人话，
# 因为「域名不存在」和「DNS 服务器不可达」对用户是两个完全不同的下一步动作。
_GAI_ERRORS = {
    -1: "解析器内部错误（EAI_BADFLAGS）",
    -2: "域名不存在或无法解析（EAI_NONAME）—— 确认拼写，或换 DNS",
    -3: "DNS 服务器暂时不可达或超时（EAI_AGAIN），稍后可重试",
    -4: "解析器返回永久性失败（EAI_FAIL），通常说明本地 hosts/DNS 配置有问题",
    -5: "该域名没有任何地址记录（EAI_NODATA）",
    -8: "地址族不支持（EAI_FAMILY）",
    11001: "找不到主机（WSAHOST_NOT_FOUND）—— 域名拼错了，或 DNS 服务器没有这条记录",
    11002: "DNS 查询暂时失败（WSATRY_AGAIN）—— DNS 服务器没响应，稍后再试",
    11003: "DNS 查询发生不可恢复的错误（WSANO_RECOVERY）",
    11004: "该域名没有对应的 IP 地址（WSANO_DATA）—— 域名存在，但没有 A/AAAA 记录",
}


@declare_primitive(
    "net.dns_resolve",
    "域名 → IP：解析一个主机名，返回它的全部 IPv4 / IPv6 地址。只读。"
    "走 socket.getaddrinfo（系统解析器，和浏览器 / curl 用的是同一套 hosts + DNS 配置），"
    "不是自己发包，所以结果就是「本机能不能解析这个域名」的答案。"
    "什么时候用：回答「这个域名解析到哪个 IP」「本机 DNS 能不能解析它」用这个；"
    "**只想知道某台主机通不通、延迟多大**用 net.ping，**想知道某个端口通不通**用 net.tcp_check"
    "（本原语不握手、不判断可达性）；排查「连不上」时按 dns_resolve → ping → tcp_check 的顺序分流："
    "本原语 ok=false 就说明问题出在解析这一步，不必再往下试。"
    "参数：host 必填（唯一必填项；带 http:// 或路径会被自动剥掉，直接传 IP 字面量也接受 ——"
    "此时原样返回、note 里说明「未走 DNS」）；family 可选 any（默认，v4/v6 都要）/ ipv4 / ipv6；"
    "limit 默认 32、上限 128（地址太多时截断，truncated=true）。"
    "返回：ok、host、count（解析到的地址总数）、returned（本次返回数）、truncated、"
    "is_literal_ip、addresses 数组（每项 ip / family / kind）、note。"
    "⚠️ 坑：① 解析失败时会区分「域名不存在」和「DNS 服务器不可达」这两类"
    "（下一步动作完全不同）；② kind=link_local（fe80::*）不是有效地址；"
    "③ 系统解析器没有超时参数，DNS 服务器无响应时这一步可能卡住数秒到十几秒 —— 这是系统的行为，"
    "本原语不做超时控制（标准库没有可中断 getaddrinfo 的办法）。",
    {"type": "object",
     "properties": {
         "host": {"type": "string",
                  "description": "要解析的主机名，如 www.baidu.com（带 http:// 或路径会被自动剥掉）"},
         "family": {"type": "string", "enum": ["any", "ipv4", "ipv6"],
                    "description": "只要某一族的地址，默认 any（两族都要）。"
                                   "（本域同名参数另写作 all / auto，含义相同：不限协议族。）"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 128,
                   "description": "最多返回多少个地址，默认 32，上限 128"},
     },
     "required": ["host"],
     "additionalProperties": False},
    block="network",
)
def net_dns_resolve(host: str, family: str = "any", limit: int = 32) -> dict:
    name = (host or "").strip()
    # 宽容一点：模型常常顺手把整条 URL 丢进来，为这种小事失败不值得
    for pre in ("http://", "https://"):
        if name.lower().startswith(pre):
            name = name[len(pre):]
    name = name.split("/")[0].split("?")[0].strip()
    if not name:
        return {"ok": False, "host": host, "addresses": [], "note": "域名不能为空"}
    fam = (family or "any").strip().lower()
    if fam not in ("any", "ipv4", "ipv6"):
        return {"ok": False, "host": name, "addresses": [],
                "note": f"family 只能是 any/ipv4/ipv6，收到 {family!r}"}
    try:
        limit = max(1, min(int(limit), 128))
    except (TypeError, ValueError):
        limit = 32
    af = {"any": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}[fam]
    try:
        infos = socket.getaddrinfo(name, None, af, socket.SOCK_STREAM)
    except socket.gaierror as e:
        code = e.args[0] if e.args else None
        return {"ok": False, "host": name, "addresses": [],
                "note": f"解析失败：{_GAI_ERRORS.get(code, f'系统解析器报错（错误码 {code}）')}"}
    except (OSError, UnicodeError) as e:
        return {"ok": False, "host": name, "addresses": [], "note": f"解析失败：{e}"}
    addrs: list[dict] = []
    seen: set[str] = set()
    for info in infos:
        af_i, _, _, _, sa = info
        if af_i == socket.AF_INET:
            ip, fam_name = sa[0], "ipv4"
        elif af_i == socket.AF_INET6:
            ip, fam_name = sa[0], "ipv6"
        else:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        addrs.append({"ip": ip, "family": fam_name, "kind": _ip_kind(ip, fam_name)})
    if not addrs:
        return {"ok": False, "host": name, "count": 0, "addresses": [],
                "note": f"{name} 没有 {fam} 地址（域名可能只配了另一族的记录）"}
    addrs.sort(key=lambda x: 0 if x["family"] == "ipv4" else 1)   # v4 排前面：多数时候要看的就是它
    page = addrs[:limit]
    literal = _is_literal_ip(name)
    note = f"{name} 解析到 {len(addrs)} 个地址"
    if len(addrs) > len(page):
        note += f"，本次返回前 {len(page)} 个（调大 limit 或收窄 family）"
    if literal:
        note += "；输入本身就是 IP 字面量，未走 DNS"
    return {"ok": True, "host": name, "count": len(addrs), "returned": len(page),
            "truncated": len(addrs) > len(page), "is_literal_ip": literal,
            "addresses": page, "note": note}


# ═══════════════════════════════════════════════════════════════════════════════
# 网络域补全（2026-09-11）—— 连通性 / 流量 / 防火墙 / 无线 / 出网
#
# 八条分两档，与上面那批只读查询共用同一条安全线：
#   · 只读六条 —— net.ping / net.tcp_check / net.io_stats / net.firewall_status /
#     net.firewall_rules / net.wifi_status：不改任何系统状态 → 不带 dry_run、不要确认
#   · 出网两条 —— net.http_get / net.download：**会主动对外通信**，download 还会落盘。
#     两道保护都上：默认 dry_run=True（只预览）+ requires_confirmation（要用户点头）
#
# 「这一域能用结构化接口的，绝不解析本地化文本」这条取向在本批继续执行：
#   · net.io_stats  → ctypes 调 iphlpapi.GetIfTable2（结构体表 + **64 位**计数器）
#   · 防火墙两条     → PowerShell 的 NetSecurity 模块（结构化对象 → JSON），
#                     不去解析 `netsh advfirewall` 的本地化文本
#   · net.tcp_check → 纯 socket，本来就没有文本
#   · ping / 无线    → 系统只给了命令行文本、没有结构化接口，退化为「**认锚点不认列名**」
#                     的宽容解析，且解析不出来时把原始输出交回给调用方（不猜）
# ═══════════════════════════════════════════════════════════════════════════════

# ── 共享小工具 ──

def _bytes_human(n) -> str | None:
    """字节数 → 人话（1.5 GB）。给模型看流量时比一长串数字直观。"""
    if n is None:
        return None
    try:
        v = float(n)
    except (TypeError, ValueError):
        return None
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024
        i += 1
    return f"{int(v)} B" if i == 0 else f"{v:.1f} {units[i]}"


def _run_cmd(args: list[str], timeout: int = 60) -> tuple[str, str | None, int]:
    """跑一条系统命令并解码输出。返回 (文本, 错误说明, 返回码)。

    stdout 与 stderr 合并 —— netsh 这类工具把错误信息写在 stdout，分开取反而会漏。
    """
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return "", f"本机没有 {args[0]} 命令", -1
    except subprocess.TimeoutExpired:
        return "", f"{args[0]} 超时（>{timeout}s）", -1
    except Exception as e:
        return "", f"调用 {args[0]} 失败：{e}", -1
    return _text(r.stdout + r.stderr), None, r.returncode


def _run_powershell(script: str, timeout: int = 120) -> tuple[str | None, str | None]:
    """跑一段 PowerShell 脚本（-Command，不需要执行策略放行脚本文件）。返回 (输出, 错误)。

    用 PowerShell 而不是解析 netsh 的理由：**NetSecurity 模块返回的是结构化对象**，
    字段名是英文、值与显示语言无关（枚举用 `.ToString()` 拿到规范名）。防火墙规则有近千条、
    中英文字段名混杂（`规则名称:` / `Rule Name:`），文本解析换台机器就废。
    """
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return None, ("本机没有 powershell.exe —— 防火墙查询走 Windows 的 NetSecurity 模块"
                      "（不解析 netsh 的本地化文本），没有 PowerShell 就查不了")
    except subprocess.TimeoutExpired:
        return None, f"PowerShell 查询超时（>{timeout}s）"
    except Exception as e:
        return None, f"调用 PowerShell 失败：{e}"
    if r.returncode != 0:
        return None, f"PowerShell 返回 {r.returncode}：{_text(r.stderr or b'')[:300]}"
    return _text(r.stdout), None


def _ps_json(script: str, timeout: int = 120) -> tuple[object, str | None]:
    """跑 PowerShell 并把输出当 JSON 解析。返回 (对象, 错误说明)。"""
    text, err = _run_powershell(script, timeout)
    if err:
        return None, err
    s = (text or "").lstrip("﻿").strip()
    if not s:
        return None, "PowerShell 没有返回任何内容"
    try:
        return json.loads(s), None
    except ValueError as e:
        return None, f"PowerShell 返回的不是合法 JSON（{e}）：{s[:200]}"


# ═══════════════════════════════════════════════════════════════════════════════
# net.ping —— 连通性与延迟（只读）
# ═══════════════════════════════════════════════════════════════════════════════

# 统计数字的标签：中英各收一份。**不能只写英文** —— 中文系统上 ping 整段输出是中文，
# 且用全角逗号（「数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，」）。
_PING_SENT_RE = re.compile(r"(?:Sent|已发送)\s*=\s*(\d+)")
_PING_RECV_RE = re.compile(r"(?:Received|已接收)\s*=\s*(\d+)")
_PING_LOST_RE = re.compile(r"(?:Lost|丢失)\s*=\s*(\d+)")
_PING_LOSS_PCT_RE = re.compile(r"\((\d+)\s*%")
_PING_RTT_RE = {
    "min": re.compile(r"(?:Minimum|最短)\s*=\s*(\d+)\s*ms", re.I),
    "max": re.compile(r"(?:Maximum|最长)\s*=\s*(\d+)\s*ms", re.I),
    "avg": re.compile(r"(?:Average|平均)\s*=\s*(\d+)\s*ms", re.I),
}
# 回复行的形状：[<>=]数字ms。中英都是这个形状（`time=24ms` / `时间=24ms` / `time<1ms`）。
_PING_LAT_RE = re.compile(r"([<=])\s*(\d+)\s*ms", re.I)
_PING_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# IPv6 要连 `::1` 这种全省略写法一起认（`(?::[0-9a-f]{0,4}){2,}` 能匹配连续两个冒号）
_PING_IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?:%\d+)?")
_PING_TARGET_RE = re.compile(r"\[([^\]]+)\]")            # 表头的 `www.x.com [1.2.3.4]`
# 「回是回了，但说的是不可达」—— 这不是「通」，得单独标出来
_PING_BAD = ("unreachable", "无法访问", "无法到达", "不可达", "一般故障", "general failure",
             "传输失败", "transmit failed")


def _ping_parse(text: str, expected: int, target: str = "") -> dict:
    """从 ping 的**本地化文本**里抽出结构化结果。

    实测（Windows 11 26200 / 中文与英文系统都验过形状）：
      · 回复行**同时含一个 IP 和一个 `<数字>ms`**；统计行（`Minimum = 0ms`）只有 ms 没有 IP，
        被这一条天然排除。**IPv6 的回复行没有 TTL**（实测 `Reply from ::1: time<1ms`），
        所以「用 ttl= 认回复行」会漏 —— 必须用「IP + 延迟」这个形状。
      · `Sent = 2` 与 `已发送 = 2` 都是「标签 = 数字」，中英各一条正则即可，与语序无关。

    两条都对不上时**不猜**：sent/received 退回「请求条数 + 数出来的回复行」，并由调用方
    把原始输出一并交出去（见 net_ping 的 raw 字段）。
    """
    replies: list[dict] = []
    bad_lines = 0
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in _PING_BAD):
            bad_lines += 1
        m = _PING_LAT_RE.search(line)
        if not m:
            continue
        ip = _PING_IPV4_RE.search(line) or _PING_IPV6_RE.search(line)
        if not ip:
            continue                       # 没有 IP → 统计行/表头，不是回复行
        op, num = m.group(1), int(m.group(2))
        # `time<1ms` 是「小于 1ms」的上界，不是精确值：系统自己的统计行也把它算作 0ms，
        # 所以这里记 0 并标记 approx（否则 rtts_ms 里的 1 会和统计行的 0 看起来互相打架），
        # 原文另存 latency_text —— 信息不丢，只是不当成精确值用。
        # `split("%")` 去掉 IPv6 的 zone（`fe80::1%12`）；`rstrip(":")` 是因为正则会把
        # 「Reply from ::1: …」结尾那个分隔冒号一起吞掉（实测），去掉它才是地址。
        ip_text = ip.group(0).split("%")[0].rstrip(":")
        replies.append({"ip": ip_text or target,
                        "latency_ms": 0 if op == "<" else num,
                        "latency_text": f"{op}{num}ms",
                        "approx": op == "<",
                        "unreachable": any(k in low for k in _PING_BAD)})
    stats: dict = {}
    for key, rx in (("sent", _PING_SENT_RE), ("received", _PING_RECV_RE), ("lost", _PING_LOST_RE)):
        m = rx.search(text)
        if m:
            stats[key] = int(m.group(1))
    m = _PING_LOSS_PCT_RE.search(text)
    if m:
        stats["loss_pct"] = float(m.group(1))

    sent = stats.get("sent", expected)
    received = stats.get("received", len(replies))
    lost = stats.get("lost", max(0, sent - received))
    loss_pct = stats.get("loss_pct", round(lost / sent * 100, 1) if sent else None)
    rtt = {}
    for key, rx in _PING_RTT_RE.items():
        m = rx.search(text)
        if m:
            rtt[key] = int(m.group(1))
    if len(rtt) < 3:
        # 统计行没解析出来（或换了语言）→ 用回复行自己算，两条路互补
        lats = [r["latency_ms"] for r in replies]
        if lats:
            rtt = {"min": min(lats), "max": max(lats), "avg": round(sum(lats) / len(lats), 1)}
    unreachable = sum(1 for r in replies if r["unreachable"])
    return {"sent": sent, "received": received, "lost": lost, "loss_pct": loss_pct,
            "rtt_ms": rtt or None, "rtts_ms": [r["latency_ms"] for r in replies],
            "reply_count": len(replies), "unreachable_replies": unreachable,
            "bad_lines": bad_lines, "approx": any(r["approx"] for r in replies),
            "stats_parsed": bool(stats), "replies": replies}


@declare_primitive(
    "net.ping",
    "测目标通不通：返回是否可达 / 延迟(最小/平均/最大) / 丢包率。只读，不改变任何系统状态。"
    "什么时候用：回答「这台机器能连上某台主机吗」「网络通不通、延迟多大」用这个；"
    "要判断**某个端口 / 某个服务**通不通用 net.tcp_check（ping 通不代表服务可用，很多主机还禁 ICMP）；"
    "本原语 ok=false 且 note 说是解析不了时，先回头用 net.dns_resolve 确认主机名；"
    "判断「本该往哪条路由走」用 net.routes。"
    "参数：host 必填（域名或 IP）；count 发几个包（默认 4，范围 1-10，发得越多结论越可信但越慢）；"
    "timeout_ms 是**每个回复等多久、单位毫秒**（默认 2000，范围 200-10000）；"
    "family 取值 auto（默认，交给系统选，通常是 IPv4）/ ipv4 / ipv6。"
    "返回：ok、reachable、host、target_ip、family、count、sent、received、lost、loss_pct、"
    "rtt_ms（min / max / avg）、rtts_ms、replies（每项 ip / latency_ms / latency_text / approx / "
    "unreachable）、unreachable_replies、bad_lines、approx、exit_code、note、raw。"
    "⚠️ **ok 的语义**：ok=true 只表示「ping 命令跑通了、拿到了系统统计」，**不代表目标可达** ——"
    "可达性看 reachable。（这与 net.tcp_check **正好相反**：tcp_check 的 ok=true 才是真的握手成功。）"
    "**reachable 的判定（三条同时满足才算通）**：① 收到了回复；② 这些回复里不全是「不可达」；"
    "③ 系统输出里**没有**「不可达 / 传输失败」类提示行（即 bad_lines=0）。"
    "第 ③ 条是 2026-09-12 补的：中文系统上「来自 1.2.3.4 的回复: 无法访问目标主机」这类行"
    "**没有 `<数字>ms`**，一条回复行都匹配不到，而统计行照样报「已接收 = 4」——"
    "只看前两条会把**不通报成通**。bad_lines 现在也在返回值里，可自行判断。"
    "⚠️ 实测坑：ping 的输出是本地化文本（中文系统上连标点都是全角），本原语只认两类语言无关锚点"
    "（回复行的「IP + 数字ms」形状、统计行的「标签 = 数字」），解析不出来时 ok 仍为 true，"
    "但会用 raw 把系统原始输出交回来 —— 宁可把原文给人看，也不猜一个可能错的数；"
    "approx=true 表示存在 `time<1ms` 这种「小于」值（本机 / 同网段常见），延迟只能算上界。"
    "注意：本原语不判断「是哪个原因不通」（防火墙丢包 / 路由不可达 / 主机没开机都表现为超时），"
    "要分流请配合 net.tcp_check / net.routes / net.dns_resolve。",
    {"type": "object",
     "properties": {
         "host": {"type": "string", "description": "目标主机名或 IP，如 www.baidu.com / 192.168.1.1"},
         "count": {"type": "integer", "minimum": 1, "maximum": 10,
                   "description": "发几个包，默认 4，范围 1-10"},
         "timeout_ms": {"type": "integer", "minimum": 200, "maximum": 10000,
                        "description": "每个回复等多久（**毫秒**，注意 net.tcp_check 的 timeout 是秒），"
                                       "默认 2000，范围 200-10000"},
         "family": {"type": "string", "enum": ["auto", "ipv4", "ipv6"],
                    "description": "强制协议族，默认 auto（交给系统选，通常是 IPv4）。"
                                   "（本域同名参数另写作 all / any，含义相同：不限协议族。）"},
     },
     "required": ["host"],
     "additionalProperties": False},
    state={"reachable": "可达"},
    block="network",
)
def net_ping(host: str, count: int = 4, timeout_ms: int = 2000,
             family: str = "auto") -> dict:
    target = (host or "").strip()
    out = {"ok": False, "host": target, "reachable": False, "target_ip": None,
           "family": (family or "auto").lower(), "count": None, "sent": 0, "received": 0,
           "lost": 0, "loss_pct": None, "rtt_ms": None, "rtts_ms": [], "replies": [],
           "unreachable_replies": 0, "bad_lines": 0, "note": "", "raw": None}
    if not target:
        out["note"] = "目标主机不能为空"
        return out
    fam = (family or "auto").strip().lower()
    if fam not in ("auto", "ipv4", "ipv6"):
        out["note"] = f"family 只能是 auto/ipv4/ipv6，收到 {family!r}"
        return out
    try:
        count = max(1, min(int(count), 10))
        timeout_ms = max(200, min(int(timeout_ms), 10000))
    except (TypeError, ValueError):
        out["note"] = "count / timeout_ms 必须是整数"
        return out
    out["count"] = count
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms)]
    if fam == "ipv4":
        cmd.append("-4")
    elif fam == "ipv6":
        cmd.append("-6")
    cmd.append(target)
    # 单条命令的最长等待 = 发包数 × 每包超时 + 余量
    text, err, rc = _run_cmd(cmd, timeout=int(count * timeout_ms / 1000) + 15)
    if err:
        out["note"] = err
        return out
    out["exit_code"] = rc
    parsed = _ping_parse(text, count, target)
    for k in ("sent", "received", "lost", "loss_pct", "rtt_ms", "rtts_ms"):
        out[k] = parsed[k]
    out["replies"] = parsed["replies"]
    out["approx"] = parsed["approx"]
    out["bad_lines"] = parsed["bad_lines"]                    # ← 这两个以前算完就丢，没进返回值
    out["unreachable_replies"] = parsed["unreachable_replies"]
    # 表头里系统把自己解析到的 IP 写在方括号里（`Pinging www.a.shifen.com [183.2.172.177]`）
    m = _PING_TARGET_RE.search(text)
    out["target_ip"] = (m.group(1).split("%")[0] if m else
                        (target if _is_literal_ip(target.split("%")[0]) else None))
    # 既没有回复也没有统计行 → 命令根本没发出去（典型：主机名解析不了）。
    # ⚠️ 这种情况要把 sent/received 清零：`_ping_parse` 在没有统计行时会退回「按请求条数估算」，
    # 那个估算只在命令真跑起来时成立；一个包都没发出去却报「发了 1 个丢了 1 个」是**假数据**。
    if not parsed["reply_count"] and not parsed["stats_parsed"]:
        out.update({"ok": False, "sent": 0, "received": 0, "lost": 0, "loss_pct": None,
                    "note": "ping 既没有回复也没有统计输出 —— 通常是主机名解析不了"
                            "（系统找不到这个名字），原始输出见 raw",
                    "raw": text.strip()[:600]})
        return out
    out["ok"] = True
    bad = parsed["unreachable_replies"]
    # ⚠️ 第三个条件是 2026-09-12 补的，堵的是一个**把「不通」报成「通」**的洞：
    # 中文系统上「来自 1.2.3.4 的回复: 无法访问目标主机」这类行**没有 `<数字>ms`**，
    # 于是一条回复行都匹配不到 → unreachable_replies 会是 0，而统计行照样报「已接收 = 4」
    # → 光看前两个条件就判成「通」了。真正抓到这件事的是 bad_lines（数「不可达 / 传输失败」
    # 类文本行）—— 它一直算得出来，却从没被读过。
    out["reachable"] = (parsed["received"] > 0 and bad < parsed["received"]
                        and parsed["bad_lines"] == 0)
    if parsed["bad_lines"]:
        # 系统自己说了「不可达 / 传输失败」—— 判定「不通」的直接证据，优先于别的迹象
        out["note"] = (f"不通：系统输出里有 {parsed['bad_lines']} 行「不可达 / 传输失败」类提示"
                       f"（统计行可能仍报「已接收」，那是收到的 ICMP 错误报文，不代表对方可达）")
        out["raw"] = text.strip()[:600]
    elif parsed["sent"] and not parsed["received"]:
        out["note"] = f"不通：发了 {parsed['sent']} 个包一个都没回（100% 丢包）——" \
                      f"对方没开机 / 被防火墙丢了 / 路由到不了，都长这样"
    elif bad >= parsed["received"] and parsed["received"]:
        out["note"] = ("收到的是「目标不可达」类回复 —— 有回应但不是真的通，"
                       "多半是路由/网关那边拦下来的")
    elif parsed["received"] < parsed["sent"]:
        out["note"] = f"部分丢包：{parsed['lost']}/{parsed['sent']} 丢失"
    else:
        out["note"] = f"通：{parsed['received']}/{parsed['sent']} 个回复"
        if parsed["rtt_ms"]:
            out["note"] += f"，平均 {parsed['rtt_ms'].get('avg')}ms"
    # 统计行没解析出来（换了语言 / 非预期格式）时把原始输出带上 —— 不猜，把原文交出去。
    # 只在「统计行缺失」时附原文：统计行解析成功、只是没收到回复（100% 丢包）的情况不需要，
    # 那种情况下 rtt 为空是**正确结果**而不是解析失败。
    if not parsed["stats_parsed"]:
        out["raw"] = text.strip()[:600]
        out["note"] += "；系统统计行未能解析，原始输出见 raw"
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# net.tcp_check —— 端口连通性（只读，但**可被滥用为端口扫描**，见 description）
# ═══════════════════════════════════════════════════════════════════════════════

@declare_primitive(
    "net.tcp_check",
    "测某个 TCP 端口能不能连上：返回是否连得通 / 握手耗时 / 连的是哪个 IP:端口。只读，"
    "只是跟目标握一次手再断开，不发任何数据、不改任何状态。"
    "什么时候用：回答「这个服务开着吗」「端口通不通（防火墙有没有放行）」用这个 —— "
    "它比 ping 更能说明问题：ping 不通不代表服务不可用（很多主机禁 ICMP），"
    "但端口连得上就一定是通的。"
    "**它是探测目标主机（通常是远端）的端口**；要查**本机**某个端口被谁占用（占用进程名）用 "
    "net.port_owner —— 本原语不会告诉你占用者是谁；域名解析不了时先用 net.dns_resolve 确认"
    "（本原语 ok=false 且 note 说解析失败，就是这一步的问题）；怀疑是路由 / 网关那边的问题"
    "（多个默认路由、走了 VPN）看 net.routes。"
    "参数：host 必填（域名或 IP）；port 必填（1-65535）；"
    "timeout 是**单次连接超时秒数**（默认 3，范围 0.2-30）——"
    "**超时设小会得到假的「不通」**（跨洋链路正常也要几百毫秒），拿不准就给 5-10 秒"
    "（注意 net.ping 的同名概念叫 timeout_ms，单位是**毫秒**，别混）；"
    "family 取值 auto（默认，两族都试）/ ipv4 / ipv6。"
    "返回：ok、host、port、reachable、connected_to（\"IP:端口\"）、latency_ms、timeout_s、"
    "attempts 数组（每项 ip / family / ok / latency_ms / error）、note。"
    "⚠️ **ok 的语义**：本原语的 ok=true 表示**握手真的成功了**（与 net.ping 正好相反 —— ping 的 "
    "ok 只表示「命令跑通了」，可达性看 reachable）。本原语里 ok 与 reachable 同真同假。"
    "域名会解析出多个地址（IPv4/IPv6），本原语**逐个试**，attempts 里能看到每个地址的结果与"
    "失败原因（拒绝连接=服务没开；超时=被防火墙丢包 / 主机不在；解析失败=域名问题）。"
    "⚠️ **本原语可能被滥用为端口扫描**：它本身只探测「一个」端口，但连续对同一主机的多个端口"
    "调用它，效果就等同于端口扫描 —— 这在多数网络的使用条款里是禁止的，也会触发对方的"
    "入侵检测。**只对你有权探测的主机使用**（自己的机器、自己的服务、已获授权的目标）。"
    "本原语不做频率限制，是否批量探测完全取决于调用方 —— 请自觉。",
    {"type": "object",
     "properties": {
         "host": {"type": "string", "description": "目标主机名或 IP"},
         "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                  "description": "TCP 端口（1-65535）"},
         "timeout": {"type": "number", "minimum": 0.2, "maximum": 30,
                     "description": "单次连接超时**秒**数，默认 3，范围 0.2-30"
                                    "（net.ping 的 timeout_ms 是毫秒，别混）"},
         "family": {"type": "string", "enum": ["auto", "ipv4", "ipv6"],
                    "description": "只试某一族地址，默认 auto（两族都试）。"
                                   "（本域同名参数另写作 all / any，含义相同：不限协议族。）"},
     },
     "required": ["host", "port"],
     "additionalProperties": False},
    block="network",
)
def net_tcp_check(host: str, port, timeout: float = 3.0, family: str = "auto") -> dict:
    target = (host or "").strip()
    out = {"ok": False, "host": target, "port": None, "reachable": False, "connected_to": None,
           "latency_ms": None, "timeout_s": None, "attempts": [], "note": ""}
    if not target:
        out["note"] = "目标主机不能为空"
        return out
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        out["note"] = f"端口不是数字：{port!r}"
        return out
    if not (0 < port_i < 65536):
        out["note"] = "端口必须在 1-65535 之间"
        return out
    out["port"] = port_i
    try:
        to = float(timeout)
    except (TypeError, ValueError):
        out["note"] = f"timeout 不是数字：{timeout!r}"
        return out
    to = max(0.2, min(to, 30.0))
    out["timeout_s"] = to
    fam = (family or "auto").strip().lower()
    if fam not in ("auto", "ipv4", "ipv6"):
        out["note"] = f"family 只能是 auto/ipv4/ipv6，收到 {family!r}"
        return out
    af = {"auto": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}[fam]
    try:
        infos = socket.getaddrinfo(target, port_i, af, socket.SOCK_STREAM)
    except socket.gaierror as e:
        code = e.args[0] if e.args else None
        out["note"] = f"域名解析失败：{_GAI_ERRORS.get(code, f'系统解析器报错（码 {code}）')}"
        return out
    except (OSError, UnicodeError) as e:
        out["note"] = f"域名解析失败：{e}"
        return out
    if not infos:
        out["note"] = f"{target} 没有可用地址"
        return out
    best = None
    for af_i, _, _, _, sa in infos:
        ip = sa[0]
        fam_name = "ipv6" if af_i == socket.AF_INET6 else "ipv4"
        item = {"ip": ip, "family": fam_name, "ok": False, "latency_ms": None, "error": None}
        s = socket.socket(af_i, socket.SOCK_STREAM)
        s.settimeout(to)
        t0 = time.perf_counter()
        try:
            s.connect(sa)
            item["ok"] = True
            item["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        except socket.timeout:
            item["error"] = (f"超时（{to}s 内没握手成功）—— 被防火墙丢包、或主机不在线；"
                             f"也可能是超时给太短")
        except ConnectionRefusedError:
            item["error"] = "连接被拒绝 —— 主机在，但这个端口没有服务在监听"
        except OSError as e:
            item["error"] = f"连接失败：{e}"
        finally:
            try:
                s.close()
            except OSError:
                pass
        out["attempts"].append(item)
        if item["ok"]:
            best = item
            break                       # 一个地址通了就算通，不必再试其余
    if best:
        out["ok"] = True
        out["reachable"] = True
        out["connected_to"] = f"{best['ip']}:{port_i}"
        out["latency_ms"] = best["latency_ms"]
        out["note"] = f"端口通：{out['connected_to']}（握手 {best['latency_ms']}ms）"
        if len(out["attempts"]) > 1:
            out["note"] += f"；按顺序试到第 {len(out['attempts'])} 个地址才通"
    else:
        out["note"] = "端口不通：" + "；".join(
            f"{a['ip']} → {a['error']}" for a in out["attempts"])
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# net.io_stats —— 每块网卡的收发流量（只读）
# ═══════════════════════════════════════════════════════════════════════════════

class _MIB_IF_ROW2(ctypes.Structure):
    """MIB_IF_ROW2（netioapi.h）—— 网卡流量计数器的结构体。

    为什么不用老一版的 GetIfTable / MIB_IFROW：那套的 dwInOctets 是 **32 位**，
    流量过了 4GB 就回绕，「一共收了多少」直接变成错数（现在的机器一天就能跑过）。
    这里要的是 GetIfTable2 的 ULONG64。布局照抄 Windows SDK，实测 sizeof = 1352 字节
    （x64），错一个字段后面全乱，所以只取到 OutQLen 为止、后面一个不多写。
    """
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", ctypes.c_ulong),
        ("InterfaceGuid", ctypes.c_ubyte * 16),
        ("Alias", ctypes.c_wchar * 257),
        ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_ulong),
        ("IfType", ctypes.c_ulong),
        ("TunnelType", ctypes.c_ulong),
        ("MediaType", ctypes.c_ulong),
        ("PhysicalMediumType", ctypes.c_ulong),
        ("AccessType", ctypes.c_ulong),
        ("DirectionType", ctypes.c_ulong),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte * 8),
        ("OperStatus", ctypes.c_ulong),
        ("AdminStatus", ctypes.c_ulong),
        ("MediaConnectState", ctypes.c_ulong),
        ("NetworkGuid", ctypes.c_ubyte * 16),
        ("ConnectionType", ctypes.c_ulong),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


class _MIB_IF_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", ctypes.c_ulong), ("Table", _MIB_IF_ROW2 * 1)]


def _if_counters() -> tuple[list[dict], str | None]:
    """读全部网卡接口的 64 位计数器（GetIfTable2）。返回 (行列表, 错误说明)。

    ⚠️ 这张表是**系统分配**的，用完必须 `FreeMibTable` 还回去 —— 不还就是内存泄漏。
    所以所有值都在 free 之前抄进 Python dict，不留任何指向该内存的引用。
    """
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")
    except (AttributeError, OSError) as e:
        return [], f"本机拿不到 iphlpapi（{e}）：net.io_stats 只能在 Windows 上跑"
    iphlpapi.GetIfTable2.restype = ctypes.c_ulong
    iphlpapi.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.POINTER(_MIB_IF_TABLE2))]
    tbl = ctypes.POINTER(_MIB_IF_TABLE2)()
    try:
        ret = iphlpapi.GetIfTable2(ctypes.byref(tbl))
    except Exception as e:
        return [], f"调用 GetIfTable2 失败：{e}"
    if ret != 0:
        return [], f"GetIfTable2 失败（错误码 {ret}）"
    out: list[dict] = []
    try:
        n = int(tbl.contents.NumEntries)
        rows = ctypes.cast(ctypes.byref(tbl.contents, _MIB_IF_TABLE2.Table.offset),
                           ctypes.POINTER(_MIB_IF_ROW2 * n)).contents
        for r in rows:
            out.append({
                "index": int(r.InterfaceIndex),
                "alias": r.Alias or "",
                "description": r.Description or "",
                "status": _OPER_STATUS.get(int(r.OperStatus), f"CODE_{int(r.OperStatus)}"),
                "mtu": None if r.Mtu == _UNKNOWN_U32 else int(r.Mtu),
                "type": _IF_TYPE_NAMES.get(int(r.IfType), str(int(r.IfType))),
                "bytes_recv": int(r.InOctets), "bytes_sent": int(r.OutOctets),
                "packets_recv": int(r.InUcastPkts) + int(r.InNUcastPkts),
                "packets_sent": int(r.OutUcastPkts) + int(r.OutNUcastPkts),
                "errors_recv": int(r.InErrors), "errors_sent": int(r.OutErrors),
                "discards_recv": int(r.InDiscards), "discards_sent": int(r.OutDiscards),
                # 下面四个**量纲不同**，名字必须说清：原名 `unicast_recv` / `multicast_recv`
                # 看着像一对，实际一个数的是**包**、一个数的是**字节**（2026-09-12 审计抓到）；
                # 而且它们造出来从没被 net_io_stats 透传出去，是纯死字段。
                "unicast_pkts_recv": int(r.InUcastPkts),
                "unicast_pkts_sent": int(r.OutUcastPkts),
                "multicast_bytes_recv": int(r.InMulticastOctets),
                "broadcast_bytes_recv": int(r.InBroadcastOctets),
                "out_queue_len": int(r.OutQLen),
            })
    finally:
        try:
            iphlpapi.FreeMibTable(tbl)          # 系统分配的表，必须还
        except Exception:
            pass
    return out, None


@declare_primitive(
    "net.io_stats",
    "每块网卡收发了多少流量、丢了多少包：按网卡给累计收发字节/包数/错误数/丢弃数与上下行队列长度。"
    "只读，读的是内核维护的计数器。"
    "什么时候用：回答「本机一共下了多少流量」「哪块网卡在跑流量」「是不是在丢包」用这个；"
    "要看网卡本身的名称 / 状态 / 类型 / 速率 / MAC 用 net.interfaces（本原语的名称与状态正是"
    "复用它的枚举，两张表按 index 对得上）；问「我的 IP / 网关 / DNS」用 net.ip_config。"
    "**只统计真实网卡**（以 net.interfaces 那套网卡枚举做基准）——"
    "实测本机 GetIfTable2 返回 48 行，其中绝大多数是 WFP/Npcap/QoS 这类**过滤驱动**"
    "（`WLAN-WFP Native MAC Layer LightWeight Filter-0000` …），它们的计数器是父网卡的**副本**，"
    "不过滤掉就会把同一份流量重复算 6 次。要看那些传 include_all=true。"
    "参数：include_all（默认 false，只报真实网卡）；sort 取值 traffic（默认，按总流量降序）/ "
    "name / index。"
    "返回：ok、count、real_count、adapters 数组（每项 index / name / description / type / status / "
    "is_real_adapter / mac / speed_mbps / bytes_recv / bytes_sent / bytes_recv_human / "
    "bytes_sent_human / packets_recv / packets_sent / unicast_pkts_recv / unicast_pkts_sent / "
    "multicast_bytes_recv / broadcast_bytes_recv / errors_recv / errors_sent / discards_recv / "
    "discards_sent / mtu / out_queue_len）、totals（bytes_recv / bytes_sent / "
    "bytes_recv_human / bytes_sent_human / adapters_counted）、note。"
    "⚠️ **四个拆分字段的量纲不同，看名字**：`*_pkts_*` 数的是**包**，`*_bytes_*` 数的是**字节** ——"
    "`unicast_pkts_recv` 是 `packets_recv` 里单播那一部分（`packets_recv` = 单播 + 非单播），"
    "`multicast_bytes_recv` / `broadcast_bytes_recv` 是 `bytes_recv` 里对应那部分。"
    "（2026-09-12 审计：这四个以前名字像一对却量纲不同，而且造出来根本没返回。）"
    "⚠️ 两个必须说清楚的边界："
    "① 计数器是**系统启动以来的累计值**，不是速率 —— 本原语无状态、不做两次采样，"
    "所以「现在下载速度多少」用不了它（那需要前后两次调用自己求差）。"
    "② 网卡一禁用 / 重连，计数器常被清零；返回的是一瞬间的快照，两次调用之间系统可能重置。"
    "sort 默认按总流量降序 —— 一般情况下第一块就是当前真正在跑流量的那块。",
    {"type": "object",
     "properties": {
         "include_all": {"type": "boolean",
                         "description": "true=连过滤驱动等非真实网卡也返回，默认 false"},
         "sort": {"type": "string", "enum": ["traffic", "name", "index"],
                  "description": "排序方式，默认 traffic（按总流量降序）"},
     },
     "required": [],
     "additionalProperties": False},
    block="network",
)
def net_io_stats(include_all: bool = False, sort: str = "traffic") -> dict:
    order = (sort or "traffic").strip().lower()
    if order not in ("traffic", "name", "index"):
        return {"ok": False, "count": 0, "adapters": [], "totals": None,
                "note": f"sort 只能是 traffic/name/index，收到 {sort!r}"}
    counters, err = _if_counters()
    if err:
        return {"ok": False, "count": 0, "adapters": [], "totals": None, "note": err}
    info, ierr = _adapters()               # 复用本文件已有的网卡枚举（拿名称/描述/状态）
    by_index = {a["index"]: a for a in info}
    rows: list[dict] = []
    for c in counters:
        meta = by_index.get(c["index"])
        if meta is None and not include_all:
            continue                       # 过滤驱动/虚拟接口：不是真实网卡，默认不报
        rows.append({
            "index": c["index"],
            "name": meta["name"] if meta else c["alias"],
            "description": meta["description"] if meta else c["description"],
            "type": meta["type"] if meta else c["type"],
            "status": meta["status"] if meta else c["status"],
            "is_real_adapter": meta is not None,
            "mac": meta["mac"] if meta else None,
            "speed_mbps": meta["speed_mbps"] if meta else None,
            "bytes_recv": c["bytes_recv"], "bytes_sent": c["bytes_sent"],
            "bytes_recv_human": _bytes_human(c["bytes_recv"]),
            "bytes_sent_human": _bytes_human(c["bytes_sent"]),
            "packets_recv": c["packets_recv"], "packets_sent": c["packets_sent"],
            "unicast_pkts_recv": c["unicast_pkts_recv"],
            "unicast_pkts_sent": c["unicast_pkts_sent"],
            "multicast_bytes_recv": c["multicast_bytes_recv"],
            "broadcast_bytes_recv": c["broadcast_bytes_recv"],
            "errors_recv": c["errors_recv"], "errors_sent": c["errors_sent"],
            "discards_recv": c["discards_recv"], "discards_sent": c["discards_sent"],
            "mtu": c["mtu"], "out_queue_len": c["out_queue_len"],
        })
    if order == "name":
        rows.sort(key=lambda x: (x["name"] or "").lower())
    elif order == "index":
        rows.sort(key=lambda x: x["index"])
    else:
        rows.sort(key=lambda x: x["bytes_recv"] + x["bytes_sent"], reverse=True)
    real = [r for r in rows if r["is_real_adapter"]]
    totals = {
        "bytes_recv": sum(r["bytes_recv"] for r in real),
        "bytes_sent": sum(r["bytes_sent"] for r in real),
        "adapters_counted": len(real),
    }
    totals["bytes_recv_human"] = _bytes_human(totals["bytes_recv"])
    totals["bytes_sent_human"] = _bytes_human(totals["bytes_sent"])
    note = (f"真实网卡 {len(real)} 块，累计收 {totals['bytes_recv_human']} / "
            f"发 {totals['bytes_sent_human']}（系统启动以来，不是速率）")
    if ierr:
        note += f"；网卡名称查询失败（{ierr}），名称用的是系统别名"
    if not include_all and len(rows) < len(counters):
        note += f"；已过滤掉 {len(counters) - len(rows)} 个过滤驱动/虚拟接口（include_all=true 可看）"
    if any(r["discards_recv"] or r["errors_recv"] for r in real):
        note += "；有网卡存在丢弃/错误计数，可能是链路质量或驱动问题"
    return {"ok": True, "count": len(rows), "real_count": len(real),
            "adapters": rows, "totals": totals, "note": note}


# ═══════════════════════════════════════════════════════════════════════════════
# 防火墙（只读）—— 走 PowerShell 的 NetSecurity 模块（结构化），不解析 netsh 的本地化文本
# ═══════════════════════════════════════════════════════════════════════════════

_FW_PROFILE_CN = {"Domain": "域", "Private": "专用", "Public": "公用"}
_FW_PROFILE_SCRIPT = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8\n"
    "@(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{"
    " n=$_.Name; e=$_.Enabled.ToString();"
    " i=$_.DefaultInboundAction.ToString(); o=$_.DefaultOutboundAction.ToString() } })"
    " | ConvertTo-Json -Depth 3 -Compress\n"
)


@declare_primitive(
    "net.firewall_status",
    "防火墙开没开：按三个配置档（域 / 专用 / 公用）返回各自的开关状态与默认出入站动作。只读。"
    "什么时候用：回答「防火墙开着吗」「哪个配置档被关了」用这个；"
    "要看**具体规则**（某程序有没有被放行、哪些入站规则被禁用了）用 net.firewall_rules ——"
    "那一条面对的是本机近千条规则、强制分页，**别拿它当「防火墙开没开」的答案**。"
    "参数：无（不接受任何参数）。"
    "返回：ok、all_enabled（三档是否全开）、profiles 数组（每项 profile / profile_cn / enabled / "
    "default_inbound / default_outbound）、disabled_profiles（被关掉的档，没有则空数组）、note。"
    "default_inbound / default_outbound 是「没有规则命中时怎么办」，值可能是 NotConfigured"
    "（表示跟随系统默认，不是「没配置所以不生效」）。"
    "Windows 会按当前网络位置（域 / 专用 / 公用）选一个配置档生效，所以**某一档关着不等于现在"
    "没防护** —— 要知道当前生效的是哪一档，配合 net.ip_config / net.wifi_status 判断网络类型。"
    "实现说明：走 PowerShell 的 NetSecurity 模块（结构化对象），不解析 `netsh advfirewall` 的"
    "本地化文本 —— 中文系统上那里连「状态」「启用」都是中文，文本解析换台机器就废。"
    "要改防火墙状态（开关/加规则）不在本原语范围内，属「会改变系统状态」，需另开原语并过确认。",
    {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    state={"all_enabled": "防火墙全开"},
    block="network",
)
def net_firewall_status() -> dict:
    data, err = _ps_json(_FW_PROFILE_SCRIPT, timeout=60)
    if err:
        return {"ok": False, "all_enabled": False, "profiles": [], "disabled_profiles": [],
                "note": err}
    rows = data if isinstance(data, list) else [data]
    profiles: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = str(r.get("n") or "")
        enabled = str(r.get("e") or "").strip().lower() == "true"
        profiles.append({"profile": name, "profile_cn": _FW_PROFILE_CN.get(name, name),
                         "enabled": enabled,
                         "default_inbound": r.get("i"), "default_outbound": r.get("o")})
    if not profiles:
        return {"ok": False, "all_enabled": False, "profiles": [], "disabled_profiles": [],
                "note": "没读到任何防火墙配置档（系统返回空）"}
    # 系统固定按 域 → 专用 → 公用 打印，但这里按名字显式排序，不依赖顺序
    rank = {"Domain": 0, "Private": 1, "Public": 2}
    profiles.sort(key=lambda x: rank.get(x["profile"], 9))
    off = [p["profile_cn"] for p in profiles if not p["enabled"]]
    all_on = not off
    note = ("三档防火墙全部开启（域 / 专用 / 公用）" if all_on
            else "⚠️ 有配置档的防火墙被关了：" + "、".join(off)
                 + " —— 该档生效时本机不设防")
    return {"ok": True, "all_enabled": all_on, "profiles": profiles,
            "disabled_profiles": off, "note": note}


def _fw_rules_script(direction: str, action: str, enabled: str, name: str,
                     offset: int, limit: int) -> str:
    """拼防火墙规则查询的 PowerShell 脚本。

    过滤尽量交给 PowerShell：`-Direction/-Action/-Enabled` 是 Get-NetFirewallRule 的原生参数，
    名字过滤用 `Where-Object` + `String.ToLower().Contains()`（String 是核心类型，
    受限语言模式下也能跑；不用 `[WildcardPattern]::Escape` 那种非核心类型的静态方法）。
    **注入防护**：name 作为 PowerShell **单引号字符串**字面量嵌入，内部的 `'` 一律翻倍 ——
    单引号串里 `$`、反引号、分号全是字面量，这是唯一安全的拼法。
    """
    args = []
    if direction == "inbound":
        args.append("-Direction Inbound")
    elif direction == "outbound":
        args.append("-Direction Outbound")
    if action == "allow":
        args.append("-Action Allow")
    elif action == "block":
        args.append("-Action Block")
    if enabled == "true":
        args.append("-Enabled True")
    elif enabled == "false":
        args.append("-Enabled False")
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8\n"
              "$sel = Get-NetFirewallRule " + " ".join(args) + "\n")
    if name:
        lit = "'" + name.replace("'", "''").lower() + "'"
        script += ("$sel = $sel | Where-Object { $_.DisplayName -and "
                   "$_.DisplayName.ToLower().Contains(" + lit + ") }\n")
    script += ("$all = @($sel)\n"
               "$page = @($all | Select-Object -Skip " + str(offset) + " -First " + str(limit) +
               " | ForEach-Object { [pscustomobject]@{ n=$_.DisplayName;"
               " d=$_.Direction.ToString(); a=$_.Action.ToString();"
               " e=$_.Enabled.ToString(); p=$_.Profile.ToString(); g=$_.Group } })\n"
               "[pscustomobject]@{ t=$all.Count; i=$page } | ConvertTo-Json -Depth 3 -Compress\n")
    return script


@declare_primitive(
    "net.firewall_rules",
    "查防火墙规则列表：按名字/方向/动作/启用状态过滤后**分页**返回。只读。"
    "什么时候用：回答「某程序有没有被防火墙放行」「哪些入站规则被禁用了」「有没有阻止类规则」"
    "用这个；**只想知道防火墙开没开**（三档开关状态、默认动作）用 net.firewall_status ——"
    "那是一条命令的事，不必在本原语的近千条规则里翻。"
    "⚠️ **本机有近千条规则（实测 981 条），绝不能一次全吐** —— 所以本原语强制分页："
    "limit 默认 50、上限 500，offset 翻页，返回里的 matched/truncated 告诉你还有多少没取。"
    "过滤参数（都可选，不传=不限）：name 是**子串**匹配（不区分大小写，如 `chrome` / `Edge`）；"
    "direction=inbound/outbound；action=allow/block；enabled=true/false。"
    "先用 name + direction 收窄，往往一次就能拿到想要的几条。"
    "返回：ok、matched（过滤后命中条数）、returned（本页条数）、offset、limit、truncated、"
    "rules 数组（每项 name / direction / action / enabled / profile / profile_list / group）、note。"
    "rules[].enabled 是**真布尔**，profile 是生效的配置档（Any 表示三档都算）。"
    "⚠️ 两个坑："
    "① 同名规则可能有多条（同一程序的不同配置档/不同分组会各建一条），要按 profile 区分；"
    "② group 常是 `@FirewallAPI.dll,-32752` 这种**字符串资源引用**，不是人话名字 ——"
    "那是系统内置规则的分组名，需要查资源才能翻译，本原语原样返回不猜。"
    "实现说明：走 PowerShell 的 NetSecurity 模块（结构化对象），不解析 `netsh advfirewall` ——"
    "那里的字段名和值在中英文系统上是不同的词（`规则名称:`/`Rule Name:`、`入站`/`In`），"
    "文本解析换台机器就废。",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "按规则名子串过滤（不区分大小写），省略=不限。如 chrome"},
         "direction": {"type": "string", "enum": ["any", "inbound", "outbound"],
                       "description": "方向，默认 any"},
         "action": {"type": "string", "enum": ["any", "allow", "block"],
                    "description": "动作，默认 any"},
         "enabled": {"type": "string", "enum": ["any", "true", "false"],
                     "description": "只看启用/禁用的规则，默认 any。⚠️ **这个参数是字符串枚举，"
                                    "不是布尔**（必须传 \"true\"/\"false\"/\"any\" 三个字符串之一）——"
                                    "本域其它布尔参数才是真布尔，别把 JSON 的 true 传进来"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                   "description": "本页最多返回条数，默认 50，上限 500"},
         "offset": {"type": "integer", "minimum": 0,
                    "description": "跳过前 N 条（翻页用），默认 0"},
     },
     "required": [],
     "additionalProperties": False},
    block="network",
)
def net_firewall_rules(name: str = "", direction: str = "any", action: str = "any",
                       enabled: str = "any", limit: int = 50, offset: int = 0) -> dict:
    d = (direction or "any").strip().lower()
    a = (action or "any").strip().lower()
    e = (enabled or "any").strip().lower()
    for val, allowed, label in ((d, ("any", "inbound", "outbound"), "direction"),
                                (a, ("any", "allow", "block"), "action"),
                                (e, ("any", "true", "false"), "enabled")):
        if val not in allowed:
            return {"ok": False, "matched": 0, "returned": 0, "rules": [],
                    "note": f"{label} 只能是 {'/'.join(allowed)}，收到 {val!r}"}
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    script = _fw_rules_script(d, a, e, (name or "").strip(), offset, limit)
    data, err = _ps_json(script, timeout=180)
    if err:
        return {"ok": False, "matched": 0, "returned": 0, "rules": [], "note": err}
    if not isinstance(data, dict):
        return {"ok": False, "matched": 0, "returned": 0, "rules": [],
                "note": f"PowerShell 返回的结构不是预期的对象：{str(data)[:200]}"}
    items = data.get("i") or []
    if isinstance(items, dict):            # ConvertTo-Json 对单元素数组会退化成对象
        items = [items]
    rules: list[dict] = []
    for r in items:
        if not isinstance(r, dict):
            continue
        prof_raw = str(r.get("p") or "")
        prof_list = [p.strip().lower() for p in prof_raw.split(",") if p.strip()]
        if prof_raw.strip().lower() == "any":
            prof_list = []
        rules.append({"name": r.get("n"), "direction": str(r.get("d") or "").lower(),
                      "action": str(r.get("a") or "").lower(),
                      "enabled": str(r.get("e") or "").lower() == "true",
                      "profile": prof_raw, "profile_list": prof_list,
                      "group": r.get("g")})
    try:
        matched = int(data.get("t") or 0)
    except (TypeError, ValueError):
        matched = len(rules)
    more = offset + len(rules) < matched
    filters = []
    if name:
        filters.append(f"名字含 {name!r}")
    if d != "any":
        filters.append(d)
    if a != "any":
        filters.append(a)
    if e != "any":
        filters.append(f"enabled={e}")
    note = (f"命中 {matched} 条" + (f"（过滤：{'，'.join(filters)}）" if filters else "（未过滤）")
            + f"，本页返回 {len(rules)} 条")
    if more:
        note += f"；还有 {matched - offset - len(rules)} 条，用 offset={offset + len(rules)} 继续取"
    else:
        note += "；已是最后一页"
    if any(str(x.get("group") or "").startswith("@") for x in rules):
        note += "；部分 group 是系统的字符串资源引用（@xxx.dll,-NNN），不是人话名字"
    return {"ok": True, "matched": matched, "returned": len(rules), "offset": offset,
            "limit": limit, "truncated": more, "rules": rules, "note": note}


# ═══════════════════════════════════════════════════════════════════════════════
# net.wifi_status —— 无线状态（只读）—— `netsh wlan`，认锚点不认列名
# ═══════════════════════════════════════════════════════════════════════════════

_PCT_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*%$")
# 标签 → 规范字段名。中英各收一份（和本文件 _STATE_ALIASES 同一套做法：认不出就不猜）。
# 注意 "加密" 同时能对上 cipher/encryption，所以只留给 encryption；cipher 用 ASCII 的 cipher + 密码。
_WLAN_LABELS: dict[str, tuple[str, ...]] = {
    "name": ("name", "名称", "名稱"),
    "interface_name": ("interface name", "接口名称", "介面名稱"),
    "description": ("description", "描述"),
    "guid": ("guid",),
    "physical_address": ("physical address", "物理地址"),
    "interface_type": ("interface type", "接口类型", "介面類型"),
    "state": ("state", "状态", "狀態"),
    "ssid": ("ssid",),
    "bssid": ("bssid", "ap bssid"),
    "band": ("band", "频带", "頻帶", "波段"),
    "channel": ("channel", "信道", "通道", "頻道", "频道"),
    "radio_type": ("radio type", "无线电类型", "無線電類型"),
    "network_type": ("network type", "网络类型", "網路類型"),
    "authentication": ("authentication", "身份验证", "身份驗證", "验证", "驗證"),
    "cipher": ("cipher", "密码", "密碼"),
    "encryption": ("encryption", "加密"),
    "profile": ("profile", "配置文件", "設定檔"),
    "rx_rate": ("receive rate (mbps)", "接收速率(mbps)", "接收速率（mbps）"),
    "tx_rate": ("transmit rate (mbps)", "传输速率(mbps)", "傳輸速率(mbps)", "发送速率(mbps)"),
    "rssi": ("rssi",),
}
_WLAN_LOOKUP = {lab: canon for canon, labs in _WLAN_LABELS.items() for lab in labs}
_WLAN_LINE_RE = re.compile(r"^(\s*)([^:]+?)\s*:\s*(.*)$")


def _wlan_field(label: str) -> tuple[str, int | None]:
    """netsh wlan 的标签 → (规范字段名, 序号)。认不出返回 ("", None)。

    两条路：
      1. **语言无关的锚点** —— SSID / BSSID / RSSI / GUID 这几个缩写在所有语言版本里原样出现，
         所以带序号的 `SSID 1` / `BSSID 2` 先剥掉尾号再查表；
      2. **多语言别名表** —— 其余字段（状态/信道/速率…）只能靠标签词，中英各收一份。
    认不出就返回空 —— 不猜（信号强度还另有一条「值带 %」的后路，见各处调用）。
    """
    lab = (label or "").strip().lower()
    idx = None
    m = re.match(r"^(.*?)\s*(\d+)$", lab)
    if m:
        lab, idx = m.group(1).strip(), int(m.group(2))
    canon = _WLAN_LOOKUP.get(lab)
    if canon is None and lab.endswith("(mbps)"):
        # 速率两行的括号里永远是 ASCII 的 Mbps（单位不翻译），拿它当锚点
        if "接收" in lab or "receive" in lab:
            canon = "rx_rate"
        elif "传输" in lab or "transmit" in lab or "发送" in lab or "上传" in lab:
            canon = "tx_rate"
    if canon is None and lab.startswith("ssid"):
        canon = "ssid"
    if canon is None and lab.startswith("bssid"):
        canon = "bssid"
    return (canon or ""), idx


def _fnum(v) -> float | None:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _inum(v) -> int | None:
    f = _fnum(v)
    return None if f is None else int(f)


def _conn_state(v: str) -> bool | None:
    """netsh 的状态值（本地化）→ 是否已连接。认不出返回 None（不猜）。

    ⚠️ 顺序要紧：`未连接` 里含 `连接`，所以「断开类」必须**先**判。
    """
    low = (v or "").strip().lower()
    if not low:
        return None
    if any(k in low for k in ("disconnected", "已断开", "已中斷", "未连接", "未連接", "已中断")):
        return False
    if "connect" in low or "连接" in low or "連線" in low:
        return True
    return None


def _signal_quality(pct) -> str | None:
    """信号百分比 → 人话档位（微软自己的分档口径）。"""
    if pct is None:
        return None
    if pct >= 80:
        return "excellent"
    if pct >= 60:
        return "good"
    if pct >= 40:
        return "fair"
    return "weak"


def _parse_wlan_interfaces(text: str) -> list[dict]:
    """`netsh wlan show interfaces` → 每个无线接口一个 dict。

    每个接口块以 `Name : xxx` 开头（其余字段都是同缩进的 key : value），所以「遇到 name
    就开新块」。信号强度不靠标签认，靠**值以 % 结尾**认 —— 这是全语言通用的锚点。
    """
    blocks: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        m = _WLAN_LINE_RE.match(raw)
        if not m:
            continue
        canon, _ = _wlan_field(m.group(2))
        val = m.group(3).strip()
        if canon == "name":
            cur = {}
            blocks.append(cur)
        if cur is None:
            continue
        if not canon:
            pm = _PCT_RE.match(val)
            if pm:
                cur["signal_pct"] = float(pm.group(1))
            continue
        if canon == "ssid":
            cur["ssid"] = val
        elif canon == "bssid":
            cur["bssid"] = val.upper()
        elif canon == "physical_address":
            cur["mac"] = val
        elif canon == "state":
            cur["state"] = val
            cur["state_connected"] = _conn_state(val)
        elif canon in ("channel", "rssi"):
            cur["channel" if canon == "channel" else "rssi_dbm"] = _inum(val)
        elif canon in ("rx_rate", "tx_rate"):
            cur["rx_rate_mbps" if canon == "rx_rate" else "tx_rate_mbps"] = _fnum(val)
        else:
            cur[canon] = val
    for b in blocks:
        if b.get("state_connected") is None:
            # 状态词认不出来时的后路：SSID 有值 = 连上了（SSID 只在下发关联后才有）
            b["state_connected"] = bool(b.get("ssid"))
        b["connected"] = bool(b.get("state_connected"))
        b["signal_quality"] = _signal_quality(b.get("signal_pct"))
    return blocks


def _parse_wlan_networks(text: str) -> list[dict]:
    """`netsh wlan show networks mode=bssid` → 附近网络列表。

    结构靠**顺序 + 块头**判定（顺序由 netsh 固定，实测与语言无关）：
      `SSID 1 : x` 开一个网络块 → `Network type / Authentication / Encryption`（网络级）
      → `BSSID 1 : mac` 开一个 AP 子块 → `Signal(%) / Radio type / Band / Channel`（AP 级）。
    所以判据是「当前有没有进入 BSSID 子块」：没有就是网络级，有就是 AP 级。
    """
    nets: list[dict] = []
    cur_net: dict | None = None
    cur_bss: dict | None = None
    for raw in text.splitlines():
        m = _WLAN_LINE_RE.match(raw)
        if not m:
            continue
        canon, _ = _wlan_field(m.group(2))
        val = m.group(3).strip()
        if canon == "ssid":
            cur_net = {"ssid": val, "bssids": []}
            nets.append(cur_net)
            cur_bss = None
            continue
        if cur_net is None:
            continue
        if canon == "bssid":
            cur_bss = {"bssid": val.upper()}
            cur_net["bssids"].append(cur_bss)
            continue
        target = cur_bss if cur_bss is not None else cur_net
        if not canon:
            pm = _PCT_RE.match(val)
            if pm:
                target["signal_pct"] = float(pm.group(1))
            continue
        if canon in ("channel", "rssi"):
            target["channel" if canon == "channel" else "rssi_dbm"] = _inum(val)
        elif canon in ("rx_rate", "tx_rate"):
            continue                      # 附近网络列表里的 rates 是「基础速率」清单，不是链路速率
        else:
            target[canon] = val
    for n in nets:
        sigs = [b.get("signal_pct") for b in n["bssids"] if b.get("signal_pct") is not None]
        n["signal_pct"] = max(sigs) if sigs else n.get("signal_pct")
        n["signal_quality"] = _signal_quality(n.get("signal_pct"))
        n["bssid_count"] = len(n["bssids"])
    return nets


@declare_primitive(
    "net.wifi_status",
    "无线状态：当前连的是哪个 WiFi、信号多强（可选顺带列出附近有哪些网络）。只读。"
    "什么时候用：回答「连着哪个 WiFi」「信号好不好」「附近有哪些网络」用这个。"
    "要判断**当前网络位置对应的防火墙防护**（域 / 专用 / 公用哪一档生效、开没开）用 "
    "net.firewall_status，本原语只描述无线链路本身、不管防火墙；"
    "看有线网卡 / IP / 网关 / DNS 用 net.interfaces / net.ip_config。"
    "参数：include_networks（默认 false）；limit 仅在 include_networks=true 时有意义。"
    "返回：ok、connected（有没有连上）、ssid、signal_pct、interface（当前那块无线网卡的详情）、"
    "interfaces（全部无线接口）、network_count、networks（含 networks[].bssids）、note、raw。"
    "interface 详情里的字段：ssid / bssid / band(2.4/5/6 GHz) / channel /"
    "radio_type(802.11ac 等) / authentication / cipher / rx_rate_mbps / tx_rate_mbps /"
    "signal_pct / signal_quality(excellent|good|fair|weak) / rssi_dbm / connected / state。"
    "include_networks=true 会再跑一次扫描（`netsh wlan show networks mode=bssid`），"
    "**这次扫描要 1-4 秒**、且会短暂占用无线网卡，所以默认关闭；打开后用 limit 限制返回条数"
    "（默认 20，按信号从强到弱排序）。"
    "⚠️ 两个边界："
    "① 只在有无线网卡的机器上有意义，台式机/无线禁用时返回 ok=false + 说明；"
    "② 标签是本地化的（中文系统上 `状态`/`信道`/`接收速率(Mbps)`），本原语靠"
    "「SSID/BSSID 这类不翻译的缩写 + 值带 % 的信号行 + 中英别名表」三级锚点认字段，"
    "认不出的字段留空而不是猜一个 —— 真要看原文，ok=false 时会把系统原始输出带在 raw 里。"
    "要改无线状态（连/断某个网络）不在本原语范围内。",
    {"type": "object",
     "properties": {
         "include_networks": {"type": "boolean",
                              "description": "true=顺带扫描并列出附近网络（慢 1-4 秒），默认 false"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100,
                   "description": "附近网络最多返回几个，默认 20，上限 100"},
     },
     "required": [],
     "additionalProperties": False},
    state={"ssid": "当前 WiFi", "signal_pct": "信号%"},
    block="network",
)
def net_wifi_status(include_networks: bool = False, limit: int = 20) -> dict:
    out = {"ok": False, "connected": False, "ssid": None, "signal_pct": None,
           "interface": None, "interfaces": [], "networks": None, "note": "", "raw": None}
    try:
        limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        limit = 20
    text, err, rc = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=30)
    if err:
        out["note"] = err
        return out
    ifaces = _parse_wlan_interfaces(text)
    if not ifaces:
        out["note"] = ("没读到无线接口 —— 本机可能没有无线网卡、无线被禁用，"
                       "或「无线自动配置服务(wlansvc)」没在运行；系统原始输出见 raw")
        out["raw"] = (text or "").strip()[:600]
        if rc:
            out["note"] += f"（netsh 返回 {rc}）"
        return out
    out["ok"] = True
    out["interfaces"] = ifaces
    live = next((i for i in ifaces if i.get("connected")), ifaces[0])
    out["interface"] = live
    out["connected"] = bool(live.get("connected"))
    out["ssid"] = live.get("ssid")
    out["signal_pct"] = live.get("signal_pct")
    if out["connected"]:
        out["note"] = (f"已连上 {live.get('ssid') or '(SSID 未知)'}"
                       + (f"，信号 {live['signal_pct']}%（{live['signal_quality']}）"
                          if live.get("signal_pct") is not None else "，信号强度未读到")
                       + (f"，{live['band']} 信道 {live['channel']}" if live.get("band") else ""))
    else:
        out["note"] = f"无线接口 {live.get('name') or ''} 当前未连接任何网络"
    if not include_networks:
        return out
    text2, err2, _ = _run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=60)
    if err2:
        out["note"] += f"；附近网络扫描失败：{err2}"
        out["networks"] = []
        return out
    nets = _parse_wlan_networks(text2)
    if not nets:
        out["note"] += "；附近网络一个都没扫到（扫描结果格式与预期不符或环境无信号）"
        out["raw"] = (text2 or "").strip()[:600]
        out["networks"] = []
        return out
    nets.sort(key=lambda x: (x.get("signal_pct") is None, -(x.get("signal_pct") or 0)))
    out["network_count"] = len(nets)
    out["networks"] = nets[:limit]
    out["note"] += (f"；附近可见 {len(nets)} 个网络，返回信号最强的 {len(out['networks'])} 个")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# 出网两条（net.http_get / net.download）—— 本域安全增量最大的一档
#
# 为什么这两条要**两道保护都上**（默认 dry_run=True + requires_confirmation）：
#   · 它们能把本机数据发到任意外部地址（数据外泄）
#   · download 还能把外部的东西写进本地磁盘（落地恶意文件 / 覆盖有用文件）
# 只读原语那套「无副作用所以免检」在这里完全不成立，所以：
#   默认只预览 → 调用方要有意识；真执行要用户点头 → 模型绕不过。
# ═══════════════════════════════════════════════════════════════════════════════

_UA = "IntentOS/1.0 (net.http_get)"
_TEXT_CT = ("text/", "application/json", "application/xml", "application/javascript",
            "application/x-javascript", "application/x-yaml", "application/ld+json",
            "application/problem+json", "application/x-www-form-urlencoded",
            "image/svg+xml")
_NET_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def _check_url(url: str) -> tuple[str, str | None]:
    """只放行 http / https —— 挡掉 file://（读本地文件）、ftp:// 等其它 scheme。

    `urllib` 认得一堆 scheme（`file:` 能直接读本机文件），不挡就等于给了一条绕过
    文件域全部安全判定的暗道。这条是硬拒，不是提示。
    """
    u = (url or "").strip().strip('"')
    if not u:
        return "", "url 不能为空"
    low = u.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return u, None
    scheme = u.split("://")[0] if "://" in u else "(无 scheme)"
    return u, (f"只支持 http / https，收到 {scheme}:// ——"
               f"其它协议（file: 读本地文件 / ftp: 等）一律拒绝，"
               f"本地文件请用文件域的原语")


def _decode_body(raw: bytes, ctype: str) -> tuple[str | None, str | None]:
    """响应体 → (文本, None) 或 (None, base64)。

    是不是文本按 Content-Type 判断（`text/*`、json、xml…）；是文本再按 utf-8 → gbk 试解码，
    都不行就退回 base64 —— 二进制内容硬塞进 JSON 字符串只会得到一堆乱码。
    """
    ct = (ctype or "").split(";")[0].strip().lower()
    textual = (not ct) or any(ct.startswith(p) for p in _TEXT_CT) \
        or ct.endswith("+json") or ct.endswith("+xml")
    if not raw:
        return None, None                   # 空响应体：两个字段都给 null，别给个空 base64
    if textual:
        for enc in ("utf-8", "gbk"):
            try:
                return raw.decode(enc), None
            except UnicodeDecodeError:
                continue
    return None, base64.b64encode(raw).decode("ascii")


def _open_url(req, timeout: float, follow_redirects: bool = True):
    """发请求。follow_redirects=False 时用自定义 opener 把 3xx 变成异常抛出来。

    不用全局 `urllib.request.urlopen` —— 它永远跟随重定向，而「跟随到哪去了」本身
    就是调用方需要知道的信息（跳转后的域名可能完全不是你以为的那个）。
    """
    if follow_redirects:
        return urllib.request.urlopen(req, timeout=timeout)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, rq, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(
                rq.full_url, code, f"重定向到 {newurl}（follow_redirects=False 已拦下）",
                headers, fp)

    opener = urllib.request.build_opener(_NoRedirect)
    return opener.open(req, timeout=timeout)


@declare_primitive(
    "net.http_get",
    "发一个 HTTP 请求并取回响应（方法/请求头/请求体/超时/大小上限都可控）。"
    "⚠️ **本原语会主动出网**：请求会真的发到 url 指向的外部服务器，请求头和请求体里的"
    "一切内容都会离开本机 —— **别把密钥、口令、本机路径、用户隐私塞进 headers 或 body**，"
    "除非你确认目标可信。因此它**两道保护都上**：预览时**不发任何请求**，"
    "真发要过用户确认（requires_confirmation）—— 模型绕不过。"
    "回答「这个接口返回什么」「这个网页有没有 200」「服务活着吗」用这个；"
    "要把拿到的东西**落到本地文件**用 net.download（它带大小上限、断点续传、原子落盘、系统禁区"
    "硬拒），本原语只把响应体读进上下文、不写盘。"
    "返回：ok、dry_run、status / reason / final_url（跟随重定向后的真实地址）/ headers / "
    "content_type / body（文本）或 body_base64（二进制）/ bytes_read / truncated / elapsed_ms / "
    "note；dry_run=true 时不发请求，返回 planned（method / url / header_names / body_bytes / "
    "timeout_s / max_bytes）。"
    "4xx/5xx 也算成功拿到响应（ok=true，status 就是 404/500）—— 只有连不上、超时、DNS 失败"
    "才是 ok=false。"
    "参数：method 支持 GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS；body 传字符串（按 utf-8 编码，"
    "没给 Content-Type 时默认 text/plain; charset=utf-8）；max_bytes 限制读取的响应体大小"
    "（默认 256KB，上限 5MB，**超了就截断**并在 truncated=true 里说明）—— 不设上限的话"
    "随便一个下载链接就能把上下文撑爆。"
    "⚠️ 边界：① 只支持 http/https（file:// 等一律拒绝）；② 会自动解 gzip 响应；"
    "③ 同名响应头（如多个 Set-Cookie）在 headers 里会被压成一个 —— 需要完整的用 "
    "escape 或专门的 HTTP 客户端；④ 本原语不限制目标（含内网/局域网地址），"
    "只对你有权访问的地址使用。",
    {"type": "object",
     "properties": {
         "url": {"type": "string", "description": "完整 URL，必须以 http:// 或 https:// 开头"},
         "method": {"type": "string",
                    "enum": list(_NET_METHODS), "description": "HTTP 方法，默认 GET"},
         "headers": {"type": "object", "additionalProperties": {"type": "string"},
                     "description": "请求头（键值都是字符串），可选"},
         "body": {"type": "string", "description": "请求体字符串（utf-8 编码），可选"},
         "timeout": {"type": "number", "description": "超时秒数，默认 15，范围 1-120"},
         "max_bytes": {"type": "integer",
                       "description": "响应体读取上限（字节），默认 262144（256KB），上限 5242880（5MB）"},
         "follow_redirects": {"type": "boolean",
                              "description": "是否跟随 3xx 重定向，默认 True"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不发请求（默认）；False=真发（还需用户确认）"},
     },
     "required": ["url"],
     "additionalProperties": False},
    policy={"requires_confirmation": True},
    state={"status": "HTTP 状态"},
    block="network",
)
def net_http_get(url: str, method: str = "GET", headers: dict | None = None,
                 body: str | None = None, timeout: float = 15.0,
                 max_bytes: int = 262144, follow_redirects: bool = True,
                 dry_run: bool = True) -> dict:
    out = {"ok": False, "dry_run": bool(dry_run), "status": None, "reason": None,
           "url": url, "final_url": None, "headers": None, "content_type": None,
           "body": None, "body_base64": None, "bytes_read": 0, "truncated": False,
           "elapsed_ms": None, "note": ""}
    target, uerr = _check_url(url)
    if uerr:
        out["note"] = uerr
        return out
    out["url"] = target
    meth = (method or "GET").strip().upper()
    if meth not in _NET_METHODS:
        out["note"] = f"method 只能是 {'/'.join(_NET_METHODS)}，收到 {method!r}"
        return out
    try:
        to = max(1.0, min(float(timeout), 120.0))
    except (TypeError, ValueError):
        out["note"] = f"timeout 不是数字：{timeout!r}"
        return out
    try:
        cap = max(1, min(int(max_bytes), 5 * 1024 * 1024))
    except (TypeError, ValueError):
        cap = 262144
    hdrs = {}
    for k, v in (headers or {}).items():
        hdrs[str(k)] = str(v)
    req_body = body.encode("utf-8") if isinstance(body, str) else (body or None)
    # ⚠️ 安全铁律：dry_run 默认 True —— 预览阶段**一个字节都不出网**
    if dry_run:
        out["note"] = (f"只读预览：未发送任何请求。真执行会向 {target} 发 {meth}"
                       f"，请求头 {len(hdrs)} 个、请求体 {len(req_body) if req_body else 0} 字节，"
                       f"最多读回 {cap} 字节 —— 需显式传 dry_run=False 并过用户确认")
        out["planned"] = {"method": meth, "url": target,
                          "header_names": sorted(hdrs.keys()),
                          "body_bytes": len(req_body) if req_body else 0,
                          "timeout_s": to, "max_bytes": cap}
        return out
    if req_body is not None and not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "text/plain; charset=utf-8"
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = _UA
    req = urllib.request.Request(target, data=req_body, headers=hdrs, method=meth)
    t0 = time.perf_counter()
    resp = None
    try:
        resp = _open_url(req, to, bool(follow_redirects))
        ctype = resp.headers.get("Content-Type")
        status = int(getattr(resp, "status", 0) or resp.getcode())
        raw = b"" if meth == "HEAD" else resp.read(cap + 1)
        if len(raw) > cap:
            raw, out["truncated"] = raw[:cap], True
        cenc = (resp.headers.get("Content-Encoding") or "").lower()
        if "gzip" in cenc and raw:
            try:
                raw = gzip.decompress(raw)
                out["truncated"] = False        # 解压后是按原始长度截的，重算一遍
                if len(raw) > cap:
                    raw, out["truncated"] = raw[:cap], True
            except OSError:
                pass                            # 截断过的 gzip 解不开，保持原样（下面会走 base64）
        out["status"] = status
        out["reason"] = getattr(resp, "reason", None)
        out["final_url"] = resp.geturl()
        out["headers"] = {k: v for k, v in resp.headers.items()}
        out["content_type"] = ctype
        out["bytes_read"] = len(raw)
        text, b64 = _decode_body(raw, ctype or "")
        out["body"], out["body_base64"] = text, b64
        out["ok"] = True
        out["note"] = (f"{meth} {target} → {status} {out['reason'] or ''}"
                       f"，读回 {len(raw)} 字节")
        if out["final_url"] and out["final_url"] != target:
            out["note"] += f"（重定向到 {out['final_url']}）"
        if out["truncated"]:
            out["note"] += f"；响应体超过 {cap} 字节已截断（调大 max_bytes 取全）"
        if b64:
            out["note"] += "；非文本响应，body_base64 是原始字节的 base64"
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也走 HTTPRedirectHandler 的拒绝路径（follow_redirects=False 时）——
        # 只要拿到了状态码就算「成功完成了一次 HTTP 交换」，不当传输错误处理
        try:
            raw = e.read(cap + 1)
        except Exception:
            raw = b""
        if len(raw) > cap:
            raw, out["truncated"] = raw[:cap], True
        ctype = (e.headers.get("Content-Type") if e.headers else None)
        out.update({"ok": True, "status": int(getattr(e, "code", 0) or 0),
                    "reason": getattr(e, "reason", None),
                    "final_url": getattr(e, "url", None) or target,
                    "headers": {k: v for k, v in (e.headers.items() if e.headers else [])},
                    "content_type": ctype, "bytes_read": len(raw)})
        text, b64 = _decode_body(raw, ctype or "")
        out["body"], out["body_base64"] = text, b64
        out["note"] = (f"{meth} {target} → HTTP {out['status']} {out['reason'] or ''}"
                       f"（拿到了响应，属正常结果）")
    except urllib.error.URLError as e:
        out["note"] = f"请求失败：{e.reason}（DNS 解析不了 / 连不上 / TLS 失败 / 超时都可能长这样）"
    except (socket.timeout, TimeoutError):
        out["note"] = f"请求超时（>{to}s）"
    except (OSError, ValueError) as e:
        out["note"] = f"请求失败：{e}"
    finally:
        out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    return out


# ── 下载（出网 + 落盘）──

_NET_SYSTEM_ROOTS = [os.environ.get("SystemRoot") or r"C:\Windows",
                     os.environ.get("ProgramFiles") or r"C:\Program Files",
                     os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
                     os.environ.get("ProgramData") or r"C:\ProgramData"]


def _download_target(path: str) -> tuple[str, str | None]:
    """下载落点的体检：返回 (规范化绝对路径, 中文拒绝理由)。

    只拦**系统禁区**（盘根 + Windows / Program Files / ProgramData）——
    往那儿写文件是「覆盖系统组件」级别的破坏。另外「父目录必须已存在」：
    本原语不自动建目录（自动建目录 = 帮调用方把文件铺到它没确认过的位置上）。
    ⚠️ 这里只做 `normpath + abspath`，**不解析符号链接**：真正的加固应建立在
    链接解析之后的真实路径上（fs 域那套做法），本原语按「不自动建目录 + 默认不覆盖 + 要确认」
    来兜底。要写系统目录请用文件域的原语（那里有完整判定）。
    """
    raw = (path or "").strip().strip('"')
    if not raw:
        return "", "目标路径不能为空"
    target = os.path.normpath(os.path.abspath(os.path.expanduser(raw)))
    if len(target) <= 3 and target[1:2] == ":":                 # `D:\` 这种盘根
        return target, "不允许下载到盘根目录"
    low = os.path.normcase(target)
    for r in _NET_SYSTEM_ROOTS:
        rn = os.path.normcase(os.path.normpath(r))
        if low == rn or low.startswith(rn + os.sep):
            return target, f"系统目录（Windows / Program Files / ProgramData）不允许写入：{r}"
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        return target, f"目标目录不存在：{parent}（本原语不自动建目录，请先建好）"
    return target, None


@declare_primitive(
    "net.download",
    "从网上下载文件到本地磁盘（带大小上限、断点续传、原子落盘）。"
    "⚠️ **本原语会主动出网，还会往本地写文件** —— 是本域风险最高的原语（数据外泄 + 落地文件"
    "两条路都占）。两道保护都上：预览时**不联网、不写任何文件**（**唯一例外见下面的 probe**），"
    "真下载要过用户确认（requires_confirmation）—— 模型绕不过。"
    "回答「把这个文件下到某处」用这个。"
    "**只想看一眼内容、不落盘请用 net.http_get**（那条把响应读进上下文、写不了文件；本条是"
    "「把远端的东西变成本地文件」，会写盘所以更重）。"
    "关键设计："
    "① **写临时文件再改名** —— 先写 `目标路径.part`，下完才 `os.replace` 成正式名字；"
    "中途失败/被打断时**正式文件根本不存在**，不会留一个看起来正常其实半截的文件（"
    "半截的安装包/压缩包最坑人）。"
    "② **断点续传** —— 已经存在 `.part` 且服务器支持 Range（返回 206）时，从已有字节数接着下，"
    "返回里的 resumed_from_bytes 告诉你这次续了多少；服务器不支持就从头来（会被记在 note 里）。"
    "③ **大小上限** —— max_bytes 默认 100MB、上限 1GB，**边下边查**：超过上限立即中止、"
    "保留 .part 供下次续传，并明确报 limit_exceeded。不设上限的话，一条恶意链接就能把盘塞满。"
    "④ **默认不覆盖** —— 目标已存在就拒绝，要覆盖必须 overwrite=true。"
    "⑤ **系统禁区硬拒** —— 盘根 / Windows / Program Files / ProgramData 一律不许写；"
    "父目录必须已存在（不自动建目录）。"
    "参数：probe=true 会在预览阶段先发一个 HEAD 探一下（响应大小/类型/是否支持续传）——"
    "⚠️ **这一步已经出网**（会把请求头原样送到目标服务器），所以它**不受「预览免确认」保护**："
    "只要 probe=true，**即使 dry_run=True 也照样要过用户确认**。默认关闭；"
    "sha256=true 时下完算校验值（大文件会多花一点时间）。"
    "失败时返回 ok=false + part_file + part_bytes，这些就是「断点信息」——"
    "下次调用会从那里继续。",
    {"type": "object",
     "properties": {
         "url": {"type": "string", "description": "下载地址，必须以 http:// 或 https:// 开头"},
         "path": {"type": "string",
                  "description": "落盘的完整本地路径（含文件名），父目录必须已存在"},
         "overwrite": {"type": "boolean", "description": "目标已存在时是否覆盖，默认 False"},
         "max_bytes": {"type": "integer",
                       "description": "大小上限（字节），默认 104857600（100MB），上限 1073741824（1GB）"},
         "timeout": {"type": "number", "description": "网络超时秒数，默认 30，范围 1-300"},
         "resume": {"type": "boolean",
                    "description": "存在 .part 时是否尝试续传，默认 True"},
         "probe": {"type": "boolean",
                   "description": "true=预览阶段先发 HEAD 探测（**会真出网**，因此"
                                  "**不再免确认**：即使 dry_run=True 也要过用户确认），默认 False"},
         "sha256": {"type": "boolean", "description": "true=下完算 sha256，默认 False"},
         "headers": {"type": "object", "additionalProperties": {"type": "string"},
                     "description": "额外请求头，可选"},
         "dry_run": {"type": "boolean",
                     "description": "True=只预览不联网不写盘（默认）；False=真下载（还需用户确认）"},
     },
     "required": ["url", "path"],
     "additionalProperties": False},
    policy={"requires_confirmation": True, "preview_exempt_args": ["probe"]},
    state={"bytes_written": "已下载字节"},
    block="network",
)
def net_download(url: str, path: str, overwrite: bool = False, max_bytes: int = 104857600,
                 timeout: float = 30.0, resume: bool = True, probe: bool = False,
                 sha256: bool = False, headers: dict | None = None,
                 dry_run: bool = True) -> dict:
    out = {"ok": False, "dry_run": bool(dry_run), "url": url, "path": None, "final_url": None,
           "bytes_written": 0, "total_bytes": None, "resumed_from_bytes": 0, "part_file": None,
           "part_bytes": 0, "limit_exceeded": False, "content_type": None, "sha256": None,
           "probe": None, "elapsed_ms": None, "note": ""}
    target_url, uerr = _check_url(url)
    if uerr:
        out["note"] = uerr
        return out
    out["url"] = target_url
    target, perr = _download_target(path)
    out["path"] = target
    if perr:
        out["note"] = perr
        return out
    try:
        cap = max(1, min(int(max_bytes), 1024 * 1024 * 1024))
    except (TypeError, ValueError):
        cap = 104857600
    try:
        to = max(1.0, min(float(timeout), 300.0))
    except (TypeError, ValueError):
        to = 30.0
    part = target + ".part"
    out["part_file"] = part
    exists = os.path.exists(target)
    part_size = os.path.getsize(part) if os.path.exists(part) else 0
    out["part_bytes"] = part_size
    if exists and not overwrite and not dry_run:
        out["note"] = (f"目标已存在，拒绝覆盖：{target}（确认要覆盖请传 overwrite=true）")
        return out
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = _UA
    out["planned"] = {"url": target_url, "path": target, "part_file": part,
                      "max_bytes": cap, "timeout_s": to,
                      "target_exists": exists, "part_bytes": part_size,
                      "will_resume": bool(resume and part_size)}

    # 预览阶段默认**不联网**（probe=true 才发 HEAD —— 那一步已经出网了，得说清楚）
    if dry_run:
        bits = [f"只读预览：未联网、未写任何文件。真执行会下载 {target_url} 到 {target}"]
        if exists:
            bits.append("目标已存在，覆盖需 overwrite=true" if not overwrite
                        else "目标已存在，会被覆盖（overwrite=true）")
        if part_size and resume:
            bits.append(f"检测到未完成的 .part（{part_size} 字节），会尝试从断点续传")
        bits.append(f"大小上限 {_bytes_human(cap)}，超限立即中止")
        out["note"] = "；".join(bits)
        if probe:
            info, perr2 = _head_probe(target_url, hdrs, to, cap)
            out["probe"] = info
            out["note"] += ("；已完成 HEAD 探测（**这一步已经出网**）：" + (perr2 or "见 probe"))
        return out

    t0 = time.perf_counter()
    resp = None
    written = 0
    try:
        start = part_size if (resume and part_size) else 0
        if start:
            hdrs["Range"] = f"bytes={start}-"
        req = urllib.request.Request(target_url, headers=hdrs, method="GET")
        resp = _open_url(req, to, follow_redirects=True)
        status = int(getattr(resp, "status", 200) or 200)
        # 跟随重定向后**实际**落在哪个地址 —— 跳转后的域名可能完全不是你以为的那个，
        # 调用方需要知道。此前这个字段初始化成 None 后再没被赋值，于是下面那句
        # 「（重定向到 …）」永远不成立、是死代码（2026-09-12 审计抓到）。
        try:
            out["final_url"] = resp.geturl() or target_url
        except Exception:
            out["final_url"] = target_url
        if start and status != 206:
            # 服务器不认 Range（回了 200 = 全量）→ 老老实实从头写，并说清楚
            start = 0
            out["note"] = "服务器不支持断点续传（Range 请求回了 200），已从头下载；"
        ctype = resp.headers.get("Content-Type")
        clen = resp.headers.get("Content-Length")
        total = None
        if clen and str(clen).isdigit():
            total = int(clen) + start
        out["total_bytes"] = total
        out["content_type"] = ctype
        if total is not None and total > cap:
            out["limit_exceeded"] = True
            out["note"] = (f"拒绝下载：文件大小 {_bytes_human(total)} 超过上限 "
                           f"{_bytes_human(cap)}（调大 max_bytes 或换个小文件）")
            return out
        out["resumed_from_bytes"] = start
        mode = "ab" if start else "wb"
        h = hashlib.sha256() if sha256 else None
        with open(part, mode) as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if start + written > cap:
                    # 这一块还没落盘（写之前就拦下了）——「已落盘」要按不含它的量算，
                    # 否则报出来的数字和磁盘上的实际大小对不上
                    kept = start + written - len(chunk)
                    out["limit_exceeded"] = True
                    out["bytes_written"] = kept
                    out["part_bytes"] = kept
                    out["note"] = (f"下载中止：本次已落盘 {_bytes_human(kept)}，"
                                   f"再写下一个数据块就会超过大小上限 {_bytes_human(cap)}，"
                                   f"为不越界提前停下。半截文件保留在 .part（断点信息）——"
                                   f"下次调用会从 {_bytes_human(kept)} 处续传，或调大 max_bytes")
                    return out
                f.write(chunk)
                if h is not None:
                    h.update(chunk)
        if h is not None:
            out["sha256"] = h.hexdigest()
        os.replace(part, target)             # 原子改名：到这一步正式文件才出现
        out["ok"] = True
        out["bytes_written"] = written
        out["part_bytes"] = 0
        out["note"] = ((out["note"] if out["note"] else "")
                       + f"已下载 {_bytes_human(written)} 到 {target}"
                       + (f"（续传自 {_bytes_human(start)}）" if start else "")
                       + (f"，总大小 {_bytes_human(total)}" if total else "，服务器未给总大小"))
        if out["final_url"] and out["final_url"] != target_url:
            out["note"] += f"（重定向到 {out['final_url']}）"
    except urllib.error.HTTPError as e:
        out["note"] = f"服务器返回 HTTP {getattr(e, 'code', '?')} {getattr(e, 'reason', '')}"
        out["part_bytes"] = os.path.getsize(part) if os.path.exists(part) else 0
    except urllib.error.URLError as e:
        out["note"] = f"下载失败：{e.reason}（DNS/连接/TLS/超时都可能长这样）"
        out["part_bytes"] = os.path.getsize(part) if os.path.exists(part) else 0
    except (socket.timeout, TimeoutError):
        out["note"] = f"下载超时（>{to}s）"
        out["part_bytes"] = os.path.getsize(part) if os.path.exists(part) else 0
    except (OSError, ValueError) as e:
        out["note"] = f"下载失败：{e}"
        out["part_bytes"] = os.path.getsize(part) if os.path.exists(part) else 0
    finally:
        out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    if not out["ok"] and out["part_bytes"]:
        out["note"] += (f"；已下 {_bytes_human(out['part_bytes'])} 保留在 {part}，"
                        f"下次调用会从这里续传（断点信息）")
    return out


def _head_probe(url: str, hdrs: dict, timeout: float, cap: int) -> tuple[dict, str | None]:
    """发一个 HEAD 探测：大小 / 类型 / 是否支持断点续传。返回 (信息, 错误说明)。

    ⚠️ 这一步**已经出网**（会把请求头送到目标服务器），所以只有显式传 probe=true 才做。
    """
    info = {"status": None, "content_length": None, "content_type": None,
            "accept_ranges": None, "final_url": None, "size_human": None,
            "exceeds_limit": None, "resumable": None}
    try:
        req = urllib.request.Request(url, headers=hdrs, method="HEAD")
        with _open_url(req, timeout, follow_redirects=True) as resp:
            clen = resp.headers.get("Content-Length")
            ar = resp.headers.get("Accept-Ranges")
            info.update({"status": int(getattr(resp, "status", 0) or 0),
                         "content_length": int(clen) if clen and str(clen).isdigit() else None,
                         "content_type": resp.headers.get("Content-Type"),
                         "accept_ranges": ar, "final_url": resp.geturl()})
    except urllib.error.HTTPError as e:
        info["status"] = int(getattr(e, "code", 0) or 0)
        return info, f"HEAD 返回 HTTP {info['status']}（服务器不支持 HEAD 或资源不可用）"
    except Exception as e:
        return info, f"HEAD 探测失败：{e}"
    if info["content_length"] is not None:
        info["size_human"] = _bytes_human(info["content_length"])
        info["exceeds_limit"] = info["content_length"] > cap
    info["resumable"] = bool(info["accept_ranges"] and "bytes" in str(info["accept_ranges"]).lower())
    return info, None
