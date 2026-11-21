#!/usr/bin/env python3
"""
AmneziaWG Client Subscription & Management API Server (v2).
1. Раздаёт актуальные конфигурации клиентов по постоянным клиентским токенам (awg_tok_*):
   - Raw .conf (/sub/<token>)
   - vpn:// (/vpn/<token>)
   - JSON (/json/<token>)
   - MikroTik RouterOS CLI (/rsc/<token>)
   Поддерживает ETag / 304 Not Modified.
2. Предоставляет защищённый Admin API (/api/v1/...) по мастер-токену (awg_adm_*):
   - Управление клиентами (список, просмотр .conf/vpn://, создание, изменение, удаление)
   - Смена внешнего Endpoint сервера (IPv4 / IPv6 / домен)
   - Смена профиля маскировки (12 UDP-протоколов + Custom) и ротация сервера
3. Dual-mode HTTP + HTTPS на одном порту (по умолчанию 8443/tcp):
   - Существующие http://<vps>:8443/sub/<token> продолжают работать без изменений
   - Admin API (/api/v1/...) работает по HTTPS (самоподписанный TLS сертификат)
     или из доверенной приватной/локальной сети (WG-туннель / loopback).
Не требует внешних библиотек (чистый Python 3 стандартной библиотеки).
"""

import base64
import glob
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

API_VERSION = "3.2.0"
AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
AWG_IFACE = os.environ.get("AWG_IFACE", "awg0")
TOKENS_FILE = os.path.join(AWG_DIR, "tokens.json")
ADMIN_TOKEN_FILE = os.path.join(AWG_DIR, "admin_token")
API_TLS_CERT = os.path.join(AWG_DIR, "api_tls.crt")
API_TLS_KEY = os.path.join(AWG_DIR, "api_tls.key")
ENDPOINT_MODE_FILE = os.path.join(AWG_DIR, "endpoint_mode.conf")
PRESET_FILE = os.path.join(AWG_DIR, "preset.conf")
MANAGER_BIN = os.environ.get("AWG_MANAGER_BIN", "/usr/local/bin/awg-manager")
API_HOST = os.environ.get("AWG_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("AWG_API_PORT", "8443"))
ALLOW_INSECURE_ADMIN = os.environ.get("AWG_API_ALLOW_INSECURE_ADMIN", "0") == "1"

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RESERVED_NAMES = {"awg0", "warp0", "server", "default"}
TOKEN_RE = re.compile(r"^awg_tok_[a-f0-9]{32,64}$")
ADMIN_TOKEN_RE = re.compile(r"^awg_adm_[a-f0-9]{32,128}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ANY_SECRET_RE = re.compile(r"awg_(?:tok|adm)_[a-f0-9]{16,128}")

# Защита от брутфорса: {ip: [count, timestamp]}
FAILED_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 20
BAN_WINDOW_SEC = 60

ADMIN_FAILED_ATTEMPTS = {}
ADMIN_MAX_FAILED_ATTEMPTS = 10
ADMIN_BAN_WINDOW_SEC = 300

STEALTH_PRESETS = [
    {"id": "quic",      "label": "HTTP/3 (QUIC)",            "default_port": 443,   "desc": "YouTube / HTTPS (RFC 9000)"},
    {"id": "quic-alt",  "label": "HTTP/3 (QUIC Alt)",        "default_port": 0,     "desc": "QUIC на высоком порту 20000-59999/udp"},
    {"id": "stun",      "label": "WebRTC / STUN",            "default_port": 3478,  "desc": "Telegram / WhatsApp звонки (RFC 5389)"},
    {"id": "stun-alt",  "label": "WebRTC / STUN (Alt)",      "default_port": 0,     "desc": "STUN на высоком порту 20000-50000/udp"},
    {"id": "dtls",      "label": "DTLS 1.2 (Zoom / VoIP)",   "default_port": 8801,  "desc": "RFC 6347 ClientHello"},
    {"id": "dns",       "label": "DNS (EDNS0)",              "default_port": 53,    "desc": "DNS-запрос ya.ru (RFC 6891)"},
    {"id": "ntp",       "label": "NTP v4 (Время)",           "default_port": 123,   "desc": "RFC 5905 Client Request"},
    {"id": "sip",       "label": "SIP (VoIP / Телефония)",   "default_port": 5060,  "desc": "RFC 3261 OPTIONS"},
    {"id": "steam",     "label": "Игровой (Steam A2S)",      "default_port": 27015, "desc": "Source Engine Query"},
    {"id": "minecraft", "label": "Игровой (Minecraft)",      "default_port": 19132, "desc": "RakNet Unconnected Ping"},
    {"id": "discord",   "label": "Discord Voice (UDP)",      "default_port": 50001, "desc": "UDP IP Discovery"},
    {"id": "dht",       "label": "BitTorrent DHT (BEP-5)",   "default_port": 6881,  "desc": "DHT Ping Query"},
    {"id": "custom",    "label": "Пользовательский",         "default_port": 0,     "desc": "Ручной порт и строка I1"},
]
VALID_PRESET_IDS = {p["id"] for p in STEALTH_PRESETS}

_PUB_IP_CACHE = {
    "ts": 0.0,
    "ipv4": "",
    "ipv6": "",
    "ipv6_diag": "",
    "ipv6_local": [],
}
_PUB_IP_CACHE_TTL_SEC = 15.0

_IGNORED_V6_IFACE_RE = re.compile(
    r"^(?:lo|awg\d*|wg\d*|warp\d*|tun\d*|tap\d*|docker\d*|br-[0-9a-f]+|"
    r"veth.*|virbr.*|cni.*|flannel.*|podman.*|tailscale\d*|zt.*)$",
    re.IGNORECASE,
)
_GLOBAL_UNICAST_V6_NET = ipaddress.IPv6Network("2000::/3")
_NON_PUBLIC_V6_NETS = (
    ipaddress.IPv6Network("2001::/32"),       # Teredo
    ipaddress.IPv6Network("2001:2::/48"),     # BMWG
    ipaddress.IPv6Network("2001:10::/28"),    # ORCHID
    ipaddress.IPv6Network("2001:20::/28"),    # ORCHIDv2
    ipaddress.IPv6Network("2001:db8::/32"),   # Documentation
    ipaddress.IPv6Network("2001:4:112::/48"), # AS112
    ipaddress.IPv6Network("2002::/16"),       # 6to4
    ipaddress.IPv6Network("3fff::/20"),       # Documentation (RFC 9637)
)


def normalize_public_ipv6(ip_str):
    """Возвращает канонический публичный IPv6 (2000::/3, не ULA/link-local/special) или ''."""
    if not ip_str or not isinstance(ip_str, str):
        return ""
    clean = ip_str.strip().strip("[]").split("%")[0].split("/")[0]
    if not clean or ":" not in clean:
        return ""
    try:
        addr = ipaddress.IPv6Address(clean)
    except Exception:
        return ""
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or addr.is_site_local
        or addr.ipv4_mapped is not None
        or addr not in _GLOBAL_UNICAST_V6_NET
    ):
        return ""
    for bad_net in _NON_PUBLIC_V6_NETS:
        if addr in bad_net:
            return ""
    return str(addr)


def split_endpoint_host_port(raw, default_port="443"):
    """Извлекает (host, port) из Endpoint/URL, корректно сохраняя голый или [скобочный] IPv6."""
    s = (raw or "").strip()
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    if "/" in s:
        s = s.split("/", 1)[0]
    if s.startswith("[") and "]" in s:
        idx = s.index("]")
        h = s[1:idx]
        rest = s[idx + 1:]
        last_port = rest.rsplit(":", 1)[-1] if ":" in rest else ""
        return h, (last_port if last_port.isdigit() else default_port)
    m4 = re.match(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})(.*)$", s)
    if m4:
        h, rest = m4.group(1), m4.group(2)
        last_port = rest.rsplit(":", 1)[-1] if ":" in rest else ""
        return h, (last_port if last_port.isdigit() else default_port)
    try:
        ip6 = ipaddress.IPv6Address(s)
        return str(ip6), default_port
    except Exception:
        pass
    if ":" in s:
        h, _ = s.split(":", 1)
        last_port = s.rsplit(":", 1)[-1]
        return h, (last_port if last_port.isdigit() else default_port)
    return s, default_port


def _normalize_peer_ip(ip_str):
    """Убирает префикс IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4) и zone ID."""
    raw = (ip_str or "").split("%")[0].strip()
    try:
        addr = ipaddress.ip_address(raw)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(addr)
    except Exception:
        return raw


def _check_rate_limit(store, client_ip, max_attempts, window_sec):
    now = time.time()
    stale = [ip for ip, (_, ts) in list(store.items()) if now - ts > window_sec]
    for ip in stale:
        store.pop(ip, None)
    entry = store.get(client_ip)
    return bool(entry and entry[0] >= max_attempts)


def _record_failed(store, client_ip):
    now = time.time()
    entry = store.get(client_ip)
    if entry:
        entry[0] += 1
        entry[1] = now
    else:
        store[client_ip] = [1, now]


def is_rate_limited(client_ip):
    return _check_rate_limit(FAILED_ATTEMPTS, client_ip, MAX_FAILED_ATTEMPTS, BAN_WINDOW_SEC)


def record_failed_attempt(client_ip):
    _record_failed(FAILED_ATTEMPTS, client_ip)


def is_admin_rate_limited(client_ip):
    return _check_rate_limit(ADMIN_FAILED_ATTEMPTS, client_ip, ADMIN_MAX_FAILED_ATTEMPTS, ADMIN_BAN_WINDOW_SEC)


def record_admin_failed(client_ip):
    _record_failed(ADMIN_FAILED_ATTEMPTS, client_ip)


def is_private_client_ip(ip_str):
    try:
        addr = ipaddress.ip_address(_normalize_peer_ip(ip_str))
        return addr.is_loopback or addr.is_private or addr.is_link_local
    except Exception:
        return False


def is_valid_client_name(name):
    if not name or not isinstance(name, str):
        return False
    if not CLIENT_NAME_RE.fullmatch(name):
        return False
    if name.lower() in RESERVED_NAMES or name.endswith("-lan-bypass"):
        return False
    return True


def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception as e:
        print(f"Ошибка чтения {TOKENS_FILE}: {e}", file=sys.stderr)
    return {}


def load_admin_token():
    if not os.path.exists(ADMIN_TOKEN_FILE):
        return ""
    try:
        tok = Path(ADMIN_TOKEN_FILE).read_text(encoding="utf-8").strip()
        if ADMIN_TOKEN_RE.fullmatch(tok):
            return tok
    except Exception as e:
        print(f"Ошибка чтения {ADMIN_TOKEN_FILE}: {e}", file=sys.stderr)
    return ""


def find_client_by_token(token):
    if not token or not isinstance(token, str):
        return None
    token = token.strip()
    if not TOKEN_RE.fullmatch(token):
        return None

    tokens_data = load_tokens()
    for client_name, cdata in tokens_data.items():
        if isinstance(cdata, dict):
            c_token = cdata.get("token", "")
        elif isinstance(cdata, str):
            c_token = cdata
        else:
            continue

        if secrets.compare_digest(c_token, token):
            if is_valid_client_name(client_name):
                return client_name
    return None


def sanitize_client_config(conf_str):
    """
    1. Очищает Endpoint от дублированных портов.
    2. Для legacy IPv4-only полного туннеля (AllowedIPs = 0.0.0.0/0) достраивает ::/0,
       не затирая явно заданные кастомные подсети.
    3. Для стандартного DNS (1.1.1.1 / 1.0.0.1 / 9.9.9.9) достраивает IPv6 DNS,
       не затирая явно заданный кастомный DNS.
    4. Гарантирует Dual-Stack Address (fd42:42:42::<oct>/128).
    """
    lines = []
    sec = ""
    for line in conf_str.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("[") and trimmed.endswith("]"):
            sec = trimmed[1:-1].lower()
            lines.append(line)
            continue

        # 1. Endpoint fix
        if sec == "peer" and trimmed.startswith("Endpoint") and "=" in line:
            prefix, val = line.split("=", 1)
            h, last_port = split_endpoint_host_port(val, default_port="443")
            if ":" in h and not h.startswith("["):
                lines.append(f"{prefix.strip()} = [{h}]:{last_port}")
            else:
                lines.append(f"{prefix.strip()} = {h}:{last_port}")
            continue

        # 2. AllowedIPs fix: upgrade legacy exact "0.0.0.0/0" to dual-stack, keep custom CIDRs intact
        if sec == "peer" and trimmed.startswith("AllowedIPs") and "=" in line:
            prefix, val = line.split("=", 1)
            if val.strip() == "0.0.0.0/0":
                lines.append(f"{prefix.strip()} = 0.0.0.0/0, ::/0")
            else:
                lines.append(line)
            continue

        # 3. DNS fix: upgrade default Cloudflare/Quad9 IPv4-only DNS to dual-stack, keep custom DNS intact
        if sec == "interface" and trimmed.startswith("DNS") and "=" in line:
            prefix, val = line.split("=", 1)
            vclean = val.strip()
            if ":" not in vclean and vclean in ("1.1.1.1, 1.0.0.1", "1.1.1.1, 9.9.9.9", "1.1.1.1"):
                lines.append(f"{prefix.strip()} = {vclean}, 2606:4700:4700::1111, 2606:4700:4700::1001")
            else:
                lines.append(line)
            continue

        # 4. Address check: ensure IPv6 address
        if sec == "interface" and trimmed.startswith("Address") and "=" in line:
            prefix, val = line.split("=", 1)
            raw_addr = val.strip()
            if ":" in raw_addr:
                lines.append(line)
            else:
                ip_clean = raw_addr.split("/")[0].strip()
                last_oct = ip_clean.rsplit(".", 1)[-1] if "." in ip_clean else "2"
                lines.append(f"{prefix.strip()} = {raw_addr}, fd42:42:42::{last_oct}/128")
            continue

        lines.append(line)

    return "\n".join(lines)


def conf_to_vpn_url(conf_text, client_name="client"):
    """Преобразует текст .conf в официальную ссылку Amnezia vpn://..."""
    endpoint = ""
    dns = "1.1.1.1"
    for line in conf_text.splitlines():
        line = line.strip()
        if line.startswith("Endpoint") and "=" in line:
            endpoint = line.split("=", 1)[1].strip()
        elif line.startswith("DNS") and "=" in line:
            dns = line.split("=", 1)[1].strip()

    host, _ = split_endpoint_host_port(endpoint, default_port="443")
    if not host:
        host = "awg-server"
    amnezia_payload = {
        "containers": [
            {
                "container": "amnezia-awg",
                "awg": {
                    "last_config": conf_text
                }
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": f"AWG 3.1 - {client_name}",
        "dns1": dns.split(",")[0].strip(),
        "hostName": host
    }
    encoded = base64.b64encode(json.dumps(amnezia_payload).encode("utf-8")).decode("utf-8")
    return f"vpn://{encoded}"


def conf_to_mikrotik_rsc(conf_text, client_name):
    """Генерирует RouterOS CLI скрипт для нативного WireGuard или контейнера."""
    params = {}
    section = None
    for line in conf_text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if "=" in line and section:
            k, v = line.split("=", 1)
            params[f"{section}.{k.strip()}"] = v.strip()

    srv_endpoint = params.get("peer.Endpoint", "")
    ep_host, ep_port = split_endpoint_host_port(srv_endpoint, default_port="443")
    if not ep_host:
        ep_host = "0.0.0.0"

    rsc = [
        f"# MikroTik RouterOS Configuration for client: {client_name}",
        f"# Generated by awg-manager at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "# 1. Настройка параметров WireGuard peer",
        f'/interface wireguard set [find name="awg0"] private-key="{params.get("interface.PrivateKey", "")}" mtu={params.get("interface.MTU", "1280")}',
        f'/interface wireguard peers set [find interface="awg0"] public-key="{params.get("peer.PublicKey", "")}" endpoint-address="{ep_host}" endpoint-port={ep_port} allowed-address=0.0.0.0/0 persistent-keepalive=25',
        "",
        "# 2. Настройка переменных обфускации для AmneziaWG Proxy-контейнера",
        f'/container envs set [find name="awg_env" key="AWG_HPK"] value="{params.get("interface.HeaderProtectionKey", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_S1"] value="{params.get("interface.S1", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_S2"] value="{params.get("interface.S2", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_S3"] value="{params.get("interface.S3", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_S4"] value="{params.get("interface.S4", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_I1"] value="{params.get("interface.I1", "")}"',
        f'/container envs set [find name="awg_env" key="AWG_JC"] value="{params.get("interface.Jc", "4")}"',
        "",
        "# 3. Перезапуск контейнера для применения",
        '/container stop [find name="awg-proxy"]',
        ':delay 2s',
        '/container start [find name="awg-proxy"]',
        f':log info "AmneziaWG: {client_name} tunnel configuration updated successfully"'
    ]
    return "\n".join(rsc)


def parse_conf_kv(conf_text):
    """Разбирает .conf на {'interface': {...}, 'peer': {...}}."""
    res = {"interface": {}, "peer": {}}
    sec = ""
    for line in conf_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            sec = s[1:-1].lower()
            continue
        if "=" in line and sec in res:
            k, v = line.split("=", 1)
            res[sec][k.strip()] = v.strip()
    return res


def parse_server_conf():
    """Читает awg0.conf и возвращает (iface_dict, peers_list)."""
    srv_path = Path(AWG_DIR) / f"{AWG_IFACE}.conf"
    if not srv_path.is_file():
        return {}, []
    iface = {}
    peers = []
    sec = ""
    cur_peer = None
    for line in srv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s == "[Interface]":
            sec = "interface"
            continue
        if s == "[Peer]":
            sec = "peer"
            if cur_peer:
                peers.append(cur_peer)
            cur_peer = {"name": "", "public_key": "", "allowed_ips": ""}
            continue
        if sec == "interface":
            if "=" in line and not s.startswith("#"):
                k, v = line.split("=", 1)
                iface[k.strip()] = v.strip()
        elif sec == "peer" and cur_peer is not None:
            if s.startswith("#") and not cur_peer["name"]:
                cur_peer["name"] = s.lstrip("#").strip()
            elif "=" in line:
                k, v = line.split("=", 1)
                ks = k.strip()
                if ks == "PublicKey":
                    cur_peer["public_key"] = v.strip()
                elif ks == "AllowedIPs":
                    cur_peer["allowed_ips"] = v.strip()
    if cur_peer:
        peers.append(cur_peer)
    return iface, peers


def get_awg_live_dump():
    """Читает runtime статистику пиров через `awg show <iface> dump`."""
    stats = {}
    try:
        out = subprocess.check_output(
            ["awg", "show", AWG_IFACE, "dump"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode("utf-8", errors="replace")
    except Exception:
        return stats

    lines = out.splitlines()
    for ln in lines[1:]:
        parts = ln.split("\t")
        if len(parts) < 8:
            continue
        pub = parts[0].strip()
        try:
            hs = int(parts[4])
        except ValueError:
            hs = 0
        try:
            rx = int(parts[5])
        except ValueError:
            rx = 0
        try:
            tx = int(parts[6])
        except ValueError:
            tx = 0
        stats[pub] = {"last_handshake": hs, "rx_bytes": rx, "tx_bytes": tx}
    return stats


def _invalidate_pub_ip_cache():
    _PUB_IP_CACHE["ts"] = 0.0


def _collect_local_public_ipv6():
    """Собирает публичные (2000::/3) глобальные IPv6 с не-виртуальных интерфейсов."""
    recs = []
    try:
        out = subprocess.check_output(
            ["ip", "-6", "-j", "addr", "show"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).decode("utf-8", errors="replace")
        data = json.loads(out)
        if isinstance(data, list):
            for iface_obj in data:
                if not isinstance(iface_obj, dict):
                    continue
                ifname = str(iface_obj.get("ifname", "") or "")
                if not ifname or _IGNORED_V6_IFACE_RE.match(ifname):
                    continue
                for a in iface_obj.get("addr_info", []) or []:
                    if not isinstance(a, dict):
                        continue
                    if a.get("family") != "inet6" or a.get("scope") != "global":
                        continue
                    if a.get("deprecated") or a.get("tentative") or a.get("dadfailed"):
                        continue
                    plt = a.get("preferred_life_time")
                    if plt is not None and int(plt) == 0:
                        continue
                    ip_norm = normalize_public_ipv6(str(a.get("local", "") or ""))
                    if not ip_norm:
                        continue
                    recs.append({
                        "ifname": ifname,
                        "ip": ip_norm,
                        "prefixlen": int(a.get("prefixlen", 64) or 64),
                        "temporary": bool(a.get("temporary")),
                        "secondary": bool(a.get("secondary")),
                        "dynamic": bool(a.get("dynamic")),
                        "mngtmpaddr": bool(a.get("mngtmpaddr")),
                    })
            return recs
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ip", "-6", "-o", "addr", "show", "scope", "global"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).decode("utf-8", errors="replace")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            ifname = parts[1].split("@")[0]
            if not ifname or _IGNORED_V6_IFACE_RE.match(ifname):
                continue
            if "deprecated" in parts or "tentative" in parts or "dadfailed" in parts:
                continue
            cidr = parts[3]
            ip_norm = normalize_public_ipv6(cidr)
            if not ip_norm:
                continue
            plen = 64
            if "/" in cidr:
                try:
                    plen = int(cidr.split("/", 1)[1])
                except ValueError:
                    plen = 64
            recs.append({
                "ifname": ifname,
                "ip": ip_norm,
                "prefixlen": plen,
                "temporary": ("temporary" in parts),
                "secondary": ("secondary" in parts),
                "dynamic": ("dynamic" in parts),
                "mngtmpaddr": ("mngtmpaddr" in parts),
            })
    except Exception:
        pass
    return recs


def _detect_default_devs(family_flag="-6"):
    devs = []
    for cmd in (
        ["ip", family_flag, "-o", "route", "show", "table", "all"],
        ["ip", family_flag, "-o", "route", "show", "default"],
    ):
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=3
            ).decode("utf-8", errors="replace")
            for ln in out.splitlines():
                toks = ln.split()
                if not toks or toks[0] != "default":
                    continue
                for i in range(len(toks) - 1):
                    if toks[i] == "dev":
                        d = toks[i + 1].split("@")[0]
                        if d and not _IGNORED_V6_IFACE_RE.match(d) and d not in devs:
                            devs.append(d)
            if cmd[-1] == "all":
                break
        except Exception:
            continue
    return devs


def _route_get_v6(dst, from_ip=""):
    cmd = ["ip", "-6", "-o", "route", "get", dst]
    if from_ip:
        cmd.extend(["from", from_ip])
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=3
        ).decode("utf-8", errors="replace")
    except Exception:
        return "", ""
    m_dev = re.search(r"\bdev\s+([^\s]+)", out)
    m_src = re.search(r"\bsrc\s+([^\s]+)", out)
    dev = m_dev.group(1).split("@")[0] if m_dev else ""
    src = m_src.group(1) if m_src else ""
    if dev and _IGNORED_V6_IFACE_RE.match(dev):
        return "", ""
    return dev, src


def _upgrade_temporary_v6(ifname, ip_norm, recs):
    """Предпочитает постоянный IPv6 на том же интерфейсе/префиксе, если ядро выбрало SLAAC temporary."""
    match = [r for r in recs if r["ifname"] == ifname and r["ip"] == ip_norm]
    if not match or not match[0]["temporary"]:
        return ip_norm
    perms = [r for r in recs if r["ifname"] == ifname and not r["temporary"]]
    if not perms:
        return ip_norm
    try:
        target_p64 = ipaddress.IPv6Address(ip_norm).packed[:8]
    except Exception:
        target_p64 = None
    perms.sort(key=lambda r: (
        0 if (target_p64 is not None and ipaddress.IPv6Address(r["ip"]).packed[:8] == target_p64) else 1,
        1 if r["secondary"] else 0,
        1 if (r["dynamic"] and not r["mngtmpaddr"]) else 0,
    ))
    return perms[0]["ip"]


def _solicit_router_ra(wan_dev):
    """Шлёт Router Solicitation на WAN чтобы заставить шлюз датацентра прислать RA с префиксом IPv6."""
    if not wan_dev:
        return
    try:
        subprocess.run(
            ["ping6", "-c", "1", "-w", "1", f"ff02::2%{wan_dev}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            ["rdisc6", "-m", wan_dev],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except Exception:
        pass


def _discover_cloud_ipv6():
    """Ищет выделенный провайдером IPv6 в cloud-init, IMDS метаданных, netplan и конфигах сети."""
    def check_text(txt, source_name):
        cands = []
        for m in re.finditer(r"\b(2[0-9a-fA-F]{3}:[0-9a-fA-F:]+)(?:/(\d+))?\b", txt):
            raw = m.group(1).lower()
            plen = int(m.group(2)) if m.group(2) else 64
            try:
                ip_obj = ipaddress.IPv6Address(raw)
                if ip_obj.is_global and not ip_obj.is_multicast and not ip_obj.is_link_local and not ip_obj.is_private:
                    cands.append((raw, plen))
            except Exception:
                pass
        if not cands:
            return None
        best_ip, best_plen = cands[0]
        for c_ip, c_plen in cands:
            if not c_ip.endswith("::1"):
                best_ip, best_plen = c_ip, c_plen
                break
        gw_m = re.search(r"(?:gateway6|via|gateway)\s*[:=]\s*[\"'\s]*([23][0-9a-fA-F:]+)", txt)
        found_gw = ""
        if gw_m:
            try:
                g = ipaddress.IPv6Address(gw_m.group(1).lower())
                if g.is_global:
                    found_gw = str(g)
            except Exception:
                pass
        if not found_gw:
            try:
                net = ipaddress.IPv6Network(f"{best_ip}/{best_plen}", strict=False)
                found_gw = str(net.network_address + 1)
            except Exception:
                pass
        return best_ip, best_plen, found_gw, source_name

    # 1. IMDS Cloud Metadata
    for imds_url in [
        "http://169.254.169.254/openstack/latest/network_data.json",
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/hetzner/v1/metadata/network",
    ]:
        try:
            req = urllib.request.Request(imds_url, headers={"User-Agent": "cloud-init"})
            with urllib.request.urlopen(req, timeout=0.8) as r:
                res = check_text(r.read().decode("utf-8", errors="replace"), imds_url)
                if res:
                    return res
        except Exception:
            pass

    # 2. Local config files on disk
    file_patterns = [
        "/run/cloud-init/instance-data.json",
        "/run/cloud-init/result.json",
        "/var/lib/cloud/instance/instance-data.json",
        "/var/lib/cloud/instances/*/network-data.json",
        "/var/lib/cloud/instance/user-data",
        "/etc/netplan/*.yaml",
        "/etc/netplan/*.yml",
        "/etc/network/interfaces",
        "/etc/network/interfaces.d/*",
        "/etc/systemd/network/*.network",
        "/etc/sysconfig/network-scripts/ifcfg-*",
    ]
    for pat in file_patterns:
        for fpath in glob.glob(pat):
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        res = check_text(f.read(), fpath)
                        if res:
                            return res
                except Exception:
                    pass

    return "", 0, "", "not_found"


def _activate_discovered_ipv6(ip, plen, gw, wan_dev):
    """Поднимает обнаруженный в облачных метаданных IPv6 на WAN интерфейсе."""
    if not ip or not wan_dev:
        return False
    plen = plen or 64
    try:
        subprocess.run(
            ["ip", "-6", "addr", "replace", f"{ip}/{plen}", "dev", wan_dev],
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except Exception:
        try:
            subprocess.run(
                ["ip", "-6", "addr", "add", f"{ip}/{plen}", "dev", wan_dev],
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:
            pass
    if gw:
        try:
            subprocess.run(
                ["ip", "-6", "route", "replace", "default", "via", gw, "dev", wan_dev, "onlink"],
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:
            try:
                subprocess.run(
                    ["ip", "-6", "route", "replace", "default", "via", gw, "dev", wan_dev],
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
            except Exception:
                pass
    if os.path.isdir("/etc/netplan"):
        np_path = "/etc/netplan/60-awg-ipv6.yaml"
        if not os.path.isfile(np_path):
            routes_block = (
                f"      routes:\n        - to: default\n          via: {gw}\n          on-link: true\n"
                if gw
                else ""
            )
            content = (
                "network:\n"
                "  version: 2\n"
                "  ethernets:\n"
                f"    {wan_dev}:\n"
                "      addresses:\n"
                f"        - {ip}/{plen}\n"
                f"{routes_block}"
            )
            try:
                with open(np_path, "w", encoding="utf-8") as f:
                    f.write(content)
                os.chmod(np_path, 0o600)
                subprocess.run(["netplan", "apply"], stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
    return True


def _probe_external_ipv6(iface_or_ip="", max_urls=4):
    urls = (
        "https://api6.ipify.org",
        "https://ipv6.icanhazip.com",
        "https://v6.ident.me",
        "https://api64.ipify.org",
    )[:max_urls]
    for url in urls:
        cmd = ["curl", "-6", "-fsS", "--connect-timeout", "2", "--max-time", "3"]
        if iface_or_ip:
            cmd.extend(["--interface", iface_or_ip])
        cmd.append(url)
        try:
            resp = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=4
            ).decode("utf-8", errors="replace").strip()
            v6 = normalize_public_ipv6(resp)
            if v6:
                return v6
        except Exception:
            continue
    return ""


def _detect_public_ipv6_with_diag():
    """
    Определяет внешний IPv6 VPS для Endpoint клиентов:
    1) Учитывает AWG_IPV6_ENDPOINT при явном переопределении.
    2) Проверяет маршрутизацию ядра (`ip -6 route get`), игнорируя awg/wg/warp/docker/veth.
    3) Заменяет SLAAC `temporary` на постоянный адрес того же интерфейса/префикса.
    4) Проверяет policy-routing (`from <cand>`) и `default` маршруты.
    5) Использует HTTPS IPv6-echo только если в ОС действительно есть IPv6 uplink (NAT66/policy).
    Возвращает (public_ipv6, local_public_addrs, diag_code).
    """
    env_override = normalize_public_ipv6(os.environ.get("AWG_IPV6_ENDPOINT", ""))
    if env_override:
        return env_override, [env_override], "ok"

    recs = _collect_local_public_ipv6()
    local_ips = []
    for r in recs:
        if r["ip"] not in local_ips:
            local_ips.append(r["ip"])

    default_devs = _detect_default_devs("-6")
    wan4_devs = _detect_default_devs("-4")

    saw_wan_route = False
    for probe_dst in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
        rdev, rsrc = _route_get_v6(probe_dst)
        if not rdev:
            continue
        saw_wan_route = True
        v6 = normalize_public_ipv6(rsrc)
        if v6:
            v6 = _upgrade_temporary_v6(rdev, v6, recs)
            return v6, local_ips, "ok"

    if recs:
        ranked = sorted(
            recs,
            key=lambda r: (
                1 if r["temporary"] else 0,
                1 if r["secondary"] else 0,
                0 if r["ifname"] in default_devs else (1 if r["ifname"] in wan4_devs else 2),
                1 if (r["dynamic"] and not r["mngtmpaddr"]) else 0,
            ),
        )
        for rec in ranked[:4]:
            for probe_dst in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
                rdev, _ = _route_get_v6(probe_dst, from_ip=rec["ip"])
                if rdev:
                    cand = _upgrade_temporary_v6(rdev, rec["ip"], recs)
                    return cand, local_ips, "ok"
        if default_devs:
            for rec in ranked:
                if rec["ifname"] in default_devs:
                    cand = _upgrade_temporary_v6(rec["ifname"], rec["ip"], recs)
                    return cand, local_ips, "ok"
        ext_cand = _probe_external_ipv6(ranked[0]["ip"], max_urls=1)
        if ext_cand:
            return ext_cand, local_ips, "ok"
        cand = _upgrade_temporary_v6(ranked[0]["ifname"], ranked[0]["ip"], recs)
        return cand, local_ips, "local_assigned"

    if default_devs or saw_wan_route:
        ext_v6 = _probe_external_ipv6()
        if ext_v6:
            return ext_v6, local_ips, "ok"
        if local_ips:
            return local_ips[0], local_ips, "local_assigned"
        return "", local_ips, "no_egress"

    # Автоматический поиск и подъём IPv6 для ЛЮБОГО случайного VPS (SLAAC / IMDS / cloud-init / netplan)
    primary_wan = wan4_devs[0] if wan4_devs else ("eth0" if os.path.exists("/sys/class/net/eth0") else "")
    if primary_wan:
        _solicit_router_ra(primary_wan)
        time.sleep(0.3)
        recs_after = _collect_local_public_ipv6()
        if recs_after:
            ext_v6 = _probe_external_ipv6()
            return ext_v6 or recs_after[0]["ip"], [r["ip"] for r in recs_after], "ok"

        disc_ip, disc_plen, disc_gw, disc_src = _discover_cloud_ipv6()
        if disc_ip:
            _activate_discovered_ipv6(disc_ip, disc_plen, disc_gw, primary_wan)
            ext_v6 = _probe_external_ipv6()
            return ext_v6 or disc_ip, [disc_ip], "discovered_" + disc_src

    return "", [], "no_interface_ipv6"


def detect_public_ips_with_diag():
    now = time.time()
    if now - _PUB_IP_CACHE["ts"] < _PUB_IP_CACHE_TTL_SEC:
        return (
            _PUB_IP_CACHE["ipv4"],
            _PUB_IP_CACHE["ipv6"],
            _PUB_IP_CACHE["ipv6_diag"],
            list(_PUB_IP_CACHE["ipv6_local"]),
        )

    pub4 = ""
    try:
        out4 = subprocess.check_output(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).decode("utf-8", errors="replace")
        m = re.search(r"\bsrc\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out4)
        if m:
            cand = m.group(1)
            if not is_private_client_ip(cand):
                pub4 = cand
    except Exception:
        pass

    pub6, local_ips6, diag6 = _detect_public_ipv6_with_diag()

    _PUB_IP_CACHE["ts"] = now
    _PUB_IP_CACHE["ipv4"] = pub4
    _PUB_IP_CACHE["ipv6"] = pub6
    _PUB_IP_CACHE["ipv6_diag"] = diag6
    _PUB_IP_CACHE["ipv6_local"] = list(local_ips6)
    return pub4, pub6, diag6, list(local_ips6)


def detect_public_ips_cached():
    pub4, pub6, _, _ = detect_public_ips_with_diag()
    return pub4, pub6


def detect_preset_id(iface):
    if os.path.exists(PRESET_FILE):
        try:
            p = Path(PRESET_FILE).read_text(encoding="utf-8").strip()
            if p:
                return p
        except Exception:
            pass
    i1 = iface.get("I1", "")
    port = str(iface.get("ListenPort", ""))
    if "2112a442" in i1:
        return "stun" if port == "3478" else "stun-alt"
    if "16fefd0000" in i1:
        return "dtls"
    if "027961027275" in i1:
        return "dns"
    if "2300000000000000" in i1:
        return "ntp"
    if "4f5054494f4e5320" in i1:
        return "sip"
    if "54536f75726365" in i1:
        return "steam"
    if "00ffff00fefefefe" in i1:
        return "minecraft"
    if "00010046" in i1:
        return "discord"
    if "64313a6164323a696432303a" in i1:
        return "dht"
    if "0000000108" in i1:
        return "quic" if port == "443" else "quic-alt"
    return "quic"


def read_endpoint_mode():
    if os.path.exists(ENDPOINT_MODE_FILE):
        try:
            val = Path(ENDPOINT_MODE_FILE).read_text(encoding="utf-8").strip()
            if val:
                return val
        except Exception:
            pass
    return "ipv4"


def build_client_item(name, peer_info, live_stats, tokens_data, include_config=False):
    conf_path = Path(AWG_DIR).resolve() / f"{name}.conf"
    conf_str = ""
    etag = ""
    updated_at = 0
    if conf_path.parent == Path(AWG_DIR).resolve() and conf_path.is_file():
        try:
            raw = conf_path.read_text(encoding="utf-8", errors="replace")
            conf_str = sanitize_client_config(raw)
            etag = hashlib.sha256(conf_str.encode("utf-8")).hexdigest()[:16]
            updated_at = int(conf_path.stat().st_mtime)
        except Exception:
            pass

    kv = parse_conf_kv(conf_str) if conf_str else {"interface": {}, "peer": {}}
    addr_raw = kv["interface"].get("Address") or (peer_info or {}).get("allowed_ips", "")
    ipv4 = ""
    ipv6 = ""
    for part in addr_raw.split(","):
        p = part.strip().split("/")[0]
        if ":" in p and not ipv6:
            ipv6 = p
        elif "." in p and not ipv4:
            ipv4 = p

    tok_entry = tokens_data.get(name)
    token = ""
    ep_mode = "server"
    ep_host = ""
    if isinstance(tok_entry, dict):
        token = str(tok_entry.get("token", "") or "")
        ep_mode = str(tok_entry.get("endpoint_mode", "server") or "server")
        ep_host = str(tok_entry.get("endpoint_host", "") or "")
    elif isinstance(tok_entry, str):
        token = tok_entry

    pub_key = (peer_info or {}).get("public_key", "")
    st = live_stats.get(pub_key, {}) if pub_key else {}
    last_hs = int(st.get("last_handshake", 0) or 0)
    now = int(time.time())
    hs_age = (now - last_hs) if last_hs > 0 and now >= last_hs else -1
    is_online = last_hs > 0 and 0 <= hs_age <= 180

    item = {
        "name": name,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "allowed_ips_server": (peer_info or {}).get("allowed_ips", ""),
        "public_key": pub_key,
        "is_online": is_online,
        "last_handshake": last_hs,
        "handshake_age_sec": hs_age,
        "rx_bytes": int(st.get("rx_bytes", 0) or 0),
        "tx_bytes": int(st.get("tx_bytes", 0) or 0),
        "token": token,
        "endpoint": kv["peer"].get("Endpoint", ""),
        "endpoint_mode": ep_mode,
        "endpoint_host": ep_host,
        "dns": kv["interface"].get("DNS", ""),
        "mtu": kv["interface"].get("MTU", ""),
        "allowed_ips": kv["peer"].get("AllowedIPs", ""),
        "keepalive": kv["peer"].get("PersistentKeepalive", ""),
        "etag": etag,
        "updated_at": updated_at,
    }
    if include_config and conf_str:
        item["config"] = conf_str
        item["vpn_url"] = conf_to_vpn_url(conf_str, name)
        if token:
            item["sub_path"] = f"/sub/{token}"
    return item


def build_state_snapshot(include_configs=False, target_client=None, tls_enabled=False):
    iface, peers = parse_server_conf()
    live_stats = get_awg_live_dump()
    tokens_data = load_tokens()

    peer_by_name = {}
    ordered_names = []
    for p in peers:
        nm = p.get("name", "")
        if is_valid_client_name(nm):
            peer_by_name[nm] = p
            if nm not in ordered_names:
                ordered_names.append(nm)

    clients = []
    target_item = None
    for nm in ordered_names:
        want_cfg = include_configs or (target_client == nm)
        item = build_client_item(nm, peer_by_name.get(nm), live_stats, tokens_data, include_config=want_cfg)
        clients.append(item)
        if target_client == nm:
            target_item = item

    listen_port = 0
    try:
        listen_port = int(iface.get("ListenPort", "0") or "0")
    except ValueError:
        listen_port = 0

    preset_id = detect_preset_id(iface)
    ep_mode = read_endpoint_mode()
    pub4, pub6, diag6, local_ips6 = detect_public_ips_with_diag()

    sample_ep = ""
    for c in clients:
        if c.get("endpoint_mode", "server") == "server" and c.get("endpoint"):
            sample_ep = c["endpoint"]
            break
    if not sample_ep and clients:
        sample_ep = clients[0].get("endpoint", "")

    if not pub4 and sample_ep:
        h, _ = split_endpoint_host_port(sample_ep)
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", h):
            pub4 = h

    etag_src = json.dumps(
        {
            "port": listen_port,
            "preset": preset_id,
            "ep_mode": ep_mode,
            "ep": sample_ep,
            "pub4": pub4,
            "pub6": pub6,
            "ipv6_diag": diag6,
            "i1": iface.get("I1", ""),
            "s": [iface.get(k, "") for k in ("S1", "S2", "S3", "S4", "HeaderProtectionKey")],
            "clients": [(c["name"], c["etag"], c["token"]) for c in clients],
        },
        sort_keys=True,
    ).encode("utf-8")
    server_etag = hashlib.sha256(etag_src).hexdigest()[:16]

    server = {
        "version": API_VERSION,
        "listen_port": listen_port,
        "preset": preset_id,
        "endpoint_mode": ep_mode,
        "endpoint": sample_ep,
        "public_ipv4": pub4,
        "public_ipv6": pub6,
        "ipv6_diag": diag6,
        "ipv6_local_addrs": local_ips6,
        "api_port": API_PORT,
        "tls_enabled": tls_enabled,
        "client_count": len(clients),
        "server_etag": server_etag,
        "presets": STEALTH_PRESETS,
    }
    return server, clients, target_item


def _resolve_manager_bin():
    if os.path.exists(MANAGER_BIN):
        return MANAGER_BIN
    sibling = str(Path(__file__).resolve().parent / "install.sh")
    if os.path.exists(sibling):
        return sibling
    return MANAGER_BIN


def run_manager(args, skip_api_restart=False):
    cmd = [_resolve_manager_bin()] + list(args)
    env = os.environ.copy()
    env["AWGM_PLAIN"] = "1"
    env["AWG_DIR"] = AWG_DIR
    env["AWG_API_PORT"] = str(API_PORT)
    if skip_api_restart:
        env["AWG_SKIP_API_RESTART"] = "1"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
        combined = ANSI_RE.sub("", (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        combined = ANY_SECRET_RE.sub("awg_***", combined)
        return proc.returncode == 0, combined
    except Exception as e:
        return False, ANY_SECRET_RE.sub("awg_***", str(e))


class SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"AWG-API-Server/{API_VERSION}"

    def _client_ip(self):
        return _normalize_peer_ip(self.client_address[0]) if self.client_address else "unknown"

    def log_message(self, format, *args):
        client_ip = self._client_ip()
        msg = format % args
        masked_msg = ANY_SECRET_RE.sub("awg_***", msg)
        print(f"[{self.log_date_time_string()}] {client_ip} - {masked_msg}")

    def _is_tls(self):
        return isinstance(self.connection, ssl.SSLSocket)

    def _tls_configured(self):
        return getattr(self.server, "ssl_context", None) is not None

    def send_json(self, status_code, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self, max_bytes=65536):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None, "Некорректный Content-Length"
        if length <= 0:
            return {}, None
        if length > max_bytes:
            return None, "Тело запроса слишком большое"
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return None, "Ожидается JSON-объект"
            return data, None
        except Exception:
            return None, "Некорректный JSON"

    def _check_admin_auth(self):
        client_ip = self._client_ip()
        if is_admin_rate_limited(client_ip):
            self.send_json(429, {"error": "Too Many Requests", "message": "Слишком много неудачных попыток авторизации."})
            return False

        # Для публичных IP требуем TLS, если TLS настроен и не включён ALLOW_INSECURE_ADMIN
        if self._tls_configured() and not self._is_tls() and not is_private_client_ip(client_ip) and not ALLOW_INSECURE_ADMIN:
            self.send_json(426, {
                "error": "Upgrade Required",
                "message": "Admin API требует HTTPS (используйте https://<host>:8443/api/v1/... или обращение через VPN-туннель)."
            })
            return False

        expected = load_admin_token()
        if not expected:
            self.send_json(503, {
                "error": "Admin API Disabled",
                "message": "Admin-токен не настроен на сервере. Выполните: sudo awg-manager admin-token"
            })
            return False

        auth = self.headers.get("Authorization", "").strip()
        provided = ""
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        elif self.headers.get("X-Admin-Token"):
            provided = self.headers.get("X-Admin-Token", "").strip()

        if not provided or not ADMIN_TOKEN_RE.fullmatch(provided) or not secrets.compare_digest(provided, expected):
            record_admin_failed(client_ip)
            self.send_json(403, {"error": "Forbidden", "message": "Недействительный Admin-токен."})
            return False
        return True

    def do_HEAD(self):
        self.handle_get_or_head(is_head=True)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_get(parsed)
            return
        self.handle_get_or_head(is_head=False)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_post(parsed)
            return
        self.send_json(404, {"error": "Not Found"})

    def do_PATCH(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_patch(parsed)
            return
        self.send_json(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_delete(parsed)
            return
        self.send_json(404, {"error": "Not Found"})

    # --- Admin API v1 handlers -----------------------------------------------

    def handle_admin_get(self, parsed):
        if not self._check_admin_auth():
            return
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/") if p]
        # /api/v1/clients
        if parts == ["api", "v1", "clients"] or parts == ["api", "v1", "server"]:
            server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
            etag = f'"{server["server_etag"]}"'
            if self.headers.get("If-None-Match", "").strip() == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self.send_json(200, {"server": server, "clients": clients}, extra_headers={"ETag": etag})
            return

        # /api/v1/clients/<name>
        if len(parts) == 4 and parts[:3] == ["api", "v1", "clients"]:
            cname = parts[3]
            if not is_valid_client_name(cname):
                self.send_json(400, {"error": "Bad Request", "message": "Некорректное имя клиента."})
                return
            server, _, item = build_state_snapshot(include_configs=False, target_client=cname, tls_enabled=self._tls_configured())
            if not item:
                self.send_json(404, {"error": "Not Found", "message": f"Клиент '{cname}' не найден."})
                return
            etag = f'"{item["etag"]}"' if item.get("etag") else ""
            headers = {"ETag": etag} if etag else None
            self.send_json(200, {"server": server, "client": item}, extra_headers=headers)
            return

        self.send_json(404, {"error": "Not Found"})

    def handle_admin_post(self, parsed):
        if not self._check_admin_auth():
            return
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/") if p]
        body, err = self._read_json_body()
        if err:
            self.send_json(400, {"error": "Bad Request", "message": err})
            return

        # POST /api/v1/clients — создать нового клиента
        if parts == ["api", "v1", "clients"]:
            name = str(body.get("name", "") or "").strip()
            if not is_valid_client_name(name):
                self.send_json(400, {"error": "Bad Request", "message": "Некорректное имя клиента (A-Z, 0-9, _, -, 1..32)."})
                return
            args = ["add-client", name]
            for field, flag in (
                ("dns", "--dns"),
                ("mtu", "--mtu"),
                ("allowed_ips", "--allowed-ips"),
                ("keepalive", "--keepalive"),
                ("endpoint", "--endpoint"),
            ):
                val = str(body.get(field, "") or "").strip()
                if val:
                    if "\n" in val or "\r" in val:
                        self.send_json(400, {"error": "Bad Request", "message": f"Недопустимое значение поля {field}."})
                        return
                    args.extend([flag, val])

            ok, out = run_manager(args)
            if not ok:
                self.send_json(400, {"error": "Create Failed", "message": out[-600:] or "Ошибка создания клиента"})
                return

            _invalidate_pub_ip_cache()
            server, _, item = build_state_snapshot(include_configs=False, target_client=name, tls_enabled=self._tls_configured())
            self.send_json(201, {"ok": True, "server": server, "client": item, "output": out[-500:]})
            return

        # POST /api/v1/server/endpoint — сменить внешний Endpoint сервера (ipv4|ipv6|<host>)
        if parts == ["api", "v1", "server", "endpoint"]:
            target = str(body.get("target", "") or "").strip()
            if not target or "\n" in target or "\r" in target or len(target) > 128:
                self.send_json(400, {"error": "Bad Request", "message": "Укажите target: ipv4, ipv6 или домен/IP."})
                return
            args = ["endpoint", target]
            if body.get("all") or body.get("reset_overrides"):
                args.append("--all")
            ok, out = run_manager(args)
            if not ok:
                self.send_json(400, {"error": "Endpoint Switch Failed", "message": out[-600:] or "Ошибка смены Endpoint"})
                return
            _invalidate_pub_ip_cache()
            server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
            self.send_json(200, {"ok": True, "server": server, "clients": clients, "output": out[-500:]})
            return

        # POST /api/v1/server/preset — сменить профиль маскировки
        if parts == ["api", "v1", "server", "preset"]:
            preset = str(body.get("preset", "") or "").strip().lower()
            if preset not in VALID_PRESET_IDS:
                self.send_json(400, {"error": "Bad Request", "message": f"Неизвестный профиль маскировки: {preset}"})
                return
            args = ["preset", preset]
            if preset == "custom":
                cport = str(body.get("port", "") or "").strip()
                ci1 = str(body.get("i1", "") or "").strip()
                if cport:
                    if not cport.isdigit() or not (1 <= int(cport) <= 65535):
                        self.send_json(400, {"error": "Bad Request", "message": "Некорректный порт (1..65535)."})
                        return
                    args.append(cport)
                if ci1:
                    if "\n" in ci1 or "\r" in ci1 or len(ci1) > 512:
                        self.send_json(400, {"error": "Bad Request", "message": "Некорректная строка I1."})
                        return
                    if not cport:
                        args.append("")
                    args.append(ci1)
            ok, out = run_manager(args, skip_api_restart=True)
            if not ok:
                self.send_json(400, {"error": "Preset Failed", "message": out[-600:] or "Ошибка смены маскировки"})
                return
            _invalidate_pub_ip_cache()
            server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
            self.send_json(200, {"ok": True, "server": server, "clients": clients, "output": out[-500:]})
            return

        # POST /api/v1/server/rotate — ротация порта, ключей и параметров обфускации
        if parts == ["api", "v1", "server", "rotate"]:
            preset = str(body.get("preset", "") or "").strip().lower()
            args = ["rotate"]
            if preset:
                if preset not in VALID_PRESET_IDS or preset == "custom":
                    self.send_json(400, {"error": "Bad Request", "message": f"Недопустимый профиль для ротации: {preset}"})
                    return
                args.append(preset)
            ok, out = run_manager(args, skip_api_restart=True)
            if not ok:
                self.send_json(400, {"error": "Rotate Failed", "message": out[-600:] or "Ошибка ротации сервера"})
                return
            _invalidate_pub_ip_cache()
            server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
            self.send_json(200, {"ok": True, "server": server, "clients": clients, "output": out[-500:]})
            return

        self.send_json(404, {"error": "Not Found"})

    def handle_admin_patch(self, parsed):
        if not self._check_admin_auth():
            return
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 4 or parts[:3] != ["api", "v1", "clients"]:
            self.send_json(404, {"error": "Not Found"})
            return

        cname = parts[3]
        if not is_valid_client_name(cname):
            self.send_json(400, {"error": "Bad Request", "message": "Некорректное имя клиента."})
            return

        body, err = self._read_json_body()
        if err:
            self.send_json(400, {"error": "Bad Request", "message": err})
            return

        args = ["edit-client", cname]
        final_name = cname

        new_name = str(body.get("rename", "") or "").strip()
        if new_name and new_name != cname:
            if not is_valid_client_name(new_name):
                self.send_json(400, {"error": "Bad Request", "message": "Некорректное новое имя клиента."})
                return
            args.extend(["--rename", new_name])
            final_name = new_name

        for field, flag in (
            ("dns", "--dns"),
            ("mtu", "--mtu"),
            ("allowed_ips", "--allowed-ips"),
            ("keepalive", "--keepalive"),
            ("endpoint", "--endpoint"),
        ):
            if field in body and body[field] is not None:
                val = str(body[field]).strip()
                if "\n" in val or "\r" in val:
                    self.send_json(400, {"error": "Bad Request", "message": f"Недопустимое значение поля {field}."})
                    return
                if val != "" or field == "endpoint":
                    args.extend([flag, val])

        if body.get("rekey"):
            args.append("--rekey")
        if body.get("rotate_token"):
            args.append("--rotate-token")

        if len(args) == 2:
            self.send_json(400, {"error": "Bad Request", "message": "Не передано ни одного поля для изменения."})
            return

        ok, out = run_manager(args)
        if not ok:
            self.send_json(400, {"error": "Update Failed", "message": out[-600:] or "Ошибка изменения клиента"})
            return

        _invalidate_pub_ip_cache()
        server, _, item = build_state_snapshot(include_configs=False, target_client=final_name, tls_enabled=self._tls_configured())
        self.send_json(200, {"ok": True, "server": server, "client": item, "output": out[-500:]})

    def handle_admin_delete(self, parsed):
        if not self._check_admin_auth():
            return
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 4 or parts[:3] != ["api", "v1", "clients"]:
            self.send_json(404, {"error": "Not Found"})
            return

        cname = parts[3]
        if not is_valid_client_name(cname):
            self.send_json(400, {"error": "Bad Request", "message": "Некорректное имя клиента."})
            return

        ok, out = run_manager(["remove-client", cname])
        if not ok:
            self.send_json(400, {"error": "Delete Failed", "message": out[-600:] or "Ошибка удаления клиента"})
            return

        _invalidate_pub_ip_cache()
        server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
        self.send_json(200, {"ok": True, "deleted": cname, "server": server, "clients": clients, "output": out[-500:]})

    # --- Client Subscription API (GET / HEAD, backward compatible) -----------

    def extract_token_and_format(self, parsed_url):
        query = urllib.parse.parse_qs(parsed_url.query)
        req_format = query.get("format", ["conf"])[0].lower()

        token = None
        if "token" in query and query["token"]:
            token = query["token"][0].strip()
        elif "sub" in query and query["sub"]:
            token = query["sub"][0].strip()

        if not token:
            auth = self.headers.get("Authorization", "").strip()
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()

        path_parts = [p for p in parsed_url.path.strip("/").split("/") if p]
        if path_parts:
            if path_parts[0] in ("vpn", "json", "rsc", "mikrotik"):
                req_format = "rsc" if path_parts[0] == "mikrotik" else path_parts[0]

            last_part = path_parts[-1]
            if last_part.endswith(".conf"):
                last_part = last_part[:-5]
                req_format = "conf"
            elif last_part.endswith(".json"):
                last_part = last_part[:-5]
                req_format = "json"
            elif last_part.endswith(".rsc"):
                last_part = last_part[:-4]
                req_format = "rsc"

            if TOKEN_RE.fullmatch(last_part):
                token = last_part

        return token, req_format

    def handle_get_or_head(self, is_head=False):
        client_ip = self._client_ip()

        if is_rate_limited(client_ip):
            self.send_json(429, {"error": "Too Many Requests", "message": "Слишком много запросов. Попробуйте через минуту."})
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/health", "/ping", "/status"):
            self.send_json(200, {
                "status": "ok",
                "service": "awg-subscription-api",
                "protocol": "AmneziaWG 3.1",
                "api_version": 2,
                "client_management": bool(load_admin_token()),
                "tls_enabled": self._tls_configured(),
                "formats": ["conf", "vpn", "json", "rsc"],
            })
            return

        token, req_format = self.extract_token_and_format(parsed_url)
        if not token:
            record_failed_attempt(client_ip)
            self.send_json(400, {
                "error": "Bad Request",
                "message": "Не указан токен. Формат: /sub/<token>, /vpn/<token>, или ?token=<token>"
            })
            return

        client_name = find_client_by_token(token)
        if not client_name:
            record_failed_attempt(client_ip)
            self.send_json(403, {"error": "Forbidden", "message": "Недействительный токен клиента."})
            return

        conf_path = Path(AWG_DIR).resolve() / f"{client_name}.conf"
        if conf_path.parent != Path(AWG_DIR).resolve() or not conf_path.is_file():
            self.send_json(404, {"error": "Not Found", "message": f"Конфиг {client_name} не найден."})
            return

        try:
            raw_bytes = conf_path.read_bytes()
            conf_str = raw_bytes.decode("utf-8")
            conf_str = sanitize_client_config(conf_str)
            raw_bytes = conf_str.encode("utf-8")
        except Exception as e:
            self.send_json(500, {"error": "Internal Error", "message": str(e)})
            return

        etag = f'"{hashlib.sha256(raw_bytes).hexdigest()[:16]}"'
        client_etag = self.headers.get("If-None-Match", "").strip()
        if client_etag and client_etag == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        if req_format == "vpn":
            out_bytes = conf_to_vpn_url(conf_str, client_name).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = f"{client_name}.vpn"
        elif req_format == "json":
            json_data = {
                "client": client_name,
                "etag": etag.strip('"'),
                "config": conf_str,
                "vpn_url": conf_to_vpn_url(conf_str, client_name),
                "updated_at": int(conf_path.stat().st_mtime)
            }
            out_bytes = json.dumps(json_data, ensure_ascii=False, indent=2).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = f"{client_name}.json"
        elif req_format in ("rsc", "mikrotik"):
            out_bytes = conf_to_mikrotik_rsc(conf_str, client_name).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = f"{client_name}.rsc"
        else:
            out_bytes = raw_bytes
            content_type = "text/plain; charset=utf-8"
            filename = f"{client_name}.conf"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(out_bytes)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("ETag", etag)
        self.send_header("X-Config-Version", etag.strip('"'))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        if not is_head:
            self.wfile.write(out_bytes)


class DualModeThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, ssl_context=None):
        self.ssl_context = ssl_context
        super().__init__(server_address, RequestHandlerClass)

    def process_request_thread(self, request, client_address):
        try:
            if self.ssl_context is not None:
                request.settimeout(5.0)
                try:
                    peek = request.recv(1, socket.MSG_PEEK)
                except (socket.timeout, OSError):
                    self.shutdown_request(request)
                    return
                if not peek:
                    self.shutdown_request(request)
                    return
                if peek == b"\x16":
                    try:
                        request = self.ssl_context.wrap_socket(request, server_side=True)
                    except (ssl.SSLError, OSError):
                        self.shutdown_request(request)
                        return
            request.settimeout(30.0)
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


class DualModeThreadedHTTPServerV6(DualModeThreadedHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()


def build_ssl_context():
    if not (os.path.isfile(API_TLS_CERT) and os.path.isfile(API_TLS_KEY)):
        try:
            os.makedirs(os.path.dirname(API_TLS_CERT), mode=0o700, exist_ok=True)
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", API_TLS_KEY, "-out", API_TLS_CERT,
                    "-days", "3650", "-nodes",
                    "-subj", "/CN=awg-api",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            os.chmod(API_TLS_CERT, 0o600)
            os.chmod(API_TLS_KEY, 0o600)
        except Exception:
            pass
    if not (os.path.isfile(API_TLS_CERT) and os.path.isfile(API_TLS_KEY)):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=API_TLS_CERT, keyfile=API_TLS_KEY)
        return ctx
    except Exception as e:
        print(f"ВНИМАНИЕ: не удалось загрузить TLS сертификат ({API_TLS_CERT}): {e}", file=sys.stderr)
        return None


def _bind_api_server(ssl_ctx):
    bind_host = (API_HOST or "").strip()
    if ":" in bind_host or (bind_host in ("", "0.0.0.0") and getattr(socket, "has_dualstack_ipv6", lambda: False)()):
        v6_host = "::" if bind_host in ("", "0.0.0.0", "::") else bind_host.strip("[]")
        try:
            httpd = DualModeThreadedHTTPServerV6((v6_host, API_PORT), SubscriptionHandler, ssl_context=ssl_ctx)
            return httpd, f"[{v6_host}]:{API_PORT}" + (" (dual-stack IPv4+IPv6)" if v6_host == "::" else " (IPv6)")
        except OSError:
            if ":" in bind_host and bind_host != "::":
                raise
    httpd = DualModeThreadedHTTPServer((bind_host or "0.0.0.0", API_PORT), SubscriptionHandler, ssl_context=ssl_ctx)
    return httpd, f"{bind_host or '0.0.0.0'}:{API_PORT}"


def run_server():
    ssl_ctx = build_ssl_context()
    try:
        httpd, listen_desc = _bind_api_server(ssl_ctx)
    except OSError as e:
        print(f"ОШИБКА: Не удалось занять порт {API_HOST}:{API_PORT}: {e}", file=sys.stderr)
        sys.exit(1)

    proto = "HTTP+HTTPS (dual-mode)" if ssl_ctx else "HTTP"
    print(f"AmneziaWG API v2 слушает на {listen_desc} [{proto}]")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка API сервера...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--detect-ip":
        pub4, pub6, diag6, local6 = detect_public_ips_with_diag()
        print(json.dumps({
            "ipv4": pub4,
            "ipv6": pub6,
            "ipv6_diag": diag6,
            "ipv6_local_addrs": local6,
        }, ensure_ascii=False))
        sys.exit(0)
    run_server()
