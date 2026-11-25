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
     или из доверенной локальной/туннельной сети (loopback / подсеть awg0).
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
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

API_VERSION = "3.2.7"
AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
AWG_IFACE = os.environ.get("AWG_IFACE", "awg0")
TOKENS_FILE = os.path.join(AWG_DIR, "tokens.json")
ADMIN_TOKEN_FILE = os.path.join(AWG_DIR, "admin_token")
API_TLS_CERT = os.path.join(AWG_DIR, "api_tls.crt")
API_TLS_KEY = os.path.join(AWG_DIR, "api_tls.key")
ENDPOINT_MODE_FILE = os.path.join(AWG_DIR, "endpoint_mode.conf")
MANUAL_IPV6_FILE = os.path.join(AWG_DIR, "manual_ipv6.conf")
PRESET_FILE = os.path.join(AWG_DIR, "preset.conf")
MANAGER_BIN = os.environ.get("AWG_MANAGER_BIN", "/usr/local/bin/awg-manager")
API_HOST = os.environ.get("AWG_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("AWG_API_PORT", "8443"))
ALLOW_INSECURE_ADMIN = os.environ.get("AWG_API_ALLOW_INSECURE_ADMIN", "0") == "1"
MAX_CONCURRENT_REQUESTS = 64

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RESERVED_NAMES = {"awg0", "warp0", "server", "default"}
TOKEN_RE = re.compile(r"^awg_tok_[a-f0-9]{32,64}$")
ADMIN_TOKEN_RE = re.compile(r"^awg_adm_[a-f0-9]{32,128}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ANY_SECRET_RE = re.compile(r"awg_(?:tok|adm)_[a-f0-9]{16,128}")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
CPS_I1_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_<>\s\x21-\x7e]{1,512}$")

_STATE_LOCK = threading.Lock()

# Защита от брутфорса: {bucket: [count, timestamp]}
FAILED_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 20
BAN_WINDOW_SEC = 60
MAX_TRACKED_IPS = 4096

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
# Известные публичные DNS-резолверы, которые не могут быть собственным IP интерфейса VPS
_PUBLIC_DNS_V6_NETS = (
    ipaddress.IPv6Network("2001:4860:4860::/48"),  # Google Public DNS
    ipaddress.IPv6Network("2606:4700:4700::/48"),  # Cloudflare DNS
    ipaddress.IPv6Network("2620:fe::/48"),         # Quad9
    ipaddress.IPv6Network("2620:119:35::/48"),     # OpenDNS
    ipaddress.IPv6Network("2620:119:53::/48"),     # OpenDNS
    ipaddress.IPv6Network("2a10:50c0::/32"),       # AdGuard DNS
    ipaddress.IPv6Network("2a0d:2a00::/32"),       # CleanBrowsing
    ipaddress.IPv6Network("2001:67c:28a0::/48"),   # Yandex DNS
)


def has_unsafe_chars(val):
    """Отклоняет любые управляющие символы, CR/LF и Unicode line-separators (\x85, \u2028, \u2029)."""
    if not isinstance(val, str):
        return True
    for ch in val:
        code = ord(ch)
        if code < 32 or code == 127 or ch in ("\x85", "\u2028", "\u2029"):
            return True
    if len(val.splitlines()) > 1:
        return True
    return False


def validate_dns_value(raw):
    """Проверяет список DNS-адресов (IPv4/IPv6 через запятую)."""
    if has_unsafe_chars(raw) or len(raw) > 256:
        return False
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts or len(parts) > 8:
        return False
    for p in parts:
        try:
            ipaddress.ip_address(p)
        except ValueError:
            if not HOSTNAME_RE.fullmatch(p):
                return False
    return True


def validate_allowed_ips_value(raw):
    """Проверяет список CIDR-подсетей AllowedIPs."""
    if has_unsafe_chars(raw) or len(raw) > 1024:
        return False
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts or len(parts) > 64:
        return False
    for p in parts:
        try:
            ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    return True


def validate_endpoint_value(raw):
    """Проверяет допустимое значение поля endpoint (режим или host[:port])."""
    if has_unsafe_chars(raw) or len(raw) > 255:
        return False
    s = raw.strip()
    if s.lower() in ("", "server", "default", "ipv4", "4", "ipv6", "6"):
        return True
    host, port = split_endpoint_host_port(s, default_port="443")
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.fullmatch(host))


def normalize_public_ipv6(ip_str, reject_public_dns=False):
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
    if reject_public_dns:
        for dns_net in _PUBLIC_DNS_V6_NETS:
            if addr in dns_net:
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
        # Возможен IPv6 с портом без скобок или hostname:port
        head, tail = s.rsplit(":", 1)
        if tail.isdigit():
            try:
                ip6 = ipaddress.IPv6Address(head)
                return str(ip6), tail
            except Exception:
                pass
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


def _rate_limit_bucket(ip_str):
    """Для IPv6 группирует адреса по /64 префиксу, чтобы ротация внутри /64 не обходила лимит."""
    norm = _normalize_peer_ip(ip_str)
    try:
        addr = ipaddress.ip_address(norm)
        if isinstance(addr, ipaddress.IPv6Address) and not addr.is_loopback:
            net = ipaddress.IPv6Network(f"{addr}/64", strict=False)
            return str(net)
        return str(addr)
    except Exception:
        return norm


def _check_rate_limit(store, client_ip, max_attempts, window_sec):
    bucket = _rate_limit_bucket(client_ip)
    now = time.time()
    with _STATE_LOCK:
        stale = [k for k, (_, ts) in store.items() if now - ts > window_sec]
        for k in stale:
            store.pop(k, None)
        entry = store.get(bucket)
        return bool(entry and entry[0] >= max_attempts)


def _record_failed(store, client_ip, window_sec):
    bucket = _rate_limit_bucket(client_ip)
    now = time.time()
    with _STATE_LOCK:
        if len(store) >= MAX_TRACKED_IPS and bucket not in store:
            stale = [k for k, (_, ts) in store.items() if now - ts > window_sec]
            for k in stale:
                store.pop(k, None)
            if len(store) >= MAX_TRACKED_IPS:
                oldest_key = min(store.items(), key=lambda kv: kv[1][1])[0]
                store.pop(oldest_key, None)
        entry = store.get(bucket)
        if entry:
            entry[0] += 1
            entry[1] = now
        else:
            store[bucket] = [1, now]


def is_rate_limited(client_ip):
    return _check_rate_limit(FAILED_ATTEMPTS, client_ip, MAX_FAILED_ATTEMPTS, BAN_WINDOW_SEC)


def record_failed_attempt(client_ip):
    _record_failed(FAILED_ATTEMPTS, client_ip, BAN_WINDOW_SEC)


def is_admin_rate_limited(client_ip):
    return _check_rate_limit(ADMIN_FAILED_ATTEMPTS, client_ip, ADMIN_MAX_FAILED_ATTEMPTS, ADMIN_BAN_WINDOW_SEC)


def record_admin_failed(client_ip):
    _record_failed(ADMIN_FAILED_ATTEMPTS, client_ip, ADMIN_BAN_WINDOW_SEC)


def is_private_client_ip(ip_str):
    try:
        addr = ipaddress.ip_address(_normalize_peer_ip(ip_str))
        return addr.is_loopback or addr.is_private or addr.is_link_local
    except Exception:
        return False


def is_trusted_local_or_tunnel_ip(ip_str):
    """
    Разрешает доступ без TLS только с loopback (127.0.0.0/8, ::1) или из самой
    подсети интерфейса awg0 (а не с произвольных соседей по VPC/VLAN датацентра).
    """
    try:
        addr = ipaddress.ip_address(_normalize_peer_ip(ip_str))
    except Exception:
        return False
    if addr.is_loopback:
        return True
    iface, _ = parse_server_conf()
    addr_field = iface.get("Address", "")
    for part in addr_field.split(","):
        cidr = part.strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if addr.version == net.version and addr in net:
                return True
        except ValueError:
            continue
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
    for attempt in range(2):
        try:
            with open(TOKENS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            if attempt == 0:
                time.sleep(0.02)
                continue
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
    matched = None
    for client_name, cdata in tokens_data.items():
        if isinstance(cdata, dict):
            c_token = cdata.get("token", "")
        elif isinstance(cdata, str):
            c_token = cdata
        else:
            continue

        if isinstance(c_token, str) and secrets.compare_digest(c_token, token):
            if is_valid_client_name(client_name):
                matched = client_name
    return matched


def read_manual_ipv6():
    """Читает manual_ipv6.conf (поддерживает '<ip>' или '<ip>|<plen>|<gw>')."""
    if not os.path.isfile(MANUAL_IPV6_FILE):
        return ""
    try:
        raw = Path(MANUAL_IPV6_FILE).read_text(encoding="utf-8").strip()
        if not raw:
            return ""
        first = raw.splitlines()[0].split("|", 1)[0].strip()
        return normalize_public_ipv6(first)
    except Exception:
        return ""


def sanitize_client_config(conf_str):
    """
    Безопасная нормализация клиентского конфига без искажения намеренных настроек:
    1. Очищает Endpoint от дублированных портов и гарантирует [скобки] для IPv6.
    2. НЕ перезаписывает AllowedIPs и DNS (сохраняет как кастомные CIDR/DNS, так и
       намеренный IPv4-only режим 0.0.0.0/0 на VPS без исходящего IPv6).
    3. Гарантирует MTU >= 1280 при наличии IPv6 в Address или AllowedIPs (RFC 8200 / Linux IPV6_MIN_MTU).
    """
    cleaned = conf_str.replace("\r\n", "\n").replace("\r", "\n")
    for bad_sep in ("\x85", "\u2028", "\u2029", "\x0b", "\x0c"):
        cleaned = cleaned.replace(bad_sep, " ")

    lines = []
    sec = ""
    has_ipv6 = False
    for line in cleaned.split("\n"):
        trimmed = line.strip()
        if trimmed.startswith("[") and trimmed.endswith("]"):
            sec = trimmed[1:-1].lower()
            lines.append(line)
            continue

        if sec == "peer" and trimmed.startswith("Endpoint") and "=" in line:
            prefix, val = line.split("=", 1)
            h, last_port = split_endpoint_host_port(val, default_port="443")
            if ":" in h and not h.startswith("["):
                lines.append(f"{prefix.strip()} = [{h}]:{last_port}")
            else:
                lines.append(f"{prefix.strip()} = {h}:{last_port}")
            continue

        if sec == "peer" and trimmed.startswith("AllowedIPs") and "=" in line:
            _, val = line.split("=", 1)
            if ":" in val:
                has_ipv6 = True
            lines.append(line)
            continue

        if sec == "interface" and trimmed.startswith("Address") and "=" in line:
            _, val = line.split("=", 1)
            if ":" in val:
                has_ipv6 = True
            lines.append(line)
            continue

        lines.append(line)

    if has_ipv6:
        fixed = []
        sec = ""
        for line in lines:
            trimmed = line.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                sec = trimmed[1:-1].lower()
                fixed.append(line)
                continue
            if sec == "interface" and trimmed.startswith("MTU") and "=" in line:
                prefix, val = line.split("=", 1)
                try:
                    mtu_num = int(val.strip())
                except ValueError:
                    mtu_num = 0
                if 0 < mtu_num < 1280:
                    fixed.append(f"{prefix.strip()} = 1280")
                    continue
            fixed.append(line)
        lines = fixed

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


def _ros_escape(val):
    """Экранирует строку для безопасной вставки в двойные кавычки RouterOS CLI."""
    s = str(val or "")
    out = []
    for ch in s:
        if ord(ch) < 32 or ord(ch) == 127:
            continue
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "$":
            out.append("\\$")
        elif ch == "?":
            out.append("\\?")
        else:
            out.append(ch)
    return "".join(out)


def conf_to_mikrotik_rsc(conf_text, client_name):
    """Генерирует безопасный справочный RouterOS CLI скрипт с экранированием параметров."""
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
    if not ep_port.isdigit():
        ep_port = "443"
    mtu_val = params.get("interface.MTU", "1280")
    if not mtu_val.isdigit():
        mtu_val = "1280"
    safe_client = _ros_escape(client_name)

    rsc = [
        f"# MikroTik RouterOS Configuration for client: {safe_client}",
        f"# Generated by awg-manager v{API_VERSION} at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "# Рекомендуемый способ для AmneziaWG 3.1: используйте контейнер amneziawg-mikrotik с URL подписки /sub/<token>",
        "",
        f':local awgClient "{safe_client}"',
        f':local awgEndpoint "{_ros_escape(ep_host)}"',
        f':local awgPort {ep_port}',
        f':local awgMtu {mtu_val}',
        f':local awgPrivKey "{_ros_escape(params.get("interface.PrivateKey", ""))}"',
        f':local awgPubKey "{_ros_escape(params.get("peer.PublicKey", ""))}"',
        f':local awgHpk "{_ros_escape(params.get("interface.HeaderProtectionKey", ""))}"',
        f':local awgS1 "{_ros_escape(params.get("interface.S1", ""))}"',
        f':local awgS2 "{_ros_escape(params.get("interface.S2", ""))}"',
        f':local awgS3 "{_ros_escape(params.get("interface.S3", ""))}"',
        f':local awgS4 "{_ros_escape(params.get("interface.S4", ""))}"',
        f':local awgI1 "{_ros_escape(params.get("interface.I1", ""))}"',
        f':local awgJc "{_ros_escape(params.get("interface.Jc", "4"))}"',
        f':log info ("AmneziaWG profile loaded for " . $awgClient . " -> " . $awgEndpoint . ":" . $awgPort)',
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
    with _STATE_LOCK:
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
                    ip_norm = normalize_public_ipv6(str(a.get("local", "") or ""), reject_public_dns=True)
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
            ip_norm = normalize_public_ipv6(cidr, reject_public_dns=True)
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


def _extract_ipv6_from_json_obj(obj):
    """Безопасно извлекает публичный IPv6 хоста из JSON метаданных, пропуская DNS/nameservers."""
    skip_keys = ("dns", "nameserver", "resolver", "ntp")
    cands = []

    def walk(node, parent_key=""):
        pk = parent_key.lower()
        if any(sk in pk for sk in skip_keys):
            return
        if isinstance(node, dict):
            # Прямые поля сетевых интерфейсов OpenStack / DigitalOcean / Hetzner / Vultr
            for addr_key in ("ip_address", "address", "ipv6_address", "ip"):
                val = node.get(addr_key)
                if isinstance(val, str) and ":" in val:
                    norm = normalize_public_ipv6(val, reject_public_dns=True)
                    if norm and not norm.endswith("::1"):
                        cands.append(norm)
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for item in node:
                walk(item, parent_key)
        elif isinstance(node, str) and parent_key.lower() in ("addresses", "address", "ip_address", "ipv6"):
            norm = normalize_public_ipv6(node, reject_public_dns=True)
            if norm and not norm.endswith("::1"):
                cands.append(norm)

    walk(obj)
    return cands[0] if cands else ""


def _extract_ipv6_from_netplan_text(txt):
    """Читает секции addresses: в Netplan YAML, строго пропуская блоки nameservers:."""
    in_nameservers = False
    ns_indent = -1
    in_addresses = False
    addr_indent = -1

    for raw_line in txt.splitlines():
        stripped = raw_line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        s = stripped.strip()

        if in_nameservers:
            if indent <= ns_indent:
                in_nameservers = False
            else:
                continue

        if s.startswith("nameservers:"):
            in_nameservers = True
            ns_indent = indent
            in_addresses = False
            continue

        if in_addresses and indent <= addr_indent and not s.startswith("-"):
            in_addresses = False

        if s.startswith("addresses:"):
            in_addresses = True
            addr_indent = indent
            # inline list: addresses: [2001:..., ...]
            rest = s[len("addresses:"):].strip()
            if rest.startswith("[") and rest.endswith("]"):
                for item in rest[1:-1].split(","):
                    cand = normalize_public_ipv6(item.strip().strip("'\""), reject_public_dns=True)
                    if cand and not cand.endswith("::1"):
                        return cand
                in_addresses = False
            continue

        if in_addresses and s.startswith("-"):
            val = s[1:].strip().strip("'\"")
            cand = normalize_public_ipv6(val, reject_public_dns=True)
            if cand and not cand.endswith("::1"):
                return cand
    return ""


def _discover_cloud_ipv6_readonly():
    """
    ТОЛЬКО ЧТЕНИЕ (без изменения eth0/netplan!): проверяет, выделен ли провайдером
    публичный IPv6 в IMDS / cloud-init / netplan, строго отфильтровывая DNS-серверы.
    """
    for imds_url in (
        "http://169.254.169.254/openstack/latest/network_data.json",
        "http://169.254.169.254/metadata/v1.json",
    ):
        try:
            req = urllib.request.Request(imds_url, headers={"User-Agent": "cloud-init"})
            with urllib.request.urlopen(req, timeout=0.6) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
                cand = _extract_ipv6_from_json_obj(data)
                if cand:
                    return cand, "cloud_metadata_unconfigured"
        except Exception:
            pass

    for jpat in (
        "/run/cloud-init/instance-data.json",
        "/var/lib/cloud/instance/instance-data.json",
        "/var/lib/cloud/instances/*/network-data.json",
    ):
        for fpath in glob.glob(jpat):
            if os.path.isfile(fpath):
                try:
                    data = json.loads(Path(fpath).read_text(encoding="utf-8", errors="replace"))
                    cand = _extract_ipv6_from_json_obj(data)
                    if cand:
                        return cand, "cloud_init_unconfigured"
                except Exception:
                    pass

    for np_pat in ("/etc/netplan/*.yaml", "/etc/netplan/*.yml"):
        for fpath in sorted(glob.glob(np_pat)):
            if os.path.isfile(fpath):
                try:
                    cand = _extract_ipv6_from_netplan_text(Path(fpath).read_text(encoding="utf-8", errors="replace"))
                    if cand:
                        return cand, "netplan_unconfigured"
                except Exception:
                    pass

    return "", "no_interface_ipv6"


def _probe_external_ipv6(iface_or_ip="", max_urls=3):
    urls = (
        "https://api6.ipify.org",
        "https://ipv6.icanhazip.com",
        "https://v6.ident.me",
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
            v6 = normalize_public_ipv6(resp, reject_public_dns=True)
            if v6:
                return v6
        except Exception:
            continue
    return ""


def _detect_public_ipv6_with_diag():
    """
    Чистое (read-only) определение внешнего IPv6 VPS без побочных эффектов на сетевых интерфейсах:
    1) Учитывает AWG_IPV6_ENDPOINT и manual_ipv6.conf.
    2) Проверяет маршрутизацию ядра (`ip -6 route get`), игнорируя awg/wg/warp/docker/veth.
    3) Заменяет SLAAC `temporary` на постоянный адрес того же интерфейса/префикса.
    4) Проверяет policy-routing (`from <cand>`) и `default` маршруты.
    5) Проверяет неактивированный облачный IPv6 в метаданных (только для диагностики, без мутации eth0).
    """
    env_override = normalize_public_ipv6(os.environ.get("AWG_IPV6_ENDPOINT", ""))
    if env_override:
        return env_override, [env_override], "ok"

    man_v6 = read_manual_ipv6()
    if man_v6:
        return man_v6, [man_v6], "manual_ipv6_conf"

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
        v6 = normalize_public_ipv6(rsrc, reject_public_dns=True)
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

    disc_ip, disc_diag = _discover_cloud_ipv6_readonly()
    if disc_ip:
        return disc_ip, [], disc_diag

    return "", [], "no_interface_ipv6"


def detect_public_ips_with_diag():
    now = time.time()
    with _STATE_LOCK:
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

    with _STATE_LOCK:
        _PUB_IP_CACHE["ts"] = time.time()
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


def _etag_matches(header_val, expected_hex):
    """Проверяет совпадение If-None-Match (поддерживает "etag", W/"etag", голый etag и списки)."""
    raw = (header_val or "").strip()
    if not raw or not expected_hex:
        return False
    if raw == "*":
        return True
    for part in raw.split(","):
        item = part.strip()
        if item.startswith("W/"):
            item = item[2:].strip()
        item = item.strip('"')
        if item == expected_hex:
            return True
    return False


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

    def send_json(self, status_code, data, extra_headers=None, is_head=False):
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
        if not is_head:
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

    def _check_admin_auth(self, is_head=False):
        client_ip = self._client_ip()
        if is_admin_rate_limited(client_ip):
            self.send_json(429, {"error": "Too Many Requests", "message": "Слишком много неудачных попыток авторизации."}, is_head=is_head)
            return False

        # Для не-туннельных / внешних адресов требуем TLS, если TLS настроен и не включён ALLOW_INSECURE_ADMIN
        if self._tls_configured() and not self._is_tls() and not is_trusted_local_or_tunnel_ip(client_ip) and not ALLOW_INSECURE_ADMIN:
            self.send_json(426, {
                "error": "Upgrade Required",
                "message": "Admin API требует HTTPS (используйте https://<host>:8443/api/v1/... или обращение через VPN-туннель)."
            }, is_head=is_head)
            return False

        expected = load_admin_token()
        if not expected:
            self.send_json(503, {
                "error": "Admin API Disabled",
                "message": "Admin-токен не настроен на сервере. Выполните: sudo awg-manager admin-token"
            }, is_head=is_head)
            return False

        auth = self.headers.get("Authorization", "").strip()
        provided = ""
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        elif self.headers.get("X-Admin-Token"):
            provided = self.headers.get("X-Admin-Token", "").strip()

        if not provided or not ADMIN_TOKEN_RE.fullmatch(provided) or not secrets.compare_digest(provided, expected):
            record_admin_failed(client_ip)
            self.send_json(403, {"error": "Forbidden", "message": "Недействительный Admin-токен."}, is_head=is_head)
            return False
        return True

    def do_HEAD(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_get(parsed, is_head=True)
            return
        self.handle_get_or_head(is_head=True)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            self.handle_admin_get(parsed, is_head=False)
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

    def _validate_client_fields(self, body, allow_empty_endpoint=False):
        """Валидирует опциональные поля клиента и возвращает (args_list, error_msg)."""
        out_args = []
        if "dns" in body and body["dns"] is not None:
            val = str(body["dns"]).strip()
            if val != "":
                if not validate_dns_value(val):
                    return None, "Некорректный формат DNS (укажите IPv4/IPv6 через запятую)."
                out_args.extend(["--dns", val])

        if "mtu" in body and body["mtu"] is not None:
            val = str(body["mtu"]).strip()
            if val != "":
                if not val.isdigit() or not (576 <= int(val) <= 9000):
                    return None, "Некорректный MTU (576..9000)."
                out_args.extend(["--mtu", val])

        if "allowed_ips" in body and body["allowed_ips"] is not None:
            val = str(body["allowed_ips"]).strip()
            if val != "":
                if not validate_allowed_ips_value(val):
                    return None, "Некорректный формат AllowedIPs (укажите CIDR через запятую)."
                out_args.extend(["--allowed-ips", val])

        if "keepalive" in body and body["keepalive"] is not None:
            val = str(body["keepalive"]).strip()
            if val != "":
                if not val.isdigit() or not (0 <= int(val) <= 3600):
                    return None, "Некорректный PersistentKeepalive (0..3600)."
                out_args.extend(["--keepalive", val])

        if "endpoint" in body and body["endpoint"] is not None:
            val = str(body["endpoint"]).strip()
            if val != "" or allow_empty_endpoint:
                if not validate_endpoint_value(val):
                    return None, "Некорректный Endpoint (допустимы server, ipv4, ipv6, IP или домен)."
                out_args.extend(["--endpoint", val])

        return out_args, None

    def handle_admin_get(self, parsed, is_head=False):
        if not self._check_admin_auth(is_head=is_head):
            return
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/") if p]
        if parts == ["api", "v1", "clients"] or parts == ["api", "v1", "server"]:
            server, clients, _ = build_state_snapshot(include_configs=False, tls_enabled=self._tls_configured())
            etag_hex = server["server_etag"]
            etag = f'"{etag_hex}"'
            if _etag_matches(self.headers.get("If-None-Match", ""), etag_hex):
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self.send_json(200, {"server": server, "clients": clients}, extra_headers={"ETag": etag}, is_head=is_head)
            return

        if len(parts) == 4 and parts[:3] == ["api", "v1", "clients"]:
            cname = parts[3]
            if not is_valid_client_name(cname):
                self.send_json(400, {"error": "Bad Request", "message": "Некорректное имя клиента."}, is_head=is_head)
                return
            server, _, item = build_state_snapshot(include_configs=False, target_client=cname, tls_enabled=self._tls_configured())
            if not item:
                self.send_json(404, {"error": "Not Found", "message": f"Клиент '{cname}' не найден."}, is_head=is_head)
                return
            etag = f'"{item["etag"]}"' if item.get("etag") else ""
            headers = {"ETag": etag} if etag else None
            self.send_json(200, {"server": server, "client": item}, extra_headers=headers, is_head=is_head)
            return

        self.send_json(404, {"error": "Not Found"}, is_head=is_head)

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
            extra_args, ferr = self._validate_client_fields(body, allow_empty_endpoint=False)
            if ferr:
                self.send_json(400, {"error": "Bad Request", "message": ferr})
                return
            args = ["add-client", name] + extra_args

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
            if not target or not validate_endpoint_value(target):
                self.send_json(400, {"error": "Bad Request", "message": "Укажите корректный target: ipv4, ipv6 или домен/IP."})
                return
            custom_ip6 = str(body.get("ipv6", "") or "").strip()
            if custom_ip6 and target.lower() in ("ipv6", "6"):
                norm6 = normalize_public_ipv6(custom_ip6)
                if not norm6:
                    self.send_json(400, {"error": "Bad Request", "message": "Некорректный публичный IPv6 адрес."})
                    return
                target = norm6
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
                    if has_unsafe_chars(ci1) or not CPS_I1_ALLOWED_RE.fullmatch(ci1) or "<" not in ci1 or ">" not in ci1:
                        self.send_json(400, {"error": "Bad Request", "message": "Некорректная строка байткода I1 (ожидается CPS-формат <b 0x...>)."})
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
        if parts == ["api", "v1", "server/rotate"] or parts == ["api", "v1", "server", "rotate"]:
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

        extra_args, ferr = self._validate_client_fields(body, allow_empty_endpoint=True)
        if ferr:
            self.send_json(400, {"error": "Bad Request", "message": ferr})
            return
        args.extend(extra_args)

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

        if req_format == "mikrotik":
            req_format = "rsc"
        if req_format not in ("conf", "vpn", "json", "rsc"):
            req_format = "conf"
        return token, req_format

    def handle_get_or_head(self, is_head=False):
        client_ip = self._client_ip()

        if is_rate_limited(client_ip):
            self.send_json(429, {"error": "Too Many Requests", "message": "Слишком много запросов. Попробуйте через минуту."}, is_head=is_head)
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/health", "/ping", "/status"):
            self.send_json(200, {
                "status": "ok",
                "service": "awg-subscription-api",
                "version": API_VERSION,
                "protocol": "AmneziaWG 3.1",
                "api_version": 2,
                "client_management": bool(load_admin_token()),
                "tls_enabled": self._tls_configured(),
                "formats": ["conf", "vpn", "json", "rsc"],
            }, is_head=is_head)
            return

        if path == "/favicon.ico":
            self.send_json(404, {"error": "Not Found"}, is_head=is_head)
            return

        token, req_format = self.extract_token_and_format(parsed_url)
        if not token:
            record_failed_attempt(client_ip)
            self.send_json(400, {
                "error": "Bad Request",
                "message": "Не указан токен. Формат: /sub/<token>, /vpn/<token>, или ?token=<token>"
            }, is_head=is_head)
            return

        client_name = find_client_by_token(token)
        if not client_name:
            record_failed_attempt(client_ip)
            self.send_json(403, {"error": "Forbidden", "message": "Недействительный токен клиента."}, is_head=is_head)
            return

        conf_path = Path(AWG_DIR).resolve() / f"{client_name}.conf"
        if conf_path.parent != Path(AWG_DIR).resolve() or not conf_path.is_file():
            self.send_json(404, {"error": "Not Found", "message": f"Конфиг {client_name} не найден."}, is_head=is_head)
            return

        try:
            raw_bytes = conf_path.read_bytes()
            conf_str = raw_bytes.decode("utf-8")
            conf_str = sanitize_client_config(conf_str)
            raw_bytes = conf_str.encode("utf-8")
        except Exception as e:
            self.send_json(500, {"error": "Internal Error", "message": str(e)}, is_head=is_head)
            return

        base_etag_hex = hashlib.sha256(raw_bytes).hexdigest()[:16]
        if req_format == "conf":
            etag_hex = base_etag_hex
        else:
            etag_hex = hashlib.sha256(raw_bytes + b":" + req_format.encode("ascii")).hexdigest()[:16]
        etag = f'"{etag_hex}"'

        if _etag_matches(self.headers.get("If-None-Match", ""), etag_hex):
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
                "etag": base_etag_hex,
                "config": conf_str,
                "vpn_url": conf_to_vpn_url(conf_str, client_name),
                "updated_at": int(conf_path.stat().st_mtime)
            }
            out_bytes = json.dumps(json_data, ensure_ascii=False, indent=2).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = f"{client_name}.json"
        elif req_format == "rsc":
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
        self.send_header("X-Config-Version", base_etag_hex)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        if not is_head:
            self.wfile.write(out_bytes)


class DualModeThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = MAX_CONCURRENT_REQUESTS

    def __init__(self, server_address, RequestHandlerClass, ssl_context=None):
        self.ssl_context = ssl_context
        self._conn_sem = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address):
        if not self._conn_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_sem.release()
            self.shutdown_request(request)

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
            self._conn_sem.release()


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
            pub4, pub6 = detect_public_ips_cached()
            san_items = ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]
            if pub4:
                san_items.append(f"IP:{pub4}")
            if pub6:
                san_items.append(f"IP:{pub6}")
            san_ext = ",".join(san_items)
            rc = subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-keyout", API_TLS_KEY, "-out", API_TLS_CERT,
                    "-days", "3650", "-nodes",
                    "-subj", "/CN=awg-api",
                    "-addext", f"subjectAltName={san_ext}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).returncode
            if rc != 0:
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
            if os.path.isfile(API_TLS_CERT):
                os.chmod(API_TLS_CERT, 0o600)
            if os.path.isfile(API_TLS_KEY):
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
    print(f"AmneziaWG API v2 ({API_VERSION}) слушает на {listen_desc} [{proto}]")
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
