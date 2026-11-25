#!/usr/bin/env python3
"""
AmneziaWG 3.1 — Интерактивная двухпанельная TUI-консоль управления (v3.2.7).
Архитектура в стиле lazygit / btop на чистом Python 3 (стандартный модуль curses):
- Левая панель: 6 компактных разделов + сводка трафика и адресов.
- Правая панель: живая таблица клиентов / профилей маскировки / сетевых и сервисных действий + инспектор.
- Мгновенная навигация без мерцания и без вызова systemctl на каждое нажатие клавиши.
- Полноценные модальные окна выбора, подтверждения, ввода текста и просмотра логов.
"""

import contextlib
import curses
import glob
import json
import locale
import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

TUI_VERSION = "3.2.7"
EXIT_RELOAD_MENU = 42

AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
AWG_IFACE = os.environ.get("AWG_IFACE", "awg0")
AWG_API_PORT = os.environ.get("AWG_API_PORT", "8443")
MANAGER_BIN = os.environ.get("AWG_MANAGER_BIN", "/usr/local/bin/awg-manager")

TOKENS_FILE = os.path.join(AWG_DIR, "tokens.json")
ADMIN_TOKEN_FILE = os.path.join(AWG_DIR, "admin_token")
API_TLS_CERT = os.path.join(AWG_DIR, "api_tls.crt")
ENDPOINT_MODE_FILE = os.path.join(AWG_DIR, "endpoint_mode.conf")
MANUAL_IPV6_FILE = os.path.join(AWG_DIR, "manual_ipv6.conf")
PRESET_FILE = os.path.join(AWG_DIR, "preset.conf")
BOT_ENV_FILE = os.path.join(AWG_DIR, "bot.env")
BACKUP_DIR = "/root/awg-backups"

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RESERVED_NAMES = {"awg0", "warp0", "server", "default"}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

STEALTH_PRESETS = [
    ("quic", "HTTP/3 (QUIC)", "443/udp", "Маскировка под YouTube / HTTPS трафик (RFC 9000 QUIC v1 Initial). Рекомендуется по умолчанию."),
    ("quic-alt", "HTTP/3 (QUIC Alt)", "20000-59999", "QUIC v1 Initial на случайном высоком UDP-порту (обход фильтрации 443/udp)."),
    ("stun", "WebRTC / STUN", "3478/udp", "Маскировка под голосовые и видеозвонки Telegram / WhatsApp (RFC 5389 Binding Request)."),
    ("stun-alt", "WebRTC / STUN (Alt)", "20000-50000", "STUN Magic Cookie на высоком UDP-порту (имитация P2P медиапотока звонка)."),
    ("dtls", "DTLS 1.2 (Zoom / VoIP)", "8801/udp", "Маскировка под корпоративную видеосвязь Zoom / WebRTC DTLS ClientHello (RFC 6347)."),
    ("dns", "DNS Query (EDNS0)", "53/udp", "Маскировка под стандартные DNS-запросы с расширением EDNS0 (автообход занятого :53)."),
    ("ntp", "NTP v4 (Синхронизация)", "123/udp", "Маскировка под системную синхронизацию точного времени (RFC 5905 Client Request)."),
    ("sip", "SIP (VoIP / Телефония)", "5060/udp", "Маскировка под сигнализацию IP-телефонии SIP OPTIONS (RFC 3261)."),
    ("steam", "Steam Game (A2S)", "27015/udp", "Маскировка под игровой трафик Valve Source Engine Server Query."),
    ("minecraft", "Minecraft (RakNet)", "19132/udp", "Маскировка под пакеты RakNet Unconnected Ping игровых серверов."),
    ("discord", "Discord Voice (UDP)", "50001/udp", "Маскировка под голосовой канал Discord UDP IP Discovery."),
    ("dht", "BitTorrent DHT (BEP-5)", "6881/udp", "Маскировка под распределённую сеть обмена BitTorrent DHT Ping."),
    ("custom", "Пользовательский (Custom)", "ручной", "Свой UDP-порт и произвольная CPS-строка байткода I1 с проверкой ядром."),
]
PRESET_MAP = {p[0]: p for p in STEALTH_PRESETS}

SECTIONS = [
    ("clients", "Клиенты"),
    ("stealth", "Маскировка"),
    ("network", "Сеть / IPv6"),
    ("integrations", "API и ТГ-бот"),
    ("diagnose", "Диагностика"),
    ("system", "Обслуживание"),
]


# --- Утилиты ширины строк и форматирования ------------------------------------

def char_width(ch):
    if not ch or ord(ch) < 32:
        return 0
    eaw = unicodedata.east_asian_width(ch)
    return 2 if eaw in ("W", "F") else 1


def disp_width(s):
    return sum(char_width(c) for c in str(s or ""))


def trunc_str(s, max_cols, ellipsis="…"):
    s = str(s or "")
    if max_cols <= 0:
        return ""
    if disp_width(s) <= max_cols:
        return s
    ell_w = disp_width(ellipsis)
    if max_cols <= ell_w:
        return ellipsis[:max_cols]
    target = max_cols - ell_w
    out = []
    w = 0
    for ch in s:
        cw = char_width(ch)
        if w + cw > target:
            break
        out.append(ch)
        w += cw
    return "".join(out) + ellipsis


def pad_str(s, width, align="left"):
    t = trunc_str(s, width)
    pad = max(0, width - disp_width(t))
    if align == "right":
        return (" " * pad) + t
    if align == "center":
        left = pad // 2
        return (" " * left) + t + (" " * (pad - left))
    return t + (" " * pad)


def fmt_bytes(b):
    try:
        val = float(int(b))
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0:
            return f"{int(val)} B" if unit == "B" else f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PB"


def fmt_ago(ts, now=None):
    try:
        ts = int(ts)
    except Exception:
        return "никогда"
    if ts <= 0:
        return "никогда"
    now = int(now or time.time())
    d = max(0, now - ts)
    if d < 60:
        return f"{d}с назад"
    if d < 3600:
        return f"{d // 60}м назад"
    if d < 86400:
        return f"{d // 3600}ч назад"
    return f"{d // 86400}д назад"


def strip_ansi(text):
    return ANSI_RE.sub("", str(text or ""))


def is_valid_client_name(name):
    if not name or not isinstance(name, str):
        return False
    if not CLIENT_NAME_RE.fullmatch(name):
        return False
    if name.lower() in RESERVED_NAMES or name.endswith("-lan-bypass"):
        return False
    return True


def resolve_manager_bin():
    if os.path.isfile(MANAGER_BIN):
        return MANAGER_BIN
    sibling = str(Path(__file__).resolve().parent / "install.sh")
    if os.path.isfile(sibling):
        return sibling
    return MANAGER_BIN


# --- Сбор состояния сервера (кэшированный, без лагов на клавишах) -------------

def _parse_kv_conf(path):
    iface = {}
    peers = []
    if not os.path.isfile(path):
        return iface, peers
    sec = ""
    cur = None
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return iface, peers
    for line in lines:
        s = line.strip()
        if s == "[Interface]":
            sec = "interface"
            continue
        if s == "[Peer]":
            if cur and cur.get("public_key"):
                peers.append(cur)
            sec = "peer"
            cur = {"name": "", "public_key": "", "allowed_ips": ""}
            continue
        if s.startswith("[") and s.endswith("]"):
            sec = s[1:-1].lower()
            continue
        if sec == "interface" and "=" in line and not s.startswith("#"):
            k, v = line.split("=", 1)
            iface[k.strip()] = v.strip()
        elif sec == "peer" and cur is not None:
            if s.startswith("#") and not cur["name"]:
                cur["name"] = s.lstrip("#").strip()
            elif "=" in line:
                k, v = line.split("=", 1)
                ks, vs = k.strip(), v.strip()
                if ks == "PublicKey":
                    cur["public_key"] = vs
                elif ks == "AllowedIPs":
                    cur["allowed_ips"] = vs
    if cur and cur.get("public_key"):
        peers.append(cur)
    return iface, peers


def _detect_preset_id(iface):
    if os.path.isfile(PRESET_FILE):
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


class StateLoader:
    def __init__(self):
        self._ip_cache_ts = 0.0
        self._pub4 = ""
        self._pub6 = ""
        self.last_load_ts = 0.0
        self.data = {}

    def _detect_ips(self, force=False):
        now = time.time()
        if not force and (now - self._ip_cache_ts) < 30.0:
            return self._pub4, self._pub6
        pub4 = ""
        pub6 = ""
        try:
            out4 = subprocess.check_output(
                ["ip", "-4", "route", "get", "1.1.1.1"], stderr=subprocess.DEVNULL, timeout=1.5
            ).decode("utf-8", errors="replace")
            m = re.search(r"\bsrc\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out4)
            if m:
                pub4 = m.group(1)
        except Exception:
            pass

        if os.path.isfile(MANUAL_IPV6_FILE):
            try:
                raw = Path(MANUAL_IPV6_FILE).read_text(encoding="utf-8").strip()
                if raw:
                    pub6 = raw.splitlines()[0].split("|", 1)[0].strip()
            except Exception:
                pass
        if not pub6:
            try:
                out6 = subprocess.check_output(
                    ["ip", "-6", "-o", "addr", "show", "scope", "global"],
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                ).decode("utf-8", errors="replace")
                for ln in out6.splitlines():
                    parts = ln.split()
                    if len(parts) >= 4 and not re.match(r"^(lo|awg|wg|warp|docker|br-|veth|tun|tap)", parts[1]):
                        cand = parts[3].split("/")[0]
                        low = cand.lower()
                        if re.match(r"^[23][0-9a-f]{1,3}:", low) and not low.startswith(("2001:4860:4860:", "2606:4700:4700:", "2620:fe:", "2001:db8:")):
                            pub6 = cand
                            break
            except Exception:
                pass

        self._pub4 = pub4
        self._pub6 = pub6
        self._ip_cache_ts = now
        return pub4, pub6

    def refresh(self, force_ips=False):
        now = time.time()
        srv_conf = os.path.join(AWG_DIR, f"{AWG_IFACE}.conf")
        installed = os.path.isfile(srv_conf)
        iface, peers = _parse_kv_conf(srv_conf)

        # Одним вызовом проверяем статус всех 4 systemd-юнитов (в 4 раза быстрее!)
        units = [f"awg-quick@{AWG_IFACE}", "awg-api", "awg-bot", "awg-rotate.timer"]
        unit_states = {u: False for u in units}
        try:
            proc = subprocess.run(
                ["systemctl", "is-active"] + units,
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            lines = (proc.stdout or "").splitlines()
            for u, st in zip(units, lines):
                unit_states[u] = st.strip() == "active"
        except Exception:
            pass

        dump_stats = {}
        if installed:
            try:
                out = subprocess.check_output(
                    ["awg", "show", AWG_IFACE, "dump"], stderr=subprocess.DEVNULL, timeout=2.0
                ).decode("utf-8", errors="replace")
                for ln in out.splitlines()[1:]:
                    parts = ln.split("\t")
                    if len(parts) >= 8:
                        pub = parts[0].strip()
                        dump_stats[pub] = {
                            "peer_ep": parts[2] if parts[2] != "(none)" else "",
                            "handshake": int(parts[4]) if parts[4].isdigit() else 0,
                            "rx": int(parts[5]) if parts[5].isdigit() else 0,
                            "tx": int(parts[6]) if parts[6].isdigit() else 0,
                        }
            except Exception:
                pass

        tokens_data = {}
        if os.path.isfile(TOKENS_FILE):
            try:
                td = json.loads(Path(TOKENS_FILE).read_text(encoding="utf-8"))
                if isinstance(td, dict):
                    tokens_data = td
            except Exception:
                pass

        clients = []
        now_int = int(now)
        for idx, p in enumerate(peers, 1):
            name = p.get("name") or f"client{idx}"
            pub = p.get("public_key", "")
            st = dump_stats.get(pub, {})
            hs = st.get("handshake", 0)
            online = hs > 0 and (now_int - hs) < 180

            c_iface, c_peers = _parse_kv_conf(os.path.join(AWG_DIR, f"{name}.conf"))
            c_peer0 = c_peers[0] if c_peers else {}
            # Для клиентского .conf в [Peer] нет имени, парсим через простой разбор
            c_ep, c_alw, c_ka = "", "", ""
            c_path = os.path.join(AWG_DIR, f"{name}.conf")
            if os.path.isfile(c_path):
                try:
                    sec = ""
                    for ln in Path(c_path).read_text(encoding="utf-8", errors="replace").splitlines():
                        s = ln.strip()
                        if s.startswith("[") and s.endswith("]"):
                            sec = s[1:-1].lower()
                        elif sec == "peer" and "=" in ln:
                            k, v = ln.split("=", 1)
                            ks, vs = k.strip(), v.strip()
                            if ks == "Endpoint":
                                c_ep = vs
                            elif ks == "AllowedIPs":
                                c_alw = vs
                            elif ks == "PersistentKeepalive":
                                c_ka = vs
                except Exception:
                    pass

            addr_raw = c_iface.get("Address") or p.get("allowed_ips", "")
            ip4, ip6 = "", ""
            for part in addr_raw.split(","):
                ip_part = part.strip().split("/")[0]
                if ":" in ip_part and not ip6:
                    ip6 = ip_part
                elif "." in ip_part and not ip4:
                    ip4 = ip_part

            tent = tokens_data.get(name, {})
            tok = tent.get("token", "") if isinstance(tent, dict) else (tent if isinstance(tent, str) else "")
            ep_mode = tent.get("endpoint_mode", "server") if isinstance(tent, dict) else "server"

            clients.append({
                "name": name,
                "public_key": pub,
                "ipv4": ip4,
                "ipv6": ip6,
                "allowed_ips_srv": p.get("allowed_ips", ""),
                "endpoint": c_ep,
                "endpoint_mode": ep_mode or "server",
                "dns": c_iface.get("DNS", ""),
                "mtu": c_iface.get("MTU", ""),
                "allowed_ips": c_alw,
                "keepalive": c_ka,
                "token": tok,
                "handshake": hs,
                "is_online": online,
                "rx": st.get("rx", 0),
                "tx": st.get("tx", 0),
                "peer_ep": st.get("peer_ep", ""),
            })

        pub4, pub6 = self._detect_ips(force=force_ips)
        ep_mode_srv = "ipv4"
        if os.path.isfile(ENDPOINT_MODE_FILE):
            try:
                ep_mode_srv = Path(ENDPOINT_MODE_FILE).read_text(encoding="utf-8").strip() or "ipv4"
            except Exception:
                pass

        sample_ep = ""
        for c in clients:
            if c["endpoint_mode"] == "server" and c["endpoint"]:
                sample_ep = c["endpoint"]
                break
        if not sample_ep and clients:
            sample_ep = clients[0]["endpoint"]

        srv_addr = iface.get("Address", "")
        v4_sub = ""
        v6_sub = ""
        for part in srv_addr.split(","):
            ps = part.strip()
            if "." in ps and not v4_sub:
                m = re.match(r"^(\d+\.\d+\.\d+)\.\d+/\d+", ps)
                v4_sub = f"{m.group(1)}.0/24" if m else ps
            elif ":" in ps and not v6_sub:
                v6_sub = ps

        admin_tok = ""
        if os.path.isfile(ADMIN_TOKEN_FILE):
            try:
                admin_tok = Path(ADMIN_TOKEN_FILE).read_text(encoding="utf-8").strip()
            except Exception:
                pass

        bot_cfg = {}
        if os.path.isfile(BOT_ENV_FILE):
            try:
                for ln in Path(BOT_ENV_FILE).read_text(encoding="utf-8").splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and "=" in ln:
                        k, v = ln.split("=", 1)
                        bot_cfg[k.strip()] = v.strip().strip("'\"")
            except Exception:
                pass

        sched_desc = "Выключен"
        if unit_states["awg-rotate.timer"]:
            sched_desc = "Активен (04:00)"
            timer_p = "/etc/systemd/system/awg-rotate.timer"
            if os.path.isfile(timer_p):
                try:
                    raw_t = Path(timer_p).read_text(encoding="utf-8")
                    if "01,04,07" in raw_t:
                        sched_desc = "Раз в 3 дня (04:00)"
                    elif "Sun " in raw_t:
                        sched_desc = "Еженедельно (Вс 04:00)"
                    elif "*-*-* 04:00" in raw_t:
                        sched_desc = "Ежедневно (04:00)"
                except Exception:
                    pass

        preset_id = _detect_preset_id(iface)
        preset_meta = PRESET_MAP.get(preset_id, PRESET_MAP["quic"])

        self.data = {
            "installed": installed,
            "awg_active": unit_states[f"awg-quick@{AWG_IFACE}"],
            "api_active": unit_states["awg-api"],
            "bot_active": unit_states["awg-bot"],
            "sched_active": unit_states["awg-rotate.timer"],
            "sched_desc": sched_desc,
            "listen_port": iface.get("ListenPort", "-"),
            "mtu": iface.get("MTU", "1280"),
            "disable_cookies": iface.get("DisableCookies", "") == "on",
            "preset_id": preset_id,
            "preset_label": preset_meta[1],
            "v4_subnet": v4_sub or "-",
            "v6_subnet": v6_sub or "",
            "pub4": pub4,
            "pub6": pub6,
            "ep_mode": ep_mode_srv,
            "sample_ep": sample_ep,
            "clients": clients,
            "online_count": sum(1 for c in clients if c["is_online"]),
            "total_rx": sum(c["rx"] for c in clients),
            "total_tx": sum(c["tx"] for c in clients),
            "admin_token": admin_tok,
            "tls_ready": os.path.isfile(API_TLS_CERT),
            "bot_cfg": bot_cfg,
            "now": now_int,
        }
        self.last_load_ts = now
        return self.data


# --- Низкоуровневая отрисовка и модальные окна curses -------------------------

C_NORM = 0
C_BORDER = 1
C_BORDER_ACT = 2
C_TITLE = 3
C_OK = 4
C_WARN = 5
C_ERR = 6
C_DIM = 7
C_SEL_ACT = 8
C_SEL_IDLE = 9
C_ACCENT = 10
C_HEADER_BG = 11


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_BORDER, curses.COLOR_BLUE, -1)
    curses.init_pair(C_BORDER_ACT, curses.COLOR_CYAN, -1)
    curses.init_pair(C_TITLE, curses.COLOR_WHITE, -1)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_ERR, curses.COLOR_RED, -1)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_SEL_ACT, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_SEL_IDLE, curses.COLOR_CYAN, -1)
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN, -1)
    curses.init_pair(C_HEADER_BG, curses.COLOR_WHITE, curses.COLOR_BLUE)


def safe_addstr(win, y, x, text, attr=0):
    if text is None:
        return
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    avail = w - x - (1 if y == h - 1 else 0)
    if avail <= 0:
        return
    clipped = trunc_str(text, avail, ellipsis="")
    if not clipped:
        return
    try:
        win.addstr(y, x, clipped, attr)
    except curses.error:
        pass


def draw_box(win, y, x, h, w, title="", active=False, border_attr=None):
    if h < 2 or w < 4:
        return
    b_attr = border_attr if border_attr is not None else (
        curses.color_pair(C_BORDER_ACT) | curses.A_BOLD if active else curses.color_pair(C_BORDER)
    )
    horiz = "─" * (w - 2)
    safe_addstr(win, y, x, f"╭{horiz}╮", b_attr)
    for row in range(y + 1, y + h - 1):
        safe_addstr(win, row, x, "│", b_attr)
        safe_addstr(win, row, x + w - 1, "│", b_attr)
    safe_addstr(win, y + h - 1, x, f"╰{horiz}╯", b_attr)

    if title:
        t_str = f" {trunc_str(title, max(1, w - 6))} "
        t_attr = (curses.color_pair(C_ACCENT) | curses.A_BOLD) if active else (curses.color_pair(C_TITLE) | curses.A_BOLD)
        safe_addstr(win, y, x + 2, t_str, t_attr)


def fill_rect(win, y, x, h, w, attr=0):
    blank = " " * max(0, w)
    for r in range(y, y + h):
        safe_addstr(win, r, x, blank, attr)


def read_key(win):
    """Считывает клавишу или Unicode-символ; корректно отличает чистый Esc от escape-последовательностей."""
    try:
        ch = win.get_wch()
    except curses.error:
        return None
    if ch == "\x1b":
        win.nodelay(True)
        try:
            nxt = win.get_wch()
        except curses.error:
            nxt = None
        finally:
            win.nodelay(False)
            win.timeout(3000)
        if nxt is None:
            return "ESC"
        return None
    if ch in ("\n", "\r", curses.KEY_ENTER):
        return "ENTER"
    if ch == "\t":
        return "TAB"
    if ch in ("\x7f", "\x08", curses.KEY_BACKSPACE):
        return "BACKSPACE"
    if ch == curses.KEY_UP:
        return "UP"
    if ch == curses.KEY_DOWN:
        return "DOWN"
    if ch == curses.KEY_LEFT:
        return "LEFT"
    if ch == curses.KEY_RIGHT:
        return "RIGHT"
    if ch == curses.KEY_PPAGE:
        return "PGUP"
    if ch == curses.KEY_NPAGE:
        return "PGDN"
    if ch == curses.KEY_HOME:
        return "HOME"
    if ch == curses.KEY_END:
        return "END"
    if ch == curses.KEY_RESIZE:
        return "RESIZE"
    return ch


@contextlib.contextmanager
def suspend_curses(stdscr):
    """Временно возвращает обычный терминал (для удобного копирования токенов мышкой, QR и live tcpdump)."""
    curses.def_prog_mode()
    curses.endwin()
    try:
        sys.stdout.write("\033[?25h\033[2J\033[H")
        sys.stdout.flush()
        yield
    finally:
        curses.reset_prog_mode()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        stdscr.clear()
        stdscr.refresh()


def modal_confirm(stdscr, title, lines, confirm_label="Да, выполнить", cancel_label="Отмена", danger=False, default_yes=False):
    sel = 0 if default_yes else 1
    while True:
        h, w = stdscr.getmaxyx()
        mw = min(max(50, max((disp_width(ln) for ln in lines), default=40) + 8), w - 4)
        mh = min(len(lines) + 7, h - 2)
        my = max(0, (h - mh) // 2)
        mx = max(0, (w - mw) // 2)

        fill_rect(stdscr, my, mx, mh, mw)
        b_attr = (curses.color_pair(C_ERR) | curses.A_BOLD) if danger else (curses.color_pair(C_BORDER_ACT) | curses.A_BOLD)
        draw_box(stdscr, my, mx, mh, mw, title=title, active=not danger, border_attr=b_attr)

        for idx, ln in enumerate(lines[: mh - 5]):
            safe_addstr(stdscr, my + 2 + idx, mx + 3, trunc_str(ln, mw - 6), curses.color_pair(C_TITLE))

        btn_yes = f"  {confirm_label}  "
        btn_no = f"  {cancel_label}  "
        total_bw = disp_width(btn_yes) + disp_width(btn_no) + 4
        bx = mx + max(2, (mw - total_bw) // 2)
        by = my + mh - 3

        yes_attr = (
            (curses.color_pair(C_ERR) | curses.A_REVERSE | curses.A_BOLD)
            if (sel == 0 and danger)
            else (curses.color_pair(C_SEL_ACT) | curses.A_BOLD if sel == 0 else curses.color_pair(C_DIM))
        )
        no_attr = (curses.color_pair(C_SEL_ACT) | curses.A_BOLD) if sel == 1 else curses.color_pair(C_DIM)

        safe_addstr(stdscr, by, bx, btn_yes, yes_attr)
        safe_addstr(stdscr, by, bx + disp_width(btn_yes) + 4, btn_no, no_attr)
        stdscr.refresh()

        k = read_key(stdscr)
        if k in ("LEFT", "RIGHT", "TAB", "h", "l"):
            sel = 1 - sel
        elif k in ("y", "Y"):
            return True
        elif k in ("n", "N", "ESC", "q"):
            return False
        elif k == "ENTER":
            return sel == 0


def modal_input(stdscr, title, prompt, initial="", allow_empty=False, secret=False):
    buf = list(str(initial or ""))
    pos = len(buf)
    err_hint = ""
    while True:
        h, w = stdscr.getmaxyx()
        mw = min(max(56, disp_width(prompt) + 8), w - 4)
        mh = 9 if err_hint else 8
        my = max(0, (h - mh) // 2)
        mx = max(0, (w - mw) // 2)

        fill_rect(stdscr, my, mx, mh, mw)
        draw_box(stdscr, my, mx, mh, mw, title=title, active=True)
        safe_addstr(stdscr, my + 2, mx + 3, trunc_str(prompt, mw - 6), curses.color_pair(C_TITLE))

        field_w = mw - 6
        raw_val = ("*" * len(buf)) if secret else "".join(buf)
        start_off = max(0, pos - field_w + 2)
        vis_val = raw_val[start_off : start_off + field_w - 1]
        safe_addstr(stdscr, my + 4, mx + 3, pad_str(vis_val, field_w), curses.A_UNDERLINE | curses.A_BOLD)

        if err_hint:
            safe_addstr(stdscr, my + 5, mx + 3, trunc_str(err_hint, mw - 6), curses.color_pair(C_ERR) | curses.A_BOLD)

        safe_addstr(
            stdscr,
            my + mh - 2,
            mx + 3,
            trunc_str("Enter: Подтвердить • Ctrl+U: Очистить • Esc: Отмена", mw - 6),
            curses.color_pair(C_DIM) | curses.A_DIM,
        )

        cur_x = mx + 3 + min(field_w - 1, pos - start_off)
        try:
            curses.curs_set(1)
            stdscr.move(my + 4, cur_x)
        except curses.error:
            pass
        stdscr.refresh()

        k = read_key(stdscr)
        if k is None or k == "RESIZE":
            continue
        if k == "ESC":
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            return None
        if k == "ENTER":
            res = "".join(buf).strip()
            if not res and not allow_empty:
                err_hint = "Поле не может быть пустым (Esc для отмены)"
                continue
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            return res
        if k == "BACKSPACE":
            if pos > 0:
                buf.pop(pos - 1)
                pos -= 1
        elif k == curses.KEY_DC:
            if pos < len(buf):
                buf.pop(pos)
        elif k == "LEFT":
            pos = max(0, pos - 1)
        elif k == "RIGHT":
            pos = min(len(buf), pos + 1)
        elif k == "HOME":
            pos = 0
        elif k == "END":
            pos = len(buf)
        elif k == "\x15":  # Ctrl+U
            buf.clear()
            pos = 0
        elif isinstance(k, str) and len(k) == 1 and ord(k) >= 32:
            buf.insert(pos, k)
            pos += 1
            err_hint = ""


def modal_select(stdscr, title, items, current_idx=0, subtitle=""):
    """Модальный выбор из списка [(key, label, hint), ...]. Возвращает key или None."""
    if not items:
        return None
    sel = max(0, min(current_idx, len(items) - 1))
    scroll = 0
    while True:
        h, w = stdscr.getmaxyx()
        mw = min(max(60, w - 10), 86, w - 4)
        extra_top = 1 if subtitle else 0
        max_vis = max(4, min(len(items), h - 8 - extra_top))
        mh = max_vis + 5 + extra_top
        my = max(0, (h - mh) // 2)
        mx = max(0, (w - mw) // 2)

        if sel < scroll:
            scroll = sel
        elif sel >= scroll + max_vis:
            scroll = sel - max_vis + 1

        fill_rect(stdscr, my, mx, mh, mw)
        draw_box(stdscr, my, mx, mh, mw, title=title, active=True)
        if subtitle:
            safe_addstr(stdscr, my + 1, mx + 3, trunc_str(subtitle, mw - 6), curses.color_pair(C_DIM))

        list_y = my + 2 + extra_top
        for i in range(max_vis):
            idx = scroll + i
            if idx >= len(items):
                break
            _, label, hint = items[idx]
            row_w = mw - 4
            prefix = " ▸ " if idx == sel else "   "
            right_s = f" {hint} " if hint else ""
            left_max = max(8, row_w - disp_width(prefix) - disp_width(right_s))
            line_str = prefix + pad_str(label, left_max) + right_s
            attr = (curses.color_pair(C_SEL_ACT) | curses.A_BOLD) if idx == sel else curses.color_pair(C_TITLE)
            safe_addstr(stdscr, list_y + i, mx + 2, pad_str(line_str, row_w), attr)

        safe_addstr(
            stdscr,
            my + mh - 2,
            mx + 3,
            trunc_str("↑/↓: Выбор • Enter: Применить • Esc: Назад", mw - 6),
            curses.color_pair(C_DIM) | curses.A_DIM,
        )
        stdscr.refresh()

        k = read_key(stdscr)
        if k in ("UP", "k", "K"):
            sel = (sel - 1) % len(items)
        elif k in ("DOWN", "j", "J"):
            sel = (sel + 1) % len(items)
        elif k in ("ESC", "q", "BACKSPACE"):
            return None
        elif k == "ENTER":
            return items[sel][0]


def modal_Loading(stdscr, message):
    h, w = stdscr.getmaxyx()
    mw = min(max(44, disp_width(message) + 8), w - 4)
    mh = 5
    my = max(0, (h - mh) // 2)
    mx = max(0, (w - mw) // 2)
    fill_rect(stdscr, my, mx, mh, mw)
    draw_box(stdscr, my, mx, mh, mw, title="Выполнение", active=True)
    safe_addstr(stdscr, my + 2, mx + 3, trunc_str(message, mw - 6), curses.color_pair(C_ACCENT) | curses.A_BOLD)
    stdscr.refresh()


def modal_viewer(stdscr, title, raw_text, ok=True):
    """Прокручиваемое окно просмотра вывода команд с цветовой подсветкой [OK]/[WARN]/[FAIL]."""
    clean = strip_ansi(raw_text or "(нет вывода)")
    lines = clean.splitlines() or ["(пусто)"]
    scroll = 0
    while True:
        h, w = stdscr.getmaxyx()
        mw = max(40, w - 4)
        mh = max(10, h - 2)
        my = (h - mh) // 2
        mx = (w - mw) // 2
        body_h = mh - 4
        max_scroll = max(0, len(lines) - body_h)
        scroll = max(0, min(scroll, max_scroll))

        fill_rect(stdscr, my, mx, mh, mw)
        b_attr = (curses.color_pair(C_BORDER_ACT) if ok else curses.color_pair(C_ERR)) | curses.A_BOLD
        draw_box(stdscr, my, mx, mh, mw, title=title, active=ok, border_attr=b_attr)

        for i in range(body_h):
            idx = scroll + i
            if idx >= len(lines):
                break
            ln = lines[idx]
            attr = curses.color_pair(C_TITLE)
            if "[OK]" in ln or "успешно" in ln.lower():
                attr = curses.color_pair(C_OK)
            elif "[FAIL]" in ln or "ОШИБКА" in ln:
                attr = curses.color_pair(C_ERR) | curses.A_BOLD
            elif "[WARN]" in ln or "ВНИМАНИЕ" in ln:
                attr = curses.color_pair(C_WARN)
            elif ln.strip().startswith("==>") or ln.strip().startswith("==="):
                attr = curses.color_pair(C_ACCENT) | curses.A_BOLD
            safe_addstr(stdscr, my + 1 + i, mx + 2, trunc_str(ln, mw - 4), attr)

        pos_info = f"Строки {scroll + 1}-{min(len(lines), scroll + body_h)} из {len(lines)}"
        footer = f"↑/↓/PgUp/PgDn: Прокрутка • Enter/Esc/q: Закрыть   [{pos_info}]"
        safe_addstr(stdscr, my + mh - 2, mx + 2, trunc_str(footer, mw - 4), curses.color_pair(C_DIM) | curses.A_DIM)
        stdscr.refresh()

        k = read_key(stdscr)
        if k in ("UP", "k", "K"):
            scroll -= 1
        elif k in ("DOWN", "j", "J"):
            scroll += 1
        elif k == "PGUP":
            scroll -= body_h
        elif k == "PGDN":
            scroll += body_h
        elif k == "HOME":
            scroll = 0
        elif k == "END":
            scroll = max_scroll
        elif k in ("ENTER", "ESC", "q", "Q", " "):
            return


# --- Основное приложение двухпанельной консоли --------------------------------

class AWGTuiApp:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.loader = StateLoader()
        self.state = self.loader.refresh(force_ips=True)
        self.focus = "left"  # "left" или "right"
        self.sec_idx = 0
        self.right_idx = {s[0]: 0 for s in SECTIONS}
        self.right_scroll = {s[0]: 0 for s in SECTIONS}
        self.toast = ""
        self.toast_ok = True
        self.toast_ts = 0.0
        self.exit_code = 0

    def set_toast(self, msg, ok=True):
        self.toast = msg
        self.toast_ok = ok
        self.toast_ts = time.time()

    def run_mgr(self, args, loading_msg="Выполняется команда..."):
        modal_Loading(self.stdscr, loading_msg)
        env = os.environ.copy()
        env["AWGM_PLAIN"] = "1"
        env["AWG_DIR"] = AWG_DIR
        env["AWG_API_PORT"] = str(AWG_API_PORT)
        try:
            proc = subprocess.run(
                [resolve_manager_bin()] + list(args),
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
            out = strip_ansi((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
            ok = proc.returncode == 0
        except Exception as e:
            out = str(e)
            ok = False
        self.state = self.loader.refresh(force_ips=True)
        return ok, out

    # --- Списки элементов правой панели по разделам ---------------------------

    def _network_items(self):
        s = self.state
        em = s["ep_mode"]
        return [
            ("ep_ipv4", f"Переключить Endpoint сервера на IPv4 ({s['pub4'] or 'авто'})", "● Активен" if em == "ipv4" else ""),
            ("ep_ipv6", f"Переключить Endpoint сервера на IPv6 ({s['pub6'] or 'автопоиск'})", "● Активен" if em == "ipv6" else ""),
            ("ep_custom", "Задать внешний домен или свой IP для Endpoint", f"● {em}" if em not in ("ipv4", "ipv6") else ""),
            ("set_ipv6", "Настроить публичный IPv6 вручную (WAN / Netplan)", "eth0 + маршрут"),
            ("ep_reset_all", "Сбросить индивидуальные Endpoint всех клиентов к серверному", "--all"),
        ]

    def _integration_items(self):
        s = self.state
        return [
            ("admin_show", "Показать Admin-токен API, URL и отпечаток TLS", "копирование для роутера"),
            ("admin_rotate", "Перевыпустить Admin-токен API (rotate)", "отзыв старого ключа"),
            ("api_restart", "Перезапустить сервис подписок и API (awg-api)", "● Активен" if s["api_active"] else "○ Остановлен"),
            ("bot_setup", "Настроить Telegram-бота (токен, ADMIN_ID, топик)", "bot.env"),
            ("bot_restart", "Перезапустить Telegram-бота (awg-bot)", "● Активен" if s["bot_active"] else "○ Остановлен"),
            ("logs_view", "Посмотреть последние логи awg-api и awg-bot", "journalctl"),
        ]

    def _diagnose_items(self):
        return [
            ("diag_full", "Запустить полную самодиагностику сервера (8 проверок)", "модуль, порт, NAT, пиры"),
            ("diag_live", "Перехват входящих UDP-пакетов 15 сек (diagnose-live)", "тест блокировки ТСПУ"),
            ("status_full", "Детальная сводка состояния сервера и пиров", "awg0 + трафик"),
            ("restart_awg", f"Перезапустить туннель (awg-quick@{AWG_IFACE})", "быстрый рестарт"),
        ]

    def _system_items(self):
        return [
            ("update", "Обновить awg-manager, API и бота с GitHub", "Zero-Downtime"),
            ("backup", "Создать резервную копию конфигураций (.tar.gz)", BACKUP_DIR),
            ("restore", "Восстановить конфигурацию из резервной копии", "выбор архива"),
            ("reinstall", "[!] Переустановить AmneziaWG начисто (с авто-бэкапом)", "новые ключи"),
            ("uninstall", "[!] Полное удаление AmneziaWG с сервера", "очистка системы"),
        ]

    def current_section_key(self):
        return SECTIONS[self.sec_idx][0]

    def right_count(self, sec_key=None):
        sk = sec_key or self.current_section_key()
        if sk == "clients":
            return len(self.state["clients"])
        if sk == "stealth":
            return len(STEALTH_PRESETS)
        if sk == "network":
            return len(self._network_items())
        if sk == "integrations":
            return len(self._integration_items())
        if sk == "diagnose":
            return len(self._diagnose_items())
        if sk == "system":
            return len(self._system_items())
        return 0

    def clamp_selection(self):
        for sk, _ in SECTIONS:
            cnt = self.right_count(sk)
            if cnt <= 0:
                self.right_idx[sk] = 0
                self.right_scroll[sk] = 0
            else:
                self.right_idx[sk] = max(0, min(self.right_idx[sk], cnt - 1))

    # --- Отрисовка экрана -----------------------------------------------------

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 16 or w < 64:
            safe_addstr(self.stdscr, 1, 2, f"Окно терминала слишком мало ({w}x{h}). Минимум: 64x16.", curses.color_pair(C_WARN) | curses.A_BOLD)
            safe_addstr(self.stdscr, 3, 2, "Раздвиньте окно SSH или нажмите q для выхода.", curses.color_pair(C_TITLE))
            self.stdscr.refresh()
            return

        self.clamp_selection()
        self._draw_top_bar(w)

        body_y = 3
        body_h = h - 4
        left_w = min(28, max(23, w // 4))
        right_x = left_w
        right_w = w - left_w

        self._draw_left_pane(body_y, 0, body_h, left_w)
        self._draw_right_pane(body_y, right_x, body_h, right_w)
        self._draw_bottom_bar(h - 1, w)
        self.stdscr.refresh()

    def _draw_top_bar(self, w):
        s = self.state
        draw_box(self.stdscr, 0, 0, 3, w, title=f"AmneziaWG 3.1 — Панель управления [v{TUI_VERSION}]", active=True)

        # Индикаторы в шапке
        x = 2
        if s["awg_active"]:
            safe_addstr(self.stdscr, 1, x, "●", curses.color_pair(C_OK) | curses.A_BOLD)
            st_txt = f" {AWG_IFACE} :{s['listen_port']}/udp"
        else:
            safe_addstr(self.stdscr, 1, x, "●", curses.color_pair(C_ERR) | curses.A_BOLD)
            st_txt = f" {AWG_IFACE} остановлен"
        safe_addstr(self.stdscr, 1, x + 1, st_txt, curses.color_pair(C_TITLE) | curses.A_BOLD)
        x += 1 + disp_width(st_txt) + 2

        mask_txt = f"│ Маскировка: {s['preset_label']}"
        safe_addstr(self.stdscr, 1, x, trunc_str(mask_txt, max(0, w - x - 28)), curses.color_pair(C_ACCENT))
        x += disp_width(trunc_str(mask_txt, max(0, w - x - 28))) + 2

        # Правый блок индикаторов сервисов
        badges = [
            ("API", s["api_active"]),
            ("Бот", s["bot_active"]),
            ("Ротация", s["sched_active"]),
        ]
        bx = w - 25
        if bx > x:
            for label, is_on in badges:
                dot_attr = (curses.color_pair(C_OK) | curses.A_BOLD) if is_on else curses.color_pair(C_DIM) | curses.A_DIM
                safe_addstr(self.stdscr, 1, bx, "●", dot_attr)
                safe_addstr(self.stdscr, 1, bx + 1, f"{label} ", curses.color_pair(C_TITLE))
                bx += 2 + disp_width(label)

    def _draw_left_pane(self, y, x, h, w):
        s = self.state
        draw_box(self.stdscr, y, x, h, w, title="Разделы", active=(self.focus == "left"))

        counts = {
            "clients": f"{len(s['clients'])}",
            "stealth": "12",
            "network": "IPv6" if s["ep_mode"] == "ipv6" else "IPv4",
            "integrations": "",
            "diagnose": "",
            "system": "",
        }

        for idx, (sk, label) in enumerate(SECTIONS):
            ry = y + 1 + idx
            if ry >= y + h - 1:
                break
            is_sel = idx == self.sec_idx
            badge = counts.get(sk, "")
            badge_s = f"[{badge}]" if badge else ""
            prefix = f"▸ {idx + 1}. " if is_sel else f"  {idx + 1}. "
            inner_w = w - 2
            lbl_w = max(4, inner_w - disp_width(prefix) - disp_width(badge_s) - 1)
            line = prefix + pad_str(label, lbl_w) + badge_s + " "

            if is_sel and self.focus == "left":
                attr = curses.color_pair(C_SEL_ACT) | curses.A_BOLD
            elif is_sel:
                attr = curses.color_pair(C_SEL_IDLE) | curses.A_BOLD | curses.A_UNDERLINE
            else:
                attr = curses.color_pair(C_TITLE)
            safe_addstr(self.stdscr, ry, x + 1, pad_str(line, inner_w), attr)

        # Нижний блок живой сводки в левой панели
        div_y = y + len(SECTIONS) + 2
        if div_y < y + h - 5:
            b_attr = curses.color_pair(C_BORDER_ACT) if self.focus == "left" else curses.color_pair(C_BORDER)
            safe_addstr(self.stdscr, div_y, x, "├" + ("─" * (w - 2)) + "┤", b_attr)
            info_lines = [
                ("Онлайн:", f"{s['online_count']} / {len(s['clients'])}"),
                ("↓TX:", fmt_bytes(s["total_tx"])),
                ("↑RX:", fmt_bytes(s["total_rx"])),
                ("IPv4:", s["pub4"] or "—"),
                ("IPv6:", trunc_str(s["pub6"] or "нет", w - 9)),
                ("MTU:", str(s["mtu"])),
            ]
            for i, (k_lbl, v_lbl) in enumerate(info_lines):
                iy = div_y + 1 + i
                if iy >= y + h - 1:
                    break
                safe_addstr(self.stdscr, iy, x + 2, k_lbl, curses.color_pair(C_DIM) | curses.A_DIM)
                kx = x + 2 + disp_width(k_lbl) + 1
                safe_addstr(self.stdscr, iy, kx, trunc_str(v_lbl, w - (kx - x) - 2), curses.color_pair(C_TITLE))

    def _draw_right_pane(self, y, x, h, w):
        sk = self.current_section_key()
        if sk == "clients":
            self._draw_clients_pane(y, x, h, w)
        elif sk == "stealth":
            self._draw_stealth_pane(y, x, h, w)
        elif sk == "network":
            self._draw_action_list_pane(
                y, x, h, w,
                title="Сеть, внешний Endpoint и IPv6",
                items=self._network_items(),
                sec_key="network",
                info_lines=[
                    f"Активный Endpoint:  {self.state['sample_ep'] or 'не задан'}  (режим: {self.state['ep_mode']})",
                    f"Внешний IPv4:       {self.state['pub4'] or 'не обнаружен'}",
                    f"Внешний IPv6:       {self.state['pub6'] or 'не настроен на WAN'}",
                    f"Подсеть туннеля:    {self.state['v4_subnet']}" + (f" + {self.state['v6_subnet']}" if self.state["v6_subnet"] else ""),
                ],
            )
        elif sk == "integrations":
            adm_masked = (self.state["admin_token"][:14] + "…" + self.state["admin_token"][-6:]) if len(self.state["admin_token"]) > 24 else ("не создан")
            bot_cfg = self.state["bot_cfg"]
            self._draw_action_list_pane(
                y, x, h, w,
                title="Интеграции: HTTP/HTTPS API (:8443) и Telegram-бот",
                items=self._integration_items(),
                sec_key="integrations",
                info_lines=[
                    f"Сервис API:         {'● Работает' if self.state['api_active'] else '○ Остановлен'} (порт {AWG_API_PORT}/tcp, TLS: {'да' if self.state['tls_ready'] else 'нет'})",
                    f"Admin-токен:        {adm_masked}",
                    f"Telegram-бот:       {'● Работает' if self.state['bot_active'] else '○ Остановлен'} (ADMIN_ID: {bot_cfg.get('ADMIN_ID') or 'не задан'})",
                    f"Группа / Топик:     {bot_cfg.get('GROUP_ID') or 'только ЛС'}" + (f" / #{bot_cfg['TOPIC_ID']}" if bot_cfg.get("TOPIC_ID") else ""),
                ],
            )
        elif sk == "diagnose":
            self._draw_action_list_pane(
                y, x, h, w,
                title="Диагностика сервера и проверка блокировок ТСПУ",
                items=self._diagnose_items(),
                sec_key="diagnose",
                info_lines=[
                    f"Статус туннеля:     {'● Активен' if self.state['awg_active'] else '● Остановлен'} ({AWG_IFACE}, порт {self.state['listen_port']}/udp)",
                    f"Защита 3.1:         HPK + CPS I1 + CPA" + (" + DisableCookies" if self.state["disable_cookies"] else ""),
                    "Подсказка:          При подозрении на блок UDP провайдером запустите перехват 15с и включите клиент.",
                ],
            )
        elif sk == "system":
            self._draw_action_list_pane(
                y, x, h, w,
                title="Обновление, резервные копии и обслуживание",
                items=self._system_items(),
                sec_key="system",
                info_lines=[
                    f"Версия менеджера:   awg-manager v{TUI_VERSION}",
                    f"Каталог конфигов:   {AWG_DIR}   •   Каталог бэкапов: {BACKUP_DIR}",
                    "Внимание:           Пункты с меткой [!] меняют или удаляют ключи сервера (запрашивают подтверждение).",
                ],
            )

    def _draw_clients_pane(self, y, x, h, w):
        s = self.state
        clients = s["clients"]
        active = self.focus == "right"
        insp_h = 7 if h >= 20 else 5
        top_h = max(6, h - insp_h)

        draw_box(
            self.stdscr, y, x, top_h, w,
            title=f"Клиенты ({len(clients)} всего, {s['online_count']} онлайн) — [n] +Добавить",
            active=active,
        )

        inner_w = w - 4
        if not clients:
            safe_addstr(self.stdscr, y + 2, x + 3, "Клиентов пока нет.", curses.color_pair(C_DIM))
            safe_addstr(self.stdscr, y + 4, x + 3, "Нажмите [n] или [Enter], чтобы создать первого клиента.", curses.color_pair(C_ACCENT) | curses.A_BOLD)
            draw_box(self.stdscr, y + top_h, x, h - top_h, w, title="Инспектор клиента", active=False)
            return

        # Заголовок таблицы
        col_name = max(12, min(20, inner_w // 4))
        col_ip = max(14, min(18, inner_w // 4))
        col_hs = 13
        col_tr = max(10, inner_w - 4 - col_name - col_ip - col_hs - 3)
        hdr = f"   {pad_str('ИМЯ', col_name)} {pad_str('IPv4 ТУННЕЛЯ', col_ip)} {pad_str('HANDSHAKE', col_hs)} {pad_str('ТРАФИК ↓/↑', col_tr)}"
        safe_addstr(self.stdscr, y + 1, x + 2, trunc_str(hdr, inner_w), curses.color_pair(C_DIM) | curses.A_BOLD)

        list_h = max(1, top_h - 3)
        sel = self.right_idx["clients"]
        scr = self.right_scroll["clients"]
        if sel < scr:
            scr = sel
        elif sel >= scr + list_h:
            scr = sel - list_h + 1
        self.right_scroll["clients"] = scr

        for i in range(list_h):
            idx = scr + i
            if idx >= len(clients):
                break
            c = clients[idx]
            ry = y + 2 + i
            is_sel = idx == sel
            traf = f"↓{fmt_bytes(c['tx'])} / ↑{fmt_bytes(c['rx'])}"
            hs_str = fmt_ago(c["handshake"], s["now"])
            row_body = f"{pad_str(c['name'], col_name)} {pad_str(c['ipv4'] or '-', col_ip)} {pad_str(hs_str, col_hs)} {pad_str(traf, col_tr)}"

            if is_sel and active:
                line = f"▸ ● {row_body}"
                safe_addstr(self.stdscr, ry, x + 2, pad_str(line, inner_w), curses.color_pair(C_SEL_ACT) | curses.A_BOLD)
            else:
                row_attr = (curses.color_pair(C_SEL_IDLE) | curses.A_BOLD) if is_sel else curses.color_pair(C_TITLE)
                prefix = "▸ " if is_sel else "  "
                safe_addstr(self.stdscr, ry, x + 2, prefix, row_attr)
                dot_attr = (curses.color_pair(C_OK) | curses.A_BOLD) if c["is_online"] else (curses.color_pair(C_DIM) | curses.A_DIM)
                safe_addstr(self.stdscr, ry, x + 4, "● ", dot_attr)
                safe_addstr(self.stdscr, ry, x + 6, pad_str(row_body, inner_w - 4), row_attr)

        # Нижний инспектор выбранного клиента
        c = clients[sel]
        iy = y + top_h
        ih = h - top_h
        draw_box(self.stdscr, iy, x, ih, w, title=f"Клиент: {c['name']}", active=False)
        if ih >= 4:
            ep_info = f"Endpoint: {c['endpoint'] or '-'} [{c['endpoint_mode']}]   •   MTU: {c['mtu'] or '1280'}   •   IPv6: {c['ipv6'] or '-'}"
            safe_addstr(self.stdscr, iy + 1, x + 2, trunc_str(ep_info, inner_w), curses.color_pair(C_TITLE))
        if ih >= 5:
            alw_info = f"Маршруты: {c['allowed_ips'] or '-'}   •   DNS: {c['dns'] or '-'}"
            safe_addstr(self.stdscr, iy + 2, x + 2, trunc_str(alw_info, inner_w), curses.color_pair(C_DIM))
        if ih >= 6:
            actions = "[Enter/v] QR и конфиг   [t] Токен/ссылки   [e] Изменить   [n] +Новый   [d] Удалить"
            safe_addstr(self.stdscr, iy + ih - 2, x + 2, trunc_str(actions, inner_w), curses.color_pair(C_ACCENT) | curses.A_BOLD)

    def _draw_stealth_pane(self, y, x, h, w):
        s = self.state
        active = self.focus == "right"
        insp_h = 6
        top_h = max(6, h - insp_h)

        draw_box(
            self.stdscr, y, x, top_h, w,
            title=f"Профили маскировки ТСПУ — активен: {s['preset_label']} ({s['listen_port']}/udp)",
            active=active,
        )
        inner_w = w - 4
        list_h = max(1, top_h - 2)
        sel = self.right_idx["stealth"]
        scr = self.right_scroll["stealth"]
        if sel < scr:
            scr = sel
        elif sel >= scr + list_h:
            scr = sel - list_h + 1
        self.right_scroll["stealth"] = scr

        for i in range(list_h):
            idx = scr + i
            if idx >= len(STEALTH_PRESETS):
                break
            pid, plabel, pport, _ = STEALTH_PRESETS[idx]
            ry = y + 1 + i
            is_sel = idx == sel
            is_cur = pid == s["preset_id"]
            mark = "● АКТИВЕН" if is_cur else ""
            row_str = f"{'▸ ' if is_sel else '  '}{pad_str(plabel, 28)} {pad_str(pport, 14)} {mark}"
            if is_sel and active:
                attr = curses.color_pair(C_SEL_ACT) | curses.A_BOLD
            elif is_cur:
                attr = curses.color_pair(C_OK) | curses.A_BOLD
            elif is_sel:
                attr = curses.color_pair(C_SEL_IDLE) | curses.A_BOLD
            else:
                attr = curses.color_pair(C_TITLE)
            safe_addstr(self.stdscr, ry, x + 2, pad_str(row_str, inner_w), attr)

        pid, plabel, pport, pdesc = STEALTH_PRESETS[sel]
        iy = y + top_h
        ih = h - top_h
        draw_box(self.stdscr, iy, x, ih, w, title=f"Описание: {plabel}  •  Авто-ротация: {s['sched_desc']}", active=False)
        if ih >= 4:
            safe_addstr(self.stdscr, iy + 1, x + 2, trunc_str(pdesc, inner_w), curses.color_pair(C_TITLE))
        if ih >= 5:
            acts = "[Enter] Применить выбранный профиль   •   [p] Полная ротация сейчас   •   [s] График авто-ротации"
            safe_addstr(self.stdscr, iy + ih - 2, x + 2, trunc_str(acts, inner_w), curses.color_pair(C_ACCENT) | curses.A_BOLD)

    def _draw_action_list_pane(self, y, x, h, w, title, items, sec_key, info_lines):
        active = self.focus == "right"
        info_h = len(info_lines) + 2
        list_box_h = max(6, h - info_h)

        draw_box(self.stdscr, y, x, info_h, w, title=title, active=False)
        inner_w = w - 4
        for idx, ln in enumerate(info_lines):
            safe_addstr(self.stdscr, y + 1 + idx, x + 2, trunc_str(ln, inner_w), curses.color_pair(C_TITLE))

        ly = y + info_h
        lh = h - info_h
        draw_box(self.stdscr, ly, x, lh, w, title="Действия (↑/↓ и Enter)", active=active)

        sel = self.right_idx[sec_key]
        vis_h = max(1, lh - 2)
        scr = self.right_scroll[sec_key]
        if sel < scr:
            scr = sel
        elif sel >= scr + vis_h:
            scr = sel - vis_h + 1
        self.right_scroll[sec_key] = scr

        for i in range(vis_h):
            idx = scr + i
            if idx >= len(items):
                break
            _, label, badge = items[idx]
            ry = ly + 1 + i
            is_sel = idx == sel
            is_danger = label.startswith("[!]")
            badge_s = f" {badge} " if badge else ""
            lbl_w = max(10, inner_w - 3 - disp_width(badge_s))
            line = f"{'▸ ' if is_sel else '  '}{pad_str(label, lbl_w)}{badge_s}"
            if is_sel and active:
                attr = (curses.color_pair(C_ERR) | curses.A_REVERSE | curses.A_BOLD) if is_danger else (curses.color_pair(C_SEL_ACT) | curses.A_BOLD)
            elif is_danger:
                attr = curses.color_pair(C_ERR) | (curses.A_BOLD if is_sel else 0)
            elif is_sel:
                attr = curses.color_pair(C_SEL_IDLE) | curses.A_BOLD
            else:
                attr = curses.color_pair(C_TITLE)
            safe_addstr(self.stdscr, ry, x + 2, pad_str(line, inner_w), attr)

    def _draw_bottom_bar(self, y, w):
        if self.toast and (time.time() - self.toast_ts) < 5.0:
            attr = (curses.color_pair(C_OK) if self.toast_ok else curses.color_pair(C_ERR)) | curses.A_BOLD
            safe_addstr(self.stdscr, y, 1, pad_str(f" {self.toast}", w - 2), attr)
            return
        hint = " ↑/↓: Навигация • ←/→/Tab: Панель • 1-6: Раздел • Enter: Открыть • r: Обновить • ?: Справка • q: Выход"
        safe_addstr(self.stdscr, y, 0, pad_str(hint, w - 1), curses.color_pair(C_DIM) | curses.A_DIM)

    # --- Действия разделов ----------------------------------------------------

    def show_help(self):
        help_text = (
            "=== Горячие клавиши панели управления AmneziaWG ===\n\n"
            "НАВИГАЦИЯ:\n"
            "  ↑ / ↓ (или k / j)     Перемещение по списку в активной панели\n"
            "  → / Enter / Tab       Перейти из списка разделов в правую рабочую панель\n"
            "  ← / Esc / Backspace   Вернуться из правой панели в список разделов\n"
            "  1 .. 6                Быстрый переход сразу к нужному разделу\n"
            "  r                     Принудительно обновить статус сервисов и трафик\n"
            "  q                     Выход из панели управления\n\n"
            "РАЗДЕЛ [1] КЛИЕНТЫ:\n"
            "  Enter или v           Показать QR-код и текст .conf для сканирования/копирования\n"
            "  t                     Показать токен подписки и ссылки (.conf, vpn://, .rsc)\n"
            "  e                     Изменить клиента (имя, DNS, MTU, AllowedIPs, Endpoint, ключи)\n"
            "  n или a               Добавить нового клиента\n"
            "  d или x               Удалить выбранного клиента (с подтверждением)\n\n"
            "РАЗДЕЛ [2] МАСКИРОВКА И РОТАЦИЯ:\n"
            "  Enter                 Применить выбранный профиль маскировки (12 пресетов + Custom)\n"
            "  p                     Выполнить полную ротацию порта и ключей сервера сейчас\n"
            "  s                     Настроить расписание автоматической ночной ротации\n"
        )
        modal_viewer(self.stdscr, "Справка по управлению", help_text, ok=True)

    def action_client_qr(self, client):
        cname = client["name"]
        conf_p = os.path.join(AWG_DIR, f"{cname}.conf")
        if not os.path.isfile(conf_p):
            self.set_toast(f"Файл {conf_p} не найден", ok=False)
            return
        with suspend_curses(self.stdscr):
            print(f"\033[1;36m=== Конфигурация и QR-код клиента: {cname} ===\033[0m\n")
            try:
                with open(conf_p, "rb") as qf:
                    subprocess.run(["qrencode", "-t", "ansiutf8"], stdin=qf, check=False)
            except Exception:
                print("(утилита qrencode недоступна)")
            print(f"\n\033[1mФайл {conf_p}:\033[0m\n" + ("─" * 60))
            print(Path(conf_p).read_text(encoding="utf-8", errors="replace").strip())
            print("─" * 60)
            input("\nНажмите Enter для возврата в панель управления...")

    def action_client_token(self, client):
        cname = client["name"]
        with suspend_curses(self.stdscr):
            subprocess.run([resolve_manager_bin(), "token", cname], check=False)
            input("\nСкопируйте нужную ссылку мышкой и нажмите Enter для возврата...")
        self.state = self.loader.refresh()

    def action_client_add(self):
        name = modal_input(
            self.stdscr,
            title="Новый клиент AmneziaWG",
            prompt="Имя клиента (латиница, цифры, _ или -, например: phone, mikrotik):",
        )
        if not name:
            return
        if not is_valid_client_name(name):
            self.set_toast("Некорректное имя (допустимы A-Z, 0-9, _, -, до 32 символов)", ok=False)
            return
        ok, out = self.run_mgr(["add-client", name], f"Создаю клиента '{name}'...")
        if ok:
            self.set_toast(f"[OK] Клиент '{name}' создан", ok=True)
            # Выделяем созданного клиента и предлагаем сразу открыть QR
            for idx, c in enumerate(self.state["clients"]):
                if c["name"] == name:
                    self.right_idx["clients"] = idx
                    if modal_confirm(
                        self.stdscr,
                        title=f"Клиент '{name}' создан",
                        lines=[
                            f"IP туннеля: {c['ipv4']} / {c['ipv6']}",
                            "Показать QR-код и ссылки подписки на экране?",
                        ],
                        confirm_label="Показать QR",
                        cancel_label="Готово",
                        default_yes=True,
                    ):
                        self.action_client_qr(c)
                    break
        else:
            modal_viewer(self.stdscr, f"Ошибка создания клиента '{name}'", out, ok=False)

    def action_client_delete(self, client):
        cname = client["name"]
        if not modal_confirm(
            self.stdscr,
            title="Удаление клиента",
            lines=[
                f"Удалить клиента '{cname}' ({client['ipv4']})?",
                "Ключ доступа и постоянный токен подписки будут немедленно отозваны.",
            ],
            confirm_label=f"Удалить {cname}",
            cancel_label="Отмена",
            danger=True,
        ):
            return
        ok, out = self.run_mgr(["remove-client", cname], f"Удаляю клиента '{cname}'...")
        if ok:
            self.set_toast(f"[OK] Клиент '{cname}' удалён", ok=True)
        else:
            modal_viewer(self.stdscr, "Ошибка удаления клиента", out, ok=False)

    def action_client_edit(self, client):
        cname = client["name"]
        choices = [
            ("ep", "Сменить индивидуальный Endpoint клиента", f"сейчас: {client['endpoint_mode']}"),
            ("rename", "Переименовать клиента", cname),
            ("dns", "Изменить DNS-серверы", trunc_str(client["dns"] or "по умолчанию", 24)),
            ("mtu", "Изменить MTU туннеля", client["mtu"] or "1280"),
            ("allowed", "Изменить маршрутизируемые подсети (AllowedIPs)", trunc_str(client["allowed_ips"], 22)),
            ("rekey", "Перевыпустить ключи шифрования (--rekey)", "новая пара ключей"),
            ("rot_tok", "Перевыпустить токен подписки (--rotate-token)", "отзыв старого URL"),
        ]
        act = modal_select(self.stdscr, f"Редактирование клиента: {cname}", choices)
        if not act:
            return

        if act == "rename":
            new_n = modal_input(self.stdscr, "Переименование клиента", f"Новое имя для '{cname}':", initial=cname)
            if not new_n or new_n == cname:
                return
            ok, out = self.run_mgr(["edit-client", cname, "--rename", new_n], "Переименовываю клиента...")
        elif act == "ep":
            ep_choice = modal_select(
                self.stdscr,
                f"Endpoint для клиента '{cname}'",
                [
                    ("server", "Как у сервера по умолчанию", "рекомендуется"),
                    ("ipv4", f"Принудительно внешний IPv4 ({self.state['pub4'] or 'авто'})", "IPv4"),
                    ("ipv6", f"Принудительно внешний IPv6 ({self.state['pub6'] or 'авто'})", "IPv6"),
                    ("custom", "Указать свой домен или IP вручную", "custom"),
                ],
            )
            if not ep_choice:
                return
            ep_arg = ep_choice
            if ep_choice == "custom":
                ep_arg = modal_input(self.stdscr, "Индивидуальный Endpoint", "Введите домен или IP сервера:")
                if not ep_arg:
                    return
            ok, out = self.run_mgr(["edit-client", cname, "--endpoint", ep_arg], "Обновляю Endpoint клиента...")
        elif act == "dns":
            val = modal_input(self.stdscr, "DNS клиента", "DNS через запятую:", initial=client["dns"] or "1.1.1.1, 1.0.0.1")
            if not val:
                return
            ok, out = self.run_mgr(["edit-client", cname, "--dns", val], "Обновляю DNS клиента...")
        elif act == "mtu":
            val = modal_input(self.stdscr, "MTU клиента", "MTU (1280..9000):", initial=client["mtu"] or "1280")
            if not val:
                return
            ok, out = self.run_mgr(["edit-client", cname, "--mtu", val], "Обновляю MTU клиента...")
        elif act == "allowed":
            val = modal_input(self.stdscr, "AllowedIPs клиента", "Подсети CIDR через запятую:", initial=client["allowed_ips"] or "0.0.0.0/0, ::/0")
            if not val:
                return
            ok, out = self.run_mgr(["edit-client", cname, "--allowed-ips", val], "Обновляю AllowedIPs клиента...")
        elif act == "rekey":
            if not modal_confirm(self.stdscr, "Смена ключей клиента", [f"Перевыпустить ключи для '{cname}'?", "Клиенты без автоподписки должны будут обновить конфиг."]):
                return
            ok, out = self.run_mgr(["edit-client", cname, "--rekey"], "Перегенерирую ключи клиента...")
        elif act == "rot_tok":
            if not modal_confirm(self.stdscr, "Ротация токена подписки", [f"Перевыпустить токен подписки для '{cname}'?", "Старый URL /sub/<token> перестанет работать."], danger=True):
                return
            ok, out = self.run_mgr(["edit-client", cname, "--rotate-token"], "Перевыпускаю токен...")
        else:
            return

        if ok:
            self.set_toast(f"[OK] Параметры клиента '{cname}' обновлены", ok=True)
        else:
            modal_viewer(self.stdscr, "Ошибка изменения клиента", out, ok=False)

    def action_apply_preset(self, preset_tuple):
        pid, plabel, pport, _ = preset_tuple
        args = ["preset", pid]
        if pid == "custom":
            c_port = modal_input(self.stdscr, "Пользовательский профиль (Custom)", "UDP-порт (Enter для случайного 20000-59999):", allow_empty=True)
            if c_port is None:
                return
            c_i1 = modal_input(self.stdscr, "Пользовательский профиль (Custom)", "Строка байткода CPS I1 (например <b 0x...>, Enter = QUIC):", allow_empty=True)
            if c_i1 is None:
                return
            args.extend([c_port, c_i1])
        else:
            if not modal_confirm(
                self.stdscr,
                title="Смена профиля маскировки",
                lines=[
                    f"Переключить туннель на '{plabel}' ({pport})?",
                    "Роутеры с подпиской подхватят новый конфиг автоматически.",
                ],
                confirm_label="Применить",
            ):
                return

        ok, out = self.run_mgr(args, f"Применяю профиль маскировки '{plabel}'...")
        if ok:
            self.set_toast(f"[OK] Активирован профиль {plabel} ({self.state['listen_port']}/udp)", ok=True)
        else:
            modal_viewer(self.stdscr, "Ошибка переключения маскировки", out, ok=False)

    def action_rotate_now(self):
        if not modal_confirm(
            self.stdscr,
            title="Полная ротация сервера AmneziaWG",
            lines=[
                "Будут сменены UDP-порт, ключи сервера и параметры обфускации.",
                "Клиенты с токенами подписки (MikroTik) обновятся автоматически.",
            ],
            confirm_label="Выполнить ротацию",
        ):
            return
        ok, out = self.run_mgr(["rotate"], "Выполняю ротацию порта, ключей и обфускации...")
        if ok:
            self.set_toast(f"[OK] Ротация выполнена -> новый порт {self.state['listen_port']}/udp", ok=True)
        else:
            modal_viewer(self.stdscr, "Ошибка ротации сервера", out, ok=False)

    def action_schedule(self):
        mode = modal_select(
            self.stdscr,
            "Автоматическая ротация по расписанию (04:00)",
            [
                ("3days", "Каждые 3 дня в 04:00", "Рекомендуется"),
                ("weekly", "Раз в неделю (воскресенье, 04:00)", "weekly"),
                ("daily", "Каждый день в 04:00", "daily"),
                ("off", "Отключить автоматическую ротацию", "выкл"),
            ],
            subtitle=f"Текущий статус: {self.state['sched_desc']}",
        )
        if not mode:
            return
        ok, out = self.run_mgr(["schedule", mode], "Обновляю таймер systemd...")
        if ok:
            self.set_toast(f"[OK] Расписание ротации: {self.state['sched_desc']}", ok=True)
        else:
            modal_viewer(self.stdscr, "Ошибка настройки расписания", out, ok=False)

    def action_network(self, act_key):
        if act_key == "ep_ipv4":
            ok, out = self.run_mgr(["endpoint", "ipv4"], "Переключаю внешний Endpoint на IPv4...")
            self.set_toast("[OK] Endpoint переключён на IPv4" if ok else "Ошибка смены Endpoint", ok=ok)
            if not ok:
                modal_viewer(self.stdscr, "Ошибка смены Endpoint", out, ok=False)
        elif act_key == "ep_ipv6":
            if not self.state["pub6"]:
                # Пробуем автоподъём; если не найден — запросим вручную в модальном окне
                ok, out = self.run_mgr(["endpoint", "ipv6"], "Проверяю и активирую публичный IPv6...")
                if ok:
                    self.set_toast(f"[OK] Endpoint переключён на IPv6 ({self.state['pub6']})", ok=True)
                    return
                self.action_network("set_ipv6")
                return
            ok, out = self.run_mgr(["endpoint", "ipv6"], "Переключаю внешний Endpoint на IPv6...")
            self.set_toast(f"[OK] Endpoint переключён на IPv6 ({self.state['pub6']})" if ok else "Ошибка смены Endpoint", ok=ok)
            if not ok:
                modal_viewer(self.stdscr, "Ошибка смены Endpoint", out, ok=False)
        elif act_key == "ep_custom":
            host = modal_input(self.stdscr, "Внешний Endpoint сервера", "Введите домен или публичный IP:")
            if not host:
                return
            ok, out = self.run_mgr(["endpoint", host], f"Переключаю Endpoint на {host}...")
            if ok:
                self.set_toast(f"[OK] Endpoint сервера: {host}", ok=True)
            else:
                modal_viewer(self.stdscr, "Ошибка смены Endpoint", out, ok=False)
        elif act_key == "set_ipv6":
            ip6 = modal_input(self.stdscr, "Ручная настройка IPv6 на WAN", "Публичный IPv6 адрес VPS (например 2a01:4f8:.../64):", initial=self.state["pub6"])
            if not ip6:
                return
            gw6 = modal_input(self.stdscr, "Шлюз IPv6", "Шлюз IPv6 провайдера (Enter — вычислить ::1 автоматически):", allow_empty=True)
            if gw6 is None:
                return
            args = ["set-ipv6", ip6] + ([gw6] if gw6 else [])
            ok, out = self.run_mgr(args, f"Настраиваю IPv6 {ip6} на WAN и в Netplan...")
            if ok:
                self.set_toast(f"[OK] IPv6 {self.state['pub6']} настроен и активирован", ok=True)
            else:
                modal_viewer(self.stdscr, "Ошибка настройки IPv6", out, ok=False)
        elif act_key == "ep_reset_all":
            target = "ipv6" if self.state["ep_mode"] == "ipv6" else (self.state["ep_mode"] or "ipv4")
            if not modal_confirm(self.stdscr, "Сброс индивидуальных Endpoint", ["Перевести всех клиентов на общий Endpoint сервера (--all)?"]):
                return
            ok, out = self.run_mgr(["endpoint", target, "--all"], "Синхронизирую Endpoint всех клиентов...")
            self.set_toast("[OK] Все клиенты переведены на серверный Endpoint" if ok else "Ошибка синхронизации", ok=ok)

    def action_integrations(self, act_key):
        if act_key == "admin_show":
            with suspend_curses(self.stdscr):
                subprocess.run([resolve_manager_bin(), "admin-token", "show"], check=False)
                input("Скопируйте токен/отпечаток мышкой и нажмите Enter для возврата...")
            self.state = self.loader.refresh()
        elif act_key == "admin_rotate":
            if not modal_confirm(
                self.stdscr,
                title="Перевыпуск Admin-токена API",
                lines=[
                    "Текущий мастер-токен awg_adm_... перестанет действовать.",
                    "Потребуется обновить его в WebUI роутеров MikroTik.",
                ],
                confirm_label="Перевыпустить",
                danger=True,
            ):
                return
            ok, out = self.run_mgr(["admin-token", "rotate"], "Перевыпускаю Admin-токен API...")
            if ok:
                self.action_integrations("admin_show")
            else:
                modal_viewer(self.stdscr, "Ошибка ротации Admin-токена", out, ok=False)
        elif act_key == "api_restart":
            ok, out = self.run_mgr(["api-restart"], "Перезапускаю awg-api.service...")
            self.set_toast("[OK] API подписок перезапущен" if ok else "Ошибка рестарта awg-api", ok=ok)
        elif act_key == "bot_setup":
            cur = self.state["bot_cfg"]
            tok = modal_input(
                self.stdscr,
                "Настройка Telegram-бота (1/4)",
                "BOT_TOKEN от @BotFather:",
                initial=cur.get("BOT_TOKEN", ""),
            )
            if not tok:
                return
            adm = modal_input(
                self.stdscr,
                "Настройка Telegram-бота (2/4)",
                "ADMIN_ID (числовые User ID через запятую):",
                initial=cur.get("ADMIN_ID", ""),
            )
            if not adm:
                return
            gid = modal_input(
                self.stdscr,
                "Настройка Telegram-бота (3/4)",
                "GROUP_ID супергруппы (Enter — только личные сообщения):",
                initial=cur.get("GROUP_ID", ""),
                allow_empty=True,
            )
            if gid is None:
                return
            tid = modal_input(
                self.stdscr,
                "Настройка Telegram-бота (4/4)",
                "TOPIC_ID топика форума (Enter — без привязки к топику):",
                initial=cur.get("TOPIC_ID", ""),
                allow_empty=True,
            )
            if tid is None:
                return
            try:
                os.makedirs(AWG_DIR, mode=0o700, exist_ok=True)
                tmp_env = BOT_ENV_FILE + ".tmp"
                with open(tmp_env, "w", encoding="utf-8") as f:
                    f.write(f'BOT_TOKEN="{tok}"\nADMIN_ID="{adm}"\nGROUP_ID="{gid}"\nTOPIC_ID="{tid}"\n')
                os.chmod(tmp_env, 0o600)
                os.replace(tmp_env, BOT_ENV_FILE)
            except Exception as e:
                modal_viewer(self.stdscr, "Ошибка записи bot.env", str(e), ok=False)
                return
            ok, out = self.run_mgr(["bot"], "Устанавливаю и запускаю awg-bot.service...")
            if ok:
                self.set_toast("[OK] Telegram-бот настроен и запущен!", ok=True)
            else:
                modal_viewer(self.stdscr, "Ошибка запуска Telegram-бота", out, ok=False)
        elif act_key == "bot_restart":
            ok, out = self.run_mgr(["bot-restart"], "Перезапускаю awg-bot.service...")
            self.set_toast("[OK] Telegram-бот перезапущен" if ok else "Ошибка рестарта awg-bot", ok=ok)
        elif act_key == "logs_view":
            modal_Loading(self.stdscr, "Читаю журнал systemd...")
            try:
                out = subprocess.check_output(
                    ["journalctl", "-u", "awg-api", "-u", "awg-bot", "-n", "80", "--no-pager"],
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", errors="replace")
            except Exception as e:
                out = str(e)
            modal_viewer(self.stdscr, "Журнал awg-api и awg-bot (последние 80 строк)", out, ok=True)

    def action_diagnose(self, act_key):
        if act_key == "diag_full":
            ok, out = self.run_mgr(["diagnose"], "Выполняю самодиагностику сервера (8 проверок)...")
            modal_viewer(self.stdscr, "Результаты самодиагностики AmneziaWG", out, ok=ok)
        elif act_key == "diag_live":
            with suspend_curses(self.stdscr):
                subprocess.run([resolve_manager_bin(), "diagnose-live"], check=False)
                input("\nНажмите Enter для возврата в панель управления...")
            self.state = self.loader.refresh()
        elif act_key == "status_full":
            ok, out = self.run_mgr(["status"], "Собираю детальную сводку...")
            modal_viewer(self.stdscr, "Детальный статус сервера", out, ok=ok)
        elif act_key == "restart_awg":
            modal_Loading(self.stdscr, f"Перезапускаю awg-quick@{AWG_IFACE}...")
            rc = subprocess.run(["systemctl", "restart", f"awg-quick@{AWG_IFACE}"], capture_output=True).returncode
            self.state = self.loader.refresh()
            self.set_toast(f"[OK] Туннель {AWG_IFACE} перезапущен" if rc == 0 else "Ошибка рестарта туннеля!", ok=(rc == 0))

    def action_system(self, act_key):
        if act_key == "update":
            if not modal_confirm(
                self.stdscr,
                title="Обновление awg-manager (Zero-Downtime)",
                lines=[
                    "Скачать и установить свежие версии CLI, API, бота и TUI с GitHub?",
                    "Активные VPN-сессии клиентов прерваны не будут.",
                ],
                confirm_label="Обновить сейчас",
            ):
                return
            ok, out = self.run_mgr(["update"], "Загружаю и проверяю обновление с GitHub...")
            if ok:
                modal_viewer(self.stdscr, "Обновление успешно установлено", out, ok=True)
                self.exit_code = EXIT_RELOAD_MENU
                return "EXIT"
            modal_viewer(self.stdscr, "Ошибка обновления", out, ok=False)
        elif act_key == "backup":
            ok, out = self.run_mgr(["backup"], "Создаю архив резервной копии...")
            if ok:
                self.set_toast("[OK] Резервная копия создана в /root/awg-backups", ok=True)
            modal_viewer(self.stdscr, "Резервное копирование", out, ok=ok)
        elif act_key == "restore":
            backups = sorted(glob.glob(f"{BACKUP_DIR}/awg-backup-*.tar.gz"), reverse=True)
            choices = [(bp, os.path.basename(bp), fmt_bytes(os.path.getsize(bp))) for bp in backups[:20]]
            choices.append(("__manual__", "Указать путь к .tar.gz архиву вручную...", ""))
            picked = modal_select(self.stdscr, "Восстановление из резервной копии", choices)
            if not picked:
                return
            if picked == "__manual__":
                picked = modal_input(self.stdscr, "Путь к архиву", "Полный путь к файлу .tar.gz:")
                if not picked:
                    return
            if not modal_confirm(
                self.stdscr,
                title="Подтверждение восстановления",
                lines=[
                    f"Восстановить конфигурацию из {os.path.basename(picked)}?",
                    "Текущие файлы в /etc/amnezia/amneziawg будут перезаписаны.",
                ],
                confirm_label="Восстановить",
                danger=True,
            ):
                return
            ok, out = self.run_mgr(["restore", picked], "Восстанавливаю конфигурацию и перезапускаю сервисы...")
            modal_viewer(self.stdscr, "Результат восстановления", out, ok=ok)
        elif act_key == "reinstall":
            if not modal_confirm(
                self.stdscr,
                title="Переустановка AmneziaWG начисто",
                lines=[
                    "ВНИМАНИЕ: Все ключи сервера и клиентов будут пересозданы с нуля!",
                    "Предварительно будет сохранён бэкап в /root/awg-backups.",
                ],
                confirm_label="Переустановить",
                danger=True,
            ):
                return
            with suspend_curses(self.stdscr):
                subprocess.run([resolve_manager_bin(), "reinstall"], check=False)
                input("\nНажмите Enter для возврата в панель управления...")
            self.state = self.loader.refresh(force_ips=True)
        elif act_key == "uninstall":
            if not modal_confirm(
                self.stdscr,
                title="ПОЛНОЕ УДАЛЕНИЕ AMNEZIAWG",
                lines=[
                    "ВНИМАНИЕ: Туннель, API, Telegram-бот и пакеты AmneziaWG будут удалены!",
                    "Резервная копия конфигов сохранится в /root/awg-backups.",
                ],
                confirm_label="Удалить полностью",
                danger=True,
            ):
                return
            confirm_word = modal_input(self.stdscr, "Финальное подтверждение", "Введите слово yes для полного удаления:")
            if confirm_word != "yes":
                self.set_toast("Удаление отменено", ok=True)
                return
            with suspend_curses(self.stdscr):
                subprocess.run([resolve_manager_bin(), "uninstall"], check=False)
            self.exit_code = 0
            return "EXIT"
        return None

    def trigger_enter_on_right(self):
        sk = self.current_section_key()
        idx = self.right_idx[sk]
        if sk == "clients":
            clients = self.state["clients"]
            if not clients:
                self.action_client_add()
            else:
                self.action_client_qr(clients[idx])
        elif sk == "stealth":
            self.action_apply_preset(STEALTH_PRESETS[idx])
        elif sk == "network":
            self.action_network(self._network_items()[idx][0])
        elif sk == "integrations":
            self.action_integrations(self._integration_items()[idx][0])
        elif sk == "diagnose":
            self.action_diagnose(self._diagnose_items()[idx][0])
        elif sk == "system":
            return self.action_system(self._system_items()[idx][0])
        return None

    # --- Главный цикл событий -------------------------------------------------

    def loop(self):
        self.stdscr.keypad(True)
        self.stdscr.timeout(3000)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

        while True:
            if time.time() - self.loader.last_load_ts >= 4.0:
                self.state = self.loader.refresh()

            self.draw()
            k = read_key(self.stdscr)
            if k is None:
                continue
            if k == "RESIZE":
                continue

            # Глобальные клавиши
            if k in ("q", "Q"):
                break
            if k in ("?", "h") and self.focus == "left":
                self.show_help()
                continue
            if k == "?":
                self.show_help()
                continue
            if k in ("r", "R"):
                self.state = self.loader.refresh(force_ips=True)
                self.set_toast("Статус обновлён", ok=True)
                continue

            # Цифровой переход 1..6 к разделам
            if isinstance(k, str) and k in ("1", "2", "3", "4", "5", "6"):
                self.sec_idx = int(k) - 1
                self.focus = "right"
                continue

            if k == "TAB":
                self.focus = "right" if self.focus == "left" else "left"
                continue

            # Контекстные горячие клавиши разделов
            sk = self.current_section_key()
            if sk == "clients":
                if k in ("n", "N", "a", "A"):
                    self.action_client_add()
                    continue
                if self.state["clients"]:
                    cur_c = self.state["clients"][self.right_idx["clients"]]
                    if k in ("v", "V"):
                        self.action_client_qr(cur_c)
                        continue
                    if k in ("t", "T"):
                        self.action_client_token(cur_c)
                        continue
                    if k in ("e", "E"):
                        self.action_client_edit(cur_c)
                        continue
                    if k in ("d", "D", "x", "X"):
                        self.action_client_delete(cur_c)
                        continue
            elif sk == "stealth":
                if k in ("p", "P"):
                    self.action_rotate_now()
                    continue
                if k in ("s", "S"):
                    self.action_schedule()
                    continue

            # Навигация по панелям
            if self.focus == "left":
                if k in ("UP", "k", "K"):
                    self.sec_idx = (self.sec_idx - 1) % len(SECTIONS)
                elif k in ("DOWN", "j", "J"):
                    self.sec_idx = (self.sec_idx + 1) % len(SECTIONS)
                elif k in ("RIGHT", "ENTER", "l", "L"):
                    self.focus = "right"
                elif k == "ESC":
                    break
            else:
                cnt = self.right_count(sk)
                if k in ("LEFT", "ESC", "BACKSPACE", "h", "H"):
                    self.focus = "left"
                elif k in ("UP", "k", "K") and cnt > 0:
                    self.right_idx[sk] = (self.right_idx[sk] - 1) % cnt
                elif k in ("DOWN", "j", "J") and cnt > 0:
                    self.right_idx[sk] = (self.right_idx[sk] + 1) % cnt
                elif k == "HOME" and cnt > 0:
                    self.right_idx[sk] = 0
                elif k == "END" and cnt > 0:
                    self.right_idx[sk] = cnt - 1
                elif k == "ENTER":
                    if self.trigger_enter_on_right() == "EXIT":
                        break

        return self.exit_code


def main():
    os.environ.setdefault("ESCDELAY", "25")
    try:
        locale.setlocale(locale.LC_ALL, "")
    except Exception:
        pass

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.exit(2)
    term = os.environ.get("TERM", "")
    if not term or term == "dumb":
        sys.exit(2)

    def _run(stdscr):
        init_colors()
        app = AWGTuiApp(stdscr)
        return app.loop()

    rc = curses.wrapper(_run)
    sys.exit(rc)


if __name__ == "__main__":
    main()
