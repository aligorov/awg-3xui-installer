#!/usr/bin/env python3
"""
AmneziaWG 3.1 Telegram Management Bot (Hardened Standard Edition).
Управление клиентами (0.0.0.0/0), генерация QR-кодов, мониторинг,
ротация сервера, управление токенами и самодиагностика.
Не требует внешних pip-библиотек (чистый Python 3 стандартной библиотеки).
"""

import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

AWG_DIR = "/etc/amnezia/amneziawg"
AWG_IFACE = "awg0"
ENV_FILE = f"{AWG_DIR}/bot.env"
TOKENS_FILE = f"{AWG_DIR}/tokens.json"
MANAGER_BIN = "/usr/local/bin/awg-manager"
API_PORT = os.environ.get("AWG_API_PORT", "8443")

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RESERVED_NAMES = {"awg0", "warp0", "server", "default"}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
STATE_TTL_SEC = 600


def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip("'\"")
    for k in ("BOT_TOKEN", "ADMIN_ID", "GROUP_ID", "TOPIC_ID", "AWG_API_PORT"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


ENV = load_env()
BOT_TOKEN = str(ENV.get("BOT_TOKEN", "")).strip()
ADMIN_IDS = [
    x.strip()
    for x in str(ENV.get("ADMIN_ID", "")).split(",")
    if re.fullmatch(r"\d+", x.strip())
]
GROUP_ID = str(ENV.get("GROUP_ID", "")).strip()
TOPIC_ID = str(ENV.get("TOPIC_ID", "")).strip()
API_PORT = str(ENV.get("AWG_API_PORT", API_PORT)).strip()

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else ""

# Временное состояние пользователей {"{chat_id}_{user_id}": (state, ts)}
USER_STATE = {}


def redact(text):
    s = str(text)
    if BOT_TOKEN:
        s = s.replace(BOT_TOKEN, "***")
    return s


def strip_ansi(text):
    return ANSI_RE.sub("", str(text or ""))


def is_valid_client_name(name):
    if not isinstance(name, str) or not CLIENT_NAME_RE.fullmatch(name):
        return False
    if name.lower() in RESERVED_NAMES or name.endswith("-lan-bypass"):
        return False
    return True


def safe_awg_path(name, ext):
    if not is_valid_client_name(name):
        return None
    base = Path(AWG_DIR).resolve()
    target = (base / f"{name}.{ext}").resolve()
    if target.parent != base:
        return None
    return target


def is_admin(user_id):
    uid = str(user_id or "").strip()
    if not ADMIN_IDS or not re.fullmatch(r"\d+", uid):
        return False
    return uid in ADMIN_IDS


def check_access(chat_id, user_id, thread_id=None):
    chat_id = str(chat_id or "").strip()
    user_id = str(user_id or "").strip()
    th_id = str(thread_id) if thread_id is not None else ""

    if not is_admin(user_id):
        return False, "⛔ Доступ запрещён. Управлять VPN могут только назначенные администраторы."

    if GROUP_ID:
        if chat_id != user_id and chat_id != GROUP_ID:
            return False, "⛔ Бот настроен на работу только в назначенной группе/топике."
        if chat_id == GROUP_ID and TOPIC_ID and th_id != TOPIC_ID:
            return False, f"⛔ Команды VPN принимаются только в топике #{html.escape(TOPIC_ID)}."

    return True, ""


def set_state(user_key, state):
    now = time.time()
    stale = [k for k, (_, ts) in USER_STATE.items() if now - ts > STATE_TTL_SEC]
    for k in stale:
        USER_STATE.pop(k, None)
    USER_STATE[user_key] = (state, now)


def get_state(user_key):
    item = USER_STATE.get(user_key)
    if not item:
        return None
    state, ts = item
    if time.time() - ts > STATE_TTL_SEC:
        USER_STATE.pop(user_key, None)
        return None
    return state


def api_call(method, payload=None, files=None):
    if not BASE_URL:
        return {"ok": False, "description": "BOT_TOKEN is not configured"}

    url = f"{BASE_URL}/{method}"
    if files:
        boundary = uuid.uuid4().hex
        body = bytearray()
        if payload:
            for k, v in payload.items():
                if isinstance(v, (dict, list)):
                    v = json.dumps(v)
                body.extend(
                    f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode("utf-8")
                )
        for k, (filename, content, mime) in files.items():
            safe_name = re.sub(r'["\\\r\n/]', "_", str(filename))
            body.extend(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{safe_name}"\r\nContent-Type: {mime}\r\n\r\n'.encode("utf-8")
            )
            body.extend(content)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode("utf-8"))
        req = urllib.request.Request(
            url, data=bytes(body), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
        )
    else:
        data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        req = urllib.request.Request(url, data=data_bytes, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        print(f"API HTTP Error {e.code}: {redact(err_msg)}", file=sys.stderr)
        try:
            parsed = json.loads(err_msg)
            retry_after = parsed.get("parameters", {}).get("retry_after")
            if e.code == 429 and isinstance(retry_after, (int, float)) and 0 < retry_after <= 60:
                time.sleep(retry_after)
        except Exception:
            pass
        return {"ok": False, "description": redact(err_msg)}
    except Exception as e:
        print(f"API Request Exception: {redact(e)}", file=sys.stderr)
        return {"ok": False, "description": redact(e)}


def _apply_thread(payload, chat_id, message_thread_id):
    th = message_thread_id or (TOPIC_ID if str(chat_id).startswith("-") and TOPIC_ID else None)
    if th and str(chat_id).startswith("-"):
        try:
            payload["message_thread_id"] = int(th)
        except Exception:
            pass


def send_message(chat_id, text, reply_markup=None, message_thread_id=None, parse_mode="HTML"):
    payload = {
        "chat_id": str(chat_id),
        "text": text[:4090],
        "disable_web_page_preview": True,
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if reply_markup:
        payload["reply_markup"] = reply_markup
    _apply_thread(payload, chat_id, message_thread_id)
    return api_call("sendMessage", payload)


def send_photo(chat_id, photo_bytes, caption=None, reply_markup=None, message_thread_id=None):
    payload = {"chat_id": str(chat_id), "parse_mode": "HTML"}
    if caption:
        payload["caption"] = caption[:1020]
    if reply_markup:
        payload["reply_markup"] = reply_markup
    _apply_thread(payload, chat_id, message_thread_id)
    files = {"photo": ("qr.png", photo_bytes, "image/png")}
    return api_call("sendPhoto", payload, files=files)


def send_document(chat_id, doc_bytes, filename, caption=None, reply_markup=None, message_thread_id=None):
    payload = {"chat_id": str(chat_id), "parse_mode": "HTML"}
    if caption:
        payload["caption"] = caption[:1020]
    if reply_markup:
        payload["reply_markup"] = reply_markup
    _apply_thread(payload, chat_id, message_thread_id)
    files = {"document": (filename, doc_bytes, "application/octet-stream")}
    return api_call("sendDocument", payload, files=files)


def answer_callback(callback_id, text=None, alert=False):
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text[:200]
        payload["show_alert"] = alert
    return api_call("answerCallbackQuery", payload)


def format_bytes(b):
    try:
        b = int(b)
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"


def format_time_ago(ts):
    try:
        ts = int(ts)
    except Exception:
        return "никогда"
    if ts <= 0:
        return "никогда"
    diff = max(0, int(time.time()) - ts)
    if diff < 60:
        return f"{diff} сек назад"
    if diff < 3600:
        return f"{diff // 60} мин назад"
    if diff < 86400:
        return f"{diff // 3600} ч назад"
    return f"{diff // 86400} дн назад"


def get_client_token(name):
    if not is_valid_client_name(name):
        return None
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and name in data:
                    cdata = data[name]
                    if isinstance(cdata, dict) and cdata.get("token"):
                        return cdata["token"]
                    elif isinstance(cdata, str) and cdata.startswith("awg_tok_"):
                        return cdata
        except Exception:
            pass

    ok, out = run_manager_cmd("token", name)
    if ok:
        m = re.search(r"awg_tok_[a-f0-9]{32,64}", out)
        if m:
            return m.group(0)
    return None


def get_public_endpoint():
    conf1 = f"{AWG_DIR}/client1.conf"
    if os.path.exists(conf1):
        try:
            with open(conf1, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("Endpoint") and "=" in line:
                        ep = line.split("=", 1)[1].strip()
                        host = ep.split(":")[0].strip("[]")
                        if host:
                            return host
        except Exception:
            pass
    if "AWG_ENDPOINT" in os.environ and os.environ["AWG_ENDPOINT"]:
        return os.environ["AWG_ENDPOINT"].split(":")[0].strip("[]")
    return "YOUR_SERVER_IP"


def parse_awg_clients():
    conf_file = f"{AWG_DIR}/{AWG_IFACE}.conf"
    if not os.path.exists(conf_file):
        return []

    stats = {}
    try:
        out = subprocess.check_output(
            ["awg", "show", AWG_IFACE, "dump"], stderr=subprocess.DEVNULL, timeout=10
        ).decode("utf-8")
        for line in out.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 8:
                pubkey = parts[0]
                stats[pubkey] = {
                    "endpoint": parts[2],
                    "allowed_ips": parts[3],
                    "latest_handshake": int(parts[4]) if parts[4].isdigit() else 0,
                    "rx": int(parts[5]) if parts[5].isdigit() else 0,
                    "tx": int(parts[6]) if parts[6].isdigit() else 0,
                }
    except Exception:
        pass

    clients = []
    current = None
    with open(conf_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "[Peer]":
                if current and current.get("pubkey"):
                    clients.append(current)
                current = {"name": "", "pubkey": "", "allowed_ips": ""}
            elif line.startswith("[") and line.endswith("]"):
                if current and current.get("pubkey"):
                    clients.append(current)
                current = None
            elif line.startswith("#"):
                if current is not None and not current.get("name"):
                    current["name"] = line.lstrip("#").strip()
            elif "=" in line and current is not None:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == "PublicKey":
                    current["pubkey"] = v
                elif k == "AllowedIPs":
                    current["allowed_ips"] = v

        if current and current.get("pubkey"):
            clients.append(current)

    now = int(time.time())
    for c in clients:
        pub = c.get("pubkey", "")
        st = stats.get(pub, {})
        c["endpoint"] = st.get("endpoint", "")
        c["handshake"] = st.get("latest_handshake", 0)
        c["rx"] = st.get("rx", 0)
        c["tx"] = st.get("tx", 0)
        c["is_online"] = (now - c["handshake"] < 180) and (c["handshake"] > 0)
        if not c.get("name"):
            c["name"] = c.get("allowed_ips", "").split("/")[0] or pub[:8]

    return clients


def get_server_stats():
    conf_file = f"{AWG_DIR}/{AWG_IFACE}.conf"
    if not os.path.exists(conf_file):
        return "❌ Туннель не установлен"

    try:
        active = (
            subprocess.run(
                ["systemctl", "is-active", f"awg-quick@{AWG_IFACE}"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            == "active"
        )
    except Exception:
        active = False

    port = "?"
    has_31 = False
    has_dc = False
    try:
        with open(conf_file, "r", encoding="utf-8") as f:
            raw = f.read()
        m = re.search(r"^ListenPort\s*=\s*(\d+)", raw, re.MULTILINE)
        if m:
            port = m.group(1)
        has_31 = bool(re.search(r"^HeaderProtectionKey\s*=", raw, re.MULTILINE))
        has_dc = bool(re.search(r"^DisableCookies\s*=\s*on\b", raw, re.MULTILINE))
    except Exception:
        pass

    clients = parse_awg_clients()
    online_count = sum(1 for c in clients if c["is_online"])
    total_rx = sum(c["rx"] for c in clients)
    total_tx = sum(c["tx"] for c in clients)

    # Статус таймера авто-ротации
    sched_str = "Выкл"
    try:
        sched_act = (
            subprocess.run(
                ["systemctl", "is-active", "awg-rotate.timer"],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            == "active"
        )
        if sched_act:
            sched_str = "🟢 Активен (шедулер)"
    except Exception:
        pass

    status_icon = "🟢 Активен" if active else "🔴 Остановлен"
    proto_str = "AmneziaWG 3.1 (HPK + CPS)" if has_31 else "AmneziaWG"
    if has_dc:
        proto_str += " + DisableCookies"

    return (
        f"📊 <b>Состояние туннеля</b>\n"
        f"• Сервис: {status_icon}\n"
        f"• Интерфейс: <code>{html.escape(AWG_IFACE)}</code> ({html.escape(port)}/udp)\n"
        f"• Профиль: <code>{html.escape(proto_str)}</code>\n"
        f"• Авто-ротация: <b>{html.escape(sched_str)}</b>\n"
        f"• API подписок: <code>:{html.escape(API_PORT)}</code>\n"
        f"• Клиенты: <b>{len(clients)}</b> (🟢 <b>{online_count} онлайн</b>)\n"
        f"• Трафик клиентов: ↓ {html.escape(format_bytes(total_tx))} / ↑ {html.escape(format_bytes(total_rx))}\n"
    )


def _resolve_manager_bin():
    if os.path.exists(MANAGER_BIN):
        return MANAGER_BIN
    sibling = str(Path(__file__).resolve().parent / "install.sh")
    if os.path.exists(sibling):
        return sibling
    return MANAGER_BIN


def run_manager_cmd(action, arg=""):
    cmd = [_resolve_manager_bin(), action]
    if arg:
        cmd.append(arg)
    env = os.environ.copy()
    env["AWGM_PLAIN"] = "1"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
        combined = strip_ansi((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))
        return proc.returncode == 0, combined.strip()
    except Exception as e:
        return False, redact(e)


def handle_start(chat_id, from_id=None, thread_id=None):
    if from_id:
        USER_STATE.pop(f"{chat_id}_{from_id}", None)
    text = (
        "🛡 <b>AmneziaWG 3.1 — Защищённый VPN-сервер</b>\n\n"
        "Нативный модуль ядра с защитой от ТСПУ (QUIC мимикрия, HPK, DisableCookies).\n"
        "Весь трафик клиентов идёт через туннель (<code>0.0.0.0/0</code>).\n\n"
        "⚡ <b>Автоматическое обновление:</b> клиенты в контейнерах MikroTik обновляются по постоянным токенам при ротации сервера."
    )
    markup = {
        "inline_keyboard": [
            [{"text": "➕ Добавить клиента", "callback_data": "menu_add"}],
            [{"text": "👥 Список клиентов", "callback_data": "menu_list"}],
            [
                {"text": "🔄 Ротация сервера", "callback_data": "menu_rotate"},
                {"text": "⏱ Авто-шедулер", "callback_data": "menu_schedule"},
            ],
            [
                {"text": "📊 Статус", "callback_data": "menu_status"},
                {"text": "🩺 Диагностика", "callback_data": "menu_diagnose"},
            ],
        ]
    }
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_list_clients(chat_id, thread_id=None):
    clients = parse_awg_clients()
    if not clients:
        text = "👥 <b>Клиентов нет.</b>\nНажмите кнопку ниже, чтобы создать первого клиента:"
        markup = {"inline_keyboard": [[{"text": "➕ Добавить клиента", "callback_data": "menu_add"}]]}
        send_message(chat_id, text, markup, message_thread_id=thread_id)
        return

    text = f"👥 <b>Клиенты AmneziaWG ({len(clients)}):</b>\n\n"
    keyboard = []

    for idx, c in enumerate(clients, 1):
        name = c["name"]
        status_ico = "🟢" if c["is_online"] else "⚪"
        handshake_str = format_time_ago(c["handshake"])
        traffic_str = f"↓{format_bytes(c['tx'])} / ↑{format_bytes(c['rx'])}"
        entry = (
            f"<b>{idx}. {html.escape(name)}</b> (<code>{html.escape(c['allowed_ips'])}</code>)\n"
            f"   {status_ico} {html.escape(handshake_str)} | {html.escape(traffic_str)}\n\n"
        )
        if len(text) + len(entry) < 3800:
            text += entry

        if is_valid_client_name(name) and len(f"confirm_del_{name}".encode("utf-8")) <= 64:
            keyboard.append(
                [
                    {"text": f"📱 QR: {name}", "callback_data": f"qr_{name}"},
                    {"text": f"🔑 Токен: {name}", "callback_data": f"tok_{name}"},
                    {"text": "❌", "callback_data": f"del_{name}"},
                ]
            )

    keyboard.append(
        [
            {"text": "➕ Добавить нового", "callback_data": "menu_add"},
            {"text": "🔄 Обновить", "callback_data": "menu_list"},
        ]
    )
    keyboard.append([{"text": "« Главное меню", "callback_data": "menu_main"}])

    send_message(chat_id, text, {"inline_keyboard": keyboard}, message_thread_id=thread_id)


def handle_qr(chat_id, name, thread_id=None):
    conf_path = safe_awg_path(name, "conf")
    png_path = safe_awg_path(name, "png")
    if not conf_path or not png_path or not conf_path.exists():
        send_message(chat_id, f"❌ Конфиг клиента <code>{html.escape(name)}</code> не найден.", message_thread_id=thread_id)
        return

    conf_bytes = conf_path.read_bytes()

    if not png_path.exists():
        try:
            subprocess.run(
                ["qrencode", "-o", str(png_path), "-s", "6", "-m", "2"],
                input=conf_bytes,
                check=True,
                timeout=15,
            )
            os.chmod(png_path, 0o600)
        except Exception as e:
            print(f"Ошибка qrencode: {redact(e)}", file=sys.stderr)

    caption = (
        f"📱 <b>Клиент:</b> <code>{html.escape(name)}</code>\n"
        f"🔑 <b>Профиль:</b> AmneziaWG 3.1 (полный туннель <code>0.0.0.0/0</code>)\n\n"
        f"Сканируйте QR-код в приложении <b>Amnezia &gt;= 5.0.1.5</b> или импортируйте файл <code>{html.escape(name)}.conf</code>."
    )

    markup = {
        "inline_keyboard": [
            [{"text": f"🔑 Токен подписки: {name}", "callback_data": f"tok_{name}"}],
            [{"text": "👥 К списку клиентов", "callback_data": "menu_list"}],
        ]
    }

    if png_path.exists():
        send_photo(chat_id, png_path.read_bytes(), caption=caption, reply_markup=markup, message_thread_id=thread_id)

    send_document(
        chat_id,
        conf_bytes,
        filename=f"{name}.conf",
        caption=f"📄 <b>{html.escape(name)}.conf</b> — полный туннель (<code>AllowedIPs = 0.0.0.0/0</code>)",
        message_thread_id=thread_id,
    )


def handle_token_info(chat_id, name, thread_id=None):
    if not is_valid_client_name(name):
        send_message(chat_id, "❌ Некорректное имя клиента.", message_thread_id=thread_id)
        return

    token = get_client_token(name)
    if not token:
        send_message(chat_id, f"❌ Не удалось получить токен для <code>{html.escape(name)}</code>.", message_thread_id=thread_id)
        return

    pub_ip = get_public_endpoint()
    sub_url = f"http://{pub_ip}:{API_PORT}/sub/{token}"
    vpn_url = f"http://{pub_ip}:{API_PORT}/vpn/{token}"

    text = (
        f"🔑 <b>Данные подписки клиента:</b> <code>{html.escape(name)}</code>\n\n"
        f"• <b>Токен для контейнера:</b>\n<code>{html.escape(token)}</code>\n\n"
        f"• <b>Ссылка подписки (.conf):</b>\n<code>{html.escape(sub_url)}</code>\n\n"
        f"• <b>Ссылка Amnezia (vpn://):</b>\n<code>{html.escape(vpn_url)}</code>\n\n"
        f"💡 Вставьте токен в веб-интерфейсе контейнера AmneziaWG на роутере MikroTik. "
        f"При ротации сервера этот токен останется прежним, и клиент обновится автоматически."
    )
    markup = {
        "inline_keyboard": [
            [{"text": "📱 QR / Конфиг", "callback_data": f"qr_{name}"}],
            [{"text": "👥 К списку клиентов", "callback_data": "menu_list"}],
        ]
    }
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_add_prompt(chat_id, from_id, thread_id=None):
    set_state(f"{chat_id}_{from_id}", "waiting_client_name")
    text = (
        "➕ <b>Добавление нового клиента</b>\n\n"
        "Отправьте имя клиента сообщением в чат.\n"
        "Допустимы латинские буквы, цифры, дефис и подчёркивание (1–32 символа, например: <code>phone</code>, <code>mikrotik</code>).\n\n"
        "Для отмены отправьте /cancel или нажмите кнопку ниже:"
    )
    markup = {"inline_keyboard": [[{"text": "« Отмена", "callback_data": "menu_main"}]]}
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_create_client(chat_id, from_id, name, thread_id=None):
    USER_STATE.pop(f"{chat_id}_{from_id}", None)
    name = name.strip()
    if not is_valid_client_name(name):
        send_message(
            chat_id,
            "❌ Некорректное имя! Допустимы буквы A–Z, цифры, <code>_</code> и <code>-</code> (1–32 символа, кроме системных имён).",
            message_thread_id=thread_id,
        )
        return

    send_message(chat_id, f"⏳ Создаю клиента <code>{html.escape(name)}</code>...", message_thread_id=thread_id)
    ok, out = run_manager_cmd("add-client", name)
    if ok:
        tok = get_client_token(name)
        pub_ip = get_public_endpoint()
        sub_info = ""
        if tok:
            sub_url = f"http://{pub_ip}:{API_PORT}/sub/{tok}"
            sub_info = (
                f"\n\n🔑 <b>Токен для вебки контейнера:</b>\n<code>{html.escape(tok)}</code>\n"
                f"🌐 <b>Ссылка подписки:</b>\n<code>{html.escape(sub_url)}</code>"
            )
        send_message(chat_id, f"✅ Клиент <code>{html.escape(name)}</code> успешно добавлен!{sub_info}", message_thread_id=thread_id)
        handle_qr(chat_id, name, thread_id=thread_id)
    else:
        err_tail = html.escape(out[-600:])
        send_message(
            chat_id,
            f"❌ Ошибка добавления клиента <code>{html.escape(name)}</code>:\n<pre>{err_tail}</pre>",
            message_thread_id=thread_id,
        )


def handle_delete_confirm(chat_id, name, thread_id=None):
    if not is_valid_client_name(name):
        send_message(chat_id, "❌ Некорректное имя клиента.", message_thread_id=thread_id)
        return

    text = (
        f"⚠️ <b>Вы действительно хотите удалить клиента <code>{html.escape(name)}</code>?</b>\n"
        f"После удаления доступ через этот ключ и токен будет немедленно отозван."
    )
    markup = {
        "inline_keyboard": [
            [{"text": f"✅ Да, удалить {name}", "callback_data": f"confirm_del_{name}"}],
            [{"text": "« Отмена", "callback_data": "menu_list"}],
        ]
    }
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_delete_exec(chat_id, name, thread_id=None):
    if not is_valid_client_name(name):
        send_message(chat_id, "❌ Некорректное имя клиента.", message_thread_id=thread_id)
        return

    send_message(chat_id, f"⏳ Удаляю клиента <code>{html.escape(name)}</code>...", message_thread_id=thread_id)
    ok, out = run_manager_cmd("remove-client", name)
    if ok:
        send_message(chat_id, f"✅ Клиент <code>{html.escape(name)}</code> удалён.", message_thread_id=thread_id)
        handle_list_clients(chat_id, thread_id=thread_id)
    else:
        err_tail = html.escape(out[-600:])
        send_message(
            chat_id,
            f"❌ Ошибка удаления <code>{html.escape(name)}</code>:\n<pre>{err_tail}</pre>",
            message_thread_id=thread_id,
        )


def handle_diagnose(chat_id, thread_id=None):
    send_message(chat_id, "⏳ Запускаю самодиагностику сервера...", message_thread_id=thread_id)
    ok, out = run_manager_cmd("diagnose")
    snippet = html.escape(out[-3400:]) if out else "Нет вывода"
    prefix = "🩺 <b>Самодиагностика AmneziaWG</b>\n" if ok else "⚠️ <b>Самодиагностика завершилась с ошибкой</b>\n"
    markup = {"inline_keyboard": [[{"text": "« Главное меню", "callback_data": "menu_main"}]]}
    send_message(chat_id, f"{prefix}<pre>{snippet}</pre>", markup, message_thread_id=thread_id)


def handle_rotate_prompt(chat_id, thread_id=None):
    text = (
        "⚠️ <b>Перегенерация сервера AmneziaWG 3.1</b>\n\n"
        "Будут обновлены:\n"
        "• Случайный UDP-порт (уход из-под бана порта ТСПУ)\n"
        "• HeaderProtectionKey, CPS I1, S1–S4 и ключи шифрования\n\n"
        "⚡ <b>Клиенты с токенами (MikroTik контейнеры) обновятся автоматически!</b>\n"
        "Ручные клиенты (смартфоны) потребуют скачивания нового QR-кода.\n\n"
        "Вы действительно хотите выполнить ротацию?"
    )
    markup = {
        "inline_keyboard": [
            [{"text": "🔄 Да, выполнить ротацию", "callback_data": "confirm_rotate"}],
            [{"text": "« Отмена", "callback_data": "menu_main"}],
        ]
    }
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_rotate_exec(chat_id, thread_id=None):
    send_message(chat_id, "⏳ Выполняю перегенерацию сервера и обновление клиентов...", message_thread_id=thread_id)
    ok, out = run_manager_cmd("rotate")
    snippet = html.escape(out[-3000:]) if out else "Нет вывода"
    if ok:
        prefix = "✅ <b>Ротация AmneziaWG 3.1 успешно выполнена!</b>\n"
    else:
        prefix = "❌ <b>Ошибка ротации сервера:</b>\n"
    markup = {"inline_keyboard": [[{"text": "« Главное меню", "callback_data": "menu_main"}]]}
    send_message(chat_id, f"{prefix}<pre>{snippet}</pre>", markup, message_thread_id=thread_id)


def handle_schedule_menu(chat_id, thread_id=None):
    ok, out = run_manager_cmd("schedule", "status")
    active_str = "Выключено"
    if "Active: active" in out:
        if "3days" in out or "01,04" in out:
            active_str = "🟢 Раз в 3 дня (04:00)"
        elif "daily" in out:
            active_str = "🟢 Каждый день (04:00)"
        elif "weekly" in out or "Sun" in out:
            active_str = "🟢 Раз в неделю (04:00)"
        else:
            active_str = "🟢 Включено"

    text = (
        "⏱ <b>Автоматическая ротация сервера AmneziaWG</b>\n\n"
        "Сервер ночью сам меняет порт, ключи и сигнатуры обфускации, чтобы ТСПУ не успевал наложить блокировку.\n"
        "Клиенты с токенами (MikroTik) обновляются на лету.\n\n"
        f"Текущее расписание: <b>{html.escape(active_str)}</b>\n\n"
        "Выберите интервал:"
    )
    markup = {
        "inline_keyboard": [
            [{"text": "📅 Каждые 3 дня (04:00) [Рекомендуется]", "callback_data": "sched_3days"}],
            [{"text": "📅 Раз в неделю (04:00)", "callback_data": "sched_weekly"}],
            [{"text": "📅 Каждый день (04:00)", "callback_data": "sched_daily"}],
            [{"text": "⛔ Отключить таймер", "callback_data": "sched_off"}],
            [{"text": "« Главное меню", "callback_data": "menu_main"}],
        ]
    }
    send_message(chat_id, text, markup, message_thread_id=thread_id)


def handle_schedule_set(chat_id, mode, thread_id=None):
    ok, out = run_manager_cmd("schedule", mode)
    msg = html.escape(out[-600:]) if out else "Готово"
    send_message(chat_id, f"⏱ {msg}", message_thread_id=thread_id)
    handle_schedule_menu(chat_id, thread_id=thread_id)


def main_loop():
    if not BOT_TOKEN or not ADMIN_IDS:
        print(
            f"ОШИБКА: Задайте валидные BOT_TOKEN и числовой ADMIN_ID в {ENV_FILE} или переменных окружения",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"AmneziaWG Telegram Bot запущен. ADMIN_IDS: {len(ADMIN_IDS)}, "
        f"GROUP_ID: {GROUP_ID or 'Все'}, TOPIC_ID: {TOPIC_ID or 'Все'}, API_PORT: {API_PORT}"
    )
    offset = 0
    while True:
        try:
            updates = api_call("getUpdates", {"offset": offset, "timeout": 30})
            if not updates or not updates.get("ok"):
                time.sleep(3)
                continue

            for u in updates.get("result", []):
                offset = u["update_id"] + 1

                if "message" in u:
                    msg = u["message"]
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    from_id = str(msg.get("from", {}).get("id", ""))
                    thread_id = msg.get("message_thread_id")
                    text = msg.get("text", "").strip()
                    if not text or not chat_id or not from_id:
                        continue

                    cmd_head = text.split(None, 1)[0].split("@")[0].lower()

                    if cmd_head in ("/id", "/topic", "/chatid", "/thread"):
                        if not is_admin(from_id):
                            continue
                        title = msg.get("chat", {}).get("title", "Личные сообщения")
                        chat_type = msg.get("chat", {}).get("type", "private")
                        t_id_str = str(thread_id) if thread_id is not None else "Нет (General / ЛС)"
                        send_message(
                            chat_id,
                            f"ℹ️ <b>Информация о чате и топике:</b>\n\n"
                            f"• <b>Чат:</b> <code>{html.escape(title)}</code>\n"
                            f"• <b>Тип чата:</b> <code>{html.escape(chat_type)}</code>\n"
                            f"• <b>GROUP_ID (chat_id):</b> <code>{html.escape(chat_id)}</code>\n"
                            f"• <b>TOPIC_ID (thread_id):</b> <code>{html.escape(t_id_str)}</code>\n"
                            f"• <b>Ваш User ID:</b> <code>{html.escape(from_id)}</code>",
                            message_thread_id=thread_id,
                        )
                        continue

                    ok, err = check_access(chat_id, from_id, thread_id)
                    if not ok:
                        if chat_id == from_id:
                            send_message(chat_id, err, message_thread_id=thread_id)
                        continue

                    user_key = f"{chat_id}_{from_id}"
                    if cmd_head == "/cancel":
                        USER_STATE.pop(user_key, None)
                        handle_start(chat_id, from_id=from_id, thread_id=thread_id)
                        continue

                    state = get_state(user_key)
                    if state == "waiting_client_name" and not text.startswith("/"):
                        handle_create_client(chat_id, from_id, text, thread_id=thread_id)
                        continue

                    parts = text.split(None, 1)
                    arg = parts[1].strip() if len(parts) > 1 else ""

                    if cmd_head in ("/start", "/menu"):
                        handle_start(chat_id, from_id=from_id, thread_id=thread_id)
                    elif cmd_head in ("/clients", "/list"):
                        handle_list_clients(chat_id, thread_id=thread_id)
                    elif cmd_head == "/status":
                        send_message(chat_id, get_server_stats(), message_thread_id=thread_id)
                    elif cmd_head == "/diagnose":
                        handle_diagnose(chat_id, thread_id=thread_id)
                    elif cmd_head == "/rotate":
                        handle_rotate_prompt(chat_id, thread_id=thread_id)
                    elif cmd_head == "/schedule":
                        if arg in ("3days", "weekly", "daily", "off"):
                            handle_schedule_set(chat_id, arg, thread_id=thread_id)
                        else:
                            handle_schedule_menu(chat_id, thread_id=thread_id)
                    elif cmd_head == "/token":
                        if arg:
                            handle_token_info(chat_id, arg, thread_id=thread_id)
                        else:
                            handle_list_clients(chat_id, thread_id=thread_id)
                    elif cmd_head == "/add":
                        if arg:
                            handle_create_client(chat_id, from_id, arg, thread_id=thread_id)
                        else:
                            handle_add_prompt(chat_id, from_id=from_id, thread_id=thread_id)
                    elif cmd_head == "/qr" and arg:
                        handle_qr(chat_id, arg, thread_id=thread_id)
                    else:
                        if chat_id == from_id or text.startswith("/"):
                            handle_start(chat_id, from_id=from_id, thread_id=thread_id)

                elif "callback_query" in u:
                    cb = u["callback_query"]
                    cb_id = cb["id"]
                    from_id = str(cb.get("from", {}).get("id", ""))
                    msg = cb.get("message", {})
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    thread_id = msg.get("message_thread_id")
                    data = cb.get("data", "")

                    ok, err = check_access(chat_id, from_id, thread_id)
                    if not ok:
                        answer_callback(cb_id, "⛔ Доступ запрещён", alert=True)
                        continue

                    answer_callback(cb_id)

                    if data == "menu_main":
                        handle_start(chat_id, from_id=from_id, thread_id=thread_id)
                    elif data == "menu_list":
                        handle_list_clients(chat_id, thread_id=thread_id)
                    elif data == "menu_add":
                        handle_add_prompt(chat_id, from_id=from_id, thread_id=thread_id)
                    elif data == "menu_status":
                        send_message(chat_id, get_server_stats(), message_thread_id=thread_id)
                    elif data == "menu_diagnose":
                        handle_diagnose(chat_id, thread_id=thread_id)
                    elif data == "menu_rotate":
                        handle_rotate_prompt(chat_id, thread_id=thread_id)
                    elif data == "confirm_rotate":
                        handle_rotate_exec(chat_id, thread_id=thread_id)
                    elif data == "menu_schedule":
                        handle_schedule_menu(chat_id, thread_id=thread_id)
                    elif data.startswith("sched_"):
                        handle_schedule_set(chat_id, data[6:], thread_id=thread_id)
                    elif data.startswith("tok_"):
                        handle_token_info(chat_id, data[4:], thread_id=thread_id)
                    elif data.startswith("qr_"):
                        handle_qr(chat_id, data[3:], thread_id=thread_id)
                    elif data.startswith("del_"):
                        handle_delete_confirm(chat_id, data[4:], thread_id=thread_id)
                    elif data.startswith("confirm_del_"):
                        handle_delete_exec(chat_id, data[12:], thread_id=thread_id)

        except Exception as e:
            print(f"Ошибка в цикле polling: {redact(e)}", file=sys.stderr)
            time.sleep(3)


if __name__ == "__main__":
    main_loop()
