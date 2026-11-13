#!/usr/bin/env python3
"""
AmneziaWG 3.1 Telegram Management Bot
Управление клиентами, генерация QR-кодов, мониторинг трафика и Gemini routing.
Не требует внешних pip-библиотек (чистый Python 3 стандартной библиотеки).
"""

import os
import sys
import json
import time
import uuid
import datetime
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

AWG_DIR = "/etc/amnezia/amneziawg"
AWG_IFACE = "awg0"
ENV_FILE = f"{AWG_DIR}/bot.env"
RU_BYPASS_FILE = f"{AWG_DIR}/amnezia-russia-bypass.json"
RU_BYPASS_URL = "https://raw.githubusercontent.com/lib4u/amnezia-tunneling-ru/main/amnezia.json"
MANAGER_BIN = "/usr/local/bin/awg-manager"

# 51 подсеть для исключения RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
ALLOWED_IPS_NO_LAN = (
    "1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, "
    "32.0.0.0/3, 64.0.0.0/3, 96.0.0.0/6, 100.0.0.0/10, 100.128.0.0/9, 101.0.0.0/8, "
    "102.0.0.0/7, 104.0.0.0/5, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, "
    "128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/8, 169.0.0.0/9, 169.128.0.0/10, 169.192.0.0/11, "
    "169.224.0.0/12, 169.240.0.0/13, 169.248.0.0/14, 169.252.0.0/15, 169.255.0.0/16, "
    "170.0.0.0/7, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, "
    "174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, "
    "192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, "
    "194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4"
)

def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip("'\"")
    for k in ("BOT_TOKEN", "ADMIN_ID"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env

ENV = load_env()
BOT_TOKEN = ENV.get("BOT_TOKEN", "")
ADMIN_ID = str(ENV.get("ADMIN_ID", "")).strip()

if not BOT_TOKEN or not ADMIN_ID:
    print(f"ОШИБКА: Задайте BOT_TOKEN и ADMIN_ID в {ENV_FILE} или переменных окружения", file=sys.stderr)

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# Хранилище временного состояния пользователей {chat_id: state}
USER_STATE = {}

def api_call(method, payload=None, files=None):
    url = f"{BASE_URL}/{method}"
    if files:
        boundary = uuid.uuid4().hex
        body = bytearray()
        if payload:
            for k, v in payload.items():
                if isinstance(v, (dict, list)):
                    v = json.dumps(v)
                body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode("utf-8"))
        for k, (filename, content, mime) in files.items():
            body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n".encode("utf-8"))
            body.extend(content)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode("utf-8"))
        req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    else:
        data_bytes = json.dumps(payload).encode("utf-8") if payload else None
        headers = {"Content-Type": "application/json"} if payload else {}
        req = urllib.request.Request(url, data=data_bytes, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        print(f"API HTTP Error {e.code}: {err_msg}", file=sys.stderr)
        return {"ok": False, "description": err_msg}
    except Exception as e:
        print(f"API Request Exception: {e}", file=sys.stderr)
        return {"ok": False, "description": str(e)}

def send_message(chat_id, text, reply_markup=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api_call("sendMessage", payload)

def send_photo(chat_id, photo_bytes, caption=None, reply_markup=None):
    payload = {"chat_id": str(chat_id), "parse_mode": "Markdown"}
    if caption:
        payload["caption"] = caption
    if reply_markup:
        payload["reply_markup"] = reply_markup
    files = {"photo": ("qr.png", photo_bytes, "image/png")}
    return api_call("sendPhoto", payload, files=files)

def send_document(chat_id, doc_bytes, filename, caption=None, reply_markup=None):
    payload = {"chat_id": str(chat_id), "parse_mode": "Markdown"}
    if caption:
        payload["caption"] = caption
    if reply_markup:
        payload["reply_markup"] = reply_markup
    files = {"document": (filename, doc_bytes, "application/octet-stream")}
    return api_call("sendDocument", payload, files=files)

def answer_callback(callback_id, text=None, alert=False):
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text
        payload["show_alert"] = alert
    return api_call("answerCallbackQuery", payload)

def format_bytes(b):
    try:
        b = int(b)
    except Exception:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"

def format_time_ago(ts):
    try:
        ts = int(ts)
    except Exception:
        return "никогда"
    if ts == 0:
        return "никогда"
    diff = int(time.time()) - ts
    if diff < 60:
        return f"{diff} сек назад"
    if diff < 3600:
        return f"{diff // 60} мин назад"
    if diff < 86400:
        return f"{diff // 3600} ч назад"
    return f"{diff // 86400} дн назад"

def parse_awg_clients():
    conf_file = f"{AWG_DIR}/{AWG_IFACE}.conf"
    if not os.path.exists(conf_file):
        return []

    # Читаем awg show для runtime-статистики
    stats = {}
    try:
        out = subprocess.check_output(["awg", "show", AWG_IFACE, "dump"], stderr=subprocess.DEVNULL).decode("utf-8")
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
    current = {}
    with open(conf_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "[Peer]":
                if current and "pubkey" in current:
                    clients.append(current)
                current = {"name": "", "pubkey": "", "allowed_ips": ""}
            elif line.startswith("#"):
                if current and not current.get("name"):
                    current["name"] = line.lstrip("#").strip()
            elif "=" in line and current is not None:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == "PublicKey":
                    current["pubkey"] = v
                elif k == "AllowedIPs":
                    current["allowed_ips"] = v

        if current and "pubkey" in current:
            clients.append(current)

    now = int(time.time())
    for c in clients:
        pub = c.get("pubkey", "")
        st = stats.get(pub, {})
        c["endpoint"] = st.get("endpoint", "")
        c["handshake"] = st.get("latest_handshake", 0)
        c["rx"] = st.get("rx", 0)
        c["tx"] = st.get("tx", 0)
        # онлайн, если рукопожатие было в пределах 180 секунд
        c["is_online"] = (now - c["handshake"] < 180) and (c["handshake"] > 0)
        if not c.get("name"):
            c["name"] = c.get("allowed_ips", "").split("/")[0] or pub[:8]

    return clients

def get_server_stats():
    conf_file = f"{AWG_DIR}/{AWG_IFACE}.conf"
    if not os.path.exists(conf_file):
        return "❌ Туннель не установлен"

    try:
        active = subprocess.run(["systemctl", "is-active", f"awg-quick@{AWG_IFACE}"], capture_output=True, text=True).stdout.strip() == "active"
    except Exception:
        active = False

    clients = parse_awg_clients()
    online_count = sum(1 for c in clients if c["is_online"])
    total_rx = sum(c["rx"] for c in clients)
    total_tx = sum(c["tx"] for c in clients)

    # Проверка обхода Gemini
    warp_status = "⚪ Отключён"
    try:
        warp_active = subprocess.run(["systemctl", "is-active", "awg-gemini-warp"], capture_output=True, text=True).stdout.strip() == "active"
        if warp_active:
            warp_status = "🟢 Активен (WARP)"
    except Exception:
        pass

    status_icon = "🟢 Активен" if active else "🔴 Остановлен"
    
    text = (
        f"📊 *Состояние AmneziaWG 3.1*\n"
        f"• Сервис: {status_icon}\n"
        f"• Интерфейс: `{AWG_IFACE}`\n"
        f"• Клиенты: *{len(clients)}* (🟢 *{online_count} онлайн*)\n"
        f"• Общий трафик: ↓ {format_bytes(total_tx)} / ↑ {format_bytes(total_rx)}\n"
        f"• Обход Gemini: {warp_status}\n"
    )
    return text

def run_manager_cmd(action, arg=""):
    cmd = [MANAGER_BIN if os.path.exists(MANAGER_BIN) else "/root/vpn_script/install.sh", action]
    if arg:
        cmd.append(arg)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    except Exception as e:
        return False, str(e)

def handle_start(chat_id):
    USER_STATE.pop(chat_id, None)
    text = (
        "🛡 *AmneziaWG 3.1 — Управление туннелем*\n\n"
        "Нативный модуль ядра (DKMS) с полным профилем обфускации 3.1.\n"
        "Выберите действие ниже:"
    )
    markup = {
        "inline_keyboard": [
            [{"text": "➕ Добавить клиента", "callback_data": "menu_add"}],
            [{"text": "👥 Список клиентов", "callback_data": "menu_list"}],
            [{"text": "📊 Статус туннеля", "callback_data": "menu_status"}, {"text": "🌐 Обход AI (Gemini/GPT)", "callback_data": "menu_gemini"}],
            [{"text": "🇷🇺 Обход РФ и локальных сетей (LAN)", "callback_data": "menu_ru_bypass"}]
        ]
    }
    send_message(chat_id, text, markup)

def handle_list_clients(chat_id):
    clients = parse_awg_clients()
    if not clients:
        text = "👥 *Клиентов нет.*\nНажмите кнопку ниже, чтобы создать первого клиента:"
        markup = {"inline_keyboard": [[{"text": "➕ Добавить клиента", "callback_data": "menu_add"}]]}
        send_message(chat_id, text, markup)
        return

    text = f"👥 *Клиенты AmneziaWG ({len(clients)}):*\n\n"
    keyboard = []

    for idx, c in enumerate(clients, 1):
        status_ico = "🟢" if c["is_online"] else "⚪"
        handshake_str = format_time_ago(c["handshake"])
        traffic_str = f"↓{format_bytes(c['tx'])} / ↑{format_bytes(c['rx'])}"
        text += (
            f"*{idx}. {c['name']}* ({c['allowed_ips']})\n"
            f"   {status_ico} {handshake_str} | {traffic_str}\n\n"
        )
        keyboard.append([
            {"text": f"📱 QR / Конфиг: {c['name']}", "callback_data": f"qr_{c['name']}"},
            {"text": f"❌ Удалить", "callback_data": f"del_{c['name']}"}
        ])

    keyboard.append([{"text": "➕ Добавить нового", "callback_data": "menu_add"}, {"text": "🔄 Обновить", "callback_data": "menu_list"}])
    keyboard.append([{"text": "« Главное меню", "callback_data": "menu_main"}])

    send_message(chat_id, text, {"inline_keyboard": keyboard})

def ensure_lan_bypass_config(name):
    """Генерирует {name}-lan-bypass.conf и {name}-lan-bypass.png, если их ещё нет."""
    conf_path = f"{AWG_DIR}/{name}.conf"
    lan_conf_path = f"{AWG_DIR}/{name}-lan-bypass.conf"
    lan_png_path = f"{AWG_DIR}/{name}-lan-bypass.png"

    if not os.path.exists(conf_path):
        return False

    if not os.path.exists(lan_conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                content = f.read()
            import re
            lan_content = re.sub(
                r"^AllowedIPs\s*=.*$",
                f"AllowedIPs = {ALLOWED_IPS_NO_LAN}",
                content,
                flags=re.MULTILINE
            )
            with open(lan_conf_path, "w", encoding="utf-8") as f:
                f.write(lan_content)
            os.chmod(lan_conf_path, 0o600)
        except Exception as e:
            print(f"Ошибка создания {lan_conf_path}: {e}", file=sys.stderr)
            return False

    if not os.path.exists(lan_png_path):
        try:
            subprocess.run(
                ["qrencode", "-o", lan_png_path, "-s", "6", "-m", "2"],
                input=open(lan_conf_path, "rb").read(),
                check=True
            )
            os.chmod(lan_png_path, 0o600)
        except Exception as e:
            print(f"Ошибка qrencode для {lan_png_path}: {e}", file=sys.stderr)

    return True

def handle_qr(chat_id, name):
    conf_path = f"{AWG_DIR}/{name}.conf"
    png_path = f"{AWG_DIR}/{name}.png"

    if not os.path.exists(conf_path):
        send_message(chat_id, f"❌ Конфиг клиента `{name}` не найден.")
        return

    # Если PNG отсутствует, сгенерируем на лету
    if not os.path.exists(png_path):
        try:
            subprocess.run(["qrencode", "-o", png_path, "-s", "6", "-m", "2"], input=open(conf_path, "rb").read(), check=True)
            os.chmod(png_path, 0o600)
        except Exception as e:
            print(f"Ошибка qrencode: {e}", file=sys.stderr)

    # Проверяем и подготавливаем LAN bypass конфиг
    ensure_lan_bypass_config(name)
    lan_conf_path = f"{AWG_DIR}/{name}-lan-bypass.conf"

    caption = (
        f"📱 *Клиент:* `{name}`\n"
        f"🔑 *Профиль:* AmneziaWG 3.1 (Стандартный: весь трафик)\n\n"
        f"Сканируйте QR в официальном приложении *Amnezia >= 5.0.1.5* или скачайте прикреплённые конфиги ниже."
    )

    markup = {
        "inline_keyboard": [
            [{"text": "🏠 Показать QR для обхода локальных сетей (LAN)", "callback_data": f"qr_lan_{name}"}],
            [{"text": "👥 К списку клиентов", "callback_data": "menu_list"}]
        ]
    }

    if os.path.exists(png_path):
        with open(png_path, "rb") as f:
            send_photo(chat_id, f.read(), caption=caption, reply_markup=markup)
    
    with open(conf_path, "rb") as f:
        send_document(
            chat_id,
            f.read(),
            filename=f"{name}.conf",
            caption=f"📄 *{name}.conf* — Полный туннель (`AllowedIPs = 0.0.0.0/0`)"
        )

    if os.path.exists(lan_conf_path):
        with open(lan_conf_path, "rb") as f:
            send_document(
                chat_id,
                f.read(),
                filename=f"{name}-lan-bypass.conf",
                caption=(
                    f"🏠 *{name}-lan-bypass.conf* — Конфиг с обходом локальных сетей!\n"
                    f"Домашний роутер (`192.168.x.x`), сетевые принтеры и NAS работают напрямую мимо VPN."
                )
            )

def handle_qr_lan(chat_id, name):
    ensure_lan_bypass_config(name)
    lan_conf_path = f"{AWG_DIR}/{name}-lan-bypass.conf"
    lan_png_path = f"{AWG_DIR}/{name}-lan-bypass.png"

    if not os.path.exists(lan_conf_path):
        send_message(chat_id, f"❌ Конфиг `{name}-lan-bypass.conf` не найден.")
        return

    caption = (
        f"🏠 *QR-код с обходом локальных сетей (LAN bypass)*\n"
        f"📱 *Клиент:* `{name}`\n"
        f"🔑 *Профиль:* AmneziaWG 3.1\n\n"
        f"В этом QR-коде подсети `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` и `169.254.0.0/16` исключены из VPN — "
        f"доступ к домашнему роутеру, сетевым принтерам и умному дому идёт напрямую через Wi-Fi / LAN."
    )

    markup = {
        "inline_keyboard": [
            [{"text": "📱 Показать стандартный QR (0.0.0.0/0)", "callback_data": f"qr_{name}"}],
            [{"text": "👥 К списку клиентов", "callback_data": "menu_list"}]
        ]
    }

    if os.path.exists(lan_png_path):
        with open(lan_png_path, "rb") as f:
            send_photo(chat_id, f.read(), caption=caption, reply_markup=markup)

def handle_add_prompt(chat_id):
    USER_STATE[chat_id] = "waiting_client_name"
    text = (
        "➕ *Добавление нового клиента*\n\n"
        "Отправьте имя клиента сообщением в чат.\n"
        "Допустимы латинские буквы, цифры, дефис и подчёркивание (например: `phone`, `laptop`, `user2`).\n\n"
        "Или нажмите кнопку для отмены:"
    )
    markup = {"inline_keyboard": [[{"text": "« Отмена", "callback_data": "menu_main"}]]}
    send_message(chat_id, text, markup)

def handle_create_client(chat_id, name):
    USER_STATE.pop(chat_id, None)
    name = name.strip()
    import re
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", name):
        send_message(chat_id, "❌ Некорректное имя! Допустимы буквы A-Z, цифры, `_` и `-` (длина 1-32). Попробуйте снова.")
        return

    send_message(chat_id, f"⏳ Создаю клиента `{name}`...")
    ok, out = run_manager_cmd("add-client", name)
    if ok:
        send_message(chat_id, f"✅ Клиент `{name}` успешно добавлен!")
        handle_qr(chat_id, name)
    else:
        send_message(chat_id, f"❌ Ошибка добавления клиента `{name}`:\n```\n{out[-400:]}\n```")

def handle_delete_confirm(chat_id, name):
    text = f"⚠️ *Вы действительно хотите удалить клиента `{name}`?*\nПосле удаления доступ через этот ключ будет немедленно отозван."
    markup = {
        "inline_keyboard": [
            [{"text": f"✅ Да, удалить `{name}`", "callback_data": f"confirm_del_{name}"}],
            [{"text": "« Отмена", "callback_data": "menu_list"}]
        ]
    }
    send_message(chat_id, text, markup)

def handle_delete_exec(chat_id, name):
    send_message(chat_id, f"⏳ Удаляю клиента `{name}`...")
    ok, out = run_manager_cmd("remove-client", name)
    if ok:
        send_message(chat_id, f"✅ Клиент `{name}` удалён.")
        handle_list_clients(chat_id)
    else:
        send_message(chat_id, f"❌ Ошибка удаления `{name}`:\n```\n{out[-400:]}\n```")

def handle_gemini_info(chat_id):
    active = False
    try:
        active = subprocess.run(["systemctl", "is-active", "awg-gemini-warp"], capture_output=True, text=True).stdout.strip() == "active"
    except Exception:
        pass

    status_str = "🟢 *Включён (WARP routing)*" if active else "⚪ *Отключён*"
    text = (
        f"🌐 *Обход блокировок AI (Gemini + ChatGPT + Claude)*\n\n"
        f"• Текущий статус: {status_str}\n\n"
        f"При включении запросы к сервисам:\n"
        f"• *Google Gemini & AI Studio* (`geosite:google-deepmind`)\n"
        f"• *OpenAI & ChatGPT* (`geosite:openai`, Sora, DALL-E)\n"
        f"• *Anthropic Claude*\n\n"
        f"автоматически маршрутизируются через Cloudflare WARP с чистым резидентским Anycast IP. "
        f"Остальной мировой интернет идёт напрямую через гигабитный порт вашего VPS."
    )
    kb = []
    if active:
        kb.append([{"text": "🔴 Отключить обход AI", "callback_data": "gemini_disable"}])
        kb.append([{"text": "🔍 Проверить доступность AI API", "callback_data": "gemini_test"}])
    else:
        kb.append([{"text": "🟢 Включить обход AI (WARP)", "callback_data": "gemini_enable"}])

    kb.append([{"text": "« Главное меню", "callback_data": "menu_main"}])
    send_message(chat_id, text, {"inline_keyboard": kb})

def handle_ru_bypass(chat_id):
    send_message(chat_id, "⏳ Подготавливаю файл обхода российских сайтов (GeoIP RU)...")
    content = None
    if os.path.exists(RU_BYPASS_FILE):
        try:
            with open(RU_BYPASS_FILE, "rb") as f:
                content = f.read()
        except Exception:
            pass

    if not content:
        try:
            req = urllib.request.Request(RU_BYPASS_URL, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
                try:
                    with open(RU_BYPASS_FILE, "wb") as f:
                        f.write(content)
                except Exception:
                    pass
        except Exception as e:
            send_message(chat_id, f"❌ Не удалось загрузить базу обхода РФ: {e}")
            return

    caption = (
        "🇷🇺 *Раздельное туннелирование сайтов РФ и локальных сетей (GeoIP RU + LAN)*\n\n"
        "Чтобы Госуслуги, Сбербанк, Т-Банк, Кинопоиск, Яндекс и сервисы зоны `.ru`, "
        "а также *домашний роутер и локальная сеть* (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`) "
        "работали напрямую через домашнего провайдера на максимальной скорости:\n\n"
        "1. Сохраните прикреплённый файл `amnezia.json` на телефон/ПК.\n"
        "2. В приложении *Amnezia VPN*:\n"
        "   ⚙️ *Настройки* ➔ *Подключение* ➔ *Раздельное туннелирование сайтов*.\n"
        "3. Выберите режим: *«Адреса из списка НЕ должны использовать VPN»*.\n"
        "4. Нажмите *Импорт* и выберите скачанный файл.\n\n"
        "✅ Готово! Все российские сайты, банки и локальные устройства пойдут напрямую, а блокировки и AI — через AmneziaWG."
    )
    send_document(chat_id, content, filename="amnezia.json", caption=caption)

def main_loop():
    print(f"AmneziaWG Telegram Bot запущен. ADMIN_ID: {ADMIN_ID}")
    offset = 0
    while True:
        try:
            updates = api_call("getUpdates", {"offset": offset, "timeout": 30})
            if not updates or not updates.get("ok"):
                time.sleep(3)
                continue

            for u in updates.get("result", []):
                offset = u["update_id"] + 1

                # Обработка сообщений
                if "message" in u:
                    msg = u["message"]
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    from_id = str(msg.get("from", {}).get("id", ""))
                    text = msg.get("text", "").strip()

                    # Проверка прав доступа: строго один администратор
                    if from_id != ADMIN_ID:
                        send_message(chat_id, "⛔ Доступ запрещён. Этот бот управляет персональным VPN-сервером.")
                        continue

                    state = USER_STATE.get(chat_id)
                    if state == "waiting_client_name" and text and not text.startswith("/"):
                        handle_create_client(chat_id, text)
                        continue

                    if text in ("/start", "/menu"):
                        handle_start(chat_id)
                    elif text in ("/clients", "/list"):
                        handle_list_clients(chat_id)
                    elif text in ("/status",):
                        send_message(chat_id, get_server_stats())
                    elif text in ("/add",):
                        handle_add_prompt(chat_id)
                    else:
                        handle_start(chat_id)

                # Обработка инлайн-кнопок
                elif "callback_query" in u:
                    cb = u["callback_query"]
                    cb_id = cb["id"]
                    from_id = str(cb.get("from", {}).get("id", ""))
                    chat_id = str(cb.get("message", {}).get("chat", {}).get("id", ""))
                    data = cb.get("data", "")

                    if from_id != ADMIN_ID:
                        answer_callback(cb_id, "⛔ Доступ запрещён", alert=True)
                        continue

                    answer_callback(cb_id)

                    if data == "menu_main":
                        handle_start(chat_id)
                    elif data == "menu_list":
                        handle_list_clients(chat_id)
                    elif data == "menu_add":
                        handle_add_prompt(chat_id)
                    elif data == "menu_status":
                        send_message(chat_id, get_server_stats())
                    elif data == "menu_gemini":
                        handle_gemini_info(chat_id)
                    elif data == "menu_ru_bypass":
                        handle_ru_bypass(chat_id)
                    elif data.startswith("qr_lan_"):
                        name = data[7:]
                        handle_qr_lan(chat_id, name)
                    elif data.startswith("qr_"):
                        name = data[3:]
                        handle_qr(chat_id, name)
                    elif data.startswith("del_"):
                        name = data[4:]
                        handle_delete_confirm(chat_id, name)
                    elif data.startswith("confirm_del_"):
                        name = data[12:]
                        handle_delete_exec(chat_id, name)
                    elif data == "gemini_enable":
                        send_message(chat_id, "⏳ Настраиваю обход Gemini через Cloudflare WARP...")
                        ok, out = run_manager_cmd("warp-enable")
                        send_message(chat_id, "✅ Обход Gemini включён!" if ok else f"❌ Ошибка:\n{out[-300:]}")
                        handle_gemini_info(chat_id)
                    elif data == "gemini_disable":
                        send_message(chat_id, "⏳ Отключаю обход Gemini...")
                        ok, out = run_manager_cmd("warp-disable")
                        send_message(chat_id, "⚪ Обход Gemini выключен." if ok else f"❌ Ошибка:\n{out[-300:]}")
                        handle_gemini_info(chat_id)
                    elif data == "gemini_test":
                        send_message(chat_id, "⏳ Тестирую доступ к Google Gemini API через туннель...")
                        ok, out = run_manager_cmd("warp-test")
                        send_message(chat_id, out)

        except Exception as e:
            print(f"Ошибка в цикле polling: {e}", file=sys.stderr)
            time.sleep(3)

if __name__ == "__main__":
    main_loop()
