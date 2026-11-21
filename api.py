#!/usr/bin/env python3
"""
AmneziaWG Client Subscription and Token API Server.
Раздаёт актуальные конфигурации клиентов по постоянным секретным токенам.
Поддерживает форматы:
  - Raw .conf (по умолчанию для контейнера MikroTik и curl)
  - vpn:// (AmneziaVPN ссылка для мобильных приложений)
  - JSON (метаданные туннеля)
  - MikroTik RouterOS CLI (.rsc скрипт)
Поддерживает ETag / 304 Not Modified для сверхлегковесного поллинга.
Не требует внешних библиотек (чистый Python 3 стандартной библиотеки).
"""

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socketserver
import sys
import time
import urllib.parse
from pathlib import Path

AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
TOKENS_FILE = os.path.join(AWG_DIR, "tokens.json")
API_HOST = os.environ.get("AWG_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("AWG_API_PORT", "8443"))

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
TOKEN_RE = re.compile(r"^awg_tok_[a-f0-9]{32,64}$")

# Защита от брутфорса: {ip: [count, timestamp]}
FAILED_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 20
BAN_WINDOW_SEC = 60


def is_rate_limited(client_ip):
    now = time.time()
    stale = [ip for ip, (_, ts) in FAILED_ATTEMPTS.items() if now - ts > BAN_WINDOW_SEC]
    for ip in stale:
        FAILED_ATTEMPTS.pop(ip, None)

    entry = FAILED_ATTEMPTS.get(client_ip)
    if entry and entry[0] >= MAX_FAILED_ATTEMPTS:
        return True
    return False


def record_failed_attempt(client_ip):
    now = time.time()
    entry = FAILED_ATTEMPTS.get(client_ip)
    if entry:
        entry[0] += 1
        entry[1] = now
    else:
        FAILED_ATTEMPTS[client_ip] = [1, now]


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
            if CLIENT_NAME_RE.fullmatch(client_name):
                return client_name
    return None


def sanitize_config_endpoint(conf_str):
    """Очищает Endpoint в конфиге клиента от возможных дублированных портов: 64.118.150.81:48389:45968 -> 64.118.150.81:45968"""
    lines = []
    for line in conf_str.splitlines():
        if line.strip().startswith("Endpoint") and "=" in line:
            prefix, val = line.split("=", 1)
            raw = val.strip()
            clean_host = raw.replace("http://", "").replace("https://", "").split("/")[0]
            if clean_host.startswith("[") and "]" in clean_host:
                h = clean_host[1:clean_host.index("]")]
            elif re.match(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", clean_host):
                h = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", clean_host).group(1)
            else:
                h = clean_host.split(":")[0]
            last_port = raw.rsplit(":", 1)[-1]
            if not last_port.isdigit():
                last_port = "443"
            lines.append(f"{prefix.strip()} = {h}:{last_port}")
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

    host = endpoint.split(":")[0].strip("[]") if endpoint else "awg-server"
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
    ep_host = srv_endpoint.split(":")[0].strip("[]") if srv_endpoint else "0.0.0.0"
    ep_port = srv_endpoint.split(":")[1] if ":" in srv_endpoint else "443"

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


class SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AWG-Subscription-Server/2.0"

    def log_message(self, format, *args):
        client_ip = self.client_address[0] if self.client_address else "unknown"
        msg = format % args
        masked_msg = TOKEN_RE.sub("awg_tok_***", msg)
        print(f"[{self.log_date_time_string()}] {client_ip} - {masked_msg}")

    def send_json(self, status_code, data):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.handle_request(is_head=True)

    def do_GET(self):
        self.handle_request(is_head=False)

    def extract_token_and_format(self, parsed_url):
        query = urllib.parse.parse_qs(parsed_url.query)
        req_format = query.get("format", ["conf"])[0].lower()

        # Проверка query параметров
        token = None
        if "token" in query and query["token"]:
            token = query["token"][0].strip()
        elif "sub" in query and query["sub"]:
            token = query["sub"][0].strip()

        # Проверка Authorization: Bearer
        if not token:
            auth = self.headers.get("Authorization", "").strip()
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()

        # Разбор пути
        path_parts = [p for p in parsed_url.path.strip("/").split("/") if p]
        if path_parts:
            # Префиксы форматов в URL: /vpn/<token>, /json/<token>, /rsc/<token>, /sub/<token>
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

    def handle_request(self, is_head=False):
        client_ip = self.client_address[0] if self.client_address else "unknown"

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
                "formats": ["conf", "vpn", "json", "rsc"]
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
            conf_str = sanitize_config_endpoint(conf_str)
            raw_bytes = conf_str.encode("utf-8")
        except Exception as e:
            self.send_json(500, {"error": "Internal Error", "message": str(e)})
            return

        # Поддержка ETag для экономии трафика и быстрого поллинга (304 Not Modified)
        etag = f'"{hashlib.sha256(raw_bytes).hexdigest()[:16]}"'
        client_etag = self.headers.get("If-None-Match", "").strip()
        if client_etag and client_etag == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # Формирование ответа в зависимости от формата
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
            # Стандартный raw .conf для MikroTik контейнеров и WireGuard
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


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server():
    server_address = (API_HOST, API_PORT)
    try:
        httpd = ThreadedHTTPServer(server_address, SubscriptionHandler)
    except OSError as e:
        print(f"ОШИБКА: Не удалось занять порт {API_HOST}:{API_PORT}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"AmneziaWG Subscription API слушает на http://{API_HOST}:{API_PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка API сервера...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_server()
