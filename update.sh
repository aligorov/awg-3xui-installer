#!/usr/bin/env bash
# ==============================================================================
# AmneziaWG 3.1 & awg-manager Updater
# Автоматическое обновление awg-manager, API подписок (порт 8443) и Telegram-бота
# без разрыва и перезагрузки активных туннелей клиентов.
# ==============================================================================

set -euo pipefail

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'

step()  { printf '%b[INFO]%b %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()    { printf '%b[OK]%b %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()   { printf '%b[ERR]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  die "Этот скрипт должен быть запущен с правами root (sudo bash $0)"
fi

REPO_URL="${RAW_BASE_URL:-https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main}"
AWG_DIR="/etc/amnezia/amneziawg"
API_DIR="/etc/amnezia/awg-api"
TOKENS_DIR="/etc/amnezia/awg-tokens"
BOT_DIR="/etc/amnezia/awg-bot"
AWG_IFACE="awg0"
AWG_API_PORT="8443"

printf '%b' "$C_CYAN$C_BOLD"
cat << 'BANNER'
  ___                               _        _    _  ____ 
 / _ \ _ __  _ __   ___  ____ _ __ (_) __ _ | |  | |/ ___|
| |_| | '_ \| '_ \ / _ \|_  /| '__|| |/ _` || |  | | |  _ 
|  _  | | | | | | |  __/ / / | |   | | (_| || |__| | |_| |
|_| |_|_| |_|_| |_|\___|/___||_|   |_|\__,_| \____/ \____|
               SERVER UPDATER (Zero-Downtime)
BANNER
printf '%b\n' "$C_RESET"

step "Запуск обновления AmneziaWG Manager..."

TMP_DIR="$(mktemp -d /tmp/awg-update.XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

step "Загрузка компонентов с GitHub ($REPO_URL)..."
curl -fsSL "${REPO_URL}/install.sh" -o "$TMP_DIR/install.sh" || die "Не удалось скачать install.sh"
curl -fsSL "${REPO_URL}/api.py" -o "$TMP_DIR/api.py" || die "Не удалось скачать api.py"
curl -fsSL "${REPO_URL}/bot.py" -o "$TMP_DIR/bot.py" || die "Не удалось скачать bot.py"

step "Проверка синтаксиса скачанных файлов..."
bash -n "$TMP_DIR/install.sh" || die "Синтаксическая ошибка в install.sh!"
if command -v python3 >/dev/null 2>&1; then
  python3 -m py_compile "$TMP_DIR/api.py" || die "Синтаксическая ошибка в api.py!"
  python3 -m py_compile "$TMP_DIR/bot.py" || die "Синтаксическая ошибка в bot.py!"
fi
ok "Синтаксис проверен успешно"

step "Обновление CLI /usr/local/bin/awg-manager..."
install -m 755 "$TMP_DIR/install.sh" /usr/local/bin/awg-manager
ok "awg-manager обновлен (с поддержкой интерактивного меню и ротации)"

step "Обновление API сервиса подписок (порт $AWG_API_PORT)..."
mkdir -p "$API_DIR"
install -m 755 "$TMP_DIR/api.py" "$API_DIR/api.py"

cat > /etc/systemd/system/awg-api.service << 'UNIT'
[Unit]
Description=AmneziaWG Client Subscription & Config API
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/amnezia/awg-api/api.py
Restart=always
RestartSec=3
KillMode=process
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable awg-api >/dev/null 2>&1 || true
systemctl restart awg-api
ok "API сервис подписок запущен на порту $AWG_API_PORT/tcp"

if [ -d "$BOT_DIR" ] && [ -f "$BOT_DIR/config.env" ]; then
  step "Обновление Telegram-бота..."
  install -m 755 "$TMP_DIR/bot.py" "$BOT_DIR/bot.py"
  if systemctl is-active --quiet awg-bot 2>/dev/null; then
    systemctl restart awg-bot 2>/dev/null || true
    ok "Telegram-бот перезапущен"
  fi
fi

# Обеспечение токенов для всех существующих клиентов
step "Проверка токенов подписок для клиентов..."
mkdir -p "$TOKENS_DIR"
chmod 700 "$TOKENS_DIR"
conf="$AWG_DIR/$AWG_IFACE.conf"
token_count=0

if [ -f "$conf" ]; then
  while IFS= read -r client_name; do
    if [ -n "$client_name" ]; then
      tfile="$TOKENS_DIR/${client_name}.token"
      if [ ! -f "$tfile" ]; then
        tok="$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-32)"
        printf '%s' "$tok" > "$tfile"
        chmod 600 "$tfile"
        token_count=$((token_count + 1))
      fi
    fi
  done < <(awk '
    BEGIN { name="" }
    /^\[Peer\]/ { name="" }
    /^#/ && !name { name=$0; sub(/^#[ \t]*/, "", name) }
    /^PublicKey/ {
      if (name) print name
    }
  ' "$conf")
fi

if [ "$token_count" -gt 0 ]; then
  ok "Сгенерированы постоянные токены для $token_count клиентов"
else
  ok "Токены клиентов в порядке"
fi

# Настройка файрвола для API порта
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "${AWG_API_PORT}/tcp" comment 'AmneziaWG Subscription API' >/dev/null 2>&1 || true
  ok "Порт ${AWG_API_PORT}/tcp разрешен в UFW"
fi

printf '\n%b%b=== ОБНОВЛЕНИЕ ЗАВЕРШЕНО УСПЕШНО ===%b\n\n' "$C_GREEN" "$C_BOLD" "$C_RESET"
printf '  %b• CLI меню:%b             sudo awg-manager\n' "$C_BOLD" "$C_RESET"
printf '  %b• Интерактивное TUI:%b    навигация стрелками ↑/↓, Enter для выбора\n' "$C_BOLD" "$C_RESET"
printf '  %b• API подписок клиентов:%b  http://<IP-СЕРВЕРА>:%s/sub/<ТОКЕН>\n' "$C_BOLD" "$C_RESET" "$AWG_API_PORT"
printf '  %b• Токены клиентов:%b      sudo awg-manager token <имя_клиента>\n' "$C_BOLD" "$C_RESET"
printf '  %b• График авто-ротации:%b  sudo awg-manager schedule weekly\n' "$C_BOLD" "$C_RESET"
printf '  %b• Активный туннель:%b     awg0 продолжает работать без разрыва!\n\n' "$C_GREEN" "$C_RESET"
