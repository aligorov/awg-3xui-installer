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

VERSION="3.2.5"
resolve_repo_url() {
  local target_sha
  target_sha="$(curl -fsSL --connect-timeout 4 https://api.github.com/repos/aligorov/awg-3xui-installer/commits/main 2>/dev/null | grep -m 1 '"sha":' | cut -d '"' -f 4 || true)"
  if [ -n "$target_sha" ] && [ "${#target_sha}" -ge 40 ]; then
    printf 'https://raw.githubusercontent.com/aligorov/awg-3xui-installer/%s' "$target_sha"
  else
    printf '%s' "${RAW_BASE_URL:-https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main}"
  fi
}
REPO_URL="$(resolve_repo_url)"

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

step "Запуск обновления AmneziaWG Manager до v${VERSION}..."

TMP_DIR="$(mktemp -d /tmp/awg-update.XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

step "Загрузка актуального установщика с GitHub ($REPO_URL)..."
curl -fsSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${REPO_URL}/install.sh?_=$(date +%s)" -o "$TMP_DIR/install.sh" || die "Не удалось скачать install.sh"

bash -n "$TMP_DIR/install.sh" || die "Синтаксическая ошибка в install.sh!"

# Запуск встроенной процедуры обновления с валидацией, генерацией токенов и заменой CLI
RAW_BASE_URL="$REPO_URL" bash "$TMP_DIR/install.sh" update
