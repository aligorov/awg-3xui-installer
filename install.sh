#!/usr/bin/env bash
#===============================================================================
#  awg-manager — защищённый установщик и менеджер AmneziaWG 3.1 (Ubuntu 24.04)
#
#  Возможности:
#  - Нативный модуль ядра amneziawg.ko (DKMS из ppa:amnezia/ppa) — высокая
#    производительность без оверхеда userspace.
#  - Профиль AmneziaWG 3.1 для максимальной незаметности от ТСПУ/DPI:
#    HeaderProtectionKey, порт 443/udp (с автофолбэком), CPS I1 (имитация QUIC v1),
#    S1-S4 (с проверкой коллизий), ContentPaddingAddition, DisableCookies (при поддержке).
#  - Стандартный полный туннель (AllowedIPs = 0.0.0.0/0) без обходов и утечек.
#  - Случайная подсеть клиентов (10.RAND.RAND.0/24), блокировка гонок (flock),
#    жёсткие права доступа (0700/0600) и hardening sysctl/systemd.
#  - Защищённый Telegram-бот (HTML, fail-closed ACL, строгая валидация имён).
#  - Интерактивное TUI-меню и самодиагностика блокировок (diagnose / diagnose-live).
#===============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ОШИБКА: нужен bash. Запуск: sudo bash install.sh" >&2
  exit 1
fi
set -Eeuo pipefail

#--- конфигурация --------------------------------------------------------------
AWG_IFACE="awg0"
AWG_DIR="/etc/amnezia/amneziawg"
AWG_DNS="${AWG_DNS:-1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001}"
AWG_MTU="${AWG_MTU:-1280}"
AWG_PORT="${AWG_PORT:-}"            # пусто -> 443/udp (или случайный 20000-59999 если занят)
AWG_SUBNET="${AWG_SUBNET:-}"        # пусто -> случайный 10.x.y.0/24
AWG_IPV6_PREFIX="${AWG_IPV6_PREFIX:-fd42:42:42::}"
AWG_IPV6_SUBNET="${AWG_IPV6_SUBNET:-fd42:42:42::/64}"
AWG_ENDPOINT="${AWG_ENDPOINT:-}"    # пусто -> автоопределение внешнего IPv4/IPv6
AWG_API_PORT="${AWG_API_PORT:-8443}"  # порт HTTP API подписок для контейнеров MikroTik
CRED_FILE="/root/awg-credentials.txt"
BACKUP_DIR="/root/awg-backups"
LOG_FILE="/var/log/awg-install.log"
DBG_FILE="/var/log/awg-install.debug.log"
LOCK_FILE="/run/lock/awg-manager.lock"
TOKENS_FILE="/etc/amnezia/amneziawg/tokens.json"
ADMIN_TOKEN_FILE="/etc/amnezia/amneziawg/admin_token"
API_TLS_CERT="/etc/amnezia/amneziawg/api_tls.crt"
API_TLS_KEY="/etc/amnezia/amneziawg/api_tls.key"
ENDPOINT_MODE_FILE="/etc/amnezia/amneziawg/endpoint_mode.conf"
BOT_DIR="/opt/awg-bot"
API_DIR="/opt/awg-api"
BOT_ENV="/etc/amnezia/amneziawg/bot.env"
RAW_BASE_URL="${RAW_BASE_URL:-https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main}"
TMP_DIR=""
TEE_PID=""
IS_TTY=0

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300)

if [ "${AWGM_PLAIN:-0}" = "1" ]; then
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''
else
  C_RESET='\033[0m'
  C_RED='\033[0;31m'
  C_GREEN='\033[0;32m'
  C_YELLOW='\033[0;33m'
  C_BLUE='\033[0;34m'
  C_CYAN='\033[0;36m'
  C_BOLD='\033[1m'
fi

#--- вспомогательные функции ----------------------------------------------------
step() { printf '\n%b==> [%s] %s%b\n' "$C_CYAN" "$(date '+%F %T')" "$*" "$C_RESET"; }
warn() { printf '%bВНИМАНИЕ: %s%b\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die()  { printf '\n%bОШИБКА: %s%b\nЛог: %s\n' "$C_RED" "$*" "$C_RESET" "$LOG_FILE" >&2; exit 1; }

rand_u32() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }
rand_range() { # $1=min $2=max -> случайное целое [min,max] из /dev/urandom
  printf '%s' "$(( $(rand_u32) % ($2 - $1 + 1) + $1 ))"
}

conf_get() { # $1=ключ $2=файл -> значение первого совпадения
  sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$2" | head -n1
}

extract_host_from_endpoint() {
  # Извлекает чистый IP или домен из Endpoint/URL, отсекая любые цепочки портов (:port:port) и скобки
  local raw="$1"
  raw="${raw#http://}"
  raw="${raw#https://}"
  raw="${raw%%/*}"
  if [[ "$raw" =~ ^\[([a-fA-F0-9:]+)\] ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "$raw" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "${raw%%:*}"
}

format_endpoint() {
  local h="$1"
  local p="$2"
  if [[ "$h" =~ : ]] && [[ ! "$h" =~ ^\[ ]]; then
    printf '[%s]:%s' "$h" "$p"
  else
    printf '%s:%s' "$h" "$p"
  fi
}

sanitize_existing_client_endpoints() {
  local lport
  lport="$(conf_get ListenPort "$AWG_DIR/$AWG_IFACE.conf" || true)"
  [ -n "$lport" ] || return 0

  local cf
  for cf in "$AWG_DIR"/*.conf; do
    [ -f "$cf" ] || continue
    [ "$cf" != "$AWG_DIR/$AWG_IFACE.conf" ] || continue
    local cur_ep
    cur_ep="$(conf_get Endpoint "$cf" || true)"
    if [ -n "$cur_ep" ]; then
      local clean_h
      clean_h="$(extract_host_from_endpoint "$cur_ep")"
      if [ -n "$clean_h" ]; then
        local ep_str
        ep_str="$(format_endpoint "$clean_h" "$lport")"
        sed -i -E "s|^Endpoint[[:space:]]*=.*$|Endpoint = ${ep_str}|" "$cf"
      fi
    fi
  done
}

acquire_lock() {
  mkdir -p /run/lock
  exec 9>"$LOCK_FILE"
  flock -w 30 9 || die "не удалось получить блокировку $LOCK_FILE (выполняется другой процесс)"
}

release_lock() {
  exec 9>&- 2>/dev/null || true
}

is_script_file() {
  [ -n "${0:-}" ] && [ -f "$0" ] && [ "$(basename "$0")" != "bash" ] && [ "$(basename "$0")" != "sh" ]
}

is_valid_client_name() {
  local n="${1:-}"
  [[ "$n" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || return 1
  case "${n,,}" in
    awg0|warp0|server|default) return 1 ;;
  esac
  [[ "$n" != *-lan-bypass ]] || return 1
  return 0
}

is_private_ipv4() {
  local ip="$1" a b _
  IFS=. read -r a b _ _ <<< "$ip"
  [ "$a" = "10" ] && return 0
  [ "$a" = "127" ] && return 0
  [ "$a" = "169" ] && [ "$b" = "254" ] && return 0
  [ "$a" = "192" ] && [ "$b" = "168" ] && return 0
  [ "$a" = "172" ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 0
  [ "$a" = "100" ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 0
  return 1
}

validate_subnet_24() {
  local sub="$1" o1 o2 o3
  [[ "$sub" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.0/24$ ]] || return 1
  o1="${BASH_REMATCH[1]}"; o2="${BASH_REMATCH[2]}"; o3="${BASH_REMATCH[3]}"
  [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] || return 1
  if [ "$o1" -eq 10 ] || { [ "$o1" -eq 172 ] && [ "$o2" -ge 16 ] && [ "$o2" -le 31 ]; } || { [ "$o1" -eq 192 ] && [ "$o2" -eq 168 ]; }; then
    return 0
  fi
  return 1
}

detect_public_ip() { # печатает внешний IPv4 (учитывает AWG_ENDPOINT)
  local ip="" url
  if [ -n "${AWG_ENDPOINT:-}" ]; then
    printf '%s\n' "$AWG_ENDPOINT"
    return 0
  fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ipv4 "$ip"; then
    printf '%s\n' "$ip"
    return 0
  fi
  for url in https://api.ipify.org https://icanhazip.com https://ifconfig.me https://checkip.amazonaws.com; do
    ip="$(curl -4 -fsS --max-time 2 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  done
  return 1
}

detect_wan_iface() {
  local iface=""
  iface="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [ -z "$iface" ]; then
    iface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  fi
  printf '%s' "$iface"
}

get_subnet_prefix() { # извлекает префикс 'A.B.C.' из awg0.conf
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$conf" ]; then
    local srv_addr
    srv_addr="$(conf_get Address "$conf" || true)"
    printf '%s' "$srv_addr" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.' || true
  fi
}

detect_wan6_iface() {
  local iface=""
  iface="$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [ -z "$iface" ]; then
    iface="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  fi
  printf '%s' "$iface"
}

detect_public_ipv6() {
  local ip="" url has_global6=""
  # Быстрая проверка локального маршрута IPv6 (<2 мс, без ожидания таймаутов curl)
  ip="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ "$ip" =~ : ]] && [[ ! "${ip,,}" =~ ^(fe80|fc|fd|::1$) ]]; then
    printf '%s' "$ip"
    return 0
  fi
  has_global6="$(ip -6 -o addr show scope global 2>/dev/null | awk '!/temporary/ {print $4}' | head -n1 || true)"
  [ -n "$has_global6" ] || return 1

  for url in https://api64.ipify.org https://icanhazip.com https://ifconfig.me; do
    ip="$(curl -6 -fsS --max-time 2 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ : ]]; then
      printf '%s' "$ip"
      return 0
    fi
  done
  return 1
}

get_public_endpoint_host() {
  # 1. Если явно задан AWG_ENDPOINT в окружении
  if [ -n "${AWG_ENDPOINT:-}" ]; then
    extract_host_from_endpoint "$AWG_ENDPOINT"
    return 0
  fi

  # 2. Если сохранен режим в endpoint_mode.conf
  local mode=""
  if [ -f "$ENDPOINT_MODE_FILE" ]; then
    mode="$(cat "$ENDPOINT_MODE_FILE" 2>/dev/null | tr -d '[:space:]')"
  fi

  if [ "$mode" = "ipv6" ]; then
    local ip6
    ip6="$(detect_public_ipv6 || true)"
    if [ -n "$ip6" ]; then
      printf '%s' "$ip6"
      return 0
    fi
  elif [ -n "$mode" ] && [ "$mode" != "ipv4" ]; then
    local h
    h="$(extract_host_from_endpoint "$mode")"
    if [ -n "$h" ]; then
      printf '%s' "$h"
      return 0
    fi
  fi

  # 3. Если в существующих конфигах уже используется IPv6
  local cur_ep=""
  if [ -f "$AWG_DIR/client1.conf" ]; then
    cur_ep="$(conf_get Endpoint "$AWG_DIR/client1.conf" || true)"
  fi
  if [[ "$cur_ep" =~ : ]] && [[ ! "$cur_ep" =~ ^[0-9]+\.[0-9]+ ]]; then
    local h
    h="$(extract_host_from_endpoint "$cur_ep")"
    if [ -n "$h" ]; then
      printf '%s' "$h"
      return 0
    fi
  fi

  # 4. По умолчанию - публичный IPv4
  local ip4
  ip4="$(detect_public_ip || true)"
  if [ -n "$ip4" ]; then
    printf '%s' "$ip4"
    return 0
  fi

  # 5. Если IPv4 нет, пробуем IPv6
  detect_public_ipv6 || true
}

get_ipv6_prefix() { # извлекает IPv6 префикс (например fd42:42:42::) из awg0.conf
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$conf" ]; then
    local srv_addr
    srv_addr="$(conf_get Address "$conf")"
    local ip6
    ip6="$(printf '%s' "$srv_addr" | tr ',' '\n' | grep -i ':' | head -n1 | tr -d '[:space:]' || true)"
    if [ -n "$ip6" ]; then
      ip6="${ip6%%/*}"
      printf '%s' "${ip6%1}"
      return 0
    fi
  fi
  printf '%s' "${AWG_IPV6_PREFIX:-fd42:42:42::}"
}

confirm_yes() { # $1=вопрос; код 0 = подтверждено
  local a
  read -r -p "$1 [y/N]: " a || return 1
  case "$a" in y|Y|yes|YES|да|Да|ДА) return 0 ;; *) return 1 ;; esac
}

free_port() { # $1 = udp|tcp; криптостойкий свободный порт 20000-59999
  local proto="$1" flag p
  case "$proto" in
    udp) flag="-u" ;;
    tcp) flag="-t" ;;
    *) return 1 ;;
  esac
  for _ in $(seq 1 60); do
    p="$(rand_range 20000 59999)"
    if [ -z "$(ss -Hln "$flag" "sport = :${p}")" ]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

choose_awg_port() {
  if [ -n "${AWG_PORT:-}" ]; then
    [[ "$AWG_PORT" =~ ^[0-9]+$ ]] && [ "$AWG_PORT" -ge 1 ] && [ "$AWG_PORT" -le 65535 ] \
      || die "некорректный порт AWG_PORT='$AWG_PORT' (1..65535)"
    printf '%s' "$AWG_PORT"
    return 0
  fi
  # Для максимальной маскировки под HTTP/3 (QUIC) по умолчанию пробуем 443/udp
  if [ -z "$(ss -Hlnu "sport = :443" 2>/dev/null)" ]; then
    printf '443'
    return 0
  fi
  warn "Порт 443/udp уже занят другим сервисом — выбираю случайный порт 20000-59999/udp"
  free_port udp
}

wait_for_apt_lock() {
  local i
  for i in $(seq 1 60); do
    if flock -n /var/lib/dpkg/lock-frontend true 2>/dev/null \
      && flock -n /var/lib/apt/lists/lock true 2>/dev/null; then
      return 0
    fi
    step "apt/dpkg занят (unattended-upgrades?) — жду, попытка ${i}/60"
    sleep 5
  done
  return 1
}

apt_update() {
  local i out
  for i in $(seq 1 60); do
    if out="$(apt-get update 2>&1)"; then
      return 0
    fi
    if printf '%s' "$out" | grep -q 'Could not get lock\|Unable to lock directory'; then
      step "apt-лок занят — жду освобождения, попытка ${i}/60"
      sleep 5
    else
      printf '%s\n' "$out" >&2
      return 1
    fi
  done
  return 1
}

#--- профили маскировки AmneziaWG 3.1 (анти-ТСПУ Stealth Presets) -------------
# 1) HTTP/3 (QUIC): 443/udp, RFC 9000 QUIC v1 Initial (<b 0xc10000000108><r 8><b 0x00004120><r 288>)
# 2) HTTP/3 (QUIC Alt): 20000-59999/udp, RFC 9000 QUIC v1 Initial на высоком порту
# 3) WebRTC / STUN: 3478/udp, RFC 5389 Binding Request (<b 0x000100002112a442><r 12>)
# 4) WebRTC Alt Port: 20000-50000/udp со STUN Magic Cookie (<b 0x000100002112a442><r 12>)
# 5) DTLS 1.2 (Zoom / VoIP / AnyConnect): 8801/udp, RFC 6347 ClientHello
# 6) DNS Query (EDNS0): 53/udp, RFC 6891 EDNS0 ya.ru
# 7) NTP v4 (Синхронизация времени): 123/udp, RFC 5905 Client Request (48 байт)
# 8) SIP (IP-телефония / VoIP): 5060/udp, RFC 3261 OPTIONS
# 9) Steam Game (A2S): 27015/udp, Valve Source Engine Query
# 10) Minecraft Bedrock (RakNet): 19132/udp, RakNet Unconnected Ping
# 11) Discord Voice (UDP): 50001/udp, Discord IP Discovery Request (74 байта)
# 12) BitTorrent DHT (BEP-5): 6881/udp, DHT Ping Query

cps_i1_quic() {
  local first_b plen varint_hex out
  first_b="$(printf 'c%x' "$(rand_range 0 15)")"
  plen="$(rand_range 200 340)"
  varint_hex="$(printf '%04x' "$((0x4000 + plen))")"
  out="$(printf '<b 0x%s0000000108><r 8><b 0x0000%s><r %s>' "$first_b" "$varint_hex" "$plen")"
  printf '%s\n' "$out"
}

cps_i1_stun() {
  printf '<b 0x000100002112a442><r 12>\n'
}

cps_i1_dtls() {
  printf '<b 0x16fefd0000000000000000005c010000500000000000000050fefd><r 32><b 0x00000004c02fc03001000022><r 34>\n'
}

cps_i1_dns() {
  printf '<r 2><b 0x0100000100000000000102796102727500000100010000291000000000000000>\n'
}

cps_i1_ntp() {
  printf '<b 0x23000000000000000000000000000000000000000000000000000000000000000000000000000000><r 8>\n'
}

cps_i1_sip() {
  printf '<b 0x4f5054494f4e53207369703a766f69702e6c6f63616c205349502f322e300d0a5669613a205349502f322e302f5544502031302e302e302e313a353036303b6272616e63683d7a39684734624b><rc 10><b 0x0d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>\n'
}

cps_i1_steam() {
  printf '<b 0xffffffff54536f7572636520456e67696e6520517565727900>\n'
}

cps_i1_minecraft() {
  printf '<b 0x01><r 8><b 0x00ffff00fefefefefdfdfdfd12345678><r 8>\n'
}

cps_i1_discord() {
  printf '<b 0x00010046><r 4><b 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000>\n'
}

cps_i1_dht() {
  printf '<b 0x64313a6164323a696432303a><r 20><b 0x65313a71343a70696e67313a74323a><r 2><b 0x313a79313a7165>\n'
}

get_current_preset() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$AWG_DIR/preset.conf" ]; then
    local p
    p="$(cat "$AWG_DIR/preset.conf" 2>/dev/null | tr -d ' \r\n' || true)"
    if [ -n "$p" ]; then
      printf '%s\n' "$p"
      return
    fi
  fi
  if [ ! -f "$conf" ]; then
    printf 'quic\n'
    return
  fi
  local i1 port
  i1="$(conf_get I1 "$conf" 2>/dev/null || true)"
  port="$(conf_get ListenPort "$conf" 2>/dev/null || true)"
  if printf '%s' "$i1" | grep -q '2112a442'; then
    if [ "$port" = "3478" ]; then printf 'stun\n'; else printf 'stun-alt\n'; fi
  elif printf '%s' "$i1" | grep -q '16fefd0000'; then
    printf 'dtls\n'
  elif printf '%s' "$i1" | grep -q '027961027275'; then
    printf 'dns\n'
  elif printf '%s' "$i1" | grep -q '2300000000000000'; then
    printf 'ntp\n'
  elif printf '%s' "$i1" | grep -q '4f5054494f4e5320'; then
    printf 'sip\n'
  elif printf '%s' "$i1" | grep -q '54536f75726365'; then
    printf 'steam\n'
  elif printf '%s' "$i1" | grep -q '00ffff00fefefefe'; then
    printf 'minecraft\n'
  elif printf '%s' "$i1" | grep -q '00010046'; then
    printf 'discord\n'
  elif printf '%s' "$i1" | grep -q '64313a6164323a696432303a'; then
    printf 'dht\n'
  elif printf '%s' "$i1" | grep -q '0000000108'; then
    if [ "$port" = "443" ]; then printf 'quic\n'; else printf 'quic-alt\n'; fi
  else
    printf 'quic\n'
  fi
}

preset_title() {
  local p="${1:-quic}" actual_port="${2:-}" def_port="" desc="" alt_desc=""
  case "$p" in
    quic)      def_port="443";   desc="HTTP/3 (QUIC) — 443/udp (YouTube / HTTPS)"; alt_desc="HTTP/3 (QUIC) — %s/udp (QUIC-маскировка; базовый 443/udp)" ;;
    quic-alt)  def_port="";      desc="HTTP/3 (QUIC Alt) — 20000-59999/udp (QUIC на высоком порту)"; alt_desc="HTTP/3 (QUIC Alt) — %s/udp (QUIC на высоком порту)" ;;
    stun)      def_port="3478";  desc="WebRTC / STUN — 3478/udp (Telegram / WhatsApp звонки)"; alt_desc="WebRTC / STUN — %s/udp (STUN; базовый 3478/udp)" ;;
    stun-alt)  def_port="";      desc="WebRTC / STUN (Alt) — 20000-50000/udp со STUN Magic Cookie"; alt_desc="WebRTC / STUN (Alt) — %s/udp со STUN Magic Cookie" ;;
    dtls)      def_port="8801";  desc="DTLS 1.2 (Zoom / VoIP) — 8801/udp (RFC 6347 ClientHello)"; alt_desc="DTLS 1.2 (Zoom / VoIP) — %s/udp (базовый 8801/udp)" ;;
    dns)       def_port="53";    desc="DNS (EDNS0) — 53/udp (маскировка под DNS ya.ru)"; alt_desc="DNS (EDNS0) — %s/udp (базовый 53/udp)" ;;
    ntp)       def_port="123";   desc="NTP v4 (Время) — 123/udp (RFC 5905)"; alt_desc="NTP v4 (Время) — %s/udp (базовый 123/udp)" ;;
    sip)       def_port="5060";  desc="SIP (VoIP / Телефония) — 5060/udp (RFC 3261 OPTIONS)"; alt_desc="SIP (VoIP) — %s/udp (базовый 5060/udp)" ;;
    steam)     def_port="27015"; desc="Игровой (Steam A2S) — 27015/udp (Source Engine Query)"; alt_desc="Игровой (Steam A2S) — %s/udp (базовый 27015/udp)" ;;
    minecraft) def_port="19132"; desc="Игровой (Minecraft / RakNet) — 19132/udp"; alt_desc="Игровой (Minecraft / RakNet) — %s/udp (базовый 19132/udp)" ;;
    discord)   def_port="50001"; desc="Discord Voice (UDP) — 50001/udp (IP Discovery)"; alt_desc="Discord Voice (UDP) — %s/udp (базовый 50001/udp)" ;;
    dht)       def_port="6881";  desc="BitTorrent DHT (BEP-5) — 6881/udp (DHT Ping)"; alt_desc="BitTorrent DHT (BEP-5) — %s/udp (базовый 6881/udp)" ;;
    custom)    def_port="";      desc="Пользовательский (ручной порт и I1)"; alt_desc="Пользовательский — %s/udp (ручной порт и I1)" ;;
    *)         def_port="443";   desc="HTTP/3 (QUIC) — 443/udp"; alt_desc="HTTP/3 (QUIC) — %s/udp" ;;
  esac
  if [ -n "$actual_port" ] && [ "$actual_port" != "-" ] && [ "$actual_port" != "$def_port" ]; then
    printf "$alt_desc" "$actual_port"
  else
    printf '%s' "$desc"
  fi
}

cps_i1() {
  local p
  p="$(get_current_preset)"
  case "$p" in
    stun|stun-alt) cps_i1_stun ;;
    dtls) cps_i1_dtls ;;
    dns) cps_i1_dns ;;
    ntp) cps_i1_ntp ;;
    sip) cps_i1_sip ;;
    steam) cps_i1_steam ;;
    minecraft) cps_i1_minecraft ;;
    discord) cps_i1_discord ;;
    dht) cps_i1_dht ;;
    *) cps_i1_quic ;;
  esac
}

s4_collides() { # проверка коллизий длин для модуля ядра
  local p
  p=$(( $1 - $4 + 116 )); if [ "$p" -ge 32 ] && [ $((p % 16)) -eq 0 ] && [ "$p" -ne 128 ]; then return 0; fi
  p=$(( $2 - $4 + 60 ));  if [ "$p" -ge 32 ] && [ $((p % 16)) -eq 0 ]; then return 0; fi
  p=$(( $3 - $4 + 32 ));  if [ "$p" -ge 48 ] && [ $((p % 16)) -eq 0 ]; then return 0; fi
  return 1
}

probe_awg31() { # проверка поддержки ядром AmneziaWG 3.1
  local ifn="" kf rc i
  kf="$(mktemp)" || return 1
  chmod 600 "$kf"
  awg genkey > "$kf" || { rm -f "$kf"; return 1; }
  for i in 1 2 3; do
    ifn="awgp$$x$i"
    if ip link show "$ifn" >/dev/null 2>&1; then ifn=""; continue; fi
    if timeout -k 1 10 ip link add "$ifn" type amneziawg >/dev/null 2>&1; then break; fi
    ifn=""
  done
  if [ -z "$ifn" ]; then rm -f "$kf"; return 1; fi
  timeout -k 1 10 awg set "$ifn" s1 15 s2 15 s3 12 s4 12 \
    header-protection-key "$kf" content-padding-addition 32-128 </dev/null >/dev/null 2>&1
  rc=$?
  timeout -k 1 10 ip link del "$ifn" >/dev/null 2>&1 || true
  rm -f "$kf"
  return "$rc"
}

probe_disable_cookies() { # проверка поддержки DisableCookies (защита от active-probing)
  local ifn="" kf cf rc i
  kf="$(mktemp)" || return 1
  cf="$(mktemp)" || { rm -f "$kf"; return 1; }
  chmod 600 "$kf" "$cf"
  awg genkey > "$kf" || { rm -f "$kf" "$cf"; return 1; }
  for i in 1 2 3; do
    ifn="awgc$$x$i"
    if ip link show "$ifn" >/dev/null 2>&1; then ifn=""; continue; fi
    if timeout -k 1 10 ip link add "$ifn" type amneziawg >/dev/null 2>&1; then break; fi
    ifn=""
  done
  if [ -z "$ifn" ]; then rm -f "$kf" "$cf"; return 1; fi
  cat > "$cf" <<EOF
[Interface]
PrivateKey = $(cat "$kf")
DisableCookies = on
EOF
  timeout -k 1 10 awg setconf "$ifn" "$cf" </dev/null >/dev/null 2>&1
  rc=$?
  timeout -k 1 10 ip link del "$ifn" >/dev/null 2>&1 || true
  rm -f "$kf" "$cf"
  return "$rc"
}

upgrade_awg_packages() { # обновление старых пакетов из PPA
  local f
  for f in /etc/apt/sources.list.d/*amnezia*; do
    if [ -e "$f" ]; then rm -f "$f"; fi
  done
  wait_for_apt_lock || die "apt занят более 5 минут"
  add-apt-repository -y ppa:amnezia/ppa
  apt_update
  apt-get install "${APT[@]}" --allow-downgrades amneziawg amneziawg-dkms amneziawg-tools \
    || die "не удалось установить amneziawg из PPA"
  systemctl stop 'awg-quick@*' >/dev/null 2>&1 || true
  if [ -d /sys/module/amneziawg ] || lsmod 2>/dev/null | grep -E '^amneziawg ' >/dev/null; then
    rmmod amneziawg || die "модуль amneziawg занят — перезагрузите сервер"
  fi
  modprobe amneziawg || die "модуль amneziawg не загрузился"
}

apply_sysctl_hardening() {
  cat > /etc/sysctl.d/99-awg-hardening.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
EOF
  rm -f /etc/sysctl.d/99-awg-forward.conf
  sysctl -q -p /etc/sysctl.d/99-awg-hardening.conf
}

fetch_bot_script() {
  local bot_src="" tmp_bot
  mkdir -p "$BOT_DIR"
  chmod 755 "$BOT_DIR"
  if is_script_file; then
    bot_src="$(dirname "$(readlink -f "$0")")/bot.py"
  fi
  if [ -n "$bot_src" ] && [ -f "$bot_src" ]; then
    cp "$bot_src" "$BOT_DIR/bot.py"
    chmod 755 "$BOT_DIR/bot.py"
    return 0
  fi
  tmp_bot="$(mktemp)"
  if curl -fsSL "${RAW_BASE_URL}/bot.py" -o "$tmp_bot" 2>/dev/null \
    && [ -s "$tmp_bot" ] && python3 -m py_compile "$tmp_bot" 2>/dev/null; then
    install -m 755 "$tmp_bot" "$BOT_DIR/bot.py"
    rm -f "$tmp_bot"
    return 0
  fi
  rm -f "$tmp_bot"
  return 1
}

ensure_client_token() {
  local name="$1"
  [ -n "$name" ] || return 1
  install -d -m 700 "$AWG_DIR"
  [ -f "$TOKENS_FILE" ] || { echo "{}" > "$TOKENS_FILE"; chmod 600 "$TOKENS_FILE"; }

  python3 - "$name" "$TOKENS_FILE" <<'PY'
import sys, json, os, secrets, time

name = sys.argv[1]
tfile = sys.argv[2]
data = {}
try:
    with open(tfile, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = {}

if not isinstance(data, dict):
    data = {}

entry = data.get(name)
tok = None
if isinstance(entry, dict) and entry.get("token"):
    tok = entry["token"]
elif isinstance(entry, str) and entry.startswith("awg_tok_"):
    tok = entry

if not tok:
    tok = f"awg_tok_{secrets.token_hex(16)}"
    data[name] = {"token": tok, "created_at": int(time.time())}
    with open(tfile, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.chmod(tfile, 0o600)

print(tok)
PY
}

get_client_token() {
  local name="$1"
  [ -f "$TOKENS_FILE" ] || return 1
  python3 - "$name" "$TOKENS_FILE" <<'PY'
import sys, json
name = sys.argv[1]
tfile = sys.argv[2]
try:
    with open(tfile, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and name in data:
        entry = data[name]
        tok = entry.get("token") if isinstance(entry, dict) else entry
        if tok:
            print(tok)
            sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY
}

remove_client_token() {
  local name="$1"
  [ -f "$TOKENS_FILE" ] || return 0
  python3 - "$name" "$TOKENS_FILE" <<'PY'
import sys, json
name = sys.argv[1]
tfile = sys.argv[2]
try:
    with open(tfile, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and name in data:
        del data[name]
        with open(tfile, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
except Exception:
    pass
PY
}

ensure_admin_token() {
  install -d -m 700 "$AWG_DIR"
  if [ -f "$ADMIN_TOKEN_FILE" ]; then
    local existing
    existing="$(tr -d ' \t\r\n' < "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
    if [[ "$existing" =~ ^awg_adm_[a-f0-9]{32,128}$ ]]; then
      printf '%s\n' "$existing"
      return 0
    fi
  fi
  local tok
  tok="$(python3 -c 'import secrets; print("awg_adm_" + secrets.token_hex(32))')"
  ( umask 077 && printf '%s\n' "$tok" > "$ADMIN_TOKEN_FILE" )
  chmod 600 "$ADMIN_TOKEN_FILE"
  printf '%s\n' "$tok"
}

rotate_admin_token() {
  install -d -m 700 "$AWG_DIR"
  local tok
  tok="$(python3 -c 'import secrets; print("awg_adm_" + secrets.token_hex(32))')"
  ( umask 077 && printf '%s\n' "$tok" > "$ADMIN_TOKEN_FILE" )
  chmod 600 "$ADMIN_TOKEN_FILE"
  printf '%s\n' "$tok"
}

ensure_api_tls_cert() {
  install -d -m 700 "$AWG_DIR"
  if [ -s "$API_TLS_CERT" ] && [ -s "$API_TLS_KEY" ]; then
    chmod 600 "$API_TLS_CERT" "$API_TLS_KEY" 2>/dev/null || true
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl не найден — TLS для Admin API отключён"
    return 1
  fi
  local pub4 pub6 san="DNS:localhost,IP:127.0.0.1"
  pub4="$(detect_public_ip || true)"
  pub6="$(detect_public_ipv6 || true)"
  [ -n "$pub4" ] && san="${san},IP:${pub4}"
  [ -n "$pub6" ] && san="${san},IP:${pub6}"
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$API_TLS_KEY" -out "$API_TLS_CERT" -days 3650 -nodes \
      -subj "/CN=awg-api" \
      -addext "subjectAltName=${san}" >/dev/null 2>&1 \
    || openssl req -x509 -newkey rsa:2048 \
      -keyout "$API_TLS_KEY" -out "$API_TLS_CERT" -days 3650 -nodes \
      -subj "/CN=awg-api" >/dev/null 2>&1
  ) || return 1
  chmod 600 "$API_TLS_CERT" "$API_TLS_KEY" 2>/dev/null || true
  return 0
}

get_api_tls_fingerprint() {
  [ -s "$API_TLS_CERT" ] && command -v openssl >/dev/null 2>&1 || return 0
  openssl x509 -in "$API_TLS_CERT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || true
}

get_client_endpoint_meta() {
  local name="$1"
  [ -f "$TOKENS_FILE" ] || { printf 'server|\n'; return 0; }
  python3 - "$name" "$TOKENS_FILE" <<'PY'
import sys, json
name, tfile = sys.argv[1], sys.argv[2]
try:
    with open(tfile, "r", encoding="utf-8") as f:
        data = json.load(f)
    entry = data.get(name) if isinstance(data, dict) else None
    if isinstance(entry, dict):
        mode = str(entry.get("endpoint_mode", "server") or "server").strip()
        host = str(entry.get("endpoint_host", "") or "").strip()
        print(f"{mode}|{host}")
        sys.exit(0)
except Exception:
    pass
print("server|")
PY
}

set_client_endpoint_meta() {
  local name="$1"
  local mode="$2"
  local host="${3:-}"
  ensure_client_token "$name" >/dev/null
  python3 - "$name" "$mode" "$host" "$TOKENS_FILE" <<'PY'
import sys, json, os
name, mode, host, tfile = sys.argv[1:5]
data = {}
try:
    with open(tfile, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
entry = data.get(name)
if isinstance(entry, str):
    entry = {"token": entry}
elif not isinstance(entry, dict):
    entry = {}
entry["endpoint_mode"] = mode or "server"
if mode == "custom" and host:
    entry["endpoint_host"] = host
else:
    entry.pop("endpoint_host", None)
data[name] = entry
with open(tfile, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
os.chmod(tfile, 0o600)
PY
}

resolve_client_endpoint_host() {
  local name="$1"
  local fallback_host="${2:-}"
  local meta mode host
  meta="$(get_client_endpoint_meta "$name")"
  mode="${meta%%|*}"
  host="${meta#*|}"
  case "$mode" in
    ipv4)
      local pub4
      pub4="$(detect_public_ip || true)"
      [ -n "$pub4" ] && { printf '%s' "$pub4"; return 0; }
      ;;
    ipv6)
      local pub6
      pub6="$(detect_public_ipv6 || true)"
      [ -n "$pub6" ] && { printf '%s' "$pub6"; return 0; }
      ;;
    custom)
      [ -n "$host" ] && { printf '%s' "$host"; return 0; }
      ;;
  esac
  if [ -n "$fallback_host" ]; then
    printf '%s' "$fallback_host"
  else
    get_public_endpoint_host
  fi
}

do_admin_token() {
  local sub="${1:-show}"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  local tok
  if [ "$sub" = "rotate" ] || [ "$sub" = "--rotate" ]; then
    tok="$(rotate_admin_token)"
    step "Admin-токен API перевыпущен! Обновите его в WebUI контейнера на роутере."
  else
    tok="$(ensure_admin_token)"
  fi
  ensure_api_tls_cert || true

  local pub_ip api_host fp
  pub_ip="$(get_public_endpoint_host || true)"
  if [ -z "$pub_ip" ]; then
    pub_ip="$(detect_public_ip || true)"
  fi
  api_host="${pub_ip:-<IP_сервера>}"
  if [[ "$api_host" =~ : ]] && [[ ! "$api_host" =~ ^\[ ]]; then
    api_host="[${api_host}]"
  fi
  fp="$(get_api_tls_fingerprint || true)"

  printf '\n%b=== Admin API токен управления клиентами (для контейнера MikroTik) ===%b\n' "$C_BOLD" "$C_RESET"
  printf '  Admin-токен:         %b%s%b\n' "$C_CYAN" "$tok" "$C_RESET"
  printf '  URL управления:      https://%s:%s/api/v1/clients\n' "$api_host" "$AWG_API_PORT"
  if [ -n "$fp" ]; then
    printf '  TLS SHA256 отпечаток: %s\n' "$fp"
  fi
  printf '\nВставьте этот токен в разделе «Генератор / QR» → «Серверы VPS» на роутере.\n'
  printf 'Для перевыпуска токена: sudo awg-manager admin-token rotate\n\n'
}

notify_rotation_tg() {
  local p_name="$1"
  local new_port="$2"
  local old_port="${3:-}"
  local p_title
  p_title="$(preset_title "$p_name" "$new_port")"

  [ -r "$BOT_ENV" ] || return 0

  python3 - "$BOT_ENV" "$p_title" "$new_port" "$old_port" <<'PY'
import os, sys, urllib.request, json, html

env_file = sys.argv[1]
p_title = sys.argv[2]
new_port = sys.argv[3]
old_port = sys.argv[4] if len(sys.argv) > 4 else ""

env = {}
try:
    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
except Exception:
    sys.exit(0)

token = env.get("BOT_TOKEN")
if not token:
    sys.exit(0)

recipients = []
admin_ids = [x.strip() for x in env.get("ADMIN_ID", "").split(",") if x.strip()]
recipients.extend(admin_ids)
group_id = env.get("GROUP_ID", "").strip()
topic_id = env.get("TOPIC_ID", "").strip()
topic_id_int = int(topic_id) if topic_id.isdigit() else None

if group_id and group_id not in recipients:
    recipients.append(group_id)

if not recipients:
    sys.exit(0)

port_diff = f"<code>{new_port}/udp</code>" + (f" (был <code>{old_port}/udp</code>)" if old_port and old_port != new_port else "")
msg = (
    "🔄 <b>Ротация серверного туннеля AmneziaWG 3.1!</b>\n\n"
    f"• Профиль: <b>{html.escape(p_title)}</b>\n"
    f"• Слушающий порт: {port_diff}\n"
    "• Сеть: <b>Dual-Stack (IPv4 + IPv6)</b>\n"
    "• Обфускация: новые I1, S1–S4, HeaderProtectionKey, CPA\n"
    "• Роутеры MikroTik с токенами подписки подтянут новые параметры автоматически без разрыва связи."
)

for target in recipients:
    payload = {
        "chat_id": target,
        "text": msg,
        "parse_mode": "HTML"
    }
    if target == group_id and topic_id_int:
        payload["message_thread_id"] = topic_id_int

    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8):
            pass
    except Exception:
        pass
PY
}

fetch_api_script() {
  local api_src="" tmp_api
  mkdir -p "$API_DIR"
  chmod 755 "$API_DIR"
  if is_script_file; then
    api_src="$(dirname "$(readlink -f "$0")")/api.py"
  fi
  if [ -n "$api_src" ] && [ -f "$api_src" ]; then
    cp "$api_src" "$API_DIR/api.py"
    chmod 755 "$API_DIR/api.py"
    return 0
  fi
  tmp_api="$(mktemp)"
  if curl -fsSL "${RAW_BASE_URL}/api.py" -o "$tmp_api" 2>/dev/null \
    && [ -s "$tmp_api" ] && python3 -m py_compile "$tmp_api" 2>/dev/null; then
    install -m 755 "$tmp_api" "$API_DIR/api.py"
    rm -f "$tmp_api"
    return 0
  fi
  rm -f "$tmp_api"
  return 1
}

setup_api_service() {
  step "Настройка API-сервиса подписок и управления клиентами (порт ${AWG_API_PORT}/tcp)"
  fetch_api_script || warn "не удалось установить api.py"
  ensure_admin_token >/dev/null || true
  ensure_api_tls_cert || true

  cat > /etc/systemd/system/awg-api.service <<EOF
[Unit]
Description=AmneziaWG Client Subscription and Management API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${API_DIR}
Environment=AWG_DIR=${AWG_DIR}
Environment=AWG_API_PORT=${AWG_API_PORT}
Environment=AWG_MANAGER_BIN=/usr/local/bin/awg-manager
ExecStart=/usr/bin/python3 ${API_DIR}/api.py
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now awg-api.service >/dev/null 2>&1 || true
  systemctl restart awg-api.service >/dev/null 2>&1 || true

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${AWG_API_PORT}/tcp" >/dev/null 2>&1 || true
    step "ufw: открыт порт ${AWG_API_PORT}/tcp для API подписок"
  fi
}

do_api_status() {
  printf '\n%b=== Статус API-сервиса подписок ===%b\n' "$C_BOLD" "$C_RESET"
  systemctl status awg-api --no-pager || true
}

do_api_restart() {
  systemctl restart awg-api && step "API-сервис подписок перезапущен"
}

ensure_dualstack_support() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || return 0

  local srv_addr
  srv_addr="$(conf_get Address "$conf")"
  [ -n "$srv_addr" ] || return 0

  local ip6_pfx="${AWG_IPV6_PREFIX:-fd42:42:42::}"
  local ip6_subnet="${AWG_IPV6_SUBNET:-fd42:42:42::/64}"

  apply_sysctl_hardening || true
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null 2>&1 || true

  local wan_iface wan6_iface
  wan_iface="$(detect_wan_iface || true)"
  wan6_iface="$(detect_wan6_iface || true)"
  wan6_iface="${wan6_iface:-$wan_iface}"

  # 1. Если на сервере в Address нет IPv6
  if ! printf '%s' "$srv_addr" | grep -q ':'; then
    step "Авто-активация Dual-Stack IPv4 + IPv6 для серверного туннеля..."
    local new_srv_addr="${srv_addr}, ${ip6_pfx}1/64"
    sed -i -E "s|^Address[[:space:]]*=.*$|Address = ${new_srv_addr}|" "$conf"

    if ip link show "$AWG_IFACE" >/dev/null 2>&1; then
      ip -6 addr add "${ip6_pfx}1/64" dev "$AWG_IFACE" 2>/dev/null || true
    fi

    if ! grep -q 'ip6tables' "$conf"; then
      python3 - "$conf" "$ip6_subnet" "$wan6_iface" <<'PY'
import sys
conf = sys.argv[1]
ip6_subnet = sys.argv[2]
wan6_iface = sys.argv[3]

ip6_postup = f"; ip6tables -w -t nat -C POSTROUTING -s {ip6_subnet} -o {wan6_iface} -j MASQUERADE 2>/dev/null || ip6tables -w -t nat -A POSTROUTING -s {ip6_subnet} -o {wan6_iface} -j MASQUERADE 2>/dev/null || true; ip6tables -w -C FORWARD -i %i -o {wan6_iface} -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i %i -o {wan6_iface} -j ACCEPT 2>/dev/null || true; ip6tables -w -C FORWARD -i {wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i {wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"

ip6_postdown = f"; ip6tables -w -t nat -D POSTROUTING -s {ip6_subnet} -o {wan6_iface} -j MASQUERADE 2>/dev/null || true; ip6tables -w -D FORWARD -i %i -o {wan6_iface} -j ACCEPT 2>/dev/null || true; ip6tables -w -D FORWARD -i {wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"

try:
    with open(conf, 'r') as f:
        lines = f.readlines()
    out = []
    for line in lines:
        if line.strip().startswith('PostUp') and '=' in line and 'ip6tables' not in line:
            out.append(f"{line.rstrip()}{ip6_postup}\n")
        elif line.strip().startswith('PostDown') and '=' in line and 'ip6tables' not in line:
            out.append(f"{line.rstrip()}{ip6_postdown}\n")
        else:
            out.append(line)
    with open(conf, 'w') as f:
        f.writelines(out)
except Exception:
    pass
PY
    fi
  fi

  # Активируем правила ip6tables в ядре немедленно
  if [ -n "$wan6_iface" ]; then
    ip6tables -w -t nat -C POSTROUTING -s "${ip6_subnet}" -o "${wan6_iface}" -j MASQUERADE 2>/dev/null || ip6tables -w -t nat -A POSTROUTING -s "${ip6_subnet}" -o "${wan6_iface}" -j MASQUERADE 2>/dev/null || true
    ip6tables -w -C FORWARD -i "$AWG_IFACE" -o "${wan6_iface}" -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i "$AWG_IFACE" -o "${wan6_iface}" -j ACCEPT 2>/dev/null || true
    ip6tables -w -C FORWARD -i "${wan6_iface}" -o "$AWG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i "${wan6_iface}" -o "$AWG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi

  # 2. Обновляем конфиги клиентов
  local cf
  for cf in "$AWG_DIR"/*.conf; do
    [ -f "$cf" ] || continue
    [ "$cf" != "$AWG_DIR/$AWG_IFACE.conf" ] || continue
    local c_addr
    c_addr="$(conf_get Address "$cf" || true)"
    [ -n "$c_addr" ] || continue

    # Гарантируем AllowedIPs и DNS в клиентском конфиге
    sed -i -E "s|^AllowedIPs[[:space:]]*=.*$|AllowedIPs = 0.0.0.0/0, ::/0|" "$cf"
    sed -i -E "s|^DNS[[:space:]]*=.*$|DNS = ${AWG_DNS}|" "$cf"

    local c_priv c_pub
    c_priv="$(conf_get PrivateKey "$cf" 2>/dev/null || true)"
    [ -n "$c_priv" ] || continue
    c_pub="$(printf '%s\n' "$c_priv" | awg pubkey 2>/dev/null || true)"
    [ -n "$c_pub" ] || continue

    local target_allowed=""
    if ! printf '%s' "$c_addr" | grep -q ':'; then
      local ip_only="${c_addr%%/*}"
      local last_oct="${ip_only##*.}"
      last_oct="${last_oct:-2}"
      local cli_ip6="${ip6_pfx}${last_oct}/128"
      target_allowed="${c_addr}, ${cli_ip6}"
      sed -i -E "s|^Address[[:space:]]*=.*$|Address = ${target_allowed}|" "$cf"
    else
      target_allowed="$c_addr"
    fi

    # Обновляем AllowedIPs для этого пира в awg0.conf
    python3 -c "
import sys
conf = sys.argv[1]
pub = sys.argv[2]
new_allowed = sys.argv[3]
try:
    with open(conf, 'r') as f:
        lines = f.readlines()
    out = []
    in_target = False
    for line in lines:
        if line.strip().startswith('[Peer]'):
            in_target = False
        if line.strip().startswith('PublicKey') and pub in line:
            in_target = True
        if in_target and line.strip().startswith('AllowedIPs'):
            out.append(f'AllowedIPs = {new_allowed}\n')
            in_target = False
            continue
        out.append(line)
    with open(conf, 'w') as f:
        f.writelines(out)
except Exception:
    pass
" "$conf" "$c_pub" "$target_allowed" 2>/dev/null || true

    if ip link show "$AWG_IFACE" >/dev/null 2>&1; then
      awg set "$AWG_IFACE" peer "$c_pub" allowed-ips "${target_allowed}" 2>/dev/null || true
    fi

    touch "$cf"
  done
}

do_update() {
  step "Проверка и обновление awg-manager до последней версии"
  acquire_lock

  local tmp_upd
  tmp_upd="$(mktemp -d /tmp/awg-update.XXXXXX)"
  trap 'rm -rf "$tmp_upd"' RETURN

  step "Загрузка актуальных скриптов с GitHub..."
  local dl_err=0
  curl -fsSL "${RAW_BASE_URL}/install.sh" -o "$tmp_upd/install.sh" || dl_err=1
  curl -fsSL "${RAW_BASE_URL}/api.py" -o "$tmp_upd/api.py" || dl_err=1
  curl -fsSL "${RAW_BASE_URL}/bot.py" -o "$tmp_upd/bot.py" || dl_err=1

  if [ "$dl_err" -ne 0 ] || [ ! -s "$tmp_upd/install.sh" ]; then
    release_lock
    die "Не удалось загрузить файлы обновления. Проверьте сеть на сервере."
  fi

  if ! bash -n "$tmp_upd/install.sh" 2>/dev/null; then
    release_lock
    die "Сбой валидации синтаксиса install.sh"
  fi
  if ! python3 -m py_compile "$tmp_upd/api.py" 2>/dev/null; then
    release_lock
    die "Сбой валидации синтаксиса api.py"
  fi
  if ! python3 -m py_compile "$tmp_upd/bot.py" 2>/dev/null; then
    release_lock
    die "Сбой валидации синтаксиса bot.py"
  fi

  step "Установка обновлений CLI и сервисов..."
  install -m 755 "$tmp_upd/install.sh" /usr/local/bin/awg-manager

  mkdir -p "$API_DIR"
  install -m 755 "$tmp_upd/api.py" "$API_DIR/api.py"
  setup_api_service

  # Очистка устаревших временных путей если создавались ранее
  rm -rf /etc/amnezia/awg-api /etc/amnezia/awg-tokens 2>/dev/null || true

  if [ -d "$BOT_DIR" ]; then
    install -m 755 "$tmp_upd/bot.py" "$BOT_DIR/bot.py"
    if systemctl is-active --quiet awg-bot 2>/dev/null; then
      systemctl restart awg-bot 2>/dev/null || true
    fi
  fi

  # Генерация постоянных токенов для существующих клиентов, если их ещё нет
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$conf" ]; then
    while IFS= read -r client_name; do
      if [ -n "$client_name" ]; then
        ensure_client_token "$client_name" >/dev/null 2>&1 || true
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

  # Авто-исправление возможных дубликатов портов в конфигах клиентов
  sanitize_existing_client_endpoints || true

  # Авто-миграция туннеля и клиентов на Dual-Stack IPv4+IPv6
  ensure_dualstack_support || true

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${AWG_API_PORT:-8443}/tcp" comment 'AmneziaWG Subscription API' >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  release_lock
  step "awg-manager успешно обновлён до актуальной версии!"
  printf '  CLI утилита:        /usr/local/bin/awg-manager (обновлена)\n'
  printf '  API подписок/упр.:  awg-api.service (порт %s/tcp HTTP+HTTPS, активен)\n' "${AWG_API_PORT:-8443}"
  printf '  Admin API токен:    sudo awg-manager admin-token\n'
  printf '  Туннель и клиенты:  продолжают работать без перезапуска.\n\n'
}

cleanup() {
  if [ -n "${TMP_DIR:-}" ]; then rm -rf "$TMP_DIR"; fi
  release_lock
  if [ -n "${TEE_PID:-}" ]; then
    exec 1>&- 2>&- || true
    wait "$TEE_PID" 2>/dev/null || true
    TEE_PID=""
  fi
}
trap cleanup EXIT
trap 'die "сбой на строке ${LINENO} (код $?)"' ERR

#--- установка AmneziaWG -------------------------------------------------------
do_install() {
  acquire_lock
  step "Предпроверка системы"
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
    die "нужна Ubuntu 24.04 LTS (обнаружено: ${PRETTY_NAME:-unknown})"
  fi
  case "$(uname -m)" in
    x86_64 | aarch64) ;;
    *) die "архитектура $(uname -m) не поддерживается (нужна x86_64 или aarch64)" ;;
  esac
  [ -d /run/systemd/system ] || die "systemd не запущен — нужен VPS/сервер, не контейнер"
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet; then
    die "обнаружен контейнер: DKMS требует собственного ядра — нужен VPS"
  fi

  local sb_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
  if [ -r "$sb_var" ]; then
    local sb_state
    sb_state="$(od -An -t u1 "$sb_var" | awk '{print $NF}')"
    if [ "$sb_state" = "1" ]; then
      die "Secure Boot включён: неподписанный DKMS-модуль не загрузится. Отключите Secure Boot в UEFI."
    fi
  fi

  local avail_mb
  avail_mb="$(df -Pm / | awk 'NR==2{print $4}')"
  if [ "${avail_mb:-0}" -lt 800 ]; then
    die "мало места на / : ${avail_mb} МБ (нужно >= 800 МБ для сборки DKMS)"
  fi

  if [ -f /var/run/reboot-required ]; then
    warn "Обнаружен /var/run/reboot-required — если сборка DKMS упадёт, перезагрузите сервер и повторите."
  fi

  WAN_IFACE="$(detect_wan_iface)"
  [ -n "$WAN_IFACE" ] || die "не найден интерфейс с default-маршрутом (IPv4)"

  step "Установка зависимостей и заголовков ядра $(uname -r)"
  wait_for_apt_lock
  apt_update || die "apt-get update не удался"
  apt-get install "${APT[@]}" ca-certificates curl gnupg2 openssl software-properties-common python3
  add-apt-repository -y universe
  apt_update
  apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1 \
    || die "linux-headers-$(uname -r) недоступны в репозитории (перезагрузите сервер в актуальное ядро)"
  apt-get install "${APT[@]}" dkms build-essential "linux-headers-$(uname -r)" \
    qrencode wireguard-tools iptables iproute2

  step "Установка нативного модуля AmneziaWG (DKMS) из ppa:amnezia/ppa"
  if [ "$(dpkg-query -W -f='${Status}' amneziawg 2>/dev/null || true)" != "install ok installed" ]; then
    wait_for_apt_lock
    add-apt-repository -y ppa:amnezia/ppa
    apt_update
    apt-get install "${APT[@]}" amneziawg
  elif ! modinfo amneziawg >/dev/null 2>&1; then
    warn "Модуль amneziawg не собран для ядра $(uname -r) — пересобираю DKMS..."
    dpkg-reconfigure -f noninteractive amneziawg-dkms || dkms autoinstall || upgrade_awg_packages
  fi

  if ! modprobe amneziawg; then
    die "модуль amneziawg не загрузился (проверьте dkms status)"
  fi
  [ -d /sys/module/amneziawg ] || die "модуль amneziawg отсутствует в /sys/module"

  if ! probe_awg31; then
    warn "профиль 3.1 не принят — обновляю пакеты AmneziaWG..."
    upgrade_awg_packages
    probe_awg31 || die "модуль не принимает профиль 3.1 даже после обновления"
  fi

  local use_disable_cookies=0
  if probe_disable_cookies; then
    use_disable_cookies=1
  fi

  step "Настройка туннеля AmneziaWG 3.1 (стандартный профиль без обходов)"
  install -d -m 700 "$AWG_DIR"

  local prefix AWG_SRV_IP AWG_CLI_IP
  prefix="$(get_subnet_prefix)"
  if [ -n "$prefix" ]; then
    AWG_SUBNET="${prefix}0/24"
    AWG_SRV_IP="${prefix}1"
    AWG_CLI_IP="${prefix}2"
    step "Используется существующая подсеть: ${AWG_SUBNET}"
  elif [ -n "$AWG_SUBNET" ]; then
    validate_subnet_24 "$AWG_SUBNET" || die "некорректная подсеть AWG_SUBNET='$AWG_SUBNET' (нужна приватная /24, например 10.66.66.0/24)"
    prefix="${AWG_SUBNET%0/24}"
    AWG_SRV_IP="${prefix}1"
    AWG_CLI_IP="${prefix}2"
    step "Используется заданная подсеть: ${AWG_SUBNET}"
  else
    local rand_x rand_y
    rand_x="$(rand_range 11 254)"
    while [ "$rand_x" -eq 127 ]; do rand_x="$(rand_range 11 254)"; done
    rand_y="$(rand_range 1 254)"
    AWG_SUBNET="10.${rand_x}.${rand_y}.0/24"
    AWG_SRV_IP="10.${rand_x}.${rand_y}.1"
    AWG_CLI_IP="10.${rand_x}.${rand_y}.2"
    step "Сгенерирована случайная подсеть клиентов: ${AWG_SUBNET}"
  fi

  PUBLIC_IP="$(detect_public_ip || true)"
  if [ -z "$PUBLIC_IP" ]; then
    if [ "$IS_TTY" = 1 ]; then
      read -r -p "Не удалось определить публичный IPv4. Введите внешний IP/домен сервера: " PUBLIC_IP || die "ввод прерван"
      [ -n "$PUBLIC_IP" ] || die "внешний IP/домен не задан"
    else
      die "не удалось определить публичный IPv4 (задайте AWG_ENDPOINT=<внешний_IP>)"
    fi
  fi

  local regen=1
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    if grep -q '^HeaderProtectionKey[[:space:]]*=' "$AWG_DIR/$AWG_IFACE.conf"; then
      regen=0
      step "Конфиг $AWG_IFACE.conf (профиль 3.1) уже существует — пропускаю генерацию"
      AWG_PORT="$(conf_get ListenPort "$AWG_DIR/$AWG_IFACE.conf")"
    else
      step "Миграция старого конфига 1.x -> 3.1..."
      local ts old_f
      ts="$(date '+%Y%m%d-%H%M%S')"
      cp -a "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/$AWG_IFACE.conf.bak-1x-$ts"
      chmod 600 "$AWG_DIR/$AWG_IFACE.conf.bak-1x-$ts"
      for old_f in "$AWG_DIR"/*.conf "$AWG_DIR"/*.png; do
        [ -e "$old_f" ] || continue
        [ "$(basename "$old_f")" = "${AWG_IFACE}.conf" ] && continue
        rm -f "$old_f"
      done
      warn "При миграции 1.x -> 3.1 ключи и параметры шифрования обновлены полностью — все клиенты (включая client1) должны заново импортировать конфиг/QR!"
    fi
  fi

  if [ "$regen" -eq 1 ]; then
    AWG_PORT="$(choose_awg_port)" || die "не найден свободный UDP-порт"
    ( umask 077
      set +x
      local srv_priv srv_pub cli_priv cli_pub
      srv_priv="$(awg genkey)"
      srv_pub="$(printf '%s\n' "$srv_priv" | awg pubkey)"
      cli_priv="$(awg genkey)"
      cli_pub="$(printf '%s\n' "$cli_priv" | awg pubkey)"

      local jc jmin jmax s1 s2 s3 s4 s4_free=() h1 h2 h3 h4 i1 hpk cpa dc_line=""
      jc=$(rand_range 3 5)
      jmin=$(rand_range 40 79)
      jmax=$((jmin + $(rand_range 50 160)))
      s1=$(rand_range 15 150)
      s2=$(rand_range 15 150)
      while [ $((s1 + 56)) -eq "$s2" ]; do s2=$(rand_range 15 150); done
      s3=$(rand_range 12 55)
      while [ $((s2 + 28)) -eq "$s3" ] || [ $((s1 + 84)) -eq "$s3" ]; do s3=$(rand_range 12 55); done

      for ((s4_cand = 12; s4_cand <= 27; s4_cand++)); do
        if [ "$s4_cand" -eq 16 ]; then continue; fi
        s4_collides "$s1" "$s2" "$s3" "$s4_cand" || s4_free+=("$s4_cand")
      done
      [ "${#s4_free[@]}" -gt 0 ] || die "ошибка расчёта параметров S4"
      s4="${s4_free[$(rand_range 0 $((${#s4_free[@]} - 1)))]}"
      h1=1; h2=2; h3=3; h4=4
      i1="$(cps_i1)" || die "ошибка генерации I1"
      hpk="$(awg genkey)"
      cpa='32-128'
      if [ "$use_disable_cookies" -eq 1 ]; then
        dc_line=$'DisableCookies = on\n'
      fi

      cat > "$AWG_DIR/$AWG_IFACE.conf" <<EOF
[Interface]
PrivateKey = ${srv_priv}
Address = ${AWG_SRV_IP}/24, ${AWG_IPV6_PREFIX}1/64
ListenPort = ${AWG_PORT}
MTU = ${AWG_MTU}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
S3 = ${s3}
S4 = ${s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
I1 = ${i1}
HeaderProtectionKey = ${hpk}
ContentPaddingAddition = ${cpa}
${dc_line}PostUp = iptables -w -t nat -C POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -C FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -C FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; ip6tables -w -t nat -C POSTROUTING -s ${AWG_IPV6_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || ip6tables -w -t nat -A POSTROUTING -s ${AWG_IPV6_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || true; ip6tables -w -C FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || true; ip6tables -w -C FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -w -t nat -D POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || true; iptables -w -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || true; iptables -w -D FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; ip6tables -w -t nat -D POSTROUTING -s ${AWG_IPV6_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || true; ip6tables -w -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || true; ip6tables -w -D FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

[Peer]
# client1
PublicKey = ${cli_pub}
AllowedIPs = ${AWG_CLI_IP}/32, ${AWG_IPV6_PREFIX}2/128
EOF

      cat > "$AWG_DIR/client1.conf" <<EOF
[Interface]
PrivateKey = ${cli_priv}
Address = ${AWG_CLI_IP}/32, ${AWG_IPV6_PREFIX}2/128
DNS = ${AWG_DNS}
MTU = ${AWG_MTU}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
S3 = ${s3}
S4 = ${s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
I1 = ${i1}
HeaderProtectionKey = ${hpk}
ContentPaddingAddition = ${cpa}

[Peer]
PublicKey = ${srv_pub}
Endpoint = $(format_endpoint "$PUBLIC_IP" "$AWG_PORT")
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
      chmod 600 "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/client1.conf"
      qrencode -o "$AWG_DIR/client1.png" -s 6 -m 2 < "$AWG_DIR/client1.conf" || true
      chmod 600 "$AWG_DIR/client1.png" 2>/dev/null || true
    )
  fi

  apply_sysctl_hardening

  systemctl enable "awg-quick@${AWG_IFACE}" >/dev/null 2>&1 || true
  systemctl restart "awg-quick@${AWG_IFACE}" || die "сервис awg-quick не запустился"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${AWG_PORT}/udp" >/dev/null
    step "ufw: открыт порт ${AWG_PORT}/udp"
  fi

  step "Установка утилиты управления awg-manager в /usr/local/bin/"
  if is_script_file; then
    local self_real
    self_real="$(readlink -f "$0")"
    if [ "$self_real" != "/usr/local/bin/awg-manager" ]; then
      install -m 755 "$self_real" /usr/local/bin/awg-manager
    fi
  else
    local tmp_mgr
    tmp_mgr="$(mktemp)"
    curl -fsSL "${RAW_BASE_URL}/install.sh" -o "$tmp_mgr" || { rm -f "$tmp_mgr"; die "не удалось скачать install.sh"; }
    bash -n "$tmp_mgr" || { rm -f "$tmp_mgr"; die "скачанный install.sh повреждён"; }
    install -m 755 "$tmp_mgr" /usr/local/bin/awg-manager
    rm -f "$tmp_mgr"
  fi

  if ! fetch_bot_script; then
    warn "Не удалось установить bot.py сейчас (будет скачан при настройке бота)."
  fi

  local tok1
  tok1="$(ensure_client_token "client1")"
  setup_api_service

  ( umask 077
    cat > "$CRED_FILE" <<EOF
# AmneziaWG 3.1 — $(date '+%F %T')
AWG_ENDPOINT=${PUBLIC_IP}:${AWG_PORT}/udp
AWG_SUBNET=${AWG_SUBNET}
AWG_CLIENT_CONFIG=${AWG_DIR}/client1.conf
AWG_CLIENT_QR=${AWG_DIR}/client1.png
AWG_CLIENT_TOKEN=${tok1}
AWG_CLIENT_SUB_URL=http://${PUBLIC_IP}:${AWG_API_PORT}/sub/${tok1}
EOF
    chmod 600 "$CRED_FILE"
  )

  release_lock

  step "Установка AmneziaWG 3.1 успешно завершена!"
  printf '\n'
  printf '============================================================\n'
  printf '  СЕРВЕР AMNEZIAWG 3.1 ГОТОВ К РАБОТЕ\n'
  printf '============================================================\n'
  printf '  Эндпоинт:        %s:%s/udp\n' "$PUBLIC_IP" "$AWG_PORT"
  printf '  Подсеть туннеля: %s\n' "$AWG_SUBNET"
  printf '  Маскировка ТСПУ: QUIC I1 + HPK + S1-S4 + CPA%s\n' "$([ "$use_disable_cookies" -eq 1 ] && echo ' + DisableCookies' || echo '')"
  printf '  Клиентский файл: %s/client1.conf (0.0.0.0/0)\n' "$AWG_DIR"
  printf '  QR-код (PNG):    %s/client1.png\n' "$AWG_DIR"
  printf '  Токен подписки:  %s\n' "$tok1"
  printf '  URL подписки:    http://%s:%s/sub/%s\n' "$PUBLIC_IP" "$AWG_API_PORT" "$tok1"
  printf '%s\n' '------------------------------------------------------------'
  printf '  УПРАВЛЕНИЕ СЕРВЕРОМ:\n'
  printf '  • Консольное меню:   sudo awg-manager\n'
  printf '  • Telegram-бот:      sudo awg-manager bot\n'
  printf '  • Самодиагностика:   sudo awg-manager diagnose\n'
  printf '============================================================\n\n'

  if [ -f "$AWG_DIR/client1.conf" ] && [ "$IS_TTY" = 1 ]; then
    printf 'QR-код первого клиента (сканируйте в Amnezia >= 5.0.1.5):\n\n'
    qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
  fi
}

#--- управление клиентами ------------------------------------------------------
do_add_client() {
  acquire_lock
  local name="" opt_dns="" opt_mtu="" opt_allowed="" opt_keepalive="" opt_endpoint=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dns) opt_dns="${2:-}"; shift 2 ;;
      --mtu) opt_mtu="${2:-}"; shift 2 ;;
      --allowed-ips) opt_allowed="${2:-}"; shift 2 ;;
      --keepalive) opt_keepalive="${2:-}"; shift 2 ;;
      --endpoint) opt_endpoint="${2:-}"; shift 2 ;;
      --*) die "неизвестный флаг для add-client: $1" ;;
      *)
        if [ -z "$name" ]; then name="$1"; fi
        shift
        ;;
    esac
  done

  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  if [ -z "$name" ]; then
    if [ "$IS_TTY" = 1 ]; then
      read -r -p "Имя нового клиента (латиница/цифры, например phone): " name || die "ввод прерван"
    else
      die "укажите имя: awg-manager add-client <name>"
    fi
  fi
  is_valid_client_name "$name" || die "некорректное имя '$name' (допустимы A-Z, 0-9, _, -, 1-32 символа, не системное)"

  if [ -f "$AWG_DIR/$name.conf" ] || grep -q "^# ${name}$" "$conf"; then
    die "клиент '$name' уже существует"
  fi

  local prefix prefix_re
  prefix="$(get_subnet_prefix)"
  [ -n "$prefix" ] || die "не удалось определить подсеть из $conf"
  prefix_re="${prefix//./\\.}"

  local used ip="" i
  used="$(awk -F'=' '/^AllowedIPs[[:space:]]*=/{print $2}' "$conf" | grep -oE "${prefix_re}[0-9]+" | sort -u || true)"
  for i in $(seq 2 254); do
    if ! printf '%s\n' "$used" | grep -qx "${prefix}${i}"; then
      ip="${prefix}${i}"
      break
    fi
  done
  [ -n "$ip" ] || die "в подсети ${prefix}0/24 нет свободных адресов"

  set +x
  local k v
  local -A P=()
  for k in MTU Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 ListenPort; do
    v="$(conf_get "$k" "$conf" || true)"
    [ -n "$v" ] || die "в $conf нет параметра $k"
    P[$k]="$v"
  done
  for k in I1 HeaderProtectionKey ContentPaddingAddition; do
    P[$k]="$(conf_get "$k" "$conf" || true)"
  done

  local cli_dns="${opt_dns:-$AWG_DNS}"
  local cli_mtu="${opt_mtu:-${P[MTU]}}"
  local cli_allowed="${opt_allowed:-0.0.0.0/0, ::/0}"
  local cli_keepalive="${opt_keepalive:-25}"

  [[ "$cli_mtu" =~ ^[0-9]+$ ]] && [ "$cli_mtu" -ge 576 ] && [ "$cli_mtu" -le 9000 ] || die "некорректный MTU: $cli_mtu"
  [[ "$cli_keepalive" =~ ^[0-9]+$ ]] && [ "$cli_keepalive" -le 3600 ] || die "некорректный Keepalive: $cli_keepalive"
  case "$cli_dns$cli_allowed" in *$'\n'*|*$'\r'*) die "недопустимые символы переноса строки" ;; esac

  local srv_pub endpoint priv pubk ep_mode="server" ep_custom_host=""
  srv_pub="$(conf_get PrivateKey "$conf" | awg pubkey)" || die "ошибка pubkey сервера"

  case "${opt_endpoint:-server}" in
    server|default|"")
      ep_mode="server"
      endpoint="$(get_public_endpoint_host)"
      ;;
    ipv4|4)
      ep_mode="ipv4"
      endpoint="$(detect_public_ip || true)"
      [ -n "$endpoint" ] || die "внешний IPv4 не обнаружен на сервере"
      ;;
    ipv6|6)
      ep_mode="ipv6"
      endpoint="$(detect_public_ipv6 || true)"
      [ -n "$endpoint" ] || die "внешний IPv6 не обнаружен на сервере"
      ;;
    *)
      ep_mode="custom"
      ep_custom_host="$(extract_host_from_endpoint "$opt_endpoint")"
      [ -n "$ep_custom_host" ] || die "некорректный endpoint: $opt_endpoint"
      endpoint="$ep_custom_host"
      ;;
  esac
  [ -n "$endpoint" ] || die "не удалось определить внешний IP сервера"

  ( umask 077
    priv="$(awg genkey)"
    pubk="$(printf '%s\n' "$priv" | awg pubkey)"

    local ip6_pfx ip6_addr client_full_addr
    ip6_pfx="$(get_ipv6_prefix)"
    ip6_addr="${ip6_pfx}${i}/128"
    client_full_addr="${ip}/32, ${ip6_addr}"

    awg set "$AWG_IFACE" peer "$pubk" allowed-ips "$client_full_addr" \
      || die "ядро не приняло peer (awg set)"

    if ! cat >> "$conf" <<EOF

[Peer]
# ${name}
PublicKey = ${pubk}
AllowedIPs = ${client_full_addr}
EOF
    then
      awg set "$AWG_IFACE" peer "$pubk" remove 2>/dev/null || true
      die "не удалось дописать peer в $conf"
    fi

    cat > "$AWG_DIR/$name.conf" <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${client_full_addr}
DNS = ${cli_dns}
MTU = ${cli_mtu}
Jc = ${P[Jc]}
Jmin = ${P[Jmin]}
Jmax = ${P[Jmax]}
S1 = ${P[S1]}
S2 = ${P[S2]}
S3 = ${P[S3]}
S4 = ${P[S4]}
H1 = ${P[H1]}
H2 = ${P[H2]}
H3 = ${P[H3]}
H4 = ${P[H4]}
${P[I1]:+I1 = ${P[I1]}
}${P[HeaderProtectionKey]:+HeaderProtectionKey = ${P[HeaderProtectionKey]}
}${P[ContentPaddingAddition]:+ContentPaddingAddition = ${P[ContentPaddingAddition]}
}
[Peer]
PublicKey = ${srv_pub}
Endpoint = $(format_endpoint "$endpoint" "${P[ListenPort]}")
AllowedIPs = ${cli_allowed}
PersistentKeepalive = ${cli_keepalive}
EOF
    chmod 600 "$AWG_DIR/$name.conf" "$conf"
    qrencode -o "$AWG_DIR/$name.png" -s 6 -m 2 < "$AWG_DIR/$name.conf" || true
    chmod 600 "$AWG_DIR/$name.png" 2>/dev/null || true
  )

  local tok
  tok="$(ensure_client_token "$name")"
  if [ "$ep_mode" != "server" ]; then
    set_client_endpoint_meta "$name" "$ep_mode" "$ep_custom_host"
  fi
  local ep_pub="${endpoint:-$(detect_public_ip || true)}"
  local api_ep_host="$ep_pub"
  if [[ "$api_ep_host" =~ : ]] && [[ ! "$api_ep_host" =~ ^\[ ]]; then
    api_ep_host="[${api_ep_host}]"
  fi
  local sub_url="http://${api_ep_host}:${AWG_API_PORT}/sub/${tok}"

  release_lock
  step "Клиент '$name' ($ip) успешно создан!"
  printf '  Файл конфига:             %s/%s.conf\n' "$AWG_DIR" "$name"
  printf '  QR-код:                   %s/%s.png\n' "$AWG_DIR" "$name"
  printf '  Токен для контейнера:     %b%s%b\n' "$C_CYAN" "$tok" "$C_RESET"
  printf '  Ссылка подписки (.conf):  %s\n\n' "$sub_url"
  if [ "$IS_TTY" = 1 ]; then
    qrencode -t ansiutf8 < "$AWG_DIR/$name.conf" || true
  fi
}

do_edit_client() {
  acquire_lock
  local name="" new_name="" opt_dns="" has_dns=0 opt_mtu="" has_mtu=0
  local opt_allowed="" has_allowed=0 opt_keepalive="" has_keepalive=0
  local opt_endpoint="" has_endpoint=0 do_rekey=0 do_rotate_tok=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --rename) new_name="${2:-}"; shift 2 ;;
      --dns) opt_dns="${2:-}"; has_dns=1; shift 2 ;;
      --mtu) opt_mtu="${2:-}"; has_mtu=1; shift 2 ;;
      --allowed-ips) opt_allowed="${2:-}"; has_allowed=1; shift 2 ;;
      --keepalive) opt_keepalive="${2:-}"; has_keepalive=1; shift 2 ;;
      --endpoint) opt_endpoint="${2:-}"; has_endpoint=1; shift 2 ;;
      --rekey) do_rekey=1; shift ;;
      --rotate-token) do_rotate_tok=1; shift ;;
      --*) die "неизвестный флаг для edit-client: $1" ;;
      *)
        if [ -z "$name" ]; then name="$1"; fi
        shift
        ;;
    esac
  done

  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"
  [ -n "$name" ] || die "укажите имя: awg-manager edit-client <name> [опции]"
  is_valid_client_name "$name" || die "некорректное имя клиента '$name'"
  [ -f "$AWG_DIR/$name.conf" ] || die "конфиг клиента '$name' не найден"

  if [ "$has_mtu" -eq 1 ]; then
    [[ "$opt_mtu" =~ ^[0-9]+$ ]] && [ "$opt_mtu" -ge 576 ] && [ "$opt_mtu" -le 9000 ] || die "некорректный MTU: $opt_mtu"
  fi
  if [ "$has_keepalive" -eq 1 ]; then
    [[ "$opt_keepalive" =~ ^[0-9]+$ ]] && [ "$opt_keepalive" -le 3600 ] || die "некорректный Keepalive: $opt_keepalive"
  fi
  case "$opt_dns$opt_allowed" in *$'\n'*|*$'\r'*) die "недопустимые символы переноса строки" ;; esac

  # 1. Переименование клиента
  if [ -n "$new_name" ] && [ "$new_name" != "$name" ]; then
    is_valid_client_name "$new_name" || die "некорректное новое имя '$new_name'"
    if [ -f "$AWG_DIR/$new_name.conf" ] || grep -q "^# ${new_name}$" "$conf"; then
      die "клиент '$new_name' уже существует"
    fi
    python3 - "$conf" "$name" "$new_name" <<'PY'
import sys, os
conf_path, old_n, new_n = sys.argv[1:4]
lines = open(conf_path, "r", encoding="utf-8").read().splitlines()
out = []
in_peer = False
renamed = False
for ln in lines:
    s = ln.strip()
    if s == "[Peer]":
        in_peer = True
        out.append(ln)
    elif s.startswith("["):
        in_peer = False
        out.append(ln)
    elif in_peer and not renamed and s.startswith("#") and s[1:].strip() == old_n:
        out.append(f"# {new_n}")
        renamed = True
    else:
        out.append(ln)
tmp = conf_path + ".rename.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, conf_path)
PY
    mv "$AWG_DIR/$name.conf" "$AWG_DIR/$new_name.conf"
    [ -f "$AWG_DIR/$name.png" ] && mv "$AWG_DIR/$name.png" "$AWG_DIR/$new_name.png" || true
    if [ -f "$TOKENS_FILE" ]; then
      python3 - "$TOKENS_FILE" "$name" "$new_name" <<'PY'
import sys, json, os
tf, old_n, new_n = sys.argv[1:4]
try:
    data = json.load(open(tf, "r", encoding="utf-8"))
    if isinstance(data, dict) and old_n in data:
        data[new_n] = data.pop(old_n)
        with open(tf, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(tf, 0o600)
except Exception:
    pass
PY
    fi
    name="$new_name"
  fi

  local cconf="$AWG_DIR/$name.conf"
  ensure_client_token "$name" >/dev/null

  # 2. Перегенерация ключевой пары клиента (--rekey)
  if [ "$do_rekey" -eq 1 ]; then
    set +x
    local old_pub peer_allowed new_priv new_pub
    old_pub="$(awk -v want="$name" '/^\[Peer\]/{c=""} /^#/{c=$0; sub(/^#[ \t]*/,"",c); next} /^PublicKey/{if(c==want){v=$0; sub(/^PublicKey[ \t]*=[ \t]*/,"",v); print v; exit}}' "$conf")"
    peer_allowed="$(awk -v want="$name" '/^\[Peer\]/{c=""} /^#/{c=$0; sub(/^#[ \t]*/,"",c); next} /^AllowedIPs/{if(c==want){v=$0; sub(/^AllowedIPs[ \t]*=[ \t]*/,"",v); print v; exit}}' "$conf")"
    [ -n "$old_pub" ] && [ -n "$peer_allowed" ] || die "peer '$name' не найден в $conf"

    new_priv="$(awg genkey)"
    new_pub="$(printf '%s\n' "$new_priv" | awg pubkey)"

    if awg show "$AWG_IFACE" >/dev/null 2>&1; then
      awg set "$AWG_IFACE" peer "$old_pub" remove 2>/dev/null || true
      awg set "$AWG_IFACE" peer "$new_pub" allowed-ips "$peer_allowed" \
        || die "ядро не приняло обновлённый peer (awg set)"
    fi

    python3 - "$conf" "$old_pub" "$new_pub" <<'PY'
import sys, os
conf_path, old_p, new_p = sys.argv[1:4]
lines = open(conf_path, "r", encoding="utf-8").read().splitlines()
out = []
for ln in lines:
    if ln.strip().startswith("PublicKey") and "=" in ln:
        k, v = ln.split("=", 1)
        if v.strip() == old_p:
            out.append(f"PublicKey = {new_p}")
            continue
    out.append(ln)
tmp = conf_path + ".rekey.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, conf_path)
PY

    python3 - "$cconf" "$new_priv" <<'PY'
import sys, os
cconf, new_priv = sys.argv[1:3]
lines = open(cconf, "r", encoding="utf-8").read().splitlines()
out = []
sec = ""
for ln in lines:
    s = ln.strip()
    if s.startswith("[") and s.endswith("]"):
        sec = s[1:-1].lower()
        out.append(ln)
        continue
    if sec == "interface" and s.startswith("PrivateKey") and "=" in ln:
        out.append(f"PrivateKey = {new_priv}")
    else:
        out.append(ln)
tmp = cconf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, cconf)
PY
  fi

  # 3. Индивидуальный Endpoint клиента (--endpoint)
  local new_ep_formatted=""
  if [ "$has_endpoint" -eq 1 ]; then
    local lport ep_mode="server" ep_host="" resolved_host=""
    lport="$(conf_get ListenPort "$conf" || true)"
    [ -n "$lport" ] || die "не удалось определить ListenPort"
    case "${opt_endpoint:-server}" in
      server|default|"")
        ep_mode="server"
        resolved_host="$(get_public_endpoint_host)"
        ;;
      ipv4|4)
        ep_mode="ipv4"
        resolved_host="$(detect_public_ip || true)"
        [ -n "$resolved_host" ] || die "внешний IPv4 не обнаружен на сервере"
        ;;
      ipv6|6)
        ep_mode="ipv6"
        resolved_host="$(detect_public_ipv6 || true)"
        [ -n "$resolved_host" ] || die "внешний IPv6 не обнаружен на сервере"
        ;;
      *)
        ep_mode="custom"
        ep_host="$(extract_host_from_endpoint "$opt_endpoint")"
        [ -n "$ep_host" ] || die "некорректный endpoint: $opt_endpoint"
        resolved_host="$ep_host"
        ;;
    esac
    [ -n "$resolved_host" ] || die "не удалось определить внешний адрес сервера"
    set_client_endpoint_meta "$name" "$ep_mode" "$ep_host"
    new_ep_formatted="$(format_endpoint "$resolved_host" "$lport")"
  fi

  # 4. Обновление DNS / MTU / AllowedIPs / Keepalive / Endpoint в <name>.conf
  if [ "$has_dns" -eq 1 ] || [ "$has_mtu" -eq 1 ] || [ "$has_allowed" -eq 1 ] || [ "$has_keepalive" -eq 1 ] || [ -n "$new_ep_formatted" ]; then
    python3 - "$cconf" "$has_dns" "$opt_dns" "$has_mtu" "$opt_mtu" "$has_allowed" "$opt_allowed" "$has_keepalive" "$opt_keepalive" "$new_ep_formatted" <<'PY'
import sys, os
cconf = sys.argv[1]
has_dns, dns_v = int(sys.argv[2]), sys.argv[3]
has_mtu, mtu_v = int(sys.argv[4]), sys.argv[5]
has_alw, alw_v = int(sys.argv[6]), sys.argv[7]
has_ka, ka_v = int(sys.argv[8]), sys.argv[9]
new_ep = sys.argv[10]

lines = open(cconf, "r", encoding="utf-8").read().splitlines()
out = []
sec = ""
seen_dns = seen_mtu = seen_alw = seen_ka = seen_ep = False

for ln in lines:
    s = ln.strip()
    if s.startswith("[") and s.endswith("]"):
        # Перед переходом в [Peer] добавим отсутствующие [Interface] поля
        if sec == "interface":
            if has_dns and not seen_dns and dns_v:
                out.append(f"DNS = {dns_v}"); seen_dns = True
            if has_mtu and not seen_mtu and mtu_v:
                out.append(f"MTU = {mtu_v}"); seen_mtu = True
        sec = s[1:-1].lower()
        out.append(ln)
        continue
    if "=" in ln:
        k = ln.split("=", 1)[0].strip()
        if sec == "interface" and k == "DNS" and has_dns:
            if dns_v:
                out.append(f"DNS = {dns_v}")
            seen_dns = True
            continue
        if sec == "interface" and k == "MTU" and has_mtu:
            out.append(f"MTU = {mtu_v}")
            seen_mtu = True
            continue
        if sec == "peer" and k == "AllowedIPs" and has_alw:
            out.append(f"AllowedIPs = {alw_v}")
            seen_alw = True
            continue
        if sec == "peer" and k == "PersistentKeepalive" and has_ka:
            if ka_v != "0":
                out.append(f"PersistentKeepalive = {ka_v}")
            seen_ka = True
            continue
        if sec == "peer" and k == "Endpoint" and new_ep:
            out.append(f"Endpoint = {new_ep}")
            seen_ep = True
            continue
    out.append(ln)

if sec == "peer":
    if has_alw and not seen_alw and alw_v:
        out.append(f"AllowedIPs = {alw_v}")
    if has_ka and not seen_ka and ka_v and ka_v != "0":
        out.append(f"PersistentKeepalive = {ka_v}")
    if new_ep and not seen_ep:
        out.append(f"Endpoint = {new_ep}")

tmp = cconf + ".edit.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, cconf)
PY
  fi

  # 5. Ротация клиентского токена подписки (--rotate-token)
  if [ "$do_rotate_tok" -eq 1 ]; then
    python3 - "$name" "$TOKENS_FILE" <<'PY'
import sys, json, os, secrets, time
name, tf = sys.argv[1:3]
data = {}
try:
    data = json.load(open(tf, "r", encoding="utf-8"))
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
entry = data.get(name)
if isinstance(entry, str):
    entry = {}
elif not isinstance(entry, dict):
    entry = {}
entry["token"] = f"awg_tok_{secrets.token_hex(16)}"
entry.setdefault("created_at", int(time.time()))
entry["rotated_at"] = int(time.time())
data[name] = entry
with open(tf, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
os.chmod(tf, 0o600)
PY
  fi

  chmod 600 "$cconf" 2>/dev/null || true
  qrencode -o "$AWG_DIR/$name.png" -s 6 -m 2 < "$cconf" 2>/dev/null || true
  chmod 600 "$AWG_DIR/$name.png" 2>/dev/null || true
  touch "$cconf"

  release_lock
  step "Клиент '$name' успешно обновлён"
}

do_remove_client() {
  acquire_lock
  local key="${1:-}"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  if [ -z "$key" ]; then
    if [ "$IS_TTY" = 1 ]; then
      do_list_clients
      read -r -p "Имя или PublicKey удаляемого клиента: " key || die "ввод прерван"
    else
      die "укажите имя: awg-manager remove-client <name>"
    fi
  fi

  local pub="" name=""
  if [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    pub="$key"
    name="$(awk -v p="$pub" '/^\[Peer\]/{c=""} /^#/{c=$0; sub(/^#[ \t]*/,"",c)} /^PublicKey/{v=$0; sub(/^PublicKey[ \t]*=[ \t]*/,"",v); if(v==p){print c; exit}}' "$conf")"
  else
    is_valid_client_name "$key" || die "некорректное имя клиента '$key'"
    name="$key"
    pub="$(awk -v want="$name" '/^\[Peer\]/{c=""} /^#/{c=$0; sub(/^#[ \t]*/,"",c); next} /^PublicKey/{if(c==want){v=$0; sub(/^PublicKey[ \t]*=[ \t]*/,"",v); print v; exit}}' "$conf")"
    [ -n "$pub" ] || die "клиент '$name' не найден"
  fi

  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    awg set "$AWG_IFACE" peer "$pub" remove 2>/dev/null || true
  fi

  if grep -qF "$pub" "$conf"; then
    local tmp
    tmp="$(umask 077 && mktemp "$AWG_DIR/.awg0.XXXXXX")"
    awk -v p="$pub" '
      function flush(   i) { if (n > 0 && !drop) for (i = 1; i <= n; i++) print buf[i]; n = 0; drop = 0 }
      /^\[Peer\]/ { flush(); inpeer = 1 }
      /^\[Interface\]/ { flush(); inpeer = 0 }
      {
        if (inpeer) {
          buf[++n] = $0
          if ($0 ~ /^PublicKey[[:space:]]*=/) {
            v = $0; sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", v)
            if (v == p) drop = 1
          }
        } else print
      }
      END { flush() }
    ' "$conf" > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$conf"
  fi

  if [ -n "$name" ] && is_valid_client_name "$name"; then
    remove_client_token "$name"
    rm -f "$AWG_DIR/$name.conf" "$AWG_DIR/$name.png" \
      "$AWG_DIR/${name}-lan-bypass.conf" "$AWG_DIR/${name}-lan-bypass.png"
    step "Клиент '$name' удалён"
  else
    step "Peer $pub удалён"
  fi
  release_lock
}

do_list_clients() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  printf '\n%b=== Список клиентов AmneziaWG ===%b\n' "$C_BOLD" "$C_RESET"
  printf '%-4s %-16s %-34s %-10s %-14s %s\n' "№" "ИМЯ" "IP АДРЕС (IPv4 + IPv6)" "СТАТУС" "HANDSHAKE" "ТРАФИК (↓TX / ↑RX)"
  printf '%s\n' "------------------------------------------------------------------------------------------------"

  local dump=""
  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    dump="$(awg show "$AWG_IFACE" dump 2>/dev/null || true)"
  fi

  local now
  now=$(date +%s)

  AWG_DUMP="$dump" AWG_CONF="$conf" AWG_NOW="$now" AWG_PLAIN="${AWGM_PLAIN:-0}" python3 - <<'PY'
import os

dump_lines = os.environ.get("AWG_DUMP", "").strip().split("\n")
now = int(os.environ.get("AWG_NOW", "0"))
conf = os.environ.get("AWG_CONF", "")
plain = os.environ.get("AWG_PLAIN", "0") == "1"

stats = {}
for line in dump_lines:
    parts = line.split("\t")
    if len(parts) >= 8:
        stats[parts[0]] = {
            "handshake": int(parts[4]) if parts[4].isdigit() else 0,
            "rx": int(parts[5]) if parts[5].isdigit() else 0,
            "tx": int(parts[6]) if parts[6].isdigit() else 0,
        }

def fmt_bytes(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def fmt_time(ts):
    if ts == 0:
        return "никогда"
    d = max(0, now - ts)
    if d < 60:
        return f"{d}с назад"
    if d < 3600:
        return f"{d // 60}м назад"
    if d < 86400:
        return f"{d // 3600}ч назад"
    return f"{d // 86400}д назад"

clients = []
curr = None
with open(conf, "r", encoding="utf-8") as f:
    for line in f:
        l = line.strip()
        if l == "[Peer]":
            if curr and curr.get("pub"):
                clients.append(curr)
            curr = {"name": "", "pub": "", "ip": ""}
        elif l.startswith("[") and l.endswith("]"):
            if curr and curr.get("pub"):
                clients.append(curr)
            curr = None
        elif l.startswith("#") and curr is not None and not curr.get("name"):
            curr["name"] = l.lstrip("#").strip()
        elif "=" in l and curr is not None:
            k, v = l.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "PublicKey":
                curr["pub"] = v
            elif k == "AllowedIPs":
                curr["ip"] = v
    if curr and curr.get("pub"):
        clients.append(curr)

for i, c in enumerate(clients, 1):
    pub = c.get("pub", "")
    st = stats.get(pub, {"handshake": 0, "rx": 0, "tx": 0})
    hs = st["handshake"]
    online = (now - hs < 180) and (hs > 0)
    if plain:
        status = "Online" if online else "Offline"
        st_fmt = f"{status:<10}"
    else:
        status = "\033[0;32mOnline\033[0m" if online else "\033[0;37mOffline\033[0m"
        st_fmt = f"{status:<19}"
    name = c.get("name") or "client"
    raw_ip = c.get("ip", "")
    ip_parts = [x.strip().split("/")[0] for x in raw_ip.split(",") if x.strip()]
    ip_display = " + ".join(ip_parts) if ip_parts else "-"
    traf = f"↓{fmt_bytes(st['tx'])} / ↑{fmt_bytes(st['rx'])}"
    print(f"{i:<4} {name:<16} {ip_display:<34} {st_fmt} {fmt_time(hs):<14} {traf}")
PY
  printf '\n'
}

#--- Telegram-бот -------------------------------------------------------------
do_bot_setup() {
  step "Настройка Telegram-бота для управления клиентами"
  local token="" admin_id="" group_id="" topic_id=""

  if [ -r "$BOT_ENV" ]; then
    # shellcheck disable=SC1090
    . "$BOT_ENV"
    token="${BOT_TOKEN:-}"
    admin_id="${ADMIN_ID:-}"
    group_id="${GROUP_ID:-}"
    topic_id="${TOPIC_ID:-}"
  fi

  if [ "$IS_TTY" = 1 ]; then
    printf '\n1. Создайте бота в Telegram через @BotFather и скопируйте токен.\n'
    read -r -p "Токен бота [текущий: ${token:+задан}]: " new_token || return 1
    if [ -n "$new_token" ]; then token="$new_token"; fi

    printf '\n2. Узнайте свой числовой Telegram ID через @userinfobot (несколько — через запятую).\n'
    read -r -p "Ваш Telegram ID [текущий: ${admin_id:-нет}]: " new_id || return 1
    if [ -n "$new_id" ]; then admin_id="$new_id"; fi

    printf '\n3. (Опционально) ID группы (например -1001234567890, Enter — только ЛС или текущее значение):\n'
    read -r -p "GROUP_ID [текущий: ${group_id:-нет}]: " new_gid || true
    if [ -n "$new_gid" ]; then group_id="$new_gid"; fi

    printf '\n4. (Опционально) ID топика форума (число, Enter — без привязки к топику):\n'
    read -r -p "TOPIC_ID [текущий: ${topic_id:-нет}]: " new_tid || true
    if [ -n "$new_tid" ]; then topic_id="$new_tid"; fi
  fi

  admin_id="$(printf '%s' "$admin_id" | tr -d '[:space:]')"
  group_id="$(printf '%s' "$group_id" | tr -d '[:space:]')"
  topic_id="$(printf '%s' "$topic_id" | tr -d '[:space:]')"

  [[ "$token" =~ ^[0-9]{6,}:[A-Za-z0-9_-]{20,}$ ]] || die "некорректный формат токена бота"
  [[ "$admin_id" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "ADMIN_ID должен содержать только числовые ID через запятую"
  if [ -n "$group_id" ]; then
    [[ "$group_id" =~ ^-?[0-9]+$ ]] || die "GROUP_ID должен быть целым числом (например -1001234567890)"
  fi
  if [ -n "$topic_id" ]; then
    [[ "$topic_id" =~ ^[0-9]+$ ]] || die "TOPIC_ID должен быть положительным целым числом"
  fi

  install -d -m 700 "$AWG_DIR"
  ( umask 077
    cat > "$BOT_ENV" <<EOF
BOT_TOKEN="${token}"
ADMIN_ID="${admin_id}"
GROUP_ID="${group_id}"
TOPIC_ID="${topic_id}"
EOF
    chmod 600 "$BOT_ENV"
  )

  fetch_bot_script || die "файл bot.py не найден и не удалось скачать/проверить"

  cat > /etc/systemd/system/awg-bot.service <<EOF
[Unit]
Description=AmneziaWG Telegram Management Bot
After=network-online.target awg-quick@${AWG_IFACE}.service
Wants=network-online.target awg-quick@${AWG_IFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${BOT_ENV}
ExecStart=/usr/bin/python3 ${BOT_DIR}/bot.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now awg-bot.service
  systemctl restart awg-bot.service
  sleep 1

  if systemctl is-active --quiet awg-bot; then
    step "Telegram-бот успешно запущен! Отправьте /start вашему боту."
  else
    journalctl -u awg-bot -n 20 --no-pager
    warn "Бот не запустился — проверьте логи выше"
  fi
}

do_bot_status() {
  printf '\n%b=== Статус Telegram-бота ===%b\n' "$C_BOLD" "$C_RESET"
  systemctl status awg-bot --no-pager || true
}

do_bot_restart() {
  systemctl restart awg-bot && step "Telegram-бот перезапущен"
}

#--- статус сервера -----------------------------------------------------------
do_status() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  printf '\n%b============================================================%b\n' "$C_CYAN" "$C_RESET"
  printf '  %bAmneziaWG 3.1 — Состояние сервера%b\n' "$C_BOLD" "$C_RESET"
  printf '%b============================================================%b\n' "$C_CYAN" "$C_RESET"
  local active
  active="$(systemctl is-active "awg-quick@${AWG_IFACE}" 2>/dev/null || true)"
  if [ "$active" = "active" ]; then
    printf '  Сервис awg-quick:  %b🟢 Активен (awg0)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Сервис awg-quick:  %b🔴 Остановлен%b\n' "$C_RED" "$C_RESET"
  fi
  local srv_port
  srv_port="$(conf_get ListenPort "$conf")"
  printf '  ListenPort:        %s/udp\n' "$srv_port"
  printf '  Маскировка:        %b%s%b\n' "$C_CYAN" "$(preset_title "$(get_current_preset)" "$srv_port")" "$C_RESET"
  local srv_addr
  srv_addr="$(conf_get Address "$conf")"
  if printf '%s' "$srv_addr" | grep -q ':'; then
    local ip6_pfx
    ip6_pfx="$(get_ipv6_prefix)"
    printf '  Подсеть туннеля:   %s (IPv4) + %s/64 (Dual-Stack IPv6)\n' "$(get_subnet_prefix)0/24" "$ip6_pfx"
  else
    printf '  Подсеть туннеля:   %s\n' "$(get_subnet_prefix)0/24"
  fi
  printf '  Клиентов в базе:   %s\n' "$(grep -c '^\[Peer\]' "$conf" || true)"

  local cur_ep="" cf_ep
  if [ -f "$AWG_DIR/client1.conf" ]; then
    cur_ep="$(conf_get Endpoint "$AWG_DIR/client1.conf" || true)"
  fi
  if [ -z "$cur_ep" ]; then
    for cf_ep in "$AWG_DIR"/*.conf; do
      [ -f "$cf_ep" ] || continue
      [ "$cf_ep" != "$AWG_DIR/$AWG_IFACE.conf" ] || continue
      cur_ep="$(conf_get Endpoint "$cf_ep" || true)"
      [ -n "$cur_ep" ] && break
    done
  fi
  local pub4 pub6
  pub4="$(detect_public_ip || true)"
  pub6="$(detect_public_ipv6 || true)"
  printf '  Внешний IPv4:      %s\n' "${pub4:-нет}"
  printf '  Внешний IPv6:      %s\n' "${pub6:-нет}"
  printf '  Внешний Endpoint:  %b%s%b\n' "$C_BOLD" "${cur_ep:-не задан}" "$C_RESET"

  local bot_act
  bot_act="$(systemctl is-active awg-bot 2>/dev/null || true)"
  if [ "$bot_act" = "active" ]; then
    printf '  Telegram-бот:      %b🟢 Работает (awg-bot)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Telegram-бот:      %b⚪ Не запущен%b\n' "$C_YELLOW" "$C_RESET"
  fi

  local api_act
  api_act="$(systemctl is-active awg-api 2>/dev/null || true)"
  if [ "$api_act" = "active" ]; then
    printf '  API подписок:      %b🟢 Работает (порт %s/tcp)%b\n' "$C_GREEN" "$AWG_API_PORT" "$C_RESET"
  else
    printf '  API подписок:      %b⚪ Не запущен%b\n' "$C_YELLOW" "$C_RESET"
  fi

  local sched_act
  sched_act="$(systemctl is-active awg-rotate.timer 2>/dev/null || true)"
  if [ "$sched_act" = "active" ]; then
    printf '  Авто-шедулер:      %b🟢 Включен (ночная ротация)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Авто-шедулер:      %b⚪ Отключен%b\n' "$C_YELLOW" "$C_RESET"
  fi
  printf '%b------------------------------------------------------------%b\n' "$C_CYAN" "$C_RESET"

  do_list_clients
}

#--- самодиагностика ----------------------------------------------------------
DIAG_FAILS=0
DIAG_WARNS=0
d_ok()   { printf '  %b[OK]%b   %s\n' "$C_GREEN" "$C_RESET" "$*"; }
d_fail() { printf '  %b[FAIL]%b %s\n' "$C_RED" "$C_RESET" "$*"; DIAG_FAILS=$((DIAG_FAILS + 1)); }
d_warn() { printf '  %b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*"; DIAG_WARNS=$((DIAG_WARNS + 1)); }
d_info() { printf '  %b[..]%b   %s\n' "$C_BLUE" "$C_RESET" "$*"; }

diag_live_capture() { # 15-секундный перехват входящих UDP без -w /tmp (обход AppArmor Ubuntu 24.04)
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || { warn "туннель не установлен"; return 1; }
  if ! command -v tcpdump >/dev/null 2>&1; then
    warn "tcpdump не установлен: sudo apt-get install -y tcpdump"; return 1
  fi
  local port wan cnt
  port="$(conf_get ListenPort "$conf")"
  wan="$(detect_wan_iface)"
  step "Перехват входящих UDP на ${wan:-any}:${port} — 15 секунд"
  printf 'Включите VPN на клиенте СЕЙЧАС. Слушаю эфир...\n'
  cnt="$(timeout 15 tcpdump -ni "${wan:-any}" -l -nn -c 100 "udp port ${port}" 2>/dev/null | wc -l | tr -d ' ' || true)"
  if [ "${cnt:-0}" -gt 0 ]; then
    d_ok "За 15с зафиксировано ${cnt} пакетов на ${port}/udp — входящий трафик ДОХОДИТ до сервера"
    printf 'Если handshake при этом не появляется — дело в ключах, профиле 3.1 или клиентском конфиге.\n'
  else
    d_fail "0 пакетов на ${port}/udp за 15с — трафик блокируется ВЫШЕ сервера (облачный firewall или ТСПУ/провайдер)"
    printf 'Откройте %s/udp в облачном firewall; при блоке ТСПУ проверьте порт 443/udp и актуальность AmneziaVPN >= 5.0.1.5.\n' "$port"
  fi
}

do_diagnose() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  DIAG_FAILS=0; DIAG_WARNS=0
  local block_suspect=0

  printf '\n%b============================================================%b\n' "$C_CYAN" "$C_RESET"
  printf '  %bAmneziaWG 3.1 — Самодиагностика сервера%b\n' "$C_BOLD" "$C_RESET"
  printf '%b============================================================%b\n' "$C_CYAN" "$C_RESET"

  if [ ! -f "$conf" ]; then
    d_fail "Конфиг $conf не найден — AmneziaWG не установлен."
    printf '\nЗапустите установку: %bsudo awg-manager install%b\n' "$C_BOLD" "$C_RESET"
    return 0
  fi

  local port subnet wan
  port="$(conf_get ListenPort "$conf")"
  subnet="$(get_subnet_prefix)0/24"
  wan="$(detect_wan_iface)"
  d_info "Интерфейс: ${AWG_IFACE}, порт: ${port:-?}/udp, подсеть: ${subnet}, WAN: ${wan:-?}"

  step "1/8 Модуль ядра и профиль обфускации 3.1"
  if [ -d /sys/module/amneziawg ] || lsmod 2>/dev/null | grep -E '^amneziawg ' >/dev/null; then
    d_ok "Модуль amneziawg загружен"
  else
    d_fail "Модуль amneziawg не загружен. Проверьте: dkms status; sudo modprobe amneziawg"
  fi
  local ver; ver="$(awg --version 2>/dev/null | head -n1 || true)"
  d_info "awg-tools: ${ver:-версия не определена}"
  if grep -q '^HeaderProtectionKey' "$conf" && grep -q '^I1' "$conf" && grep -q '^ContentPaddingAddition' "$conf"; then
    local s_ok=1 s_val k
    for k in S1 S2 S3 S4; do
      s_val="$(conf_get "$k" "$conf")"
      if [ -z "$s_val" ] || [ "$s_val" -lt 12 ] 2>/dev/null; then s_ok=0; fi
    done
    if [ "$s_ok" -eq 1 ]; then
      d_ok "Профиль 3.1 валиден (HPK + CPS I1 + CPA + S1-S4>=12)"
    else
      d_fail "Один из S1-S4 < 12 — несовместимо с HeaderProtectionKey"
    fi
  else
    d_warn "Нет полного профиля 3.1 (HPK/I1/CPA) — слабее защита от DPI"
  fi
  if grep -q '^DisableCookies[[:space:]]*=[[:space:]]*on' "$conf"; then
    d_ok "DisableCookies = on (защита от active probing ТСПУ)"
  else
    d_info "DisableCookies не включён (зависит от версии модуля)"
  fi

  step "2/8 Сервис и интерфейс"
  if systemctl is-active --quiet "awg-quick@${AWG_IFACE}" 2>/dev/null; then
    d_ok "Сервис awg-quick@${AWG_IFACE} активен"
  else
    d_fail "Сервис не активен. sudo systemctl restart awg-quick@${AWG_IFACE}; journalctl -u awg-quick@${AWG_IFACE} -n 30 --no-pager"
  fi
  if ip link show "$AWG_IFACE" >/dev/null 2>&1; then
    local addr; addr="$(ip -4 -o addr show "$AWG_IFACE" 2>/dev/null | awk '{print $4}' | head -n1)"
    if [ -n "$addr" ]; then d_ok "Интерфейс ${AWG_IFACE} поднят, адрес ${addr}"; else d_fail "Интерфейс ${AWG_IFACE} без IPv4-адреса"; fi
  else
    d_fail "Интерфейс ${AWG_IFACE} отсутствует"
  fi

  step "3/8 UDP-порт"
  if [ -n "$port" ] && [ -n "$(ss -Hlnu "sport = :${port}" 2>/dev/null)" ]; then
    d_ok "Порт ${port}/udp слушается"
  else
    d_fail "Никто не слушает ${port:-?}/udp — сокет не поднят или порт занят другим процессом"
  fi

  step "4/8 Форвардинг, rp_filter и NAT"
  local fwd rpf fwd6
  fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)"
  if [ "$fwd" = "1" ]; then d_ok "net.ipv4.ip_forward = 1"; else d_fail "ip_forward=${fwd:-?}, нужно 1: sudo sysctl -w net.ipv4.ip_forward=1"; fi
  fwd6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || true)"
  if [ "$fwd6" = "1" ]; then d_ok "net.ipv6.conf.all.forwarding = 1 (Dual-Stack)"; else d_warn "net.ipv6.conf.all.forwarding = ${fwd6:-0}"; fi
  rpf="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || true)"
  if [ "$rpf" = "1" ]; then
    d_warn "net.ipv4.conf.all.rp_filter = 1 (строгий режим может резать асимметричный трафик; рекомендуется 2)"
  else
    d_ok "net.ipv4.conf.all.rp_filter = ${rpf:-?}"
  fi
  if [ -n "$wan" ]; then
    if iptables -w -t nat -C POSTROUTING -s "$subnet" -o "$wan" -j MASQUERADE 2>/dev/null; then
      d_ok "NAT MASQUERADE ${subnet} -> ${wan}"
    else
      d_fail "Нет MASQUERADE ${subnet} -> ${wan}. Перезапустите туннель"
    fi
    local wan6_check
    wan6_check="$(detect_wan6_iface || true)"
    wan6_check="${wan6_check:-$wan}"
    local ip6_subnet="${AWG_IPV6_SUBNET:-fd42:42:42::/64}"
    if ip6tables -w -t nat -C POSTROUTING -s "$ip6_subnet" -o "$wan6_check" -j MASQUERADE 2>/dev/null; then
      d_ok "IPv6 NAT MASQUERADE ${ip6_subnet} -> ${wan6_check}"
    fi
    if iptables -w -C FORWARD -i "$AWG_IFACE" -o "$wan" -j ACCEPT 2>/dev/null; then
      d_ok "FORWARD ${AWG_IFACE} -> ${wan} разрешён"
    else
      d_warn "Нет FORWARD ${AWG_IFACE} -> ${wan} — трафик клиентов может не проходить"
    fi
  else
    d_warn "WAN-интерфейс не определён (нет default route?)"
  fi

  step "5/8 Межсетевой экран"
  local ufw_active=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw_active=1
    if ufw status 2>/dev/null | grep -Eq "^${port}/udp[[:space:]]+ALLOW"; then
      d_ok "ufw: ${port}/udp разрешён"
    else
      d_fail "ufw активен, ${port}/udp закрыт: sudo ufw allow ${port}/udp"
    fi
  else
    d_info "ufw не активен (рекомендуется настроить firewall для SSH + ${port}/udp)"
  fi
  local inpol
  inpol="$(iptables -w -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3}')"
  if [ "$inpol" = "DROP" ] || [ "$inpol" = "REJECT" ]; then
    if [ "$ufw_active" -eq 1 ]; then
      d_info "iptables INPUT policy: ${inpol} (управляется ufw)"
    elif iptables -w -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
      d_ok "INPUT policy ${inpol}, ${port}/udp явно разрешён"
    else
      d_warn "INPUT policy ${inpol}, явного ACCEPT для ${port}/udp нет — возможен блок входящих"
    fi
  else
    d_info "iptables INPUT policy: ${inpol:-ACCEPT}"
  fi
  d_info "Облачный firewall (Hetzner/Oracle/AWS/GCP) изнутри не виден — проверьте ${port}/udp в панели провайдера"

  step "6/8 Внешняя связность"
  local pub; pub="$(detect_public_ip || true)"
  if [ -n "$pub" ]; then
    d_ok "Внешний IP: ${pub} (DNS и HTTPS с сервера работают)"
  else
    d_warn "Внешний IP не определён — проверьте egress/DNS сервера"
  fi

  step "7/8 Endpoint в конфигах клиентов"
  if [ -n "$pub" ]; then
    local checked=0 mism=0 f ep eip
    for f in "$AWG_DIR"/*.conf; do
      [ -f "$f" ] || continue
      [ "$(basename "$f")" = "${AWG_IFACE}.conf" ] && continue
      ep="$(conf_get Endpoint "$f")"; [ -n "$ep" ] || continue
      checked=$((checked + 1))
      eip="$(extract_host_from_endpoint "$ep")"
      [ "$eip" = "$pub" ] || mism=$((mism + 1))
    done
    if [ "$checked" -eq 0 ]; then d_info "Клиентских конфигов с Endpoint нет"
    elif [ "$mism" -eq 0 ]; then d_ok "Endpoint во всех ${checked} конфигах = ${pub}"
    else d_warn "${mism}/${checked} конфигов указывают на другой IP. Если IP сервера менялся — пересоздайте клиентов"; fi
  else
    d_info "Пропущено (внешний IP не определён)"
  fi

  step "8/8 Подключения клиентов (handshake / трафик)"
  local npeer; npeer="$(grep -c '^\[Peer\]' "$conf" || true)"
  local dump=""
  if awg show "$AWG_IFACE" >/dev/null 2>&1; then dump="$(awg show "$AWG_IFACE" dump 2>/dev/null || true)"; fi
  if [ "${npeer:-0}" -eq 0 ]; then
    d_info "Клиенты не настроены — добавьте клиента (меню пункт 2), затем повторите диагностику"
  elif [ -z "$dump" ]; then
    d_warn "awg show dump пуст — интерфейс не поднят"
  else
    local now stats n ever online totrx
    now="$(date +%s)"
    stats="$(printf '%s\n' "$dump" | awk -v now="$now" 'NF>=8{n++; if($5>0)ever++; if($5>0 && now-$5<180)online++; rx+=$6} END{printf "%d %d %d %d", n+0, ever+0, online+0, rx+0}')"
    read -r n ever online totrx <<< "$stats"
    d_info "Пиров: ${n}, подключались хоть раз: ${ever}, онлайн (<180с): ${online}, RX всего: ${totrx} Б"
    if [ "$n" -eq 0 ]; then
      d_warn "В интерфейсе нет пиров — конфиг не применён, перезапустите туннель"
    elif [ "$ever" -eq 0 ]; then
      d_fail "Ни один клиент ни разу не подключился (handshake=0, RX=0) — входящие пакеты не доходят"
      block_suspect=1
    elif [ "$online" -eq 0 ]; then
      d_warn "Подключались ранее (${ever}), но сейчас активных нет — клиент offline или блокировка появилась недавно"
    else
      d_ok "${online} клиент(ов) онлайн — туннель работает"
    fi
  fi

  printf '\n%b============================================================%b\n' "$C_CYAN" "$C_RESET"
  printf '  %bВЕРДИКТ%b\n' "$C_BOLD" "$C_RESET"
  printf '%b============================================================%b\n' "$C_CYAN" "$C_RESET"
  if [ "$block_suspect" -eq 1 ] && [ "$DIAG_FAILS" -eq 1 ]; then
    printf '%bСервер исправен и слушает %s/udp, но пакеты от клиентов НЕ доходят.%b\n' "$C_YELLOW" "$port" "$C_RESET"
    printf 'Это блокировка ВНЕ сервера. По частоте причин:\n'
    printf '  1. Облачный firewall/security group: откройте %s/udp в панели провайдера.\n' "$port"
    printf '  2. Провайдер / ТСПУ режет UDP или подсеть хостера.\n'
    printf '     Порт 443/udp + QUIC I1 + HPK уже активны; при блоке подсети хостера нужна смена IP/VPS.\n'
    printf '  3. Клиент использует неверный Endpoint (IP:порт) — см. пункт 7 выше.\n'
    printf 'Точный тест: %bsudo awg-manager diagnose-live%b\n' "$C_BOLD" "$C_RESET"
    if [ "$IS_TTY" = "1" ] && [ "${AWGM_PLAIN:-0}" != "1" ] && command -v tcpdump >/dev/null 2>&1; then
      if confirm_yes "Запустить 15-секундный перехват входящих пакетов сейчас?"; then
        diag_live_capture
      fi
    fi
  elif [ "$DIAG_FAILS" -eq 0 ]; then
    printf '%bКритических ошибок нет (WARN: %s).%b\n' "$C_GREEN" "$DIAG_WARNS" "$C_RESET"
    printf 'Если конкретный клиент не подключается — проверьте его сеть, версию Amnezia >= 5.0.1.5 или Endpoint.\n'
  else
    printf '%bНайдено неисправностей: %s (WARN: %s).%b\n' "$C_RED" "$DIAG_FAILS" "$DIAG_WARNS" "$C_RESET"
    printf 'Исправьте пункты [FAIL] сверху вниз и повторите: sudo awg-manager diagnose\n'
  fi
  printf '\n'
  return 0
}

#--- ротация, токены и шедулер -----------------------------------------------
do_token() {
  local name="${1:-}"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  if [ -z "$name" ]; then
    if [ "$IS_TTY" = 1 ]; then
      read -r -p "Имя клиента для получения токена: " name || die "ввод прерван"
    else
      die "укажите имя: awg-manager token <client_name>"
    fi
  fi
  is_valid_client_name "$name" || die "некорректное имя '$name'"

  local token
  token="$(ensure_client_token "$name")"
  [ -n "$token" ] || die "не удалось получить токен для '$name'"

  sanitize_existing_client_endpoints || true

  local pub_ip=""
  pub_ip="$(get_public_endpoint_host)"
  pub_ip="${pub_ip:-$(detect_public_ip || true)}"
  local api_url_host="$pub_ip"
  if [[ "$api_url_host" =~ : ]] && [[ ! "$api_url_host" =~ ^\[ ]]; then
    api_url_host="[${api_url_host}]"
  fi

  printf '\n%b=== Данные подписки клиента: %s ===%b\n' "$C_BOLD" "$name" "$C_RESET"
  printf '  Клиент:                  %s\n' "$name"
  printf '  Токен для вебки:         %b%s%b\n' "$C_CYAN" "$token" "$C_RESET"
  printf '  URL сервера API:         http://%s:%s\n' "$api_url_host" "$AWG_API_PORT"
  printf '  Ссылка подписки (.conf): http://%s:%s/sub/%s\n' "$api_url_host" "$AWG_API_PORT" "$token"
  printf '  Ссылка Amnezia (vpn://): http://%s:%s/vpn/%s\n' "$api_url_host" "$AWG_API_PORT" "$token"
  printf '  RouterOS скрипт (.rsc):  http://%s:%s/rsc/%s\n\n' "$api_url_host" "$AWG_API_PORT" "$token"
  printf 'Вставьте токен или ссылку подписки в веб-интерфейсе контейнера AmneziaWG на роутере.\n'
}

do_switch_endpoint() {
  acquire_lock
  local target="${1:-}"
  local force_all=0
  if [ "${2:-}" = "--all" ] || [ "${2:-}" = "--reset-overrides" ]; then
    force_all=1
  fi
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"
  local lport
  lport="$(conf_get ListenPort "$conf" || true)"
  [ -n "$lport" ] || die "не удалось определить ListenPort"

  local pub4 pub6
  pub4="$(detect_public_ip || true)"
  pub6="$(detect_public_ipv6 || true)"

  if [ -z "$target" ]; then
    if [ "$IS_TTY" = 1 ]; then
      printf '\n%b=== Настройка внешнего Endpoint подключения клиентов ===%b\n' "$C_BOLD" "$C_RESET"
      printf '  1) Внешний IPv4: %s\n' "${pub4:-не определен}"
      printf '  2) Внешний IPv6: %s\n' "${pub6:-не определен}"
      printf '  3) Ввести свой домен или IP вручную\n'
      printf '  0) Отмена\n'
      local ech
      read -r -p "Выберите режим (1-3, 0 отмена): " ech || { release_lock; return 0; }
      case "$ech" in
        1) target="ipv4" ;;
        2) target="ipv6" ;;
        3) read -r -p "Введите внешний домен или IP: " target || { release_lock; return 0; } ;;
        *) release_lock; return 0 ;;
      esac
    else
      die "укажите режим: awg-manager endpoint [ipv4|ipv6|<хост>]"
    fi
  fi

  local target_host=""
  case "$target" in
    ipv4|4)
      [ -n "$pub4" ] || die "внешний IPv4 не обнаружен на сервере"
      target_host="$pub4"
      printf 'ipv4\n' > "$ENDPOINT_MODE_FILE"
      ;;
    ipv6|6)
      [ -n "$pub6" ] || die "внешний IPv6 не обнаружен на сервере (провайдер VPS не назначил IPv6)"
      target_host="$pub6"
      printf 'ipv6\n' > "$ENDPOINT_MODE_FILE"
      ;;
    *)
      target_host="$(extract_host_from_endpoint "$target")"
      [ -n "$target_host" ] || die "некорректный адрес: $target"
      printf '%s\n' "$target_host" > "$ENDPOINT_MODE_FILE"
      ;;
  esac

  local formatted_ep
  formatted_ep="$(format_endpoint "$target_host" "$lport")"
  step "Переключение Endpoint сервера на: $formatted_ep"

  local cf cname cmeta cmode count=0 skipped=0
  for cf in "$AWG_DIR"/*.conf; do
    [ -f "$cf" ] || continue
    [ "$cf" != "$AWG_DIR/$AWG_IFACE.conf" ] || continue
    cname="$(basename "$cf" .conf)"
    cmeta="$(get_client_endpoint_meta "$cname")"
    cmode="${cmeta%%|*}"
    if [ "$force_all" -eq 0 ] && [ "$cmode" != "server" ] && [ -n "$cmode" ]; then
      skipped=$((skipped + 1))
      continue
    fi
    if [ "$force_all" -eq 1 ] && [ "$cmode" != "server" ]; then
      set_client_endpoint_meta "$cname" "server" ""
    fi
    sed -i -E "s|^Endpoint[[:space:]]*=.*$|Endpoint = ${formatted_ep}|" "$cf"
    qrencode -o "${cf%.conf}.png" -s 6 -m 2 < "$cf" 2>/dev/null || true
    chmod 600 "${cf%.conf}.png" 2>/dev/null || true
    touch "$cf"
    count=$((count + 1))
  done

  release_lock
  step "Обновлен Endpoint для ${count} клиентов (индивидуальных override сохранено: ${skipped})."
  printf '  Новый внешний Endpoint: %b%s%b\n' "$C_GREEN" "$formatted_ep" "$C_RESET"
  printf '  Роутеры с токенами подписки автоматически подтянут новый адрес при следующем опросе.\n\n'
}

#--- ротация всего туннеля сервера и смена маскировки -----------------------
apply_tunnel_rotation() {
  local p_name="$1"
  local new_port="$2"
  local i1="$3"
  local jc="$4"
  local jmin="$5"
  local jmax="$6"
  local cpa="$7"
  local rotate_keys="$8" # true или false

  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  local old_port
  old_port="$(conf_get ListenPort "$conf")"
  step "Смена порта серверного туннеля: ${old_port}/udp -> ${new_port}/udp"

  local srv_addr mtu wan_iface
  srv_addr="$(conf_get Address "$conf")"
  mtu="$(conf_get MTU "$conf")"
  mtu="${mtu:-$AWG_MTU}"
  wan_iface="$(detect_wan_iface || true)"

  local public_ip
  public_ip="$(get_public_endpoint_host)"
  [ -n "$public_ip" ] || die "не удалось определить публичный IP сервера"

  local clients_raw
  clients_raw="$(awk '
    BEGIN { name=""; ip="" }
    /^\[Peer\]/ { if (name && ip) print name "|" ip; name=""; ip="" }
    /^#/ && !name { name=$0; sub(/^#[ \t]*/, "", name) }
    /^AllowedIPs/ { ip=$0; sub(/^AllowedIPs[ \t]*=[ \t]*/, "", ip) }
    END { if (name && ip) print name "|" ip }
  ' "$conf")"

  [ -n "$clients_raw" ] || die "в $conf не найдено клиентов"

  ( umask 077
    set +x
    local srv_priv srv_pub
    if [ "$rotate_keys" = "true" ]; then
      srv_priv="$(awg genkey)"
      srv_pub="$(printf '%s\n' "$srv_priv" | awg pubkey)"
      step "Сгенерированы новые ключи сервера (полная ротация туннеля)"
    else
      srv_priv="$(conf_get PrivateKey "$conf")"
      [ -n "$srv_priv" ] || srv_priv="$(awg genkey)"
      srv_pub="$(printf '%s\n' "$srv_priv" | awg pubkey)"
    fi

    local s1 s2 s3 s4 s4_free=() h1 h2 h3 h4 hpk dc_line=""
    s1=$(rand_range 15 150)
    s2=$(rand_range 15 150)
    while [ $((s1 + 56)) -eq "$s2" ]; do s2=$(rand_range 15 150); done
    s3=$(rand_range 12 55)
    while [ $((s2 + 28)) -eq "$s3" ] || [ $((s1 + 84)) -eq "$s3" ]; do s3=$(rand_range 12 55); done

    for ((s4_cand = 12; s4_cand <= 27; s4_cand++)); do
      if [ "$s4_cand" -eq 16 ]; then continue; fi
      s4_collides "$s1" "$s2" "$s3" "$s4_cand" || s4_free+=("$s4_cand")
    done
    [ "${#s4_free[@]}" -gt 0 ] || die "ошибка расчёта параметров S4"
    s4="${s4_free[$(rand_range 0 $((${#s4_free[@]} - 1)))]}"
    h1=1; h2=2; h3=3; h4=4
    hpk="$(awg genkey)"
    if grep -q '^DisableCookies[[:space:]]*=[[:space:]]*on' "$conf"; then
      dc_line=$'DisableCookies = on\n'
    fi

    local subnet
    subnet="$(get_subnet_prefix)0/24"
    local wan6_iface
    wan6_iface="$(detect_wan6_iface || true)"
    wan6_iface="${wan6_iface:-$wan_iface}"
    local ip6_subnet="${AWG_IPV6_SUBNET:-fd42:42:42::/64}"
    local ip6_pfx
    ip6_pfx="$(get_ipv6_prefix)"

    if ! printf '%s' "$srv_addr" | grep -q ':'; then
      srv_addr="${srv_addr}, ${ip6_pfx}1/64"
    fi

    local tmp_conf
    tmp_conf="$(mktemp)"
    chmod 600 "$tmp_conf"

    cat > "$tmp_conf" <<EOF
[Interface]
PrivateKey = ${srv_priv}
Address = ${srv_addr}
ListenPort = ${new_port}
MTU = ${mtu}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
S3 = ${s3}
S4 = ${s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
I1 = ${i1}
HeaderProtectionKey = ${hpk}
ContentPaddingAddition = ${cpa}
${dc_line}PostUp = iptables -w -t nat -C POSTROUTING -s ${subnet} -o ${wan_iface} -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -s ${subnet} -o ${wan_iface} -j MASQUERADE; iptables -w -C FORWARD -i %i -o ${wan_iface} -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i %i -o ${wan_iface} -j ACCEPT; iptables -w -C FORWARD -i ${wan_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i ${wan_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; ip6tables -w -t nat -C POSTROUTING -s ${ip6_subnet} -o ${wan6_iface} -j MASQUERADE 2>/dev/null || ip6tables -w -t nat -A POSTROUTING -s ${ip6_subnet} -o ${wan6_iface} -j MASQUERADE 2>/dev/null || true; ip6tables -w -C FORWARD -i %i -o ${wan6_iface} -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i %i -o ${wan6_iface} -j ACCEPT 2>/dev/null || true; ip6tables -w -C FORWARD -i ${wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -w -I FORWARD 1 -i ${wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -w -t nat -D POSTROUTING -s ${subnet} -o ${wan_iface} -j MASQUERADE 2>/dev/null || true; iptables -w -D FORWARD -i %i -o ${wan_iface} -j ACCEPT 2>/dev/null || true; iptables -w -D FORWARD -i ${wan_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; ip6tables -w -t nat -D POSTROUTING -s ${ip6_subnet} -o ${wan6_iface} -j MASQUERADE 2>/dev/null || true; ip6tables -w -D FORWARD -i %i -o ${wan6_iface} -j ACCEPT 2>/dev/null || true; ip6tables -w -D FORWARD -i ${wan6_iface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
EOF

    local c_name c_ip cli_priv cli_pub cli_dns cli_mtu cli_allowed cli_ka cli_ep_host c_count=0
    while IFS='|' read -r c_name c_ip; do
      [ -n "$c_name" ] && [ -n "$c_ip" ] || continue
      is_valid_client_name "$c_name" || continue

      local c_full_addr="$c_ip"
      if ! printf '%s' "$c_ip" | grep -q ':'; then
        local ip_only="${c_ip%%/*}"
        local last_oct="${ip_only##*.}"
        last_oct="${last_oct:-2}"
        c_full_addr="${c_ip}, ${ip6_pfx}${last_oct}/128"
      fi

      cli_priv=""
      cli_dns="$AWG_DNS"
      cli_mtu="$mtu"
      cli_allowed="0.0.0.0/0, ::/0"
      cli_ka="25"
      if [ -f "$AWG_DIR/${c_name}.conf" ]; then
        cli_priv="$(conf_get PrivateKey "$AWG_DIR/${c_name}.conf" 2>/dev/null || true)"
        local ex_dns ex_mtu ex_alw ex_ka
        ex_dns="$(conf_get DNS "$AWG_DIR/${c_name}.conf" 2>/dev/null || true)"
        ex_mtu="$(conf_get MTU "$AWG_DIR/${c_name}.conf" 2>/dev/null || true)"
        ex_alw="$(awk '/^\[Peer\]/{p=1;next} /^\[/{p=0} p && /^AllowedIPs[[:space:]]*=/{sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/,""); print; exit}' "$AWG_DIR/${c_name}.conf" 2>/dev/null || true)"
        ex_ka="$(conf_get PersistentKeepalive "$AWG_DIR/${c_name}.conf" 2>/dev/null || true)"
        [ -n "$ex_dns" ] && cli_dns="$ex_dns"
        [ -n "$ex_mtu" ] && cli_mtu="$ex_mtu"
        [ -n "$ex_alw" ] && cli_allowed="$ex_alw"
        [ -n "$ex_ka" ] && cli_ka="$ex_ka"
      fi
      if [ -z "$cli_priv" ]; then
        cli_priv="$(awg genkey)"
      fi
      cli_pub="$(printf '%s\n' "$cli_priv" | awg pubkey)"
      cli_ep_host="$(resolve_client_endpoint_host "$c_name" "$public_ip")"
      cli_ep_host="${cli_ep_host:-$public_ip}"

      cat >> "$tmp_conf" <<EOF

[Peer]
# ${c_name}
PublicKey = ${cli_pub}
AllowedIPs = ${c_full_addr}
EOF

      cat > "$AWG_DIR/${c_name}.conf" <<EOF
[Interface]
PrivateKey = ${cli_priv}
Address = ${c_full_addr}
DNS = ${cli_dns}
MTU = ${cli_mtu}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
S3 = ${s3}
S4 = ${s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
I1 = ${i1}
HeaderProtectionKey = ${hpk}
ContentPaddingAddition = ${cpa}

[Peer]
PublicKey = ${srv_pub}
Endpoint = $(format_endpoint "$cli_ep_host" "$new_port")
AllowedIPs = ${cli_allowed}
PersistentKeepalive = ${cli_ka}
EOF
      chmod 600 "$AWG_DIR/${c_name}.conf"
      qrencode -o "$AWG_DIR/${c_name}.png" -s 6 -m 2 < "$AWG_DIR/${c_name}.conf" || true
      chmod 600 "$AWG_DIR/${c_name}.png" 2>/dev/null || true

      ensure_client_token "$c_name" >/dev/null
      c_count=$((c_count + 1))
    done <<< "$clients_raw"

    mv "$tmp_conf" "$conf"
    chmod 600 "$conf"
    printf '%s\n' "$p_name" > "$AWG_DIR/preset.conf"
    chmod 600 "$AWG_DIR/preset.conf" 2>/dev/null || true
    step "Обновлены параметры для ${c_count} клиентов (токены, IP и индивидуальные настройки сохранены)"
  )

  if [ -n "$old_port" ] && [ "$old_port" != "$new_port" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw delete allow "${old_port}/udp" >/dev/null 2>&1 || true
    ufw allow "${new_port}/udp" >/dev/null 2>&1 || true
    step "ufw: закрыт порт ${old_port}/udp, открыт ${new_port}/udp"
  fi

  systemctl restart "awg-quick@${AWG_IFACE}" || die "не удалось перезапустить туннель"
  step "Туннель awg0 успешно перезапущен на порту ${new_port}/udp"

  if [ "${AWG_SKIP_API_RESTART:-0}" != "1" ] && systemctl is-active --quiet awg-api 2>/dev/null; then
    systemctl restart awg-api 2>/dev/null || true
  fi

  notify_rotation_tg "$p_name" "$new_port" "$old_port" || true

  printf '\n%b============================================================%b\n' "$C_GREEN" "$C_RESET"
  printf '  %bСерверный туннель AmneziaWG успешно обновлен!%b\n' "$C_BOLD" "$C_RESET"
  printf '  Профиль маскировки:  %s\n' "$(preset_title "$p_name" "$new_port")"
  printf '  Слушающий UDP-порт:  %s/udp\n' "$new_port"
  printf '  Все клиенты с токенами подхватят новый конфиг автоматически.\n'
  printf '%b============================================================%b\n\n' "$C_GREEN" "$C_RESET"
}

apply_tunnel_preset() {
  local p_name="$1"
  local custom_p="${2:-}"
  local custom_i1="${3:-}"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  local cur_port target_port="" target_i1="" target_jc="" target_jmin="" target_jmax="" target_cpa=""
  cur_port="$(conf_get ListenPort "$conf" || true)"

  _pick_port_or_alt() {
    local want="$1" lo="${2:-20000}" hi="${3:-59999}"
    if [ "$cur_port" != "$want" ] && [ -n "$(ss -Hlnu "sport = :${want}" 2>/dev/null || true)" ]; then
      warn "Порт ${want}/udp занят другим процессом, выбираю свободный ${lo}-${hi}/udp"
      rand_range "$lo" "$hi"
    else
      printf '%s' "$want"
    fi
  }

  case "$p_name" in
    quic)
      target_port="$(_pick_port_or_alt 443 20000 59999)"
      target_i1="$(cps_i1_quic)"
      target_jc="$(rand_range 3 5)"
      target_jmin="$(rand_range 40 70)"
      target_jmax=$((target_jmin + $(rand_range 50 120)))
      target_cpa='32-128'
      ;;
    quic-alt)
      target_port="$(rand_range 20000 59999)"
      target_i1="$(cps_i1_quic)"
      target_jc="$(rand_range 3 5)"
      target_jmin="$(rand_range 40 70)"
      target_jmax=$((target_jmin + $(rand_range 50 120)))
      target_cpa='32-128'
      ;;
    stun)
      target_port="$(_pick_port_or_alt 3478 20000 50000)"
      target_i1="$(cps_i1_stun)"
      target_jc=3; target_jmin=20; target_jmax=60; target_cpa='20-80'
      ;;
    stun-alt)
      target_port="$(rand_range 20000 50000)"
      target_i1="$(cps_i1_stun)"
      target_jc=3; target_jmin=20; target_jmax=60; target_cpa='20-80'
      ;;
    dtls)
      target_port="$(_pick_port_or_alt 8801 20000 59999)"
      target_i1="$(cps_i1_dtls)"
      target_jc=4; target_jmin=40; target_jmax=110; target_cpa='32-128'
      ;;
    dns)
      if [ "$cur_port" != "53" ] && [ -n "$(ss -Hlnu "sport = :53" 2>/dev/null | grep '0\.0\.0\.0:53' || true)" ]; then
        warn "Порт 53/udp занят (0.0.0.0:53), выбираю альтернативный 20000-59999"
        target_port="$(rand_range 20000 59999)"
      else
        target_port=53
      fi
      target_i1="$(cps_i1_dns)"
      target_jc=2; target_jmin=30; target_jmax=80; target_cpa='32-64'
      ;;
    ntp)
      target_port="$(_pick_port_or_alt 123 20000 59999)"
      target_i1="$(cps_i1_ntp)"
      target_jc=2; target_jmin=24; target_jmax=64; target_cpa='16-48'
      ;;
    sip)
      target_port="$(_pick_port_or_alt 5060 20000 59999)"
      target_i1="$(cps_i1_sip)"
      target_jc=3; target_jmin=30; target_jmax=90; target_cpa='24-96'
      ;;
    steam)
      if [ "$cur_port" != "27015" ] && [ -n "$(ss -Hlnu "sport = :27015" 2>/dev/null || true)" ]; then
        target_port=3074
      else
        target_port=27015
      fi
      target_i1="$(cps_i1_steam)"
      target_jc=4; target_jmin=40; target_jmax=90; target_cpa='16-64'
      ;;
    minecraft)
      target_port="$(_pick_port_or_alt 19132 20000 59999)"
      target_i1="$(cps_i1_minecraft)"
      target_jc=3; target_jmin=30; target_jmax=85; target_cpa='20-80'
      ;;
    discord)
      target_port="$(_pick_port_or_alt 50001 50000 50999)"
      target_i1="$(cps_i1_discord)"
      target_jc=4; target_jmin=30; target_jmax=90; target_cpa='24-96'
      ;;
    dht)
      target_port="$(_pick_port_or_alt 6881 20000 59999)"
      target_i1="$(cps_i1_dht)"
      target_jc=3; target_jmin=35; target_jmax=95; target_cpa='24-88'
      ;;
    custom)
      target_port="${custom_p:-$(rand_range 20000 59999)}"
      target_i1="${custom_i1:-$(cps_i1_quic)}"
      target_jc=4; target_jmin=40; target_jmax=100; target_cpa='32-128'
      ;;
    *)
      die "Неизвестный профиль '$p_name'. Допустимы: quic, quic-alt, stun, stun-alt, dtls, dns, ntp, sip, steam, minecraft, discord, dht, custom"
      ;;
  esac

  apply_tunnel_rotation "$p_name" "$target_port" "$target_i1" "$target_jc" "$target_jmin" "$target_jmax" "$target_cpa" false
}

do_preset() {
  local p_arg="${1:-}"
  local custom_p="${2:-}"
  local custom_i1="${3:-}"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  acquire_lock

  if [ -z "$p_arg" ]; then
    printf '\n%b=== Смена профиля маскировки туннеля (Stealth Presets) ===%b\n' "$C_CYAN$C_BOLD" "$C_RESET"
    local cur_p
    cur_p="$(get_current_preset)"
    printf 'Текущий активный профиль сервера: %b%s%b\n\n' "$C_GREEN$C_BOLD" "$(preset_title "$cur_p" "$(conf_get ListenPort "$conf")")" "$C_RESET"
    printf 'Выберите профиль маскировки трафика:\n'
    printf '   1) HTTP/3 (QUIC)            — 443/udp        (YouTube / HTTPS) [По умолчанию]\n'
    printf '   2) HTTP/3 (QUIC Alt)        — 20000-59999/udp (QUIC на высоком порту)\n'
    printf '   3) WebRTC / STUN            — 3478/udp       (Telegram / WhatsApp звонки)\n'
    printf '   4) WebRTC (Alt Port)        — 20000-50000/udp со STUN Magic Cookie\n'
    printf '   5) DTLS 1.2 (Zoom / VoIP)   — 8801/udp       (RFC 6347 ClientHello)\n'
    printf '   6) DNS (EDNS0)              — 53/udp         (DNS-запросы ya.ru)\n'
    printf '   7) NTP v4 (Время)           — 123/udp        (RFC 5905)\n'
    printf '   8) SIP (VoIP / Телефония)   — 5060/udp       (RFC 3261 OPTIONS)\n'
    printf '   9) Игровой (Steam A2S)      — 27015/udp      (Source Engine Query)\n'
    printf '  10) Игровой (Minecraft)      — 19132/udp      (RakNet Unconnected Ping)\n'
    printf '  11) Discord Voice (UDP)      — 50001/udp      (IP Discovery)\n'
    printf '  12) BitTorrent DHT (BEP-5)   — 6881/udp       (DHT Ping)\n'
    printf '  13) Пользовательский         — ручной ввод порта и I1\n'
    printf '   0) Назад\n\n'
    local choice=""
    read -r -p "Выберите профиль (1-13, 0 для отмены): " choice || { release_lock; return 0; }
    case "$choice" in
      1) p_arg="quic" ;;
      2) p_arg="quic-alt" ;;
      3) p_arg="stun" ;;
      4) p_arg="stun-alt" ;;
      5) p_arg="dtls" ;;
      6) p_arg="dns" ;;
      7) p_arg="ntp" ;;
      8) p_arg="sip" ;;
      9) p_arg="steam" ;;
      10) p_arg="minecraft" ;;
      11) p_arg="discord" ;;
      12) p_arg="dht" ;;
      13) p_arg="custom" ;;
      0|q|quit|exit) release_lock; return 0 ;;
      *) release_lock; die "Неверный выбор '$choice'" ;;
    esac
  fi

  if [ "$p_arg" = "custom" ]; then
    if [ -z "$custom_p" ] && [ "$IS_TTY" = 1 ]; then
      read -r -p "Введите UDP-порт сервера (1-65535): " custom_p || { release_lock; die "ввод прерван"; }
    fi
    if [ -z "$custom_i1" ] && [ "$IS_TTY" = 1 ]; then
      read -r -p "Введите строку I1 (байткод AmneziaWG): " custom_i1 || { release_lock; die "ввод прерван"; }
    fi
  fi

  step "Применение профиля маскировки: $(preset_title "$p_arg")"
  apply_tunnel_preset "$p_arg" "$custom_p" "$custom_i1"
  release_lock
}

do_rotate() {
  acquire_lock
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  local p_arg="${1:-}"
  if [ -z "$p_arg" ]; then
    p_arg="$(get_current_preset)"
  fi

  step "Полная ротация туннеля сервера: смена порта, ключей сервера и параметров обфускации"
  local old_port new_port="" try_p
  old_port="$(conf_get ListenPort "$conf")"

  _pick_rotated_port() {
    local base_port="${1:-}"
    if [ -n "$base_port" ] && [ "$old_port" != "$base_port" ] && [ -z "$(ss -Hlnu "sport = :${base_port}" 2>/dev/null || true)" ]; then
      printf '%s' "$base_port"
      return
    fi
    for _ in $(seq 1 40); do
      try_p="$(rand_range 20000 59999)"
      if [ "$try_p" != "$old_port" ] && [ -z "$(ss -Hlnu "sport = :${try_p}" 2>/dev/null || true)" ]; then
        printf '%s' "$try_p"
        return
      fi
    done
    rand_range 20000 59999
  }

  local target_i1 target_jc target_jmin target_jmax target_cpa
  case "$p_arg" in
    quic)
      new_port="$(_pick_rotated_port 443)"
      target_i1="$(cps_i1_quic)"
      target_jc="$(rand_range 3 5)"; target_jmin="$(rand_range 40 70)"; target_jmax=$((target_jmin + $(rand_range 50 120))); target_cpa='32-128'
      ;;
    quic-alt)
      new_port="$(_pick_rotated_port "")"
      target_i1="$(cps_i1_quic)"
      target_jc="$(rand_range 3 5)"; target_jmin="$(rand_range 40 70)"; target_jmax=$((target_jmin + $(rand_range 50 120))); target_cpa='32-128'
      ;;
    stun)
      new_port="$(_pick_rotated_port 3478)"
      target_i1="$(cps_i1_stun)"
      target_jc=3; target_jmin=20; target_jmax=60; target_cpa='20-80'
      ;;
    stun-alt)
      new_port="$(_pick_rotated_port "")"
      target_i1="$(cps_i1_stun)"
      target_jc=3; target_jmin=20; target_jmax=60; target_cpa='20-80'
      ;;
    dtls)
      new_port="$(_pick_rotated_port 8801)"
      target_i1="$(cps_i1_dtls)"
      target_jc=4; target_jmin=40; target_jmax=110; target_cpa='32-128'
      ;;
    dns)
      new_port="$(_pick_rotated_port 53)"
      target_i1="$(cps_i1_dns)"
      target_jc=2; target_jmin=30; target_jmax=80; target_cpa='32-64'
      ;;
    ntp)
      new_port="$(_pick_rotated_port 123)"
      target_i1="$(cps_i1_ntp)"
      target_jc=2; target_jmin=24; target_jmax=64; target_cpa='16-48'
      ;;
    sip)
      new_port="$(_pick_rotated_port 5060)"
      target_i1="$(cps_i1_sip)"
      target_jc=3; target_jmin=30; target_jmax=90; target_cpa='24-96'
      ;;
    steam)
      new_port="$(_pick_rotated_port 27015)"
      target_i1="$(cps_i1_steam)"
      target_jc=4; target_jmin=40; target_jmax=90; target_cpa='16-64'
      ;;
    minecraft)
      new_port="$(_pick_rotated_port 19132)"
      target_i1="$(cps_i1_minecraft)"
      target_jc=3; target_jmin=30; target_jmax=85; target_cpa='20-80'
      ;;
    discord)
      new_port="$(_pick_rotated_port 50001)"
      target_i1="$(cps_i1_discord)"
      target_jc=4; target_jmin=30; target_jmax=90; target_cpa='24-96'
      ;;
    dht)
      new_port="$(_pick_rotated_port 6881)"
      target_i1="$(cps_i1_dht)"
      target_jc=3; target_jmin=35; target_jmax=95; target_cpa='24-88'
      ;;
    *)
      p_arg="quic"
      new_port="$(_pick_rotated_port 443)"
      target_i1="$(cps_i1_quic)"
      target_jc="$(rand_range 3 5)"; target_jmin="$(rand_range 40 70)"; target_jmax=$((target_jmin + $(rand_range 50 120))); target_cpa='32-128'
      ;;
  esac

  apply_tunnel_rotation "$p_arg" "$new_port" "$target_i1" "$target_jc" "$target_jmin" "$target_jmax" "$target_cpa" true
  release_lock
}

do_schedule() {
  local mode="${1:-}"
  local timer_file="/etc/systemd/system/awg-rotate.timer"
  local svc_file="/etc/systemd/system/awg-rotate.service"

  if [ -z "$mode" ] && [ "$IS_TTY" = 1 ]; then
    printf '\n%b=== Настройка авто-ротации по расписанию (шедулер) ===%b\n' "$C_BOLD" "$C_RESET"
    local cur="Выключено"
    if systemctl is-active --quiet awg-rotate.timer 2>/dev/null; then
      cur="Активен ($(systemctl cat awg-rotate.timer 2>/dev/null | grep '^OnCalendar' | head -n1 || true))"
    fi
    printf 'Текущий статус: %s\n\n' "$cur"
    printf '1) Раз в 3 дня в 04:00 (рекомендуется против ТСПУ)\n'
    printf '2) Раз в неделю (воскресенье, 04:00)\n'
    printf '3) Каждый день в 04:00\n'
    printf '4) Отключить авто-ротацию\n'
    printf '0) Назад\n'
    local ch
    read -r -p "Выберите вариант [1-4, 0]: " ch || return 0
    case "$ch" in
      1) mode="3days" ;;
      2) mode="weekly" ;;
      3) mode="daily" ;;
      4) mode="off" ;;
      *) return 0 ;;
    esac
  fi

  case "$mode" in
    off|disable|stop)
      systemctl disable --now awg-rotate.timer 2>/dev/null || true
      step "Авто-ротация AmneziaWG отключена"
      ;;
    3days|daily|weekly|"")
      local cal=""
      if [ "$mode" = "daily" ]; then
        cal="*-*-* 04:00:00"
      elif [ "$mode" = "weekly" ]; then
        cal="Sun *-*-* 04:00:00"
      else
        mode="3days"
        cal="*-*-01,04,07,10,13,16,19,22,25,28 04:00:00"
      fi

      cat > "$svc_file" <<EOF
[Unit]
Description=AmneziaWG Scheduled Key and Port Rotation
After=network.target awg-quick@${AWG_IFACE}.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/awg-manager rotate
EOF

      cat > "$timer_file" <<EOF
[Unit]
Description=AmneziaWG Auto-Rotation Timer

[Timer]
OnCalendar=${cal}
Persistent=true

[Install]
WantedBy=timers.target
EOF

      systemctl daemon-reload
      systemctl enable --now awg-rotate.timer >/dev/null 2>&1
      step "Авто-ротация включена: ${mode} (${cal})"
      ;;
    status)
      printf '\n=== Статус таймера авто-ротации ===\n'
      systemctl status awg-rotate.timer --no-pager || true
      ;;
    *)
      die "неизвестный режим '$mode'. Допустимо: 3days, weekly, daily, off, status"
      ;;
  esac
}

#--- бэкап, восстановление, переустановка и удаление ---------------------------
do_backup() {
  acquire_lock
  step "Создание бэкапа AmneziaWG"
  local ts tar
  ts="$(date '+%Y%m%d-%H%M%S')"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  tar="$BACKUP_DIR/awg-backup-$ts.tar.gz"

  local items=()
  [ -d "$AWG_DIR" ] && items+=("etc/amnezia/amneziawg")
  [ -f "$CRED_FILE" ] && items+=("root/awg-credentials.txt")
  [ "${#items[@]}" -gt 0 ] || die "нечего архивировать"

  ( umask 077
    tar -czf "$tar" -C / "${items[@]}"
    chmod 600 "$tar"
    tar -tzf "$tar" >/dev/null
  ) || die "ошибка создания/проверки архива $tar"

  release_lock
  step "Бэкап создан и проверен: $tar"
}

do_restore() {
  acquire_lock
  local file="${1:-}"
  [ -n "$file" ] || die "укажите файл бэкапа"
  [ -f "$file" ] || die "файл $file не найден"

  if tar -tvf "$file" 2>/dev/null | grep -Eq '^[lhcbps]'; then
    die "архив содержит симлинки или спецфайлы — восстановление отменено"
  fi
  if tar -tzf "$file" 2>/dev/null | grep -Eq '(^/|^\.\./|/\.\./|/\.\.$)'; then
    die "архив содержит небезопасные пути — восстановление отменено"
  fi

  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  tar --no-same-owner -xzf "$file" -C /
  chmod 700 "$AWG_DIR" 2>/dev/null || true
  chmod 600 "$AWG_DIR"/*.conf "$AWG_DIR"/*.png "$AWG_DIR/bot.env" 2>/dev/null || true
  systemctl start "awg-quick@${AWG_IFACE}"
  if systemctl is-enabled --quiet awg-bot 2>/dev/null; then
    systemctl restart awg-bot 2>/dev/null || true
  fi
  release_lock
  step "Восстановление завершено!"
}

do_reinstall() {
  do_backup
  acquire_lock
  step "Очистка старых ключей и конфигураций туннеля (bot.env сохранён)..."
  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  local f
  for f in "$AWG_DIR"/*.conf "$AWG_DIR"/*.png; do
    [ -e "$f" ] || continue
    rm -f "$f"
  done
  release_lock
  do_install
  if [ -r "$BOT_ENV" ] && systemctl is-enabled --quiet awg-bot 2>/dev/null; then
    systemctl restart awg-bot 2>/dev/null || true
  fi
}

do_uninstall() {
  acquire_lock
  step "Полное удаление AmneziaWG"
  if [ -d "$AWG_DIR" ]; then
    release_lock
    do_backup || true
    acquire_lock
  fi

  # Очистка legacy WARP/dnsmasq юнитов от прошлых версий, если оставались
  systemctl disable --now awg-ai-warp.service awg-gemini-warp.service wg-quick@warp0 2>/dev/null || true
  ip rule del fwmark 0x51 table 51820 2>/dev/null || true
  iptables -w -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true
  rm -f /etc/systemd/system/awg-ai-warp.service /etc/systemd/system/awg-gemini-warp.service \
    /etc/dnsmasq.d/ai-warp.conf /etc/dnsmasq.d/gemini-warp.conf /etc/wireguard/warp0.conf
  if [ -f /etc/resolv.conf ] && grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf \
    && ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl enable --now systemd-resolved 2>/dev/null || true
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
  fi

  systemctl stop awg-bot 2>/dev/null || true
  systemctl disable awg-bot 2>/dev/null || true
  systemctl stop awg-api 2>/dev/null || true
  systemctl disable awg-api 2>/dev/null || true
  systemctl stop awg-rotate.timer 2>/dev/null || true
  systemctl disable awg-rotate.timer 2>/dev/null || true
  rm -f /etc/systemd/system/awg-bot.service /etc/systemd/system/awg-api.service \
    /etc/systemd/system/awg-rotate.service /etc/systemd/system/awg-rotate.timer

  local port="" wan="" prefix=""
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    port="$(conf_get ListenPort "$AWG_DIR/$AWG_IFACE.conf")"
  fi
  wan="$(detect_wan_iface)"
  prefix="$(get_subnet_prefix)"

  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  systemctl disable "awg-quick@${AWG_IFACE}" 2>/dev/null || true

  if [ -n "$prefix" ] && [ -n "$wan" ]; then
    iptables -w -t nat -D POSTROUTING -s "${prefix}0/24" -o "$wan" -j MASQUERADE 2>/dev/null || true
    iptables -w -D FORWARD -i "$AWG_IFACE" -o "$wan" -j ACCEPT 2>/dev/null || true
    iptables -w -D FORWARD -i "$wan" -o "$AWG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
  if [ -n "$port" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw delete allow "${port}/udp" >/dev/null 2>&1 || true
  fi
  if [ -n "$AWG_API_PORT" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw delete allow "${AWG_API_PORT}/tcp" >/dev/null 2>&1 || true
  fi

  apt-get purge "${APT[@]}" amneziawg amneziawg-dkms amneziawg-tools 2>/dev/null || true
  rmmod amneziawg 2>/dev/null || true
  add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true

  rm -rf "$AWG_DIR" "$BOT_DIR" "$API_DIR" /usr/local/bin/awg-manager "$CRED_FILE" \
    /etc/sysctl.d/99-awg-hardening.conf /etc/sysctl.d/99-awg-forward.conf
  systemctl daemon-reload
  release_lock
  step "Удаление завершено."
}

#--- интерактивное меню (TUI) --------------------------------------------------
read_menu_key() {
  local key=""
  IFS= read -rsn1 key 2>/dev/null || return 1
  if [ "$key" = $'\x1b' ]; then
    local seq=""
    IFS= read -rsn2 -t 0.05 seq 2>/dev/null || true
    case "$seq" in
      "[A"|"OA") echo "UP" ;;
      "[B"|"OB") echo "DOWN" ;;
      "[C"|"OC") echo "RIGHT" ;;
      "[D"|"OD") echo "LEFT" ;;
      "") echo "ESC" ;;
      *) echo "OTHER" ;;
    esac
  elif [ "$key" = "" ]; then
    echo "ENTER"
  elif [ "$key" = "k" ] || [ "$key" = "K" ]; then
    echo "UP"
  elif [ "$key" = "j" ] || [ "$key" = "J" ]; then
    echo "DOWN"
  elif [ "$key" = "q" ] || [ "$key" = "Q" ]; then
    echo "QUIT"
  else
    echo "$key"
  fi
}

show_menu() {
  local is_interactive=0
  if [ -t 0 ] && [ -t 1 ] && [ "${AWGM_PLAIN:-0}" != "1" ]; then
    is_interactive=1
  fi

  local items=(
    "Список клиентов, статус и QR-коды"
    "Добавить нового клиента"
    "Удалить клиента"
    "Токен и ссылка подписки для клиента"
    "Admin-токен API (для управления с роутера)"
    "Сменить профиль маскировки (Stealth Presets)"
    "Сменить внешний Endpoint (IPv4 / IPv6)"
    "Ротация сервера сейчас (смена порта, ключей и обфускации)"
    "Настроить авто-ротацию сервера по расписанию (шедулер)"
    "Настроить Telegram-бота"
    "Детальный статус и статистика"
    "Перезапустить туннель"
    "Самодиагностика — почему не подключается"
    "Перехват входящих пакетов 15с (diagnose-live)"
    "Обновить awg-manager до последней версии"
    "Резервная копия (бэкап) / Восстановление"
    "Переустановить AmneziaWG начисто (с бэкапом)"
    "Полное удаление AmneziaWG"
    "Выход"
  )
  local num_items=${#items[@]}
  local exit_idx=$((num_items - 1))
  local selected=0

  # Восстановление курсора при выходе или сигнале
  trap 'printf "\033[?25h" 2>/dev/null || true' EXIT INT TERM

  while :; do
    local srv_status="🔴"
    if systemctl is-active --quiet "awg-quick@${AWG_IFACE}" 2>/dev/null; then
      srv_status="🟢"
    fi
    local bot_status="⚪ Отключён"
    if systemctl is-active --quiet awg-bot 2>/dev/null; then
      bot_status="🟢 Работает"
    fi
    local api_status="⚪ Отключён"
    if systemctl is-active --quiet awg-api 2>/dev/null; then
      api_status="🟢 Порт ${AWG_API_PORT:-8443}/tcp"
    fi
    local sched_status="⚪ Выключен"
    if systemctl is-active --quiet awg-rotate.timer 2>/dev/null; then
      sched_status="🟢 Включён"
    fi

    local conf="$AWG_DIR/$AWG_IFACE.conf"
    local port="-" subnet="-" count="0" cur_preset="QUIC"
    if [ -f "$conf" ]; then
      port="$(conf_get ListenPort "$conf")"
      subnet="$(get_subnet_prefix)0/24"
      count="$(grep -c '^\[Peer\]' "$conf" || true)"
      cur_preset="$(get_current_preset)"
    fi

    if [ "$is_interactive" -eq 1 ]; then
      # Скрываем курсор при отрисовке стрелочного меню
      printf '\033[?25l'
      clear 2>/dev/null || printf '\033[H\033[J'
    fi

    printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"
    printf '  %bAmneziaWG 3.1 — Панель управления сервером%b\n' "$C_BOLD" "$C_RESET"
    printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"
    printf '  Туннель awg0:  %s (%s/udp, %s, клиентов: %s)\n' "$srv_status" "$port" "$subnet" "$count"
    printf '  Маскировка:    %b%s%b\n' "$C_GREEN" "$(preset_title "$cur_preset" "$port")" "$C_RESET"
    printf '  Telegram-бот:  %b%s%b\n' "$C_CYAN" "$bot_status" "$C_RESET"
    printf '  API подписок:  %b%s%b\n' "$C_CYAN" "$api_status" "$C_RESET"
    printf '  Шедулер:       %b%s%b\n' "$C_CYAN" "$sched_status" "$C_RESET"
    printf '%b------------------------------------------------------------%b\n' "$C_BLUE" "$C_RESET"

    if [ "$is_interactive" -eq 1 ]; then
      printf '  %bУправление:%b %b↑ / ↓%b или %bj / k%b • %bEnter%b Выбрать • %bq%b Выход\n' \
        "$C_YELLOW" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET"
      printf '%b------------------------------------------------------------%b\n' "$C_BLUE" "$C_RESET"

      local i
      for ((i=0; i<num_items; i++)); do
        if [ "$i" -eq 0 ]; then
          printf '  %bУПРАВЛЕНИЕ КЛИЕНТАМИ И ПОДПИСКАМИ:%b\n' "$C_BOLD" "$C_RESET"
        elif [ "$i" -eq 5 ]; then
          printf '  %bСЕРВЕР, МАСКИРОВКА И РОТАЦИЯ:%b\n' "$C_BOLD" "$C_RESET"
        elif [ "$i" -eq 11 ]; then
          printf '  %bДИАГНОСТИКА И ОБСЛУЖИВАНИЕ:%b\n' "$C_BOLD" "$C_RESET"
        elif [ "$i" -eq "$exit_idx" ]; then
          printf '%b------------------------------------------------------------%b\n' "$C_BLUE" "$C_RESET"
        fi

        local num_str=""
        if [ "$i" -eq "$exit_idx" ]; then
          num_str=" 0"
        else
          printf -v num_str "%2d" "$((i+1))"
        fi

        if [ "$i" -eq "$selected" ]; then
          printf '  %b❯ \033[7m [%s] %-48s \033[0m%b\n' "$C_CYAN$C_BOLD" "$num_str" "${items[i]}" "$C_RESET"
        else
          printf '    [%s] %-50s\n' "$num_str" "${items[i]}"
        fi
      done
      printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"

      local key
      key="$(read_menu_key)" || break
      case "$key" in
        UP)
          selected=$(( (selected - 1 + num_items) % num_items ))
          continue
          ;;
        DOWN)
          selected=$(( (selected + 1) % num_items ))
          continue
          ;;
        QUIT|ESC)
          break
          ;;
        0)
          selected="$exit_idx"
          ;;
        [1-9])
          if [ "$key" -le "$exit_idx" ]; then
            selected=$((key - 1))
          fi
          ;;
        ENTER)
          ;;
        *)
          continue
          ;;
      esac
    else
      # Неинтерактивный режим (скрипт или plain pipe)
      local pi
      for ((pi=0; pi<exit_idx; pi++)); do
        printf ' %2d) %s\n' "$((pi+1))" "${items[pi]}"
      done
      printf '  0) %s\n' "${items[exit_idx]}"
      printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"
      local choice=""
      read -r -p "Выберите пункт (1-${exit_idx}, 0 для выхода): " choice || break
      case "$choice" in
        0|q|quit|exit) break ;;
        *)
          if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$exit_idx" ]; then
            selected=$((choice - 1))
          else
            printf 'Неизвестный пункт: %s\n' "$choice"
            continue
          fi
          ;;
      esac
    fi

    # Возвращаем нормальный курсор для вывода запущенного действия
    printf '\033[?25h'
    printf '\n'

    case "$selected" in
      0)
        do_list_clients
        local subch
        read -r -p "Введите номер или имя клиента для вывода QR [или Enter назад]: " subch || true
        if [ -n "$subch" ]; then
          local cname=""
          if [[ "$subch" =~ ^[0-9]+$ ]]; then
            cname="$(awk -v want="$subch" '
              BEGIN { n=0 }
              /^\[Peer\]/ { name="" }
              /^#/ && !name { name=$0; sub(/^#[ \t]*/, "", name) }
              /^PublicKey/ {
                n++
                if (n == want) { print (name ? name : "client" n); exit }
              }
            ' "$conf")"
          elif is_valid_client_name "$subch" && [ -f "$AWG_DIR/$subch.conf" ]; then
            cname="$subch"
          fi

          if [ -n "$cname" ] && is_valid_client_name "$cname" && [ -f "$AWG_DIR/$cname.conf" ]; then
            printf '\nQR-код (%s.conf):\n\n' "$cname"
            qrencode -t ansiutf8 < "$AWG_DIR/$cname.conf" || true
          else
            printf 'Клиент %s не найден.\n' "$subch"
          fi
        fi
        ;;
      1) do_add_client "" ;;
      2) do_remove_client "" ;;
      3) do_token "" ;;
      4) do_admin_token "show" ;;
      5) do_preset "" ;;
      6) do_switch_endpoint "" ;;
      7)
        if confirm_yes "Выполнить полную ротацию серверного туннеля прямо сейчас (смена порта, ключей сервера и параметров обфускации)?"; then
          do_rotate ""
        fi
        ;;
      8) do_schedule "" ;;
      9)
        printf '\n%bНастройка Telegram-бота:%b\n' "$C_BOLD" "$C_RESET"
        printf '  1) Настроить токен и запустить бота\n'
        printf '  2) Статус бота\n'
        printf '  3) Перезапустить бота\n'
        printf '  0) Назад в главное меню\n'
        local bch
        read -r -p "Выберите действие (1-3, 0 назад): " bch || true
        case "$bch" in
          1) do_bot_setup ;;
          2) do_bot_status ;;
          3) do_bot_restart ;;
        esac
        ;;
      10) do_status ;;
      11) systemctl restart "awg-quick@${AWG_IFACE}" && step "Туннель перезапущен" ;;
      12) do_diagnose ;;
      13) diag_live_capture ;;
      14) do_update ;;
      15)
        printf '\n%bРезервная копия и восстановление:%b\n' "$C_BOLD" "$C_RESET"
        printf '  1) Создать бэкап сейчас\n'
        printf '  2) Восстановить из файла архива\n'
        printf '  0) Назад в главное меню\n'
        local bkch
        read -r -p "Выберите действие (1-2, 0 назад): " bkch || true
        if [ "$bkch" = "1" ]; then
          do_backup
        elif [ "$bkch" = "2" ]; then
          read -r -p "Путь к tar.gz архиву: " bkp || true
          do_restore "$bkp"
        fi
        ;;
      16)
        if confirm_yes "Переустановить AmneziaWG начисто (текущие конфиги сохранятся в бэкап, ключи обновятся)?"; then
          do_reinstall
        fi
        ;;
      17)
        if confirm_yes "Полностью удалить AmneziaWG с сервера?"; then
          do_uninstall
        fi
        ;;
      18)
        break
        ;;
    esac

    if [ "$is_interactive" -eq 1 ]; then
      printf '\n%bНажмите Enter для возврата в меню...%b' "$C_CYAN" "$C_RESET"
      read -r _ || true
    fi
  done

  printf '\033[?25h' 2>/dev/null || true
  printf '\nВыход из панели управления AmneziaWG.\n'
}

#--- диспетчер команд ---------------------------------------------------------
ACTION="${1:-}"

if [ -t 0 ] && [ -t 1 ] && [ "${AWGM_PLAIN:-0}" != "1" ]; then IS_TTY=1; fi

if [ -z "$ACTION" ]; then
  if [ "$IS_TTY" = 1 ] && [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    ACTION="menu"
  else
    ACTION="install"
  fi
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите от root: sudo bash install.sh ${ACTION}" >&2
  exit 1
fi

( umask 077 && touch "$LOG_FILE" "$DBG_FILE" )
chmod 600 "$LOG_FILE" "$DBG_FILE" 2>/dev/null || true
case "$ACTION" in
  menu|admin-token|token|clients|list-clients|status|api-status|bot-status|help|-h|--help)
    ;;
  *)
    if [ "${AWGM_PLAIN:-0}" != "1" ]; then
      LOG_FIFO="$(mktemp -u /tmp/awg-log-fifo.XXXXXX)"
      if mkfifo "$LOG_FIFO" 2>/dev/null; then
        tee -a "$LOG_FILE" < "$LOG_FIFO" &
        TEE_PID=$!
        exec > "$LOG_FIFO" 2>&1
        rm -f "$LOG_FIFO"
      fi
    fi
    ;;
esac

case "$ACTION" in
  menu) show_menu ;;
  install) do_install ;;
  reinstall) do_reinstall ;;
  preset|mask) do_preset "${2:-}" "${3:-}" "${4:-}" ;;
  rotate) do_rotate "${2:-}" ;;
  schedule) do_schedule "${2:-}" ;;
  token) do_token "${2:-}" ;;
  admin-token) do_admin_token "${2:-show}" ;;
  endpoint|ip-mode) do_switch_endpoint "${2:-}" "${3:-}" ;;
  api-status) do_api_status ;;
  api-restart) do_api_restart ;;
  add-client) shift; do_add_client "$@" ;;
  edit-client) shift; do_edit_client "$@" ;;
  remove-client) do_remove_client "${2:-}" ;;
  list-clients|clients) do_list_clients ;;
  bot) do_bot_setup ;;
  bot-status) do_bot_status ;;
  bot-restart) do_bot_restart ;;
  status) do_status ;;
  diagnose) do_diagnose ;;
  diagnose-live) diag_live_capture ;;
  update|self-update) do_update ;;
  backup) do_backup ;;
  restore) do_restore "${2:-}" ;;
  uninstall) do_uninstall ;;
  help|-h|--help)
    cat <<EOF
Использование: sudo awg-manager [команда]

Команды:
  menu          Интерактивное меню управления (TUI со стрелками ↑/↓)
  update        Обновить awg-manager и API подписок до последней версии
  install       Установка или идемпотентная проверка сервера
  reinstall     Полная переустановка ключей и туннеля (с бэкапом)
  preset        Сменить профиль маскировки (quic|quic-alt|stun|stun-alt|dtls|dns|ntp|sip|steam|minecraft|discord|dht|custom)
  endpoint      Сменить внешний Endpoint (ipv4|ipv6|<домен_или_IP>) [--all]
  rotate        Полная ротация туннеля сервера (смена порта, ключей и обфускации)
  schedule      Настройка авто-ротации по расписанию (3days|weekly|daily|off|status)
  token         Показать токен и ссылку подписки для клиента
  admin-token   Показать или перевыпустить (rotate) Admin-токен API для контейнера роутера
  api-status    Статус API-сервиса подписок и управления
  api-restart   Перезапуск API-сервиса подписок и управления
  clients       Список клиентов, статус онлайн и трафик
  add-client    Добавить нового клиента [--dns ... --mtu ... --allowed-ips ... --endpoint ...]
  edit-client   Изменить клиента [--rename ... --dns ... --mtu ... --allowed-ips ... --endpoint ... --rekey --rotate-token]
  remove-client Удалить клиента (по имени или pubkey)
  bot           Настройка Telegram-бота для управления клиентами
  bot-status    Статус Telegram-бота
  bot-restart   Перезапуск Telegram-бота
  status        Детальный статус сервисов и интерфейса
  diagnose      Самодиагностика: модуль, порт, NAT, firewall, handshake
  diagnose-live 15-секундный перехват входящих пакетов (точный тест блокировки)
  backup        Создать резервную копию
  restore       Восстановить из архива
  uninstall     Полное удаление с сервера
EOF
    ;;
  *) die "Неизвестная команда '$ACTION'. Справка: sudo awg-manager help" ;;
esac
