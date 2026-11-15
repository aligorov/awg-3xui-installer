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
AWG_DNS="${AWG_DNS:-1.1.1.1, 9.9.9.9}"
AWG_MTU="${AWG_MTU:-1280}"
AWG_PORT="${AWG_PORT:-}"            # пусто -> 443/udp (или случайный 20000-59999 если занят)
AWG_SUBNET="${AWG_SUBNET:-}"        # пусто -> случайный 10.x.y.0/24
AWG_ENDPOINT="${AWG_ENDPOINT:-}"    # пусто -> автоопределение внешнего IPv4
CRED_FILE="/root/awg-credentials.txt"
BACKUP_DIR="/root/awg-backups"
LOG_FILE="/var/log/awg-install.log"
DBG_FILE="/var/log/awg-install.debug.log"
LOCK_FILE="/run/lock/awg-manager.lock"
BOT_DIR="/opt/awg-bot"
BOT_ENV="/etc/amnezia/amneziawg/bot.env"
RAW_BASE_URL="https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main"
TMP_DIR=""
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
  for url in https://api.ipify.org https://icanhazip.com https://ifconfig.me https://checkip.amazonaws.com; do
    ip="$(curl -4 -fsS --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  done
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ipv4 "$ip"; then
    printf '%s\n' "$ip"
    return 0
  fi
  return 1
}

detect_wan_iface() {
  local iface
  iface="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  if [ -z "$iface" ]; then
    iface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  fi
  printf '%s' "$iface"
}

get_subnet_prefix() { # извлекает префикс 'A.B.C.' из awg0.conf
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$conf" ]; then
    local srv_addr
    srv_addr="$(conf_get Address "$conf")"
    printf '%s' "$srv_addr" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.'
  fi
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

#--- обфускация AmneziaWG 3.1 (анти-ТСПУ) --------------------------------------
cps_i1() { # маскирующий пакет I1 в форме QUIC v1 Initial (RFC 9000, с рандомным DCID и длиной)
  local first_b plen varint_hex out
  first_b="$(printf 'c%x' "$(rand_range 0 15)")"
  plen="$(rand_range 200 340)"
  varint_hex="$(printf '%04x' "$((0x4000 + plen))")"
  out="$(printf '<b 0x%s0000000108><r 8><b 0x0000%s><r %s>' "$first_b" "$varint_hex" "$plen")"
  [[ "$out" =~ ^\<b\ 0xc[0-9a-f]0000000108\>\<r\ 8\>\<b\ 0x00004[0-9a-f]{3}\>\<r\ [0-9]{3}\>$ ]] || return 1
  printf '%s\n' "$out"
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
  if lsmod | grep -q '^amneziawg '; then
    rmmod amneziawg || die "модуль amneziawg занят — перезагрузите сервер"
  fi
  modprobe amneziawg || die "модуль amneziawg не загрузился"
}

apply_sysctl_hardening() {
  cat > /etc/sysctl.d/99-awg-hardening.conf <<'EOF'
net.ipv4.ip_forward = 1
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

cleanup() {
  if [ -n "${TMP_DIR:-}" ]; then rm -rf "$TMP_DIR"; fi
  release_lock
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
Address = ${AWG_SRV_IP}/24
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
${dc_line}PostUp = iptables -w -t nat -C POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -C FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -C FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE 2>/dev/null || true; iptables -w -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT 2>/dev/null || true; iptables -w -D FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

[Peer]
# client1
PublicKey = ${cli_pub}
AllowedIPs = ${AWG_CLI_IP}/32
EOF

      cat > "$AWG_DIR/client1.conf" <<EOF
[Interface]
PrivateKey = ${cli_priv}
Address = ${AWG_CLI_IP}/32
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
Endpoint = ${PUBLIC_IP}:${AWG_PORT}
AllowedIPs = 0.0.0.0/0
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

  ( umask 077
    cat > "$CRED_FILE" <<EOF
# AmneziaWG 3.1 — $(date '+%F %T')
AWG_ENDPOINT=${PUBLIC_IP}:${AWG_PORT}/udp
AWG_SUBNET=${AWG_SUBNET}
AWG_CLIENT_CONFIG=${AWG_DIR}/client1.conf
AWG_CLIENT_QR=${AWG_DIR}/client1.png
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
  local name="${1:-}"
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
  for k in MTU Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 HeaderProtectionKey ContentPaddingAddition ListenPort; do
    v="$(conf_get "$k" "$conf")"
    [ -n "$v" ] || die "в $conf нет параметра $k"
    P[$k]="$v"
  done

  local srv_pub endpoint priv pubk
  srv_pub="$(conf_get PrivateKey "$conf" | awg pubkey)" || die "ошибка pubkey сервера"

  local ep_host=""
  if [ -f "$AWG_DIR/client1.conf" ]; then
    ep_host="$(conf_get Endpoint "$AWG_DIR/client1.conf" | sed -E 's/^\[?([^\]]+)\]?:[0-9]+$/\1/')"
  fi
  endpoint="${ep_host:-$(detect_public_ip || true)}"
  [ -n "$endpoint" ] || die "не удалось определить внешний IP сервера"

  ( umask 077
    priv="$(awg genkey)"
    pubk="$(printf '%s\n' "$priv" | awg pubkey)"

    awg set "$AWG_IFACE" peer "$pubk" allowed-ips "$ip/32" \
      || die "ядро не приняло peer (awg set)"

    if ! cat >> "$conf" <<EOF

[Peer]
# ${name}
PublicKey = ${pubk}
AllowedIPs = ${ip}/32
EOF
    then
      awg set "$AWG_IFACE" peer "$pubk" remove 2>/dev/null || true
      die "не удалось дописать peer в $conf"
    fi

    cat > "$AWG_DIR/$name.conf" <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${ip}/32
DNS = ${AWG_DNS}
MTU = ${P[MTU]}
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
I1 = ${P[I1]}
HeaderProtectionKey = ${P[HeaderProtectionKey]}
ContentPaddingAddition = ${P[ContentPaddingAddition]}

[Peer]
PublicKey = ${srv_pub}
Endpoint = ${endpoint}:${P[ListenPort]}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    chmod 600 "$AWG_DIR/$name.conf" "$conf"
    qrencode -o "$AWG_DIR/$name.png" -s 6 -m 2 < "$AWG_DIR/$name.conf" || true
    chmod 600 "$AWG_DIR/$name.png" 2>/dev/null || true
  )

  release_lock
  step "Клиент '$name' ($ip) успешно создан!"
  printf '  Файл конфига (0.0.0.0/0): %s/%s.conf\n' "$AWG_DIR" "$name"
  printf '  QR-код:                   %s/%s.png\n\n' "$AWG_DIR" "$name"
  if [ "$IS_TTY" = 1 ]; then
    qrencode -t ansiutf8 < "$AWG_DIR/$name.conf" || true
  fi
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
  printf '%-4s %-18s %-16s %-10s %-18s %s\n' "№" "ИМЯ" "IP АДРЕС" "СТАТУС" "HANDSHAKE" "ТРАФИК (↓TX / ↑RX)"
  printf '%s\n' "----------------------------------------------------------------------------------"

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
    ip = c.get("ip", "").split("/")[0]
    traf = f"↓{fmt_bytes(st['tx'])} / ↑{fmt_bytes(st['rx'])}"
    print(f"{i:<4} {name:<18} {ip:<16} {st_fmt} {fmt_time(hs):<18} {traf}")
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
  printf '  ListenPort:        %s/udp\n' "$(conf_get ListenPort "$conf")"
  printf '  Подсеть туннеля:   %s\n' "$(get_subnet_prefix)0/24"
  printf '  Клиентов в базе:   %s\n' "$(grep -c '^\[Peer\]' "$conf" || true)"

  local bot_act
  bot_act="$(systemctl is-active awg-bot 2>/dev/null || true)"
  if [ "$bot_act" = "active" ]; then
    printf '  Telegram-бот:      %b🟢 Работает (awg-bot)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Telegram-бот:      %b⚪ Не запущен%b\n' "$C_YELLOW" "$C_RESET"
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
  if lsmod 2>/dev/null | grep -q '^amneziawg '; then
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
  local fwd rpf
  fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)"
  if [ "$fwd" = "1" ]; then d_ok "net.ipv4.ip_forward = 1"; else d_fail "ip_forward=${fwd:-?}, нужно 1: sudo sysctl -w net.ipv4.ip_forward=1"; fi
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
      eip="$(printf '%s' "$ep" | sed -E 's/^\[?([^\]]+)\]?:[0-9]+$/\1/')"
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
  rm -f /etc/systemd/system/awg-bot.service

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

  apt-get purge "${APT[@]}" amneziawg amneziawg-dkms amneziawg-tools 2>/dev/null || true
  rmmod amneziawg 2>/dev/null || true
  add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true

  rm -rf "$AWG_DIR" "$BOT_DIR" /usr/local/bin/awg-manager "$CRED_FILE" \
    /etc/sysctl.d/99-awg-hardening.conf /etc/sysctl.d/99-awg-forward.conf
  systemctl daemon-reload
  release_lock
  step "Удаление завершено."
}

#--- интерактивное меню (TUI) --------------------------------------------------
show_menu() {
  local choice
  while :; do
    local srv_status="🔴"
    if systemctl is-active --quiet "awg-quick@${AWG_IFACE}" 2>/dev/null; then
      srv_status="🟢"
    fi
    local bot_status="⚪ Отключён"
    if systemctl is-active --quiet awg-bot 2>/dev/null; then
      bot_status="🟢 Работает"
    fi

    local conf="$AWG_DIR/$AWG_IFACE.conf"
    local port="-" subnet="-" count="0"
    if [ -f "$conf" ]; then
      port="$(conf_get ListenPort "$conf")"
      subnet="$(get_subnet_prefix)0/24"
      count="$(grep -c '^\[Peer\]' "$conf" || true)"
    fi

    printf '\n%b============================================================%b\n' "$C_BLUE" "$C_RESET"
    printf '  %bAmneziaWG 3.1 — Панель управления сервером%b\n' "$C_BOLD" "$C_RESET"
    printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"
    printf '  Туннель awg0:  %s (%s/udp, %s, клиентов: %s)\n' "$srv_status" "$port" "$subnet" "$count"
    printf '  Telegram-бот:  %b%s%b\n' "$C_CYAN" "$bot_status" "$C_RESET"
    printf '%b------------------------------------------------------------%b\n' "$C_BLUE" "$C_RESET"
    printf '  %bНе подключается? Пункт 10 — самодиагностика (ТСПУ/порт/NAT)%b\n' "$C_YELLOW" "$C_RESET"
    printf '  %bУПРАВЛЕНИЕ КЛИЕНТАМИ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    1) Список клиентов, статус и QR-коды\n'
    printf '    2) Добавить нового клиента\n'
    printf '    3) Удалить клиента\n'
    printf '  %bСЕРВИС И МОНИТОРИНГ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    4) Настроить Telegram-бота (управление через ТГ)\n'
    printf '    5) Детальный статус и статистика\n'
    printf '    6) Перезапустить туннель\n'
    printf '  %bОБСЛУЖИВАНИЕ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    7) Резервная копия (бэкап) / Восстановление\n'
    printf '    8) Переустановить AmneziaWG начисто (с бэкапом)\n'
    printf '    9) Полное удаление AmneziaWG\n'
    printf '   10) Самодиагностика — почему не подключается\n'
    printf '   11) Перехват входящих пакетов 15с (diagnose-live)\n'
    printf '    0) Выход\n'
    printf '%b============================================================%b\n' "$C_BLUE" "$C_RESET"
    read -r -p "Выберите пункт меню: " choice || { printf '\n'; break; }

    case "$choice" in
      1)
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
            read -r -p "Нажмите Enter для возврата..." _ || true
          else
            printf 'Клиент %s не найден.\n' "$subch"
          fi
        fi
        ;;
      2) do_add_client "" ;;
      3) do_remove_client "" ;;
      4)
        printf '\n1) Настроить токен и запустить бота\n2) Статус бота\n3) Перезапустить бота\n'
        local bch
        read -r -p "Выбор: " bch || true
        case "$bch" in
          1) do_bot_setup ;;
          2) do_bot_status ;;
          3) do_bot_restart ;;
        esac
        ;;
      5) do_status ;;
      6) systemctl restart "awg-quick@${AWG_IFACE}" && step "Туннель перезапущен" ;;
      7)
        printf '\n1) Создать бэкап\n2) Восстановить из файла\n'
        local bkch
        read -r -p "Выбор: " bkch || true
        if [ "$bkch" = "1" ]; then do_backup; elif [ "$bkch" = "2" ]; then
          read -r -p "Путь к tar.gz архиву: " bkp || true
          do_restore "$bkp"
        fi
        ;;
      8)
        if confirm_yes "Переустановить AmneziaWG начисто (текущие конфиги сохранятся в бэкап, ключи обновятся)?"; then
          do_reinstall
        fi
        ;;
      9)
        if confirm_yes "Полностью удалить AmneziaWG с сервера?"; then
          do_uninstall
        fi
        ;;
      10) do_diagnose ;;
      11) diag_live_capture ;;
      0|q|quit|exit) break ;;
      *) printf 'Неизвестный пункт: %s\n' "$choice" ;;
    esac
  done
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
if [ "${AWGM_PLAIN:-0}" != "1" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
fi

case "$ACTION" in
  menu) show_menu ;;
  install) do_install ;;
  reinstall) do_reinstall ;;
  add-client) do_add_client "${2:-}" ;;
  remove-client) do_remove_client "${2:-}" ;;
  list-clients|clients) do_list_clients ;;
  bot) do_bot_setup ;;
  bot-status) do_bot_status ;;
  bot-restart) do_bot_restart ;;
  status) do_status ;;
  diagnose) do_diagnose ;;
  diagnose-live) diag_live_capture ;;
  backup) do_backup ;;
  restore) do_restore "${2:-}" ;;
  uninstall) do_uninstall ;;
  help|-h|--help)
    cat <<EOF
Использование: sudo awg-manager [команда]

Команды:
  menu          Интерактивное меню управления (TUI)
  install       Установка или идемпотентная проверка сервера
  reinstall     Полная переустановка ключей и туннеля (с бэкапом)
  clients       Список клиентов, статус онлайн и трафик
  add-client    Добавить нового клиента
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
