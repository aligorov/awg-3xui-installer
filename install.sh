#!/usr/bin/env bash
#===============================================================================
#  awg-manager — установщик и менеджер AmneziaWG 3.1 для Ubuntu 24.04 LTS
#
#  Возможности:
#  - Нативный модуль ядра amneziawg.ko (DKMS из ppa:amnezia/ppa) — гигабитная
#    производительность без оверхеда userspace.
#  - Полный профиль обфускации AmneziaWG 3.1: HeaderProtectionKey,
#    CPS-пакет I1 (маскировка под DNS-ответ), S1-S4, ContentPaddingAddition.
#  - Случайная подсеть для клиентов (10.RAND.RAND.0/24) для исключения коллизий.
#  - Управление клиентами через Telegram-бота (готовые .conf и QR-коды в чат).
#  - Прозрачный обход блокировок Gemini (geosite:google-deepmind) через
#    Cloudflare WARP + dnsmasq nftset (без влияния на остальной трафик).
#  - Интерактивное TUI-меню в терминале для полного управления сервером.
#===============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ОШИБКА: нужен bash. Запуск: sudo bash install.sh" >&2
  exit 1
fi
set -Eeuo pipefail

#--- конфигурация --------------------------------------------------------------
AWG_IFACE="awg0"
AWG_DIR="/etc/amnezia/amneziawg"
AWG_DNS="1.1.1.1"
AWG_MTU="1280"
AWG_PORT="${AWG_PORT:-}"            # пусто -> случайный UDP 20000-59999
AWG_PORT_ENV="${AWG_PORT:-}"
AWG_SUBNET="${AWG_SUBNET:-}"        # пусто -> случайный 10.x.y.0/24
CRED_FILE="/root/awg-credentials.txt"
BACKUP_DIR="/root/awg-backups"
LOG_FILE="/var/log/awg-install.log"
DBG_FILE="/var/log/awg-install.debug.log"
BOT_DIR="/opt/awg-bot"
BOT_ENV="/etc/amnezia/amneziawg/bot.env"
WARP_DIR="/etc/amnezia/warp"
TMP_DIR=""
IS_TTY=0

# Подсети для обхода локальной сети (AllowedIPs без RFC 1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 и 169.254.0.0/16)
ALLOWED_IPS_NO_LAN="1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/3, 96.0.0.0/6, 100.0.0.0/10, 100.128.0.0/9, 101.0.0.0/8, 102.0.0.0/7, 104.0.0.0/5, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/8, 169.0.0.0/9, 169.128.0.0/10, 169.192.0.0/11, 169.224.0.0/12, 169.240.0.0/13, 169.248.0.0/14, 169.252.0.0/15, 169.255.0.0/16, 170.0.0.0/7, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4"

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300)

# Цветовое оформление для терминала
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'

#--- вспомогательные функции ----------------------------------------------------
step() { printf '\n%b==> [%s] %s%b\n' "$C_CYAN" "$(date '+%F %T')" "$*" "$C_RESET"; }
warn() { printf '%bВНИМАНИЕ: %s%b\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die()  { printf '\n%bОШИБКА: %s%b\nЛог: %s\n' "$C_RED" "$*" "$C_RESET" "$LOG_FILE" >&2; exit 1; }

rand_hex() { openssl rand -hex "${1:-8}"; }
rand_u32() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }
rand_range() { # $1=min $2=max -> случайное целое [min,max] из /dev/urandom
  printf '%s' "$(( $(rand_u32) % ($2 - $1 + 1) + $1 ))"
}

conf_get() { # $1=ключ $2=файл -> значение первого совпадения
  sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$2" | head -n1
}

detect_public_ip() { # печатает внешний IPv4
  local ip
  ip="$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  fi
  if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$ip"
}

detect_wan_iface() {
  local iface
  iface="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  if [ -z "$iface" ]; then
    iface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  fi
  printf '%s' "$iface"
}

get_subnet_prefix() { # извлекает префикс '10.x.y.' из awg0.conf
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

#--- обфускация AmneziaWG 3.1 --------------------------------------------------
cps_i1() { # маскирующий пакет I1 в форме DNS-ответа (cdns.icloud.com)
  local label answers hex qtail ttl o1 o2 o3 o4 i out
  label=$(rand_range 20 62)
  answers=$(rand_range 1 2)
  hex=$(printf '85800001%04x00000000%02x' "$answers" "$label")
  qtail='0463646e730669636c6f756403636f6d0000010001'
  case $(rand_range 1 4) in
    1) ttl='0000003c' ;; 2) ttl='0000012c' ;; 3) ttl='00000384' ;; *) ttl='00000e10' ;;
  esac
  for ((i = 0; i < answers; i++)); do
    o1=$(rand_range 1 221)
    case "$o1" in 10) o1=222 ;; 127) o1=223 ;; esac
    o2=$(rand_range 0 255); o3=$(rand_range 0 255); o4=$(rand_range 1 254)
    qtail="${qtail}$(printf 'c00c00010001%s0004%02x%02x%02x%02x' "$ttl" "$o1" "$o2" "$o3" "$o4")"
  done
  out=$(printf '<r 2><b 0x%s><rc %s><b 0x%s>' "$hex" "$label" "$qtail")
  [[ "$out" =~ ^\<r\ 2\>\<b\ 0x[0-9a-f]{22}\>\<rc\ [0-9]{1,2}\>\<b\ 0x([0-9a-f]{2})+\>$ ]] || return 1
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

cleanup() { if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT
trap 'die "сбой на строке ${LINENO} (код $?)"' ERR

#--- установка AmneziaWG -------------------------------------------------------
do_install() {
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

  # Secure Boot проверка
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

  WAN_IFACE="$(detect_wan_iface)"
  [ -n "$WAN_IFACE" ] || die "не найден интерфейс с default-маршрутом (IPv4)"

  step "Установка зависимостей и заголовков ядра $(uname -r)"
  wait_for_apt_lock
  apt_update || die "apt-get update не удался"
  apt-get install "${APT[@]}" ca-certificates curl gnupg2 openssl software-properties-common python3
  add-apt-repository -y universe
  apt_update
  apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1 \
    || die "linux-headers-$(uname -r) недоступны в репозитории"
  apt-get install "${APT[@]}" dkms build-essential "linux-headers-$(uname -r)" \
    qrencode wireguard-tools iptables iproute2

  step "Установка нативного модуля AmneziaWG (DKMS) из ppa:amnezia/ppa"
  if [ "$(dpkg-query -W -f='${Status}' amneziawg 2>/dev/null || true)" != "install ok installed" ]; then
    wait_for_apt_lock
    add-apt-repository -y ppa:amnezia/ppa
    apt_update
    apt-get install "${APT[@]}" amneziawg
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

  step "Настройка туннеля AmneziaWG (профиль 3.1)"
  install -d -m 700 "$AWG_DIR"

  # Определение случайной подсети клиентов (если конфиг новый)
  local prefix
  prefix="$(get_subnet_prefix)"
  if [ -n "$prefix" ]; then
    AWG_SUBNET="${prefix}0/24"
    AWG_SRV_IP="${prefix}1"
    AWG_CLI_IP="${prefix}2"
    step "Используется существующая подсеть: ${AWG_SUBNET}"
  else
    if [ -z "$AWG_SUBNET" ]; then
      # Генерация случайной подсети 10.x.y.0/24
      local rand_x rand_y
      rand_x="$(rand_range 11 254)"
      while [ "$rand_x" -eq 127 ]; do rand_x="$(rand_range 11 254)"; done
      rand_y="$(rand_range 1 254)"
      AWG_SUBNET="10.${rand_x}.${rand_y}.0/24"
      AWG_SRV_IP="10.${rand_x}.${rand_y}.1"
      AWG_CLI_IP="10.${rand_x}.${rand_y}.2"
      step "Сгенерирована случайная подсеть клиентов: ${AWG_SUBNET}"
    fi
  fi

  if [ -z "$AWG_PORT" ]; then
    AWG_PORT="$(free_port udp)" || die "не найден свободный UDP-порт"
  fi

  PUBLIC_IP="$(detect_public_ip)" || die "не удалось определить внешний IP сервера"

  local regen=1
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    if grep -q '^HeaderProtectionKey[[:space:]]*=' "$AWG_DIR/$AWG_IFACE.conf"; then
      regen=0
      step "Конфиг $AWG_IFACE.conf (профиль 3.1) уже существует — пропускаю генерацию"
      AWG_PORT="$(conf_get ListenPort "$AWG_DIR/$AWG_IFACE.conf")"
    else
      step "Миграция старого конфига 1.x -> 3.1..."
      local ts
      ts="$(date '+%Y%m%d-%H%M%S')"
      cp -a "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/$AWG_IFACE.conf.bak-1x-$ts"
      local npeers
      npeers="$(grep -c '^\[Peer\]' "$AWG_DIR/$AWG_IFACE.conf" || true)"
      if [ "$npeers" -gt 1 ]; then
        warn "В старом конфиге было $npeers пиров. После миграции останется client1, остальных пересоздайте через add-client!"
      fi
    fi
  fi

  if [ "$regen" -eq 1 ]; then
    ( umask 077
      set +x
      local srv_priv srv_pub cli_priv cli_pub
      srv_priv="$(awg genkey)"
      srv_pub="$(printf '%s\n' "$srv_priv" | awg pubkey)"
      cli_priv="$(awg genkey)"
      cli_pub="$(printf '%s\n' "$cli_priv" | awg pubkey)"

      local jc jmin jmax s1 s2 s3 s4 s4_free=() h1 h2 h3 h4 i1 hpk cpa
      jc=$(rand_range 3 6)
      jmin=$(rand_range 40 89)
      jmax=$((jmin + $(rand_range 50 250)))
      s1=$(rand_range 15 150)
      s2=$(rand_range 15 150)
      while [ $((s1 + 56)) -eq "$s2" ]; do s2=$(rand_range 15 150); done
      s3=$(rand_range 12 55)
      while [ $((s2 + 28)) -eq "$s3" ]; do s3=$(rand_range 12 55); done

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
PostUp = iptables -w -t nat -A POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -A FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -A FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -D FORWARD -i ${WAN_IFACE} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

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
      cat > "$AWG_DIR/client1-lan-bypass.conf" <<EOF
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
AllowedIPs = ${ALLOWED_IPS_NO_LAN}
PersistentKeepalive = 25
EOF
      chmod 600 "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/client1.conf" "$AWG_DIR/client1-lan-bypass.conf"
      qrencode -o "$AWG_DIR/client1.png" -s 6 -m 2 < "$AWG_DIR/client1.conf" || true
      qrencode -o "$AWG_DIR/client1-lan-bypass.png" -s 6 -m 2 < "$AWG_DIR/client1-lan-bypass.conf" || true
      chmod 600 "$AWG_DIR/client1.png" "$AWG_DIR/client1-lan-bypass.png" 2>/dev/null || true
    )
  fi

  printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-awg-forward.conf
  sysctl -q -p /etc/sysctl.d/99-awg-forward.conf

  systemctl enable "awg-quick@${AWG_IFACE}" >/dev/null 2>&1 || true
  systemctl restart "awg-quick@${AWG_IFACE}" || die "сервис awg-quick не запустился"

  # Firewall UFW
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${AWG_PORT}/udp" >/dev/null
    step "ufw: открыт порт ${AWG_PORT}/udp"
  fi

  # Установка симлинка awg-manager
  install -m 755 "$0" /usr/local/bin/awg-manager 2>/dev/null || true

  # Установка скрипта бота в /opt/awg-bot
  mkdir -p "$BOT_DIR"
  local bot_src="$(dirname "$0")/bot.py"
  if [ -f "$bot_src" ]; then
    cp "$bot_src" "$BOT_DIR/bot.py"
    chmod 755 "$BOT_DIR/bot.py"
  fi

  # Копирование базы обхода РФ, если есть
  local ru_src="$(dirname "$0")/amnezia-russia-bypass.json"
  if [ -f "$ru_src" ]; then
    cp "$ru_src" "$AWG_DIR/amnezia-russia-bypass.json"
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

  step "Установка AmneziaWG 3.1 успешно завершена!"
  printf '\n'
  printf '============================================================\n'
  printf '  СЕРВЕР AMNEZIAWG 3.1 ГОТОВ К РАБОТЕ\n'
  printf '============================================================\n'
  printf '  Эндпоинт:        %s:%s/udp\n' "$PUBLIC_IP" "$AWG_PORT"
  printf '  Подсеть туннеля: %s\n' "$AWG_SUBNET"
  printf '  Клиентский файл: %s/client1.conf (весь трафик 0.0.0.0/0)\n' "$AWG_DIR"
  printf '  С обходом LAN:   %s/client1-lan-bypass.conf (локальные сети мимо VPN)\n' "$AWG_DIR"
  printf '  QR-код (PNG):    %s/client1.png\n' "$AWG_DIR"
  printf '%s\n' '------------------------------------------------------------'
  printf '  УПРАВЛЕНИЕ СЕРВЕРОМ:\n'
  printf '  • Консольное меню:   sudo awg-manager\n'
  printf '  • Telegram-бот:      sudo awg-manager bot\n'
  printf '  • Обход Gemini:      sudo awg-manager warp-enable\n'
  printf '============================================================\n\n'

  if [ -f "$AWG_DIR/client1.conf" ]; then
    printf 'QR-код первого клиента (сканируйте в Amnezia >= 5.0.1.5):\n\n'
    qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
  fi
}

#--- управление клиентами ------------------------------------------------------
do_add_client() {
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
  [[ "$name" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "некорректное имя '$name' (допустимы A-Z, 0-9, _, -)"

  if [ -f "$AWG_DIR/$name.conf" ] || grep -q "^# ${name}$" "$conf"; then
    die "клиент '$name' уже существует"
  fi

  local prefix
  prefix="$(get_subnet_prefix)"
  [ -n "$prefix" ] || die "не удалось определить подсеть из $conf"

  local used ip="" i
  used="$(awk -F'=' '/^AllowedIPs[[:space:]]*=/{print $2}' "$conf" | grep -oE "${prefix}[0-9]+" | sort -u || true)"
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

  # Если есть client1.conf, берем Endpoint из него (чтобы не дергать curl)
  local ep_host=""
  if [ -f "$AWG_DIR/client1.conf" ]; then
    ep_host="$(conf_get Endpoint "$AWG_DIR/client1.conf" | cut -d':' -f1)"
  fi
  endpoint="${ep_host:-$(detect_public_ip)}" || die "не удалось определить IP сервера"

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
    cat > "$AWG_DIR/${name}-lan-bypass.conf" <<EOF
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
AllowedIPs = ${ALLOWED_IPS_NO_LAN}
PersistentKeepalive = 25
EOF
    chmod 600 "$AWG_DIR/$name.conf" "$AWG_DIR/${name}-lan-bypass.conf" "$conf"
    qrencode -o "$AWG_DIR/$name.png" -s 6 -m 2 < "$AWG_DIR/$name.conf" || true
    qrencode -o "$AWG_DIR/${name}-lan-bypass.png" -s 6 -m 2 < "$AWG_DIR/${name}-lan-bypass.conf" || true
    chmod 600 "$AWG_DIR/$name.png" "$AWG_DIR/${name}-lan-bypass.png" 2>/dev/null || true
  )

  step "Клиент '$name' ($ip) успешно создан!"
  printf '  Файл конфига (0.0.0.0/0):       %s/%s.conf\n' "$AWG_DIR" "$name"
  printf '  QR-код:                         %s/%s.png\n' "$AWG_DIR" "$name"
  printf '  С обходом локалок (LAN bypass): %s/%s-lan-bypass.conf\n' "$AWG_DIR" "$name"
  printf '  QR-код обхода LAN:              %s/%s-lan-bypass.png\n\n' "$AWG_DIR" "$name"
  if [ "$IS_TTY" = 1 ]; then
    qrencode -t ansiutf8 < "$AWG_DIR/$name.conf" || true
  fi
}

do_remove_client() {
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
    name="$key"
    pub="$(awk -v want="$name" '/^\[Peer\]/{c=""} /^#/{c=$0; sub(/^#[ \t]*/,"",c); next} /^PublicKey/{if(c==want){v=$0; sub(/^PublicKey[ \t]*=[ \t]*/,"",v); print v; exit}}' "$conf")"
    [ -n "$pub" ] || die "клиент '$name' не найден"
  fi

  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    awg set "$AWG_IFACE" peer "$pub" remove 2>/dev/null || true
  fi

  if grep -qF "$pub" "$conf"; then
    local tmp
    tmp="$(mktemp "$AWG_DIR/.awg0.XXXXXX")"
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

  if [ -n "$name" ]; then
    rm -f "$AWG_DIR/$name.conf" "$AWG_DIR/$name.png" "$AWG_DIR/${name}-lan-bypass.conf" "$AWG_DIR/${name}-lan-bypass.png"
    step "Клиент '$name' удалён"
  else
    step "Peer $pub удалён"
  fi
}

do_list_clients() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен"

  printf '\n%b=== Список клиентов AmneziaWG ===%b\n' "$C_BOLD" "$C_RESET"
  printf '%-4s %-18s %-16s %-10s %-18s %s\n' "№" "ИМЯ" "IP АДРЕС" "СТАТУС" "HANDSHAKE" "ТРАФИК (RX/TX)"
  printf '%s\n' "----------------------------------------------------------------------------------"

  # Извлекаем dump из awg show
  local dump=""
  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    dump="$(awg show "$AWG_IFACE" dump 2>/dev/null || true)"
  fi

  local now idx=0
  now=$(date +%s)

  python3 -c "
import sys

dump_lines = '''$dump'''.strip().split('\n')
stats = {}
for line in dump_lines:
    parts = line.split('\t')
    if len(parts) >= 8:
        stats[parts[0]] = {
            'endpoint': parts[2],
            'handshake': int(parts[4]) if parts[4].isdigit() else 0,
            'rx': int(parts[5]) if parts[5].isdigit() else 0,
            'tx': int(parts[6]) if parts[6].isdigit() else 0
        }

def fmt_bytes(b):
    for u in ['B', 'KB', 'MB', 'GB']:
        if b < 1024: return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} TB'

def fmt_time(ts):
    if ts == 0: return 'никогда'
    d = $now - ts
    if d < 60: return f'{d}с назад'
    if d < 3600: return f'{d//60}м назад'
    if d < 86400: return f'{d//3600}ч назад'
    return f'{d//86400}д назад'

conf = '$conf'
clients = []
curr = {}
with open(conf, 'r') as f:
    for line in f:
        l = line.strip()
        if l == '[Peer]':
            if curr and 'pub' in curr: clients.append(curr)
            curr = {'name': '', 'pub': '', 'ip': ''}
        elif l.startswith('#') and curr is not None and not curr.get('name'):
            curr['name'] = l.lstrip('#').strip()
        elif '=' in l and curr is not None:
            k, v = l.split('=', 1)
            k, v = k.strip(), v.strip()
            if k == 'PublicKey': curr['pub'] = v
            elif k == 'AllowedIPs': curr['ip'] = v
    if curr and 'pub' in curr: clients.append(curr)

for i, c in enumerate(clients, 1):
    pub = c.get('pub', '')
    st = stats.get(pub, {'handshake': 0, 'rx': 0, 'tx': 0})
    hs = st['handshake']
    online = ($now - hs < 180) and (hs > 0)
    status = '\033[0;32mOnline\033[0m' if online else '\033[0;37mOffline\033[0m'
    name = c.get('name') or 'client'
    ip = c.get('ip', '').split('/')[0]
    traf = f'↓{fmt_bytes(st[\"tx\"])} / ↑{fmt_bytes(st[\"rx\"])}'
    print(f'{i:<4} {name:<18} {ip:<16} {status:<19} {fmt_time(hs):<18} {traf}')
"
  printf '\n'
}

#--- Cloudflare WARP для AI (Gemini + OpenAI ChatGPT + Claude) -----------------
do_warp_enable() {
  step "Настройка обхода блокировок AI (Google Gemini, OpenAI ChatGPT, Claude) через Cloudflare WARP"
  wait_for_apt_lock
  apt_update
  apt-get install "${APT[@]}" dnsmasq nftables wireguard-tools curl jq python3

  mkdir -p "$WARP_DIR"
  local warp_conf="/etc/wireguard/warp0.conf"

  # Если профиль warp0 ещё не зарегистрирован — регистрируем через API Cloudflare
  if [ ! -f "$warp_conf" ]; then
    step "Регистрация бесплатного профиля Cloudflare WARP..."
    python3 -c "
import urllib.request, json, random, string, datetime, subprocess

priv = subprocess.check_output(['wg', 'genkey']).decode().strip()
pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).decode().strip()

def rand_str(n): return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
install_id = rand_str(22)
fcm_token = f'{install_id}:APA91b' + rand_str(134)
url = f'https://api.cloudflareclient.com/v0a{random.randint(1000, 1999)}/reg'

headers = {
    'CF-Client-Version': 'a-7.21-0721',
    'User-Agent': 'okhttp/3.12.1',
    'Content-Type': 'application/json; charset=UTF-8',
}
body = {
    'key': pub,
    'install_id': install_id,
    'fcm_token': fcm_token,
    'warp_enabled': False,
    'tos': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
    'type': 'Android',
    'locale': 'en_US'
}

req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers=headers)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    v4 = data['config']['interface']['addresses']['v4']
    cf_pub = data['config']['peers'][0]['public_key']
    cf_ep = 'engage.cloudflareclient.com:2408'

conf = f'''[Interface]
PrivateKey = {priv}
Address = {v4}/32
Table = 51820

[Peer]
PublicKey = {cf_pub}
Endpoint = {cf_ep}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''
with open('$warp_conf', 'w') as f:
    f.write(conf)
" || die "не удалось зарегистрировать Cloudflare WARP"
    chmod 600 "$warp_conf"
  fi

  # Запуск интерфейса warp0
  systemctl enable wg-quick@warp0 >/dev/null 2>&1 || true
  systemctl restart wg-quick@warp0 || die "не удалось запустить интерфейс warp0"

  # Настройка dnsmasq с nftset для AI-сервисов (Gemini, OpenAI, Claude)
  systemctl stop systemd-resolved 2>/dev/null || true
  systemctl disable systemd-resolved 2>/dev/null || true
  rm -f /etc/resolv.conf
  printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf

  cat > /etc/dnsmasq.d/ai-warp.conf <<'EOF'
# Обход блокировок AI через Cloudflare WARP (nftset)
port=53
listen-address=127.0.0.1
server=1.1.1.1
server=8.8.8.8
domain-needed
bogus-priv

# --- Google Gemini & DeepMind (geosite:google-deepmind) ---
nftset=/gemini.google.com/4#inet#awg_ai#ai_v4
nftset=/aistudio.google.com/4#inet#awg_ai#ai_v4
nftset=/generativelanguage.googleapis.com/4#inet#awg_ai#ai_v4
nftset=/ai.google.dev/4#inet#awg_ai#ai_v4
nftset=/deepmind.com/4#inet#awg_ai#ai_v4
nftset=/deepmind.google/4#inet#awg_ai#ai_v4
nftset=/notebooklm.google/4#inet#awg_ai#ai_v4
nftset=/notebooklm.google.com/4#inet#awg_ai#ai_v4
nftset=/makersuite.google.com/4#inet#awg_ai#ai_v4
nftset=/alkalimakersuite-pa.clients6.google.com/4#inet#awg_ai#ai_v4
nftset=/proactivebackend-pa.googleapis.com/4#inet#awg_ai#ai_v4

# --- OpenAI & ChatGPT (geosite:openai) ---
nftset=/openai.com/4#inet#awg_ai#ai_v4
nftset=/chatgpt.com/4#inet#awg_ai#ai_v4
nftset=/chat.com/4#inet#awg_ai#ai_v4
nftset=/sora.com/4#inet#awg_ai#ai_v4
nftset=/oaistatic.com/4#inet#awg_ai#ai_v4
nftset=/oaiusercontent.com/4#inet#awg_ai#ai_v4
nftset=/livekit.cloud/4#inet#awg_ai#ai_v4
nftset=/auth0.openai.com/4#inet#awg_ai#ai_v4
nftset=/openaiapi-site.azureedge.net/4#inet#awg_ai#ai_v4

# --- Anthropic Claude ---
nftset=/claude.ai/4#inet#awg_ai#ai_v4
nftset=/anthropic.com/4#inet#awg_ai#ai_v4
EOF

  # Настройка nftables таблицы и маркировки пакетов
  nft 'add table inet awg_ai' 2>/dev/null || true
  nft 'add set inet awg_ai ai_v4 { type ipv4_addr; flags interval, timeout; timeout 1h; }' 2>/dev/null || true
  nft 'add chain inet awg_ai prerouting { type filter hook prerouting priority mangle; }' 2>/dev/null || true
  nft 'flush chain inet awg_ai prerouting' 2>/dev/null || true
  nft 'add rule inet awg_ai prerouting ip daddr @ai_v4 meta mark set 0x51' 2>/dev/null || true

  # Маршрутизация по fwmark
  ip rule del fwmark 0x51 table 51820 2>/dev/null || true
  ip rule add fwmark 0x51 table 51820
  iptables -w -t nat -C POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || \
    iptables -w -t nat -A POSTROUTING -o warp0 -j MASQUERADE

  systemctl restart dnsmasq

  # Создание юнита автостарта правил
  cat > /etc/systemd/system/awg-ai-warp.service <<'EOF'
[Unit]
Description=AmneziaWG AI (Gemini + ChatGPT) Cloudflare WARP Routing
After=network.target wg-quick@warp0.service
Wants=wg-quick@warp0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft add table inet awg_ai
ExecStart=/usr/bin/nft add set inet awg_ai ai_v4 { type ipv4_addr; flags interval, timeout; timeout 1h; }
ExecStart=/usr/bin/nft add chain inet awg_ai prerouting { type filter hook prerouting priority mangle; }
ExecStart=/usr/bin/nft add rule inet awg_ai prerouting ip daddr @ai_v4 meta mark set 0x51
ExecStart=/bin/sh -c 'ip rule del fwmark 0x51 table 51820 2>/dev/null || true; ip rule add fwmark 0x51 table 51820'
ExecStart=/usr/sbin/iptables -w -t nat -A POSTROUTING -o warp0 -j MASQUERADE
ExecStop=/bin/sh -c 'ip rule del fwmark 0x51 table 51820 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now awg-ai-warp.service

  step "Обход Gemini + ChatGPT через Cloudflare WARP успешно настроен!"
  do_warp_test
}

do_warp_disable() {
  step "Отключение обхода AI (Gemini + ChatGPT)"
  systemctl disable --now awg-ai-warp.service 2>/dev/null || true
  systemctl stop wg-quick@warp0 2>/dev/null || true
  systemctl disable wg-quick@warp0 2>/dev/null || true
  ip rule del fwmark 0x51 table 51820 2>/dev/null || true
  iptables -w -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true
  rm -f /etc/dnsmasq.d/ai-warp.conf /etc/dnsmasq.d/gemini-warp.conf
  systemctl restart dnsmasq 2>/dev/null || true
  step "Обход AI отключён"
}

do_warp_test() {
  step "Проверка доступности Google Gemini и OpenAI ChatGPT..."
  local res_gemini res_openai
  res_gemini="$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://generativelanguage.googleapis.com || true)"
  if [ "$res_gemini" = "200" ] || [ "$res_gemini" = "404" ] || [ "$res_gemini" = "400" ]; then
    printf '%b  [OK] Google Gemini API:  доступен (HTTP %s)%b\n' "$C_GREEN" "$res_gemini" "$C_RESET"
  else
    printf '%b  [FAIL] Google Gemini API: код %s%b\n' "$C_RED" "$res_gemini" "$C_RESET"
  fi

  res_openai="$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://api.openai.com || true)"
  if [ "$res_openai" = "200" ] || [ "$res_openai" = "404" ] || [ "$res_openai" = "405" ]; then
    printf '%b  [OK] OpenAI / ChatGPT:   доступен (HTTP %s)%b\n' "$C_GREEN" "$res_openai" "$C_RESET"
  else
    printf '%b  [FAIL] OpenAI / ChatGPT:  код %s%b\n' "$C_RED" "$res_openai" "$C_RESET"
  fi
}

do_ru_bypass() {
  step "База раздельного туннелирования для сайтов РФ (GeoIP RU)"
  local target="$AWG_DIR/amnezia-russia-bypass.json"
  local url="https://raw.githubusercontent.com/lib4u/amnezia-tunneling-ru/main/amnezia.json"
  local local_src="$(dirname "$0")/amnezia-russia-bypass.json"

  if [ -f "$local_src" ]; then
    cp "$local_src" "$target"
  elif [ ! -f "$target" ]; then
    step "Загрузка актуального списка российских сайтов и сервисов..."
    curl -fsSL "$url" -o "$target" 2>/dev/null || warn "не удалось скачать базу"
  fi

  if [ -f "$target" ]; then
    printf '\n%bФайл базы готов:%b %s (%s)\n' "$C_GREEN" "$C_RESET" "$target" "$(du -h "$target" | awk '{print $1}')"
    printf '\n%bИНСТРУКЦИЯ ПО НАСТРОЙКЕ В ПРИЛОЖЕНИИ AMNEZIA VPN:%b\n' "$C_BOLD" "$C_RESET"
    printf '1. Скопируйте файл %s к себе на телефон или компьютер.\n' "$target"
    printf '   (Или отправьте команду в Telegram-боте: кнопка "🇷🇺 Обход сайтов РФ")\n'
    printf '2. В приложении Amnezia VPN:\n'
    printf '   Настройки (шестерёнка) -> Подключение -> Раздельное туннелирование сайтов\n'
    printf '3. Выберите режим: «Адреса из списка НЕ должны использовать VPN»\n'
    printf '4. Нажмите «Импорт» и выберите скачанный файл.\n\n'
    printf '%bГотово! Все российские банки, Госуслуги и сайты .ru пойдут напрямую.%b\n\n' "$C_GREEN" "$C_RESET"
  fi
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
    printf '\n1. Создайте бота в Telegram через @BotFather и скопируйте токен бота.\n'
    read -r -p "Токен бота [текущий: ${token:-нет}]: " new_token || return 1
    if [ -n "$new_token" ]; then token="$new_token"; fi

    printf '\n2. Узнайте свой Telegram ID через @userinfobot (цифры, можно несколько через запятую).\n'
    read -r -p "Ваш Telegram ID [текущий: ${admin_id:-нет}]: " new_id || return 1
    if [ -n "$new_id" ]; then admin_id="$new_id"; fi

    printf '\n3. (Опционально) ID группы, если бот будет в группе/супергруппе (например, -1001234567890, или Enter пропустить):\n'
    printf '   Подсказка: отправьте команду /id боту в группе, чтобы узнать ID.\n'
    read -r -p "GROUP_ID [текущий: ${group_id:-нет}]: " new_gid || true
    if [ -n "$new_gid" ]; then group_id="$new_gid"; fi

    printf '\n4. (Опционально) ID топика / темы форума (thread_id, например 42, или Enter для General/любого):\n'
    read -r -p "TOPIC_ID [текущий: ${topic_id:-нет}]: " new_tid || true
    if [ -n "$new_tid" ]; then topic_id="$new_tid"; fi
  fi

  [ -n "$token" ] || die "токен бота не может быть пустым"
  [ -n "$admin_id" ] || die "admin_id не может быть пустым"

  ( umask 077
    cat > "$BOT_ENV" <<EOF
BOT_TOKEN="${token}"
ADMIN_ID="${admin_id}"
GROUP_ID="${group_id}"
TOPIC_ID="${topic_id}"
EOF
    chmod 600 "$BOT_ENV"
  )

  mkdir -p "$BOT_DIR"
  local bot_src="$(dirname "$0")/bot.py"
  if [ -f "$bot_src" ]; then
    cp "$bot_src" "$BOT_DIR/bot.py"
  elif [ ! -f "$BOT_DIR/bot.py" ]; then
    die "файл bot.py не найден"
  fi
  chmod 755 "$BOT_DIR/bot.py"

  cat > /etc/systemd/system/awg-bot.service <<EOF
[Unit]
Description=AmneziaWG Telegram Management Bot
After=network.target awg-quick@${AWG_IFACE}.service
Wants=awg-quick@${AWG_IFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${BOT_ENV}
ExecStart=/usr/bin/python3 ${BOT_DIR}/bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now awg-bot.service
  sleep 1

  if systemctl is-active --quiet awg-bot; then
    step "Telegram-бот успешно запущен! Откройте вашего бота в Telegram и отправьте /start"
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

  # Статус бота
  local bot_act
  bot_act="$(systemctl is-active awg-bot 2>/dev/null || true)"
  if [ "$bot_act" = "active" ]; then
    printf '  Telegram-бот:      %b🟢 Работает (awg-bot)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Telegram-бот:      %b⚪ Не запущен%b\n' "$C_YELLOW" "$C_RESET"
  fi

  # Статус Gemini / OpenAI WARP
  local warp_act
  warp_act="$(systemctl is-active awg-ai-warp 2>/dev/null || true)"
  if [ "$warp_act" = "active" ]; then
    printf '  Обход AI (Gemini/GPT): %b🟢 Включён (Cloudflare WARP)%b\n' "$C_GREEN" "$C_RESET"
  else
    printf '  Обход AI (Gemini/GPT): %b⚪ Отключён%b\n' "$C_YELLOW" "$C_RESET"
  fi
  printf '%b------------------------------------------------------------%b\n' "$C_CYAN" "$C_RESET"

  do_list_clients
}

#--- бэкап и удаление ---------------------------------------------------------
do_backup() {
  step "Создание бэкапа AmneziaWG"
  local ts tar
  ts="$(date '+%Y%m%d-%H%M%S')"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  tar="$BACKUP_DIR/awg-backup-$ts.tar.gz"

  tar -czf "$tar" -C / etc/amnezia/amneziawg root/awg-credentials.txt 2>/dev/null || true
  chmod 600 "$tar"
  step "Бэкап создан: $tar"
}

do_restore() {
  local file="${1:-}"
  [ -n "$file" ] || die "укажите файл бэкапа"
  [ -f "$file" ] || die "файл $file не найден"

  # Защита от симлинков
  if tar -tvf "$file" 2>/dev/null | grep -q '^[lh]'; then
    die "архив содержит симлинки — восстановление отменено"
  fi

  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  tar -xzf "$file" -C /
  chmod 700 "$AWG_DIR" 2>/dev/null || true
  chmod 600 "$AWG_DIR"/*.conf 2>/dev/null || true
  systemctl start "awg-quick@${AWG_IFACE}"
  step "Восстановление завершено!"
}

do_uninstall() {
  step "Полное удаление AmneziaWG"
  do_backup
  do_warp_disable 2>/dev/null || true
  systemctl stop awg-bot 2>/dev/null || true
  systemctl disable awg-bot 2>/dev/null || true
  rm -f /etc/systemd/system/awg-bot.service

  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  systemctl disable "awg-quick@${AWG_IFACE}" 2>/dev/null || true

  local wan
  wan="$(detect_wan_iface)"
  local prefix
  prefix="$(get_subnet_prefix)"
  if [ -n "$prefix" ] && [ -n "$wan" ]; then
    iptables -w -t nat -D POSTROUTING -s "${prefix}0/24" -o "$wan" -j MASQUERADE 2>/dev/null || true
  fi

  apt-get purge "${APT[@]}" amneziawg amneziawg-dkms amneziawg-tools 2>/dev/null || true
  rmmod amneziawg 2>/dev/null || true
  add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true

  rm -rf "$AWG_DIR" "$BOT_DIR" /usr/local/bin/awg-manager "$CRED_FILE" /etc/sysctl.d/99-awg-forward.conf
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
    local warp_status="⚪ Отключён"
    if systemctl is-active --quiet awg-ai-warp 2>/dev/null; then
      warp_status="🟢 Активен"
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
    printf '  Туннель awg0:     %s (%s/udp, %s, клиентов: %s)\n' "$srv_status" "$port" "$subnet" "$count"
    printf '  Telegram-бот:     %b%s%b\n' "$C_CYAN" "$bot_status" "$C_RESET"
    printf '  Обход AI (Gemini/GPT): %b%s%b\n' "$C_CYAN" "$warp_status" "$C_RESET"
    printf '%b------------------------------------------------------------%b\n' "$C_BLUE" "$C_RESET"
    printf '  %bУПРАВЛЕНИЕ КЛИЕНТАМИ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    1) Список клиентов, статус и QR-коды\n'
    printf '    2) Добавить нового клиента\n'
    printf '    3) Удалить клиента\n'
    printf '  %bСЕРВИСЫ И ИНТЕГРАЦИИ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    4) Настроить Telegram-бота (управление через ТГ)\n'
    printf '    5) Настройка обхода AI (Gemini + ChatGPT) через WARP\n'
    printf '    6) Обход сайтов РФ (GeoIP RU) — база amnezia.json\n'
    printf '    7) Детальный статус и статистика (awg show)\n'
    printf '    8) Перезапустить туннель\n'
    printf '  %bОБСЛУЖИВАНИЕ:%b\n' "$C_BOLD" "$C_RESET"
    printf '    9) Резервная копия (бэкап) / Восстановление\n'
    printf '   10) Переустановить AmneziaWG начисто\n'
    printf '   11) Полное удаление AmneziaWG\n'
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
            # Поиск имени клиента по номеру
            cname="$(awk -v want="$subch" '
              BEGIN { n=0 }
              /^\[Peer\]/ { name="" }
              /^#/ && !name { name=$0; sub(/^#[ \t]*/, "", name) }
              /^PublicKey/ {
                n++
                if (n == want) { print (name ? name : "client" n); exit }
              }
            ' "$conf")"
          elif [ -f "$AWG_DIR/$subch.conf" ]; then
            cname="$subch"
          fi

          if [ -n "$cname" ] && [ -f "$AWG_DIR/$cname.conf" ]; then
            printf '\nТип QR-кода для клиента %s:\n' "$cname"
            printf '  1) Стандартный (0.0.0.0/0 — весь интернет через VPN)\n'
            printf '  2) С обходом LAN (локальные сети 192.168/10/172 идут напрямую)\n'
            local pt
            read -r -p "Выбор [1]: " pt || true
            local qf="$AWG_DIR/$cname.conf"
            if [ "$pt" = "2" ]; then
              if [ ! -f "$AWG_DIR/${cname}-lan-bypass.conf" ]; then
                sed "s|AllowedIPs[[:space:]]*=.*|AllowedIPs = ${ALLOWED_IPS_NO_LAN}|" "$AWG_DIR/$cname.conf" > "$AWG_DIR/${cname}-lan-bypass.conf"
                chmod 600 "$AWG_DIR/${cname}-lan-bypass.conf"
              fi
              qf="$AWG_DIR/${cname}-lan-bypass.conf"
            fi
            printf '\nQR-код (%s):\n\n' "$(basename "$qf")"
            qrencode -t ansiutf8 < "$qf" || true
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
      5)
        printf '\n1) Включить обход AI (WARP)\n2) Проверить доступность Gemini + ChatGPT\n3) Отключить обход\n'
        local wch
        read -r -p "Выбор: " wch || true
        case "$wch" in
          1) do_warp_enable ;;
          2) do_warp_test ;;
          3) do_warp_disable ;;
        esac
        ;;
      6) do_ru_bypass ;;
      7) do_status ;;
      8) systemctl restart "awg-quick@${AWG_IFACE}" && step "Туннель перезапущен" ;;
      9)
        printf '\n1) Создать бэкап\n2) Восстановить из файла\n'
        local bkch
        read -r -p "Выбор: " bkch || true
        if [ "$bkch" = "1" ]; then do_backup; elif [ "$bkch" = "2" ]; then
          read -r -p "Путь к tar.gz архиву: " bkp || true
          do_restore "$bkp"
        fi
        ;;
      10)
        if confirm_yes "Переустановить AmneziaWG начисто (текущие клиенты будут сохранены в бэкап)?"; then
          do_install
        fi
        ;;
      11)
        if confirm_yes "Полностью удалить AmneziaWG с сервера?"; then
          do_uninstall
        fi
        ;;
      0|q|quit|exit) break ;;
      *) printf 'Неизвестный пункт: %s\n' "$choice" ;;
    esac
  done
}

#--- диспетчер команд ---------------------------------------------------------
ACTION="${1:-}"

if [ -t 0 ] && [ -t 1 ]; then IS_TTY=1; fi

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
exec > >(tee -a "$LOG_FILE") 2>&1

case "$ACTION" in
  menu) show_menu ;;
  install) do_install ;;
  add-client) do_add_client "${2:-}" ;;
  remove-client) do_remove_client "${2:-}" ;;
  list-clients|clients) do_list_clients ;;
  bot) do_bot_setup ;;
  bot-status) do_bot_status ;;
  bot-restart) do_bot_restart ;;
  warp-enable) do_warp_enable ;;
  warp-disable) do_warp_disable ;;
  warp-test) do_warp_test ;;
  ru-bypass) do_ru_bypass ;;
  status) do_status ;;
  backup) do_backup ;;
  restore) do_restore "${2:-}" ;;
  uninstall) do_uninstall ;;
  help|-h|--help)
    cat <<EOF
Использование: sudo bash install.sh [команда]

Команды:
  menu          Интерактивное меню управления (TUI)
  install       Установка или идемпотентная проверка сервера
  clients       Список клиентов, статус онлайн и трафик
  add-client    Добавить нового клиента
  remove-client Удалить клиента (по имени или pubkey)
  bot           Настройка Telegram-бота для управления клиентами
  warp-enable   Включить обход Gemini через Cloudflare WARP
  warp-disable  Отключить обход Gemini
  warp-test     Проверить доступность Google Gemini API
  status        Детальный статус сервисов и интерфейса
  backup        Создать резервную копию
  restore       Восстановить из архива
  uninstall     Полное удаление с сервера
EOF
    ;;
  *) die "Неизвестная команда '$ACTION'. Справка: bash install.sh help" ;;
esac
