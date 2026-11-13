#!/usr/bin/env bash
#===============================================================================
#  awg-3xui-installer — автономный установщик для Ubuntu 24.04 LTS (noble)
#
#  Последовательность (без интерактивных вопросов):
#    1. Предпроверка: root, bash, Ubuntu 24.04, не контейнер, архитектура,
#       systemd, Secure Boot, место на диске (>=1.5 ГБ), сеть до GitHub и PPA,
#       защита от параллельного запуска
#    2. Зависимости + заголовки текущего ядра + fail2ban/nftables (для 3x-ui)
#    3. AmneziaWG: НАТИВНЫЙ модуль ядра amneziawg (DKMS из ppa:amnezia/ppa)
#       + amneziawg-tools (awg / awg-quick)
#    4. WireGuard: wireguard-tools (wg / wg-quick) — модуль уже в ядре Ubuntu
#    5. Рабочий туннель: awg0 + NAT + клиентский конфиг + QR-код
#       + runtime-проверка: адрес, UDP-порт, ip_forward, NAT-правило
#    6. Панель 3x-ui (неинтерактивно: случайные порт/логин/пароль/путь)
#    7. Firewall (только если ufw уже активен) + верификация + итог с кредами
#
#  Запуск:
#    curl -fsSL https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main/install.sh | sudo bash
#
#  Переопределение через окружение (буквы/цифры/_/-):
#    AWG_PORT, PANEL_PORT, PANEL_USER, PANEL_PASS, PANEL_PATH
#    пример: sudo AWG_PORT=51820 PANEL_PORT=8443 bash install.sh
#
#  Логи:       /var/log/awg-3xui-install.log
#              /var/log/awg-3xui-install.debug.log  (трассировка каждой команды)
#  Результат:  /root/awg-3xui-credentials.txt (0600)
#===============================================================================

# Защита от запуска через sh/dash (скрипт требует bash). Строка POSIX-совместима.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ОШИБКА: нужен bash. Запуск: curl -fsSL <url>/install.sh | sudo bash" >&2
  exit 1
fi
set -Eeuo pipefail

#--- конфигурация --------------------------------------------------------------
AWG_IFACE="awg0"
AWG_DIR="/etc/amnezia/amneziawg"
AWG_SUBNET="10.8.1.0/24"
AWG_SRV_IP="10.8.1.1"
AWG_CLI_IP="10.8.1.2"
AWG_DNS="1.1.1.1"
AWG_MTU="1280"
AWG_PORT="${AWG_PORT:-}"            # пусто -> случайный свободный UDP 20000-59999
AWG_PORT_ENV="${AWG_PORT:-}"        # исходное значение из окружения (для предупреждений)
PANEL_PORT="${PANEL_PORT:-}"        # пусто -> случайный свободный TCP 20000-59999
PANEL_USER="${PANEL_USER:-}"        # пусто -> случайный
PANEL_PASS="${PANEL_PASS:-}"        # пусто -> случайный
PANEL_PATH="${PANEL_PATH:-}"        # webBasePath панели, без слэшей
PANEL_API_TOKEN=""
CRED_FILE="/root/awg-3xui-credentials.txt"
LOG_FILE="/var/log/awg-3xui-install.log"
DBG_FILE="/var/log/awg-3xui-install.debug.log"
XUI_INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh"
PPA_INRELEASE_URL="https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/InRelease"
TMP_DIR=""

#--- helpers -------------------------------------------------------------------
step() { printf '\n==> [%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { printf '\nОШИБКА: %s\nПодробности: %s и %s\n' "$*" "$LOG_FILE" "$DBG_FILE" >&2; exit 1; }
rand_hex() { openssl rand -hex "${1:-8}"; }
rand_u32() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }

free_port() { # $1 = udp|tcp; печатает свободный порт, 60 попыток
  local proto="$1" flag p
  case "$proto" in
    udp) flag="-u" ;;
    tcp) flag="-t" ;;
    *) return 1 ;;
  esac
  for _ in $(seq 1 60); do
    p=$((20000 + RANDOM % 40000))
    if [ -z "$(ss -Hln "$flag" "sport = :${p}")" ]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

wait_for_apt_lock() { # unattended-upgrades может держать dpkg-лок минутами
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

panel_http_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    "http://127.0.0.1:${PANEL_PORT}/${PANEL_PATH}/" || true
}

cleanup() { if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT
trap 'die "сбой на строке ${LINENO} (код $?)"' ERR

#--- 1. предпроверка -----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите от root:  curl -fsSL <url>/install.sh | sudo bash" >&2
  exit 1
fi

# защита от параллельного запуска (лок держится до конца процесса)
exec 9>/run/lock/awg-3xui-installer.lock
flock -n 9 || { echo "ОШИБКА: установщик уже запущен в другом процессе" >&2; exit 1; }

mkdir -p /var/log
touch "$LOG_FILE" "$DBG_FILE"
chmod 600 "$LOG_FILE" "$DBG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1
exec 5>>"$DBG_FILE"
BASH_XTRACEFD=5   # без export: иначе дочерние bash (dpkg/dkms) ругаются на fd 5
set -x

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
  die "обнаружен контейнер (LXC/OpenVZ/Docker): DKMS-модуль требует собственного ядра — нужен VPS"
fi

# Secure Boot: читаем EFI-переменную напрямую (без установки mokutil).
# Формат: 4 байта атрибутов + 1 байт значения (1 = включён).
SB_VAR="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -r "$SB_VAR" ]; then
  SB_STATE="$(od -An -t u1 "$SB_VAR" | awk '{print $NF}')"
  if [ "$SB_STATE" = "1" ]; then
    die "Secure Boot включён: неподписанный DKMS-модуль amneziawg не загрузится. Отключите Secure Boot в UEFI и запустите установщик снова."
  fi
fi

AVAIL_MB="$(df -Pm / | awk 'NR==2{print $4}')"
if [ "${AVAIL_MB:-0}" -lt 1500 ]; then
  die "мало места на / : ${AVAIL_MB} МБ (нужно >= 1500 МБ: DKMS-сборка + 3x-ui ~300 МБ)"
fi

WAN_IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
[ -n "$WAN_IFACE" ] || die "не найден интерфейс с default-маршрутом (IPv4)"

curl -fsS --max-time 15 -o /dev/null "$XUI_INSTALL_URL" \
  || die "нет доступа к GitHub (raw.githubusercontent.com) — установщик не сможет скачать компоненты"
curl -fsS --max-time 15 -o /dev/null "$PPA_INRELEASE_URL" \
  || die "нет доступа к PPA (ppa.launchpadcontent.net) — не поставить amneziawg-dkms"

#--- 2. зависимости ------------------------------------------------------------
step "Установка зависимостей и заголовков ядра $(uname -r)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300)

wait_for_apt_lock || die "apt/dpkg занят более 5 минут (unattended-upgrades?) — повторите позже"
apt-get update || { sleep 5; apt-get update; }
apt-get install "${APT[@]}" ca-certificates curl gnupg2 openssl \
  software-properties-common python3-launchpadlib
wait_for_apt_lock || die "apt/dpkg занят более 5 минут — повторите позже"
add-apt-repository -y universe
apt-get update
apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1 \
  || die "linux-headers-$(uname -r) недоступен в репозиториях — DKMS не собрать (нестандартное ядро?)"
apt-get install "${APT[@]}" \
  dkms build-essential "linux-headers-$(uname -r)" \
  qrencode wireguard-tools iptables iproute2

# fail2ban + nftables заранее: 3x-ui настраивает IP Limit поверх уже установленного
# fail2ban и не ходит в apt (иначе может упасть на dpkg-локе unattended-upgrades).
# pyasynchat — как в апстриме 3x-ui для Ubuntu>=24 (fail2ban 1.0.2 / Python 3.12).
step "fail2ban + nftables (для IP Limit в 3x-ui)"
apt-get install "${APT[@]}" fail2ban nftables python3-pip
if python3 -m pip install --break-system-packages pyasynchat; then
  systemctl restart fail2ban || true
else
  step "ВНИМАНИЕ: pyasynchat не установлен (нет доступа к PyPI?) — IP Limit может не работать"
fi
systemctl is-active --quiet fail2ban \
  || step "ВНИМАНИЕ: fail2ban не активен — IP Limit в 3x-ui может не работать"

#--- 3. AmneziaWG: модуль ядра + инструменты -----------------------------------
step "AmneziaWG: нативный модуль ядра (DKMS) + awg-tools из ppa:amnezia/ppa"
if [ "$(dpkg-query -W -f='${Status}' amneziawg 2>/dev/null || true)" = "install ok installed" ]; then
  step "пакет amneziawg уже установлен — пропускаю"
else
  wait_for_apt_lock || die "apt/dpkg занят более 5 минут — повторите позже"
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update
  apt-get install "${APT[@]}" amneziawg
fi

if ! modprobe amneziawg; then
  dkms status || true
  tail -n 40 /var/lib/dkms/amneziawg/*/build/make.log 2>/dev/null || true
  die "модуль amneziawg не загрузился (лог сборки DKMS — выше)"
fi
[ -d /sys/module/amneziawg ] || die "модуль amneziawg не появился в /sys/module"
awg --version
dkms status | grep amneziawg || true

#--- 4. WireGuard (модуль в ядре Ubuntu) ----------------------------------------
step "WireGuard: проверка нативной поддержки ядром"
command -v wg >/dev/null 2>&1 || die "wireguard-tools не установлены"
modinfo wireguard >/dev/null 2>&1 || die "модуль wireguard недоступен в ядре $(uname -r)"
wg --version

#--- 5. туннель awg0 + клиент ---------------------------------------------------
step "Настройка туннеля AmneziaWG (${AWG_IFACE})"
install -d -m 700 "$AWG_DIR"

if [ -z "$AWG_PORT" ]; then
  AWG_PORT="$(free_port udp)" || die "не найден свободный UDP-порт"
fi
if ! [[ "$AWG_PORT" =~ ^[0-9]+$ ]] || [ "$AWG_PORT" -lt 1 ] || [ "$AWG_PORT" -gt 65535 ]; then
  die "AWG_PORT некорректен: $AWG_PORT"
fi

PUBLIC_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
if ! [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  PUBLIC_IP="$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
fi
if ! [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  step "ВНИМАНИЕ: внешний IP не определён через echo-сервисы, использую адрес интерфейса: ${PUBLIC_IP}"
fi
[[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "не удалось определить IP сервера"

if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
  step "$AWG_IFACE.conf уже существует — генерацию пропускаю (идемпотентный запуск)"
  CONF_PORT="$(awk -F'=' '/^ListenPort/{gsub(/[ \t]/,"",$2); print $2; exit}' "$AWG_DIR/$AWG_IFACE.conf")"
  if ! [[ "$CONF_PORT" =~ ^[0-9]+$ ]]; then
    die "не удалось прочитать ListenPort из $AWG_DIR/$AWG_IFACE.conf"
  fi
  if [ -n "$AWG_PORT_ENV" ] && [ "$AWG_PORT_ENV" != "$CONF_PORT" ]; then
    step "ВНИМАНИЕ: AWG_PORT=${AWG_PORT_ENV} из окружения игнорируется — используется порт ${CONF_PORT} из существующего конфига"
  fi
  AWG_PORT="$CONF_PORT"
  if [ ! -f "$AWG_DIR/client1.conf" ]; then
    step "ВНИМАНИЕ: client1.conf отсутствует — клиентские ключи не восстановить, добавьте peer вручную (см. README)"
  fi
else
  umask 077
  SRV_PRIV="$(awg genkey)"
  SRV_PUB="$(printf '%s\n' "$SRV_PRIV" | awg pubkey)"
  CLI_PRIV="$(awg genkey)"
  CLI_PUB="$(printf '%s\n' "$CLI_PRIV" | awg pubkey)"

  # Параметры обфускации AmneziaWG (проверено на tools v3.1: совместимы с AWG 1.x–3.x)
  JC=$((3 + RANDOM % 6))                 # 3..8 junk-пакетов
  JMIN=$((20 + RANDOM % 30))             # 20..49
  JMAX=$((JMIN + 30 + RANDOM % 40))      # JMIN+30..JMIN+69 (< 1280)
  S1=$((15 + RANDOM % 100))              # 15..114
  S2=$((S1 + 60 + RANDOM % 40))          # S1+60..S1+99 (разница > 56)
  HVALS=()
  while [ "${#HVALS[@]}" -lt 4 ]; do
    v=$(( $(rand_u32) % 2147483643 + 5 ))
    dup=0
    for h in "${HVALS[@]}"; do
      if [ "$h" = "$v" ]; then dup=1; fi
    done
    if [ "$dup" -eq 0 ]; then HVALS+=("$v"); fi
  done
  H1="${HVALS[0]}"; H2="${HVALS[1]}"; H3="${HVALS[2]}"; H4="${HVALS[3]}"

  cat > "$AWG_DIR/$AWG_IFACE.conf" <<EOF
[Interface]
PrivateKey = ${SRV_PRIV}
Address = ${AWG_SRV_IP}/24
ListenPort = ${AWG_PORT}
MTU = ${AWG_MTU}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
PostUp = iptables -w -t nat -A POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -A FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -A FORWARD -i ${WAN_IFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${AWG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; iptables -w -D FORWARD -i ${WAN_IFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT

[Peer]
# client1
PublicKey = ${CLI_PUB}
AllowedIPs = ${AWG_CLI_IP}/32
EOF

  cat > "$AWG_DIR/client1.conf" <<EOF
[Interface]
PrivateKey = ${CLI_PRIV}
Address = ${AWG_CLI_IP}/32
DNS = ${AWG_DNS}
MTU = ${AWG_MTU}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${PUBLIC_IP}:${AWG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
  chmod 600 "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/client1.conf"
fi

printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-awg-forward.conf
sysctl -q -p /etc/sysctl.d/99-awg-forward.conf

systemctl enable "awg-quick@${AWG_IFACE}" >/dev/null
if ! systemctl restart "awg-quick@${AWG_IFACE}"; then
  journalctl -u "awg-quick@${AWG_IFACE}" -n 25 --no-pager || true
  die "awg-quick@${AWG_IFACE} не запустился (journal — выше)"
fi
sleep 1
awg show "$AWG_IFACE" >/dev/null || die "интерфейс ${AWG_IFACE} не поднялся"

# runtime-верификация туннеля: мало "сервис active" — проверяем факты
ip -4 addr show "$AWG_IFACE" | grep -q "$AWG_SRV_IP" \
  || die "на ${AWG_IFACE} нет адреса ${AWG_SRV_IP}"
[ -n "$(ss -Hlnu "sport = :${AWG_PORT}")" ] \
  || die "amneziawg не слушает UDP ${AWG_PORT}"
[ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] \
  || die "net.ipv4.ip_forward не включился"
iptables -w -t nat -C POSTROUTING -s "$AWG_SUBNET" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null \
  || die "NAT-правило MASQUERADE не применилось (PostUp)"
step "туннель проверен: адрес ${AWG_SRV_IP}, UDP ${AWG_PORT}, ip_forward=1, NAT — на месте"

#--- 6. панель 3x-ui -------------------------------------------------------------
step "Панель 3x-ui (неинтерактивная установка)"
umask 022   # дальше ставится панель со своими правами; 077 был только для ключей
if [ -z "$PANEL_PORT" ]; then
  PANEL_PORT="$(free_port tcp)" || die "не найден свободный TCP-порт"
fi
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
  die "PANEL_PORT некорректен: $PANEL_PORT"
fi
: "${PANEL_USER:=$(rand_hex 5)}"
: "${PANEL_PASS:=$(rand_hex 16)}"
: "${PANEL_PATH:=$(rand_hex 6)}"
for v in "$PANEL_USER" "$PANEL_PASS" "$PANEL_PATH"; do
  if ! [[ "$v" =~ ^[A-Za-z0-9_-]+$ ]]; then
    die "PANEL_USER/PANEL_PASS/PANEL_PATH: допустимы только латинские буквы, цифры, '_' и '-' (получено: '$v')"
  fi
done

# пропускаем только если есть И бинарник, И юнит: частичная установка чинится
# повторным прогоном официального install.sh (он поддерживает repair/upgrade)
if [ -x /usr/local/x-ui/x-ui ] && [ -f /etc/systemd/system/x-ui.service ]; then
  step "3x-ui уже установлена — пропускаю установку"
else
  TMP_DIR="$(mktemp -d)"
  curl -fsSL "$XUI_INSTALL_URL" -o "$TMP_DIR/install-3xui.sh"
  wait_for_apt_lock || die "apt/dpkg занят более 5 минут — повторите позже"
  XUI_NONINTERACTIVE=1 \
  XUI_PANEL_PORT="$PANEL_PORT" \
  XUI_USERNAME="$PANEL_USER" \
  XUI_PASSWORD="$PANEL_PASS" \
  XUI_WEB_BASE_PATH="$PANEL_PATH" \
  XUI_SSL_MODE=none \
  XUI_DB_TYPE=sqlite \
    bash "$TMP_DIR/install-3xui.sh"
fi
if ! systemctl is-active --quiet x-ui; then
  journalctl -u x-ui -n 25 --no-pager || true
  die "сервис x-ui не активен (journal — выше)"
fi

# фактические креды из файла установки (работает и для свежей, и для существующей панели)
if [ -r /etc/x-ui/install-result.env ]; then
  # shellcheck disable=SC1091
  . /etc/x-ui/install-result.env
  PANEL_USER="${XUI_USERNAME:-$PANEL_USER}"
  PANEL_PASS="${XUI_PASSWORD:-$PANEL_PASS}"
  PANEL_PORT="${XUI_PANEL_PORT:-$PANEL_PORT}"
  PANEL_PATH="${XUI_WEB_BASE_PATH:-$PANEL_PATH}"
  PANEL_API_TOKEN="${XUI_API_TOKEN:-}"
else
  step "ВНИМАНИЕ: /etc/x-ui/install-result.env не найден — ниже показаны сгенерированные креды; фактические смотрите: x-ui settings"
fi

PANEL_CODE="$(panel_http_code)"
case "$PANEL_CODE" in
  200 | 301 | 302 | 307 | 308) ;;
  *) sleep 3; PANEL_CODE="$(panel_http_code)" ;;   # панель могла ещё стартовать
esac
case "$PANEL_CODE" in
  200 | 301 | 302 | 307 | 308) step "панель отвечает локально: HTTP ${PANEL_CODE}" ;;
  *) step "ВНИМАНИЕ: панель ответила кодом '${PANEL_CODE}' — проверьте: journalctl -u x-ui" ;;
esac

#--- 7. firewall -----------------------------------------------------------------
step "Firewall"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "${AWG_PORT}/udp" >/dev/null
  ufw allow "${PANEL_PORT}/tcp" >/dev/null
  step "ufw активен: открыты ${AWG_PORT}/udp (AmneziaWG) и ${PANEL_PORT}/tcp (панель)"
else
  step "ufw не активен — правила не меняю. Откройте порты в firewall облачного провайдера."
fi

#--- итог -------------------------------------------------------------------------
step "Итоговая верификация"
systemctl is-active "awg-quick@${AWG_IFACE}" x-ui
AWG_VER="$(awg --version 2>/dev/null | head -n1 || true)"
XUI_VER="$(/usr/local/x-ui/x-ui -v 2>/dev/null | head -n1 || true)"
DKMS_LINE="$(dkms status 2>/dev/null | grep amneziawg | head -n1 || true)"
F2B_STATUS="$(systemctl is-active fail2ban 2>/dev/null || true)"

if [ -f "$AWG_DIR/client1.conf" ]; then
  qrencode -o "$AWG_DIR/client1.png" -s 6 -m 2 < "$AWG_DIR/client1.conf" || true
fi

umask 077
cat > "$CRED_FILE" <<EOF
# awg-3xui-installer — $(date '+%F %T')
PANEL_URL=http://${PUBLIC_IP}:${PANEL_PORT}/${PANEL_PATH}
PANEL_USER=${PANEL_USER}
PANEL_PASS=${PANEL_PASS}
PANEL_PATH=${PANEL_PATH}
PANEL_API_TOKEN=${PANEL_API_TOKEN}
AWG_ENDPOINT=${PUBLIC_IP}:${AWG_PORT}/udp
AWG_CLIENT_CONFIG=${AWG_DIR}/client1.conf
AWG_CLIENT_QR=${AWG_DIR}/client1.png
EOF
chmod 600 "$CRED_FILE"

set +x
printf '\n'
printf '%s\n' '============================================================'
printf '  УСТАНОВКА ЗАВЕРШЕНА\n'
printf '%s\n' '============================================================'
printf '  AmneziaWG (модуль ядра): %s\n' "${AWG_VER:-unknown}"
printf '  DKMS:                    %s\n' "${DKMS_LINE:-unknown}"
printf '  3x-ui:                   %s\n' "${XUI_VER:-unknown}"
printf '  fail2ban (IP Limit):     %s\n' "${F2B_STATUS:-unknown}"
printf '%s\n' '------------------------------------------------------------'
printf '  Панель 3x-ui (HTTP, без SSL):\n'
printf '    URL:    http://%s:%s/%s\n' "$PUBLIC_IP" "$PANEL_PORT" "$PANEL_PATH"
printf '    Логин:  %s\n' "$PANEL_USER"
printf '    Пароль: %s\n' "$PANEL_PASS"
printf '%s\n' '------------------------------------------------------------'
printf '  AmneziaWG сервер: %s:%s/udp (интерфейс %s)\n' "$PUBLIC_IP" "$AWG_PORT" "$AWG_IFACE"
printf '  Клиентский конфиг: %s/client1.conf\n' "$AWG_DIR"
printf '  QR-код (PNG):      %s/client1.png\n' "$AWG_DIR"
printf '%s\n' '------------------------------------------------------------'
printf '  Все креды:  %s (chmod 600)\n' "$CRED_FILE"
printf '  Логи:       %s\n' "$LOG_FILE"
printf '              %s\n' "$DBG_FILE"
printf '%s\n' '============================================================'
printf '  ВАЖНО:\n'
printf '  * Панель работает по HTTP. Для безопасного доступа используйте\n'
printf '    SSH-туннель: ssh -L 8443:127.0.0.1:%s root@%s\n' "$PANEL_PORT" "$PUBLIC_IP"
printf '    затем откройте http://127.0.0.1:8443/%s\n' "$PANEL_PATH"
printf '    SSL можно настроить позже командой: x-ui\n'
printf '  * Порты %s/udp и %s/tcp должны быть открыты в firewall\n' "$AWG_PORT" "$PANEL_PORT"
printf '    облачного провайдера (security group).\n'
printf '%s\n' '============================================================'
if [ -f "$AWG_DIR/client1.conf" ]; then
  printf '\n  QR-код клиентского конфига (сканируйте в приложении Amnezia):\n\n'
  qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
fi
sleep 1   # дать tee дописать лог