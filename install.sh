#!/usr/bin/env bash
#===============================================================================
#  awg-3xui-installer — автономный установщик для Ubuntu 24.04 LTS (noble)
#
#  Последовательность (без интерактивных вопросов):
#    1. Предпроверка: root, Ubuntu 24.04, systemd, Secure Boot, доступ к GitHub
#    2. Зависимости + заголовки текущего ядра
#    3. AmneziaWG: НАТИВНЫЙ модуль ядра amneziawg (DKMS из ppa:amnezia/ppa)
#       + amneziawg-tools (awg / awg-quick)
#    4. WireGuard: wireguard-tools (wg / wg-quick) — модуль уже в ядре Ubuntu
#    5. Рабочий туннель: awg0 + NAT + клиентский конфиг + QR-код
#    6. Панель 3x-ui (неинтерактивно: случайные порт/логин/пароль/путь)
#    7. Firewall (только если ufw уже активен) + верификация + итог с кредами
#
#  Запуск:
#    curl -fsSL https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main/install.sh | sudo bash
#
#  Переопределение через окружение:
#    AWG_PORT, PANEL_PORT, PANEL_USER, PANEL_PASS, PANEL_PATH
#    пример: sudo AWG_PORT=51820 PANEL_PORT=8443 bash install.sh
#
#  Логи:       /var/log/awg-3xui-install.log
#              /var/log/awg-3xui-install.debug.log  (трассировка каждой команды)
#  Результат:  /root/awg-3xui-credentials.txt (0600)
#===============================================================================
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
PANEL_PORT="${PANEL_PORT:-}"        # пусто -> случайный свободный TCP 20000-59999
PANEL_USER="${PANEL_USER:-}"        # пусто -> случайный
PANEL_PASS="${PANEL_PASS:-}"        # пусто -> случайный
PANEL_PATH="${PANEL_PATH:-}"        # webBasePath панели, без слэшей
CRED_FILE="/root/awg-3xui-credentials.txt"
LOG_FILE="/var/log/awg-3xui-install.log"
DBG_FILE="/var/log/awg-3xui-install.debug.log"
XUI_INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh"
TMP_DIR=""

#--- helpers -------------------------------------------------------------------
step() { printf '\n==> [%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { printf '\nОШИБКА: %s\nПодробности: %s и %s\n' "$*" "$LOG_FILE" "$DBG_FILE" >&2; exit 1; }
rand_hex() { openssl rand -hex "${1:-8}"; }
rand_u32() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }

free_port() { # $1 = udp|tcp; печатает свободный порт, 60 попыток
  local proto="$1" p
  for _ in $(seq 1 60); do
    p=$((20000 + RANDOM % 40000))
    if [ -z "$(ss -Hln"${proto}" "sport = :${p}")" ]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT
trap 'die "сбой на строке ${LINENO} (код $?)"' ERR

#--- 1. предпроверка -----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите от root:  curl -fsSL <url>/install.sh | sudo bash" >&2
  exit 1
fi

mkdir -p /var/log
touch "$LOG_FILE" "$DBG_FILE"
chmod 600 "$LOG_FILE" "$DBG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1
exec 5>>"$DBG_FILE"
export BASH_XTRACEFD=5
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

WAN_IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
[ -n "$WAN_IFACE" ] || die "не найден интерфейс с default-маршрутом"

curl -fsSI --max-time 15 -o /dev/null "$XUI_INSTALL_URL" \
  || die "нет доступа к GitHub (raw.githubusercontent.com) — установщик не сможет скачать компоненты"

#--- 2. зависимости ------------------------------------------------------------
step "Установка зависимостей и заголовков ядра $(uname -r)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

apt-get update
apt-get install "${APT[@]}" ca-certificates curl gnupg2 openssl \
  software-properties-common python3-launchpadlib
add-apt-repository -y universe
apt-get update
apt-get install "${APT[@]}" \
  dkms build-essential "linux-headers-$(uname -r)" mokutil \
  qrencode wireguard-tools iptables iproute2

if mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'; then
  die "Secure Boot включён: неподписанный DKMS-модуль amneziawg не загрузится. Отключите Secure Boot в UEFI и запустите установщик снова."
fi

#--- 3. AmneziaWG: модуль ядра + инструменты -----------------------------------
step "AmneziaWG: нативный модуль ядра (DKMS) + awg-tools из ppa:amnezia/ppa"
if dpkg -s amneziawg >/dev/null 2>&1; then
  step "пакет amneziawg уже установлен — пропускаю"
else
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
if ! [[ "$AWG_PORT" =~ ^[0-9]+$ ]] || [ "$AWG_PORT" -gt 65535 ]; then
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
  AWG_PORT="$(awk -F'= ' '/^ListenPort/{print $2; exit}' "$AWG_DIR/$AWG_IFACE.conf")"
else
  umask 077
  SRV_PRIV="$(awg genkey)"
  SRV_PUB="$(printf '%s\n' "$SRV_PRIV" | awg pubkey)"
  CLI_PRIV="$(awg genkey)"
  CLI_PUB="$(printf '%s\n' "$CLI_PRIV" | awg pubkey)"

  # Параметры обфускации AmneziaWG (совместимы с клиентами AWG 1.x/2.x)
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
systemctl restart "awg-quick@${AWG_IFACE}"
sleep 1
awg show "$AWG_IFACE" >/dev/null || die "интерфейс ${AWG_IFACE} не поднялся (systemctl status awg-quick@${AWG_IFACE})"

#--- 6. панель 3x-ui -------------------------------------------------------------
step "Панель 3x-ui (неинтерактивная установка)"
if [ -z "$PANEL_PORT" ]; then
  PANEL_PORT="$(free_port tcp)" || die "не найден свободный TCP-порт"
fi
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -gt 65535 ]; then
  die "PANEL_PORT некорректен: $PANEL_PORT"
fi
: "${PANEL_USER:=$(rand_hex 5)}"
: "${PANEL_PASS:=$(rand_hex 16)}"
: "${PANEL_PATH:=$(rand_hex 6)}"
if [[ "$PANEL_PATH" == */* ]]; then
  die "PANEL_PATH не должен содержать слэшей: $PANEL_PATH"
fi

if [ -x /usr/local/x-ui/x-ui ]; then
  step "3x-ui уже установлена — пропускаю установку"
  if [ -r /etc/x-ui/install-result.env ]; then
    # shellcheck disable=SC1091
    . /etc/x-ui/install-result.env
    PANEL_USER="${XUI_USERNAME:-$PANEL_USER}"
    PANEL_PASS="${XUI_PASSWORD:-$PANEL_PASS}"
    PANEL_PORT="${XUI_PANEL_PORT:-$PANEL_PORT}"
    PANEL_PATH="${XUI_WEB_BASE_PATH:-$PANEL_PATH}"
  fi
else
  TMP_DIR="$(mktemp -d)"
  curl -fsSL "$XUI_INSTALL_URL" -o "$TMP_DIR/install-3xui.sh"
  XUI_NONINTERACTIVE=1 \
  XUI_PANEL_PORT="$PANEL_PORT" \
  XUI_USERNAME="$PANEL_USER" \
  XUI_PASSWORD="$PANEL_PASS" \
  XUI_WEB_BASE_PATH="$PANEL_PATH" \
  XUI_SSL_MODE=none \
  XUI_DB_TYPE=sqlite \
    bash "$TMP_DIR/install-3xui.sh"
fi
systemctl is-active --quiet x-ui || die "сервис x-ui не активен (journalctl -u x-ui)"

PANEL_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PANEL_PORT}/${PANEL_PATH}/" || true)"
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
AWG_ENDPOINT=${PUBLIC_IP}:${AWG_PORT}/udp
AWG_CLIENT_CONFIG=${AWG_DIR}/client1.conf
AWG_CLIENT_QR=${AWG_DIR}/client1.png
EOF
chmod 600 "$CRED_FILE"

set +x
printf '\n'
printf '============================================================\n'
printf '  УСТАНОВКА ЗАВЕРШЕНА\n'
printf '============================================================\n'
printf '  AmneziaWG (модуль ядра): %s\n' "${AWG_VER:-unknown}"
printf '  DKMS:                    %s\n' "${DKMS_LINE:-unknown}"
printf '  3x-ui:                   %s\n' "${XUI_VER:-unknown}"
printf '------------------------------------------------------------\n'
printf '  Панель 3x-ui (HTTP, без SSL):\n'
printf '    URL:    http://%s:%s/%s\n' "$PUBLIC_IP" "$PANEL_PORT" "$PANEL_PATH"
printf '    Логин:  %s\n' "$PANEL_USER"
printf '    Пароль: %s\n' "$PANEL_PASS"
printf '------------------------------------------------------------\n'
printf '  AmneziaWG сервер: %s:%s/udp (интерфейс %s)\n' "$PUBLIC_IP" "$AWG_PORT" "$AWG_IFACE"
printf '  Клиентский конфиг: %s/client1.conf\n' "$AWG_DIR"
printf '  QR-код (PNG):      %s/client1.png\n' "$AWG_DIR"
printf '------------------------------------------------------------\n'
printf '  Все креды:  %s (chmod 600)\n' "$CRED_FILE"
printf '  Логи:       %s\n' "$LOG_FILE"
printf '              %s\n' "$DBG_FILE"
printf '============================================================\n'
printf '  ВАЖНО:\n'
printf '  * Панель работает по HTTP. Для безопасного доступа используйте\n'
printf '    SSH-туннель: ssh -L 8443:127.0.0.1:%s root@%s\n' "$PANEL_PORT" "$PUBLIC_IP"
printf '    затем откройте http://127.0.0.1:8443/%s\n' "$PANEL_PATH"
printf '    SSL можно настроить позже командой: x-ui\n'
printf '  * Порты %s/udp и %s/tcp должны быть открыты в firewall\n' "$AWG_PORT" "$PANEL_PORT"
printf '    облачного провайдера (security group).\n'
printf '============================================================\n'
if [ -f "$AWG_DIR/client1.conf" ]; then
  printf '\n  QR-код клиентского конфига (сканируйте в приложении Amnezia):\n\n'
  qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
fi
sleep 1   # дать tee дописать лог