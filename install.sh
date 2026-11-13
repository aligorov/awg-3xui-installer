#!/usr/bin/env bash
#===============================================================================
#  awg-3xui-installer — установщик и менеджер для Ubuntu 24.04 LTS (noble)
#
#  Компоненты: AmneziaWG (НАТИВНЫЙ модуль ядра, DKMS из ppa:amnezia/ppa),
#  WireGuard tools (модуль уже в ядре Ubuntu), панель 3x-ui.
#  Туннель awg0 — полный профиль AmneziaWG 3.1: шифрование заголовков
#  (HeaderProtectionKey), CPS-пакет I1, паддинги S1-S4, ContentPaddingAddition.
#
#  Запуск без аргументов:
#    в терминале (TTY)   -> интерактивное меню управления
#    curl ... | sudo bash -> автономная установка без вопросов (как раньше)
#
#  Команды (sudo bash install.sh <команда>):
#    install | uninstall | reinstall | migrate | status
#    add-client [name] | remove-client <name|pubkey> | list-clients
#    creds | backup | restore <file.tar.gz> | update | restart | logs | help
#
#  Установка (последовательность без интерактивных вопросов):
#    1. Предпроверка: root, bash, Ubuntu 24.04, не контейнер, архитектура,
#       systemd, Secure Boot, место на диске (>=1.5 ГБ), сеть до GitHub и PPA,
#       защита от параллельного запуска
#    2. Зависимости + заголовки текущего ядра + fail2ban/nftables (для 3x-ui)
#    3. AmneziaWG: модуль ядра amneziawg (DKMS) + amneziawg-tools (awg/awg-quick)
#    4. WireGuard: wireguard-tools (wg / wg-quick)
#    5. Туннель awg0 (профиль 3.1) + NAT + клиентский конфиг + QR-код
#       + runtime-проверка: адрес, UDP-порт, ip_forward, NAT-правило
#       Конфиги профиля 1.x мигрируются на 3.1 с бэкапом и перевыпуском ключей
#    6. Панель 3x-ui (неинтерактивно: случайные порт/логин/пароль/путь)
#    7. Firewall (только если ufw уже активен) + верификация + итог с кредами
#
#  Переопределение через окружение (буквы/цифры/_/-):
#    AWG_PORT, PANEL_PORT, PANEL_USER, PANEL_PASS, PANEL_PATH
#    пример: sudo AWG_PORT=51820 PANEL_PORT=8443 bash install.sh install
#
#  Логи:       /var/log/awg-3xui-install.log
#              /var/log/awg-3xui-install.debug.log  (трассировка, без ключей)
#  Результат:  /root/awg-3xui-credentials.txt (0600)
#  Бэкапы:     /root/awg-3xui-backups/ (0700, файлы 0600)
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
PANEL_PORT_ENV="${PANEL_PORT:-}"    # исходные значения из окружения: после uninstall
PANEL_USER_ENV="${PANEL_USER:-}"    # следующая установка снова случайная, если
PANEL_PASS_ENV="${PANEL_PASS:-}"    # пользователь не задал параметры явно
PANEL_PATH_ENV="${PANEL_PATH:-}"
PANEL_API_TOKEN=""
CRED_FILE="/root/awg-3xui-credentials.txt"
BACKUP_DIR="/root/awg-3xui-backups"
LOG_FILE="/var/log/awg-3xui-install.log"
DBG_FILE="/var/log/awg-3xui-install.debug.log"
XUI_INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh"
PPA_INRELEASE_URL="https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/InRelease"
TMP_DIR=""
IS_TTY=0                            # определяется в dispatch ДО редиректа в tee

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300)

#--- helpers -------------------------------------------------------------------
step() { printf '\n==> [%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { printf '\nОШИБКА: %s\nПодробности: %s и %s\n' "$*" "$LOG_FILE" "$DBG_FILE" >&2; exit 1; }
warn() { step "ВНИМАНИЕ: $*"; }
rand_hex() { openssl rand -hex "${1:-8}"; }
rand_u32() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }
rand_range() { # $1=min $2=max -> случайное целое [min,max]
  printf '%s' "$(( $(rand_u32) % ($2 - $1 + 1) + $1 ))"
}

conf_get() { # $1=ключ $2=файл -> значение первого совпадения (без пробелов вокруг =)
  sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$2" | head -n1
}

detect_public_ip() { # печатает IPv4; предупреждения -> stderr (stdout занят значением)
  local ip
  ip="$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  fi
  if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    printf 'ВНИМАНИЕ: внешний IP не определён через echo-сервисы, использую адрес интерфейса: %s\n' "$ip" >&2
  fi
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$ip"
}

require_awg31() { # клиентские операции возможны только на установленном профиле 3.1
  [ -f "$AWG_DIR/$AWG_IFACE.conf" ] || die "туннель не установлен — выполните: bash install.sh install"
  grep -q '^HeaderProtectionKey[[:space:]]*=' "$AWG_DIR/$AWG_IFACE.conf" \
    || die "конфиг профиля 1.x — сначала выполните: bash install.sh migrate"
}

confirm_yes() { # $1=вопрос; код 0 = подтверждено
  local a
  read -r -p "$1 [y/N]: " a || return 1
  case "$a" in y|Y|yes|YES|да|Да|ДА) return 0 ;; *) return 1 ;; esac
}

cps_i1() { # маскирующий пакет I1 в форме DNS-ответа (cdns.icloud.com).
  # Теги только переносимые (<b>/<r>/<rc>): их понимают и модуль ядра, и
  # amneziawg-go. Форма DNS-ответа проверена в поле: чистая случайность
  # (<r N>) ломала рукопожатие на мобильных сетях, DNS-образный пакет — нет.
  local label answers hex qtail ttl o1 o2 o3 o4 i out
  label=$(rand_range 20 62)          # метка имени; предел DNS — 63 байта
  answers=$(rand_range 1 2)
  # Заголовок: флаги 0x8580 (как в штатном спецпакете вендора), 1 вопрос,
  # answers ответов. Последний байт — длина метки.
  hex=$(printf '85800001%04x00000000%02x' "$answers" "$label")
  qtail='0463646e730669636c6f756403636f6d0000010001'   # cdns.icloud.com A IN
  case $(rand_range 1 4) in          # TTL один на пакет — как у реальных резолверов
    1) ttl='0000003c' ;; 2) ttl='0000012c' ;; 3) ttl='00000384' ;; *) ttl='00000e10' ;;
  esac
  for ((i = 0; i < answers; i++)); do
    o1=$(rand_range 1 221)           # 10 и 127 перекладываем в 222/223 без цикла
    case "$o1" in 10) o1=222 ;; 127) o1=223 ;; esac
    o2=$(rand_range 0 255); o3=$(rand_range 0 255); o4=$(rand_range 1 254)
    qtail="${qtail}$(printf 'c00c00010001%s0004%02x%02x%02x%02x' \
      "$ttl" "$o1" "$o2" "$o3" "$o4")"
  done
  out=$(printf '<r 2><b 0x%s><rc %s><b 0x%s>' "$hex" "$label" "$qtail")
  # самопроверка: битый I1 уехал бы во все конфиги и упал только при поднятии
  [[ "$out" =~ ^\<r\ 2\>\<b\ 0x[0-9a-f]{22}\>\<rc\ [0-9]{1,2}\>\<b\ 0x([0-9a-f]{2})+\>$ ]] || return 1
  printf '%s\n' "$out"
}

s4_collides() { # $1..$4 = S1 S2 S3 S4; код 0 = есть вредное совпадение длин
  # Размеры сообщений: init 148, response 92, cookie 64; данные = S4+32+16k.
  local p
  p=$(( $1 - $4 + 116 )); if [ "$p" -ge 32 ] && [ $((p % 16)) -eq 0 ] && [ "$p" -ne 128 ]; then return 0; fi
  p=$(( $2 - $4 + 60 ));  if [ "$p" -ge 32 ] && [ $((p % 16)) -eq 0 ]; then return 0; fi
  p=$(( $3 - $4 + 32 ));  if [ "$p" -ge 48 ] && [ $((p % 16)) -eq 0 ]; then return 0; fi
  return 1
}

probe_awg31() { # модуль ядра принимает профиль 3.1? Временный интерфейс, не awg0.
  local ifn="" kf rc i
  kf="$(mktemp)" || return 1
  chmod 600 "$kf"
  awg genkey > "$kf" || { rm -f "$kf"; return 1; }   # ключ не попадает в argv/лог
  for i in 1 2 3; do
    ifn="awgp$$x$i"
    if ip link show "$ifn" >/dev/null 2>&1; then ifn=""; continue; fi
    if timeout -k 1 10 ip link add "$ifn" type amneziawg >/dev/null 2>&1; then
      break
    fi
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

#--- установка -----------------------------------------------------------------
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

  #--- зависимости -------------------------------------------------------------
  step "Установка зависимостей и заголовков ядра $(uname -r)"
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
    warn "pyasynchat не установлен (нет доступа к PyPI?) — IP Limit может не работать"
  fi
  systemctl is-active --quiet fail2ban \
    || warn "fail2ban не активен — IP Limit в 3x-ui может не работать"

  #--- AmneziaWG: модуль ядра + инструменты ------------------------------------
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

  step "Проверка поддержки профиля 3.1 модулем ядра (HeaderProtectionKey)"
  probe_awg31 || die "модуль amneziawg не принимает профиль 3.1. Обновите пакеты: apt-get update && apt-get install --only-upgrade amneziawg-dkms amneziawg-tools — и запустите установщик снова"

  #--- WireGuard (модуль в ядре Ubuntu) -----------------------------------------
  step "WireGuard: проверка нативной поддержки ядром"
  command -v wg >/dev/null 2>&1 || die "wireguard-tools не установлены"
  modinfo wireguard >/dev/null 2>&1 || die "модуль wireguard недоступен в ядре $(uname -r)"
  wg --version

  #--- туннель awg0 + клиент -----------------------------------------------------
  step "Настройка туннеля AmneziaWG (${AWG_IFACE}, профиль 3.1)"
  install -d -m 700 "$AWG_DIR"

  if [ -z "$AWG_PORT" ]; then
    AWG_PORT="$(free_port udp)" || die "не найден свободный UDP-порт"
  fi
  if ! [[ "$AWG_PORT" =~ ^[0-9]+$ ]] || [ "$AWG_PORT" -lt 1 ] || [ "$AWG_PORT" -gt 65535 ]; then
    die "AWG_PORT некорректен: $AWG_PORT"
  fi

  PUBLIC_IP="$(detect_public_ip)" || die "не удалось определить IP сервера"

  REGEN=1
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    if grep -q '^HeaderProtectionKey[[:space:]]*=' "$AWG_DIR/$AWG_IFACE.conf"; then
      REGEN=0
      step "$AWG_IFACE.conf уже существует (профиль 3.1) — генерацию пропускаю (идемпотентный запуск)"
      CONF_PORT="$(awk -F'=' '/^ListenPort/{gsub(/[ \t]/,"",$2); print $2; exit}' "$AWG_DIR/$AWG_IFACE.conf")"
      if ! [[ "$CONF_PORT" =~ ^[0-9]+$ ]]; then
        die "не удалось прочитать ListenPort из $AWG_DIR/$AWG_IFACE.conf"
      fi
      if [ -n "$AWG_PORT_ENV" ] && [ "$AWG_PORT_ENV" != "$CONF_PORT" ]; then
        warn "AWG_PORT=${AWG_PORT_ENV} из окружения игнорируется — используется порт ${CONF_PORT} из существующего конфига"
      fi
      AWG_PORT="$CONF_PORT"
      if [ ! -f "$AWG_DIR/client1.conf" ]; then
        warn "client1.conf отсутствует — клиентские ключи не восстановить, добавьте peer вручную (см. README)"
      fi
    else
      step "МИГРАЦИЯ: $AWG_IFACE.conf профиля 1.x -> 3.1 (шифрование заголовков). Старые клиентские конфиги перестанут работать — нужен новый client1.conf/QR"
      TS="$(date '+%Y%m%d-%H%M%S')"
      cp -a "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/$AWG_IFACE.conf.bak-1x-$TS"
      if [ -f "$AWG_DIR/client1.conf" ]; then
        cp -a "$AWG_DIR/client1.conf" "$AWG_DIR/client1.conf.bak-1x-$TS"
      fi
      step "бэкапы старых конфигов: $AWG_DIR/*.bak-1x-$TS"
      CONF_PORT="$(awk -F'=' '/^ListenPort/{gsub(/[ \t]/,"",$2); print $2; exit}' "$AWG_DIR/$AWG_IFACE.conf")"
      if [[ "$CONF_PORT" =~ ^[0-9]+$ ]]; then
        if [ -n "$AWG_PORT_ENV" ] && [ "$AWG_PORT_ENV" != "$CONF_PORT" ]; then
          warn "AWG_PORT=${AWG_PORT_ENV} из окружения игнорируется — сохраняю порт ${CONF_PORT}, чтобы не менять firewall"
        fi
        AWG_PORT="$CONF_PORT"
      fi
    fi
  fi

  if [ "$REGEN" -eq 1 ]; then
    umask 077
    # xtrace печатает аргументы и heredoc'ы — на время генерации ключей глушим,
    # чтобы приватные ключи не попали в debug-лог.
    set +x
    SRV_PRIV="$(awg genkey)"
    SRV_PUB="$(printf '%s\n' "$SRV_PRIV" | awg pubkey)"
    CLI_PRIV="$(awg genkey)"
    CLI_PUB="$(printf '%s\n' "$CLI_PRIV" | awg pubkey)"

    # Параметры профиля AmneziaWG 3.1: шифрование заголовков (HeaderProtectionKey),
    # CPS-пакет I1, паддинги S1-S4. Ограничения модуля ядра: S1+56 != S2,
    # S3 != S2+28, при ключе защиты S1-S4 >= 12 (первые 12 байт — nonce ChaCha20),
    # S4 без совпадений длин пакетов данных с рукопожатием.
    JC=$(rand_range 3 6)                   # 3..6 junk-пакетов
    JMIN=$(rand_range 40 89)
    JMAX=$((JMIN + $(rand_range 50 250)))  # ~90..339 (< 1280)
    S1=$(rand_range 15 150)
    S2=$(rand_range 15 150)
    while [ $((S1 + 56)) -eq "$S2" ]; do S2=$(rand_range 15 150); done
    S3=$(rand_range 12 55)
    while [ $((S2 + 28)) -eq "$S3" ]; do S3=$(rand_range 12 55); done
    S4_FREE=()
    for ((s4 = 12; s4 <= 27; s4++)); do
      if [ "$s4" -eq 16 ]; then continue; fi   # 16: длина данных кратна 16, как у vanilla WG
      s4_collides "$S1" "$S2" "$S3" "$s4" || S4_FREE+=("$s4")
    done
    [ "${#S4_FREE[@]}" -gt 0 ] || die "внутренняя ошибка: нет S4 без коллизий длин"
    S4="${S4_FREE[$(rand_range 0 $((${#S4_FREE[@]} - 1)))]}"
    H1=1; H2=2; H3=3; H4=4                 # при шифровании заголовков тип скрыт ключом
    I1="$(cps_i1)" || die "не удалось сгенерировать маскирующий пакет I1"
    HPK="$(awg genkey)"                    # один ключ на сервер и всех его клиентов
    [[ "$HPK" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || die "awg genkey вернул ключ неверного формата"
    CPA='32-128'                           # добавочный паддинг внутри шифрованной части

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
S3 = ${S3}
S4 = ${S4}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
I1 = ${I1}
HeaderProtectionKey = ${HPK}
ContentPaddingAddition = ${CPA}
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
S3 = ${S3}
S4 = ${S4}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
I1 = ${I1}
HeaderProtectionKey = ${HPK}
ContentPaddingAddition = ${CPA}

[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${PUBLIC_IP}:${AWG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    chmod 600 "$AWG_DIR/$AWG_IFACE.conf" "$AWG_DIR/client1.conf"
    set -x
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

  #--- панель 3x-ui ---------------------------------------------------------------
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
    warn "/etc/x-ui/install-result.env не найден — ниже показаны сгенерированные креды; фактические смотрите: x-ui settings"
  fi

  PANEL_CODE="$(panel_http_code)"
  case "$PANEL_CODE" in
    200 | 301 | 302 | 307 | 308) ;;
    *) sleep 3; PANEL_CODE="$(panel_http_code)" ;;   # панель могла ещё стартовать
  esac
  case "$PANEL_CODE" in
    200 | 301 | 302 | 307 | 308) step "панель отвечает локально: HTTP ${PANEL_CODE}" ;;
    *) warn "панель ответила кодом '${PANEL_CODE}' — проверьте: journalctl -u x-ui" ;;
  esac

  #--- firewall -------------------------------------------------------------------
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
AWG_PROFILE=3.1
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
  printf '  Профиль: AmneziaWG 3.1 (шифрование заголовков, I1, S1-S4)\n'
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
  printf '  * Профиль 3.1: клиентам нужно приложение Amnezia >= 5.0.1.5.\n'
  printf '    Конфиги профиля 1.x с этим сервером больше не работают.\n'
  printf '  * Управление: sudo bash install.sh (меню) или bash install.sh help\n'
  printf '%s\n' '============================================================'
  if [ -f "$AWG_DIR/client1.conf" ]; then
    printf '\n  QR-код клиентского конфига (сканируйте в приложении Amnezia):\n\n'
    qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
  fi
  sleep 1   # дать tee дописать лог
}

#--- полное удаление -------------------------------------------------------------
do_uninstall() {
  step "Полное удаление: AmneziaWG + 3x-ui (с предварительным бэкапом)"

  # порты читаем ДО удаления — они нужны для очистки правил ufw
  local awg_port="" panel_port=""
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    awg_port="$(conf_get ListenPort "$AWG_DIR/$AWG_IFACE.conf")"
  fi
  if [ -r /etc/x-ui/install-result.env ]; then
    panel_port="$(sed -n 's/^XUI_PANEL_PORT=//p' /etc/x-ui/install-result.env | head -n1 | tr -cd '0-9')"
  fi

  # 1. бэкап обязателен: x-ui uninstall удаляет /etc/x-ui вместе с БД (все inbound'ы)
  local ts tar="" members=()
  ts="$(date '+%Y%m%d-%H%M%S')"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  if [ -d "$AWG_DIR" ]; then members+=("etc/amnezia/amneziawg"); fi
  if [ -d /etc/x-ui ]; then members+=("etc/x-ui"); fi
  if [ -f "$CRED_FILE" ]; then members+=("${CRED_FILE#/}"); fi
  if [ "${#members[@]}" -gt 0 ]; then
    tar="$BACKUP_DIR/uninstall-$ts.tar.gz"
    tar -czf "$tar" -C / "${members[@]}" || die "не удалось создать бэкап $tar — удаление отменено"
    chmod 600 "$tar"
    step "бэкап перед удалением: $tar"
  else
    step "бэкап не нужен: конфигов и БД панели нет"
  fi

  # 2. туннель: stop выполняет PostDown (снимает iptables-правила)
  if systemctl cat "awg-quick@${AWG_IFACE}" >/dev/null 2>&1; then
    systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || warn "awg-quick@${AWG_IFACE} не остановился"
    systemctl disable "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  fi

  # 3. осиротевшие правила iptables (если PostDown не отработал при падении сервиса)
  local wan i
  wan="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  if [ -n "$wan" ] && command -v iptables >/dev/null 2>&1; then
    for i in 1 2 3 4 5; do
      iptables -w -t nat -C POSTROUTING -s "$AWG_SUBNET" -o "$wan" -j MASQUERADE 2>/dev/null || break
      iptables -w -t nat -D POSTROUTING -s "$AWG_SUBNET" -o "$wan" -j MASQUERADE 2>/dev/null || break
    done
    for i in 1 2 3 4 5; do
      iptables -w -C FORWARD -i "$AWG_IFACE" -o "$wan" -j ACCEPT 2>/dev/null || break
      iptables -w -D FORWARD -i "$AWG_IFACE" -o "$wan" -j ACCEPT 2>/dev/null || break
    done
    for i in 1 2 3 4 5; do
      iptables -w -C FORWARD -i "$wan" -o "$AWG_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break
      iptables -w -D FORWARD -i "$wan" -o "$AWG_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break
    done
  fi

  # 4. панель: официальный uninstall (confirm читает stdin -> echo y).
  #    Удаляет /etc/x-ui вместе с БД — поэтому бэкап выше обязателен.
  if [ -x /usr/bin/x-ui ]; then
    echo y | x-ui uninstall || warn "x-ui uninstall завершился с ошибкой — чищу остатки вручную"
  else
    step "x-ui не найден — пропускаю официальный uninstall"
  fi
  systemctl stop x-ui 2>/dev/null || true
  systemctl disable x-ui 2>/dev/null || true
  rm -rf /usr/local/x-ui /etc/x-ui || true
  rm -f /etc/systemd/system/x-ui.service /usr/bin/x-ui || true
  systemctl daemon-reload 2>/dev/null || true

  # 5. jail'ы IP Limit от 3x-ui (апстрим uninstall их не трогает)
  rm -f /etc/fail2ban/filter.d/3x-ipl.conf /etc/fail2ban/action.d/3x-ipl.conf \
    /etc/fail2ban/jail.d/3x-ipl.conf /etc/fail2ban/jail.d/3x-ipl-backend.conf
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    systemctl restart fail2ban || warn "fail2ban не перезапустился после удаления jail'ов"
  fi

  # 6. ufw: снимаем только свои правила (если ufw активен и порты известны)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    if [[ "$awg_port" =~ ^[0-9]+$ ]]; then
      echo y | ufw delete allow "${awg_port}/udp" >/dev/null 2>&1 || true
    fi
    if [[ "$panel_port" =~ ^[0-9]+$ ]]; then
      echo y | ufw delete allow "${panel_port}/tcp" >/dev/null 2>&1 || true
    fi
  fi

  # 7. пакеты AWG: purge сам снимает DKMS-модуль (prerm: dkms remove --all).
  #    fail2ban/wireguard-tools/dkms НЕ трогаем: они общие и защищают SSH.
  if dpkg-query -W -f='${Status}\n' amneziawg amneziawg-dkms amneziawg-tools 2>/dev/null | grep -q 'install ok installed'; then
    wait_for_apt_lock || warn "apt занят — purge может не удаться"
    apt-get purge "${APT[@]}" amneziawg amneziawg-dkms amneziawg-tools \
      || warn "purge пакетов AWG не удался — снимите вручную: apt-get purge amneziawg amneziawg-dkms amneziawg-tools"
  fi
  rmmod amneziawg 2>/dev/null || step "модуль amneziawg остался в памяти — исчезнет после перезагрузки"

  # 8. PPA
  if command -v add-apt-repository >/dev/null 2>&1; then
    add-apt-repository -y --remove ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update >/dev/null 2>&1 || true
  fi

  # 9. конфиги, sysctl-файл, креды (бэкап уже снят). Runtime net.ipv4.ip_forward
  #    сознательно не трогаем: его могли включить другие сервисы; после перезагрузки
  #    он вернётся к значению по умолчанию, т.к. наш sysctl-файл удалён.
  rm -rf "$AWG_DIR" || true
  rm -f /etc/sysctl.d/99-awg-forward.conf "$CRED_FILE" || true

  # следующая установка — с чистого листа: случайные порты/креды,
  # если пользователь не задал их окружением явно
  AWG_PORT="$AWG_PORT_ENV"
  PANEL_PORT="$PANEL_PORT_ENV"
  PANEL_USER="$PANEL_USER_ENV"
  PANEL_PASS="$PANEL_PASS_ENV"
  PANEL_PATH="$PANEL_PATH_ENV"

  step "Удаление завершено"
  printf '%s\n' '------------------------------------------------------------'
  printf '  Удалено: туннель awg0, конфиги AWG, 3x-ui (включая БД),\n'
  printf '           jail'"'"'ы IP Limit, пакеты amneziawg*, PPA, правила ufw.\n'
  printf '  Сохранено: fail2ban, wireguard-tools, dkms (общие компоненты),\n'
  printf '             логи установки, бэкап.\n'
  if [ -n "$tar" ]; then
    printf '  Бэкап: %s\n' "$tar"
    printf '  Восстановление: sudo bash install.sh install, затем restore %s\n' "$tar"
  fi
  printf '%s\n' '------------------------------------------------------------'
}

#--- переустановка ----------------------------------------------------------------
do_reinstall() {
  step "Переустановка: полное удаление, затем чистая установка"
  do_uninstall
  do_install
}

#--- миграция 1.x -> 3.1 ------------------------------------------------------------
do_migrate() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен — выполните install (он сразу создаст профиль 3.1)"
  if grep -q '^HeaderProtectionKey[[:space:]]*=' "$conf"; then
    step "Профиль уже 3.1 — миграция не нужна. Для проверки/починки: bash install.sh install"
    return 0
  fi
  step "Миграция 1.x -> 3.1 через установщик (бэкап старых конфигов будет создан)"
  do_install
}

#--- статус -------------------------------------------------------------------------
do_status() {
  step "Статус awg-3xui"
  local conf="$AWG_DIR/$AWG_IFACE.conf" u
  if [ -f "$conf" ]; then
    if grep -q '^HeaderProtectionKey[[:space:]]*=' "$conf"; then
      printf '  Профиль AWG: 3.1 (шифрование заголовков)\n'
    else
      printf '  Профиль AWG: 1.x — доступна миграция: bash install.sh migrate\n'
    fi
    printf '  ListenPort:  %s/udp\n' "$(conf_get ListenPort "$conf")"
    printf '  Клиентов:    %s\n' "$(grep -c '^PublicKey' "$conf" || true)"
  else
    printf '  Туннель: не установлен (%s нет)\n' "$conf"
  fi
  for u in "awg-quick@${AWG_IFACE}" x-ui fail2ban; do
    printf '  %-22s %s\n' "$u:" "$(systemctl is-active "$u" 2>/dev/null || true)"
  done
  if command -v awg >/dev/null 2>&1 && awg show "$AWG_IFACE" >/dev/null 2>&1; then
    printf '\n'
    awg show "$AWG_IFACE"
  fi
  if command -v dkms >/dev/null 2>&1; then
    dkms status 2>/dev/null | grep amneziawg | sed 's/^/  DKMS: /' || true
  fi
  if [ -x /usr/local/x-ui/x-ui ]; then
    printf '  3x-ui: %s\n' "$(/usr/local/x-ui/x-ui -v 2>/dev/null | head -n1 || true)"
  fi
  if [ -r /etc/x-ui/install-result.env ]; then
    printf '  Панель: http://127.0.0.1:%s/%s\n' \
      "$(sed -n 's/^XUI_PANEL_PORT=//p' /etc/x-ui/install-result.env | head -n1 | tr -cd '0-9')" \
      "$(sed -n 's/^XUI_WEB_BASE_PATH=//p' /etc/x-ui/install-result.env | head -n1)"
  fi
  if [ -f "$CRED_FILE" ]; then
    printf '  Креды: %s\n' "$CRED_FILE"
  fi
}

#--- клиенты ------------------------------------------------------------------------
peer_pub_by_name() { # $1=имя (комментарий '# name' в [Peer]) -> PublicKey
  awk -v want="$1" '
    /^\[/ { cname="" }
    /^#/ { cname=$0; sub(/^#[[:space:]]*/, "", cname); next }
    /^PublicKey[[:space:]]*=/ {
      if (cname == want) { v=$0; sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", v); print v; exit }
    }
  ' "$AWG_DIR/$AWG_IFACE.conf"
}

peer_name_by_pub() { # $1=PublicKey -> имя из комментария (может быть пустым)
  awk -v p="$1" '
    /^\[/ { cname="" }
    /^#/ { cname=$0; sub(/^#[[:space:]]*/, "", cname) }
    /^PublicKey[[:space:]]*=/ {
      v=$0; sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", v)
      if (v == p) { print cname; exit }
    }
  ' "$AWG_DIR/$AWG_IFACE.conf"
}

do_add_client() {
  local name="${1:-}"
  require_awg31
  if [ -z "$name" ]; then
    if [ "$IS_TTY" = 1 ]; then
      read -r -p "Имя нового клиента (латиница/цифры/_/-): " name || die "ввод прерван"
    else
      die "укажите имя: bash install.sh add-client <name>"
    fi
  fi
  [[ "$name" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "имя '$name': допустимы латинские буквы, цифры, '_' и '-', длина 1-32"
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -f "$AWG_DIR/$name.conf" ] || grep -q "^# ${name}$" "$conf"; then
    die "клиент '$name' уже существует"
  fi
  awg show "$AWG_IFACE" >/dev/null 2>&1 || die "интерфейс $AWG_IFACE не поднят — выполните: bash install.sh restart"

  # следующий свободный адрес 10.8.1.2..254 (по AllowedIPs всех [Peer])
  local used i ip=""
  used="$(awk -F'=' '/^AllowedIPs[[:space:]]*=/{print $2}' "$conf" | grep -oE '10\.8\.1\.[0-9]+' | sort -u || true)"
  for i in $(seq 2 254); do
    if ! printf '%s\n' "$used" | grep -qx "10.8.1.$i"; then
      ip="10.8.1.$i"
      break
    fi
  done
  [ -n "$ip" ] || die "в подсети 10.8.1.0/24 нет свободных адресов"

  # параметры серверного профиля переносим в клиентский конфиг: они должны совпадать.
  # xtrace печатает значения присваиваний — HeaderProtectionKey секретный,
  # поэтому всё чтение параметров и генерация ключей идут без трассировки.
  set +x
  local k v
  local -A P=()
  for k in MTU Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 HeaderProtectionKey ContentPaddingAddition ListenPort; do
    v="$(conf_get "$k" "$conf")"
    [ -n "$v" ] || die "в $conf нет параметра $k — конфиг повреждён?"
    P[$k]="$v"
  done
  local srv_pub endpoint priv pubk
  srv_pub="$(conf_get PrivateKey "$conf" | awg pubkey)" || die "не удалось вычислить pubkey сервера"
  [ -n "$srv_pub" ] || die "pubkey сервера пуст — проверьте PrivateKey в $conf"
  endpoint="$(detect_public_ip)" || die "не удалось определить внешний IP сервера"

  umask 077
  priv="$(awg genkey)"
  pubk="$(printf '%s\n' "$priv" | awg pubkey)"

  # сначала runtime: если ядро отвергло peer, файлы не трогаем
  awg set "$AWG_IFACE" peer "$pubk" allowed-ips "$ip/32" \
    || die "ядро не приняло peer (awg set) — файлы не изменены"

  if ! cat >> "$conf" <<EOF

[Peer]
# ${name}
PublicKey = ${pubk}
AllowedIPs = ${ip}/32
EOF
  then
    awg set "$AWG_IFACE" peer "$pubk" remove 2>/dev/null || true
    die "не удалось дописать peer в $conf — runtime-peer отозван"
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
  set -x
  qrencode -o "$AWG_DIR/$name.png" -s 6 -m 2 < "$AWG_DIR/$name.conf" || true
  step "клиент '$name' добавлен: $ip, конфиг $AWG_DIR/$name.conf"
  printf '\n  QR-код клиента (сканируйте в приложении Amnezia >= 5.0.1.5):\n\n'
  qrencode -t ansiutf8 < "$AWG_DIR/$name.conf" || true
}

do_remove_client() {
  local key="${1:-}"
  require_awg31
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  if [ -z "$key" ]; then
    if [ "$IS_TTY" = 1 ]; then
      do_list_clients
      read -r -p "Имя или PublicKey удаляемого клиента: " key || die "ввод прерван"
    else
      die "укажите имя или pubkey: bash install.sh remove-client <name|pubkey>"
    fi
  fi
  local pub="" name=""
  if [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    pub="$key"
    name="$(peer_name_by_pub "$pub")"
  else
    [[ "$key" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "некорректное имя/pubkey: $key"
    name="$key"
    pub="$(peer_pub_by_name "$name")"
    [ -n "$pub" ] || die "клиент '$name' не найден в $conf (список: bash install.sh list-clients)"
  fi

  local npeers
  npeers="$(grep -c '^PublicKey' "$conf" || true)"
  if [ "$npeers" = 1 ]; then
    warn "это последний peer — туннель останется без клиентов"
  fi

  # runtime
  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    awg set "$AWG_IFACE" peer "$pub" remove || warn "runtime-peer не удалён (возможно, его не было)"
  else
    step "интерфейс не поднят — правлю только конфиг"
  fi

  # перезапись конфига без [Peer]-блока с этим PublicKey
  if grep -qF "$pub" "$conf"; then
    local tmp
    tmp="$(mktemp "$AWG_DIR/.awg0.XXXXXX")"
    if awk -v p="$pub" '
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
    ' "$conf" > "$tmp"; then
      chmod 600 "$tmp"
      mv "$tmp" "$conf"
    else
      rm -f "$tmp"
      die "не удалось перезаписать $conf"
    fi
  else
    step "в конфиге peer не найден — удалён только из runtime"
  fi

  if [ -n "$name" ]; then
    rm -f "$AWG_DIR/$name.conf" "$AWG_DIR/$name.png"
    step "клиент '$name' удалён (peer, конфиг и QR)"
  else
    step "peer удалён: $pub"
  fi
}

do_list_clients() {
  local conf="$AWG_DIR/$AWG_IFACE.conf"
  [ -f "$conf" ] || die "туннель не установлен — выполните install"
  step "Клиенты из $conf"
  printf '  %-20s %-45s %s\n' "ИМЯ" "PUBKEY" "ALLOWED-IPS"
  awk '
    /^\[/ { name="" }
    /^#/ { name=$0; sub(/^#[[:space:]]*/, "", name) }
    /^PublicKey[[:space:]]*=/ { pub=$0; sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", pub) }
    /^AllowedIPs[[:space:]]*=/ {
      ip=$0; sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/, "", ip)
      printf "  %-20s %-45s %s\n", (name == "" ? "(без имени)" : name), pub, ip
    }
  ' "$conf"
  if awg show "$AWG_IFACE" >/dev/null 2>&1; then
    printf '\n'
    awg show "$AWG_IFACE"
  else
    step "интерфейс $AWG_IFACE не поднят — runtime-статистики нет"
  fi
}

#--- креды --------------------------------------------------------------------------
do_creds() {
  [ -r "$CRED_FILE" ] || die "файл кредов не найден: $CRED_FILE (выполните install)"
  step "Креды ($CRED_FILE)"
  cat "$CRED_FILE"
  if [ -f "$AWG_DIR/client1.conf" ] && command -v qrencode >/dev/null 2>&1; then
    printf '\n  QR клиентского конфига:\n\n'
    qrencode -t ansiutf8 < "$AWG_DIR/client1.conf" || true
  fi
}

#--- бэкап / восстановление -----------------------------------------------------------
do_backup() {
  step "Бэкап конфигов AWG и БД панели"
  local ts tar members=() stopped=0 ok=0
  ts="$(date '+%Y%m%d-%H%M%S')"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  tar="$BACKUP_DIR/awg-3xui-$ts.tar.gz"
  if [ -d "$AWG_DIR" ]; then members+=("etc/amnezia/amneziawg"); fi
  if [ -d /etc/x-ui ]; then members+=("etc/x-ui"); fi
  if [ -f "$CRED_FILE" ]; then members+=("${CRED_FILE#/}"); fi
  [ "${#members[@]}" -gt 0 ] || die "нечего бэкапить: ни конфигов AWG, ни /etc/x-ui"

  # консистентность SQLite: кратко останавливаем x-ui; запуск обратно гарантирован
  # (между stop и start нет команд, способных прервать функцию)
  if systemctl is-active --quiet x-ui 2>/dev/null; then
    systemctl stop x-ui || warn "x-ui не остановился — бэкап БД может быть неконсистентным"
    stopped=1
  fi
  if tar -czf "$tar" -C / "${members[@]}"; then ok=1; fi
  if [ "$stopped" = 1 ]; then
    systemctl start x-ui || warn "x-ui не запустился после бэкапа — проверьте: journalctl -u x-ui"
  fi
  [ "$ok" = 1 ] || die "tar не смог создать $tar"
  chmod 600 "$tar"
  step "бэкап готов: $tar ($(du -h "$tar" | awk '{print $1}'))"
  tar -tzf "$tar" | sed 's/^/  /'
}

do_restore() {
  local file="${1:-}"
  [ -n "$file" ] || die "укажите файл: bash install.sh restore /root/awg-3xui-backups/<file>.tar.gz"
  [ -f "$file" ] && [ -r "$file" ] || die "файл не найден или не читается: $file"
  tar -tzf "$file" >/dev/null 2>&1 || die "файл не читается как tar.gz: $file"

  # защита от tar-slip: только пути этого установщика, без '..' и абсолютных путей
  local m bad=0
  while IFS= read -r m; do
    case "$m" in
      etc/amnezia/amneziawg|etc/amnezia/amneziawg/*|etc/x-ui|etc/x-ui/*|root/awg-3xui-credentials.txt) ;;
      *) bad=1 ;;
    esac
    case "$m" in *..*) bad=1 ;; esac
    [ "$bad" = 0 ] || break
  done < <(tar -tzf "$file")
  [ "$bad" = 0 ] || die "архив содержит посторонние пути — восстановление отменено (ожидается бэкап этого установщика)"

  # восстанавливать есть смысл только на установленную систему
  [ -x /usr/local/x-ui/x-ui ] || [ -d "$AWG_DIR" ] \
    || die "система не установлена — сначала install, потом restore"

  step "Восстановление из $file (сервисы будут перезапущены)"
  systemctl stop "awg-quick@${AWG_IFACE}" 2>/dev/null || true
  systemctl stop x-ui 2>/dev/null || true
  tar -xzf "$file" -C / || die "распаковка не удалась"
  if [ -d "$AWG_DIR" ]; then
    chmod 700 "$AWG_DIR" 2>/dev/null || true
    chmod 600 "$AWG_DIR"/*.conf 2>/dev/null || true
  fi
  if [ -f "$AWG_DIR/$AWG_IFACE.conf" ]; then
    if ! systemctl start "awg-quick@${AWG_IFACE}"; then
      journalctl -u "awg-quick@${AWG_IFACE}" -n 25 --no-pager || true
      die "awg-quick не запустился после восстановления"
    fi
  fi
  if [ -x /usr/local/x-ui/x-ui ]; then
    if ! systemctl start x-ui; then
      journalctl -u x-ui -n 25 --no-pager || true
      die "x-ui не запустился после восстановления"
    fi
  fi
  step "восстановлено из $file"
}

#--- обновление -----------------------------------------------------------------------
do_update() {
  step "Обновление AmneziaWG (DKMS) и 3x-ui"
  command -v awg >/dev/null 2>&1 || die "AWG не установлен — нечего обновлять (выполните install)"
  wait_for_apt_lock || die "apt/dpkg занят более 5 минут — повторите позже"
  apt-get update || { sleep 5; apt-get update; }
  apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1 \
    || die "linux-headers-$(uname -r) недоступен — DKMS не собрать для текущего ядра"
  apt-get install "${APT[@]}" --only-upgrade amneziawg amneziawg-dkms amneziawg-tools "linux-headers-$(uname -r)" \
    || die "apt --only-upgrade не удался"

  step "Перезагрузка модуля ядра (туннель будет недоступен несколько секунд)"
  systemctl stop "awg-quick@${AWG_IFACE}" || warn "awg-quick не остановился"
  if rmmod amneziawg 2>/dev/null; then
    modprobe amneziawg || die "обновлённый модуль не загрузился"
    probe_awg31 || die "обновлённый модуль не принимает профиль 3.1 — проверьте версию пакетов amneziawg"
  else
    warn "модуль не выгрузился (занят) — новая версия вступит в силу после перезагрузки сервера"
  fi
  if ! systemctl start "awg-quick@${AWG_IFACE}"; then
    journalctl -u "awg-quick@${AWG_IFACE}" -n 25 --no-pager || true
    die "туннель не поднялся после обновления"
  fi
  awg show "$AWG_IFACE" >/dev/null || die "интерфейс не поднялся после обновления"

  if [ -x /usr/bin/x-ui ]; then
    step "Обновление 3x-ui (официальный update.sh, данные сохраняются)"
    echo y | x-ui update || warn "x-ui update завершился с ошибкой"
  fi
  step "Обновление завершено"
  awg --version | head -n1
  dkms status 2>/dev/null | grep amneziawg || true
  systemctl is-active "awg-quick@${AWG_IFACE}" x-ui 2>/dev/null || true
}

#--- перезапуск -------------------------------------------------------------------------
do_restart() {
  step "Перезапуск сервисов"
  if ! systemctl restart "awg-quick@${AWG_IFACE}"; then
    journalctl -u "awg-quick@${AWG_IFACE}" -n 25 --no-pager || true
    die "awg-quick@${AWG_IFACE} не запустился"
  fi
  if [ -x /usr/local/x-ui/x-ui ] || [ -f /etc/systemd/system/x-ui.service ]; then
    if ! systemctl restart x-ui; then
      journalctl -u x-ui -n 25 --no-pager || true
      die "x-ui не запустился"
    fi
  fi
  sleep 1
  awg show "$AWG_IFACE" >/dev/null || die "интерфейс не поднялся"
  systemctl is-active "awg-quick@${AWG_IFACE}" x-ui 2>/dev/null || true
  step "сервисы перезапущены"
}

#--- логи ---------------------------------------------------------------------------------
do_logs() {
  step "Последние строки логов"
  printf '== %s ==\n' "$LOG_FILE"
  tail -n 40 "$LOG_FILE" 2>/dev/null || true
  printf '\n== journal: awg-quick@%s + x-ui ==\n' "$AWG_IFACE"
  journalctl -u "awg-quick@${AWG_IFACE}" -u x-ui -n 30 --no-pager 2>/dev/null || true
  printf '\nПолная трассировка: %s\n' "$DBG_FILE"
}

#--- меню и справка ------------------------------------------------------------------------
usage() {
  cat <<'EOF'
awg-3xui-installer — AmneziaWG (модуль ядра, профиль 3.1) + 3x-ui для Ubuntu 24.04

Запуск без аргументов:
  в терминале (TTY)    -> интерактивное меню
  curl ... | sudo bash -> автономная установка без вопросов

Команды (sudo bash install.sh <команда>):
  install                    установка с нуля / идемпотентный повтор
  uninstall                  полное удаление (с бэкапом в /root/awg-3xui-backups)
  reinstall                  uninstall + install
  migrate                    профиль 1.x -> 3.1 (шифрование заголовков)
  status                     состояние сервисов, туннеля, версии
  add-client [name]          новый клиент (конфиг + QR)
  remove-client <name|pubkey>  удалить клиента
  list-clients               список клиентов + runtime-статистика
  creds                      показать креды и QR
  backup                     бэкап конфигов и БД панели
  restore <file.tar.gz>      восстановление из бэкапа
  update                     обновить AWG (DKMS) и 3x-ui
  restart                    перезапустить сервисы
  logs                       последние строки логов
  help                       эта справка

Примеры:
  curl -fsSL <url>/install.sh | sudo bash      # автономная установка
  sudo bash install.sh                         # меню
  sudo bash install.sh add-client phone
  sudo AWG_PORT=51820 bash install.sh install

Переменные окружения (install): AWG_PORT, PANEL_PORT, PANEL_USER, PANEL_PASS, PANEL_PATH
EOF
}

show_menu() {
  local choice rf
  while :; do
    printf '\n%s\n' '============================================================'
    printf '  awg-3xui-installer — меню управления\n'
    printf '%s\n' '============================================================'
    printf '   1) Установка с нуля / идемпотентный повтор (install)\n'
    printf '   2) Полное удаление (uninstall, с бэкапом)\n'
    printf '   3) Переустановка начисто (reinstall)\n'
    printf '   4) Миграция профиля 1.x -> 3.1 (migrate)\n'
    printf '   5) Статус (status)\n'
    printf '   6) Добавить клиента (add-client)\n'
    printf '   7) Удалить клиента (remove-client)\n'
    printf '   8) Список клиентов (list-clients)\n'
    printf '   9) Показать креды и QR (creds)\n'
    printf '  10) Бэкап конфигов и БД панели (backup)\n'
    printf '  11) Восстановление из бэкапа (restore)\n'
    printf '  12) Обновление AWG + 3x-ui (update)\n'
    printf '  13) Перезапуск сервисов (restart)\n'
    printf '  14) Логи (logs)\n'
    printf '   0) Выход\n'
    printf '%s\n' '------------------------------------------------------------'
    read -r -p 'Выбор: ' choice || { printf '\n'; break; }
    set -x   # install завершается с set +x (защита кредов) — возвращаем трассировку
    case "$choice" in
      1) do_install ;;
      2) if confirm_yes "Удалить AWG + 3x-ui полностью (бэкап будет создан)?"; then
           do_uninstall
         else step "отменено"; fi ;;
      3) if confirm_yes "Переустановить начисто (текущие конфиги и БД панели будут удалены, бэкап будет создан)?"; then
           do_reinstall
         else step "отменено"; fi ;;
      4) do_migrate ;;
      5) do_status ;;
      6) do_add_client "" ;;
      7) do_remove_client "" ;;
      8) do_list_clients ;;
      9) do_creds ;;
      10) do_backup ;;
      11) read -r -p 'Путь к файлу бэкапа: ' rf || rf=""
          do_restore "$rf" ;;
      12) do_update ;;
      13) do_restart ;;
      14) do_logs ;;
      0|q|quit|exit) break ;;
      *) printf 'Неизвестный пункт: %s\n' "$choice" ;;
    esac
  done
  step "Выход из меню"
}

#--- dispatch ---------------------------------------------------------------------------
ACTION="${1:-}"
case "$ACTION" in
  help|-h|--help) usage; exit 0 ;;
esac

# TTY определяем ДО перенаправления вывода в tee: после exec stdout уже не TTY.
# Меню — только когда и stdin, и stdout терминал; curl | bash -> автоустановка.
IS_TTY=0
if [ -t 0 ] && [ -t 1 ]; then IS_TTY=1; fi

if [ -z "$ACTION" ]; then
  if [ "$IS_TTY" = 1 ]; then ACTION="menu"; else ACTION="install"; fi
fi
case "$ACTION" in
  menu|install|uninstall|reinstall|migrate|status|add-client|remove-client|list-clients|creds|backup|restore|update|restart|logs) ;;
  *) printf 'Неизвестная команда: %s\n\n' "$ACTION" >&2; usage >&2; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите от root: sudo bash install.sh ${ACTION}" >&2
  exit 1
fi

mkdir -p /var/log
touch "$LOG_FILE" "$DBG_FILE"
chmod 600 "$LOG_FILE" "$DBG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1
exec 5>>"$DBG_FILE"
BASH_XTRACEFD=5   # без export: иначе дочерние bash (dpkg/dkms) ругаются на fd 5
set -x

# лок только для изменяющих действий; status/list-clients/creds/logs — read-only
case "$ACTION" in
  status|list-clients|creds|logs) ;;
  *)
    exec 9>/run/lock/awg-3xui-installer.lock
    flock -n 9 || { echo "ОШИБКА: установщик уже запущен в другом процессе" >&2; exit 1; }
    ;;
esac

step "Действие: ${ACTION}"
case "$ACTION" in
  menu) show_menu ;;
  install) do_install ;;
  uninstall) do_uninstall ;;
  reinstall) do_reinstall ;;
  migrate) do_migrate ;;
  status) do_status ;;
  add-client) do_add_client "${2:-}" ;;
  remove-client) do_remove_client "${2:-}" ;;
  list-clients) do_list_clients ;;
  creds) do_creds ;;
  backup) do_backup ;;
  restore) do_restore "${2:-}" ;;
  update) do_update ;;
  restart) do_restart ;;
  logs) do_logs ;;
esac
sleep 1   # дать tee дописать лог