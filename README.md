# awg-3xui-installer

Автономный установщик VPN-сервера на **Ubuntu 24.04 LTS**: один скрипт, без интерактивных вопросов, в фиксированной последовательности ставит **AmneziaWG с нативным модулем ядра** (не userspace-Go), **WireGuard tools** и панель **3x-ui**, после чего поднимает рабочий туннель и печатает все креды.

## Что ставится

| Компонент | Источник | Тип |
|---|---|---|
| `amneziawg` (модуль ядра `amneziawg.ko`) | `ppa:amnezia/ppa`, пакет `amneziawg-dkms` | DKMS, нативно в ядре, пересобирается при обновлении ядра |
| `awg` / `awg-quick` | `ppa:amnezia/ppa`, пакет `amneziawg-tools` | userspace-инструменты AmneziaWG |
| `wg` / `wg-quick` | репозитории Ubuntu, `wireguard-tools` | модуль `wireguard` уже встроен в ядро Ubuntu |
| 3x-ui | официальный `install.sh` из `MHSanaei/3x-ui` | systemd-сервис `x-ui`, SQLite |

## Требования

- чистая **Ubuntu 24.04 LTS** (x86_64 или aarch64), VPS/сервер с systemd;
- запуск от **root**;
- **Secure Boot выключен** (DKMS-модуль не подписан; установщик проверяет и останавливается с понятной ошибкой);
- доступ к `github.com` / `raw.githubusercontent.com` и `ppa.launchpadcontent.net`;
- заголовки текущего ядра доступны в репозиториях (`linux-headers-$(uname -r)` ставятся автоматически).

## Установка (одна команда)

```bash
curl -fsSL https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main/install.sh | sudo bash
```

Последовательность внутри скрипта:

1. предпроверка (root, Ubuntu 24.04, архитектура, systemd, Secure Boot, сеть);
2. зависимости + заголовки ядра;
3. `ppa:amnezia/ppa` → `amneziawg` (DKMS-модуль + tools), `modprobe amneziawg`, проверка `/sys/module/amneziawg`;
4. проверка нативного `wireguard` в ядре + `wireguard-tools`;
5. генерация ключей и параметров обфускации (`Jc/Jmin/Jmax/S1/S2/H1–H4`), конфиг `awg0`, NAT, `ip_forward`, запуск `awg-quick@awg0`, клиентский конфиг + QR;
6. 3x-ui в неинтерактивном режиме (`XUI_NONINTERACTIVE=1`, случайные порт/логин/пароль/webBasePath, SQLite, без SSL);
7. правила ufw (только если ufw уже активен), верификация сервисов, итоговый блок с кредами и QR-кодом.

Повторный запуск идемпотентен: существующие конфиги и установленные компоненты не перегенерируются.

## Переопределение параметров

```bash
sudo AWG_PORT=51820 PANEL_PORT=8443 PANEL_USER=admin PANEL_PASS='мой-пароль' PANEL_PATH=secret bash install.sh
```

| Переменная | По умолчанию |
|---|---|
| `AWG_PORT` | случайный свободный UDP 20000–59999 |
| `PANEL_PORT` | случайный свободный TCP 20000–59999 |
| `PANEL_USER` | случайные 10 hex-символов |
| `PANEL_PASS` | случайные 32 hex-символа |
| `PANEL_PATH` | случайные 12 hex-символов (webBasePath) |

## Результат

- панель: `http://<IP>:<PANEL_PORT>/<PANEL_PATH>` — логин/пароль печатаются в конце;
- клиентский конфиг AmneziaWG: `/etc/amnezia/amneziawg/client1.conf` (+ QR `client1.png`, QR выводится в терминал);
- все креды: `/root/awg-3xui-credentials.txt` (chmod 600), дубль от 3x-ui: `/etc/x-ui/install-result.env`;
- логи: `/var/log/awg-3xui-install.log` и `/var/log/awg-3xui-install.debug.log` (трассировка каждой команды, chmod 600).

## Безопасность

- Панель ставится **без SSL** (HTTP) — это осознанный дефолт автономной установки без домена. Безопасный доступ сразу после установки:

  ```bash
  ssh -L 8443:127.0.0.1:<PANEL_PORT> root@<IP>
  # затем в браузере: http://127.0.0.1:8443/<PANEL_PATH>
  ```

  Сертификат можно выпустить позже через меню `x-ui` (Let's Encrypt для домена или IP).
- Порты `AWG_PORT/udp` и `PANEL_PORT/tcp` должны быть открыты в security group облачного провайдера.
- Клиентский туннель — только IPv4 (`AllowedIPs = 0.0.0.0/0`), DNS `1.1.1.1`, MTU 1280, keepalive 25 с.

## Добавление второго клиента

```bash
cd /etc/amnezia/amneziawg
awg genkey | tee client2.key | awg pubkey > client2.pub
# скопируйте client1.conf -> client2.conf, замените PrivateKey и Address (10.8.1.3/32)
awg set awg0 peer "$(cat client2.pub)" allowed-ips 10.8.1.3/32
# и допишите [Peer] с этим PublicKey в awg0.conf, чтобы пережить перезапуск
```

## Лицензия

MIT