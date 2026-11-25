# awg-manager v3.2.7: AmneziaWG 3.1 (TSPU-Stealth & Dual-Stack VPN Server)

Надёжный установщик, менеджер, HTTP/HTTPS API подписок и Telegram-бот управления **AmneziaWG 3.1** (нативный модуль ядра `amneziawg.ko`) для **Ubuntu 24.04 LTS** с усиленной защитой от ТСПУ/DPI, поддержкой **Dual-Stack (IPv4 + IPv6)** и бесшовной интеграцией с роутерами MikroTik.

---

## Ключевые возможности

### Незаметность для ТСПУ / DPI (AmneziaWG 3.1)
- **12 профилей маскировки (Stealth Presets) + Custom:**
  - `quic` — HTTP/3 (QUIC, RFC 9000) на `443/udp` (или авто-фолбэк на `20000-59999/udp`)
  - `quic-alt` — HTTP/3 (QUIC) на высоком порту `20000-59999/udp`
  - `stun` / `stun-alt` — WebRTC / STUN (`3478/udp` или `20000-50000/udp`, звонки Telegram/WhatsApp)
  - `dtls` — DTLS 1.2 ClientHello (`8801/udp`, Zoom / VoIP)
  - `dns` — DNS Query EDNS0 (`53/udp` с безопасным обходом `systemd-resolved`)
  - `ntp` — NTP v4 Client Request (`123/udp`)
  - `sip` — SIP OPTIONS (`5060/udp`, IP-телефония)
  - `steam` — Valve Source Engine Query (`27015/udp`)
  - `minecraft` — RakNet Unconnected Ping (`19132/udp`)
  - `discord` — Discord Voice IP Discovery (`50001/udp`)
  - `dht` — BitTorrent DHT Ping (`6881/udp`)
  - `custom` — пользовательский UDP-порт и CPS-байткод `I1` (с предварительной проверкой ядром до перезапуска `awg0`)
- **Профиль обфускации 3.1:** `HeaderProtectionKey` (шифрование заголовков), `ContentPaddingAddition`, `Jc`, `Jmin..Jmax`, `S1..S4 >= 12` с математической защитой от коллизий длин пакетов (`s4_collides`) и `DisableCookies = on` (защита от active probing при поддержке модулем).

### Интеллектуальный Dual-Stack (IPv4 + IPv6)
- **Двойной стек внутри туннеля:** адресация `10.x.y.0/24` + `fd42:42:42::/64`, `MTU = 1280` (совместимость с RFC 8200 / `IPV6_MIN_MTU`), динамический `TCPMSS --clamp-mss-to-pmtu` только для интерфейса `awg0`.
- **Умная адаптация к сети VPS:** если у сервера есть рабочий выход в глобальный IPv6-интернет, клиентам выдаётся полный Dual-Stack (`AllowedIPs = 0.0.0.0/0, ::/0`); если у провайдера нет исходящего IPv6-маршрута — автоматически выставляется `0.0.0.0/0` без blackhole трафика, при этом индивидуальные `--allowed-ips` и `--dns` клиентов бережно сохраняются.
- **Переключение внешнего Endpoint (`ipv4` / `ipv6` / домен):** сервер и отдельные клиенты могут подключаться как по IPv4, так и по публичному IPv6 для обхода блокировок IPv4-подсетей хостеров.

### Автоматическая ротация, подписки и Admin API (`awg-api.service`, порт `8443/tcp`)
- **Безопасная ротация с авто-откатом (`rotate`):** смена UDP-порта, ключей сервера и обфускации с сохранением снэпшота конфигов — если новый сокет не поднялся, туннель автоматически откатывается к предыдущей рабочей конфигурации без простоя.
- **Шедулер (`awg-rotate.timer`):** автоматическая ночная ротация каждые 3 дня, еженедельно или ежедневно.
- **Dual-Mode HTTP + HTTPS на одном порту `8443/tcp`:**
  - **Клиентские подписки (`awg_tok_*`, HTTP/HTTPS, кэширование `ETag` / `304 Not Modified`):**
    - `/sub/<token>` — готовый `.conf` файл AmneziaWG
    - `/vpn/<token>` — ссылка `vpn://` для импорта в AmneziaVPN
    - `/json/<token>` (или `/sub/<token>?format=json`) — JSON-манифест
    - `/rsc/<token>` — справочный скрипт для RouterOS
  - **Защищённый Admin API v1 (`awg_adm_*`, HTTPS с самоподписанным ECDSA SAN-сертификатом или через туннель `awg0`):**
    - `GET /api/v1/clients`, `GET /api/v1/clients/<name>`, `POST /api/v1/clients`, `PATCH /api/v1/clients/<name>`, `DELETE /api/v1/clients/<name>`
    - `POST /api/v1/server/endpoint`, `POST /api/v1/server/preset`, `POST /api/v1/server/rotate`
  - **Защита от перебора:** потокобезопасный rate-limit (20 ошибок/мин для подписок, 10 ошибок/5 мин для Admin API с группировкой IPv6 по `/64`).

### Безопасность и надёжность сервера
- **Изоляция и атомарность:** `umask 077`, каталог `/etc/amnezia/amneziawg` (`700`), конфиги, ключи, QR и `tokens.json` (`600`) с атомарной записью через `os.replace`, защита от гонок через `flock` (`/run/lock/awg-manager.lock`).
- **Sysctl и systemd hardening:** `ip_forward=1`, `ipv6.forwarding=1`, `accept_ra=2`, `rp_filter=2`, `tcp_syncookies=1`; изоляция `awg-api` и `awg-bot` (`NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectKernelModules`, `RestrictSUIDSGID`, `LockPersonality`).

---

## Быстрая установка

На чистом VPS с **Ubuntu 24.04 LTS** от имени `root`:

```bash
curl -fsSL https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main/install.sh | sudo bash
```

Или локально из клонированного репозитория:

```bash
sudo bash install.sh
```

### Переменные окружения при установке

| Переменная | По умолчанию | Описание |
| :--- | :--- | :--- |
| `AWG_PORT` | пусто (`443/udp`, иначе свободный `20000-59999`) | UDP-порт сервера (`1..65535`) |
| `AWG_SUBNET` | пусто (случайная `10.x.y.0/24`) | Приватная IPv4-подсеть клиентов `/24` |
| `AWG_IPV6_PREFIX` | `fd42:42:42::` | Внутренний ULA IPv6-префикс туннеля |
| `AWG_ENDPOINT` | пусто (автоопределение внешнего IP) | Внешний IP или домен для клиентских конфигов |
| `AWG_DNS` | `1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001` | DNS-серверы для клиентов |
| `AWG_MTU` | `1280` | MTU туннеля (`>= 1280` для совместимости с IPv6 RFC 8200) |
| `AWG_API_PORT` | `8443` | TCP-порт HTTP/HTTPS API подписок и управления |
| `AWGM_PLAIN` | `0` | `1` — отключить ANSI-цвета и `tee`-логирование |

---

## Двухпанельная TUI-консоль (`awg-manager`)

```bash
sudo awg-manager
```

Панель управления выполнена в виде полноэкранной **двухпанельной `curses`-консоли** (в стиле `lazygit` / `btop`, без внешних зависимостей и без мерцания по SSH):
- **Слева** — 6 компактных разделов + живая сводка онлайн-пиров, трафика и внешних адресов:
  1. **Клиенты** — таблица клиентов, инспектор параметров (`Endpoint`, `MTU`, `DNS`, `AllowedIPs`) и мгновенные действия для выбранного клиента:
     - `Enter` / `v` — QR-код и текст `.conf` (с удобным копированием мышкой)
     - `t` — токен и ссылки подписки (`.conf`, `vpn://`, `.rsc`)
     - `e` — редактирование клиента (имя, индивидуальный Endpoint, DNS, MTU, AllowedIPs, перевыпуск ключей и токена)
     - `n` / `a` — создать нового клиента
     - `d` / `x` — удалить клиента (с защитным подтверждением)
  2. **Маскировка** — выбор любого из **12 профилей маскировки + Custom** стрелками (`Enter`), полная ротация сейчас (`p`) и настройка расписания (`s`).
  3. **Сеть / IPv6** — переключение внешнего Endpoint (`IPv4` / `IPv6` / свой домен), ручная настройка публичного IPv6 на WAN / Netplan и синхронизация `--all`.
  4. **API и ТГ-бот** — просмотр/перевыпуск `awg_adm_...` токена и TLS SHA256 отпечатка, настройка `bot.env`, перезапуск и чтение логов `journalctl`.
  5. **Диагностика** — самодиагностика (8 проверок с цветовой подсветкой `[OK]`/`[WARN]`/`[FAIL]`), 15-секундный live-перехват UDP (`diagnose-live`), рестарт `awg0`.
  6. **Обслуживание** — Zero-Downtime обновление, создание бэкапов, выбор архива для восстановления из списка и изолированная зона переустановки/удаления.

- **Навигация:** `↑` / `↓` (`k` / `j`), `←` / `→` / `Tab` (смена панели), `1`–`6` (быстрый переход к разделу), `r` (обновить), `?` (справка), `q` (выход).
- Для принудительного запуска классического текстового меню (например в нестандартных терминалах) можно передать `AWGM_CLASSIC_MENU=1 sudo awg-manager`.

---

## Обновление сервера (Zero-Downtime Update)

Обновление `awg-manager`, `awg-api` и `awg-bot` без разрыва активных сессий клиентов:

```bash
curl -fsSL https://raw.githubusercontent.com/aligorov/awg-3xui-installer/main/update.sh | sudo bash
```

Или через установленный CLI:

```bash
sudo awg-manager update
```

---

## Telegram-бот управления (`bot.py`)

Написан на чистой стандартной библиотеке Python 3, использует fail-closed модель доступа (`/etc/amnezia/amneziawg/bot.env`, `chmod 600`):
- `BOT_TOKEN` — токен от `@BotFather`
- `ADMIN_ID` — один или несколько числовых Telegram User ID через запятую
- `GROUP_ID` и `TOPIC_ID` *(опционально)* — привязка к группе и конкретному топику супергруппы

### Команды бота
- `/start`, `/menu` — главное меню управления
- `/clients [стр]`, `/list` — постраничный список клиентов со статусом, трафиком и кнопками `QR`, `Токен`, `Удалить`
- `/add [имя]` — создать клиента и получить `.conf`, QR-код и ссылку подписки
- `/qr <имя>` — получить `.conf` и QR-код клиента
- `/token [имя]` — постоянный токен и ссылки подписки (корректно форматирует как IPv4, так и `[IPv6]`)
- `/stealth [профиль]`, `/preset` — выбор любого из 12 профилей маскировки
- `/rotate` — ротация порта, ключей и обфускации сервера (с подтверждением)
- `/schedule [3days|weekly|daily|off]` — расписание автоматической ночной ротации
- `/status` — состояние туннеля, Endpoint, маскировки и трафика
- `/diagnose` — запуск серверной самодиагностики
- `/id`, `/topic` — служебный вывод `chat_id`, `thread_id` и `User ID` для настройки `bot.env`

---

## CLI-команды `awg-manager`

| Команда | Описание |
| :--- | :--- |
| `sudo awg-manager` / `menu` | Интерактивное меню управления (TUI) |
| `sudo awg-manager update` | Обновление скриптов и сервисов без разрыва туннеля |
| `sudo awg-manager install` | Установка или идемпотентная проверка сервера |
| `sudo awg-manager reinstall` | Переустановка ключей и туннеля с сохранением бэкапа и `bot.env` |
| `sudo awg-manager clients` | Список клиентов, IPv4+IPv6 адреса, статус онлайн и трафик |
| `sudo awg-manager add-client <имя> [опции]` | Создать клиента (`--dns`, `--mtu`, `--allowed-ips`, `--keepalive`, `--endpoint`) |
| `sudo awg-manager edit-client <имя> [опции]` | Изменить клиента (`--rename`, `--dns`, `--mtu`, `--allowed-ips`, `--keepalive`, `--endpoint`, `--rekey`, `--rotate-token`) |
| `sudo awg-manager remove-client <имя\|pubkey>` | Удалить клиента и его токен |
| `sudo awg-manager token <имя>` | Показать постоянный токен клиента и ссылки подписки |
| `sudo awg-manager admin-token [show\|rotate]` | Показать или перевыпустить мастер-токен Admin API и SHA256 отпечаток TLS |
| `sudo awg-manager preset [профиль]` | Сменить профиль маскировки (`quic`, `quic-alt`, `stun`, `stun-alt`, `dtls`, `dns`, `ntp`, `sip`, `steam`, `minecraft`, `discord`, `dht`, `custom`) |
| `sudo awg-manager endpoint [ipv4\|ipv6\|хост] [--all]` | Переключить внешний Endpoint сервера |
| `sudo awg-manager set-ipv6 <ipv6> [шлюз] [--all]` | Настроить публичный IPv6 на WAN-интерфейсе + `netplan` и переключить Endpoint |
| `sudo awg-manager rotate [профиль]` | Полная ротация порта, ключей и параметров обфускации |
| `sudo awg-manager schedule [3days\|weekly\|daily\|off\|status]` | Управление таймером авто-ротации |
| `sudo awg-manager api-status` / `api-restart` | Статус и перезапуск `awg-api.service` |
| `sudo awg-manager bot` / `bot-status` / `bot-restart` | Настройка, статус и перезапуск `awg-bot.service` |
| `sudo awg-manager status` | Детальный статус интерфейса и пиров |
| `sudo awg-manager diagnose` / `diagnose-live` | Самодиагностика сервера и 15-секундный перехват входящих UDP-пакетов |
| `sudo awg-manager backup` / `restore <файл.tar.gz>` | Создание и безопасное восстановление резервной копии |
| `sudo awg-manager uninstall` | Полное удаление AmneziaWG, правил `iptables`/`ip6tables`, сервисов и настроек |

---

## Интеграция с MikroTik (`amneziawg-mikrotik`)

Сервер полностью совместим с контейнером [`routeros-aligorov/amneziawg-mikrotik`](https://github.com/aligorov/routeros-aligorov):
1. **Через Admin API (управление всем пулом клиентов с роутера):** выполните `sudo awg-manager admin-token` и добавьте VPS (`https://<IP>:8443`, `awg_adm_...` и TLS SHA256 fingerprint) в разделе **VPS Fleet** веб-интерфейса контейнера.
2. **Через прямую подписку одного туннеля:** выполните `sudo awg-manager token <имя>` и укажите URL `http://<IP>:8443/sub/awg_tok_...` в настройках подписки туннеля — контейнер будет проверять `ETag` (`If-None-Match`) и автоматически применять новые ключи, порт и обфускацию при ротациях.

---

## Совместимость клиентов

- **AmneziaVPN >= 5.0.1.5** (Windows, macOS, Linux, iOS, Android)
- **AmneziaWG** с поддержкой профиля 3.1 (`HeaderProtectionKey` и `ContentPaddingAddition`)
