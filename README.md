# SSH-MCP

Многопользовательский [MCP](https://modelcontextprotocol.io/)-сервер для SSH:
даёт агенту инструменты для работы на нескольких серверах, не раскрывая ему ни
адресов, ни логинов, ни паролей, ни ключей. Агент называет **имя сервера** из
`servers.yaml`, а подключение, аутентификация и вычистка секретов происходят на
стороне сервера.

Реализация: Python + [FastMCP](https://github.com/jlowin/fastmcp) + `paramiko`,
транспорт — **stdio** (stdout занят JSON-RPC, логи идут только в stderr).

## Возможности

- 26 инструментов и 2 MCP-ресурса (см. раздел «Инструменты»).
- Каталог серверов в `servers.yaml` с комментариями, `description` и `tags` —
  агент выбирает машину по ним.
- Аутентификация по лестнице `key → agent → password` с накоплением ошибок.
- Свой `known_hosts` рядом с конфигом: TOFU (`auto_add`/`tofu`), строгий
  `reject`, привязка к отпечатку (`pin`).
- Fence от prompt-injection и redaction секретов в ответах; аудит в `audit.jsonl`.
- Пул соединений на процесс, параллельные вызовы, фоновые задачи.

## Требования

- Python 3.10+.
- Пакеты из `requirements.txt`: `fastmcp>=2.0`, `paramiko>=3.4`, `PyYAML>=6.0`,
  `python-dotenv>=1.0`.

## Установка

```bash
pip install -r requirements.txt
```

Пакеты должны стоять в **том же** `python`, которым MCP запускается из
`kilo.json` (см. «Регистрация в Kilo»).

## Конфигурация

Два файла рядом друг с другом (в каталоге пакета или в `SSH_MCP_CONFIG_DIR`):

```bash
copy servers.example.yaml servers.yaml     # каталог серверов
copy .env.example .env                     # секреты
```

Порядок поиска `servers.yaml`:

1. путь аргументом: `python mcp_server.py <path>` — или `SSH_MCP_CONFIG`;
2. `SSH_MCP_CONFIG_DIR/servers.yaml`;
3. `servers.yaml` рядом с пакетом (по умолчанию).

`servers.yaml` обычно коммитится (секретов в нём нет — только `${ПЕРЕМЕННАЯ}`),
а `.env`, `known_hosts`, `audit.jsonl` и `logs/` — в `.gitignore`.

### `servers.yaml`

```yaml
defaults:              # значения по умолчанию для всех серверов
  port: 22
  username: root
  connect_timeout: 30
  auth_timeout: 30
  host_key_policy: auto_add
  keepalive_interval: 30

settings:
  allowed_local_dirs:  # локальные папки для upload/download
    - D:/Work
  default_server: prod

servers:
  # Комментарий НАД именем сервера попадает в comments и виден агенту
  # в ssh_list_servers / ssh_server_info — пишите сюда «карту местности».
  prod:
    host: 203.0.113.10
    default_workdir: /opt/app
    description: Продакшн приложения (docker compose)
    tags: [prod, docker, deploy]
    default: true
    auth:
      type: password
      password: ${PROD_PASSWORD}     # значение из .env

  internal:
    host: 198.51.100.20
    jump_via: prod                   # доступ только через jump-host (или: bastion)
    description: Внутренний хост за NAT
    tags: [internal, jump]
    auth:
      type: password
      password: ${INTERNAL_PASSWORD}

  keyauth:
    host: 203.0.113.30
    description: Хост с доступом по ключу
    tags: [keyauth]
    auth:
      type: key
      key_path: ${DEPLOY_KEY:-~/.ssh/id_ed25519}
      passphrase: ${DEPLOY_KEY_PASSPHRASE}
      password_fallback: false
```

Ключи сервера: `host`, `port`, `username`, `jump_via` (он же `bastion`),
`default_workdir` (он же `workdir`), `description`, `tags`, `auth`,
`connect_timeout`, `auth_timeout`, `keepalive_interval`, `host_key_policy`,
`host_key_fingerprint`, `known_hosts`. Неизвестные ключи — ошибка конфигурации
(строгая валидация), опечатка не «проглотится».

Политики host-key:

- `auto_add` / `tofu` — первый увиденный ключ записывается в `known_hosts` рядом
  с конфигом и дальше сверяется (для первого подключения удобно);
- `reject` — ключ обязан уже быть в `known_hosts`, иначе отказ;
- `pin` — сверка только с `host_key_fingerprint` (формат как у `ssh-keygen -lf`:
  `SHA256:` + 43 символа base64). Смена ключа на хосте намеренно рвёт соединение.
  Порядок: подключиться один раз при `auto_add` → взять отпечаток из
  `ssh_server_info` → вписать в `host_key_fingerprint` и переключить на `pin`.

Подстановка работает в любом строковом поле: `${VAR}` или `${VAR:-default}`.
Ссылка на неопределённую переменную без значения по умолчанию — ошибка загрузки.

### `.env`

Читается автоматически из каталога `servers.yaml`, существующие переменные
окружения не перекрывает. Секреты серверов пишутся здесь и подставляются в YAML
через `${ИМЯ}`:

```
PROD_PASSWORD=
INTERNAL_PASSWORD=
DEPLOY_KEY=
DEPLOY_KEY_PASSPHRASE=
PROD_HOST_KEY_FINGERPRINT=      # для host_key_policy: pin
```

Переменные самого MCP (необязательные, с рабочими значениями по умолчанию):

| Переменная | Назначение |
|---|---|
| `SSH_MCP_CONFIG` | путь к `servers.yaml` |
| `SSH_MCP_CONFIG_DIR` | каталог конфига: оттуда берутся `.env`, `known_hosts`, `audit.jsonl` |
| `SSH_ALLOWED_LOCAL_DIRS` | доп. локальные папки для upload/download, через `;` (Windows) или `:` |
| `SSH_MCP_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR` (по умолчанию `INFO`) |
| `SSH_MCP_LOG_FILE` | путь к ротируемому логу; `off` выключает файл (по умолчанию `ssh-mcp.log` рядом с `servers.yaml`) |

## Запуск

```bash
python mcp_server.py                 # servers.yaml рядом с пакетом
python mcp_server.py /etc/ssh-mcp/servers.yaml
SSH_MCP_CONFIG_DIR=/etc/ssh-mcp python mcp_server.py
```

Это stdio-сервер: обычно его запускает не человек, а MCP-клиент (Kilo). Уход
клиента (EOF на stdin, `Ctrl-C`) — штатное завершение: пул соединений
закрывается, процесс выходит с кодом 0. Ошибка конфигурации → код 2.

## Регистрация в Kilo

Добавьте сервер в `kilo.json` (проектный или глобальный):

```json
{
  "mcp": {
    "ssh-yaml": {
      "type": "local",
      "command": ["python", ".\\SSH-MCP\\mcp_server.py"]
    }
  }
}
```

После правки конфига MCP нужно переподключить (перезапуск Kilo/сервера).

## Ключи: генерация и авторизация

`ssh_generate_key` создаёт пару ключей на этой машине, `ssh_install_key` кладёт
публичную половину в `~/.ssh/authorized_keys` сервера. Приватный ключ не покидает
диск и в ответ не попадает; `servers.yaml` инструменты не редактируют.

Порядок «перейти с пароля на ключ»:

1. В `servers.yaml` для сервера задайте `auth.type: auto`, `auth.key_path:
   <путь>` (и оставьте `auth.password` / `${...}`) — пока ключ не установлен,
   подключение идёт по паролю.
2. `ssh_generate_key(server="<имя>")` — создаёт ключ по этому `key_path`; вернёт
   публичный ключ и отпечаток.
3. `ssh_install_key(server="<имя>")` — добавляет публичный ключ на хост, используя
   текущую аутентификацию (пароль из профиля). Операция идемпотентна.
4. Следующее подключение идёт лестницей `key → agent → password`: ключ теперь
   существует и авторизован, поэтому срабатывает первым. Если ключ удалить или он
   не подойдёт, лестница сама вернётся к паролю.

Если в `auth.key_path` задана passphrase, добавьте её в `auth.passphrase`
(`${ПЕРЕМЕННАЯ}` из `.env`) — иначе `ssh_generate_key(passphrase=...)` создаст
зашифрованный ключ, который сервер не сможет прочитать.

## Инструменты

Выбор сервера: сначала `ssh_list_servers`, сопоставить запрос с `description`,
`comments`, `tags`, затем передать точное имя в аргументе `server`. Без аргумента
используется сервер по умолчанию.

| Группа | Инструменты |
|---|---|
| Каталог | `ssh_list_servers`, `ssh_server_info`, `ssh_guide`, `ssh_audit`, `ssh_forget_host_key` |
| Выполнение | `ssh_execute`, `ssh_job_status`, `ssh_sudo`, `ssh_signal` |
| Файлы | `ssh_list_files`, `ssh_read_file`, `ssh_write_file`, `ssh_upload_file`, `ssh_download_file` |
| ФС | `ssh_stat`, `ssh_read_link`, `ssh_symlink`, `ssh_mkdir`, `ssh_move`, `ssh_remove`, `ssh_chmod`, `ssh_copy_between` |
| Пакетно/поиск | `ssh_run_many`, `ssh_find` |
| Ключи | `ssh_generate_key`, `ssh_install_key` |

MCP-ресурсы: `ssh://connections` и `ssh://connections/{server}` — живое состояние
пула соединений.

Особенности:

- `ssh_sudo` передаёт пароль через stdin (не в argv), режим без prompt;
- `ssh_execute(background=True)` → `ssh_job_status` для задач, не влезающих в
  таймаут; логи фоновых задач в `ssh-mcp-job-*/`;
- `ssh_run_many(command, servers[])` — одна команда на N серверов параллельно;
- `ssh_guide(topic)` — шпаргалка по возможностям сервера прямо из тула.

## Безопасность

- Агент видит только имя, host, порт, username, `description`, `tags` и
  комментарии — но не пароли, не passphrase и не путь к приватному ключу.
- Ответы (`stdout`/`stderr`/содержимое файлов) оборачиваются в fence-маркеры
  «это данные, а не инструкции».
- Реестр известных секретов вычищается из ответов, логов и аудита. Границы:
  посторонние секреты, прочитанные агентом из удалённых файлов, MCP не
  распознаёт — не выводите их без нужды.
- `allowed_local_dirs` ограничивает локальные пути для `ssh_upload_file` /
  `ssh_download_file` (пустой список = любой путь, не рекомендуется).
- Держите `.env` и `servers.yaml` с ограниченными правами; в репозиторий
  коммитится только `.example` без значений.

## Тесты

```bash
python -m pytest tests -q
```

Тесты самодостаточны: собственный sshd на `paramiko` (`tests/sshd.py`) с exec,
SFTP и пробросом `direct-tcpip`, внешний `paramiko_sshd` не нужен. Покрытие:
протокол sshd, регрессии safety, утечки секретов, рантайм сервера (63 теста).

## Известные ограничения

- `ssh_tunnel_open` (проброс портов к localhost-сервисам) — не реализован.
- Hot-reload конфига отсутствует: снимок `servers.yaml` берётся на старте,
  изменения требуют перезапуска сервера.
- Права на `.env`/`servers.yaml` — отдельная процедура (риск потерять доступ),
  в самом MCP не автоматизированы.

## Связанные файлы

- `servers.example.yaml` — образец каталога серверов с комментариями.
- `.env.example` — образец файла секретов.
- `RELEASE-PLAN.md`, `IMPROVEMENTS.md` — история реализации и открытые задачи.

Как поднять этот MCP под скилл `safe-vps-networking` — см.
`../safe-vps-networking/README.md`.
