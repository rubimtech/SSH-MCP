# План релиза ssh-mcp — параллельная реализация

Источник идей: `IMPROVEMENTS.md`. Реализация разбита на пакеты с **непересекающимися
файлами**, поэтому агенты работают одновременно в одной директории без конфликтов.

## Статус пакета WP-0 (инфраструктура) — УЖЕ СДЕЛАНО

Общий контракт, чтобы агенты не изобретали свои версии fence/redaction/audit:

| Что | Где | API для пакетов |
|---|---|---|
| Fence от prompt injection | `ssh_mcp/safety.py` | `fence(text)` — оборачивать `stdout`/`stderr`/`content` |
| Redaction секретов | `ssh_mcp/safety.py` | `register_secrets()`, `scrub()`, `scrub_obj()`; `ok()`/`fail()` чистят автоматически |
| Audit trail JSONL | `ssh_mcp/safety.py` | `audit.record(...)`; `guarded()` пишет сам |
| `guarded(call, *, name, server, summary)` | `ssh_mcp/context.py` | расширенные kwargs `server`/`summary` |
| Снапшот пула | `ssh_mcp/connection.py` | `ConnectionManager.stats() -> dict[str, dict]` |

Проверено: секреты из профилей вычищаются, fence в ответах, `audit.jsonl` пишется
(`server`, `outcome`, `detail`).

---

## Пакеты (WP-1 … WP-5) — всё можно делать одновременно

> **Статус 2026-10-03: WP-1…WP-5 и интеграция выполнены.** Реализовано 24 инструмента
> (было 8) + 2 MCP-ресурса. Приёмка: `ruff` чист, `mypy` чист, 63 теста зелёные,
> сценарии на `vibecoding-prod` и `iq220-internal` (jump-host) пройдены.
> Не сделано из пунктов плана: см. «Осталось» внизу.

### WP-1 · Транспорт и криптография — ГОТОВО
**Файлы (только эти):** `ssh_mcp/connection.py`, `ssh_mcp/models.py`, `ssh_mcp/config.py`, `ssh_mcp/errors.py`
**Инструменты:** 1.4 known_hosts, 1.5 disabled_algorithms, 1.7 лестница auth, 2.13 keepalive

- Свой `known_hosts` рядом с `servers.yaml` (append-only, TOFU), режим `pin` по fingerprint.
- Фикс имени хоста для нестандартного порта: `models.canonical_host_name` идемпотентна.
- `DISABLED_ALGORITHMS`: выключены SHA-1 KEX/подпись, `ssh-rsa`, `diffie-hellman-group1*`, SHA-1 HMAC.
- Лестница `key → agent → password`, ошибки накапливаются, passphrase только байтами.
- `keepalive_interval` из YAML (по умолчанию 30).

Проверено: TOFU создаёт и перечитывает записи, jump-host-цепочка без ретрая.

### WP-2 · Файловые операции — ГОТОВО
**Файлы (только эти):** `ssh_mcp/tools/file_tools.py`, новый `ssh_mcp/tools/fs_tools.py`
**Инструменты:** 1.3 атомарная запись, 2.3 симлинки, 2.5 mkdir/mv/rm/chmod, 2.6 copy_between, 2.11 offset, пагинация

- Запись через tmp + `chmod` + backup + `posix_rename`; симлинк перед заменой резолвится в цель.
- Симлинки: `ssh_stat`, `ssh_read_link`, `ssh_symlink`, `follow_symlinks` с цепочкой хопов.
- `ssh_mkdir` (-p), `ssh_move`, `ssh_remove`, `ssh_chmod`, `ssh_copy_between` между серверами.
- `ssh_read_file(offset, length)`, `ssh_list_files(offset, limit)` с `total`/`has_more`/`next_offset`.

Проверено на проде: атомарная запись, `.bak`, разбиение страниц, `chmod` 0600, `move`,
`copy_between`, `upload/download` атомарные, `remove -r` (12 файлов, 3 каталога).

### WP-3 · Команды и пакетные операции — ГОТОВО
**Файлы (только эти):** `ssh_mcp/tools/exec_tools.py`, новый `ssh_mcp/tools/batch_tools.py`
**Инструменты:** 2.1 run_many, 2.4 фоновые задачи, 2.7 sudo, 2.12 сигналы

- `ssh_run_many(command, servers[], max_workers)` — 2/2 сервера, wall 2.92 с.
- Фоновые задачи: `background=True` → `job_id`, `ssh_job_status`, TTL-уборка.
- `sudo` через stdin (`sudo -p "" -S sh -c`), пароль из профиля, в argv не попадает; режим без prompt.
- `ssh_signal(pid, INT/TERM/KILL)` — лестница, проверка доставки, эскалация.

Проверено: `sudo id` на обоих серверах, `signal TERM` доставлен и подтверждён (`state: gone`).

### WP-4 · Каталог, навигация, аудит — ГОТОВО
**Файлы (только эти):** `ssh_mcp/tools/servers.py`, новый `ssh_mcp/tools/find_tools.py`, `ssh_mcp/safety.py` (только класс `AuditLog`)
**Инструменты:** 2.9 resources, 2.10 ssh_guide, 2.2 рекурсивный поиск, ssh_forget_host_key, аудит-тул

- Ресурсы `ssh://connections` и `ssh://connections/{server}` через `ConnectionManager.stats()`.
- `ssh_guide(topic)`, `ssh_find(pattern, path, max_depth, regex)`, `ssh_audit(limit)`,
  `ssh_forget_host_key(host)`.

### WP-5 · Тесты и эксплуатация — ГОТОВО
**Файлы (только эти):** новый каталог `tests/`, `ssh_mcp/server.py`
**Инструменты:** 3.1 тесты, 3.2 тест на утечки, 3.4 graceful shutdown, 3.6 логи

- `tests/sshd.py` — самодостаточный sshd на paramiko без `paramiko_sshd` (exec + SFTP +
  `direct-tcpip`), 63 теста: протокол, регрессии WP-0, утечки секретов, runtime сервера.
- Graceful shutdown на stdin EOF, `RotatingFileHandler`, `propagate = False`.

---

## Правила для всех агентов

1. **Не трогать чужие файлы.** Свой список — выше; `ssh_mcp/tools/__init__.py` правит **только** интегратор.
2. **Не коммитить.** Работаем в общей директории, коммит у интегратора.
3. **Проверять перед сдачей:** `python -m ruff check .`, `python -m mypy ssh_mcp mcp_server.py --ignore-missing-imports`,
   плюс свой сценарий против реальных серверов из `servers.yaml`.
4. **Стиль:** русские docstring'и (как уже), типизация, frozen dataclass'ы, `from __future__ import annotations`.
5. Новые тулы — только через `guarded(run, name=..., server=server, summary=...)`.
6. Секреты в ответах — нельзя (редакция автоматическая, но и сам не возвращай пароли).

## Интеграция (сделано главным агентом)

1. ✅ `ssh_mcp/tools/__init__.py` → `MODULES = (servers, exec_tools, file_tools, fs_tools,
   batch_tools, find_tools)` + вызов `servers.register_resources`.
2. ✅ `ruff` + `mypy` + сценарии WP-0: fence в ответах, секреты вычищены, `audit.jsonl` пишет
   `server`/`outcome`/`detail`.
3. ✅ `servers.yaml` (рецепты-комментарии видимы агенту, `keepalive_interval`, значения
   `host_key_policy`), `IMPROVEMENTS.md` (статусы), `.gitignore` (`known_hosts`, `*.bak`, job-логи).
4. ✅ Прогон 24 инструментов против обоих серверов, включая jump-host.

## Что закрыто из IMPROVEMENTS.md

WP-0: 1.1, 1.2, 3.3 · WP-1: 1.4, 1.5, 1.7, 2.13 · WP-2: 1.3, 2.3, 2.5, 2.6, 2.11 ·
WP-3: 2.1, 2.4, 2.7, 2.12 · WP-4: 2.2, 2.9, 2.10, 3.7 · WP-5: 3.1, 3.2, 3.4, 3.6

## Осталось (вне этого релиза)

| # | Что | Почему не сейчас |
|---|---|---|
| 1.6 | Права на `.env`/`servers.yaml` (`icacls /inheritance:r` на Windows) | отдельная процедура, риск потерять доступ к секретам |
| 2.8 | `ssh_tunnel_open` (local/remote/dynamic) | нужен доступ к postgres/rocketchat на localhost; большая отдельная фича |
| 3.5 | Hot-reload конфига | текущий снапшот профиля на старте достаточно предсказуем |

## Известные грабли, на которые уже наступили

- **`sftp.mkdir` на существующем каталоге отдаёт `IOError(errno=None, "Failure")`**, а не `EEXIST`.
  Любая проверка `exc.errno != EEXIST` без `lstat`-подтверждения ломает `mkdir -p`.
- **`lstat` несуществующего пути** в `resolve_link_target` ронял атомарную запись нового файла.
- **`sudo` без запроса пароля** закрывает канал раньше, чем пароль отправлен, — слать его нельзя.
- **Тестовый sshd рвал канал `direct-tcpip` раньше времени.** После EOF от цели `_relay` сразу
  возвращал управление и отпускал серверный канал; клиент выходил из `open_channel`, когда канала
  уже не было в `_channels`, и получал «Unable to open channel» — 5 провалов из 10. Теперь канал
  живёт до закрытия от клиента (`_drain_until_client_close`), как и ведёт себя настоящий форвардер.
  Остальные падения того прогона были каскадом: исключение в потоке echo-сервера роняло соседние
  тесты. После фикса — 63 passed в 5 прогонах подряд.