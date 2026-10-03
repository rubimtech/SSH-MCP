"""Тест «секреты не утекают» (3.2).

Проверяются все места, откуда секрет может уехать к агенту или на диск:
описание профиля, вывод команд, содержимое файлов, ошибки и ``audit.jsonl``.
"""

from __future__ import annotations

import json

import pytest

from ssh_mcp.safety import PEM_PLACEHOLDER, PLACEHOLDER

from .conftest import ToolCaller


def _assert_clean(payload: str, sshd, *, where: str) -> None:
    """Проверить, что в тексте нет пароля, passphrase и приватного ключа."""
    assert sshd.password not in payload, f"пароль гостя утёк в {where}"
    assert sshd.key_passphrase not in payload, f"passphrase утёк в {where}"
    assert "BEGIN RSA PRIVATE KEY" not in payload, f"приватный ключ утёк в {where}"


def test_describe_не_раскрывает_учётные_данные(call: ToolCaller, sshd) -> None:
    """``ssh_server_info`` отдаёт профиль, но не сам пароль и не ключ."""
    payload = call.json("ssh_server_info", {"server": "testbox"})
    text = json.dumps(payload, ensure_ascii=False)

    assert payload["name"] == "testbox"
    assert payload["auth"]["password_configured"] is True
    assert payload["auth"]["passphrase_configured"] is False
    assert payload["probe"]["reachable"] is True
    _assert_clean(text, sshd, where="ssh_server_info")


def test_describe_для_ключа_не_раскрывает_passphrase(call: ToolCaller, sshd) -> None:
    """Профиль с ключом показывает факт наличия passphrase, но не саму фразу."""
    payload = call.json("ssh_server_info", {"server": "keybox"})
    text = json.dumps(payload, ensure_ascii=False)

    assert payload["auth"]["type"] == "key"
    assert payload["auth"]["passphrase_configured"] is True
    assert payload["auth"]["key_exists"] is True
    _assert_clean(text, sshd, where="ssh_server_info[keybox]")


def test_списоксерверов_не_раскрывает_секреты(call: ToolCaller, sshd) -> None:
    """``ssh_list_servers`` — единственный инструмент, который всегда доступен."""
    payload = call.json("ssh_list_servers")

    assert payload["count"] == 3
    _assert_clean(json.dumps(payload, ensure_ascii=False), sshd, where="ssh_list_servers")


def test_вывод_команды_чистит_пароль(call: ToolCaller, sshd) -> None:
    """Команда, печатающая пароль, всё равно не отдаёт его агенту."""
    payload = call.json("ssh_execute", {"command": "secret", "server": "testbox"})

    assert PLACEHOLDER in payload["stdout"]
    _assert_clean(json.dumps(payload, ensure_ascii=False), sshd, where="ssh_execute")


def test_вывод_команды_чистит_приватный_ключ(call: ToolCaller, sshd) -> None:
    """PEM-блок в выводе закрывается плейсхолдером."""
    payload = call.json("ssh_execute", {"command": "pem", "server": "testbox"})

    assert PEM_PLACEHOLDER in payload["stdout"]
    _assert_clean(json.dumps(payload, ensure_ascii=False), sshd, where="ssh_execute[pem]")


def test_вывод_команды_чистит_секреты_из_окружения(call: ToolCaller, sshd) -> None:
    """`env` на сервере тоже чистится: пароль не всплывает через окружение."""
    payload = call.json("ssh_execute", {"command": "env", "server": "testbox"})

    assert "DB_PASSWORD" in payload["stdout"]
    assert PLACEHOLDER in payload["stdout"]
    _assert_clean(json.dumps(payload, ensure_ascii=False), sshd, where="ssh_execute[env]")


def test_чтение_файла_с_секретом_чистит_содержимое(call: ToolCaller, sshd) -> None:
    """Файл с паролем на диске сервера читается уже вычищенным."""
    sshd.write_file("leaks/.env", f"DB_PASSWORD={sshd.password}\n")

    payload = call.json("ssh_read_file", {"remote_path": "leaks/.env", "server": "testbox"})

    assert PLACEHOLDER in payload["content"]
    _assert_clean(json.dumps(payload, ensure_ascii=False), sshd, where="ssh_read_file")


def test_ошибка_аутентификации_не_раскрывает_пароль(tmp_path, sshd) -> None:
    """Текст ошибки не содержит пароль профиля, даже если тот зарегистрирован."""
    from ssh_mcp.config import load_registry
    from ssh_mcp.connection import ConnectionManager
    from ssh_mcp.context import ToolContext
    from ssh_mcp.responses import ok

    wrong = "wrong-password-for-the-box"
    config = tmp_path / "broken.yaml"
    config.write_text(
        f"""servers:
  brokenbox:
    host: {sshd.host}
    port: {sshd.port}
    username: {sshd.username}
    connect_timeout: 5
    auth_timeout: 5
    auth:
      type: password
      password: {wrong}
""",
        encoding="utf-8",
    )
    registry = load_registry(config)
    ToolContext.from_registry(registry)
    manager = ConnectionManager(registry)

    with pytest.raises(Exception) as failure:  # noqa: BLE001 - проверяем текст
        with manager.client(registry.get("brokenbox")):
            pass

    rendered = ok({"error": f"{type(failure.value).__name__}: {failure.value}"})
    assert wrong not in rendered
    assert "Authentication failed" in rendered


def test_audit_jsonl_не_хранит_секреты(call: ToolCaller, sshd, audit_dir) -> None:
    """Журнал вызовов не должен сохранять пароль на диск."""
    call.json("ssh_execute", {"command": f"echo {sshd.password}", "server": "testbox"})
    call.json("ssh_read_file", {"remote_path": "leaks/.env", "server": "testbox"})

    trail = (audit_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert trail.strip(), "audit trail должен что-то записать"
    assert sshd.password not in trail
    assert sshd.key_passphrase not in trail
    for line in trail.splitlines():
        entry = json.loads(line)
        assert set(entry) >= {"ts", "tool", "server", "outcome", "detail"}


def test_аудит_фиксирует_server_outcome_detail(call: ToolCaller, audit_dir) -> None:
    """Каждый вызов оставляет сервер, исход и детали вызова."""
    call.json("ssh_execute", {"command": "uname -srm", "server": "testbox"})
    call.json("ssh_execute", {"command": "uptime", "server": "nope"})

    entries = [json.loads(line) for line in (audit_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    ok_entries = [item for item in entries if item["outcome"] == "ok"]
    error_entries = [item for item in entries if item["outcome"] != "ok"]

    assert any(item["server"] == "testbox" and item["tool"] == "ssh_execute" for item in ok_entries)
    assert any(item["outcome"] == "error" for item in error_entries)


def test_fence_присутствует_в_ответах_с_выводом(call: ToolCaller) -> None:
    """Инъекция с сервера остаётся данными, а не инструкциями для модели."""
    payload = call.json("ssh_execute", {"command": "inject", "server": "testbox"})

    assert payload["stdout"].startswith("<<<ВЫВОД СЕРВЕРА")
    assert payload["stdout"].endswith("<<<КОНЕЦ ВЫВОДА СЕРВЕРА>>>")


def test_инструкции_сервера_объясняют_fence(registry) -> None:
    """Правило fence дублируется в INSTRUCTIONS — агент знает про маркеры."""
    from ssh_mcp.server import INSTRUCTIONS

    assert "ВЫВОД СЕРВЕРА" in INSTRUCTIONS
    assert "untrusted data" in INSTRUCTIONS


def test_список_инструментов_доступен(mcp) -> None:
    """Все инструменты видны агенту: тесты ходят по тому же пути."""
    import asyncio

    from fastmcp import Client

    async def names() -> list[str]:
        async with Client(mcp) as client:
            return sorted(tool.name for tool in await client.list_tools())

    tools = asyncio.run(names())

    assert "ssh_execute" in tools
    assert "ssh_read_file" in tools
    assert "ssh_server_info" in tools
    assert len(tools) >= 20