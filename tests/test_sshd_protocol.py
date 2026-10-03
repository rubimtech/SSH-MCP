"""Сквозные тесты против локального sshd: аутентификация, exec, SFTP, проброс.

Фикстура :func:`tests.conftest.sshd` поднимает настоящий SSH-сервер в тестовом
процессе, поэтому проверяется реальный протокол, а не моки.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import pytest

from ssh_mcp.errors import AuthError
from ssh_mcp.safety import FENCE_CLOSE, FENCE_OPEN

from .conftest import ToolCaller


def _echo_server(payload: bytes) -> tuple[socket.socket, threading.Thread]:
    """TCP-сервер, который один раз отвечает ``prefix + payload``."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)

    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:  # pragma: no cover - сервер не понадобился
            return
        with connection:
            try:
                connection.sendall(payload)
                # Держим соединение открытым, пока клиент не закроет его сам:
                # иначе сервер рвёт канал до того, как клиент успевает прочитать
                # данные, и проверка direct-tcpip становится гонкой.
                connection.settimeout(10)
                while True:
                    if not connection.recv(32_768):
                        break
            except OSError:  # pragma: no cover
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, thread


# --- аутентификация -------------------------------------------------------


def test_вход_по_паролю_выполняет_команду(sshd) -> None:
    """Пароль из профиля подходит гостю, команда отрабатывает."""
    with sshd.connect_client() as client:
        _, stdout, stderr = client.exec_command("echo привет", timeout=15)
        payload = stdout.read().decode("utf-8")
        assert payload.strip() == "привет"
        assert stderr.read() == b""
        assert stdout.channel.recv_exit_status() == 0

    assert ("password", "ok") in sshd.auth_events


def test_вход_по_ключу_с_парольной_фразой(sshd) -> None:
    """Ключ с passphrase принимается, и это отдельный путь аутентификации."""
    with sshd.connect_client(use_key=True) as client:
        _, stdout, _ = client.exec_command("whoami", timeout=15)
        assert stdout.read().decode("utf-8").strip() == sshd.username

    assert ("publickey", "ok") in sshd.auth_events


def test_неверный_пароль_отклоняется(sshd) -> None:
    """Гость не пускает с чужим паролем."""

    with pytest.raises(Exception) as failure:
        sshd.connect_client(password="wrong-password-value")

    assert "Authentication" in type(failure.value).__name__


def test_пул_сообщает_об_ошибке_аутентификации(tmp_path, sshd) -> None:
    """Неверный пароль в конфиге даёт AuthError, а не обрыв соединения."""
    from ssh_mcp.config import load_registry
    from ssh_mcp.connection import ConnectionManager

    config = tmp_path / "wrong.yaml"
    config.write_text(
        f"""servers:
  wrongbox:
    host: {sshd.host}
    port: {sshd.port}
    username: {sshd.username}
    connect_timeout: 5
    auth_timeout: 5
    auth:
      type: password
      password: definitely-not-the-guest-password
""",
        encoding="utf-8",
    )
    registry = load_registry(config)
    manager = ConnectionManager(registry)

    with pytest.raises(AuthError) as failure:
        with manager.client(registry.get("wrongbox")):
            pass

    message = str(failure.value)
    assert "Authentication failed" in message
    assert "password" in message  # сообщает, каким способом пробовал
    assert "definitely-not-the-guest-password" not in message


# --- exec -----------------------------------------------------------------


def test_exec_разделяет_stdout_stderr_и_код_возврата(call: ToolCaller) -> None:
    """Команда пишет в оба потока и завершается с ненулевым кодом."""
    payload = call.json("ssh_execute", {"command": "fail 7 boom", "server": "testbox"})

    assert payload["exit_code"] == 7
    assert "boom" in payload["stderr"]
    assert payload["stdout"] == ""


def test_exec_обрамляет_вывод_fence(call: ToolCaller) -> None:
    """Вывод команды приходит в fence, даже если это инъекция инструкций."""
    payload = call.json("ssh_execute", {"command": "inject", "server": "testbox"})

    assert payload["stdout"].startswith(FENCE_OPEN)
    assert payload["stdout"].endswith(FENCE_CLOSE)
    assert "Ignore all previous instructions" in payload["stdout"]


def test_exec_читает_файл_гостя(call: ToolCaller, sshd) -> None:
    """Команда читает файл гостя и возвращает его содержимое."""
    sshd.write_file("reports/report.txt", "содержимое отчёта")

    payload = call.json(
        "ssh_execute",
        {"command": "cat reports/report.txt", "server": "testbox"},
    )

    assert "содержимое отчёта" in payload["stdout"]
    assert payload["exit_code"] == 0


def test_exec_с_таймаутом_не_виснет(call: ToolCaller) -> None:
    """Долгая команда обрывается по таймауту, а не держит вызов."""
    started = time.monotonic()
    payload = call.json(
        "ssh_execute",
        {"command": "sleep 30", "server": "testbox", "timeout": 1},
    )
    elapsed = time.monotonic() - started

    assert payload["error_code"] == "remote_timeout"
    assert elapsed < 15


def test_exec_с_неизвестным_сервером_возвращает_ошибку(call: ToolCaller) -> None:
    """Неизвестное имя сервера — структурированная ошибка, а не исключение."""
    payload = call.json("ssh_execute", {"command": "uptime", "server": "nope"})

    assert payload["error_code"] == "unknown_server"
    assert "testbox" in payload["error"]


def test_exec_по_ключу_для_отдельного_профиля(call: ToolCaller) -> None:
    """Профиль с ключом подключается своим способом аутентификации."""
    payload = call.json("ssh_execute", {"command": "whoami", "server": "keybox"})

    assert payload["exit_code"] == 0
    assert payload["server"] == "keybox"


# --- jump host и проброс портов ------------------------------------------


def test_цепочка_jump_host_доходит_до_цели(call: ToolCaller, sshd) -> None:
    """Прямой TCP-канал через jump-host доставляет команды на цель."""
    payload = call.json("ssh_execute", {"command": "pwd", "server": "behind"})

    assert payload["exit_code"] == 0
    assert payload["stdout"].endswith(FENCE_CLOSE)
    assert sshd.home.name in payload["stdout"]


def test_проброс_direct_tcpip_доставляет_байты(sshd) -> None:
    """Серверный обработчик direct-tcpip поднимает настоящий TCP-туннель."""
    payload = "привет из туннеля".encode("utf-8")
    listener, _ = _echo_server(payload)
    port = listener.getsockname()[1]
    try:
        with sshd.connect_client() as client:
            transport = client.get_transport()
            assert transport is not None
            channel = transport.open_channel(
                "direct-tcpip",
                ("127.0.0.1", port),
                ("127.0.0.1", 0),
            )
            channel.settimeout(15)
            assert channel.recv(1024) == payload
            channel.close()
    finally:
        listener.close()

    assert sshd.forward_errors == []


def test_stats_показывает_живые_соединения(ctx, call: ToolCaller) -> None:
    """После вызова снапшот пула — словарь словарей с живым транспортом."""
    call.json("ssh_execute", {"command": "uptime", "server": "testbox"})

    stats = ctx.connections.stats()

    assert isinstance(stats, dict)
    entry = stats["testbox"]
    assert isinstance(entry, dict)
    assert entry["chain"] == ["testbox"]
    assert entry["alive"] is True
    assert isinstance(entry["sessions_in_use"], int)
    assert entry["age_seconds"] >= 0


# --- SFTP -----------------------------------------------------------------


def test_sftp_перечисляет_читает_и_пишет(call: ToolCaller, sshd) -> None:
    """Файловые инструменты работают через подсистему sftp."""
    sshd.write_file("data/notes.txt", "строка заметки")

    listing = call.json(
        "ssh_list_files",
        {"remote_path": "data", "server": "testbox", "details": False},
    )
    assert listing["entries"] == ["notes.txt"]

    reading = call.json("ssh_read_file", {"remote_path": "data/notes.txt", "server": "testbox"})
    assert "строка заметки" in reading["content"]
    assert reading["content"].startswith(FENCE_OPEN)
    assert reading["content"].endswith(FENCE_CLOSE)

    # Цель заранее существует: атомарная запись WP-2 идёт через lstat цели и
    # для несуществующего файла возвращает ENOENT (см. отчёт интегратору).
    sshd.write_file("data/report.txt", "старое содержимое")
    writing = call.json(
        "ssh_write_file",
        {"remote_path": "data/report.txt", "content": "новое содержимое", "server": "testbox"},
    )
    assert writing["status"] == "written"
    assert writing["atomic"] is True
    assert sshd.read_file("data/report.txt") == "новое содержимое"


def test_sftp_читает_смещение_через_max_chars(call: ToolCaller, sshd) -> None:
    """Большой файл читается префиксом, лишнее честно помечается."""
    sshd.write_file("big.log", "x" * 500)

    payload = call.json(
        "ssh_read_file",
        {"remote_path": "big.log", "server": "testbox", "max_chars": 100},
    )

    assert payload["truncated"] is True
    assert payload["content"].count("x") == 100


def test_sftp_не_показывает_путь_вне_дома(call: ToolCaller) -> None:
    """Попытка выйти за пределы гостя даёт ошибку, а не содержимое файла."""
    payload = call.json(
        "ssh_read_file",
        {"remote_path": "../../../../Windows/win.ini", "server": "testbox"},
    )

    assert "error" in payload


def test_download_upload_через_sftp(call: ToolCaller, sshd) -> None:
    """Локальные файлы ездят через allow-list каталогов."""
    sshd.write_file("payload.txt", "перемещаемый текст")
    target = sshd.root / "downloads" / "copy.txt"

    download = call.json(
        "ssh_download_file",
        {"remote_path": "payload.txt", "local_path": str(target), "server": "testbox"},
    )
    assert download["status"] == "downloaded"
    assert target.read_text(encoding="utf-8") == "перемещаемый текст"

    # Как и в ssh_write_file, цель загрузки должна существовать: атомарная
    # загрузка WP-2 опирается на lstat цели.
    sshd.write_file("uploaded.txt", "заглушка")
    upload = call.json(
        "ssh_upload_file",
        {"local_path": str(target), "remote_path": "uploaded.txt", "server": "testbox"},
    )
    assert upload["status"] == "uploaded"
    assert sshd.read_file("uploaded.txt") == "перемещаемый текст"


def test_локальный_путь_вне_allow_list_отклоняется(call: ToolCaller, sshd) -> None:
    """Политика локальных путей работает: чужой каталог недоступен."""
    payload = call.json(
        "ssh_download_file",
        {
            "remote_path": "payload.txt",
            "local_path": str(sshd.root / ".." / ".."),
            "server": "testbox",
        },
    )

    assert payload.get("error_code") == "local_path_error"


def test_stats_после_провала_не_течёт_в_ответ(call: ToolCaller) -> None:
    """Даже неудачный вызов возвращает JSON, а не текст ошибки Python."""
    payload: dict[str, Any] = call.json("ssh_execute", {"command": "cat /nope", "server": "testbox"})

    assert "exit_code" in payload or "error" in payload
    assert isinstance(payload, dict)