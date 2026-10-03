"""Эксплуатация: graceful shutdown на stdin EOF и журналирование (3.4, 3.6).

Тесты поднимают настоящий процесс ``mcp_server.py`` и общаются с ним по stdio,
поэтому проверяется ровно то, что увидит MCP-клиент.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from ssh_mcp import server as server_module
from ssh_mcp.config import ENV_LOG_LEVEL

REPO_ROOT = Path(__file__).resolve().parent.parent
SHUTDOWN_TIMEOUT = 30

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ssh-mcp-tests", "version": "0"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}

#: Порт, на котором заведомо никто не слушает: конфиг нужен только для старта.
DEAD_PORT = 65021

STUB_CONFIG = """# Конфиг для проверки жизненного цикла: подключаться никто не будет.
defaults:
  port: {port}
  username: nobody
  connect_timeout: 2
  auth_timeout: 2

settings:
  default_server: stub
  allowed_local_dirs:
    - {directory}

servers:
  # Заглушка: нужна только чтобы процесс загрузил конфигурацию.
  stub:
    host: 127.0.0.1
    description: Заглушка для тестов жизненного цикла
    auth:
      type: password
      password: stub-password-for-lifecycle-tests
"""


def _start_process(config: Path, log_file: Path | None = None) -> subprocess.Popen[str]:
    """Запустить ``mcp_server.py`` с отдельными каналами stdio."""
    env = dict(os.environ)
    env[ENV_LOG_LEVEL] = "INFO"
    # Дочерний процесс пишет по-русски: без UTF-8 в канале будет мусор.
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if log_file is not None:
        env[server_module.ENV_LOG_FILE] = str(log_file)
    return subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "mcp_server.py"), str(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        encoding="utf-8",
    )


def _read_line_within(process: subprocess.Popen[str], timeout: float) -> str:
    """Прочитать строку ответа сервера, не зависнув навечно."""
    assert process.stdout is not None
    lines: list[str] = []

    def read() -> None:
        lines.append(process.stdout.readline())  # type: ignore[union-attr]

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():  # pragma: no cover - диагностика зависания
        process.kill()
        raise AssertionError(f"сервер не ответил за {timeout} с")
    return lines[0] if lines else ""


def _handshake(process: subprocess.Popen[str]) -> dict:
    """Отправить initialize и дождаться ответа сервера."""
    assert process.stdin is not None
    process.stdin.write(json.dumps(INITIALIZE) + "\n")
    process.stdin.write(json.dumps(INITIALIZED) + "\n")
    process.stdin.flush()

    line = _read_line_within(process, SHUTDOWN_TIMEOUT)
    assert line, "сервер не ответил на initialize"
    return json.loads(line)


def _close_stdin_and_wait(process: subprocess.Popen[str]) -> tuple[int, str]:
    """Закрыть stdin (уход клиента) и дождаться завершения процесса."""
    assert process.stdin is not None
    process.stdin.close()
    try:
        code = process.wait(timeout=SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:  # pragma: no cover - диагностика зависания
        process.kill()
        raise AssertionError("сервер не завершился после EOF на stdin")
    stderr = process.stderr.read() if process.stderr else ""
    return code, stderr


@pytest.fixture()
def stdio_config(tmp_path: Path) -> Path:
    """Рабочий ``servers.yaml`` для фонового процесса (sshd не нужен)."""
    directory = tmp_path / "config"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "servers.yaml"
    path.write_text(
        STUB_CONFIG.format(port=DEAD_PORT, directory=str(directory).replace("\\", "/")),
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def logging_state() -> Iterator[None]:
    """Вернуть состояние logging после теста, который его перенастраивает."""
    root = logging.getLogger()
    package = logging.getLogger(server_module.PACKAGE_LOGGER)
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_package_handlers = list(package.handlers)
    saved_package_level = package.level
    saved_propagate = package.propagate
    try:
        yield
    finally:
        root.handlers = saved_handlers
        root.level = saved_level
        package.handlers = saved_package_handlers
        package.level = saved_package_level
        package.propagate = saved_propagate


def _flush(package: logging.Logger) -> None:
    """Сбросить буферы файловых обработчиков, не трогая логи pytest."""
    for handler in package.handlers:
        handler.flush()


# --- graceful shutdown ----------------------------------------------------


def test_процесс_завершается_на_eof_стандина(stdio_config: Path) -> None:
    """Уход клиента (EOF на stdin) останавливает сервер с кодом 0."""
    process = _start_process(stdio_config)

    response = _handshake(process)
    assert response["result"]["serverInfo"]["name"] == "ssh_mcp"

    code, stderr = _close_stdin_and_wait(process)

    assert code == 0
    assert "Traceback" not in stderr


def test_процесс_закрывает_пул_перед_выходом(stdio_config: Path) -> None:
    """После EOF в stderr видно штатную остановку, а не исключение."""
    process = _start_process(stdio_config)
    _handshake(process)

    _, stderr = _close_stdin_and_wait(process)

    assert "MCP server stopped" in stderr
    assert "Traceback" not in stderr


def test_битый_конфиг_даёт_код_2(tmp_path: Path) -> None:
    """Ошибка конфигурации — это код 2 и запись в stderr, а не трассировка."""
    broken = tmp_path / "broken.yaml"
    broken.write_text("servers: {}\n", encoding="utf-8")

    process = _start_process(broken)
    _, stderr = process.communicate(timeout=SHUTDOWN_TIMEOUT)

    assert process.returncode == 2
    assert "Configuration error" in stderr
    assert "Traceback" not in stderr


def test_вызов_main_с_битым_конфигом_возвращает_2(tmp_path: Path, logging_state) -> None:
    """Тот же код возвращается при вызове :func:`ssh_mcp.server.main`."""
    broken = tmp_path / "broken.yaml"
    broken.write_text("servers: {}\n", encoding="utf-8")

    code = server_module.main([str(broken)])

    assert code == 2


# --- журналирование ------------------------------------------------------


def test_логи_пишутся_в_файл_рядом_с_конфигом(stdio_config: Path) -> None:
    """Старт сервера оставляет след в ротируемом файле журнала."""
    log_file = stdio_config.parent / server_module.LOG_FILENAME
    process = _start_process(stdio_config)

    _handshake(process)
    _close_stdin_and_wait(process)

    written = log_file.read_text(encoding="utf-8")
    assert "Loaded" in written
    assert "MCP server stopped" in written


def test_путь_журнала_переопределяется_окружением(stdio_config: Path, tmp_path: Path) -> None:
    """``SSH_MCP_LOG_FILE`` переносит журнал туда, куда указали."""
    log_file = tmp_path / "custom" / "journal.log"
    process = _start_process(stdio_config, log_file=log_file)

    _handshake(process)
    _close_stdin_and_wait(process)

    assert "Loaded" in log_file.read_text(encoding="utf-8")
    assert not (stdio_config.parent / server_module.LOG_FILENAME).exists()


def test_stdout_содержит_только_протокол(stdio_config: Path) -> None:
    """В stdout не попадают ни логи, ни баннер — только JSON-RPC."""
    process = _start_process(stdio_config)
    assert process.stdin is not None
    process.stdin.write(json.dumps(INITIALIZE) + "\n")
    process.stdin.flush()
    process.stdin.close()

    stdout, _ = process.communicate(timeout=SHUTDOWN_TIMEOUT)

    lines = [line for line in stdout.splitlines() if line.strip()]
    assert lines, "сервер не ответил на initialize"
    for line in lines:
        json.loads(line)


def test_configure_logging_подключает_файл_и_глушит_propagate(
    tmp_path: Path, logging_state
) -> None:
    """Файловый обработчик добавлен, а propagate у пакета выключен."""
    log_file = tmp_path / "logs" / "ssh-mcp.log"

    package = server_module.configure_logging(log_file)

    assert package.propagate is False
    assert any(
        isinstance(handler, logging.handlers.RotatingFileHandler)
        for handler in package.handlers
    )
    logging.getLogger("ssh_mcp.test").info("проверка файла журнала")
    _flush(package)

    assert "проверка файла журнала" in log_file.read_text(encoding="utf-8")


def test_configure_logging_без_файла_пишет_только_в_stderr(
    tmp_path: Path, logging_state
) -> None:
    """Без файла журнал остаётся на stderr и не создаёт мусор на диске."""
    package = server_module.configure_logging(None)

    assert package.handlers
    assert not any(
        isinstance(handler, logging.FileHandler) for handler in package.handlers
    )


def test_configure_logging_идемпотентна(tmp_path: Path, logging_state) -> None:
    """Повторная настройка не копит обработчики."""
    log_file = tmp_path / "ssh-mcp.log"

    first = server_module.configure_logging(log_file)
    count = len(first.handlers)
    second = server_module.configure_logging(log_file)

    assert len(second.handlers) == count


def test_ротация_создаёт_ротированные_файлы(
    tmp_path: Path, logging_state, monkeypatch
) -> None:
    """Файл переполняется — появляются ``.1``, ``.2`` и так далее."""
    monkeypatch.setattr(server_module, "MAX_LOG_BYTES", 512)
    log_file = tmp_path / "ssh-mcp.log"

    package = server_module.configure_logging(log_file)
    for index in range(200):
        logging.getLogger("ssh_mcp.test").info("строка журнала %04d %s", index, "x" * 40)
    _flush(package)

    rotated = sorted(path.name for path in tmp_path.iterdir())
    assert "ssh-mcp.log" in rotated
    assert "ssh-mcp.log.1" in rotated
    assert log_file.stat().st_size <= 4096
    assert package.level >= logging.INFO


def test_resolve_log_file_учитывает_окружение(tmp_path: Path, monkeypatch) -> None:
    """``SSH_MCP_LOG_FILE`` переопределяет путь, значение ``off`` его выключает."""
    monkeypatch.delenv(server_module.ENV_LOG_FILE, raising=False)
    assert server_module.resolve_log_file(tmp_path / "servers.yaml") == (
        tmp_path / server_module.LOG_FILENAME
    )

    target = tmp_path / "custom.log"
    monkeypatch.setenv(server_module.ENV_LOG_FILE, str(target))
    assert server_module.resolve_log_file(tmp_path / "servers.yaml") == target

    monkeypatch.setenv(server_module.ENV_LOG_FILE, "off")
    assert server_module.resolve_log_file(tmp_path / "servers.yaml") is None


def test_уровень_логов_берётся_из_окружения(monkeypatch, logging_state) -> None:
    """``SSH_MCP_LOG_LEVEL=DEBUG`` действительно включает отладку."""
    monkeypatch.setenv(ENV_LOG_LEVEL, "DEBUG")

    package = server_module.configure_logging(None)

    assert package.level == logging.DEBUG


def test_отказ_открыть_файл_не_ломает_запуск(tmp_path: Path, logging_state, monkeypatch) -> None:
    """Если файл журнала недоступен, сервер продолжает писать в stderr."""

    def broken(_self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(Path, "mkdir", broken)

    package = server_module.configure_logging(tmp_path / "ssh-mcp.log")

    assert package.handlers
    logging.getLogger("ssh_mcp.test").info("живём без файла")


def test_is_client_gone_отличает_обрыв_от_поломки() -> None:
    """Обрыв клиента — штатная причина, ошибка сервера — нет."""
    assert server_module._is_client_gone(EOFError())
    assert server_module._is_client_gone(BrokenPipeError())
    assert server_module._is_client_gone(RuntimeError("closed resource"))
    assert not server_module._is_client_gone(RuntimeError("boom"))


def test_инструкции_объясняют_fence() -> None:
    """Инструкции сервера остаются непустым текстом с правилом fence."""
    assert server_module.INSTRUCTIONS
    assert "servers.yaml" in server_module.INSTRUCTIONS
    assert "ВЫВОД СЕРВЕРА" in server_module.INSTRUCTIONS