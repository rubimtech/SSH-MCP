"""Общие фикстуры: локальный sshd, реестр серверов и вызов инструментов.

Тесты автономны: поднимают собственный sshd на случайном порту
(:mod:`tests.sshd`) и работают только с временными каталогами. Если paramiko
недоступен, ``sshd``-зависимые тесты пропускаются с явной причиной, а
модульные тесты (WP-0, логи, shutdown) выполняются всегда.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # позволяет запускать pytest из любого каталога
    sys.path.insert(0, str(REPO_ROOT))

from ssh_mcp.config import ServerRegistry, load_registry  # noqa: E402
from ssh_mcp.context import ToolContext  # noqa: E402
from ssh_mcp.safety import audit  # noqa: E402
from ssh_mcp.server import build_server  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover - только для типов
    from fastmcp import FastMCP

    from tests.sshd import TestSshServer

SSHD_IMPORT_REASON = "нужен paramiko — тесты против локального sshd пропущены"


def _yaml_quote(value: str) -> str:
    """Обернуть путь в YAML так, чтобы Windows-обратные слэши не стали escape."""
    return "'" + str(value).replace("'", "''") + "'"


@pytest.fixture(scope="session")
def sshd(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestSshServer]:
    """Один sshd на всю сессию тестов: генерация ключей дорогая."""
    module: ModuleType = pytest.importorskip("tests.sshd", reason=SSHD_IMPORT_REASON)
    root = tmp_path_factory.mktemp("sshd-guest")
    server = module.TestSshServer(root)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _config_text(server: TestSshServer, config_dir: Path) -> str:
    """servers.yaml на три профиля: пароль, ключ с passphrase, цель за jump-host."""
    return f"""# Тестовый конфиг: все серверы указывают на локальный sshd фикстуры.
defaults:
  port: {server.port}
  username: {server.username}
  connect_timeout: 5
  auth_timeout: 5
  host_key_policy: auto_add

settings:
  default_server: testbox
  allowed_local_dirs:
    - {_yaml_quote(config_dir)}
    - {_yaml_quote(server.root)}

servers:
  # Гость с паролем — основной сервер тестов.
  testbox:
    host: {server.host}
    description: Тестовый sshd, вход по паролю
    tags: [test, password]
    default: true
    auth:
      type: password
      password: {_yaml_quote(server.password)}

  # Гость с ключом, защищённым passphrase.
  keybox:
    host: {server.host}
    description: Тестовый sshd, вход по ключу
    tags: [test, key]
    auth:
      type: key
      key_path: {_yaml_quote(server.key_path)}
      passphrase: {_yaml_quote(server.key_passphrase)}

  # Тот же гость, но только через jump-host: проверка цепочки direct-tcpip.
  behind:
    host: {server.host}
    jump_via: testbox
    description: Тестовый sshd за jump-host
    tags: [test, jump]
    auth:
      type: password
      password: {_yaml_quote(server.password)}
"""


@pytest.fixture(scope="session")
def config_dir(tmp_path_factory: pytest.TempPathFactory, sshd: TestSshServer) -> Path:
    """Каталог с тестовым ``servers.yaml``."""
    directory = tmp_path_factory.mktemp("ssh-mcp-config")
    (directory / "servers.yaml").write_text(
        _config_text(sshd, directory),
        encoding="utf-8",
    )
    return directory


@pytest.fixture(scope="session")
def registry(config_dir: Path) -> ServerRegistry:
    """Проверенный реестр из трёх профилей на локальный sshd."""
    return load_registry(config_dir / "servers.yaml")


@pytest.fixture(scope="session")
def ctx(registry: ServerRegistry) -> Iterator[ToolContext]:
    """Общий контекст инструментов и пул соединений на сессию."""
    context = ToolContext.from_registry(registry)
    try:
        yield context
    finally:
        context.connections.close_all()


@pytest.fixture(scope="session")
def mcp(registry: ServerRegistry, ctx: ToolContext) -> FastMCP:
    """Собранный MCP-сервер: тот же объект, что у ``mcp_server.py``."""
    return build_server(registry, ctx)


@pytest.fixture(autouse=True)
def audit_dir(tmp_path: Path) -> Iterator[Path]:
    """Каждый тест пишет ``audit.jsonl`` в свой каталог и возвращает его."""
    previous = audit.path
    directory = tmp_path / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    audit.configure(directory)
    try:
        yield directory
    finally:
        if previous is None:
            audit.close()
        else:
            audit.configure(previous.parent)


class ToolCaller:
    """Вызов инструмента через настоящий MCP-клиент (транспорт в памяти).

    Так тесты проходят тот же путь, что и агент: FastMCP → JSON → ``ok()``.
    """

    def __init__(self, server: FastMCP) -> None:
        self._server = server

    def text(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        """Текст ответа инструмента (инструменты возвращают JSON-строку)."""
        return asyncio.run(self._call(name, arguments or {}))

    def json(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Ответ инструтеля, разобранный из JSON."""
        raw = self.text(name, arguments)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:  # pragma: no cover - диагностика теста
            raise AssertionError(f"{name} вернул не JSON: {raw!r}") from None

    async def _call(self, name: str, arguments: dict[str, Any]) -> str:
        from fastmcp import Client

        async with Client(self._server) as client:
            result = await client.call_tool(name, arguments)
        return "\n".join(
            getattr(part, "text", "")
            for part in getattr(result, "content", [])
        )


@pytest.fixture(scope="session")
def call(mcp: FastMCP) -> ToolCaller:
    """Клиент инструментов для сквозных тестов."""
    return ToolCaller(mcp)