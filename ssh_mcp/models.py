"""Immutable data model for a configured SSH server."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence

from .errors import AuthError

AuthType = Literal["password", "key", "auto"]
HostKeyPolicy = Literal["auto_add", "tofu", "reject", "pin"]
AuthMethod = Literal["key", "agent", "password"]

DEFAULT_KEEPALIVE = 30

# Уже нормализованное paramiko имя вида ``[host]:2222`` — оборачивать второй раз нельзя.
_BRACKETED_HOST = re.compile(r"^\[(?P<host>[^\]]+)\]:(?P<port>\d+)$")


def canonical_host_name(host: str, port: int = 22) -> str:
    """Имя хоста в том виде, в котором paramiko ищет его в ``known_hosts``.

    Paramiko передаёт в политику уже отформатированное имя (``[host]:2222`` для
    нестандартного порта), поэтому повторная обёртка давала бы
    ``[[host]:2222]:2222``, запись не находилась никогда и проверка молча
    исчезала. Функция идемпотентна: ``canonical_host_name(x) == x`` для любого
    ``x``, которое эта же функция уже нормализовала.

    Args:
        host: hostname или IP; ``[::1]`` и ``::1`` эквивалентны.
        port: порт SSH; ``22`` — единственный, для которого скобки не нужны.
    """
    text = (host or "").strip()
    already = _BRACKETED_HOST.match(text)
    if already is not None:
        return f"[{already.group('host')}]:{already.group('port')}"
    bare = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    if int(port) == 22:
        return bare
    return f"[{bare}]:{int(port)}"


@dataclass(frozen=True, slots=True)
class AuthStep:
    """Одна ступень лестницы авторизации.

    ``kwargs`` — аргументы :meth:`paramiko.SSHClient.connect`; ``passphrase``
    передаётся байтами: paramiko на cryptography-бэкенде строки не принимает.
    """

    method: AuthMethod
    kwargs: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        return self.method


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """How to authenticate against one server.

    ``type: auto`` включает лестницу ``key → agent → password``: ступени без
    доступных учётных данных молча пропускаются, а не ломают подключение.
    Явные ``password``/``key`` оставляют поведение предсказуемым: ``password``
    пробует только пароль, ``key`` — ключ, затем агента.
    """

    type: AuthType
    password: str | None = None
    key_path: Path | None = None
    passphrase: str | None = None
    use_agent: bool = True
    password_fallback: bool = True

    def describe(self) -> dict[str, Any]:
        """Что видно про учётные данные: способ и наличие секретов, без их значений.

        Локальный путь к ключу сюда не попадает: подключение должно происходить
        без участия агента, и знать, где лежит приватный ключ, модели не нужно.
        """
        return {
            "type": self.type,
            "key_exists": bool(self.key_path and self.key_path.is_file()),
            "passphrase_configured": bool(self.passphrase),
            "password_configured": bool(self.password),
            "use_agent": self.use_agent,
            "password_fallback": self.password_fallback,
            "methods": list(self.methods()),
        }

    def methods(self) -> tuple[AuthMethod, ...]:
        """Порядок ступеней лестницы без учёта их достижимости."""
        if self.type == "password":
            return ("password",)
        if self.type == "key" and self.key_path is None:
            return ("agent",) if self.use_agent else ()

        steps: list[AuthMethod] = []
        if self.key_path is not None:
            steps.append("key")
        if self.use_agent:
            steps.append("agent")
        if self.password and (self.type == "auto" or self.password_fallback):
            steps.append("password")
        return tuple(steps)

    def auth_plan(self, *, agent_keys: bool = False) -> tuple[tuple[AuthStep, ...], tuple[str, ...]]:
        """Готовая лестница и список пропущенных ступеней с причинами.

        Args:
            agent_keys: есть ли у локального ``ssh-agent`` ключи. Ступень агента
                без ключей бесполезна и стоила бы лишнего хендшейка.

        Returns:
            Пара ``(ступени, пропущенные)``; пропущенные нужны для внятной
            ошибки, когда не сработала ни одна ступень.
        """
        steps: list[AuthStep] = []
        skipped: list[str] = []

        for method in self.methods():
            if method == "key":
                if self.key_path is None:
                    skipped.append("key: no key_path configured")
                elif not self.key_path.is_file():
                    skipped.append(f"key: file not found ({self.key_path.name})")
                else:
                    steps.append(
                        AuthStep(
                            method="key",
                            kwargs={
                                "key_filename": str(self.key_path),
                                "passphrase": (
                                    self.passphrase.encode("utf-8") if self.passphrase else None
                                ),
                                "allow_agent": False,
                                "look_for_keys": False,
                            },
                        )
                    )
            elif method == "agent":
                if not agent_keys:
                    skipped.append("agent: ssh-agent has no keys")
                    continue
                steps.append(
                    AuthStep(
                        method="agent",
                        kwargs={"allow_agent": True, "look_for_keys": True},
                    )
                )
            else:
                steps.append(
                    AuthStep(
                        method="password",
                        kwargs={
                            "password": self.password,
                            "allow_agent": False,
                            "look_for_keys": False,
                        },
                    )
                )
        return tuple(steps), tuple(skipped)

    def paramiko_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for :meth:`paramiko.SSHClient.connect`.

        Возвращает аргументы первой ступени лестницы: этого достаточно там, где
        вызывающий код умеет только один способ аутентификации.
        """
        steps, skipped = self.auth_plan()
        if not steps:
            detail = f" — skipped: {'; '.join(skipped)}" if skipped else ""
            raise AuthError(f"No usable SSH credentials configured{detail}", attempts=skipped)
        return dict(steps[0].kwargs)


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """One entry of the ``servers:`` section in ``servers.yaml``."""

    name: str
    host: str
    username: str
    port: int
    auth: AuthConfig
    description: str = ""
    comments: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    jump_via: str | None = None
    default_workdir: str | None = None
    connect_timeout: int = 30
    auth_timeout: int = 30
    host_key_policy: HostKeyPolicy = "auto_add"
    known_hosts: Path | None = None
    host_key_fingerprint: str | None = None
    keepalive_interval: int = DEFAULT_KEEPALIVE
    is_default: bool = False
    defined_at: str = ""

    @property
    def target(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    @property
    def host_key_name(self) -> str:
        """Каноническое имя сервера в собственном ``known_hosts``."""
        return canonical_host_name(self.host, self.port)

    def summary(self) -> dict[str, Any]:
        """Вид для оператора: всё, включая координаты подключения.

        В ответах инструментов использовать нельзя — там работает
        :meth:`public`, потому что модель не должна видеть, как именно
        происходит подключение.
        """
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "is_default": self.is_default,
            "description": self.description,
            "comments": list(self.comments),
            "tags": list(self.tags),
            "jump_via": self.jump_via,
            "default_workdir": self.default_workdir,
            "connect_timeout": self.connect_timeout,
            "auth_timeout": self.auth_timeout,
            "host_key_policy": self.host_key_policy,
            "host_key_fingerprint": self.host_key_fingerprint,
            "host_key_name": self.host_key_name,
            "known_hosts": str(self.known_hosts) if self.known_hosts else None,
            "keepalive_interval": self.keepalive_interval,
            "auth": self.auth.describe(),
            "defined_at": self.defined_at,
        }

    def public(self, *, jump_chain: Sequence[str] = ()) -> dict[str, Any]:
        """Единственный вид, который видит модель.

        Подключение должно происходить без участия агента, поэтому наружу
        отдаются только имя, описание и способ выбрать сервер. Всё, чем
        подключение устроено внутри — адрес, порт, логин, пути на этой машине,
        отпечатки ключей, таймауты, — убрано: модели это не помогает, зато
        попадает в её контекст, логи и скриншоты диалога.

        Args:
            jump_chain: полная цепочка прыжков (имена серверов, не адреса).
        """
        return {
            "name": self.name,
            "is_default": self.is_default,
            "description": self.description,
            "comments": list(self.comments),
            "tags": list(self.tags),
            "jump_chain": list(jump_chain),
            "default_workdir": self.default_workdir,
            "auth": self.auth.describe(),
        }