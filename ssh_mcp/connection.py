"""Paramiko connection handling: auth ladder, host-key trust, pooling, async offloading.

Handshakes are expensive (one per hop), so established clients are pooled per
server and shared by concurrent tool calls: paramiko guards channel opening with
an internal lock, so many threads may multiplex sessions over one transport.
The pool is designed for parallel use:

* per-server locks, so connecting to one server never blocks another;
* reference counting, so a session shutting down cannot close connections that
   other in-flight calls are still using;
* a bounded number of concurrent sessions per server, staying under the
  ``MaxSessions`` limit of a stock OpenSSH server;
* one transparent retry when a pooled transport turns out to be dead.

Blocking paramiko calls are moved off the event loop with :func:`asyncio.to_thread`.

Three transport-level concerns live here as well:

* **Auth ladder** ``key → agent → password`` — every rung gets a fresh client and
  a fresh jump-host channel, and the resulting error lists what was tried and
  what was skipped (see :class:`~ssh_mcp.models.AuthConfig`).
* **Host-key trust** — TOFU/pin over a private ``known_hosts`` file next to
  ``servers.yaml`` (see :class:`HostKeyStore`). The user's ``~/.ssh/known_hosts``
  is never written by paramiko (``HostKeys.save()`` would rewrite it and silently
  drop ``@cert-authority``/``@revoked``); it is only read, and the trust found
  there is *adopted* into our file, so a pin can never be bypassed by it.
* **Crypto freeze and keepalive** — SHA-1 based key exchange, RSA/SHA-1
  signatures and SHA-1 MACs are refused (see :data:`DISABLED_ALGORITHMS`), and
  the transport sends keepalives every 30 s because both hosts run
  ``clientaliveinterval 0`` behind NAT.

Timeouts are deliberately asymmetric: a hop that does not answer within
:data:`HANDSHAKE_TIMEOUTS` is retried on the *same* jump transport instead of
rebuilding the chain, because measured on the real hosts the handshake either
takes 0.7 s or never happens at all — an overloaded sshd just stays silent.
"""

from __future__ import annotations

import asyncio
import atexit
import base64
import binascii
import hashlib
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence, TypeVar

import paramiko

from .config import KNOWN_HOSTS_FILENAME, ServerRegistry
from .errors import (
    AuthError,
    HostKeyError,
    HostKeyMismatchError,
    ServerBusyError,
    SshConnectionError,
    UnknownHostKeyError,
)
from .models import ServerProfile, canonical_host_name

logger = logging.getLogger(__name__)

T = TypeVar("T")

CONNECTION_TTL = 300.0
MAX_POOLED_CONNECTIONS = 16
MAX_SESSIONS_PER_SERVER = 8
CONNECTION_ATTEMPTS = 3
# Повтор сразу: окно перегрузки sshd (MaxStartups и переполненный пул PAM)
# живёт секунды, и ждать перед следующей попыткой — значит снова в него попасть.
RETRY_DELAYS = (0.0, 0.75)
# Потолок на обмен версиями и KEX. Замер на живых хостах даёт строго двухмодальное
# распределение: либо рукопожатие проходит за 0.7–0.8 с, либо ответа нет вовсе
# (промежуточных 3–20 с не бывает — зависший sshd просто не отвечает). Поэтому
# потолок можно ставить агрессивно: 5 с — это 6–7× нормального времени и в семь
# раз меньше дефолтных 15 с paramiko, из-за которых холодный вызов платил 20 с.
# Дёшево пробовать три раза лучше, чем один раз ждать 15 с: окно перегрузки
# сдвигается, и следующая попытка обычно проходит.
HANDSHAKE_TIMEOUTS = (5.0, 5.0, 5.0)
BANNER_TIMEOUT = 8
# Через jump-host рукопожатие идёт по каналу, а не по сокету: ``banner_timeout``
# и ``auth_timeout`` там не работают (paramiko ждёт в ``Channel.recv``, где
# таймаут задаётся только через ``settimeout``). Без этой границы зависший хоп
# висит все 15–20 с, пока удалённая сторона не пришлёт EOF.
CHANNEL_OPEN_TIMEOUT = 8

# Крипто-мороз: тот же список, что у tufantunc/ssh-mcp. ``keys`` — алгоритмы
# серверного ключа, ``pubkeys`` — клиентской подписи, ``kex`` — обмен ключами,
# ``macs`` — коды аутентификации сообщений. RSA оставлен только в вариантах
# SHA-2 (rsa-sha2-256/512), поэтому обычный ``ssh`` с ключом работает.
DISABLED_ALGORITHMS: Mapping[str, tuple[str, ...]] = {
    "keys": ("ssh-dss", "ssh-rsa", "rsa-sha1"),
    "pubkeys": ("ssh-dss", "ssh-rsa", "rsa-sha1"),
    "kex": ("diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"),
    "macs": ("hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"),
}

# Ошибки, означающие «соединение умерло», а не «операцию отвергли».
_TRANSIENT = (EOFError, TimeoutError, ConnectionError)

_MAX_ERROR_DETAIL = 160


def _short(exc: BaseException, limit: int = _MAX_ERROR_DETAIL) -> str:
    detail = str(exc).strip().replace("\n", " ")
    if not detail:
        return type(exc).__name__
    return detail if len(detail) <= limit else f"{detail[:limit]}…"


def fingerprint_of(key: paramiko.PKey) -> str:
    """SHA256-отпечаток ключа в формате OpenSSH (``SHA256:...`` без padding)."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def normalize_fingerprint(value: str | None) -> str:
    """Привести заданный в YAML отпечаток к сравнимому виду.

    Поддерживаются ``SHA256:<base64>`` (как у ``ssh-keygen -lf``) и
    ``MD5:<aa:bb:...>``. Неизвестный префикс даёт пустую строку — вызывающий
    код сообщит об этом как о непригодном пине.
    """
    text = (value or "").strip()
    prefix, separator, body = text.partition(":")
    if not separator or not body.strip():
        return ""
    kind = prefix.strip().casefold()
    payload = body.strip()
    if kind == "sha256":
        return "SHA256:" + payload.rstrip("=")
    if kind == "md5":
        return "MD5:" + payload.casefold()
    return ""


# --- host keys ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KnownHostRecord:
    """Одна запись собственного ``known_hosts``."""

    host: str
    key_type: str
    key_base64: str
    fingerprint: str

    def describe(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "type": self.key_type,
            "fingerprint": self.fingerprint,
        }


class HostKeyStore:
    """Append-only ``known_hosts`` сервера: чтение, TOFU-запись, pin, сброс.

    Файл свой, а не пользовательский: ``paramiko.HostKeys.save()`` нормализует
    файл при переписывании и выбросил бы строки ``@cert-authority``/``@revoked``
    вместе с комментариями. Поэтому здесь только чтение строк целиком и
    дописывание одной новой строки — остальное содержимое не трогаем никогда.

    ``fallback`` — пользовательский ``~/.ssh/known_hosts``, только для чтения:
    если оператор уже завёл там хост, доверие переносится в наш файл (adopt) и
    с этого момента решает только наш файл. Иначе paramiko нашёл бы ключ в
    системном файле раньше политики — и ``pin`` можно было бы обойти молча.
    """

    def __init__(self, path: str | Path, *, fallback: str | Path | None = None) -> None:
        self.path = Path(path)
        self.fallback = Path(fallback) if fallback is not None else None
        self._lock = threading.Lock()

    # --- reading --------------------------------------------------------

    def exists(self) -> bool:
        return self.path.is_file()

    def records(self, name: str) -> tuple[KnownHostRecord, ...]:
        """Все записи канонического имени ``name`` (идемпотентная нормализация)."""
        wanted = canonical_host_name(name)
        return tuple(
            record for record in self._entries() if canonical_host_name(record.host) == wanted
        )

    def _entries(self) -> tuple[KnownHostRecord, ...]:
        return tuple(self._entries_of(self.path))

    @staticmethod
    def _entries_of(path: Path) -> list[KnownHostRecord]:
        records: list[KnownHostRecord] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return records
        for line in lines:
            parsed = _parse_known_host_line(line)
            if parsed is None:
                continue
            hosts, key_type, key_base64 = parsed
            fingerprint = fingerprint_of_blob(key_base64)
            for host in hosts:
                records.append(
                    KnownHostRecord(
                        host=host,
                        key_type=key_type,
                        key_base64=key_base64,
                        fingerprint=fingerprint,
                    )
                )
        return records

    def _read_lines(self) -> tuple[str, ...]:
        try:
            return tuple(self.path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return ()

    # --- verification ----------------------------------------------------

    def verify(
        self,
        name: str,
        key: paramiko.PKey,
        *,
        policy: str = "tofu",
        fingerprint: str | None = None,
    ) -> KnownHostRecord:
        """Проверить предъявленный ключ и, если положено, записать его.

        Args:
            name: имя хоста как paramiko его передал (``[host]:2222`` допустим).
            key: серверный ключ из рукопожатия.
            policy: ``tofu``/``auto_add`` — записать неизвестный хост;
                ``reject`` — отказать; ``pin`` — записать только при совпадении
                с ``fingerprint``.
            fingerprint: закреплённый (``host_key_fingerprint``) отпечаток.

        Returns:
            Запись, которой соответствует ключ (только что созданная — тоже).

        Raises:
            UnknownHostKeyError: хоста нет в файле, а политика запрещает доверять.
            HostKeyMismatchError: ключ не совпадает с записанным или закреплённым.
        """
        host = canonical_host_name(name)
        received = fingerprint_of(key)
        pinned = normalize_fingerprint(fingerprint) if policy == "pin" else ""
        if policy == "pin" and not pinned:
            raise UnknownHostKeyError(
                host,
                self.path,
                hint=(
                    "host_key_policy 'pin' is set but host_key_fingerprint is unusable; "
                    "expected 'SHA256:...' from ssh-keygen -lf"
                ),
            )
        if pinned and pinned != received:
            # Пин проверяется всегда, а не только при первом знакомстве: иначе
            # запись в файле навсегда перебивала бы исправленный оператором пин.
            raise HostKeyMismatchError(
                host,
                expected=[pinned],
                received=received,
                path=self.path,
            )

        known = self.records(host)
        for record in known:
            if record.key_type == key.get_name() and record.key_base64 == key.get_base64():
                return record
        if known:
            raise HostKeyMismatchError(
                host,
                expected=[record.fingerprint for record in known],
                received=received,
                path=self.path,
            )

        adopted = self._adopt(host, key, policy=policy)
        if adopted is not None:
            return adopted

        if policy == "reject":
            raise UnknownHostKeyError(host, self.path)
        return self.add(host, key)

    def _adopt(
        self,
        host: str,
        key: paramiko.PKey,
        *,
        policy: str,
    ) -> KnownHostRecord | None:
        """Перенести доверие из пользовательского ``known_hosts`` в наш файл.

        ``pin`` пользовательский файл не рассматривает вовсе: закреплённый
        отпечаток обязан быть единственным источником истины.
        """
        if self.fallback is None or policy == "pin" or not self.fallback.is_file():
            return None
        foreign = [
            record
            for record in self._entries_of(self.fallback)
            if canonical_host_name(record.host) == host
        ]
        for record in foreign:
            if record.key_type == key.get_name() and record.key_base64 == key.get_base64():
                logger.info(
                    "Adopted %s host key for %s from %s", record.key_type, host, self.fallback
                )
                return self.add(host, key)
        if foreign:
            raise HostKeyMismatchError(
                host,
                expected=[record.fingerprint for record in foreign],
                received=fingerprint_of(key),
                path=self.fallback,
                hint=(
                    "The host key in your known_hosts differs from the one presented. "
                    "Confirm it out of band, then refresh or drop that entry "
                    "(ssh-keygen -R <host>)."
                ),
            )
        return None

    # --- writing ---------------------------------------------------------

    def add(self, name: str, key: paramiko.PKey) -> KnownHostRecord:
        """Дописать ключ хоста (TOFU), не трогая остальные строки файла."""
        host = canonical_host_name(name)
        record = KnownHostRecord(
            host=host,
            key_type=key.get_name(),
            key_base64=key.get_base64(),
            fingerprint=fingerprint_of(key),
        )
        line = f"{host} {record.key_type} {record.key_base64}\n"

        with self._lock:
            existing = self.records(host)
            for known in existing:
                if known.key_type == record.key_type and known.key_base64 == record.key_base64:
                    return known
            if existing:
                # Не перетираем запись: чужой тип ключа на известном хоте —
                # это подмена, а не обновление.
                raise HostKeyMismatchError(
                    host,
                    expected=[known.fingerprint for known in existing],
                    received=record.fingerprint,
                    path=self.path,
                )
            self._append(line)
            logger.info("Stored %s host key for %s (%s)", record.key_type, host, record.fingerprint)
        return record

    def forget(self, name: str) -> int:
        """Убрать все записи хоста из своего файла; возвращает число строк.

        Чужой файл не трогаем: его правит только явный
        :meth:`forget_user_records` (тот же смысл, что у ``ssh-keygen -R``).
        """
        return self._forget_from(self.path, name)

    def forget_user_records(self, name: str) -> int:
        """Убрать записи хоста из пользовательского ``known_hosts``.

        Без этого забытый хост на следующем же подключении снова был бы принят
        из ``~/.ssh/known_hosts``, и сброс выглядел бы сделанным, но ничего бы
        не менял. Строка удаляется целиком, ``@cert-authority``/``@revoked`` и
        комментарии остаются на месте.
        """
        if self.fallback is None:
            return 0
        return self._forget_from(self.fallback, name)

    def _forget_from(self, path: Path, name: str) -> int:
        host = canonical_host_name(name)
        with self._lock:
            kept: list[str] = []
            removed = 0
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return 0
            for line in lines:
                parsed = _parse_known_host_line(line)
                if parsed is not None and host in {canonical_host_name(item) for item in parsed[0]}:
                    removed += 1
                    continue
                kept.append(line)
            if removed:
                self._rewrite(path, kept)
        if removed:
            logger.info("Removed %d host key record(s) for %s from %s", removed, host, path)
        return removed

    def _append(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(handle, line.encode("utf-8"))
        finally:
            os.close(handle)
        self._restrict_permissions(self.path)

    @staticmethod
    def _rewrite(path: Path, lines: Sequence[str]) -> None:
        """Атомарно перезаписать файл целиком (используется только при сбросе)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
            for line in lines:
                handle.write(f"{line.rstrip()}\n")
        os.replace(temporary, path)
        HostKeyStore._restrict_permissions(path)

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        """0600 на POSIX. На NTFS chmod — декоративная бутафория (см. IMPROVEMENTS 1.6)."""
        if os.name == "nt" or not path.exists():
            return
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - depends on the filesystem
            logger.debug("Could not restrict permissions on %s", path, exc_info=True)

    # --- reporting -------------------------------------------------------

    def summary(self, name: str | None = None) -> dict[str, Any]:
        """Состояние файла (и конкретного хоста) для инструментов и диагностики."""
        entries = self._entries()
        result: dict[str, Any] = {
            "path": str(self.path),
            "exists": self.exists(),
            "entries": len(entries),
            "user_known_hosts": str(self.fallback) if self.fallback is not None else None,
        }
        if name is None:
            return result

        host = canonical_host_name(name)
        mine = [entry for entry in entries if canonical_host_name(entry.host) == host]
        foreign = (
            [
                entry
                for entry in self._entries_of(self.fallback)
                if canonical_host_name(entry.host) == host
            ]
            if self.fallback is not None and self.fallback.is_file()
            else []
        )
        result.update(
            {
                "host": host,
                "known": bool(mine),
                "keys": [item.describe() for item in mine],
                "in_user_known_hosts": bool(foreign),
            }
        )
        return result


def _parse_known_host_line(line: str) -> tuple[list[str], str, str] | None:
    """Разобрать строку ``host[,host] keytype base64``; None для чужих строк."""
    text = line.strip()
    if not text or text.startswith(("#", "@")):
        return None
    fields = text.split()
    if len(fields) < 3:
        return None
    hosts = [host for host in fields[0].split(",") if host]
    if not hosts:
        return None
    return hosts, fields[1], fields[2]


def fingerprint_of_blob(key_base64: str) -> str:
    """SHA256-отпечаток по base64-блобу публичного ключа, ``''`` при мусоре."""
    try:
        blob = base64.b64decode(key_base64, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def resolve_known_hosts_path(profile: ServerProfile, config_dir: str | Path) -> Path:
    """Путь к собственному файлу host key сервера.

    Явный ``known_hosts:`` из YAML имеет приоритет, иначе берётся файл рядом с
    ``servers.yaml`` — рядом с конфигом и паролями, а не в домашнем каталоге.
    """
    if profile.known_hosts is not None:
        return profile.known_hosts
    return Path(config_dir) / KNOWN_HOSTS_FILENAME


def user_known_hosts() -> Path:
    """Пользовательский ``~/.ssh/known_hosts`` — только для чтения и переноса доверия."""
    return Path(os.path.expanduser("~")) / ".ssh" / "known_hosts"


def host_key_store_for(profile: ServerProfile, config_dir: str | Path) -> HostKeyStore:
    """Магазин host key для одного профиля."""
    return HostKeyStore(resolve_known_hosts_path(profile, config_dir), fallback=user_known_hosts())


class TofuPolicy(paramiko.MissingHostKeyPolicy):
    """Политика доверия host key: TOFU/pin поверх :class:`HostKeyStore`.

    Загружать файл в ``client._host_keys`` нельзя: тогда paramiko сравнивает ключ
    сам и любая новая разновидность ключа (например, ``ssh-ed25519`` вместо
    прежнего ``ssh-rsa``) превращается в ``BadHostKeyException`` без
    внятного объяснения. Своя политика держит одно место принятия решений.
    """

    def __init__(self, store: HostKeyStore, profile: ServerProfile) -> None:
        self._store = store
        self._profile = profile

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        # Имя уже отформатировано paramiko: повторная обёртка дала бы
        # ``[[host]:2222]:2222``, и запись не нашлась бы никогда.
        self._store.verify(
            canonical_host_name(hostname),
            key,
            policy=self._profile.host_key_policy,
            fingerprint=self._profile.host_key_fingerprint,
        )


def _configure_client(profile: ServerProfile, store: HostKeyStore) -> paramiko.SSHClient:
    """Клиент, у которого host key решает только наш магазин.

    ``load_system_host_keys()`` здесь не вызывается намеренно: paramiko нашёл бы
    ключ в ``~/.ssh/known_hosts`` раньше политики, TOFU-запись не появилась бы,
    а ``host_key_policy: pin`` обходился бы молча. Пользовательский файл вместо
    этого читает :class:`HostKeyStore` и переносит доверие в наш.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(TofuPolicy(store, profile))
    return client


def _agent_has_keys() -> bool:
    """Есть ли у локального ``ssh-agent`` ключи.

    Ступень агента без ключей бесполезна: paramiko всё равно тратит на неё
    целый хендшейк. На Windows прокси Pageant обычно недоступен — проверка
    дешёвая и возвращает ``False``.
    """
    try:
        return bool(paramiko.Agent().get_keys())
    except Exception:  # noqa: BLE001 - агент опционален, его отсутствие не ошибка
        logger.debug("ssh-agent is not usable", exc_info=True)
        return False


def _timeout_for(attempt: int) -> float:
    """Потолок рукопожатия для попытки ``attempt`` (нумерация с нуля)."""
    return HANDSHAKE_TIMEOUTS[min(attempt, len(HANDSHAKE_TIMEOUTS) - 1)]


def _transport_factory(handshake_timeout: float) -> Callable[..., paramiko.Transport]:
    """Фабрика транспорта с нашим потолком на обмен версиями и KEX.

    ``SSHClient.connect`` задаёт ``banner_timeout`` и ``auth_timeout``, но
    ``handshake_timeout`` оставляет равным 15 с — этого не хватает, когда хоп
    висит: попытка стоит 15 с вместо двух, и следующая (обычно успешная) ещё
    пару секунд сверху.
    """

    def factory(sock: Any, **kwargs: Any) -> paramiko.Transport:
        transport = paramiko.Transport(sock, **kwargs)
        transport.handshake_timeout = handshake_timeout
        return transport

    return factory


def _tune_transport(profile: ServerProfile, client: paramiko.SSHClient) -> None:
    """Keepalive: у обоих хостов ``clientaliveinterval 0``, NAT режет молча."""
    transport = client.get_transport()
    if transport is None:  # pragma: no cover - connect() успешен ⇒ транспорт есть
        return
    if profile.keepalive_interval > 0:
        transport.set_keepalive(profile.keepalive_interval)


def _open_channel(transport: paramiko.Transport, host: str, port: int) -> paramiko.Channel:
    """Одноразовый ``direct-tcpip``-канал до следующего хоста цепочки."""
    return transport.open_channel(
        "direct-tcpip",
        (host, port),
        ("127.0.0.1", 0),
        timeout=CHANNEL_OPEN_TIMEOUT,
    )


def _open_direct(
    profile: ServerProfile,
    *,
    config_dir: str | Path,
    channel_factory: Callable[[], paramiko.Channel] | None = None,
    attempt: int = 0,
) -> paramiko.SSHClient:
    """Подключиться к одному хосту, перебирая лестницу авторизации.

    Каждая ступень получает свежий клиент (а через jump-host — свежий
    ``direct-tcpip``-канал, он одноразовый), иначе вторая попытка упадёт на
    уже израсходованном сокете.

    Args:
        attempt: номер попытки цепочки, задаёт потолок рукопожатия.

    Raises:
        AuthError: не сработала ни одна ступень; в тексте перечислены все.
        HostKeyMismatchError: сервер показал не тот ключ.
        SshConnectionError: сеть или рукопожатие.
    """
    store = host_key_store_for(profile, config_dir)
    steps, skipped = profile.auth.auth_plan(agent_keys=_agent_has_keys())
    if not steps:
        detail = f" — skipped: {'; '.join(skipped)}" if skipped else ""
        raise AuthError(
            f"No usable SSH credentials for {profile.target}{detail}",
            attempts=skipped,
        )

    handshake_timeout = _timeout_for(attempt)
    failures: list[str] = []
    for step in steps:
        client = _configure_client(profile, store)
        sock = channel_factory() if channel_factory is not None else None
        if sock is not None:
            # Единственный способ ограничить рукопожатие через jump-host: таймаут
            # на самом канале. После ``connect`` его обязано быть снять, иначе
            # он начнёт рвать чтение пакетов живой сессии.
            sock.settimeout(handshake_timeout)
        try:
            client.connect(
                hostname=profile.host,
                port=profile.port,
                username=profile.username,
                sock=sock,
                # ``timeout`` ограничивает TCP-подключение прямого хоста: без него
                # paramiko ждёт столько, сколько решит ОС (обычно ~2 минуты).
                # На jump-host канал уже открыт, там ограничение — settimeout выше.
                timeout=profile.connect_timeout,
                banner_timeout=min(profile.connect_timeout, BANNER_TIMEOUT),
                auth_timeout=profile.auth_timeout,
                disabled_algorithms=DISABLED_ALGORITHMS,
                transport_factory=_transport_factory(handshake_timeout),
                **step.kwargs,
            )
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise HostKeyMismatchError(
                canonical_host_name(exc.hostname or profile.host),
                expected=[fingerprint_of(key) for key in (exc.expected_key,) if key is not None],
                received=fingerprint_of(exc.key) if exc.key is not None else "",
                path=store.path,
            ) from exc
        except paramiko.AuthenticationException as exc:
            failures.append(f"{step.method}: {_short(exc)}")
            logger.info("Auth method %s failed for %s: %s", step.method, profile.target, exc)
        except (AuthError, HostKeyError):
            # Наши собственные verdicts по host key не должны теряться в обёртке
            # «не удалось подключиться»: агент обязан увидеть код ошибки.
            client.close()
            if sock is not None:
                sock.close()
            raise
        except Exception as exc:  # noqa: BLE001 - транспорт/сеть, лестница тут бессильна
            client.close()
            if sock is not None:
                sock.close()
            reason = _short(exc)
            raise SshConnectionError(
                f"Cannot connect to {profile.target} — {type(exc).__name__}: {reason}"
            ) from exc
        else:
            _tune_transport(profile, client)
            return client
        finally:
            if sock is not None:
                try:
                    sock.settimeout(None)
                except Exception:  # noqa: BLE001 - канал уже мог умереть
                    logger.debug("Could not reset the jump channel timeout", exc_info=True)
        client.close()
        if sock is not None:
            sock.close()

    tried = "; ".join(failures) or "nothing"
    skipped_note = f"; skipped: {', '.join(skipped)}" if skipped else ""
    raise AuthError(
        f"Authentication failed for {profile.target} "
        f"(tried {len(failures)}/{len(steps)}: {tried}{skipped_note})",
        attempts=[*failures, *skipped],
    )


@dataclass(slots=True)
class PooledConnection:
    """One established chain: jump hosts first, target client last.

    ``in_use`` counts the operations currently multiplexed over this chain.
    """

    key: str
    chain: tuple[str, ...]
    clients: list[paramiko.SSHClient]
    trust: str = ""
    opened_at: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    in_use: int = 0
    retired: bool = False

    @property
    def target(self) -> paramiko.SSHClient:
        return self.clients[-1]

    def is_alive(self, ttl: float) -> bool:
        if self.retired or time.monotonic() - self.last_used > ttl:
            return False
        transport = self.target.get_transport()
        return bool(transport and transport.is_active() and transport.is_authenticated())

    def close(self) -> None:
        for client in reversed(self.clients):
            try:
                client.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                logger.debug("Failed to close SSH client", exc_info=True)


class ConnectionManager:
    """Creates, pools and closes SSH clients for the configured servers."""

    def __init__(
        self,
        registry: ServerRegistry,
        *,
        ttl: float = CONNECTION_TTL,
        max_sessions: int = MAX_SESSIONS_PER_SERVER,
    ) -> None:
        self._registry = registry
        self._ttl = ttl
        self._max_sessions = max_sessions
        self._pool: dict[str, PooledConnection] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._slots: dict[str, threading.BoundedSemaphore] = {}
        self._guard = threading.Lock()

    def resolve(self, server: str | None) -> ServerProfile:
        return self._registry.get(server)

    # --- host keys -------------------------------------------------------

    def host_key_store(self, server: str | None = None) -> HostKeyStore:
        """Магазин host key сервера (по умолчанию — для сервера по умолчанию)."""
        return host_key_store_for(self.resolve(server), self._registry.known_hosts_dir)

    def known_hosts_path(self, server: str | None = None) -> Path:
        """Путь к собственному файлу host key — для показа агентом."""
        return self.host_key_store(server).path

    def host_key_status(self, server: str | None = None) -> dict[str, Any]:
        """Что известно про host key сервера: путь, наличие записи, отпечатки."""
        profile = self.resolve(server)
        status = host_key_store_for(profile, self._registry.known_hosts_dir).summary(
            profile.host_key_name
        )
        status.update(
            {
                "server": profile.name,
                "policy": profile.host_key_policy,
                "pinned_fingerprint": profile.host_key_fingerprint,
            }
        )
        return status

    def forget_host_key(
        self,
        server: str | None = None,
        *,
        include_user_known_hosts: bool = False,
    ) -> dict[str, Any]:
        """Сбросить запись host key сервера и выбросить его соединения из пула.

        Живой транспорт уже прошёл проверку, поэтому после сброса он должен быть
        переустановлен — иначе следующий вызов продолжит пользоваться старым
        соединением, а агент решит, что сброс сработал.

        Args:
            server: имя сервера из ``servers.yaml`` (host/tag тоже).
            include_user_known_hosts: снести запись и в ``~/.ssh/known_hosts``.
                По умолчанию **нет**: у этого файла общий владелец с обычным
                ``ssh``, и агент не должен молча править его. Без флага хост,
                лежащий и в пользовательском файле, снова будет принят оттуда —
                поэтому ``ssh_forget_host_key`` должен говорить об этом (в ответе
                есть ``in_user_known_hosts``).
        """
        profile = self.resolve(server)
        store = host_key_store_for(profile, self._registry.known_hosts_dir)
        removed = store.forget(profile.host_key_name)
        removed_foreign = (
            store.forget_user_records(profile.host_key_name)
            if include_user_known_hosts
            else 0
        )
        dropped = self._drop_pooled(profile.name)
        return {
            "server": profile.name,
            "host": profile.host_key_name,
            "known_hosts": str(store.path),
            "removed_entries": removed,
            "removed_from_user_known_hosts": removed_foreign,
            "in_user_known_hosts": bool(
                [
                    record
                    for record in HostKeyStore._entries_of(user_known_hosts())
                    if canonical_host_name(record.host) == profile.host_key_name
                ]
            ),
            "connections_dropped": dropped,
        }

    # --- pooling ---------------------------------------------------------

    @contextmanager
    def client(self, profile: ServerProfile) -> Iterator[paramiko.SSHClient]:
        """Yield a live client for the server; the pool keeps it open."""
        with self._session_slot(profile.name):
            pooled = self.acquire(profile)
            try:
                yield pooled.target
            finally:
                self._release(pooled)

    @contextmanager
    def sftp(self, profile: ServerProfile) -> Iterator[paramiko.SFTPClient]:
        with self.client(profile) as client:
            sftp_client = client.open_sftp()
            try:
                yield sftp_client
            finally:
                sftp_client.close()

    def acquire(self, profile: ServerProfile) -> PooledConnection:
        """Return a usable pooled connection, opening a new chain when needed."""
        trust = self._chain_trust(profile)
        with self._lock_for(profile.name):
            pooled = self._take(profile.name, trust)
            if pooled is not None:
                return pooled
            opened = self._connect_with_retry(profile)
            with self._guard:
                self._evict_for_room(opened.key)
                opened.in_use = 1
                self._pool[opened.key] = opened
            return opened

    def close_all(self) -> None:
        """Retire every pooled connection; in-flight calls keep theirs."""
        with self._guard:
            for pooled in list(self._pool.values()):
                if pooled.in_use > 0:
                    pooled.retired = True
                else:
                    self._discard(pooled)

    def stats(self) -> dict[str, dict[str, Any]]:
        """Read-only snapshot of the pool, for MCP resources and diagnostics."""
        now = time.monotonic()
        with self._guard:
            return {
                key: {
                    "chain": list(pooled.chain),
                    "alive": pooled.is_alive(self._ttl),
                    "sessions_in_use": pooled.in_use,
                    "age_seconds": round(now - pooled.opened_at, 1),
                    "idle_seconds": round(now - pooled.last_used, 1),
                }
                for key, pooled in self._pool.items()
            }

    async def run(
        self,
        profile: ServerProfile,
        action: Callable[[paramiko.SSHClient], T],
    ) -> T:
        """Run ``action`` with a live client in a worker thread."""
        return await asyncio.to_thread(self._run_blocking, profile, action, False)

    async def run_sftp(
        self,
        profile: ServerProfile,
        action: Callable[[paramiko.SFTPClient], T],
    ) -> T:
        """Run ``action`` with a live SFTP session in a worker thread."""
        return await asyncio.to_thread(self._run_blocking, profile, action, True)

    async def describe(self, server: str | None = None) -> dict[str, Any]:
        """Return connection facts about a server, verified against the host."""
        profile = self.resolve(server)
        info = profile.summary()
        info["jump_chain"] = list(self._registry.chain(profile.name))

        def probe(client: paramiko.SSHClient) -> dict[str, Any]:
            _, stdout, _ = client.exec_command("uname -srm", timeout=15)
            return {"reachable": True, "uname": stdout.read().decode("utf-8", "replace").strip()}

        try:
            info["probe"] = await self.run(profile, probe)
        except Exception as exc:  # noqa: BLE001 - reported to the caller, not raised
            info["probe"] = {"reachable": False, "error": str(exc)}
        return info

    # --- internals -----------------------------------------------------

    def _chain_trust(self, profile: ServerProfile) -> str:
        """Отпечаток доверия всей цепочки — тот же, что кладёт в :meth:`_open_chain`.

        Считать его здесь и там по-разному нельзя: тогда отпечаток никогда не
        совпадёт, пул будет выбрасывать исправное соединение и каждый вызов
        платит новый хендшейк (а через jump-host ещё и дверь в MaxStartups
        перегруженного sshd).
        """
        names = self._registry.chain(profile.name)
        parts = [
            trust_signature(
                profile if index == len(names) - 1 else self._registry.get(name)
            )
            for index, name in enumerate(names)
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    def _run_blocking(
        self,
        profile: ServerProfile,
        action: Callable[[Any], T],
        use_sftp: bool,
    ) -> T:
        with self._session_slot(profile.name):
            for attempt in (1, 2):
                pooled = self.acquire(profile)
                try:
                    return self._invoke(pooled, action, use_sftp)
                except Exception as exc:
                    dead = self._transport_gone(pooled)
                    if attempt == 2 or not (dead or isinstance(exc, _TRANSIENT)):
                        raise
                    self._retire(pooled)
                    logger.warning(
                        "Connection to %s failed mid-flight (%s); reconnecting and retrying once",
                        profile.name,
                        exc,
                    )
                finally:
                    self._release(pooled)
        raise SshConnectionError(f"Cannot connect to {profile.name}")  # pragma: no cover

    def _invoke(
        self,
        pooled: PooledConnection,
        action: Callable[[Any], T],
        use_sftp: bool,
    ) -> T:
        if not use_sftp:
            return action(pooled.target)
        sftp_client = pooled.target.open_sftp()
        try:
            return action(sftp_client)
        finally:
            sftp_client.close()

    def _take(self, key: str, trust: str) -> PooledConnection | None:
        with self._guard:
            pooled = self._pool.get(key)
            if pooled is None:
                return None
            if pooled.trust != trust:
                logger.info(
                    "Pooled connection for %s was opened under different trust settings; reopening",
                    key,
                )
                self._discard(pooled)
                return None
            if pooled.is_alive(self._ttl):
                pooled.last_used = time.monotonic()
                pooled.in_use += 1
                return pooled
            self._discard(pooled)
            return None

    def _release(self, pooled: PooledConnection) -> None:
        with self._guard:
            pooled.last_used = time.monotonic()
            pooled.in_use = max(0, pooled.in_use - 1)
            if pooled.in_use == 0 and (pooled.retired or self._pool.get(pooled.key) is not pooled):
                self._discard(pooled)

    def _retire(self, pooled: PooledConnection) -> None:
        """Drop a broken chain from the pool so the next call gets a fresh one."""
        with self._guard:
            if self._pool.get(pooled.key) is pooled:
                del self._pool[pooled.key]
            pooled.retired = True

    def _drop_pooled(self, key: str) -> int:
        """Retire the pooled chain of one server; returns how many were dropped."""
        with self._guard:
            pooled = self._pool.pop(key, None)
            if pooled is None:
                return 0
            if pooled.in_use > 0:
                pooled.retired = True
            else:
                pooled.close()
            return 1

    def _discard(self, pooled: PooledConnection) -> None:
        if self._pool.get(pooled.key) is pooled:
            del self._pool[pooled.key]
        pooled.retired = True
        pooled.close()

    def _evict_for_room(self, key: str) -> None:
        """Make space for a new chain, preferring idle and stale entries."""
        while len(self._pool) >= MAX_POOLED_CONNECTIONS:
            idle = [item for item in self._pool.values() if item.in_use == 0]
            if not idle:
                return
            self._discard(min(idle, key=lambda item: item.last_used))

    def _transport_gone(self, pooled: PooledConnection) -> bool:
        transport = pooled.target.get_transport()
        return transport is None or not transport.is_active()

    def _lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    @contextmanager
    def _session_slot(self, key: str) -> Iterator[None]:
        """Cap concurrent sessions per server below sshd ``MaxSessions``."""
        with self._guard:
            slot = self._slots.setdefault(key, threading.BoundedSemaphore(self._max_sessions))
        acquired = slot.acquire(timeout=60)
        if not acquired:  # pragma: no cover - only under pathological load
            raise ServerBusyError(
                f"Server '{key}' is busy: more than {self._max_sessions} operations are queued"
            )
        try:
            yield
        finally:
            slot.release()

    def _connect_with_retry(self, profile: ServerProfile) -> PooledConnection:
        """Open one chain. Per-hop retries live in :meth:`_open_hop`."""
        return self._open_chain(profile)

    def _open_hop(
        self,
        hop: ServerProfile,
        *,
        config_dir: Path,
        jump_client: paramiko.SSHClient | None,
    ) -> paramiko.SSHClient:
        """Connect one hop, retrying **on the already open jump transport**.

        Пересобирать всю цепочку при ретрае дорого и вредно: лишний хендшейк к
        jump-хосту (~1.2 с) и ещё одна неавторизованная сессия на том самом
        sshd, который только что нас отбросил. Первая попытка — дешёвый щуп
        (:data:`HANDSHAKE_TIMEOUTS`), вторая — терпеливая.

        Args:
            hop: профиль подключаемого хоста.
            config_dir: каталог с собственным ``known_hosts``.
            jump_client: уже открытый предыдущий хоп цепочки, если он есть.
        """
        channel_factory: Callable[[], paramiko.Channel] | None = None
        if jump_client is not None:
            transport = jump_client.get_transport()
            if transport is None or not transport.is_active():
                raise SshConnectionError(
                    f"Jump host dropped the session before reaching {hop.target}"
                )
            channel_factory = _channel_opener(transport, hop.host, hop.port)

        last_error: Exception | None = None
        for attempt in range(CONNECTION_ATTEMPTS):
            try:
                return _open_direct(
                    hop,
                    config_dir=config_dir,
                    channel_factory=channel_factory,
                    attempt=attempt,
                )
            except (AuthError, HostKeyError):
                # Причина конкретная (неверный пароль, чужой host key): ни
                # повтор, ни маскировка под «Incomplete connection chain».
                raise
            except Exception as exc:  # noqa: BLE001 - сеть/рукопожатие, причина важна
                last_error = exc
                logger.warning(
                    "Chain hop %s attempt %d/%d failed (%s: %s)",
                    hop.name,
                    attempt + 1,
                    CONNECTION_ATTEMPTS,
                    type(exc).__name__,
                    _short(exc),
                )
                delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
                if delay and attempt + 1 < CONNECTION_ATTEMPTS:
                    time.sleep(delay)

        reason = (
            "no attempts"
            if last_error is None
            else f"{type(last_error).__name__}: {_short(last_error)}{_chain_failure_hint(last_error)}"
        )
        if isinstance(last_error, SshConnectionError):
            # Причина уже сформулирована в ``_open_direct`` — не заворачиваем
            # второй раз, иначе в тексте остаётся «SshConnectionError: ...».
            raise last_error
        raise SshConnectionError(f"Cannot reach {hop.target} — {reason}")

    def _open_chain(self, profile: ServerProfile) -> PooledConnection:
        names = self._registry.chain(profile.name)
        config_dir = self._registry.known_hosts_dir
        clients: list[paramiko.SSHClient] = []
        current: paramiko.SSHClient | None = None

        for index, name in enumerate(names):
            # Последний хоп — сам сервер: берём профиль, который дал вызывающий
            # (он может отличаться от реестра, например, с новым паролем или пином).
            hop = profile if index == len(names) - 1 else self._registry.get(name)
            try:
                current = self._open_hop(hop, config_dir=config_dir, jump_client=current)
            except (AuthError, HostKeyError):
                for client in reversed(clients):
                    client.close()
                raise
            except SshConnectionError as exc:
                for client in reversed(clients):
                    client.close()
                raise SshConnectionError(
                    f"Incomplete connection chain to {profile.target} — {exc}"
                ) from exc
            except Exception as exc:  # noqa: BLE001 - причина попадает в текст ошибки
                for client in reversed(clients):
                    client.close()
                raise SshConnectionError(
                    f"Incomplete connection chain to {profile.target} — "
                    f"{type(exc).__name__}: {_short(exc)}"
                ) from exc
            clients.append(current)

        logger.debug("Opened connection chain %s", " -> ".join(names))
        return PooledConnection(
            key=profile.name,
            chain=tuple(names),
            clients=clients,
            trust=self._chain_trust(profile),
        )


def _chain_failure_hint(exc: Exception) -> str:
    """Подсказка по типовым причинам обрыва на хопе jump-host цепочки."""
    if isinstance(exc, (EOFError, paramiko.SSHException)):
        return (
            " The remote sshd closed the session before the handshake finished — "
            "typically a MaxStartups drop under a login flood; the call is retried "
            "immediately, and a warm pool avoids it altogether."
        )
    return ""


def trust_signature(profile: ServerProfile) -> str:
    """Короткий отпечаток настроек, при которых транспорт считается доверенным.

    Пул живёт до TTL, поэтому соединение, открытое при других правилах проверки
    host key или с другими учётными данными, использовать нельзя: оно прошло
    проверку по старым правилам. Пароль в отпечаток попадает только как хэш —
    сам секрет не используется и нигде не логируется.
    """
    auth = profile.auth
    secret = hashlib.sha256(
        f"{auth.password or ''}\x1f{auth.passphrase or ''}".encode()
    ).hexdigest()[:16]
    material = "|".join(
        (
            profile.host,
            str(profile.port),
            profile.username,
            auth.type,
            auth.key_path.name if auth.key_path else "",
            secret,
            str(auth.use_agent),
            str(auth.password_fallback),
            profile.host_key_policy,
            profile.host_key_fingerprint or "",
            str(profile.keepalive_interval),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _channel_opener(
    transport: paramiko.Transport,
    host: str,
    port: int,
) -> Callable[[], paramiko.Channel]:
    """Фабрика одноразовых каналов: каждая попытка лестницы получает свой."""
    return lambda: _open_channel(transport, host, port)


_SHARED_MANAGERS: dict[str, ConnectionManager] = {}
_SHARED_LOCK = threading.Lock()


def shared_manager(registry: ServerRegistry) -> ConnectionManager:
    """Return the process-wide pool for a configuration file.

    Several MCP sessions may live in one process (streamable HTTP, or several
    clients at once). They must multiplex over the same connections: a second
    pool would double the number of handshakes and hit the ``maxstartups``
    limit of the OpenSSH server. Pools are keyed by config path and assume the
    registry is loaded once at startup.
    """
    key = str(registry.path.resolve()).casefold()
    with _SHARED_LOCK:
        manager = _SHARED_MANAGERS.get(key)
        if manager is None:
            manager = ConnectionManager(registry)
            _SHARED_MANAGERS[key] = manager
            atexit.register(manager.close_all)
    return manager
