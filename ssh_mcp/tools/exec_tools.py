"""Remote command execution: foreground, background jobs, sudo and signals.

Модуль держит всё, что связано с запуском команд на удалённом хосте:

* обычный ``ssh_execute`` с честным дедлайном (дренаж-канал, а не
  ``recv_exit_status()``, который игнорирует таймаут);
* фоновые задачи 2.4 — ``background=True`` возвращает единый ``job_id``
  (подход tufantunc), состояние читает ``ssh_job_status``, записи живут TTL;
* ``ssh_sudo`` 2.7 — пароль уходит в stdin канала и никогда не попадает в argv;
* ``ssh_signal`` 2.12 — лестница INT→TERM→KILL с проверкой доставки.

Про сигналы отдельно: ``Channel.send_signal()`` у paramiko (как и у ssh2) не
доходит до удалённой стороны после ``shutdown_write()`` — сигнал уходит в
закрытый канал и теряется. Поэтому сигнал отправляется отдельной командой
``kill`` на том же хосте, а доставка проверяется опросом ``kill -0``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import threading
import time
import uuid
from dataclasses import dataclass, replace
from functools import partial
from typing import Any

import paramiko
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..context import ToolContext, guarded
from ..errors import RemoteTimeoutError, SshMcpError
from ..models import ServerProfile
from ..responses import STDOUT_LIMIT, clamp, clip
from ..safety import fence, register_secrets

logger = logging.getLogger(__name__)

EXECUTE = ToolAnnotations(
    title="Execute SSH command",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)
BACKGROUND = ToolAnnotations(
    title="Start detached SSH command",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)
READ_ONLY = ToolAnnotations(
    title="Background command state",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 600
POLL_INTERVAL = 0.05
KILL_GRACE = 1.0

JOB_PREFIX = "ssh-mcp-job"
LAUNCH_TIMEOUT = 60
PID_WAIT_STEPS = 30
CLEANUP_TIMEOUT = 20
JOB_LOG_READ_LIMIT = 20_000

DEFAULT_SIGNAL_GRACE = 2.0
MAX_SIGNAL_GRACE = 30.0
SIGNAL_LADDER = ("INT", "TERM", "KILL")
SIGNAL_NAMES = ("INT", "TERM", "KILL", "HUP", "QUIT", "USR1", "USR2", "STOP", "CONT", "WINCH")
MAX_PID = 4_194_304

_SUDO_PASSWORD_HINTS = (
    "incorrect password",
    "sorry, try again",
    "a password is required",
    "no tty present",
    "authentication failure",
)


class ToolArgumentError(SshMcpError):
    """Аргумент инструмента вне допустимого диапазона или списка."""

    code = "invalid_argument"


class UnknownJobError(SshMcpError):
    """Запрошен job_id, которого нет в реестре."""

    code = "unknown_job"

    def __init__(self, job_id: str, known: list[str]) -> None:
        self.job_id = job_id
        listed = ", ".join(known) if known else "(нет активных задач)"
        super().__init__(
            f"Unknown job_id '{job_id}'. Known jobs: {listed}. "
            "Call ssh_job_status() without arguments to list tracked jobs."
        )


def _env_float(name: str, default: float) -> float:
    """Положительное число из окружения, иначе значение по умолчанию."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number, using %s", name, raw, default)
        return default
    return value if value > 0 else default


JOB_TTL_SECONDS = _env_float("SSH_MCP_JOB_TTL", 3600.0)


# --- канал и обычный запуск ------------------------------------------------


def _drain(
    channel: paramiko.Channel,
    timeout: int,
) -> tuple[int, str, str]:
    """Pump a channel to completion under an absolute deadline.

    ``Channel.recv_exit_status()`` blocks forever when the remote side dies and
    ignores ``exec_command(timeout=...)``, so a hanging command would pin a
    worker thread for good. Polling ``*_ready()`` keeps the deadline honest and
    lets us keep draining (and truncating) output after the limit is hit --
    stopping early would block the remote command on a full pipe.
    """
    deadline = time.monotonic() + timeout
    stdout, stderr = bytearray(), bytearray()
    killed = False

    while True:
        moved = False
        if channel.recv_ready():
            stdout += channel.recv(65_536)
            moved = True
        if channel.recv_stderr_ready():
            stderr += channel.recv_stderr(65_536)
            moved = True

        over_limit = len(stdout) > STDOUT_LIMIT or len(stderr) > STDOUT_LIMIT
        if over_limit and not killed:
            del stdout[STDOUT_LIMIT:]
            del stderr[STDOUT_LIMIT:]
            killed = True

        if (
            channel.exit_status_ready()
            and not channel.recv_ready()
            and not channel.recv_stderr_ready()
        ):
            return channel.recv_exit_status(), stdout.decode("utf-8", "replace"), stderr.decode(
                "utf-8", "replace"
            )

        if channel.closed:
            # Канал закрыли, а код возврата не пришёл: ждать дедлайна бессмысленно.
            raise RemoteTimeoutError(
                "SSH channel closed before the command reported an exit code; "
                "the remote command may still be running"
            )

        if time.monotonic() > deadline:
            _terminate(channel)
            raise RemoteTimeoutError(
                f"Command exceeded {timeout}s and was terminated; raise 'timeout' or shorten it"
            )

        if not moved:
            time.sleep(POLL_INTERVAL)


def _terminate(channel: paramiko.Channel) -> None:
    """Ask the remote process to stop, then drop the channel."""
    try:
        channel.send_signal("INT")
    except Exception:  # noqa: BLE001 - best effort
        pass
    deadline = time.monotonic() + KILL_GRACE
    while time.monotonic() < deadline:
        if channel.exit_status_ready() and not channel.recv_ready():
            return
        time.sleep(POLL_INTERVAL)
    channel.close()


def _result(exit_code: int, out: str, err: str) -> dict[str, Any]:
    """Нормализовать вывод команды: обрезка по лимиту и fence от инъекций."""
    return {
        "exit_code": exit_code,
        "stdout": fence(clip(out.strip(), STDOUT_LIMIT, "stdout")),
        "stderr": fence(clip(err.strip(), STDOUT_LIMIT, "stderr")),
    }


def run_command(
    client: paramiko.SSHClient,
    command: str,
    workdir: str,
    timeout: int,
) -> dict[str, Any]:
    """Выполнить команду на готовом клиенте.

    Публичная точка входа: её переиспользует пакетный ``ssh_run_many``.
    """
    full = f"cd {shlex.quote(workdir)} && {command}" if workdir else command
    _, stdout, _ = client.exec_command(full)
    channel = stdout.channel
    try:
        exit_code, out, err = _drain(channel, timeout)
    finally:
        # Канал держит один из слотов MaxSessions — освобождаем сразу.
        channel.close()
    return _result(exit_code, out, err)


# --- реестр фоновых задач -------------------------------------------------


@dataclass(frozen=True, slots=True)
class RemoteJob:
    """Фоновая команда, отвязанная от канала и живущая на удалённом хосте.

    Состояние (``exit_code``, вывод) намеренно не хранится локально: файлы
    задачи лежат на хосте, локально известны только адрес и срок жизни.
    """

    job_id: str
    server: str
    host: str
    command: str
    workdir: str
    remote_dir: str
    pid: int | None
    started_at: float

    def age(self, now: float | None = None) -> float:
        moment = time.time() if now is None else now
        return max(0.0, moment - self.started_at)

    def describe(self) -> dict[str, Any]:
        """Краткая запись для списка задач (без похода в сеть)."""
        return {
            "job_id": self.job_id,
            "server": self.server,
            "command": self.command,
            "pid": self.pid,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)),
            "age_seconds": round(self.age(), 1),
        }


class JobRegistry:
    """Процесс-wide реестр фоновых задач с TTL-уборкой.

    Общий на процесс — как и пул соединений: несколько MCP-сессий должны видеть
    одну и ту же задачу, иначе статус потеряет связь с запуском.
    """

    def __init__(self, ttl: float = JOB_TTL_SECONDS) -> None:
        self._ttl = ttl
        self._jobs: dict[str, RemoteJob] = {}
        self._lock = threading.Lock()

    @property
    def ttl(self) -> float:
        return self._ttl

    def add(self, job: RemoteJob) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str) -> RemoteJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def set_pid(self, job_id: str, pid: int | None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None and pid:
                self._jobs[job_id] = replace(job, pid=pid)

    def forget(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def all(self) -> list[RemoteJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda item: item.started_at, reverse=True)

    def expired(self, now: float | None = None) -> list[RemoteJob]:
        moment = time.time() if now is None else now
        with self._lock:
            return [job for job in self._jobs.values() if job.age(moment) > self._ttl]


JOBS = JobRegistry()


# --- фоновые команды: скрипты ---------------------------------------------


def _supervisor_script(workdir: str) -> str:
    """Supervisor для фоновой задачи: pid, cd, запуск, код возврата в файл.

    Команда пользователя лежит в отдельном ``command.sh`` — так она не ломает
    supervisor (лишняя `;`, `{`/`}` или heredoc в команде не мешают парсингу),
    а её pid записывается в ``cmd.pid`` и остаётся тем pid'ом, который можно
    убить через ``ssh_signal``.
    """
    lines = [
        "#!/bin/sh",
        "# Создано ssh-mcp: supervisor фоновой команды.",
        'job_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
        'echo $$ > "$job_dir/supervisor.pid"',
    ]
    if workdir:
        lines += [
            f"if ! cd {shlex.quote(workdir)}; then",
            '    echo "cd failed: cannot enter workdir" >> "$job_dir/output.log"',
            '    echo 127 > "$job_dir/exit_code"',
            "    exit 127",
            "fi",
        ]
    lines += [
        'sh "$job_dir/command.sh" > "$job_dir/output.log" 2>&1 &',
        "child=$!",
        'echo "$child" > "$job_dir/cmd.pid"',
        'wait "$child"',
        "code=$?",
        'echo "$code" > "$job_dir/exit_code"',
        'exit "$code"',
    ]
    return "\n".join(lines) + "\n"


def _launch_script(command: str, workdir: str) -> str:
    """Одноразовый скрипт запуска: каталог задачи, два файла, отвязка процесса.

    Каталог создаётся ``mktemp -d`` (права 0700, подделать нельзя), скрипты
    пишутся через heredoc с цифровым разделителем, поэтому кавычки в команде
    пользователя остаются нетронутыми. ``setsid`` отвязывает процесс от
    терминала — иначе sshd при закрытии канала прибил бы его по SIGHUP;
    ``nohup`` оставлен запасным вариантом для систем без ``setsid``.
    """
    token = uuid.uuid4().hex[:12]
    command_end = f"__SSHM_END_COMMAND_{token}__"
    run_end = f"__SSHM_END_RUN_{token}__"
    lines = [
        "umask 077",
        f'd=$(mktemp -d "${{TMPDIR:-/tmp}}/{JOB_PREFIX}-XXXXXXXXXX") || exit 1',
        f"cat > \"$d/command.sh\" <<'{command_end}'",
        "#!/bin/sh",
        command,
        command_end,
        f"cat > \"$d/run.sh\" <<'{run_end}'",
        _supervisor_script(workdir).rstrip("\n"),
        run_end,
        'chmod 700 "$d/command.sh" "$d/run.sh"',
        "if command -v setsid >/dev/null 2>&1; then",
        '    setsid "$d/run.sh" < /dev/null > /dev/null 2>&1 &',
        "else",
        '    nohup "$d/run.sh" < /dev/null > /dev/null 2>&1 &',
        "fi",
        "i=0",
        f'while [ ! -s "$d/cmd.pid" ] && [ "$i" -lt {PID_WAIT_STEPS} ]; do',
        "    sleep 0.1",
        "    i=$((i + 1))",
        "done",
        'printf "%s\\n" "$d"',
        'cat "$d/cmd.pid" 2>/dev/null',
    ]
    return "\n".join(lines) + "\n"


def _launch_background(client: paramiko.SSHClient, script: str) -> tuple[str, int | None]:
    """Запустить скрипт запуска и вернуть (каталог задачи, pid команды)."""
    _, stdout, _ = client.exec_command(script)
    channel = stdout.channel
    try:
        exit_code, out, err = _drain(channel, LAUNCH_TIMEOUT)
    finally:
        channel.close()

    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if exit_code != 0 or len(lines) < 2:
        detail = clip((err or out).strip(), 500, "launcher") or f"exit code {exit_code}"
        raise SshMcpError(f"Cannot start background command:\n{fence(detail)}")

    directory = lines[-2]
    pid_text = lines[-1]
    if not directory.startswith("/") or JOB_PREFIX not in directory:
        raise SshMcpError("Launcher returned an unexpected job directory; refusing to continue")
    pid = int(pid_text) if pid_text.isdigit() else None
    return directory, pid


def _remove_tree(client: paramiko.SSHClient, directory: str) -> bool:
    """Снести каталог задачи на хосте (best effort, без вывода)."""
    _, stdout, _ = client.exec_command(f"rm -rf -- {shlex.quote(directory)}")
    channel = stdout.channel
    try:
        exit_code, _, _ = _drain(channel, CLEANUP_TIMEOUT)
    finally:
        channel.close()
    return exit_code == 0


async def _sweep_jobs(ctx: ToolContext) -> int:
    """Убрать задачи старше TTL: из реестра и с хоста.

    Локальная запись забывается сразу, удаление каталога — best effort: хост
    мог выключиться или сеть моргнуть, тогда каталог доживёт до следующего
    запуска той же команды на той же машине.
    """
    gone = JOBS.expired()
    for job in gone:
        JOBS.forget(job.job_id)
        try:
            profile = ctx.registry.get(job.server)
            removed = await asyncio.wait_for(
                ctx.connections.run(
                    profile,
                    partial(_remove_tree, directory=job.remote_dir),
                ),
                timeout=CLEANUP_TIMEOUT,
            )
            if not removed:
                logger.info("Could not remove job directory %s on %s", job.remote_dir, job.server)
        except Exception:  # noqa: BLE001 - уборка не должна ломать вызов
            logger.debug("Job sweep failed for %s", job.job_id, exc_info=True)
    return len(gone)


async def _start_job(
    ctx: ToolContext,
    profile: ServerProfile,
    command: str,
    workdir: str,
) -> dict[str, Any]:
    """Отвязать команду от канала и зарегистрировать её как задачу."""
    await _sweep_jobs(ctx)
    job_id = uuid.uuid4().hex[:12]
    script = _launch_script(command, workdir)
    directory, pid = await ctx.connections.run(
        profile,
        partial(_launch_background, script=script),
    )
    JOBS.add(
        RemoteJob(
            job_id=job_id,
            server=profile.name,
            host=profile.host,
            command=command,
            workdir=workdir,
            remote_dir=directory,
            pid=pid,
            started_at=time.time(),
        )
    )
    return {
        "status": "started",
        "job_id": job_id,
        "server": profile.name,
        "command": command,
        "workdir": workdir,
        "pid": pid,
        "log_path": f"{directory}/output.log",
        "ttl_seconds": JOBS.ttl,
        "hint": (
            f"ssh_job_status(job_id='{job_id}') reports exit_code and the log tail; "
            "to stop the whole job use ssh_signal(pid=supervisor_pid, signal='TERM', "
            "group=true) — a plain signal reaches only the job's shell, and INT is "
            "ignored by any process started as a background job"
        ),
    }


# --- чтение состояния задачи ----------------------------------------------


def _read_small(sftp: paramiko.SFTPClient, path: str) -> str | None:
    """Прочитать короткий служебный файл задачи (``None``, если его нет)."""
    try:
        with sftp.file(path, "rb") as handle:
            return handle.read(64).decode("utf-8", "replace").strip()
    except OSError:
        return None


def _read_remote_job(sftp: paramiko.SFTPClient, directory: str) -> dict[str, Any]:
    """Собрать состояние задачи по файлам на хосте."""
    try:
        sftp.stat(directory)
        found = True
    except OSError:
        found = False

    exit_text = _read_small(sftp, f"{directory}/exit_code")
    pid_text = _read_small(sftp, f"{directory}/cmd.pid")
    supervisor_text = _read_small(sftp, f"{directory}/supervisor.pid")

    state: dict[str, Any] = {
        "directory_found": found,
        "exit_code": int(exit_text) if exit_text and exit_text.isdigit() else None,
        "pid": int(pid_text) if pid_text and pid_text.isdigit() else None,
        "supervisor_pid": (
            int(supervisor_text) if supervisor_text and supervisor_text.isdigit() else None
        ),
    }

    try:
        size = int(sftp.stat(f"{directory}/output.log").st_size)
    except OSError:
        state.update({"log_size": None, "output": "", "truncated": False})
        return state

    limit = JOB_LOG_READ_LIMIT
    with sftp.file(f"{directory}/output.log", "rb") as handle:
        if size > limit:
            handle.seek(size - limit)
        raw = handle.read(limit + 1)
    text = raw.decode("utf-8", "replace")
    prefix = f"[начало лога пропущено, {size - len(raw)} байт]\n" if size > len(raw) else ""
    state.update(
        {
            "log_size": size,
            "output": fence(clip((prefix + text).strip(), STDOUT_LIMIT, "output")),
            "truncated": size > limit,
        }
    )
    return state


def _describe_job(job: RemoteJob, state: dict[str, Any], alive: bool | None) -> dict[str, Any]:
    """Собрать ответ по задаче из локальной записи и файлов на хосте."""
    exit_code = state["exit_code"]
    if not state["directory_found"]:
        verdict = "missing"
    elif exit_code is not None:
        verdict = "finished"
    elif alive is True:
        verdict = "running"
    elif alive is False:
        verdict = "stopped"
    else:
        verdict = "running"

    notes: list[str] = []
    if verdict == "missing":
        notes.append(
            "Каталог задачи исчез: хост перезагрузился, /tmp очищен или TTL-уборка "
            "уже удалила его."
        )
    elif verdict == "stopped":
        notes.append(
            "Процесса нет, а файл кода возврата не записан: supervisor убили "
            "вместе с оболочкой либо хост ушел в перезагрузку."
        )
    if state["truncated"]:
        notes.append("Показаны последние байты лога, начало обрезано.")
    if verdict in {"running", "stopped"} and state["supervisor_pid"]:
        notes.append(
            "Остановить задание целиком: ssh_signal(pid=supervisor_pid, "
            "signal='TERM', group=true) — pgid задания равен supervisor_pid."
        )

    payload: dict[str, Any] = {
        "job_id": job.job_id,
        "server": job.server,
        "state": verdict,
        "pid": state["pid"],
        "supervisor_pid": state["supervisor_pid"],
        "command": job.command,
        "exit_code": exit_code,
        "log_path": f"{job.remote_dir}/output.log",
        "log_size": state["log_size"],
        "output": state["output"],
        "truncated": state["truncated"],
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.started_at)),
        "age_seconds": round(job.age(), 1),
        "ttl_seconds": JOBS.ttl,
        "expires_in": max(0, round(JOBS.ttl - job.age(), 1)),
    }
    if job.workdir:
        payload["workdir"] = job.workdir
    if notes:
        payload["note"] = " ".join(notes)
    return payload


def _job_listing() -> dict[str, Any]:
    """Список отслеживаемых задач без похода в сеть."""
    jobs = JOBS.all()
    listing = []
    for job in jobs:
        entry = job.describe()
        entry["expires_in"] = max(0, round(JOBS.ttl - job.age(), 1))
        listing.append(entry)
    return {
        "count": len(jobs),
        "ttl_seconds": JOBS.ttl,
        "jobs": listing,
        "hint": "ssh_job_status(job_id) returns live state; records drop out after ttl_seconds",
    }


# --- sudo и сигналы ---------------------------------------------------------


def _feed_sudo_password(stdin: paramiko.ChannelStdinFile, password: str) -> bool:
    """Отдать sudo-пароль в stdin канала; ``False``, если он не достался.

    Две ловушки paramiko, обе найдены на живых хостах:

    * ``ChannelStdinFile.close()`` (а он же ``__del__``) вызывает
      ``shutdown_write()``, то есть **отправляет EOF**. Если разложить
      ``exec_command`` как ``_, stdout, _ = ...``, объект stdin сразу же
      освобождается и закрывается — sudo получает EOF вместо пароля;
    * если пароль не нужен (NOPASSWD, уже root, кэш sudoers), команда успевает
      завершиться, sshd закрывает канал, и запись падает с
      ``OSError: Socket is closed``. Это не ошибка вызова, поэтому молча
      продолжаем и сообщаем, что пароль не потребовался.
    """
    try:
        if password:
            stdin.write(password + "\n")
        stdin.close()
    except Exception:  # noqa: BLE001 - канал мог закрыться между exec и записью
        logger.debug("Sudo password was not delivered (channel closed early)", exc_info=True)
        return False
    return bool(password)


def _run_sudo(
    client: paramiko.SSHClient,
    command: str,
    workdir: str,
    timeout: int,
    password: str,
) -> dict[str, Any]:
    """Выполнить команду через sudo, отдав пароль в stdin канала.

    ``sudo -p '' -S`` читает пароль из stdin и не печатает промпт, поэтому пароль
    не появляется ни в argv, ни в выводе. ``sh -c`` нужен, чтобы sudo увидел
    команду целиком (иначе он разбирает только первый аргумент) и чтобы `cd`
    тоже выполнялся от root.

    Если пароля в профиле нет, команда уходит с ``sudo -n``: хост с NOPASSWD
    отработает, а хост, которому пароль нужен, сразу скажет об этом.
    """
    inner = f"cd {shlex.quote(workdir)} && {command}" if workdir else command
    if password:
        payload = "sudo -p '' -S sh -c " + shlex.quote(inner)
    else:
        payload = "sudo -n sh -c " + shlex.quote(inner)

    # stdin держим в переменной: иначе он соберётся GC и пришлёт EOF.
    stdin, stdout, _ = client.exec_command(payload)
    channel = stdout.channel
    try:
        sent = _feed_sudo_password(stdin, password)
        exit_code, out, err = _drain(channel, timeout)
    finally:
        channel.close()
    return {**_result(exit_code, out, err), "sudo_password_sent": sent}


def _clamp_grace(value: float) -> float:
    """Ограничить паузу ожидания сигнала диапазоном 0.1-30 секунд."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return DEFAULT_SIGNAL_GRACE
    return max(0.1, min(MAX_SIGNAL_GRACE, number))


def _normalize_signal(value: str) -> str:
    """Проверить имя сигнала: ``INT``/``sigterm``/``TERM`` либо номер 1-31."""
    text = value.strip().upper()
    if text.startswith("SIG"):
        text = text[3:]
    if text in SIGNAL_NAMES:
        return text
    if text.isdigit() and 1 <= int(text) <= 31:
        return text
    raise ToolArgumentError(
        f"Unknown signal '{value}'. Use one of {', '.join(SIGNAL_NAMES)} or a number 1-31."
    )


def _signal_ladder(signal: str, escalate: bool) -> list[str]:
    """Лестница сигналов: от запрошенного до KILL (или только он)."""
    if not escalate:
        return [signal]
    if signal in SIGNAL_LADDER:
        return list(SIGNAL_LADDER[SIGNAL_LADDER.index(signal) :])
    return [signal, *SIGNAL_LADDER]


def _signal_script(pid: int, signal: str, grace: float, group: bool = False) -> str:
    """Скрипт: отправить сигнал и опросом ``kill -0`` дождаться доставки.

    Отдельный exec-канал вместо ``channel.send_signal()``: после
    ``shutdown_write()`` paramiko (как и ssh2) может не отправить сигнал вообще.

    В режиме ``group`` сигнал уходит всей группе (``kill -s SIG -- -PID``) —
    это единственный способ остановить фоновое задание целиком: у него есть
    supervisor → sh → сама команда, и обычный сигнал по pid убивает только
    внешнюю оболочку. Плюс учитывается POSIX-правило: команда, запущенная как
    ``&``, не может поймать SIGINT/SIGQUIT.
    """
    steps = max(1, int(grace * 10))
    target = f"-{pid}" if group else str(pid)
    lines = [
        f"pid={pid}",
        'target="' + target + '"',
        'sig="' + signal + '"',
        "group=" + ("1" if group else "0"),
        f"steps={steps}",
        "alive() {",
        '    kill -0 "$pid" 2>/dev/null || return 1',
        "    state=$(sed -n 's/^.*) //p' \"/proc/$pid/stat\" 2>/dev/null | cut -d' ' -f1)",
        '    [ "$state" = "Z" ] && return 1',
        "    return 0",
        "}",
        # Члены группы, кроме зомби: иначе убитое, но не reap'нутое процесс
        # вечно выглядит как выжившее дерево.
        "members() {",
        "    ps -eo pgid=,stat= 2>/dev/null | awk -v g=\"$pid\" '$1 == g && $2 !~ /^Z/ {n++} END {print n + 0}'",
        "}",
        "if [ \"$group\" = \"1\" ]; then",
        '    if [ "$(members)" = "0" ]; then echo "STATUS not_found"; exit 0; fi',
        "else",
        '    if ! alive; then echo "STATUS not_found"; exit 0; fi',
        "fi",
        # Группа может пережить лидера: сигнал всё равно нужно отправить.
        'if ! kill -s "$sig" -- "$target" 2>/dev/null; then echo "STATUS send_failed"; exit 0; fi',
        'echo "STATUS sent"',
        "i=0",
        'while [ "$i" -lt "$steps" ]; do',
        "    if [ \"$group\" = \"1\" ]; then",
        '        if [ "$(members)" = "0" ]; then echo "STATUS delivered"; exit 0; fi',
        "    else",
        '        if ! alive; then echo "STATUS delivered"; exit 0; fi',
        "    fi",
        "    sleep 0.1",
        '    i=$((i + 1))',
        "done",
        'if [ "$group" = "1" ]; then',
        '    if [ "$(members)" != "0" ]; then echo "STATUS group_alive"; exit 0; fi',
        '    echo "STATUS delivered"',
        "    exit 0",
        "fi",
        'if alive; then echo "STATUS alive"; exit 0; fi',
        'echo "STATUS delivered"',
    ]
    return "\n".join(lines) + "\n"


def _parse_signal(out: str) -> str:
    """Достать строку ``STATUS ...`` из вывода скрипта отправки."""
    for line in reversed(out.splitlines()):
        text = line.strip()
        if text.startswith("STATUS "):
            return text.split(" ", 1)[1].strip()
    return "unknown"


def _send_signal(
    client: paramiko.SSHClient,
    pid: int,
    signal: str,
    grace: float,
    group: bool = False,
) -> dict[str, Any]:
    """Отправить один сигнал и вернуть факт доставки."""
    started = time.monotonic()
    _, stdout, _ = client.exec_command(_signal_script(pid, signal, grace, group))
    channel = stdout.channel
    try:
        exit_code, out, _ = _drain(channel, max(5, int(grace) + 10))
    finally:
        channel.close()
    verdict = _parse_signal(out)
    return {
        "signal": signal,
        "result": verdict,
        "sent": verdict in {"sent", "delivered", "alive", "group_alive"},
        "delivered": verdict == "delivered",
        "waited_seconds": round(time.monotonic() - started, 2),
        "exit_code": exit_code,
    }


def _probe_alive(client: paramiko.SSHClient, pid: int | None) -> bool | None:
    """Жив ли процесс: ``None``, если pid неизвестен."""
    if pid is None:
        return None
    script = f"if kill -0 {pid} 2>/dev/null; then echo alive; else echo gone; fi\n"
    _, stdout, _ = client.exec_command(script)
    channel = stdout.channel
    try:
        _, out, _ = _drain(channel, 10)
    finally:
        channel.close()
    return "alive" in out


def _status_summary(job_id: str) -> str:
    """Короткая запись для audit-трека по вызову ssh_job_status."""
    wanted = job_id.strip()
    return f"job={wanted}" if wanted else "list"


# --- регистрация инструментов ---------------------------------------------


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_execute", title="Execute SSH command", annotations=EXECUTE)
    async def ssh_execute(
        command: str,
        server: str = "",
        workdir: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        background: bool = False,
    ) -> str:
        """Run a shell command on a configured server over SSH.

        Args:
            command: Shell command to run on the remote host (required).
            server: Server name from ssh_list_servers. Empty uses the default
                server; a host address or a tag is also accepted.
            workdir: Remote working directory. Empty falls back to the server's
                configured `default_workdir`.
            timeout: Timeout in seconds (1-600, default 30).
            background: Detach the command (setsid, or nohup as a fallback) and
                return a `job_id` instead of waiting for it. Poll it with
                `ssh_job_status`. For a detached command `timeout` applies only
                to the launcher, not to the command itself.

        Returns:
            JSON with exit_code, stdout and stderr; with `background` — job_id,
            pid and the path of the remote log.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            directory = workdir or profile.default_workdir or ""
            seconds = clamp(timeout, 1, MAX_TIMEOUT, DEFAULT_TIMEOUT)
            if background:
                return await _start_job(ctx, profile, command, directory)
            result = await ctx.connections.run(
                profile,
                lambda client: run_command(client, command, directory, seconds),
            )
            result.update({"server": profile.name, "command": command})
            if directory:
                result["workdir"] = directory
            return result

        return await guarded(run, name="ssh_execute", server=server, summary=command[:200])

    @mcp.tool(
        name="ssh_job_status",
        title="Check a background SSH command",
        annotations=READ_ONLY,
    )
    async def ssh_job_status(job_id: str = "") -> str:
        """Check a command started with `ssh_execute(background=True)`.

        Args:
            job_id: Job identifier returned by the background call. Empty lists
                every tracked job with its age (no network round trip).

        Returns:
            JSON with state (running, finished, stopped, missing), exit_code,
            the tail of the command output, log path and TTL counters. The job
            record and its remote directory are dropped after the TTL.
        """

        async def run() -> dict[str, Any]:
            await _sweep_jobs(ctx)
            wanted = job_id.strip()
            if not wanted:
                return _job_listing()

            job = JOBS.get(wanted)
            if job is None:
                raise UnknownJobError(wanted, [item.job_id for item in JOBS.all()])

            profile = ctx.registry.get(job.server)
            state = await ctx.connections.run_sftp(
                profile,
                partial(_read_remote_job, directory=job.remote_dir),
            )
            alive: bool | None = None
            if state["exit_code"] is None and state["directory_found"]:
                alive = await ctx.connections.run(
                    profile,
                    partial(_probe_alive, pid=state["pid"]),
                )
                if alive:
                    JOBS.set_pid(job.job_id, state["pid"])
            return _describe_job(job, state, alive)

        return await guarded(run, name="ssh_job_status", summary=_status_summary(job_id))

    @mcp.tool(name="ssh_sudo", title="Run a command with sudo", annotations=EXECUTE)
    async def ssh_sudo(
        command: str,
        server: str = "",
        password: str = "",
        workdir: str = "",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> str:
        """Run a command on a server with root privileges.

        The sudo password is taken from the server profile by default and is
        written to the channel's stdin, never to argv, so it cannot leak into a
        process list or into this conversation. If the profile has no password
        (key-based login), the command is run with `sudo -n` and fails fast when
        the host actually wants a password.

        Args:
            command: Command to run as root (required).
            server: Server name from ssh_list_servers (empty = default).
            password: Sudo password override. Prefer the profile value: an
                explicit one becomes part of the conversation.
            workdir: Remote working directory applied inside the root shell.
            timeout: Timeout in seconds (1-600, default 30).

        Returns:
            JSON with exit_code, stdout and stderr.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            directory = workdir or profile.default_workdir or ""
            seconds = clamp(timeout, 1, MAX_TIMEOUT, DEFAULT_TIMEOUT)
            secret = password or profile.auth.password or ""
            if secret:
                # Любое эхо пароля в выводе должно быть вычищено редакцией.
                register_secrets(secret)
            result = await ctx.connections.run(
                profile,
                lambda client: _run_sudo(client, command, directory, seconds, secret),
            )
            result.update(
                {
                    "server": profile.name,
                    "command": command,
                    "sudo_mode": "password" if secret else "nopasswd",
                }
            )
            if directory:
                result["workdir"] = directory
            sent = bool(result.pop("sudo_password_sent", False))
            stderr = str(result["stderr"]).casefold()
            if result["exit_code"] != 0:
                if any(marker in stderr for marker in _SUDO_PASSWORD_HINTS):
                    result["hint"] = (
                        "sudo refused the password; check the profile password or the "
                        "sudoers rules for this user"
                    )
                elif not secret:
                    result["hint"] = (
                        "No password in the profile, so sudo ran with -n; add "
                        "auth.password or grant NOPASSWD on the host"
                    )
            elif not sent:
                result["note"] = (
                    "sudo finished without reading the password (NOPASSWD, cached "
                    "credentials or already root)"
                )
            return result

        return await guarded(run, name="ssh_sudo", server=server, summary=command[:200])

    @mcp.tool(name="ssh_signal", title="Send a signal to a remote process", annotations=EXECUTE)
    async def ssh_signal(
        pid: int,
        server: str = "",
        signal: str = "INT",
        grace: float = DEFAULT_SIGNAL_GRACE,
        escalate: bool = False,
        group: bool = False,
    ) -> str:
        """Send a signal to a process on a server and verify it was delivered.

        The signal travels as `kill -SIGNAL pid` on a separate channel, never as
        `channel.send_signal()`: after `shutdown_write()` paramiko (like ssh2)
        may drop the signal entirely. Delivery is confirmed by polling the pid.

        Two caveats found on real hosts:
        * a process started as `&` cannot catch SIGINT/SIGQUIT (POSIX rule), so
          INT against a background job always looks "delivered to nobody" —
          use TERM or KILL;
        * a command run through `sh -c` forks the real work, so a signal to
          that pid may leave grandchildren alive. Pass `group=true` with the
          job's `supervisor_pid` (from ssh_job_status) to signal the whole
          process group of a background job.

        Args:
            pid: Process id on the server (required), or a process-group leader
                when `group` is true.
            server: Server name from ssh_list_servers (empty = default).
            signal: INT, TERM, KILL, HUP, QUIT, USR1, USR2, STOP, CONT, WINCH
                or a number 1-31 (default INT).
            grace: Seconds to wait for the process to disappear after each
                signal (0.1-30, default 2).
            escalate: Walk INT→TERM→KILL starting from `signal`, stopping as
                soon as the process is gone.
            group: Send the signal to the whole process group `-pid` instead of
                the single process (default False).

        Returns:
            JSON with per-step results, whether the signal was delivered and the
            final state: gone, alive, group_alive, not_found or send_failed.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            if not 1 <= int(pid) <= MAX_PID:
                raise ToolArgumentError(f"pid must be between 1 and {MAX_PID}, got {pid}")
            first = _normalize_signal(signal)
            wait = _clamp_grace(grace)
            ladder = _signal_ladder(first, escalate)

            steps: list[dict[str, Any]] = []
            for name in ladder:
                step = await ctx.connections.run(
                    profile,
                    partial(_send_signal, pid=int(pid), signal=name, grace=wait, group=group),
                )
                steps.append(step)
                if step["delivered"] or step["result"] in {"not_found", "send_failed"}:
                    break

            final = steps[-1]["result"] if steps else "unknown"
            payload: dict[str, Any] = {
                "server": profile.name,
                "pid": int(pid),
                "requested_signal": first,
                "ladder": ladder,
                "group": group,
                "steps": steps,
                "sent": sum(1 for step in steps if step["sent"]),
                "delivered": bool(steps and steps[-1]["delivered"]),
                "state": "gone" if final == "delivered" else final,
                "escalated": len(steps) > 1,
            }
            if final == "not_found":
                payload["hint"] = "No such process: the pid is free or belongs to another session"
            elif final == "send_failed":
                payload["hint"] = "kill failed: the process belongs to another user"
            elif final == "group_alive":
                payload["hint"] = (
                    "The leader is gone but the process group still has members; "
                    "the signal reached only part of the tree"
                )
            elif final == "alive":
                payload["hint"] = (
                    "The process survived the whole ladder. Background jobs ignore "
                    "SIGINT/SIGQUIT by the POSIX & rule, and a sh -c wrapper may have "
                    "swallowed the signal: retry with signal='TERM', escalate=true, or "
                    "group=true against supervisor_pid"
                )
            return payload

        return await guarded(
            run,
            name="ssh_signal",
            server=server,
            summary=f"pid={int(pid)} {signal} group={group}",
        )