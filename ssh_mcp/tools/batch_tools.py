"""Пакетные операции: одна команда сразу на нескольких серверах.

`run_many` (2.1) закрывает запрос «проверь это на всех хостах»: команда
разворачивается параллельно по пулу соединений, а ответ — один JSON со
сводкой и результатом по каждому серверу. Ошибка одного сервера не роняет
остальные: в отчёте она лежит рядом с успешными.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..context import ToolContext, guarded
from ..models import ServerProfile
from ..responses import clamp
from .exec_tools import DEFAULT_TIMEOUT, MAX_TIMEOUT, ToolArgumentError, run_command

BATCH = ToolAnnotations(
    title="Execute SSH command on many servers",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

DEFAULT_MAX_WORKERS = 4
MAX_WORKERS = 8


def _job_error(name: str, host: str, started: float, exc: Exception) -> dict[str, Any]:
    """Отчёт по серверу, на котором команда не выполнилась."""
    return {
        "server": name,
        "host": host,
        "error": f"{type(exc).__name__}: {exc}",
        "seconds": round(time.monotonic() - started, 2),
    }


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_run_many", title="Run one command on many servers", annotations=BATCH)
    async def ssh_run_many(
        command: str,
        servers: list[str],
        workdir: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> str:
        """Run one shell command on several servers in parallel.

        Args:
            command: Shell command to run on every server (required).
            servers: Server names from ssh_list_servers (required, non-empty).
                An unknown name fails the whole call before anything runs.
            workdir: Remote working directory. Empty falls back to each server's
                own `default_workdir`.
            timeout: Per-server timeout in seconds (1-600, default 30).
            max_workers: Concurrent servers (1-8, default 4). Jump-host targets
                wait for their hop in the pool, so keep it modest.

        Returns:
            JSON with the command, a per-server report (exit_code, stdout,
            stderr) and counters: count, succeeded, failed, wall_seconds.
        """

        async def run() -> dict[str, Any]:
            if not servers:
                raise ToolArgumentError(
                    "servers must list at least one server name from ssh_list_servers"
                )
            # Резолвим всё заранее: опечатка не должна оставлять half-run.
            profiles = [ctx.registry.get(name) for name in servers]
            seconds = clamp(timeout, 1, MAX_TIMEOUT, DEFAULT_TIMEOUT)
            limit = clamp(max_workers, 1, MAX_WORKERS, DEFAULT_MAX_WORKERS)
            gate = asyncio.Semaphore(limit)
            started = time.monotonic()

            async def one(profile: ServerProfile) -> dict[str, Any]:
                directory = workdir or profile.default_workdir or ""
                async with gate:
                    begin = time.monotonic()
                    try:
                        payload = await ctx.connections.run(
                            profile,
                            lambda client: run_command(client, command, directory, seconds),
                        )
                    except Exception as exc:  # noqa: BLE001 - счёт в отчёте, не raise
                        return _job_error(profile.name, profile.host, begin, exc)
                    payload.update(
                        {
                            "server": profile.name,
                            "host": profile.host,
                            "seconds": round(time.monotonic() - begin, 2),
                        }
                    )
                    if directory:
                        payload["workdir"] = directory
                    return payload

            results = await asyncio.gather(*(one(profile) for profile in profiles))
            failed = [
                item for item in results if "error" in item or item.get("exit_code") != 0
            ]
            payload: dict[str, Any] = {
                "command": command,
                "count": len(results),
                "succeeded": len(results) - len(failed),
                "failed": len(failed),
                "ok": not failed,
                "max_workers": limit,
                "wall_seconds": round(time.monotonic() - started, 2),
                "results": list(results),
            }
            if workdir:
                payload["workdir"] = workdir
            return payload

        return await guarded(
            run,
            name="ssh_run_many",
            server=",".join(servers),
            summary=command[:200],
        )