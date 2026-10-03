"""Tool context shared by every tool module."""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import ServerRegistry
from .connection import ConnectionManager, shared_manager
from .errors import LocalPathError, SshMcpError
from .responses import fail, ok
from .safety import audit, register_secrets

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Everything a tool needs: config, connections, and local path policy."""

    registry: ServerRegistry
    connections: ConnectionManager
    allowed_local_dirs: tuple[Path, ...]

    @classmethod
    def from_registry(cls, registry: ServerRegistry) -> "ToolContext":
        audit.configure(registry.path.parent)
        for profile in registry.servers.values():
            register_secrets(profile.auth.password, profile.auth.passphrase)
        return cls(
            registry=registry,
            connections=shared_manager(registry),
            allowed_local_dirs=registry.allowed_local_dirs,
        )

    def resolve_local(self, path: str, *, for_write: bool = False) -> Path:
        """Expand ``path`` and enforce the configured local allow-list."""
        resolved = Path(path).expanduser().resolve()
        self._check_allowed(resolved)
        if for_write:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    def _check_allowed(self, resolved: Path) -> None:
        if not self.allowed_local_dirs:
            logger.warning(
                "allowed_local_dirs is empty: local file access is unrestricted (%s)", resolved
            )
            return
        for allowed in self.allowed_local_dirs:
            if resolved == allowed or allowed in resolved.parents:
                return
        raise LocalPathError(
            f"Local path '{resolved}' is outside allowed_local_dirs: "
            f"{[str(item) for item in self.allowed_local_dirs]}"
        )


async def guarded(
    call: Callable[[], Any],
    *,
    name: str,
    server: str = "",
    summary: str = "",
) -> str:
    """Run a tool callable, convert failures to JSON and write an audit entry."""
    try:
        result = call()
        if inspect.isawaitable(result):
            result = await result
        audit.record(tool=name, server=server, outcome="ok", detail=summary)
        return ok(result)
    except SshMcpError as exc:
        audit.record(tool=name, server=server, outcome="error", detail=f"{exc.code}: {exc}")
        logger.warning("%s failed: %s", name, exc)
        return fail(str(exc), error_code=exc.code)
    except Exception as exc:  # noqa: BLE001 - tools must never crash the server
        audit.record(
            tool=name, server=server, outcome="crash", detail=f"{type(exc).__name__}: {exc}"
        )
        logger.exception("%s crashed", name)
        return fail(f"{type(exc).__name__}: {exc}", error_code="internal_error")
