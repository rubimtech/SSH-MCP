"""Typed errors for the SSH MCP server.

Every error that is safe to show to the agent inherits from :class:`SshMcpError`
and knows how to render itself as a structured JSON payload.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence


class SshMcpError(Exception):
    """Base class for all errors raised by this server."""

    code: str = "error"

    def payload(self) -> dict[str, Any]:
        return {"error": str(self), "error_code": self.code}


class ConfigError(SshMcpError):
    """The server configuration file is missing or invalid."""

    code = "config_error"


class InvalidInputError(SshMcpError):
    """A tool argument is missing, malformed or would do something unsafe."""

    code = "invalid_input"


class UnknownServerError(SshMcpError):
    """The caller referenced a server name that is not configured."""

    code = "unknown_server"

    def __init__(self, name: str, available: list[str]) -> None:
        self.name = name
        self.available = available
        listed = ", ".join(available) if available else "(none configured)"
        super().__init__(
            f"Unknown server '{name}'. Configured servers: {listed}. "
            "Call ssh_list_servers to see names and descriptions."
        )

    def payload(self) -> dict[str, Any]:
        base = super().payload()
        base["available_servers"] = self.available
        return base


class LocalPathError(SshMcpError):
    """A local path is outside the configured allow-list."""

    code = "local_path_error"


class SshConnectionError(SshMcpError):
    """The remote host could not be reached."""

    code = "ssh_connection_error"


class AuthError(SshConnectionError):
    """Credentials were rejected by the remote host.

    ``attempts`` holds one entry per rung of the authentication ladder that was
    tried or skipped, so the caller can see *why* every method failed instead of
    a single anonymous "Authentication failed".
    """

    code = "ssh_auth_error"

    def __init__(self, message: str, attempts: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.attempts: tuple[str, ...] = tuple(attempts)

    def payload(self) -> dict[str, Any]:
        base = super().payload()
        if self.attempts:
            base["auth_attempts"] = list(self.attempts)
        return base


class HostKeyError(SshConnectionError):
    """Base class for host-key verification failures."""

    code = "host_key_error"


class UnknownHostKeyError(HostKeyError):
    """The host key is not on record and the profile forbids trusting it."""

    code = "unknown_host_key"

    def __init__(
        self,
        host: str,
        path: Path | None = None,
        *,
        hint: str = "",
    ) -> None:
        self.host = host
        self.known_hosts = path
        location = f" (known_hosts: {path})" if path is not None else ""
        remedy = hint or (
            "Verify the host key out of band, then either set "
            "host_key_policy: tofu or host_key_fingerprint: 'SHA256:...'"
        )
        super().__init__(f"No known host key for '{host}'{location}. {remedy}")

    def payload(self) -> dict[str, Any]:
        base = super().payload()
        base["host"] = self.host
        if self.known_hosts is not None:
            base["known_hosts"] = str(self.known_hosts)
        return base


class HostKeyMismatchError(HostKeyError):
    """The host presented a key that differs from the one on record or pinned."""

    code = "host_key_mismatch"

    def __init__(
        self,
        host: str,
        *,
        expected: Sequence[str] = (),
        received: str = "",
        path: Path | None = None,
        hint: str = "",
    ) -> None:
        self.host = host
        self.expected = tuple(expected)
        self.received = received
        self.known_hosts = path
        known = ", ".join(self.expected) if self.expected else "(nothing on record)"
        where = f" in {path}" if path is not None else ""
        detail = f"expected {known}, received {received}" if received else f"expected {known}"
        remedy = hint or (
            "Possible man-in-the-middle. Confirm the host key out of band and, "
            "if the host was rebuilt, drop the stale entry with ssh_forget_host_key."
        )
        super().__init__(f"Host key mismatch for '{host}'{where}: {detail}. {remedy}")

    def payload(self) -> dict[str, Any]:
        base = super().payload()
        base["host"] = self.host
        base["expected_fingerprints"] = list(self.expected)
        if self.received:
            base["received_fingerprint"] = self.received
        if self.known_hosts is not None:
            base["known_hosts"] = str(self.known_hosts)
        return base


class RemoteTimeoutError(SshMcpError):
    """A remote operation exceeded its timeout."""

    code = "remote_timeout"


class ServerBusyError(SshMcpError):
    """Too many concurrent operations are queued for one server."""

    code = "server_busy"