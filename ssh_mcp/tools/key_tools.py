"""SSH key tools: create a keypair locally and authorize it on a server.

One flow, two tools:

* :func:`ssh_generate_key` creates an Ed25519/RSA/ECDSA keypair on this machine
  and returns only the public half. The private key never leaves the disk and is
  never read back into a response.
* :func:`ssh_install_key` appends the public key to the remote
  ``~/.ssh/authorized_keys`` using the profile's current authentication
  (typically a password), so the next connection can use the key.

No config file is edited here. Point ``auth.key_path`` at the generated file and
set ``auth.type: auto`` once: the authentication ladder in
:class:`~ssh_mcp.models.AuthConfig` then tries the key first and falls back to
the password while the key does not exist yet or is not authorized on the host.
"""

from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Any

import paramiko  # noqa: F401 - keeps the optional-dependency contract explicit
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..connection import fingerprint_of_blob
from ..context import ToolContext, guarded
from ..errors import InvalidInputError
from ..responses import clamp
from ..safety import register_secrets
from .fs_tools import (
    atomic_replace,
    backup_file,
    discard,
    ensure_dir,
    exists,
    tmp_path_for,
)

KEYGEN = ToolAnnotations(
    title="Generate a local SSH keypair",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
INSTALL = ToolAnnotations(
    title="Authorize a public key on a server",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

KEY_TYPES = ("ed25519", "rsa", "ecdsa")
DEFAULT_RSA_BITS = 3072
MIN_RSA_BITS = 2048
MAX_RSA_BITS = 8192
PRIVATE_KEY_MODE = 0o600
PUBLIC_KEY_MODE = 0o644
SSH_DIR_MODE = 0o700
AUTHORIZED_KEYS_MODE = 0o600
MAX_AUTHORIZED_KEYS_BYTES = 1 << 20
DEFAULT_KEY_COMMENT = "ssh-mcp"
_PUBLIC_KEY_PREFIXES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-",
    "sk-ssh-ed25519@",
    "sk-ecdsa-sha2-",
)


def _generate_keypair(
    key_type: str,
    bits: int,
    passphrase: str,
) -> tuple[bytes, str, str]:
    """Build a keypair and return ``(private_pem, public_openssh, fingerprint)``.

    ``cryptography`` is used instead of paramiko because paramiko cannot
    generate Ed25519 keys (``Ed25519Key.generate`` does not exist) while it can
    serialize every supported type to the OpenSSH format.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    private: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    if key_type == "ed25519":
        private = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "rsa":
        private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    elif key_type == "ecdsa":
        private = ec.generate_private_key(ec.SECP256R1())
    else:  # pragma: no cover - guarded by the caller
        raise InvalidInputError(f"Unsupported key type: {key_type}")

    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        encryption,
    )
    public_openssh = (
        private.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    _, _, blob = public_openssh.partition(" ")
    return private_bytes, public_openssh, fingerprint_of_blob(blob)


def _parse_public_key(text: str) -> tuple[str, str, str]:
    """Split an ``authorized_keys`` line into ``(key_type, blob, comment)``.

    Accepts only the plain ``<type> <base64> [comment]`` form: option-prefixed
    lines are a different beast, and silently rewriting one would risk dropping
    a ``command=`` or ``from=`` restriction.
    """
    line = text.strip().splitlines()[0].strip() if text.strip() else ""
    if not line:
        raise InvalidInputError("Public key is empty")
    parts = line.split()
    if len(parts) < 2:
        raise InvalidInputError("Not an SSH public key line: expected '<type> <base64> [comment]'")
    key_type, blob = parts[0], parts[1]
    if not key_type.startswith(_PUBLIC_KEY_PREFIXES):
        raise InvalidInputError(f"Unrecognized public key type: {key_type}")
    if not fingerprint_of_blob(blob):
        raise InvalidInputError("Public key body is not valid base64")
    comment = " ".join(parts[2:])
    return key_type, blob, comment


def _authorized_keys_line(key_type: str, blob: str, comment: str) -> str:
    return f"{key_type} {blob} {comment}".rstrip()


def _read_authorized_keys(sftp: paramiko.SFTPClient, path: str) -> str:
    if not exists(sftp, path):
        return ""
    with sftp.open(path, "rb") as handle:
        data = handle.read(MAX_AUTHORIZED_KEYS_BYTES + 1)
    if len(data) > MAX_AUTHORIZED_KEYS_BYTES:
        raise InvalidInputError(
            "authorized_keys is larger than 1 MiB; refusing to rewrite it automatically"
        )
    return bytes(data).decode("utf-8", "replace")


def _write_authorized_keys(sftp: paramiko.SFTPClient, path: str, text: str) -> str:
    tmp = tmp_path_for(path)
    try:
        with sftp.open(tmp, "wb") as handle:
            handle.write(text.encode("utf-8"))
        sftp.chmod(tmp, AUTHORIZED_KEYS_MODE)
        return atomic_replace(sftp, tmp, path)
    except OSError:
        discard(sftp, tmp)
        raise


def _resolve_public_key(profile: Any, public_key: str) -> str:
    """Return the public key text: the argument, else the profile's ``.pub``."""
    if public_key.strip():
        return public_key
    key_path = profile.auth.key_path
    if key_path is None:
        raise InvalidInputError(
            f"Server '{profile.name}' has no auth.key_path and no public_key was given. "
            "Run ssh_generate_key first, or pass public_key explicitly."
        )
    pub = Path(f"{key_path}.pub")
    if not pub.is_file():
        raise InvalidInputError(
            f"Public key not found next to the private key for '{profile.name}'. "
            "Run ssh_generate_key first, or pass public_key explicitly."
        )
    return pub.read_text(encoding="utf-8")


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_generate_key", title="Generate an SSH keypair", annotations=KEYGEN)
    async def ssh_generate_key(
        key_path: str = "",
        server: str = "",
        key_type: str = "ed25519",
        bits: int = 0,
        comment: str = "",
        passphrase: str = "",
        overwrite: bool = False,
    ) -> str:
        """Create an SSH keypair on the machine running this server.

        The private key is written to `key_path` (mode 0600 where the OS allows
        it) and the public key to `<key_path>.pub`. Only the public key and its
        fingerprint are returned — the private key is never sent to the model.

        Typical flow: `ssh_generate_key(server=...)` → `ssh_install_key(server=...)`
        → the next connection uses the key, because `auth.type: auto` prefers it.

        Args:
            key_path: Where to write the private key. Empty uses the key_path
                configured for `server`. Must be inside allowed_local_dirs.
            server: Server name from ssh_list_servers; used to derive key_path and
                a default comment (empty = default server).
            key_type: ed25519 (default) | rsa | ecdsa.
            bits: RSA size, 2048-8192 (default 3072). Ignored for other types.
            comment: Key comment; defaults to `ssh-mcp:<server>`.
            passphrase: Encrypt the private key with this passphrase. A passphrase
                should also be set in servers.yaml (auth.passphrase) to be usable.
            overwrite: Replace an existing key at key_path (default False).

        Returns:
            JSON with status, key_type, fingerprint, the public key, both local
            paths and whether the key is encrypted.
        """
        kind = (key_type or "").strip().casefold()
        size = clamp(bits, MIN_RSA_BITS, MAX_RSA_BITS, DEFAULT_RSA_BITS)

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server) if server else ctx.registry.get(None)
            target = key_path.strip() or (
                str(profile.auth.key_path) if profile.auth.key_path else ""
            )
            if not target:
                raise InvalidInputError(
                    "Provide key_path, or set auth.key_path on the server and pass server."
                )
            if kind not in KEY_TYPES:
                raise InvalidInputError(f"key_type must be one of {', '.join(KEY_TYPES)}")
            if passphrase:
                register_secrets(passphrase)

            private = ctx.resolve_local(target, for_write=True)
            public = private.with_name(private.name + ".pub")
            if not overwrite and (private.exists() or public.exists()):
                raise InvalidInputError(
                    f"Key already exists at {private}; pass overwrite=True to replace it"
                )

            effective_bits = size if kind == "rsa" else 0
            private_bytes, public_openssh, fingerprint = _generate_keypair(
                kind, effective_bits, passphrase
            )

            private.write_bytes(private_bytes)
            try:
                private.chmod(PRIVATE_KEY_MODE)
            except OSError:  # noqa: BLE001 - chmod is advisory on Windows
                pass
            key_comment = comment.strip() or f"{DEFAULT_KEY_COMMENT}:{profile.name}"
            public.write_text(f"{public_openssh} {key_comment}\n", encoding="utf-8")
            try:
                public.chmod(PUBLIC_KEY_MODE)
            except OSError:  # noqa: BLE001
                pass

            return {
                "status": "generated",
                "key_type": kind,
                "fingerprint": fingerprint,
                "public_key": f"{public_openssh} {key_comment}",
                "private_path": str(private),
                "public_path": str(public),
                "encrypted": bool(passphrase),
                "next": (
                    f"Call ssh_install_key(server='{profile.name}') to authorize it "
                    "on the host; then set auth.type: auto so the key is tried before "
                    "the password."
                ),
            }

        return await guarded(
            run,
            name="ssh_generate_key",
            server=server,
            summary=f"{kind} {key_path or '(profile key_path)'}",
        )

    @mcp.tool(name="ssh_install_key", title="Authorize a public key", annotations=INSTALL)
    async def ssh_install_key(
        server: str = "",
        public_key: str = "",
        comment: str = "",
        backup: bool = False,
    ) -> str:
        """Add a public key to the remote ``~/.ssh/authorized_keys``.

        Connects using the profile's current authentication (so a password-only
        server works), then appends the key if it is not already there. The file
        is rewritten atomically with mode 0600 and the directory created with
        0700 if missing. Installing the same key twice is a no-op.

        Args:
            server: Server name from ssh_list_servers (empty = default).
            public_key: Public key line to install. Empty reads `<key_path>.pub`
                next to the server's configured auth.key_path.
            comment: Override the key comment (default: keep the one in the key).
            backup: Keep the previous authorized_keys as `.bak` before rewriting.

        Returns:
            JSON with status (`installed` or `already_present`), fingerprint,
            whether the `.ssh` directory was created and the rename method.
        """
        given_comment = comment.strip()

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            key_type, blob, key_comment = _parse_public_key(
                _resolve_public_key(profile, public_key)
            )
            fingerprint = fingerprint_of_blob(blob)
            line = _authorized_keys_line(key_type, blob, given_comment or key_comment)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                home = sftp.normalize(".")
                ssh_dir = posixpath.join(home, ".ssh")
                auth = posixpath.join(ssh_dir, "authorized_keys")
                created_dir = ensure_dir(sftp, ssh_dir, SSH_DIR_MODE)

                existing = _read_authorized_keys(sftp, auth)
                if blob in existing:
                    return {
                        "status": "already_present",
                        "server": profile.name,
                        "fingerprint": fingerprint,
                        "created_dir": created_dir,
                    }

                combined = existing
                if combined and not combined.endswith("\n"):
                    combined += "\n"
                combined += line + "\n"

                backup_info = (
                    backup_file(sftp, auth) if (backup and exists(sftp, auth)) else None
                )
                method = _write_authorized_keys(sftp, auth, combined)
                return {
                    "status": "installed",
                    "server": profile.name,
                    "fingerprint": fingerprint,
                    "created_dir": created_dir,
                    "rename": method,
                    "backup": backup_info,
                    "authorized_keys": auth,
                }

            return await ctx.connections.run_sftp(profile, action)

        return await guarded(
            run,
            name="ssh_install_key",
            server=server,
            summary=f"install {public_key[:40] or 'profile .pub'}",
        )
