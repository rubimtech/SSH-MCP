"""Filesystem primitives over SFTP: stat, symlinks, mkdir/move/remove/chmod.

Everything here works on the SFTP channel instead of shelling out, so the agent
gets structured JSON (and a clean audit entry) instead of parsing ``ls -l``
output, and destructive steps do not depend on a shell being present.

Two things the plain wrappers could not do and that live here now:

* symlinks are inspected with ``lstat`` and followed explicitly, so a link is
  never mistaken for its target and a link to a directory is never traversed
  by accident (``stat.S_ISLNK`` was never checked anywhere before);
* every content-changing operation is atomic: write to a sibling temporary
  file, set the mode on it, keep a backup, then ``rename`` over the target, so
  an interrupted operation leaves the old file intact instead of a truncated
  one, and a symlink at the target path keeps pointing where it did.
"""

from __future__ import annotations

import errno
import posixpath
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import paramiko
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..context import ToolContext, guarded
from ..responses import human_size

READS = ToolAnnotations(
    title="Remote filesystem info",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
WRITES = ToolAnnotations(
    title="Remote filesystem (change)",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

MAX_SYMLINK_HOPS = 8
MAX_TREE_DEPTH = 64
MAX_TREE_ENTRIES = 20_000
MAX_COPY_ENTRIES = 5_000
COPY_CHUNK = 256 * 1024
DEFAULT_DIR_MODE = 0o755
DEFAULT_FILE_MODE = 0o644
BACKUP_SUFFIX = ".bak"
TMP_MARKER = ".ssh-mcp-tmp."

_SYMBOLIC_CLAUSE = re.compile(r"^(?P<who>[ugoa]*)(?P<op>[-+=])(?P<what>[rwxXstRST]+)$")
_GROUP_SHIFT = {"u": 6, "g": 3, "o": 0}


class TraversalLimit(RuntimeError):
    """A tree walk hit its guard; report it instead of touching every path."""


@dataclass(frozen=True, slots=True)
class ModeSpec:
    """A parsed ``chmod`` argument: either a literal mask or a symbolic spec."""

    octal: int | None
    symbolic: str | None


@dataclass(slots=True)
class CopyStats:
    """Mutable tally of one copy run."""

    files: int = 0
    dirs: int = 0
    links: int = 0
    bytes_copied: int = 0
    skipped: list[str] = field(default_factory=list)


# --- mode parsing ---------------------------------------------------------


def parse_mode(text: str) -> ModeSpec:
    """Parse ``644``, ``0644``, ``0o644`` or ``u+x,go-w`` into a frozen spec."""
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("mode must not be empty: use octal like '0644' or symbolic like 'u+x'")

    # "=" is a symbolic operator too, and an octal string never contains one of
    # these three characters.
    if any(char in cleaned for char in "+-="):
        clauses = [item.strip() for item in cleaned.split(",") if item.strip()]
        if not clauses or not all(_SYMBOLIC_CLAUSE.match(item) for item in clauses):
            raise ValueError(
                f"Cannot parse symbolic mode {text!r}; examples: 'u+x', 'go-w', 'a=rw', 'u+s'"
            )
        return ModeSpec(octal=None, symbolic=",".join(clauses))

    digits = cleaned[2:] if cleaned[:2].lower() == "0o" else cleaned
    if not digits.isdigit() or not 1 <= len(digits) <= 4:
        raise ValueError(
            f"Cannot parse mode {text!r}; use octal like '0644' or symbolic like 'u+x'"
        )
    value = int(digits, 8)
    if value > 0o7777:
        raise ValueError(f"Mode {text!r} is out of range (max 7777)")
    return ModeSpec(octal=value, symbolic=None)


def apply_mode(current: int, spec: ModeSpec, *, is_dir: bool = False) -> int:
    """Resolve a spec against the current permission bits."""
    if spec.octal is not None:
        return spec.octal
    result = stat.S_IMODE(current)
    for clause in (spec.symbolic or "").split(","):
        parts = _SYMBOLIC_CLAUSE.match(clause)
        if parts is None:  # pragma: no cover - parse_mode already validated
            raise ValueError(f"Cannot parse symbolic clause {clause!r}")
        mask, value, special_mask, special_value = _clause_bits(
            parts["who"] or "a", parts["what"], result, is_dir
        )
        if parts["op"] == "=":
            result = (result & ~(mask | special_mask)) | value | special_value
        elif parts["op"] == "+":
            result |= value | special_value
        else:
            result &= ~(value | special_value)
    return result & 0o7777


def _clause_bits(who: str, what: str, current: int, is_dir: bool) -> tuple[int, int, int, int]:
    """Expand one symbolic clause into (mask, value, special_mask, special_value)."""
    rwx = 0
    if "r" in what:
        rwx |= 0o4
    if "w" in what:
        rwx |= 0o2
    if "x" in what or "X" in what and (current & 0o111 or is_dir):
        rwx |= 0o1

    mask = value = special_mask = special_value = 0
    wants_setid = "s" in what or "S" in what
    wants_sticky = "t" in what or "T" in what
    for group in "ugo" if who == "a" else who:
        shift = _GROUP_SHIFT[group]
        mask |= 0o7 << shift
        value |= rwx << shift
        if wants_setid:
            bit = stat.S_ISUID if group == "u" else stat.S_ISGID if group == "g" else 0
            special_mask |= bit
            special_value |= bit
        if wants_sticky:
            special_mask |= stat.S_ISVTX
            special_value |= stat.S_ISVTX
    return mask, value, special_mask, special_value


# --- path helpers ---------------------------------------------------------


def type_name(mode: int) -> str:
    """Human name for a file type encoded in ``st_mode``."""
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block"
    if stat.S_ISCHR(mode):
        return "char"
    return "unknown"


def describe_attr(path: str, attr: paramiko.SFTPAttributes) -> dict[str, Any]:
    """Render one stat result as agent-safe JSON."""
    return {
        "path": path,
        "type": type_name(attr.st_mode),
        "size": attr.st_size,
        "size_human": human_size(attr.st_size),
        "mode": f"0o{stat.S_IMODE(attr.st_mode):04o}",
        "permissions": stat.filemode(attr.st_mode),
        "uid": attr.st_uid,
        "gid": attr.st_gid,
        "mtime": attr.st_mtime,
        "mtime_iso": datetime.fromtimestamp(attr.st_mtime).isoformat(sep=" ", timespec="seconds"),
    }


def absolute_link_target(link_path: str, target: str) -> str:
    """Resolve a link target against the directory holding the link."""
    if posixpath.isabs(target):
        return posixpath.normpath(target)
    return posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))


def resolve_link_target(
    sftp: paramiko.SFTPClient,
    path: str,
    *,
    max_hops: int = MAX_SYMLINK_HOPS,
) -> tuple[str, list[str]]:
    """Follow a symlink chain with ``lstat`` and report every hop taken."""
    current = path
    chain: list[str] = []
    seen = {path}
    for hop in range(max_hops):
        try:
            info = sftp.lstat(current)
        except OSError as exc:
            if hop == 0 and exc.errno == errno.ENOENT:
                return current, chain
            raise
        if not stat.S_ISLNK(info.st_mode):
            return current, chain
        target = sftp.readlink(current)
        nxt = absolute_link_target(current, target)
        if nxt in seen:
            raise OSError(errno.ELOOP, f"Symlink loop at {path}")
        seen.add(nxt)
        chain.append(f"{current} -> {target}")
        current = nxt
    raise OSError(errno.ELOOP, f"Too many symlink hops starting at {path}")


def tmp_path_for(path: str) -> str:
    """Sibling temporary path: same directory means the same filesystem."""
    return f"{path}{TMP_MARKER}{secrets.token_hex(6)}"


def atomic_replace(sftp: paramiko.SFTPClient, tmp: str, target: str) -> str:
    """Rename ``tmp`` onto ``target``, preferring the atomic posix-rename.

    ``rename`` alone is not enough: SFTP v3 servers may refuse to overwrite an
    existing path, and plain ``mv`` over a symlink would replace the link
    itself instead of its target.
    """
    try:
        sftp.posix_rename(tmp, target)
        return "posix_rename"
    except (AttributeError, OSError):
        pass
    try:
        sftp.rename(tmp, target)
        return "rename"
    except OSError:
        pass
    sftp.remove(target)
    sftp.rename(tmp, target)
    return "remove+rename"


def os_reason(exc: OSError) -> str:
    """Readable one-liner for an I/O error, without the noisy repr."""
    return exc.strerror or str(exc) or type(exc).__name__


def attempt(action: Callable[[], dict[str, Any]], *, what: str) -> dict[str, Any]:
    """Run a filesystem action, turning expected I/O errors into a payload.

    SshMcpError subclasses belong to another package, and an ``errno``-carrying
    error is the normal outcome of a mistyped path, not a server fault.
    """
    try:
        return action()
    except (OSError, ValueError) as exc:
        payload: dict[str, Any] = {
            "status": "error",
            "error": f"{what}: {os_reason(exc) if isinstance(exc, OSError) else exc}",
        }
        if isinstance(exc, OSError) and exc.errno is not None:
            payload["errno"] = exc.errno
        return payload


# --- streaming copy -------------------------------------------------------


def stream_copy(
    source_sftp: paramiko.SFTPClient,
    target_sftp: paramiko.SFTPClient,
    source: str,
    target: str,
) -> int:
    """Copy one file in bounded chunks and return the number of bytes moved."""
    moved = 0
    with source_sftp.file(source, "rb") as reader, target_sftp.file(target, "wb") as writer:
        while True:
            chunk = reader.read(COPY_CHUNK)
            if not chunk:
                break
            writer.write(chunk)
            moved += len(chunk)
    return moved


def backup_file(
    sftp: paramiko.SFTPClient,
    path: str,
    suffix: str = BACKUP_SUFFIX,
) -> dict[str, Any] | None:
    """Copy the current content of ``path`` next to itself, keeping the mode."""
    info = sftp.lstat(path)
    if stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode):
        return None
    backup = f"{path}{suffix}"
    stream_copy(sftp, sftp, path, backup)
    sftp.chmod(backup, stat.S_IMODE(info.st_mode))
    return {"path": backup, "size": info.st_size}


def copy_node(
    source_sftp: paramiko.SFTPClient,
    target_sftp: paramiko.SFTPClient,
    source: str,
    target: str,
    *,
    overwrite: bool,
    stats: CopyStats,
    depth: int = 0,
) -> None:
    """Copy a file, a symlink or a whole directory tree between two endpoints."""
    if depth > MAX_TREE_DEPTH:
        raise TraversalLimit(f"Tree is deeper than {MAX_TREE_DEPTH} levels at {source}")
    if stats.files + stats.dirs + stats.links >= MAX_COPY_ENTRIES:
        raise TraversalLimit(f"Copy stopped after {MAX_COPY_ENTRIES} entries")

    info = source_sftp.lstat(source)

    if stat.S_ISLNK(info.st_mode):
        link_target = source_sftp.readlink(source)
        try:
            target_sftp.symlink(link_target, target)
        except OSError:
            # The receiver may forbid symlinks: fall back to copying the target.
            resolved, _ = resolve_link_target(source_sftp, source)
            copy_node(
                source_sftp,
                target_sftp,
                resolved,
                target,
                overwrite=overwrite,
                stats=stats,
                depth=depth + 1,
            )
            return
        stats.links += 1
        return

    if stat.S_ISDIR(info.st_mode):
        if not ensure_dir(target_sftp, target, stat.S_IMODE(info.st_mode)):
            stats.skipped.append(f"{target} (exists)")
            return
        stats.dirs += 1
        for attr in source_sftp.listdir_attr(source):
            copy_node(
                source_sftp,
                target_sftp,
                posixpath.join(source, attr.filename),
                posixpath.join(target, attr.filename),
                overwrite=overwrite,
                stats=stats,
                depth=depth + 1,
            )
        return

    if exists(target_sftp, target) and not overwrite:
        stats.skipped.append(target)
        return
    tmp = tmp_path_for(target)
    try:
        moved = stream_copy(source_sftp, target_sftp, source, tmp)
        target_sftp.chmod(tmp, stat.S_IMODE(info.st_mode))
        atomic_replace(target_sftp, tmp, target)
    except OSError:
        discard(target_sftp, tmp)
        raise
    stats.files += 1
    stats.bytes_copied += moved


def ensure_dir(sftp: paramiko.SFTPClient, path: str, mode: int) -> bool:
    """Create ``path`` if missing; report whether it was created by us.

    The errno cannot be trusted here: OpenSSH's sftp-server answers an existing
    directory with a plain ``SSH_FX_FAILURE`` (an ``IOError`` without an errno)
    instead of ``SSH_FX_EEXIST``, so trusting ``exc.errno`` alone makes every
    ``mkdir -p`` die on the first component that already exists. The
    authoritative test is therefore ``lstat``: a directory means "already
    there", anything else -- or a failed ``lstat`` -- means a real refusal.
    """
    try:
        sftp.mkdir(path, mode)
        return True
    except OSError as exc:
        try:
            info = sftp.lstat(path)
        except OSError:
            raise exc from None
        if stat.S_ISDIR(info.st_mode):
            return False
        raise FileExistsError(
            errno.EEXIST, "Path exists and is not a directory", path
        ) from exc


def exists(sftp: paramiko.SFTPClient, path: str) -> bool:
    """``lstat``-based existence check that never follows the path."""
    try:
        sftp.lstat(path)
    except OSError:
        return False
    return True


def discard(sftp: paramiko.SFTPClient, path: str) -> None:
    """Remove a leftover temporary path, ignoring the usual complaints."""
    try:
        sftp.remove(path)
    except OSError:
        pass


def collect_tree(
    sftp: paramiko.SFTPClient,
    root: str,
    *,
    limit: int = MAX_TREE_ENTRIES,
) -> list[tuple[str, int]]:
    """List a tree, parents before children, never traversing a symlink."""
    entries: list[tuple[str, int]] = []

    def walk(path: str, depth: int) -> None:
        if depth > MAX_TREE_DEPTH:
            raise TraversalLimit(f"Tree is deeper than {MAX_TREE_DEPTH} levels at {path}")
        if len(entries) >= limit:
            raise TraversalLimit(f"Tree has more than {limit} entries; narrow the path")
        mode = sftp.lstat(path).st_mode
        entries.append((path, mode))
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            return
        for attr in sftp.listdir_attr(path):
            walk(posixpath.join(path, attr.filename), depth + 1)

    walk(root, 0)
    return entries


def remove_tree(
    sftp: paramiko.SFTPClient,
    path: str,
    *,
    recursive: bool,
    limit: int = MAX_TREE_ENTRIES,
) -> dict[str, int]:
    """Delete a path, children first; refuse to follow a link into a tree."""
    info = sftp.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        sftp.remove(path)
        return {"files": 1, "dirs": 0, "links": 1 if stat.S_ISLNK(info.st_mode) else 0}
    if not recursive:
        sftp.rmdir(path)
        return {"files": 0, "dirs": 1, "links": 0}

    tally = {"files": 0, "dirs": 0, "links": 0}
    for child, mode in reversed(collect_tree(sftp, path, limit=limit)):
        if child == path:
            sftp.rmdir(child)
            tally["dirs"] += 1
        elif stat.S_ISDIR(mode):
            sftp.rmdir(child)
            tally["dirs"] += 1
        else:
            sftp.remove(child)
            if stat.S_ISLNK(mode):
                tally["links"] += 1
            else:
                tally["files"] += 1
    return tally


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_stat", title="Inspect a remote path", annotations=READS)
    async def ssh_stat(
        remote_path: str,
        server: str = "",
        follow_symlinks: bool = False,
    ) -> str:
        """Describe one path: type, size, mode, owner, times and symlink target.

        Uses `lstat` by default, so a symlink is reported as a link instead of
        silently becoming its target. `follow_symlinks=True` resolves the chain
        and reports the real file together with every hop taken.

        Args:
            remote_path: File, directory or symlink to inspect (required).
            server: Server name from ssh_list_servers (empty = default).
            follow_symlinks: Resolve a symlink to its target (default False).

        Returns:
            JSON with the stat result, or `exists: false` when the path is
            missing. Symlinks add `link_target`, `resolved_path` and `chain`.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                try:
                    info = sftp.lstat(remote_path)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                        return {
                            "path": remote_path,
                            "exists": False,
                            "type": "missing",
                            "server": profile.name,
                        }
                    raise
                payload = describe_attr(remote_path, info)
                payload["exists"] = True
                if stat.S_ISLNK(info.st_mode):
                    target = sftp.readlink(remote_path)
                    payload["is_symlink"] = True
                    payload["link_target"] = target
                    payload["link_target_absolute"] = absolute_link_target(remote_path, target)
                    if follow_symlinks:
                        resolved, chain = resolve_link_target(sftp, remote_path)
                        payload["followed_symlinks"] = True
                        payload["chain"] = chain
                        payload["resolved_path"] = resolved
                        payload.update(describe_attr(resolved, sftp.stat(resolved)))
                        payload["exists"] = True
                else:
                    payload["followed_symlinks"] = False
                    if follow_symlinks:
                        payload["resolved_path"] = remote_path
                        payload["chain"] = []
                return payload

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(
                    lambda: action(sftp), what=f"Cannot stat {remote_path}"
                ),
            )
            payload.setdefault("server", profile.name)
            return payload

        return await guarded(run, name="ssh_stat", server=server, summary=remote_path)

    @mcp.tool(name="ssh_read_link", title="Read a remote symlink", annotations=READS)
    async def ssh_read_link(remote_path: str, server: str = "") -> str:
        """Return the raw target of a symlink, exactly as the server stores it.

        Args:
            remote_path: Path of the symlink (required).
            server: Server name from ssh_list_servers (empty = default).

        Returns:
            JSON with `link_target` (as stored, may be relative) and the
            absolute form resolved against the link's directory.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                info = sftp.lstat(remote_path)
                if not stat.S_ISLNK(info.st_mode):
                    return {
                        "status": "not_a_symlink",
                        "path": remote_path,
                        "type": type_name(info.st_mode),
                        "hint": "Use ssh_stat to inspect a regular file or directory",
                    }
                target = sftp.readlink(remote_path)
                return {
                    "path": remote_path,
                    "link_target": target,
                    "link_target_absolute": absolute_link_target(remote_path, target),
                    "is_absolute": posixpath.isabs(target),
                }

            return await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(lambda: action(sftp), what=f"Cannot read link {remote_path}"),
            )

        return await guarded(run, name="ssh_read_link", server=server, summary=remote_path)

    @mcp.tool(name="ssh_symlink", title="Create a remote symlink", annotations=WRITES)
    async def ssh_symlink(
        target: str,
        link_path: str,
        server: str = "",
        overwrite: bool = False,
    ) -> str:
        """Create a symlink at `link_path` pointing to `target`.

        A relative `target` is stored as given, exactly like `ln -s`, so the
        link keeps working if the tree is moved.

        Args:
            target: What the link should point to (required).
            link_path: Path of the link to create (required).
            server: Server name from ssh_list_servers (empty = default).
            overwrite: Remove an existing entry at `link_path` first
                (default False).

        Returns:
            JSON with the created link and its absolute target.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                replaced = False
                if exists(sftp, link_path):
                    if not overwrite:
                        return {
                            "status": "error",
                            "error": f"{link_path} already exists; pass overwrite=True to replace it",
                        }
                    info = sftp.lstat(link_path)
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        sftp.rmdir(link_path)
                    else:
                        sftp.remove(link_path)
                    replaced = True
                sftp.symlink(target, link_path)
                return {
                    "status": "created",
                    "path": link_path,
                    "target": target,
                    "target_absolute": absolute_link_target(link_path, target),
                    "replaced": replaced,
                }

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(
                    lambda: action(sftp), what=f"Cannot create symlink {link_path}"
                ),
            )
            payload["server"] = profile.name
            return payload

        return await guarded(
            run, name="ssh_symlink", server=server, summary=f"{link_path} -> {target}"
        )

    @mcp.tool(name="ssh_mkdir", title="Create remote directories", annotations=WRITES)
    async def ssh_mkdir(
        path: str,
        server: str = "",
        parents: bool = True,
        exist_ok: bool = True,
        mode: str = "",
    ) -> str:
        """Create one directory or a whole chain of them.

        Existing directories are fine: they are detected with `lstat` instead of
        trusting the errno, because an SFTP server reports "already exists" as a
        bare failure. Only directories this call created are chmod-ed, and only
        when `mode` was given explicitly -- the permissions of an existing
        ancestor such as /tmp are never touched.

        Args:
            path: Directory to create (required).
            server: Server name from ssh_list_servers (empty = default).
            parents: Create missing parents like `mkdir -p` (default True).
                With False only the last component is created and its parent
                must already exist.
            exist_ok: Do not fail when the directory already exists
                (default True).
            mode: Octal permissions such as '0750' (default 0755).

        Returns:
            JSON with the mode applied and the list of directories created.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                spec = parse_mode(mode) if mode else ModeSpec(octal=DEFAULT_DIR_MODE, symbolic=None)
                if spec.octal is None:
                    raise ValueError("mkdir needs an octal mode such as '0755'")
                explicit = bool((mode or "").strip())
                parts = [part for part in path.split("/") if part]
                if not parts:
                    raise ValueError("path must not be empty")
                current = "/" if path.startswith("/") else ""
                chain: list[str] = []
                for part in parts:
                    current = posixpath.join(current, part) if current else part
                    chain.append(current)
                # parents=False creates only the last component, like `mkdir`
                # without -p: the ancestors have to be there already.
                created: list[str] = []
                for target in chain if parents else chain[-1:]:
                    if ensure_dir(sftp, target, spec.octal):
                        created.append(target)
                    elif not exist_ok:
                        raise FileExistsError(errno.EEXIST, "Directory already exists", target)
                if not parents:
                    ancestor = posixpath.dirname(chain[-1]) or "."
                    if not stat.S_ISDIR(sftp.lstat(ancestor).st_mode):
                        raise FileNotFoundError(
                            errno.ENOENT, f"parent directory does not exist: {ancestor}", chain[-1]
                        )
                # The server applies its umask on top of the requested mode, so
                # an explicit mode is set afterwards -- but only on the
                # directories we created ourselves.
                if explicit:
                    for item in created:
                        sftp.chmod(item, spec.octal)
                return {
                    "status": "created" if created else "exists",
                    "path": path,
                    "mode": f"0o{spec.octal:04o}",
                    "created": created,
                    "parents": parents,
                }

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(lambda: action(sftp), what=f"Cannot create {path}"),
            )
            payload["server"] = profile.name
            return payload

        return await guarded(run, name="ssh_mkdir", server=server, summary=path)

    @mcp.tool(name="ssh_move", title="Move or rename a remote path", annotations=WRITES)
    async def ssh_move(
        source: str,
        destination: str,
        server: str = "",
        overwrite: bool = False,
    ) -> str:
        """Move or rename a path, falling back to copy+delete across devices.

        A plain rename fails when source and destination live on different
        filesystems; that case is handled by copying the tree and removing the
        original, so `mv` between mounts behaves the way an agent expects.

        Args:
            source: Existing path (required).
            destination: New path (required).
            server: Server name from ssh_list_servers (empty = default).
            overwrite: Replace an existing destination (default False).

        Returns:
            JSON with the method used and what was moved.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                source_info = sftp.lstat(source)
                if exists(sftp, destination) and not overwrite:
                    raise FileExistsError(
                        errno.EEXIST,
                        "destination exists; pass overwrite=True to replace it",
                        destination,
                    )
                if stat.S_ISLNK(source_info.st_mode) or stat.S_ISREG(source_info.st_mode):
                    try:
                        method = atomic_replace(sftp, source, destination)
                    except OSError:
                        # Cross-device rename, or a server without the
                        # posix-rename extension: copy and drop the original.
                        method = ""
                    if method:
                        return {
                            "status": "moved",
                            "source": source,
                            "destination": destination,
                            "method": method,
                        }
                stats = CopyStats()
                copy_node(sftp, sftp, source, destination, overwrite=True, stats=stats)
                removed = remove_tree(sftp, source, recursive=True)
                return {
                    "status": "moved",
                    "source": source,
                    "destination": destination,
                    "method": "copy+delete",
                    "files": stats.files + removed["files"],
                    "dirs": stats.dirs + removed["dirs"],
                    "bytes": stats.bytes_copied,
                }

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(
                    lambda: action(sftp), what=f"Cannot move {source} to {destination}"
                ),
            )
            payload["server"] = profile.name
            return payload

        return await guarded(
            run, name="ssh_move", server=server, summary=f"{source} -> {destination}"
        )

    @mcp.tool(name="ssh_remove", title="Delete a remote path", annotations=WRITES)
    async def ssh_remove(
        path: str,
        server: str = "",
        recursive: bool = False,
        force: bool = False,
    ) -> str:
        """Delete a file, a symlink or a directory tree.

        A symlink is unlinked itself and never followed, so `recursive=True`
        cannot delete a whole tree by accident through a link.

        Args:
            path: Path to delete (required).
            server: Server name from ssh_list_servers (empty = default).
            recursive: Delete a directory and everything inside it
                (default False; without it a non-empty directory is refused).
            force: Succeed silently when the path is missing (default False).

        Returns:
            JSON with what was removed, or `status: missing` when `force` is
            set and nothing was there.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                if not exists(sftp, path):
                    if force:
                        return {"status": "missing", "path": path, "removed": {"files": 0, "dirs": 0}}
                    raise FileNotFoundError(errno.ENOENT, "No such file or directory", path)
                tally = remove_tree(sftp, path, recursive=recursive)
                return {
                    "status": "removed",
                    "path": path,
                    "recursive": recursive,
                    "removed": tally,
                    "total": sum(tally.values()),
                }

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(lambda: action(sftp), what=f"Cannot remove {path}"),
            )
            payload["server"] = profile.name
            return payload

        return await guarded(run, name="ssh_remove", server=server, summary=path)

    @mcp.tool(name="ssh_chmod", title="Change remote permissions", annotations=WRITES)
    async def ssh_chmod(
        path: str,
        mode: str,
        server: str = "",
        recursive: bool = False,
    ) -> str:
        """Change permissions of a file or directory, octal or symbolic.

        Symbolic specs are resolved against the current bits, so `u+x` adds the
        bit instead of replacing the mode. `recursive=True` applies the spec to
        every entry below `path`; symlinks are skipped because `chmod` would
        change their targets.

        Args:
            path: File or directory to change (required).
            mode: Octal such as '0644' or symbolic such as 'u+x,go-w'
                (required).
            server: Server name from ssh_list_servers (empty = default).
            recursive: Apply to a whole tree (default False).

        Returns:
            JSON with the previous and new mode and how many paths changed.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                spec = parse_mode(mode)
                info = sftp.lstat(path)
                if recursive and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    targets = collect_tree(sftp, path)
                else:
                    targets = [(path, info.st_mode)]
                changed: list[dict[str, str]] = []
                skipped: list[str] = []
                for target, mode_bits in targets:
                    if stat.S_ISLNK(mode_bits):
                        skipped.append(target)
                        continue
                    previous = stat.S_IMODE(mode_bits)
                    resolved = apply_mode(previous, spec, is_dir=stat.S_ISDIR(mode_bits))
                    if resolved != previous or not recursive:
                        sftp.chmod(target, resolved)
                    changed.append(
                        {
                            "path": target,
                            "from": f"0o{previous:04o}",
                            "to": f"0o{resolved:04o}",
                        }
                    )
                head = changed[0] if changed else {"from": None, "to": None}
                payload: dict[str, Any] = {
                    "status": "changed",
                    "path": path,
                    "mode": head["to"],
                    "previous_mode": head["from"],
                    "requested": mode,
                    "recursive": recursive,
                    "changed_count": len(changed),
                }
                if len(changed) > 1:
                    payload["changed"] = changed
                if skipped:
                    payload["skipped_symlinks"] = skipped
                return payload

            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: attempt(lambda: action(sftp), what=f"Cannot chmod {path}"),
            )
            payload["server"] = profile.name
            return payload

        return await guarded(run, name="ssh_chmod", server=server, summary=f"{path} {mode}")

    @mcp.tool(name="ssh_copy_between", title="Copy between two servers", annotations=WRITES)
    async def ssh_copy_between(
        source: str,
        destination: str,
        source_server: str = "",
        destination_server: str = "",
        overwrite: bool = False,
    ) -> str:
        """Copy a file, a symlink or a directory tree between two servers.

        Both ends go through the shared connection pool, so neither side needs
        network access to the other and no temporary file lands on the local
        disk. Symlinks are recreated as symlinks, permissions are preserved,
        and the copy is streamed in chunks so a large artifact does not have to
        fit in memory.

        Args:
            source: Path on `source_server` (required).
            destination: Path on `destination_server` (required).
            source_server: Server the data comes from (empty = default).
            destination_server: Server the data goes to (empty = default).
            overwrite: Replace files that already exist at the destination
                (default False; existing files are reported as skipped).

        Returns:
            JSON with files/dirs/links counts, bytes moved and a `partial` flag
            when `overwrite=False` left something behind.
        """

        async def run() -> dict[str, Any]:
            source_profile = ctx.registry.get(source_server)
            target_profile = ctx.registry.get(destination_server)
            stats = CopyStats()

            def action(source_sftp: paramiko.SFTPClient) -> dict[str, Any]:
                with ctx.connections.sftp(target_profile) as target_sftp:
                    copy_node(
                        source_sftp,
                        target_sftp,
                        source,
                        destination,
                        overwrite=overwrite,
                        stats=stats,
                    )
                return {
                    "status": "partial" if stats.skipped else "copied",
                    "source": source,
                    "destination": destination,
                    "source_server": source_profile.name,
                    "destination_server": target_profile.name,
                    "files": stats.files,
                    "dirs": stats.dirs,
                    "links": stats.links,
                    "bytes": stats.bytes_copied,
                    "size_human": human_size(stats.bytes_copied),
                    "skipped": stats.skipped[:20],
                    "skipped_count": len(stats.skipped),
                }

            def guarded_action(source_sftp: paramiko.SFTPClient) -> dict[str, Any]:
                return attempt(
                    lambda: action(source_sftp),
                    what=f"Cannot copy {source} to {target_profile.name}:{destination}",
                )

            payload = await ctx.connections.run_sftp(source_profile, guarded_action)
            return payload

        return await guarded(
            run,
            name="ssh_copy_between",
            server=source_server,
            summary=f"{source} -> {destination_server or '(default)'}",
        )