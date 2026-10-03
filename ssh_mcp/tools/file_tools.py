"""Remote filesystem tools: list, read, write, upload, download.

Three things the straightforward SFTP wrappers got wrong and that are handled
here now:

* writing went straight into the target, so a dropped connection left a
  half-written file behind and `mv` over a symlink replaced the link instead of
  its target -- see :func:`_write_remote_file`;
* symlinks were invisible (``stat.S_ISLNK`` was never checked), so a link and
  its target looked alike -- see :func:`_list_directory` and the
  ``follow_symlinks`` argument of the read tools;
* large files could only be read from the start and a large directory came
  back in one piece -- hence ``offset``/``length`` and ``offset``/``limit``.
"""

from __future__ import annotations

import errno
import stat
from typing import Any

import paramiko
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..context import ToolContext, guarded
from ..responses import clamp, human_size
from ..safety import fence
from .fs_tools import (
    DEFAULT_FILE_MODE,
    ModeSpec,
    apply_mode,
    atomic_replace,
    backup_file,
    discard,
    parse_mode,
    resolve_link_target,
    tmp_path_for,
    type_name,
)

READ_ONLY = ToolAnnotations(
    title="Remote filesystem (read)",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
WRITES = ToolAnnotations(
    title="Remote filesystem (write)",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

DEFAULT_READ_CHARS = 10_000
MAX_READ_CHARS = 200_000
MAX_READ_BYTES = 1024 * 1024
DEFAULT_LIST_LIMIT = 200
MAX_LIST_LIMIT = 5_000


def _entry(entry_path: str, attr: paramiko.SFTPAttributes) -> dict[str, Any]:
    """Render one directory entry."""
    mode = attr.st_mode
    return {
        "name": entry_path,
        "type": type_name(mode),
        "size": attr.st_size,
        "size_human": human_size(attr.st_size),
        "permissions": stat.filemode(mode),
        "mtime": attr.st_mtime,
    }


def _list_directory(
    sftp: paramiko.SFTPClient,
    path: str,
    *,
    details: bool,
    offset: int,
    limit: int,
    follow_symlinks: bool,
) -> dict[str, Any]:
    """List a directory with an explicit window instead of the whole listing."""
    target, chain = resolve_link_target(sftp, path) if follow_symlinks else (path, [])
    attrs = sorted(sftp.listdir_attr(target), key=lambda item: item.filename)
    total = len(attrs)
    window = attrs[offset : offset + limit] if limit else attrs[offset:]
    prefix = target.rstrip("/")
    join = f"{prefix}/" if prefix and prefix != "." else ""

    entries: list[Any] = []
    for attr in window:
        entry_path = f"{join}{attr.filename}"
        if stat.S_ISLNK(attr.st_mode):
            if not details:
                entries.append(attr.filename)
                continue
            item = _entry(entry_path, attr)
            item["link_target"] = sftp.readlink(entry_path)
            if follow_symlinks:
                try:
                    item["resolved_type"] = type_name(sftp.stat(entry_path).st_mode)
                except OSError:
                    item["resolved_type"] = "broken"
            entries.append(item)
            continue
        entries.append(_entry(entry_path, attr) if details else attr.filename)

    return {
        "path": path,
        "listing_path": target,
        "followed_symlinks": follow_symlinks,
        "resolved_chain": chain,
        "total": total,
        "offset": offset,
        "limit": limit or None,
        "count": len(window),
        "has_more": offset + len(window) < total,
        "next_offset": offset + len(window) if offset + len(window) < total else None,
        "entries": entries,
    }


def _read_remote_file(
    sftp: paramiko.SFTPClient,
    path: str,
    *,
    max_chars: int,
    offset: int,
    length: int,
    follow_symlinks: bool,
) -> dict[str, Any]:
    """Read a window of a text file, from a byte offset when asked."""
    link_info = sftp.lstat(path)
    if stat.S_ISLNK(link_info.st_mode) and not follow_symlinks:
        target = sftp.readlink(path)
        return {
            "path": path,
            "type": "link",
            "is_symlink": True,
            "link_target": target,
            "hint": "Pass follow_symlinks=True to read the target of this symlink",
        }

    target, chain = resolve_link_target(sftp, path)
    info = sftp.stat(target)
    if stat.S_ISDIR(info.st_mode):
        return {"path": path, "type": "dir", "hint": "Use ssh_list_files for directories"}

    char_cap = min(length, MAX_READ_CHARS) if length else max_chars
    byte_budget = min(length or (char_cap + 1) * 4, MAX_READ_BYTES)
    with sftp.file(target, "rb") as handle:
        handle.seek(offset)
        raw = handle.read(byte_budget + 1)
    complete = len(raw) <= byte_budget
    text = raw[:byte_budget].decode("utf-8", "replace")
    content = text[:char_cap]
    return {
        "path": path,
        "resolved_path": target,
        "resolved_chain": chain,
        "type": "file",
        "size": info.st_size,
        "offset": offset,
        "requested_bytes": length or None,
        "returned_chars": len(content),
        "content": fence(content),
        "truncated": len(text) > len(content) or not complete,
        "next_offset": offset + len(raw) if (len(raw) > len(content) or not complete) else None,
        "eof": offset >= info.st_size,
    }


def _target_mode(
    sftp: paramiko.SFTPClient,
    path: str,
    spec: ModeSpec | None,
) -> tuple[int, int | None]:
    """Pick the mode for the replacement file: requested, else preserved."""
    previous: int | None
    try:
        previous = stat.S_IMODE(sftp.lstat(path).st_mode)
    except OSError:
        previous = None
    current = previous if previous is not None else DEFAULT_FILE_MODE
    if spec is None:
        return current, previous
    return apply_mode(current, spec), previous


def _write_remote_file(
    sftp: paramiko.SFTPClient,
    path: str,
    content: str,
    *,
    spec: ModeSpec | None,
    backup: bool,
    atomic: bool,
) -> dict[str, Any]:
    """Write a file atomically, resolving symlinks to their target first.

    ``sftp.file(path, "w")`` truncates the file it opens, so an interrupted
    write leaves a corrupt file where the old content used to be. Writing to a
    sibling temporary file and renaming it over the target makes the swap a
    single filesystem operation: either the old file or the complete new one.

    A symlink at ``path`` is resolved before the swap, so the link keeps
    pointing where it did instead of being overwritten by a regular file.
    """
    data = content.encode("utf-8")

    if not atomic:
        with sftp.file(path, "wb") as handle:
            handle.write(data)
        return {
            "status": "written",
            "path": path,
            "written_to": path,
            "atomic": False,
            "size": sftp.stat(path).st_size,
        }

    target, chain = resolve_link_target(sftp, path)
    resolved_mode, previous = _target_mode(sftp, target, spec)
    tmp = tmp_path_for(target)
    backup_info: dict[str, Any] | None = None
    try:
        with sftp.file(tmp, "wb") as handle:
            handle.write(data)
        sftp.chmod(tmp, resolved_mode)
        if backup and previous is not None:
            backup_info = backup_file(sftp, target)
        method = atomic_replace(sftp, tmp, target)
    except OSError:
        discard(sftp, tmp)
        raise
    return {
        "status": "written",
        "path": path,
        "written_to": target,
        "resolved_chain": chain,
        "followed_symlink": bool(chain),
        "atomic": True,
        "rename": method,
        "mode": f"0o{resolved_mode:04o}",
        "previous_mode": f"0o{previous:04o}" if previous is not None else None,
        "backup": backup_info,
        "size": sftp.stat(target).st_size,
    }


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_list_files", title="List remote directory", annotations=READ_ONLY)
    async def ssh_list_files(
        remote_path: str = ".",
        server: str = "",
        details: bool = True,
        offset: int = 0,
        limit: int = 0,
        follow_symlinks: bool = False,
    ) -> str:
        """List files and directories on a configured server, a page at a time.

        Args:
            remote_path: Remote directory path (default: home directory).
            server: Server name from ssh_list_servers (empty = default).
            details: Include size, permissions and mtime (default True).
            offset: Number of entries to skip (default 0). Entries are sorted
                by name, so paging is stable.
            limit: Page size, 1-5000. 0 uses the default page of 200.
            follow_symlinks: Resolve links so a link to a directory is listed
                as a directory (default False). With the default, a symlink is
                reported as `type: link` together with `link_target`.

        Returns:
            JSON with the entries plus `total`, `offset`, `has_more` and
            `next_offset`; pass `next_offset` back as `offset` to continue.
        """
        page = clamp(limit, 0, MAX_LIST_LIMIT, 0) or DEFAULT_LIST_LIMIT
        start = clamp(offset, 0, 10_000_000, 0)

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                payload = _list_directory(
                    sftp,
                    remote_path,
                    details=details,
                    offset=start,
                    limit=page,
                    follow_symlinks=follow_symlinks,
                )
                payload["server"] = profile.name
                return payload

            def guarded_action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                try:
                    return action(sftp)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                        return {
                            "status": "missing",
                            "path": remote_path,
                            "error": f"No such directory: {remote_path}",
                            "server": profile.name,
                        }
                    raise

            return await ctx.connections.run_sftp(profile, guarded_action)

        return await guarded(
            run,
            name="ssh_list_files",
            server=server,
            summary=f"{remote_path} @{start}+{page}",
        )

    @mcp.tool(name="ssh_read_file", title="Read remote file", annotations=READ_ONLY)
    async def ssh_read_file(
        remote_path: str,
        server: str = "",
        max_chars: int = DEFAULT_READ_CHARS,
        offset: int = 0,
        length: int = 0,
        follow_symlinks: bool = True,
    ) -> str:
        """Read a text file from a configured server without downloading it.

        Args:
            remote_path: Remote file path (required).
            server: Server name from ssh_list_servers (empty = default).
            max_chars: Maximum characters to return (1-200000, default 10000).
            offset: Byte offset to start from (default 0) — the cheap way to
                walk a large log without transferring all of it.
            length: How many bytes to read, 1-1048576. 0 means "as much as
                `max_chars` allows". When given, it also replaces `max_chars`.
            follow_symlinks: Read through a symlink (default True). With False,
                a symlink is described instead of read, and `ssh_read_link`
                gives its target.

        Returns:
            JSON with size, content, `next_offset` when more is left, and a
            truncated flag.
        """
        limit = clamp(max_chars, 1, MAX_READ_CHARS, DEFAULT_READ_CHARS)
        window = clamp(length, 0, MAX_READ_BYTES, 0)
        start = clamp(offset, 0, 10**12, 0)

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                payload = _read_remote_file(
                    sftp,
                    remote_path,
                    max_chars=limit,
                    offset=start,
                    length=window,
                    follow_symlinks=follow_symlinks,
                )
                payload["server"] = profile.name
                return payload

            def guarded_action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                try:
                    return action(sftp)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                        return {
                            "path": remote_path,
                            "type": "missing",
                            "error": f"No such file: {remote_path}",
                            "server": profile.name,
                        }
                    raise

            return await ctx.connections.run_sftp(profile, guarded_action)

        return await guarded(
            run,
            name="ssh_read_file",
            server=server,
            summary=f"{remote_path} @{start}+{window}",
        )

    @mcp.tool(name="ssh_write_file", title="Write remote file", annotations=WRITES)
    async def ssh_write_file(
        remote_path: str,
        content: str,
        server: str = "",
        mode: str = "",
        backup: bool = False,
        atomic: bool = True,
    ) -> str:
        """Write text content to a file on a configured server.

        The write is atomic by default: the content goes to a temporary file in
        the same directory, gets the target's permissions, an optional backup is
        kept, and only then is it renamed over the target. A dropped connection
        therefore leaves the old file untouched instead of a truncated one. A
        symlink at `remote_path` is followed, so the link survives the write.

        Args:
            remote_path: Remote file path to create or overwrite (required).
            content: Full text content to write (required).
            server: Server name from ssh_list_servers (empty = default).
            mode: Permissions to apply, octal such as '0640' or symbolic such
                as 'u+x'. Empty keeps the current mode (0644 for a new file).
            backup: Keep the previous content next to the file as
                `<path>.bak` before replacing it (default False).
            atomic: Set False to write in place, truncating the target first
                (default True).

        Returns:
            JSON with status, the resolved path, mode, backup and size.
        """
        spec = parse_mode(mode) if mode else None

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                return _write_remote_file(
                    sftp,
                    remote_path,
                    content,
                    spec=spec,
                    backup=backup,
                    atomic=atomic,
                )

            def guarded_action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                try:
                    payload = action(sftp)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                        return {
                            "status": "error",
                            "error": f"Parent directory is missing for {remote_path}",
                            "hint": "Create it with ssh_mkdir first",
                            "server": profile.name,
                        }
                    raise
                payload["server"] = profile.name
                return payload

            return await ctx.connections.run_sftp(profile, guarded_action)

        return await guarded(run, name="ssh_write_file", server=server, summary=remote_path)

    @mcp.tool(name="ssh_upload_file", title="Upload file via SFTP", annotations=WRITES)
    async def ssh_upload_file(
        local_path: str,
        remote_path: str,
        server: str = "",
        atomic: bool = True,
    ) -> str:
        """Upload a local file to a configured server.

        Args:
            local_path: Local file to send; must be inside allowed_local_dirs.
            remote_path: Destination path on the server (required).
            server: Server name from ssh_list_servers (empty = default).
            atomic: Send to a temporary file and rename it into place, keeping
                the destination's permissions (default True). With False an
                interrupted upload leaves a partial file.

        Returns:
            JSON with status, paths and size.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            source = ctx.resolve_local(local_path)
            if not source.is_file():
                return {"status": "error", "error": f"Local file not found: {source}"}
            size = source.stat().st_size

            def action(sftp: paramiko.SFTPClient) -> dict[str, Any]:
                if not atomic:
                    sftp.put(str(source), remote_path)
                    return {"rename": "none"}
                target, chain = resolve_link_target(sftp, remote_path)
                mode, _ = _target_mode(sftp, target, None)
                tmp = tmp_path_for(target)
                try:
                    sftp.put(str(source), tmp)
                    sftp.chmod(tmp, mode)
                    method = atomic_replace(sftp, tmp, target)
                except OSError:
                    discard(sftp, tmp)
                    raise
                return {
                    "rename": method,
                    "written_to": target,
                    "resolved_chain": chain,
                    "mode": f"0o{mode:04o}",
                }

            extra = await ctx.connections.run_sftp(profile, action)
            payload = {
                "status": "uploaded",
                "server": profile.name,
                "local_path": str(source),
                "remote_path": remote_path,
                "size": size,
                "atomic": atomic,
            }
            payload.update(extra)
            return payload

        return await guarded(
            run,
            name="ssh_upload_file",
            server=server,
            summary=local_path + " -> " + remote_path,
        )

    @mcp.tool(name="ssh_download_file", title="Download file via SFTP", annotations=READ_ONLY)
    async def ssh_download_file(
        remote_path: str,
        local_path: str,
        server: str = "",
    ) -> str:
        """Download a file from a configured server to the local machine.

        Args:
            remote_path: File on the server to fetch (required).
            local_path: Local destination; must be inside allowed_local_dirs.
            server: Server name from ssh_list_servers (empty = default).

        Returns:
            JSON with status, paths and size.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            target = ctx.resolve_local(local_path, for_write=True)
            await ctx.connections.run_sftp(
                profile,
                lambda sftp: sftp.get(remote_path, str(target)),
            )
            return {
                "status": "downloaded",
                "server": profile.name,
                "remote_path": remote_path,
                "local_path": str(target),
                "size": target.stat().st_size,
            }

        return await guarded(
            run,
            name="ssh_download_file",
            server=server,
            summary=remote_path + " -> " + local_path,
        )