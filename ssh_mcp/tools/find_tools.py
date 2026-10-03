"""Рекурсивный обход удалённого сервера: поиск файлов и каталогов по имени.

Ни один из трёх изученных аналогов (votsie, tufantunc, TheSashaDev) рекурсивного
поиска не умеет: каталог с тысячами файлов приходится листать постранично
`ssh_list_files`, и нужный конфиг за пределами первой страницы недостижим.

Обход здесь ограничен по глубине, числу каталогов и времени, а результат — это
список метаданных: содержимое файлов при поиске **не читается**, поэтому
бинарники и много мегабайт текста в ответ попасть не могут.
"""

from __future__ import annotations

import fnmatch
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import paramiko
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..context import ToolContext, guarded
from ..errors import SshMcpError
from ..responses import clamp, human_size

READ_ONLY = ToolAnnotations(
    title="Recursive remote search",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

DEFAULT_MAX_DEPTH = 4
MAX_MAX_DEPTH = 12
DEFAULT_MAX_RESULTS = 200
HARD_MAX_RESULTS = 2000
DEFAULT_TIME_BUDGET = 60
MAX_TIME_BUDGET = 300
MAX_DIRS_VISITED = 2000
MAX_SKIPPED_REPORTED = 20

# Каталоги, которые почти никогда не содержат нужного агенту и обход которых
# дорог: VCS, зависимости и кэши сборщиков.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        ".gradle",
    }
)


@dataclass(frozen=True, slots=True)
class FindQuery:
    """Нормализованный и ограниченный запрос на рекурсивный обход."""

    pattern: str
    match_target: str
    matcher: Callable[[str, str], bool]
    max_depth: int
    max_results: int
    time_budget: float
    include_dirs: bool
    skip_dirs: frozenset[str]


@dataclass(slots=True)
class WalkState:
    """Накопители обхода: что нашли, куда не смогли зайти и почему остановились."""

    matches: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    dirs_visited: int = 0
    depth_limited: bool = False
    stop_reason: str = ""


def _build_matcher(
    pattern: str,
    *,
    regex: bool,
    case_sensitive: bool,
) -> Callable[[str, str], bool]:
    """Компилировать glob или regex в проверку ``(имя, относительный_путь)``."""
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise SshMcpError(f"Некорректный regex '{pattern}': {exc}") from exc

        def search_regex(name: str, rel_path: str) -> bool:
            return compiled.search(name) is not None or compiled.search(rel_path) is not None

        return search_regex

    needle = pattern if case_sensitive else pattern.casefold()

    def search_glob(name: str, rel_path: str) -> bool:
        subject = name if case_sensitive else name.casefold()
        return fnmatch.fnmatchcase(subject, needle)

    return search_glob


def _build_query(
    pattern: str,
    *,
    regex: bool,
    case_sensitive: bool,
    max_depth: int,
    max_results: int,
    time_budget: int,
    include_dirs: bool,
) -> FindQuery:
    text = pattern.strip()
    if not text:
        raise SshMcpError("pattern обязателен: например '*.env', 'docker-compose*' или '^nginx' с regex=true")
    return FindQuery(
        pattern=text,
        match_target="regex" if regex else ("path" if "/" in text else "name"),
        matcher=_build_matcher(text, regex=regex, case_sensitive=case_sensitive),
        max_depth=clamp(max_depth, 1, MAX_MAX_DEPTH, DEFAULT_MAX_DEPTH),
        max_results=clamp(max_results, 1, HARD_MAX_RESULTS, DEFAULT_MAX_RESULTS),
        time_budget=float(clamp(time_budget, 5, MAX_TIME_BUDGET, DEFAULT_TIME_BUDGET)),
        include_dirs=include_dirs,
        skip_dirs=SKIP_DIRS,
    )


def _entry_kind(attr: paramiko.SFTPAttributes) -> str:
    mode = attr.st_mode
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
        return "special"
    return "file"


def _match_entry(path: str, rel_path: str, attr: paramiko.SFTPAttributes, kind: str) -> dict[str, Any]:
    return {
        "path": path,
        "rel_path": rel_path,
        "name": attr.filename,
        "type": kind,
        "size": attr.st_size,
        "size_human": human_size(attr.st_size) if kind != "dir" else "-",
        "mode": stat.filemode(attr.st_mode),
        "mtime": attr.st_mtime,
    }


def _reason(exc: Exception) -> str:
    text = str(exc).strip() or type(exc).__name__
    return f"{type(exc).__name__}: {text[:160]}"


def _find_remote(
    sftp: paramiko.SFTPClient,
    root: str,
    query: FindQuery,
) -> dict[str, Any]:
    """Обойти каталог ``root`` и собрать записи, подходящие под запрос."""
    try:
        root_attr = sftp.stat(root)
    except (OSError, paramiko.SSHException) as exc:
        raise SshMcpError(f"Не удалось открыть '{root}' на сервере: {_reason(exc)}") from exc
    if not stat.S_ISDIR(root_attr.st_mode):
        raise SshMcpError(
            f"'{root}' не является каталогом; для одного файла используйте ssh_read_file"
        )

    state = WalkState()
    deadline = time.monotonic() + query.time_budget
    base = root.rstrip("/") or "/"
    # Стек хранит (абсолютный_путь, путь_от_корня, глубина): глубина 1 — прямые
    # потомки корня, max_depth ограничивает именно её.
    stack: list[tuple[str, str, int]] = [(base, ".", 1)]

    while stack:
        if state.stop_reason:
            break
        if state.dirs_visited >= MAX_DIRS_VISITED:
            state.stop_reason = f"достигнут предел в {MAX_DIRS_VISITED} каталогов"
            break
        if time.monotonic() > deadline:
            state.stop_reason = f"превышен лимит времени {int(query.time_budget)} с"
            break

        current, current_rel, depth = stack.pop()
        try:
            entries = sorted(sftp.listdir_attr(current), key=lambda item: item.filename)
        except (OSError, paramiko.SSHException) as exc:
            state.skipped.append({"path": current, "reason": _reason(exc)})
            continue
        state.dirs_visited += 1

        children: list[tuple[str, str, int]] = []
        prefix = f"{current}/"
        for attr in entries:
            kind = _entry_kind(attr)
            name = attr.filename
            child = prefix + name
            rel = f"{current_rel}/{name}" if current_rel != "." else name

            if kind == "dir":
                if name in query.skip_dirs:
                    continue
                if depth < query.max_depth:
                    children.append((child, rel, depth + 1))
                else:
                    state.depth_limited = True

            if kind == "dir" and not query.include_dirs:
                continue
            if not query.matcher(name, rel):
                continue
            if len(state.matches) >= query.max_results:
                state.stop_reason = f"достигнут предел в {query.max_results} совпадений"
                break
            state.matches.append(_match_entry(child, rel, attr, kind))

        for item in reversed(children):
            stack.append(item)

    matches = sorted(state.matches, key=lambda item: item["path"])
    skipped = state.skipped[:MAX_SKIPPED_REPORTED]
    return {
        "root": root,
        "pattern": query.pattern,
        "match_target": query.match_target,
        "max_depth": query.max_depth,
        "max_results": query.max_results,
        "count": len(matches),
        "dirs_visited": state.dirs_visited,
        "depth_limited": state.depth_limited,
        "truncated": bool(state.stop_reason),
        "stop_reason": state.stop_reason,
        "matches": matches,
        "skipped": skipped,
        "skipped_omitted": len(state.skipped) - len(skipped),
        "skipped_dirs": sorted(query.skip_dirs),
        "hint": _hint(matches, state, query),
    }


def _hint(matches: list[dict[str, Any]], state: WalkState, query: FindQuery) -> str:
    if not matches:
        advice = "Увеличьте max_depth, уточните pattern или снимите regex=true для точного поиска."
        if state.depth_limited:
            advice = "Глубина max_depth исчерпана — увеличьте max_depth. " + advice
        return f"Ничего не найдено. {advice}"
    if state.stop_reason:
        return f"Список неполон ({state.stop_reason}); повторите с большими лимитами."
    if state.skipped:
        return f"Найдено {len(matches)}. Часть каталогов недоступна для чтения — см. skipped."
    return f"Найдено {len(matches)} записей; содержимое не читалось." + (
        "" if query.include_dirs else " Каталоги исключены (include_dirs=false)."
    )


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name="ssh_find", title="Recursive remote search", annotations=READ_ONLY)
    async def ssh_find(
        pattern: str,
        path: str = ".",
        max_depth: int = DEFAULT_MAX_DEPTH,
        server: str = "",
        regex: bool = False,
        case_sensitive: bool = True,
        include_dirs: bool = True,
        max_results: int = DEFAULT_MAX_RESULTS,
        time_budget: int = DEFAULT_TIME_BUDGET,
    ) -> str:
        """Найти файлы и каталоги на сервере рекурсивным обходом.

        Args:
            pattern: Что искать. По умолчанию glob по имени (`*.env`,
                `docker-compose*`); с `regex: true` — регулярное выражение,
                которое проверяется и по имени, и по пути.
            path: Каталог для обхода (по умолчанию рабочий каталог сервера).
            max_depth: Глубина обхода, 1 — только прямые потомки (1-12).
            server: Имя сервера из ssh_list_servers (пусто = сервер по умолчанию).
            regex: Искать регулярным выражением вместо glob.
            case_sensitive: Учитывать регистр (по умолчанию да).
            include_dirs: Возвращать и каталоги тоже.
            max_results: Ограничение числа совпадений (1-2000, по умолчанию 200).
            time_budget: Лимит времени обхода в секундах (5-300, по умолчанию 60).

        Returns:
            JSON со списком `matches` (путь, тип, размер, права, mtime) и
            служебными полями: dirs_visited, depth_limited, stop_reason, skipped.
            Содержимое файлов не читается.
        """

        async def run() -> dict[str, Any]:
            profile = ctx.registry.get(server)
            query = _build_query(
                pattern,
                regex=regex,
                case_sensitive=case_sensitive,
                max_depth=max_depth,
                max_results=max_results,
                time_budget=time_budget,
                include_dirs=include_dirs,
            )
            root = path or profile.default_workdir or "."
            payload = await ctx.connections.run_sftp(
                profile,
                lambda sftp: _find_remote(sftp, root, query),
            )
            payload["server"] = profile.name
            payload["server"] = profile.name
            return payload

        return await guarded(run, name="ssh_find", server=server, summary=f"{pattern} @ {path}")