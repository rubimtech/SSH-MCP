"""Shared helpers for tool payloads: JSON encoding, limits, and formatting."""

from __future__ import annotations

import json
from typing import Any

from .safety import scrub_obj

CHARACTER_LIMIT = 25_000
STDOUT_LIMIT = 50 * 1024


def to_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def ok(payload: Any, *, limit: int = CHARACTER_LIMIT) -> str:
    """Serialize a successful tool result, shrinking and scrubbing it."""
    text = to_json(scrub_obj(payload))
    if len(text) <= limit:
        return text

    shrunk = _shrink(payload, limit)
    if shrunk is not None:
        shrunk["truncated"] = True
        text = to_json(scrub_obj(shrunk))
        if len(text) <= limit:
            return text

    note = f"\n[Response truncated: {len(text)} characters, limit {limit}]"
    return text[: max(0, limit - len(note))] + note


def fail(error: str, **extra: Any) -> str:
    """Serialize an error result in the same shape as :func:`ok`."""
    return to_json(scrub_obj({"error": error, **extra}))


def _shrink(payload: dict[str, Any], limit: int) -> dict[str, Any] | None:
    """Drop trailing list items until the payload fits into ``limit``."""
    container = next(
        (key for key, value in payload.items() if isinstance(value, list) and value),
        None,
    )
    if container is None:
        return None

    items = list(payload[container])
    candidate = {**payload, container: items, "count": len(items)}
    while items and len(to_json(candidate)) > limit:
        del items[len(items) // 2 :]
    if not items:
        return None

    candidate["count"] = len(items)
    candidate["omitted"] = len(payload[container]) - len(items)
    return candidate


def clamp(value: int, minimum: int, maximum: int, default: int) -> int:
    """Clamp a user-supplied numeric argument into a safe range."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def clip(text: str, limit: int, label: str) -> str:
    """Trim ``text`` to ``limit`` characters and mark the truncation."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[{label} truncated at {limit} characters]"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "K", "M", "G"):
        if value < 1024:
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024
    return f"{value:.1f}T"