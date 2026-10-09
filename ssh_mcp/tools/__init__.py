"""Tool registration."""

from __future__ import annotations

from fastmcp import FastMCP

from ..context import ToolContext
from . import batch_tools, exec_tools, file_tools, find_tools, fs_tools, key_tools, servers

MODULES = (servers, exec_tools, file_tools, fs_tools, batch_tools, find_tools, key_tools)


def register_all(mcp: FastMCP, ctx: ToolContext) -> None:
    """Register every tool module against the server."""
    for module in MODULES:
        module.register(mcp, ctx)
    servers.register_resources(mcp, ctx)


__all__ = ["MODULES", "ToolContext", "register_all"]