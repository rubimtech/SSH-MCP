"""Multi-server SSH MCP server.

Tools take a ``server`` name that resolves against ``servers.yaml``; call
``ssh_list_servers`` first to see which server is which.
"""

from __future__ import annotations

from .config import ServerRegistry, load_registry
from .context import ToolContext
from .errors import SshMcpError
from .server import build_server, main

__all__ = [
    "ServerRegistry",
    "SshMcpError",
    "ToolContext",
    "build_server",
    "load_registry",
    "main",
]