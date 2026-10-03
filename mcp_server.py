#!/usr/bin/env python3
"""Entrypoint for the multi-server SSH MCP server.

Usage:
    python mcp_server.py [path/to/servers.yaml]

The config path defaults to ``SSH_MCP_CONFIG``, then to ``servers.yaml``
next to this file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ssh_mcp import main  # noqa: E402 - import after sys.path setup

if __name__ == "__main__":
    raise SystemExit(main())
