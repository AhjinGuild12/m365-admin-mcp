"""MCPServer factory: register tools from an allowlist constant and run stdio."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer

from m365_mcp_kernel.errors import SanitizedGraphError


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    description: str


def registered_tool_names(mcp: MCPServer) -> tuple[str, ...]:
    return tuple(tool.name for tool in mcp._tool_manager.list_tools())


def create_server(
    name: str,
    tools: Sequence[ToolSpec],
    *,
    version: str = "0.1.0",
    declared_names: Sequence[str] | None = None,
) -> MCPServer:
    """Build MCPServer(name), register tools, assert set-equality with the table."""
    mcp = MCPServer(name, version=version)
    table = tuple(declared_names) if declared_names is not None else tuple(t.name for t in tools)
    for spec in tools:
        mcp.add_tool(spec.fn, name=spec.name, description=spec.description)
    actual = registered_tool_names(mcp)
    if set(actual) != set(table) or len(actual) != len(set(table)):
        raise SanitizedGraphError("tool_allowlist_mismatch", status_class="other")
    if len(tools) != len(set(t.name for t in tools)):
        raise SanitizedGraphError("tool_allowlist_mismatch", status_class="other")
    return mcp


def run_stdio(mcp: MCPServer) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    mcp.run(transport="stdio")
