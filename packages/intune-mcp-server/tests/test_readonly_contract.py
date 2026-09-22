from __future__ import annotations

from pathlib import Path

import pytest

from intune_mcp.allowlist import TOOL_NAMES
from intune_mcp.server import advertised_tool_names
from m365_mcp_kernel.network_policy import check_tree

SRC = Path(__file__).resolve().parents[1] / "src" / "intune_mcp"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"


def test_registered_tools_equal_r5_table() -> None:
    names = advertised_tool_names()
    assert set(names) == set(TOOL_NAMES)
    assert len(names) == 13
    assert tuple(sorted(names)) == tuple(sorted(TOOL_NAMES))


def test_renamed_tool_would_fail_set_equality() -> None:
    renamed = list(TOOL_NAMES)
    renamed[0] = "get_intune_overview_v2"
    assert set(renamed) != set(TOOL_NAMES)


def test_ast_import_policy_passes_on_workload_tree() -> None:
    violations = check_tree(SRC)
    assert violations == [], [str(v) for v in violations]


def test_ast_catches_httpx_in_tool_module(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_httpx.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("httpx" in v.message for v in violations)


def test_ast_catches_socket_import_in_tool_module(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_socket.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("socket" in v.message for v in violations)


def test_ast_catches_string_built_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_dynamic_import.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("__import__" in v.message for v in violations)


def test_stdio_entry_selects_stdio_only() -> None:
    main_src = (SRC / "__main__.py").read_text(encoding="utf-8")
    server_src = (SRC / "server.py").read_text(encoding="utf-8")
    assert "run_stdio" in server_src
    assert "streamable-http" not in main_src
    assert "streamable-http" not in server_src
    assert "FastMCP" not in server_src


def test_server_constructs_intune_retry_flag() -> None:
    from intune_mcp.server import INTUNE_MISSING_RETRY_AFTER_SECONDS

    assert INTUNE_MISSING_RETRY_AFTER_SECONDS == 5.0
