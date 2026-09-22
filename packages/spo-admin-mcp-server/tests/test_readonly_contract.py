from __future__ import annotations

from pathlib import Path

from spo_admin_mcp.allowlist import GRAPH_GRANTS, TOOL_NAMES
from spo_admin_mcp.server import advertised_tool_names
from m365_mcp_kernel.network_policy import check_tree

SRC = Path(__file__).resolve().parents[1] / "src" / "spo_admin_mcp"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"


def test_registered_tools_equal_the_seven_names() -> None:
    names = advertised_tool_names()
    assert set(names) == set(TOOL_NAMES)
    assert len(names) == 7
    assert "list_sites" not in names
    assert "get_site" not in names


def test_grants_are_the_two_application_permissions() -> None:
    assert set(GRAPH_GRANTS) == {"Reports.Read.All", "SharePointTenantSettings.Read.All"}
    assert not any(name.startswith("Sites.") for name in GRAPH_GRANTS)


def test_renamed_tool_would_fail_set_equality() -> None:
    renamed = list(TOOL_NAMES)
    renamed[0] = "get_tenant_sharing_settings_v2"
    assert set(renamed) != set(TOOL_NAMES)


def test_ast_import_policy_passes_on_workload_tree() -> None:
    violations = check_tree(SRC)
    assert violations == [], [str(item) for item in violations]


def test_ast_catches_httpx_in_tool_module(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_httpx.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("httpx" in item.message for item in violations)


def test_ast_catches_socket_import_in_tool_module(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_socket.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("socket" in item.message for item in violations)


def test_ast_catches_string_built_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_dynamic_import.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("__import__" in item.message for item in violations)


def test_stdio_entry_selects_stdio_only() -> None:
    root = SRC
    main_src = (root / "__main__.py").read_text(encoding="utf-8")
    server_src = (root / "server.py").read_text(encoding="utf-8")
    assert "run_stdio" in server_src
    assert "streamable-http" not in main_src
    assert "streamable-http" not in server_src
    assert "FastMCP" not in server_src
    assert "missing_retry_after_seconds" not in server_src
