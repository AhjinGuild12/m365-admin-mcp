from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

from entra_mcp.allowlist import TOOL_NAMES
from entra_mcp.graph_client import GraphClient
from entra_mcp.network_policy import check_tree

SRC = Path(__file__).resolve().parents[1] / "src" / "entra_mcp"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"
WRITE_VERBS = frozenset({"post", "put", "patch", "delete", "request", "send", "head", "options"})


def test_graph_client_public_surface_has_no_write_method() -> None:
    public = {
        name
        for name, _ in inspect.getmembers(GraphClient, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    public |= {
        name
        for name in dir(GraphClient)
        if not name.startswith("_") and callable(getattr(GraphClient, name, None))
    }
    overlap = public & WRITE_VERBS
    assert overlap == set()
    assert "get" in public


def test_ast_import_policy_passes_on_real_tree() -> None:
    violations = check_tree(SRC)
    assert violations == [], [str(v) for v in violations]


def test_ast_catches_socket_import_in_tool_module(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_socket.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("socket" in v.message for v in violations)


def test_ast_catches_string_built_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text(
        (FIXTURES / "tool_dynamic_import.py").read_text(encoding="utf-8")
    )
    violations = check_tree(tree)
    assert any("__import__" in v.message for v in violations)


def test_mcp_server_import_surface() -> None:
    module = importlib.import_module("mcp.server.mcpserver")
    assert hasattr(module, "MCPServer")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("mcp.server.fastmcp")


def test_registered_tools_equal_r5_table() -> None:
    from entra_mcp.server import registered_tool_names

    assert tuple(sorted(registered_tool_names())) == tuple(sorted(TOOL_NAMES))
    assert set(registered_tool_names()) == set(TOOL_NAMES)
    assert len(registered_tool_names()) == 42
    assert "list_user_consents" not in registered_tool_names()
    assert "list_mfa_registration" not in registered_tool_names()
    assert "list_pim_activation_requests" not in registered_tool_names()
    assert "onPremisesLastPasswordSyncDateTime" not in (
        SRC / "allowlist.py"
    ).read_text(encoding="utf-8")


def test_no_verify_false_or_trust_env_true_in_graph_client() -> None:
    source = (SRC / "graph_client.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.bad: list[str] = []

        def visit_Call(self, node: ast.Call) -> None:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.bad.append("verify=False")
                if kw.arg == "trust_env" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.bad.append("trust_env=True")
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(tree)
    assert visitor.bad == []
    assert "DefaultAzureCredential" not in source
    assert "trust_env=False" in source


def test_stdio_entry_selects_stdio_only() -> None:
    main_src = (SRC / "__main__.py").read_text(encoding="utf-8")
    server_src = (SRC / "server.py").read_text(encoding="utf-8")
    assert 'transport="stdio"' in main_src
    assert "streamable-http" not in main_src
    assert "streamable-http" not in server_src
    assert "sse" not in main_src.lower()
