from __future__ import annotations

import ast
import inspect
from pathlib import Path

from m365_mcp_kernel.graph_client import GraphClient, Origin
from m365_mcp_kernel.network_policy import check_tree

SRC = Path(__file__).resolve().parents[1] / "src" / "m365_mcp_kernel"
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
    assert "fetch_report" in public


def test_origin_enum_is_graph_only() -> None:
    assert list(Origin) == [Origin.GRAPH]
    assert Origin.GRAPH.value == "graph"


def test_ast_import_policy_passes_on_real_tree() -> None:
    violations = check_tree(SRC)
    assert violations == [], [str(v) for v in violations]


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


def test_report_download_has_no_network_import() -> None:
    source = (SRC / "report_download.py").read_text(encoding="utf-8")
    assert "httpx" not in source
    assert "azure" not in source
    assert "socket" not in source
