from __future__ import annotations

from pathlib import Path

from m365_mcp_kernel.network_policy import check_tree

SRC = Path(__file__).resolve().parents[1] / "src" / "m365_mcp_kernel"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"


def test_kernel_tree_allows_only_graph_client_network() -> None:
    violations = check_tree(SRC)
    assert violations == [], [str(v) for v in violations]


def test_report_download_importing_httpx_is_violation(tmp_path: Path) -> None:
    tree = tmp_path / "pkg"
    tree.mkdir()
    (tree / "report_download.py").write_text(
        (FIXTURES / "tool_httpx_report.py").read_text(encoding="utf-8")
    )
    violations = check_tree(tree)
    assert any("httpx" in v.message for v in violations)


def test_workload_module_importing_httpx_is_violation(tmp_path: Path) -> None:
    tree = tmp_path / "intune_mcp"
    tree.mkdir()
    (tree / "devices.py").write_text("import httpx\n")
    violations = check_tree(tree)
    assert any("httpx" in v.message for v in violations)


def test_ast_catches_socket_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_socket.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("socket" in v.message for v in violations)


def test_ast_catches_subprocess_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text((FIXTURES / "tool_subprocess.py").read_text(encoding="utf-8"))
    violations = check_tree(tree)
    assert any("subprocess" in v.message for v in violations)


def test_ast_catches_string_built_import(tmp_path: Path) -> None:
    tree = tmp_path / "tools"
    tree.mkdir()
    (tree / "evil.py").write_text(
        (FIXTURES / "tool_dynamic_import.py").read_text(encoding="utf-8")
    )
    violations = check_tree(tree)
    assert any("__import__" in v.message for v in violations)
