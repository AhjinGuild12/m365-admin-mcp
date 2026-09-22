"""KTD13 first-party import allowlist (AST). No network I/O."""

from __future__ import annotations

import ast
from pathlib import Path

NETWORK_MODULES = frozenset(
    {
        "httpx",
        "socket",
        "ssl",
        "subprocess",
        "ctypes",
        "importlib",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "urllib.error",
        "urllib.response",
        "urllib.robotparser",
        "http",
        "http.client",
        "http.server",
        "http.cookiejar",
        "http.cookies",
        "asyncio",
        "aiohttp",
        "requests",
        "urllib3",
    }
)

GRAPH_CLIENT_ALLOWED_NETWORK = frozenset(
    {
        "httpx",
        "azure.identity",
    }
)

AZURE_ALLOWED_NAMES = frozenset({"ClientSecretCredential"})


class PolicyViolation:
    def __init__(self, path: Path, message: str) -> None:
        self.path = path
        self.message = message

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _module_root(alias: str) -> str:
    return alias.split(".", 1)[0]


def _is_network_module(name: str) -> bool:
    if name in NETWORK_MODULES:
        return True
    root = _module_root(name)
    if root in NETWORK_MODULES:
        return True
    if name.startswith("urllib") or name.startswith("http.") or name == "http":
        return True
    if name.startswith("azure.identity") or name == "azure.identity":
        return True
    if name.startswith("importlib"):
        return True
    return False


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, *, is_graph_client: bool) -> None:
        self.path = path
        self.is_graph_client = is_graph_client
        self.violations: list[PolicyViolation] = []

    def _allow_network(self, name: str) -> bool:
        if not self.is_graph_client:
            return False
        if name in GRAPH_CLIENT_ALLOWED_NETWORK:
            return True
        if name.startswith("azure.identity"):
            return True
        return False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            if _is_network_module(name) and not self._allow_network(name):
                self.violations.append(
                    PolicyViolation(self.path, f"forbidden import {name}")
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module == "azure.identity" or module.startswith("azure.identity"):
            if not self.is_graph_client:
                self.violations.append(
                    PolicyViolation(self.path, f"forbidden import from {module}")
                )
            else:
                for alias in node.names:
                    if alias.name == "*":
                        self.violations.append(
                            PolicyViolation(self.path, "star import from azure.identity")
                        )
                    elif alias.name not in AZURE_ALLOWED_NAMES:
                        self.violations.append(
                            PolicyViolation(
                                self.path,
                                f"forbidden azure.identity name {alias.name}",
                            )
                        )
            self.generic_visit(node)
            return
        if _is_network_module(module) and not self._allow_network(module):
            self.violations.append(
                PolicyViolation(self.path, f"forbidden import from {module}")
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "__import__":
            self.violations.append(
                PolicyViolation(self.path, "dynamic __import__ is forbidden")
            )
        elif isinstance(func, ast.Attribute) and func.attr in {
            "import_module",
            "__import__",
        }:
            self.violations.append(
                PolicyViolation(self.path, f"dynamic import {func.attr} is forbidden")
            )
        self.generic_visit(node)


def check_tree(root: Path) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for path in sorted(root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        is_graph_client = path.name == "graph_client.py"
        visitor = _ImportVisitor(path, is_graph_client=is_graph_client)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    return violations
