"""Shared fakes. No network."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError


def gid(ch: str) -> str:
    """Build a GUID-shaped value without embedding one in source."""
    return f"{ch * 8}-{ch * 4}-{ch * 4}-{ch * 4}-{ch * 12}"


class FakeGraph:
    def __init__(
        self,
        *,
        pages: dict[str, list[dict[str, Any]]] | None = None,
        gets: dict[str, Any] | None = None,
        errors: dict[str, SanitizedGraphError] | None = None,
        page_error_after: dict[str, int] | None = None,
    ) -> None:
        self.pages = pages or {}
        self.gets = gets or {}
        self.errors = errors or {}
        self.page_error_after = page_error_after or {}
        self.calls: list[dict[str, Any]] = []

    def get(self, path: str, params: dict[str, str] | None = None, headers=None, **kwargs: Any) -> Any:
        self.calls.append({"path": path, "params": dict(params or {}), "headers": dict(headers or {})})
        if path in self.errors and path not in self.page_error_after:
            raise self.errors[path]
        if path in self.gets:
            return self.gets[path]
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")

    def iter_pages(self, path: str, params=None, headers=None, *, item_cap: int | None = None, origin=None):
        self.calls.append({"path": path, "params": dict(params or {}), "headers": dict(headers or {})})
        if path in self.errors and path not in self.page_error_after:
            raise self.errors[path]
        items = list(self.pages.get(path, []))
        fail_after = self.page_error_after.get(path)
        yielded = 0
        for item in items:
            if fail_after is not None and yielded >= fail_after:
                raise self.errors.get(path) or SanitizedGraphError(
                    "5xx retries_exhausted", status_class="5xx"
                )
            yield item
            yielded += 1
            if item_cap is not None and yielded >= item_cap:
                return

    def fetch_report(self, function_path: str, period: str) -> list[dict[str, str]]:
        self.calls.append({"path": function_path, "params": {"period": period}, "headers": {}})
        if function_path in self.errors:
            raise self.errors[function_path]
        return list(self.pages.get(function_path, []))


class FakeExo:
    def __init__(
        self,
        *,
        pages: dict[str, list[dict[str, Any]]] | None = None,
        errors: dict[str, SanitizedGraphError] | None = None,
        page_error_after: dict[str, int] | None = None,
    ) -> None:
        self.pages = pages or {}
        self.errors = errors or {}
        self.page_error_after = page_error_after or {}
        self.calls: list[dict[str, Any]] = []

    def iter_rows(self, endpoint, cmdlet, params=None, *, anchor=None, select=None):
        self.calls.append(
            {
                "endpoint": endpoint,
                "cmdlet": cmdlet,
                "params": dict(params or {}),
                "headers": {"X-AnchorMailbox": anchor},
                "anchor": anchor,
                "select": select,
            }
        )
        if endpoint in self.errors and endpoint not in self.page_error_after:
            raise self.errors[endpoint]
        items = list(self.pages.get(endpoint, []))
        fail_after = self.page_error_after.get(endpoint)
        yielded = 0
        for item in items:
            if fail_after is not None and yielded >= fail_after:
                raise self.errors.get(endpoint) or SanitizedGraphError(
                    "5xx retries_exhausted", status_class="5xx"
                )
            yield item
            yielded += 1
