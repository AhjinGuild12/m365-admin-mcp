from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from entra_mcp.errors import SanitizedGraphError
from entra_mcp.graph_client import GraphClient


class FakeGraph:
    """Minimal GraphClient stand-in for tool tests."""

    def __init__(
        self,
        *,
        gets: dict[str, Any] | None = None,
        pages: dict[str, list[dict[str, Any]]] | None = None,
        get_errors: dict[str, SanitizedGraphError] | None = None,
        page_errors: dict[str, SanitizedGraphError] | None = None,
        page_error_after: dict[str, int] | None = None,
        page_error_on_hit: dict[str, int] | None = None,
        expand_reject: str | None = None,
    ) -> None:
        self.gets = gets or {}
        self.pages = pages or {}
        self.get_errors = get_errors or {}
        self.page_errors = page_errors or {}
        self.page_error_after = page_error_after or {}
        self.expand_reject = expand_reject
        self.page_error_on_hit = page_error_on_hit or {}
        self._path_hits: dict[str, int] = {}
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    def get(self, path: str, params: dict[str, str] | None = None, headers=None) -> dict[str, Any]:
        self.calls.append((path, dict(params) if params else None))
        if path in self.get_errors:
            raise self.get_errors[path]
        if path in self.gets:
            return self.gets[path]
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")

    def iter_pages(
        self,
        path: str,
        params: dict[str, str] | None = None,
        headers=None,
        *,
        item_cap: int | None = None,
    ):
        self.calls.append((path, dict(params) if params else None))
        self._path_hits[path] = self._path_hits.get(path, 0) + 1
        expand = (params or {}).get("$expand", "")
        if self.expand_reject and self.expand_reject in expand:
            raise SanitizedGraphError("4xx graph_error", status_class="4xx")
        hit = self._path_hits[path]
        fail_on = self.page_error_on_hit.get(path)
        if path in self.page_errors and path not in self.page_error_after:
            if fail_on is None or hit == fail_on:
                raise self.page_errors[path]
        items = list(self.pages.get(path, []))
        yielded = 0
        fail_after = self.page_error_after.get(path)
        for item in items:
            if fail_after is not None and yielded >= fail_after:
                raise self.page_errors[path]
            yield item
            yielded += 1
            if item_cap is not None and yielded >= item_cap:
                return

    def collect_page(
        self,
        path: str,
        params: dict[str, str] | None = None,
        headers=None,
        *,
        item_cap: int | None = None,
    ) -> list[dict[str, Any]]:
        return list(self.iter_pages(path, params=params, headers=headers, item_cap=item_cap))


@pytest.fixture
def graph_client_factory():
    def _make(**kwargs) -> GraphClient:
        token = kwargs.pop("token", "test-token")
        sleeps: list[float] = []

        def sleep(delay: float) -> None:
            sleeps.append(delay)

        if "token_provider" not in kwargs:
            kwargs["token_provider"] = lambda t=token: t
        client = GraphClient(sleep=sleep, **kwargs)
        client.sleeps = sleeps  # type: ignore[attr-defined]
        return client

    return _make
