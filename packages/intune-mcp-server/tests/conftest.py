from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


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
        expand_reject: str | None = None,
        retry_then: dict[str, Any] | None = None,
    ) -> None:
        self.gets = gets or {}
        self.pages = pages or {}
        self.get_errors = get_errors or {}
        self.page_errors = page_errors or {}
        self.page_error_after = page_error_after or {}
        self.expand_reject = expand_reject
        self.retry_then = retry_then or {}
        self.calls: list[tuple[str, dict[str, str] | None]] = []
        self._429_remaining = 1 if retry_then else 0

    def get(self, path: str, params: dict[str, str] | None = None, headers=None, **kwargs) -> dict[str, Any]:
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
        origin=None,
    ):
        self.calls.append((path, dict(params) if params else None))
        expand = (params or {}).get("$expand", "")
        if self.expand_reject and self.expand_reject in expand:
            raise SanitizedGraphError("4xx graph_error", status_class="4xx")
        if path in self.retry_then and self._429_remaining > 0:
            self._429_remaining -= 1
            raise SanitizedGraphError("4xx retries_exhausted", status_class="4xx")
        if path in self.page_errors and path not in self.page_error_after:
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
        origin=None,
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
