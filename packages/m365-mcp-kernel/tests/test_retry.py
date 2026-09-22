from __future__ import annotations

import httpx
import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import INTUNE_MISSING_RETRY_AFTER_SECONDS


def test_intune_mode_missing_retry_after_waits_five_seconds(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        if n["c"] == 1:
            return httpx.Response(429, json={"error": "slow"})
        return httpx.Response(200, json={"ok": True})

    client = graph_client_factory(
        missing_retry_after_seconds=INTUNE_MISSING_RETRY_AFTER_SECONDS,
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    assert client.get("/deviceManagement/managedDevices") == {"ok": True}
    assert n["c"] == 2
    assert client.sleeps == [5.0]


def test_non_intune_mode_fails_on_missing_retry_after(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        return httpx.Response(429, json={"error": "slow"})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="malformed_retry_after"):
        client.get("/organization")
    assert n["c"] == 1
    assert client.sleeps == []


def test_malformed_retry_after_fails_in_intune_mode(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "soon"}, json={"error": "x"})

    client = graph_client_factory(
        missing_retry_after_seconds=INTUNE_MISSING_RETRY_AFTER_SECONDS,
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    with pytest.raises(SanitizedGraphError, match="malformed_retry_after"):
        client.get("/deviceManagement/managedDevices")
    assert n["c"] == 1
    assert client.sleeps == []


def test_malformed_retry_after_fails_in_non_intune_mode(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "soon"}, json={"error": "x"})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="malformed_retry_after"):
        client.get("/organization")
    assert n["c"] == 1
