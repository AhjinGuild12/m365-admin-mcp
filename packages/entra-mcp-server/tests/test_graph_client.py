from __future__ import annotations

import json

import httpx
import pytest

from entra_mcp.errors import SanitizedGraphError
from entra_mcp.graph_client import (
    GRAPH_BASE,
    encode_path_segment,
    escape_odata_string,
    parse_retry_after,
)


def test_encode_path_segment_neutralizes_query_injection() -> None:
    encoded = encode_path_segment("x?$select=ipAddress")
    assert "?" not in encoded
    assert "$" not in encoded
    assert encoded == "x%3F%24select%3DipAddress"


def test_escape_odata_string_quote_breakout() -> None:
    assert escape_odata_string("x' or 1 eq 1") == "x'' or 1 eq 1"


def test_get_rejects_absolute_url(graph_client_factory) -> None:
    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    )
    with pytest.raises(SanitizedGraphError, match="invalid_path|absolute_url"):
        client.get("https://evil.example/v1.0/users")


def test_get_rejects_question_in_path(graph_client_factory) -> None:
    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    )
    with pytest.raises(SanitizedGraphError, match="path_query_rejected"):
        client.get("/users/x?$select=ipAddress")


def test_poisoned_next_link_refused(graph_client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(GRAPH_BASE + "/users"):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "1"}],
                    "@odata.nextLink": "https://evil.example/loot",
                },
            )
        raise AssertionError(f"unexpected {request.url}")

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="pagination_origin_rejected"):
        client.collect_page("/users")


def test_retry_after_429_then_success(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        if n["c"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "slow"})
        return httpx.Response(200, json={"id": "u1"})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    assert client.get("/users/u1") == {"id": "u1"}
    assert n["c"] == 2
    assert client.sleeps == [0.0]


def test_retry_503_then_success(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        if n["c"] == 1:
            return httpx.Response(503, headers={"Retry-After": "0"}, json={"error": "busy"})
        return httpx.Response(200, json={"ok": True})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    assert client.get("/organization") == {"ok": True}


def test_retries_exhausted_sanitized(graph_client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "0"},
            json={"error": {"code": "AADSTS70000", "message": "secret=supersecret"}},
        )

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="retries_exhausted") as exc:
        client.get("/users/u1")
    text = str(exc.value)
    assert "AADSTS" not in text
    assert "supersecret" not in text
    assert "graph.microsoft.com" not in text


def test_malformed_retry_after_no_retry(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "soon"}, json={"error": "x"})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="malformed_retry_after"):
        client.get("/users/u1")
    assert n["c"] == 1


def test_parse_retry_after_rejects_garbage() -> None:
    assert parse_retry_after("nope") is None
    assert parse_retry_after("") is None
    assert parse_retry_after("12") == 12.0


def test_token_acquisition_failure_sanitized(graph_client_factory) -> None:
    def boom() -> str:
        raise RuntimeError("AADSTS7000215: Invalid client secret provided. secret=abc")

    client = graph_client_factory(
        token_provider=boom,
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))),
    )
    with pytest.raises(SanitizedGraphError, match="token_acquisition_failed") as exc:
        client.get("/users/u1")
    assert "AADSTS" not in str(exc.value)
    assert "abc" not in str(exc.value)


def test_http_error_drops_query_and_body(graph_client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": {"code": "Bad", "message": "filter=secret"}},
        )

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.get("/users/u1", params={"$filter": "mail eq 'x'"})
    dumped = json.dumps({"msg": str(exc.value), "cls": exc.value.status_class})
    assert "filter" not in dumped
    assert "secret" not in dumped
    assert exc.value.status_class == "4xx"


def test_follow_redirects_disabled(graph_client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/x"})

    http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    client = graph_client_factory(http_client=http)
    with pytest.raises(SanitizedGraphError):
        client.get("/users/u1")
