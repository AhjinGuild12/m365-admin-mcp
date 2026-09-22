from __future__ import annotations

import json

import httpx
import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import MAX_RETRY_WAIT_SECONDS

from exchange_admin_mcp.exo_client import ExoAdminApiClient
from tests.conftest import gid

TENANT = gid("a")


def _client(handler, sleeps: list[float] | None = None) -> ExoAdminApiClient:
    return ExoAdminApiClient(
        tenant_id=TENANT,
        client_id=gid("b"),
        client_secret="not-a-real-secret",
        token_provider=lambda: "test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=(sleeps.append if sleeps is not None else (lambda _delay: None)),
    )


def test_trust_env_is_false_and_redirects_are_not_followed() -> None:
    client = ExoAdminApiClient(
        tenant_id=TENANT,
        client_id=gid("b"),
        client_secret="not-a-real-secret",
        token_provider=lambda: "test-token",
    )
    assert client._http.follow_redirects is False
    trust = getattr(client._http, "_trust_env", None)
    assert trust is False


def test_redirect_is_not_followed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "https://evil.example/steal"},
            content=b"redirect-body-should-not-leak",
        )

    client = _client(handler)
    with pytest.raises(SanitizedGraphError, match="graph_error") as raised:
        client.invoke("OrganizationConfig", "Get-OrganizationConfig", {})
    assert "redirect-body-should-not-leak" not in str(raised.value)
    assert "evil.example" not in str(raised.value)
    assert len(seen) == 1


def test_retry_after_then_success() -> None:
    sleeps: list[float] = []
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, json={"error": "slow-down-secret"})
        return httpx.Response(200, json={"value": []})

    client = _client(handler, sleeps)
    payload = client.invoke("OrganizationConfig", "Get-OrganizationConfig", {})
    assert payload["value"] == []
    assert calls["n"] == 2
    assert sleeps == [2.0]


def test_wait_budget_exhausted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": str(int(MAX_RETRY_WAIT_SECONDS) + 5)},
            content=b"budget-secret",
        )

    client = _client(handler, [])
    with pytest.raises(SanitizedGraphError, match="retry_budget_exhausted") as raised:
        client.invoke("OrganizationConfig", "Get-OrganizationConfig", {})
    assert "budget-secret" not in str(raised.value)


def test_token_failure_is_sanitized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("http was called")

    def boom() -> str:
        raise RuntimeError("https://login.example/secret-token")

    client = ExoAdminApiClient(
        tenant_id=TENANT,
        client_id=gid("b"),
        client_secret="not-a-real-secret",
        token_provider=boom,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SanitizedGraphError, match="token_acquisition_failed") as raised:
        client.invoke("OrganizationConfig", "Get-OrganizationConfig", {})
    assert "secret-token" not in str(raised.value)
    assert raised.value.status_class == "auth"


def test_error_body_never_appears_in_the_message() -> None:
    secret = "tenant-body-must-stay-out"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, content=json.dumps({"error": secret}).encode())

    client = _client(handler)
    with pytest.raises(SanitizedGraphError, match="graph_error") as raised:
        client.invoke("OrganizationConfig", "Get-OrganizationConfig", {})
    assert secret not in str(raised.value)
    assert raised.value.status_code == 400  # type: ignore[attr-defined]
