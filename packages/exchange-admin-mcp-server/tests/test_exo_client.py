from __future__ import annotations

import json

import httpx
import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.allowlist import EXO_ENDPOINTS
from exchange_admin_mcp.exo_client import (
    ExoAdminApiClient,
    fetch_one_admin_api,
    system_mailbox_anchor,
)
from exchange_admin_mcp.schemas import ORGANIZATION_CONFIG_SCHEMA
from tests.conftest import gid

TENANT = gid("c")


def _client(handler) -> ExoAdminApiClient:
    return ExoAdminApiClient(
        tenant_id=TENANT,
        client_id=gid("d"),
        client_secret="not-a-real-secret",
        token_provider=lambda: "test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def _capture(status: int = 200, payload: dict | None = None, headers: dict | None = None):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = payload if payload is not None else {"value": []}
        return httpx.Response(status, json=body, headers=headers)

    return _client(handler), seen


def test_rejects_unknown_endpoint_and_cmdlet_and_parameter_before_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("http was called")

    client = _client(handler)
    with pytest.raises(SanitizedGraphError, match="cmdlet_not_allowed"):
        client.invoke("Mailbox", "Set-Mailbox", {"Identity": "alex@contoso.com"})
    with pytest.raises(SanitizedGraphError, match="parameter_not_allowed"):
        client.invoke("Mailbox", "Get-Mailbox", {"Filter": "x"})
    with pytest.raises(SanitizedGraphError, match="endpoint_not_allowed"):
        client.invoke("TransportRule", "Get-TransportRule", {})
    with pytest.raises(SanitizedGraphError, match="parameter_required"):
        client.invoke("MailboxFolderPermission", "Get-MailboxFolderPermission", {})


def test_each_endpoint_url_headers_and_body() -> None:
    samples = {
        "Mailbox": {"ResultSize": 10},
        "MailboxFolderPermission": {"Identity": "alex@contoso.com:\\Calendar", "ResultSize": 10},
        "DistributionGroupMember": {"Identity": "roomlist@contoso.com", "ResultSize": 10},
        "DynamicDistributionGroupMember": {"Identity": "all-staff@contoso.com", "ResultSize": 10},
        "AcceptedDomain": {"ResultSize": 10},
        "OrganizationConfig": {},
    }
    for endpoint, params in samples.items():
        cmdlet = next(iter(EXO_ENDPOINTS[endpoint]))
        client, seen = _capture()
        client.invoke(endpoint, cmdlet, params, select=None)
        request = seen[0]
        assert str(request.url) == f"https://outlook.office365.com/adminapi/v2.0/{TENANT}/{endpoint}"
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["X-AnchorMailbox"] == system_mailbox_anchor(TENANT)
        body = json.loads(request.content)
        assert body["CmdletInput"]["CmdletName"] == cmdlet
        if params:
            assert body["CmdletInput"]["Parameters"] == params
        else:
            assert "Parameters" not in body["CmdletInput"]


def test_system_mailbox_anchor_when_none_supplied() -> None:
    client, seen = _capture()
    client.invoke("OrganizationConfig", "Get-OrganizationConfig", {}, anchor=None)
    assert seen[0].headers["X-AnchorMailbox"] == system_mailbox_anchor(TENANT)
    assert "bb558c35-97f1-4cb9-8ff7-d53741dc928c" in seen[0].headers["X-AnchorMailbox"]


def test_mailbox_anchor_is_sent_when_supplied() -> None:
    client, seen = _capture()
    client.invoke(
        "Mailbox",
        "Get-Mailbox",
        {"Identity": "alex@contoso.com"},
        anchor="AAD-SMTP:alex@contoso.com",
    )
    assert seen[0].headers["X-AnchorMailbox"] == "AAD-SMTP:alex@contoso.com"


def test_nextlink_with_other_tenant_or_host_is_rejected() -> None:
    bad_links = [
        f"https://outlook.office365.com/adminapi/v2.0/{gid('e')}/Mailbox?$skiptoken=1",
        "https://evil.example/adminapi/v2.0/" + TENANT + "/Mailbox",
        f"https://graph.microsoft.com/v1.0/adminapi/v2.0/{TENANT}/Mailbox",
    ]
    for link in bad_links:
        client, _seen = _capture(
            payload={"value": [{"Name": "one"}], "@odata.nextLink": link}
        )
        rows = []
        with pytest.raises(SanitizedGraphError, match="pagination_origin_rejected"):
            for row in client.iter_rows("OrganizationConfig", "Get-OrganizationConfig", {}):
                rows.append(row)
        assert rows == [{"Name": "one"}]


def test_cmdlet_error_payload_raises_and_yields_nothing() -> None:
    client, _seen = _capture(payload={"error": {"message": "leaked-cmdlet-text"}})
    with pytest.raises(SanitizedGraphError, match="cmdlet_execution_failed") as raised:
        list(client.iter_rows("OrganizationConfig", "Get-OrganizationConfig", {}))
    assert "leaked-cmdlet-text" not in str(raised.value)


def test_fetch_one_empty_and_one_row() -> None:
    empty, _ = _capture(payload={"value": []})
    with pytest.raises(SanitizedGraphError, match="not_found"):
        fetch_one_admin_api(
            empty,
            "OrganizationConfig",
            "Get-OrganizationConfig",
            {},
            ORGANIZATION_CONFIG_SCHEMA,
            None,
        )
    one, _ = _capture(
        payload={
            "Name": "contoso",
            "MailTipsAllTipsEnabled": True,
            "Guid": gid("f"),
            "Identity": "dn",
        }
    )
    body = fetch_one_admin_api(
        one,
        "OrganizationConfig",
        "Get-OrganizationConfig",
        {},
        ORGANIZATION_CONFIG_SCHEMA,
        None,
    )
    assert body["complete"] is True
    assert body["items_scanned"] == 1
    assert body["items"][0]["Name"] == "contoso"
    assert "Guid" not in body["items"][0]
    assert "Identity" not in body["items"][0]
