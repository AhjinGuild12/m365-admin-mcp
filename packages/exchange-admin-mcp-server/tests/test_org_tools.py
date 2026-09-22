from __future__ import annotations

import json

from exchange_admin_mcp.allowlist import HARD_CAP
from exchange_admin_mcp.tools.org import get_organization_config, list_accepted_domains
from tests.conftest import FakeExo, gid


class _Recording:
    """Minimal client whose iter_rows records the body shape the tool asked for."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls: list[dict] = []

    def iter_rows(self, endpoint, cmdlet, params=None, *, anchor=None, select=None):
        self.calls.append(
            {
                "endpoint": endpoint,
                "cmdlet": cmdlet,
                "params": dict(params or {}),
                "anchor": anchor,
                "select": select,
            }
        )
        if "value" in self.payload:
            yield from self.payload["value"]
            return
        yield self.payload


def test_organization_config_has_no_parameters_and_strips_ids() -> None:
    client = _Recording(
        {
            "Name": "contoso",
            "MailTipsAllTipsEnabled": True,
            "MailTipsExternalRecipientsTipsEnabled": False,
            "MailTipsLargeAudienceThreshold": 25,
            "Guid": gid("a"),
            "Id": gid("b"),
            "Identity": "CN=contoso",
        }
    )
    body = get_organization_config(client)  # type: ignore[arg-type]
    assert client.calls[0]["endpoint"] == "OrganizationConfig"
    assert client.calls[0]["cmdlet"] == "Get-OrganizationConfig"
    assert client.calls[0]["params"] == {}
    assert body["complete"] is True
    assert len(body["items"]) == 1
    assert body["items"][0]["Name"] == "contoso"
    dumped = json.dumps(body)
    assert "Guid" not in dumped
    assert '"Id"' not in dumped
    assert "Identity" not in dumped


def test_accepted_domain_truncation() -> None:
    rows = [
        {"DomainName": f"d{i}.contoso.com", "DomainType": "Authoritative", "Name": f"d{i}", "Guid": gid("c")}
        for i in range(HARD_CAP + 1)
    ]
    client = FakeExo(pages={"AcceptedDomain": rows})
    body = list_accepted_domains(client, top=HARD_CAP)
    assert body["truncated"] is True
    assert body["stop_reason"] == "item_cap"
    assert len(body["items"]) == HARD_CAP
    assert "Guid" not in json.dumps(body)
