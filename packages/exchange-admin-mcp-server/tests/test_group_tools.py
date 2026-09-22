from __future__ import annotations

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.allowlist import HARD_CAP
from exchange_admin_mcp.tools.groups import (
    list_distribution_group_members,
    list_dynamic_distribution_group_members,
)
from tests.conftest import FakeExo


def _member(index: int) -> dict:
    return {
        "DisplayName": f"Person {index}",
        "PrimarySmtpAddress": f"p{index}@contoso.com",
        "Alias": f"p{index}",
        "RecipientType": "UserMailbox",
        "RecipientTypeDetails": "UserMailbox",
        "HiddenFromAddressListsEnabled": index == 0,
        "FirstName": "Pat",
        "LastName": "Lee",
        "Identity": "drop",
    }


def test_endpoints_and_hidden_flag() -> None:
    dist = FakeExo(pages={"DistributionGroupMember": [_member(0)]})
    body = list_distribution_group_members(dist, identity="rooms@contoso.com", top=10)
    assert dist.calls[0]["endpoint"] == "DistributionGroupMember"
    assert dist.calls[0]["cmdlet"] == "Get-DistributionGroupMember"
    assert dist.calls[0]["params"]["Identity"] == "rooms@contoso.com"
    assert body["items"][0]["HiddenFromAddressListsEnabled"] is True
    assert "Identity" not in body["items"][0]

    dynamic = FakeExo(pages={"DynamicDistributionGroupMember": [_member(1)]})
    list_dynamic_distribution_group_members(dynamic, identity="all@contoso.com")
    assert dynamic.calls[0]["endpoint"] == "DynamicDistributionGroupMember"
    assert dynamic.calls[0]["cmdlet"] == "Get-DynamicDistributionGroupMember"


def test_missing_identity_makes_zero_calls() -> None:
    client = FakeExo()
    with pytest.raises(SanitizedGraphError, match="parameter_required"):
        list_distribution_group_members(client, identity="")
    assert client.calls == []


def test_truncation_at_hard_cap() -> None:
    client = FakeExo(pages={"DistributionGroupMember": [_member(i) for i in range(HARD_CAP + 5)]})
    body = list_distribution_group_members(client, identity="all@contoso.com", top=HARD_CAP)
    assert body["truncated"] is True
    assert body["stop_reason"] == "item_cap"
    assert len(body["items"]) == HARD_CAP


def test_partial_page_after_error() -> None:
    client = FakeExo(
        pages={"DistributionGroupMember": [_member(1), _member(2)]},
        errors={"DistributionGroupMember": SanitizedGraphError("4xx graph_error", status_class="4xx")},
        page_error_after={"DistributionGroupMember": 1},
    )
    body = list_distribution_group_members(client, identity="all@contoso.com")
    assert body["complete"] is False
    assert body["stop_reason"] == "page_error"
    assert body["items"][0]["PrimarySmtpAddress"] == "p1@contoso.com"
