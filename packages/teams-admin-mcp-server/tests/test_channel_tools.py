from __future__ import annotations

import json

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from teams_admin_mcp.tools.channels import get_channel, list_channel_members, list_channels
from tests.conftest import FakeGraph, gid

TEAM = "team-1"
CHANNEL = "19:abc@thread.tacv2"


def test_invalid_membership_type_before_call() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="invalid_membership_type"):
        list_channels(client, TEAM, membership_type="secret")
    assert client.calls == []


def test_channel_list_drops_email_weburl_and_tenant() -> None:
    client = FakeGraph(
        pages={
            "/teams/team-1/channels": [
                {
                    "id": CHANNEL,
                    "displayName": "General",
                    "description": "",
                    "membershipType": "standard",
                    "isArchived": False,
                    "createdDateTime": "2026-01-01T00:00:00Z",
                    "email": "general@contoso.com",
                    "webUrl": "https://example.test/ch",
                    "tenantId": gid("0"),
                }
            ]
        }
    )
    body = list_channels(client, TEAM)
    dumped = json.dumps(body)
    assert "email" not in body["items"][0]
    assert "webUrl" not in dumped
    assert "tenantId" not in dumped
    assert "email" not in client.calls[0]["params"]["$select"]
    assert body["complete"] is True


def test_empty_channel_page_is_complete() -> None:
    client = FakeGraph(pages={"/teams/team-1/channels": []})
    body = list_channels(client, TEAM, membership_type="private")
    assert body["items"] == []
    assert body["complete"] is True
    assert client.calls[0]["params"]["$filter"] == "membershipType eq 'private'"


def test_get_channel_encodes_colon_and_at() -> None:
    encoded = "19%3Aabc%40thread.tacv2"
    client = FakeGraph(
        gets={
            f"/teams/team-1/channels/{encoded}": {
                "id": CHANNEL,
                "displayName": "General",
                "description": "",
                "membershipType": "shared",
                "isArchived": False,
                "createdDateTime": "2026-01-01T00:00:00Z",
                "moderationSettings": {
                    "userNewMessageRestriction": "everyone",
                    "replyRestriction": "everyone",
                    "allowNewMessageFromBots": True,
                    "allowNewMessageFromConnectors": False,
                    "extra": True,
                },
                "email": "nope@contoso.com",
            }
        }
    )
    body = get_channel(client, TEAM, CHANNEL)
    assert client.calls[0]["path"] == f"/teams/team-1/channels/{encoded}"
    assert body["id"] == CHANNEL
    assert "extra" not in body["moderationSettings"]
    assert "email" not in body


def test_shared_channel_members_first_page_403() -> None:
    path = f"/teams/team-1/channels/{'19%3Aabc%40thread.tacv2'}/members"
    client = FakeGraph(errors={path: SanitizedGraphError("4xx graph_error", status_class="4xx")})
    with pytest.raises(SanitizedGraphError, match="4xx graph_error"):
        list_channel_members(client, TEAM, CHANNEL, gid("0"), top=5)
