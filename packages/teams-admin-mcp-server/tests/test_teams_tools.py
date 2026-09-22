from __future__ import annotations

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from teams_admin_mcp.allowlist import TEAMS_LIST_FILTER
from teams_admin_mcp.tools.teams import (
    get_team,
    get_team_sensitivity_labels,
    list_teams,
    list_user_joined_teams,
)
from tests.conftest import FakeGraph, gid

TEAM = gid("b")


def _team_row(**extra: object) -> dict:
    row = {
        "id": TEAM,
        "displayName": "Finance",
        "description": "books",
        "visibility": "private",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "webUrl": "https://example.test/team",
        "tenantId": gid("0"),
        "unused": "nope",
    }
    row.update(extra)
    return row


def test_list_teams_filter_has_no_consistency_header() -> None:
    client = FakeGraph(pages={"/groups": [_team_row()]})
    body = list_teams(client, top=5)
    call = client.calls[0]
    assert call["params"]["$filter"] == TEAMS_LIST_FILTER
    assert call["params"]["$top"] == "5"
    assert "ConsistencyLevel" not in call["headers"]
    assert "ConsistencyLevel" not in call["params"]
    assert body["filter_verified"] is True
    assert "unused" not in body["items"][0]
    assert "webUrl" not in body["items"][0]
    assert "tenantId" not in body["items"][0]


def test_list_teams_prefix_escapes_quote_and_verifies_rows() -> None:
    client = FakeGraph(
        pages={
            "/groups": [
                _team_row(displayName="O'Brien Team"),
                _team_row(id="other", displayName="Other"),
            ]
        }
    )
    body = list_teams(client, display_name_prefix="O'Brien", top=10)
    filt = client.calls[0]["params"]["$filter"]
    assert "startswith(displayName,'O''Brien')" in filt
    assert filt.startswith(TEAMS_LIST_FILTER)
    assert [row["displayName"] for row in body["items"]] == ["O'Brien Team"]
    assert body["filter_verified"] is False


def test_top_cap_makes_zero_requests() -> None:
    client = FakeGraph(pages={"/groups": []})
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        list_teams(client, top=201)
    assert client.calls == []


def test_sensitivity_labels_empty_and_unavailable() -> None:
    empty = FakeGraph(
        gets={
            f"/groups/{TEAM}": {
                "id": TEAM,
                "displayName": "Finance",
                "visibility": "private",
                "classification": None,
                "assignedLabels": [],
            }
        }
    )
    body = get_team_sensitivity_labels(empty, TEAM)
    assert body["assignedLabels"] == []
    assert body["labels_status"] == "empty"
    assert body["id"] == TEAM

    missing = FakeGraph(
        gets={
            f"/groups/{TEAM}": {
                "id": TEAM,
                "displayName": "Finance",
                "visibility": "public",
                "classification": "General",
            }
        }
    )
    unavailable = get_team_sensitivity_labels(missing, TEAM)
    assert unavailable["assignedLabels"] is None
    assert unavailable["labels_status"] == "unavailable"


def test_sensitivity_labels_project_children_only() -> None:
    client = FakeGraph(
        gets={
            f"/groups/{TEAM}": {
                "id": TEAM,
                "displayName": "Finance",
                "visibility": "private",
                "classification": "General",
                "assignedLabels": [
                    {"labelId": "lab", "displayName": "Confidential", "color": "red", "tenantId": gid("0")}
                ],
            }
        }
    )
    body = get_team_sensitivity_labels(client, TEAM)
    assert body["labels_status"] == "present"
    assert body["assignedLabels"] == [{"labelId": "lab", "displayName": "Confidential"}]


def test_get_team_id_mismatch_and_projection() -> None:
    mismatch = FakeGraph(gets={f"/teams/{TEAM}": {"id": "someone-else", "displayName": "X"}})
    with pytest.raises(SanitizedGraphError, match="id_mismatch"):
        get_team(mismatch, TEAM)
    client = FakeGraph(
        gets={
            f"/teams/{TEAM}": {
                "id": TEAM,
                "displayName": "Finance",
                "description": "books",
                "visibility": "private",
                "isArchived": False,
                "classification": "General",
                "createdDateTime": "2026-01-01T00:00:00Z",
                "isMembershipLimitedToOwners": False,
                "memberSettings": {"allowCreateUpdateChannels": True, "unused": True},
                "guestSettings": {"allowCreateUpdateChannels": False, "allowDeleteChannels": False},
                "summary": {"ownersCount": 1, "membersCount": 4, "guestsCount": 0},
                "webUrl": "https://example.test",
                "tenantId": gid("0"),
            }
        }
    )
    body = get_team(client, TEAM)
    assert body["id"] == TEAM
    assert body["memberSettings"] == {"allowCreateUpdateChannels": True}
    assert "tenantId" not in body
    assert "webUrl" not in body


def test_joined_teams_encodes_guest_upn() -> None:
    upn = "ada#EXT#@contoso.com"
    encoded = "ada%23EXT%23%40contoso.com"
    client = FakeGraph(pages={f"/users/{encoded}/joinedTeams": [{"id": TEAM, "displayName": "Finance", "description": "", "isArchived": False, "tenantId": gid("0")}]})
    body = list_user_joined_teams(client, upn)
    assert client.calls[0]["path"] == f"/users/{encoded}/joinedTeams"
    assert client.calls[0]["params"] == {}
    assert body["complete"] is True
    assert "tenantId" not in body["items"][0]


def test_joined_teams_rejects_slash_before_call() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="invalid_path_segment"):
        list_user_joined_teams(client, "a/b")
    assert client.calls == []
