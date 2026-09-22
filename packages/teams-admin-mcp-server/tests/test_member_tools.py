from __future__ import annotations

import json

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from teams_admin_mcp.tools.members import list_team_members, list_team_owners
from tests.conftest import FakeGraph, gid

HOME = gid("0")
OTHER = gid("c")
TEAM = "team-1"


def _member(name: str, *, roles: list[str], tenant: str | None) -> dict:
    row = {"id": name, "displayName": name, "userId": name, "email": f"{name}@contoso.com", "roles": roles}
    if tenant is not None:
        row["tenantId"] = tenant
    return row


def test_member_origin_and_tenant_strip() -> None:
    client = FakeGraph(
        pages={
            "/teams/team-1/members": [
                _member("ada", roles=["owner"], tenant=HOME),
                _member("bob", roles=[], tenant=OTHER),
                _member("cy", roles=["member"], tenant=None),
            ]
        }
    )
    body = list_team_members(client, TEAM, HOME, top=10)
    origins = [row["member_origin"] for row in body["items"]]
    assert origins == ["home", "external", "unknown"]
    dumped = json.dumps(body)
    assert "tenantId" not in dumped
    assert HOME not in dumped
    assert OTHER not in dumped


def test_first_page_403_raises() -> None:
    client = FakeGraph(
        errors={"/teams/team-1/members": SanitizedGraphError("4xx graph_error", status_class="4xx")}
    )
    with pytest.raises(SanitizedGraphError, match="4xx graph_error"):
        list_team_members(client, TEAM, HOME, top=5)


def test_owners_complete_partial_and_throttle() -> None:
    one = FakeGraph(
        pages={
            "/teams/team-1/members": [
                _member("ada", roles=["owner"], tenant=HOME),
                _member("bob", roles=[], tenant=HOME),
            ]
        }
    )
    body = list_team_owners(one, TEAM, HOME)
    assert len(body["items"]) == 1
    assert body["owner_count"] == 1
    assert body["complete"] is True
    assert one.calls[0]["params"]["$top"] == "999"

    none = FakeGraph(pages={"/teams/team-1/members": [_member("bob", roles=[], tenant=HOME)]})
    empty = list_team_owners(none, TEAM, HOME)
    assert empty["items"] == []
    assert empty["owner_count"] == 0

    capped = FakeGraph(
        pages={"/teams/team-1/members": [_member(f"u{i}", roles=["owner"], tenant=HOME) for i in range(3)]}
    )
    from teams_admin_mcp.tools import members as members_mod

    original = members_mod.OWNER_SCAN_CAP
    members_mod.OWNER_SCAN_CAP = 2
    try:
        capped_body = list_team_owners(capped, TEAM, HOME)
    finally:
        members_mod.OWNER_SCAN_CAP = original
    assert capped_body["owner_count"] is None
    assert capped_body["stop_reason"] == "item_cap"
    assert capped_body["complete"] is False

    throttled = FakeGraph(
        pages={"/teams/team-1/members": [_member("ada", roles=["owner"], tenant=HOME), _member("bea", roles=["owner"], tenant=HOME)]},
        errors={"/teams/team-1/members": SanitizedGraphError("5xx retries_exhausted", status_class="5xx")},
        page_error_after={"/teams/team-1/members": 1},
    )
    partial = list_team_owners(throttled, TEAM, HOME)
    assert partial["owner_count"] is None
    assert partial["stop_reason"] == "throttling_exhausted"
    assert len(partial["items"]) == 1
