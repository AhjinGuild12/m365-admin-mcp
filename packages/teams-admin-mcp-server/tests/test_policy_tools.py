from __future__ import annotations

import json

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from teams_admin_mcp.tools.policies import get_user_teams_policy_assignments
from tests.conftest import FakeGraph, gid

USER = gid("d")
TENANT = gid("0")


def test_upn_is_rejected_before_any_call() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="guid_required"):
        get_user_teams_policy_assignments(client, "adele@contoso.com")
    assert client.calls == []


def test_id_mismatch_and_empty_body() -> None:
    mismatch = FakeGraph(gets={f"/admin/teams/userConfigurations/{USER}": {"id": gid("e"), "userPrincipalName": "a@contoso.com"}})
    with pytest.raises(SanitizedGraphError, match="id_mismatch"):
        get_user_teams_policy_assignments(mismatch, USER)
    empty = FakeGraph(gets={f"/admin/teams/userConfigurations/{USER}": {}})
    with pytest.raises(SanitizedGraphError, match="not_found"):
        get_user_teams_policy_assignments(empty, USER)


def test_case_match_empty_assignments_and_identifier_strip() -> None:
    client = FakeGraph(
        gets={
            f"/admin/teams/userConfigurations/{gid('D')}": {
                "id": gid("d"),
                "userPrincipalName": "ada@contoso.com",
                "accountType": "user",
                "isEnterpriseVoiceEnabled": False,
                "featureTypes": ["Teams"],
                "tenantId": TENANT,
                "telephoneNumbers": ["+1555"],
                "effectivePolicyAssignments": [],
            }
        }
    )
    body = get_user_teams_policy_assignments(client, gid("D"))
    assert body["id"] == gid("d")
    assert body["userPrincipalName"] == "ada@contoso.com"
    assert body["effectivePolicyAssignments"] == []
    dumped = json.dumps(body)
    assert "tenantId" not in dumped
    assert "telephoneNumbers" not in dumped
    assert TENANT not in dumped


def test_group_id_kept_and_403_is_unchanged() -> None:
    client = FakeGraph(
        gets={
            f"/admin/teams/userConfigurations/{USER}": {
                "id": USER,
                "userPrincipalName": "ada@contoso.com",
                "accountType": "user",
                "isEnterpriseVoiceEnabled": True,
                "featureTypes": [],
                "effectivePolicyAssignments": [
                    {
                        "policyType": "TeamsMeetingPolicy",
                        "policyAssignment": {
                            "displayName": "Default",
                            "assignmentType": "direct",
                            "policyId": "pol",
                            "groupId": "grp",
                            "tenantId": TENANT,
                        },
                        "extra": True,
                    }
                ],
            }
        }
    )
    body = get_user_teams_policy_assignments(client, USER)
    assignment = body["effectivePolicyAssignments"][0]
    assert assignment["policyAssignment"]["groupId"] == "grp"
    assert "tenantId" not in json.dumps(assignment)
    assert "extra" not in assignment

    denied = FakeGraph(
        errors={
            f"/admin/teams/userConfigurations/{USER}": SanitizedGraphError(
                "4xx graph_error", status_class="4xx"
            )
        }
    )
    with pytest.raises(SanitizedGraphError, match="4xx graph_error") as exc:
        get_user_teams_policy_assignments(denied, USER)
    assert exc.value.status_class == "4xx"
    assert "cloud" not in exc.value.message
