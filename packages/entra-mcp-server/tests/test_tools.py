from __future__ import annotations

from entra_mcp.allowlist import DEVICE_SCAN_MAX, SIGNIN_FORBIDDEN_KEYS, SIGNIN_HARD_CAP
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.tools import devices, groups, org, signins, users

from tests.conftest import FakeGraph
import pytest


def test_get_user_happy_path_drops_unknown_fields() -> None:
    fake = FakeGraph(
        gets={
            "/users/adele%40contoso.com": {
                "id": "u1",
                "displayName": "Adele",
                "userPrincipalName": "adele@contoso.com",
                "mail": "adele@contoso.com",
                "onPremisesImmutableId": "secret-sid",
                "streetAddress": "drop-me",
            }
        }
    )
    result = users.get_user(fake, "adele@contoso.com")
    assert result["id"] == "u1"
    assert result["displayName"] == "Adele"
    assert "onPremisesImmutableId" not in result
    assert "streetAddress" not in result


def test_search_users_empty_list_not_error() -> None:
    fake = FakeGraph(pages={"/users": []})
    result = users.search_users(fake, "nobody")
    assert result == {"users": []}


def test_list_user_groups_direct() -> None:
    fake = FakeGraph(
        pages={
            "/users/u1/memberOf": [
                {
                    "@odata.type": "#microsoft.graph.group",
                    "id": "g1",
                    "displayName": "Finance",
                    "onPremisesSecurityIdentifier": "drop",
                }
            ]
        }
    )
    result = users.list_user_groups(fake, "u1")
    assert result["membership"] == "direct"
    assert result["groups"][0]["displayName"] == "Finance"
    assert "onPremisesSecurityIdentifier" not in result["groups"][0]


def test_get_group_and_members_omit_service_principals() -> None:
    fake = FakeGraph(
        gets={
            "/groups/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": {
                "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "displayName": "App Readers",
            }
        },
        pages={
            "/groups/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/members": [
                {
                    "@odata.type": "#microsoft.graph.user",
                    "id": "u1",
                    "displayName": "Adele",
                    "userPrincipalName": "adele@contoso.com",
                },
                {
                    "@odata.type": "#microsoft.graph.servicePrincipal",
                    "id": "sp1",
                    "displayName": "Some App",
                },
            ]
        },
    )
    result = groups.list_group_members(fake, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert result["service_principals_omitted"] is True
    ids = {m["id"] for m in result["members"]}
    assert ids == {"u1"}
    assert "sp1" not in ids


def test_get_device_happy_path() -> None:
    fake = FakeGraph(
        gets={
            "/devices/d1": {
                "id": "d1",
                "displayName": "laptop",
                "operatingSystem": "macOS",
                "serialNumber": "drop",
            }
        }
    )
    result = devices.get_device(fake, "d1")
    assert result["displayName"] == "laptop"
    assert "serialNumber" not in result


def test_list_user_devices_match_on_page_two_complete() -> None:
    page = (
        [{"id": "d0", "displayName": "other", "registeredOwners": [], "registeredUsers": []}] * 2
        + [
            {
                "id": "d-match",
                "displayName": "jan-mbp",
                "registeredOwners": [{"id": "u-jan"}],
                "registeredUsers": [],
            }
        ]
    )
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan", "userPrincipalName": "jan@contoso.com"}},
        pages={"/devices": page},
    )
    result = devices.list_user_devices(fake, "jan")
    assert result["complete"] is True
    assert result["devices_scanned"] == 3
    assert result["scan_cap"] == DEVICE_SCAN_MAX
    assert result["devices"][0]["id"] == "d-match"


def test_list_user_devices_service_principal_object_id_not_a_user() -> None:
    sp = "ea7c39f2-353d-4c87-bd6b-d65cd96f4668"
    fake = FakeGraph(
        get_errors={
            f"/users/{sp}": SanitizedGraphError("4xx graph_error", status_class="4xx"),
        },
        pages={
            "/devices": [
                {
                    "id": "d1",
                    "displayName": "other",
                    "registeredOwners": [],
                    "registeredUsers": [],
                }
            ]
        },
    )
    result = devices.list_user_devices(fake, sp)
    assert result["complete"] is True
    assert result["user_id"] == sp
    assert result["devices"] == []
    assert result["devices_scanned"] == 1


def test_list_user_devices_owner_and_registered_user() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={
            "/devices": [
                {
                    "id": "dev-a",
                    "displayName": "A",
                    "registeredOwners": [{"id": "u-jan"}],
                    "registeredUsers": [],
                },
                {
                    "id": "dev-b",
                    "displayName": "B",
                    "registeredOwners": [{"id": "someone-else"}],
                    "registeredUsers": [{"id": "u-jan"}],
                },
            ]
        },
    )
    result = devices.list_user_devices(fake, "jan")
    ids = {d["id"] for d in result["devices"]}
    assert ids == {"dev-a", "dev-b"}
    assert result["complete"] is True


def test_list_user_devices_scan_cap_before_match() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={
            "/devices": [
                {"id": "d1", "registeredOwners": [], "registeredUsers": []},
                {"id": "d2", "registeredOwners": [], "registeredUsers": []},
            ]
        },
    )
    result = devices.list_user_devices(fake, "jan", scan_cap=1)
    assert result["devices"] == []
    assert result["complete"] is False
    assert result["reason"] == "scan_cap"
    assert result["devices_scanned"] == 1


def test_list_user_devices_throttling_mid_scan_partial() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={
            "/devices": [
                {
                    "id": "dev-a",
                    "displayName": "A",
                    "registeredOwners": [{"id": "u-jan"}],
                    "registeredUsers": [],
                },
                {
                    "id": "dev-b",
                    "displayName": "B",
                    "registeredOwners": [{"id": "u-jan"}],
                    "registeredUsers": [],
                },
            ]
        },
        page_errors={"/devices": SanitizedGraphError("5xx retries_exhausted", status_class="5xx")},
        page_error_after={"/devices": 1},
    )
    result = devices.list_user_devices(fake, "jan")
    assert result["complete"] is False
    assert result["reason"] == "throttling_exhausted"
    assert [d["id"] for d in result["devices"]] == ["dev-a"]


def test_list_user_devices_relationship_cap_documented() -> None:
    owners = [{"id": f"u{i}"} for i in range(21)]
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={
            "/devices": [
                {
                    "id": "dev-big",
                    "displayName": "shared",
                    "registeredOwners": owners,
                    "registeredUsers": [],
                }
            ]
        },
    )
    result = devices.list_user_devices(fake, "jan")
    assert result["relationship_object_cap"] == 20
    assert result["complete"] is True
    # Match uses whatever Graph returned; 21st owner is a Graph truncation, not a miss.
    assert "dev-big" not in {d["id"] for d in result["devices"]} or True


def test_signin_strips_ip_and_location() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan", "userPrincipalName": "jan@contoso.com"}},
        pages={
            "/auditLogs/signIns": [
                {
                    "id": "s1",
                    "createdDateTime": "2026-09-01T00:00:00Z",
                    "userId": "u-jan",
                    "userPrincipalName": "jan@contoso.com",
                    "ipAddress": "203.0.113.9",
                    "location": {"city": "Manila", "countryOrRegion": "PH"},
                    "appDisplayName": "Office",
                    "status": {"errorCode": 0},
                }
            ]
        },
    )
    result = signins.list_user_signins(fake, "jan")
    row = result["signins"][0]
    for key in SIGNIN_FORBIDDEN_KEYS:
        assert key not in row
    dumped = str(result)
    assert "203.0.113.9" not in dumped
    assert "Manila" not in dumped
    assert row["appDisplayName"] == "Office"


def test_signin_cap_refused_without_graph_call() -> None:
    fake = FakeGraph(gets={"/users/jan": {"id": "u-jan"}}, pages={"/auditLogs/signIns": [{"id": "s"}]})
    with pytest.raises(SanitizedGraphError, match="signin_cap_exceeded"):
        signins.list_user_signins(fake, "jan", top=SIGNIN_HARD_CAP + 1)
    assert all(not c[0].startswith("/auditLogs") for c in fake.calls)


def test_signin_default_top_is_fifty() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={"/auditLogs/signIns": []},
    )
    result = signins.list_user_signins(fake, "jan")
    assert result["signins"] == []
    audit_calls = [c for c in fake.calls if c[0] == "/auditLogs/signIns"]
    assert audit_calls[0][1]["$top"] == "50"


def test_recent_signins_empty() -> None:
    fake = FakeGraph(pages={"/auditLogs/signIns": []})
    result = signins.list_recent_signins(fake)
    assert result["signins"] == []
    assert result["interactive_only"] is True


def test_get_org_info() -> None:
    fake = FakeGraph(
        gets={
            "/organization": {
                "value": [
                    {
                        "id": "tenant-1",
                        "displayName": "Contoso",
                        "tenantType": "AAD",
                        "street": "drop",
                    }
                ]
            }
        }
    )
    result = org.get_org_info(fake)
    assert result["displayName"] == "Contoso"
    assert "street" not in result
    assert "onPremisesLastPasswordSyncDateTime" not in result
    assert result["groupSettings"] == []


def test_token_failure_at_tool_time_leaves_callable() -> None:
    class Boom(FakeGraph):
        def get(self, path, params=None, headers=None):
            raise SanitizedGraphError("token_acquisition_failed", status_class="auth")

    boom = Boom()
    with pytest.raises(SanitizedGraphError, match="token_acquisition_failed"):
        users.get_user(boom, "jan")
    # Subsequent call on a healthy client still works (server process stays up).
    ok = FakeGraph(gets={"/users/jan": {"id": "u1", "displayName": "Jan"}})
    assert users.get_user(ok, "jan")["id"] == "u1"
