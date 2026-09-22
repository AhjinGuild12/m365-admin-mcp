from __future__ import annotations

from datetime import datetime, timedelta, timezone

from entra_mcp.allowlist import CREDENTIAL_FORBIDDEN_KEYS, SIGNIN_FORBIDDEN_KEYS, TOOL_NAMES
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.tools import apps, audits, authmethods, groups, licenses, roles, signins, users

from tests.conftest import FakeGraph
import pytest

SKU = "11111111-1111-1111-1111-111111111111"
GROUP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP = "22222222-2222-2222-2222-222222222222"


def test_list_subscribed_skus_projects_and_maps_friendly_name() -> None:
    fake = FakeGraph(
        pages={
            "/subscribedSkus": [
                {
                    "skuId": SKU,
                    "skuPartNumber": "SPE_E3",
                    "capabilityStatus": "Enabled",
                    "consumedUnits": 10,
                    "prepaidUnits": {"enabled": 12, "suspended": 0, "warning": 0, "lockedOut": 9},
                    "servicePlans": [
                        {
                            "servicePlanName": "EXCHANGE_S_ENTERPRISE",
                            "provisioningStatus": "Success",
                            "secretPlan": "drop",
                        }
                    ],
                    "appliesTo": "User",
                    "accountSkuId": "drop-me",
                }
            ]
        }
    )
    result = licenses.list_subscribed_skus(fake)
    sku = result["skus"][0]
    assert sku["friendlyName"] == "Microsoft 365 E3"
    assert sku["prepaidUnits"] == {"enabled": 12, "suspended": 0, "warning": 0}
    assert "lockedOut" not in sku["prepaidUnits"]
    assert sku["servicePlans"][0]["servicePlanName"] == "EXCHANGE_S_ENTERPRISE"
    assert "secretPlan" not in sku["servicePlans"][0]
    assert "accountSkuId" not in sku


def test_get_user_licenses_includes_account_enabled_and_assignment_error() -> None:
    fake = FakeGraph(
        gets={
            "/users/jan": {
                "id": "u1",
                "userPrincipalName": "jan@contoso.com",
                "accountEnabled": False,
                "usageLocation": "NZ",
                "streetAddress": "drop",
                "licenseAssignmentStates": [
                    {
                        "skuId": SKU,
                        "state": "Active",
                        "error": "CountViolation",
                        "assignedByGroup": GROUP,
                    }
                ],
            }
        },
        pages={
            "/users/jan/licenseDetails": [
                {
                    "skuId": SKU,
                    "skuPartNumber": "SPE_E3",
                    "servicePlans": [{"servicePlanName": "TEAMS1", "provisioningStatus": "Success"}],
                }
            ]
        },
    )
    result = licenses.get_user_licenses(fake, "jan")
    assert result["accountEnabled"] is False
    assert result["licenses"][0]["friendlyName"] == "Microsoft 365 E3"
    assert result["licenseAssignmentStates"][0]["error"] == "CountViolation"
    assert "streetAddress" not in result


def test_list_users_by_sku_enabled_only_filters_disabled() -> None:
    fake = FakeGraph(
        pages={
            "/subscribedSkus": [{"skuId": SKU, "skuPartNumber": "SPE_E3"}],
            "/users": [
                {"id": "u1", "userPrincipalName": "a@contoso.com", "accountEnabled": True},
                {"id": "u2", "userPrincipalName": "b@contoso.com", "accountEnabled": False},
            ]
        }
    )
    result = licenses.list_users_by_sku(fake, SKU, enabled_only=True)
    assert [u["id"] for u in result["users"]] == ["u1"]
    assert result["skuId"] == SKU
    assert result["skuPartNumber"] == "SPE_E3"
    assert result["friendlyName"] == "Microsoft 365 E3"


def test_list_license_groups_falls_back_when_count_filter_rejected() -> None:
    fake = FakeGraph(
        pages={
            "/groups": [
                {"id": "g1", "displayName": "E3", "assignedLicenses": [{"skuId": SKU}]},
                {"id": "g2", "displayName": "plain", "assignedLicenses": []},
            ]
        },
        page_errors={"/groups": SanitizedGraphError("4xx graph_error", status_class="4xx")},
        page_error_on_hit={"/groups": 1},
    )
    result = licenses.list_license_groups(fake)
    assert result["filter_mode"] == "fallback_scan"
    assert [g["id"] for g in result["groups"]] == ["g1"]


def test_list_stale_users_never_projects_mail() -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake = FakeGraph(
        pages={
            "/users": [
                {
                    "id": "u1",
                    "displayName": "Old",
                    "userPrincipalName": "old@contoso.com",
                    "userType": "Member",
                    "accountEnabled": True,
                    "mail": "old@contoso.com",
                    "otherMails": ["alt@contoso.com"],
                    "signInActivity": {"lastSignInDateTime": old},
                }
            ]
        }
    )
    result = users.list_stale_users(fake, days=90)
    assert result["users"][0]["id"] == "u1"
    assert "mail" not in result["users"][0]
    assert "otherMails" not in result["users"][0]


def test_check_user_in_group_truncated_negative_is_not_authoritative() -> None:
    fake = FakeGraph(
        gets={
            "/users/jan": {"id": "u1", "userPrincipalName": "jan@contoso.com"},
            f"/groups/{GROUP}": {"id": GROUP, "displayName": "Target"},
        },
        pages={
            f"/users/u1/transitiveMemberOf/microsoft.graph.group": [
                {"id": "other", "displayName": "Other"}
            ]
        },
    )
    result = users.check_user_in_group(fake, "jan", GROUP)
    assert result["is_member"] is False
    assert result["membership"] == "transitive"
    assert result["authoritative"] is True


def test_get_user_manager_null_on_404() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u1"}},
        get_errors={
            "/users/u1/manager": SanitizedGraphError("4xx graph_error", status_class="4xx"),
        },
    )
    result = users.get_user_manager(fake, "jan")
    assert result == {"manager": None, "user_id": "u1"}


def test_list_user_direct_reports_keeps_odata_type() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u1"}},
        pages={
            "/users/u1/directReports": [
                {
                    "@odata.type": "#microsoft.graph.user",
                    "id": "u2",
                    "displayName": "Report",
                    "userPrincipalName": "r@contoso.com",
                }
            ]
        },
    )
    result = users.list_user_direct_reports(fake, "jan")
    assert result["direct_reports"][0]["@odata.type"].endswith("user")


def test_list_group_owners_flags_empty_as_visible_inventory() -> None:
    fake = FakeGraph(
        gets={f"/groups/{GROUP}": {"id": GROUP, "displayName": "Empty"}},
        pages={f"/groups/{GROUP}/owners": []},
    )
    result = groups.list_group_owners(fake, GROUP)
    assert result["ownerless"] is True
    assert result["inventory"] == "visible_graph_v1"


def test_list_dynamic_groups_does_not_invent_error_state() -> None:
    fake = FakeGraph(
        pages={
            "/groups": [
                {
                    "id": "g1",
                    "displayName": "Dyn",
                    "groupTypes": ["DynamicMembership"],
                    "membershipRule": '(user.department -eq "IT")',
                    "membershipRuleProcessingState": "On",
                }
            ]
        }
    )
    result = groups.list_dynamic_groups(fake)
    assert result["groups"][0]["membershipRuleProcessingState"] == "On"
    dumped = str(result)
    assert "error state" not in dumped.lower()


def test_directory_role_members_scope_is_active_direct_only() -> None:
    fake = FakeGraph(
        pages={
            "/directoryRoles": [
                {
                    "id": "r1",
                    "displayName": "Global Administrator",
                    "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
                }
            ],
            "/directoryRoles/r1/members": [
                {
                    "@odata.type": "#microsoft.graph.user",
                    "id": "u1",
                    "displayName": "Jan",
                    "userPrincipalName": "jan@contoso.com",
                    "accountEnabled": True,
                },
                {
                    "@odata.type": "#microsoft.graph.servicePrincipal",
                    "id": "sp1",
                    "displayName": "Backup App",
                },
            ],
        }
    )
    result = roles.list_directory_role_members(fake, role="Global Administrator")
    assert result["scope"] == "active_direct_only"
    assert result["includes_pim_eligible"] is False
    ids = {m["id"] for m in result["roles"][0]["members"]}
    assert ids == {"u1", "sp1"}


def test_directory_audits_strip_ip() -> None:
    fake = FakeGraph(
        pages={
            "/auditLogs/directoryAudits": [
                {
                    "id": "a1",
                    "activityDisplayName": "Add member to role",
                    "category": "RoleManagement",
                    "result": "success",
                    "activityDateTime": "2026-09-01T00:00:00Z",
                    "ipAddress": "203.0.113.9",
                    "initiatedBy": {
                        "user": {
                            "userPrincipalName": "jan@contoso.com",
                            "ipAddress": "198.51.100.4",
                        }
                    },
                    "targetResources": [
                        {
                            "id": "u1",
                            "displayName": "Adele",
                            "type": "User",
                            "modifiedProperties": [
                                {"displayName": "Role.DisplayName", "oldValue": None, "newValue": "GA"}
                            ],
                        }
                    ],
                }
            ]
        }
    )
    result = audits.list_directory_audits(fake, days=1)
    dumped = str(result)
    assert "203.0.113.9" not in dumped
    assert "198.51.100.4" not in dumped
    assert "ipAddress" not in dumped
    assert result["audits"][0]["activityDisplayName"] == "Add member to role"


def test_audit_cap_refused_without_graph_call() -> None:
    fake = FakeGraph(pages={"/auditLogs/directoryAudits": [{"id": "a"}]})
    with pytest.raises(SanitizedGraphError, match="audit_cap_exceeded"):
        audits.list_directory_audits(fake, top=201)
    assert fake.calls == []


def test_get_service_principal_strips_credential_secrets() -> None:
    fake = FakeGraph(
        gets={
            "/servicePrincipals/sp1": {
                "id": "sp1",
                "appId": APP,
                "displayName": "Backup",
                "keyCredentials": [
                    {
                        "keyId": "k1",
                        "displayName": "cert",
                        "endDateTime": "2027-01-01T00:00:00Z",
                        "key": "BASE64SECRETKEY",
                        "customKeyIdentifier": "deadbeef",
                    }
                ],
                "passwordCredentials": [
                    {
                        "keyId": "p1",
                        "displayName": "secret",
                        "endDateTime": "2027-01-01T00:00:00Z",
                        "secretText": "super-secret-value",
                        "hint": "sup",
                    }
                ],
            }
        },
        pages={
            "/servicePrincipals/sp1/oauth2PermissionGrants": [
                {"id": "g1", "clientId": "sp1", "consentType": "AllPrincipals", "scope": "User.Read"}
            ],
            "/servicePrincipals/sp1/appRoleAssignments": [],
            "/servicePrincipals/sp1/owners": [],
        },
    )
    result = apps.get_service_principal(fake, "sp1")
    dumped = str(result)
    assert "super-secret-value" not in dumped
    assert "BASE64SECRETKEY" not in dumped
    assert "deadbeef" not in dumped
    for key in CREDENTIAL_FORBIDDEN_KEYS:
        assert key not in result["passwordCredentials"][0]
        assert key not in result["keyCredentials"][0]
    assert result["keyCredentials"][0]["keyId"] == "k1"


def test_list_expiring_app_credentials_filters_and_strips() -> None:
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    later = (datetime.now(timezone.utc) + timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake = FakeGraph(
        pages={
            "/applications": [
                {
                    "id": "a1",
                    "appId": APP,
                    "displayName": "Soon",
                    "passwordCredentials": [
                        {
                            "keyId": "p-soon",
                            "endDateTime": soon,
                            "secretText": "do-not-leak",
                        },
                        {"keyId": "p-later", "endDateTime": later, "secretText": "also-secret"},
                    ],
                    "keyCredentials": [],
                }
            ]
        }
    )
    result = apps.list_expiring_app_credentials(fake, within_days=90)
    assert len(result["credentials"]) == 1
    assert result["credentials"][0]["keyId"] == "p-soon"
    dumped = str(result)
    assert "do-not-leak" not in dumped
    assert "also-secret" not in dumped


def test_list_tenant_wide_consents_resolves_sp_names() -> None:
    fake = FakeGraph(
        pages={
            "/oauth2PermissionGrants": [
                {
                    "id": "g1",
                    "clientId": "sp-client",
                    "resourceId": "sp-resource",
                    "consentType": "AllPrincipals",
                    "scope": "User.Read",
                }
            ]
        },
        gets={
            "/servicePrincipals/sp-client": {
                "id": "sp-client",
                "appId": APP,
                "displayName": "Client App",
            },
            "/servicePrincipals/sp-resource": {
                "id": "sp-resource",
                "appId": "33333333-3333-3333-3333-333333333333",
                "displayName": "Graph",
            },
        },
    )
    result = apps.list_tenant_wide_consents(fake)
    grant = result["grants"][0]
    assert grant["clientDisplayName"] == "Client App"
    assert grant["resourceDisplayName"] == "Graph"
    assert "AllPrincipals" in result["consentType"]


def test_list_user_app_assignments_names_default_role() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u1"}},
        pages={
            "/users/u1/appRoleAssignments": [
                {
                    "id": "as1",
                    "resourceId": "sp1",
                    "resourceDisplayName": "App",
                    "appRoleId": "00000000-0000-0000-0000-000000000000",
                    "principalType": "User",
                }
            ]
        },
    )
    result = apps.list_user_app_assignments(fake, "jan")
    assert result["assignments"][0]["appRoleName"] == "default"


def test_list_mfa_registration_projects_allowlisted_fields() -> None:
    fake = FakeGraph(
        pages={
            "/reports/authenticationMethods/userRegistrationDetails": [
                {
                    "id": "u1",
                    "userPrincipalName": "jan@contoso.com",
                    "isMfaRegistered": False,
                    "isAdmin": True,
                    "methodsRegistered": [],
                    "ssn": "drop",
                }
            ]
        }
    )
    result = authmethods.list_mfa_registration(fake, admins_only=True)
    row = result["registrations"][0]
    assert row["isMfaRegistered"] is False
    assert "ssn" not in row
    filt = fake.calls[0][1]["$filter"]
    assert "isMfaRegistered eq false" in filt
    assert "isAdmin eq true" in filt


def test_get_signin_strips_forbidden_fields() -> None:
    fake = FakeGraph(
        gets={
            "/auditLogs/signIns/s1": {
                "id": "s1",
                "createdDateTime": "2026-09-01T00:00:00Z",
                "appDisplayName": "Office",
                "ipAddress": "203.0.113.9",
                "location": {"city": "Auckland"},
            }
        }
    )
    result = signins.get_signin(fake, "s1")
    for key in SIGNIN_FORBIDDEN_KEYS:
        assert key not in result
    assert "203.0.113.9" not in str(result)
    assert result["appDisplayName"] == "Office"


def test_signin_app_id_filter_is_interactive_preset() -> None:
    fake = FakeGraph(
        gets={"/users/jan": {"id": "u-jan"}},
        pages={"/auditLogs/signIns": []},
    )
    result = signins.list_user_signins(fake, "jan", app_id=APP)
    assert result["interactive_user_signins_to_app"] is True
    filt = fake.calls[1][1]["$filter"]
    assert f"appId eq '{APP}'" in filt
    assert "isInteractive eq true" in filt


def test_list_user_consents_is_not_a_registered_tool() -> None:
    assert "list_user_consents" not in TOOL_NAMES
    assert "list_mfa_registration" not in TOOL_NAMES
