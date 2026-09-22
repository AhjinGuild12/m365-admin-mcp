from __future__ import annotations

from entra_mcp.allowlist import TOOL_NAMES
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.tools import audits, org, policies, roles, signins, users

from tests.conftest import FakeGraph
import pytest

POLICY = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_ca_list_projects_and_state_filter() -> None:
    fake = FakeGraph(
        pages={
            "/identity/conditionalAccess/policies": [
                {
                    "id": POLICY,
                    "displayName": "Require MFA",
                    "state": "enabled",
                    "conditions": {"users": {"includeUsers": ["All"]}, "secret": "drop"},
                    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
                    "sessionControls": None,
                }
            ]
        }
    )
    result = policies.list_conditional_access_policies(fake, state="enabled")
    row = result["policies"][0]
    assert row["displayName"] == "Require MFA"
    assert "secret" not in row["conditions"]
    assert "resolve_hint" in result
    assert "state eq 'enabled'" in fake.calls[0][1]["$filter"]


def test_named_locations_keep_cidr_only() -> None:
    fake = FakeGraph(
        pages={
            "/identity/conditionalAccess/namedLocations": [
                {
                    "id": "loc1",
                    "displayName": "Office",
                    "@odata.type": "#microsoft.graph.ipNamedLocation",
                    "isTrusted": True,
                    "ipRanges": [{"cidrAddress": "203.0.113.0/24", "extra": "drop"}],
                }
            ]
        }
    )
    result = policies.list_named_locations(fake)
    assert result["locations"][0]["ipRanges"] == [{"cidrAddress": "203.0.113.0/24"}]
    assert "policy configuration" in result["note"]


def test_auth_strengths_use_policy_path() -> None:
    fake = FakeGraph(pages={"/policies/authenticationStrengthPolicies": [{"id": "s1", "displayName": "MFA"}]})
    result = policies.list_authentication_strengths(fake)
    assert result["policies"][0]["displayName"] == "MFA"
    assert fake.calls[0][0] == "/policies/authenticationStrengthPolicies"


def test_security_settings_keep_partial_error() -> None:
    fake = FakeGraph(
        gets={
            "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
            "/policies/adminConsentRequestPolicy": {"isEnabled": True, "notifyReviewers": False, "requestDurationInDays": 30},
        },
        get_errors={
            "/policies/authorizationPolicy": SanitizedGraphError("4xx graph_error", status_class="4xx"),
        },
    )
    result = policies.get_tenant_security_settings(fake)
    assert result["complete"] is False
    assert result["securityDefaults"]["isEnabled"] is False
    assert result["authorizationPolicy"]["status_class"] == "4xx"


def test_cross_tenant_marks_service_default() -> None:
    fake = FakeGraph(
        gets={
            "/policies/crossTenantAccessPolicy": {"id": "base"},
            "/policies/crossTenantAccessPolicy/default": {
                "isServiceDefault": True,
                "inboundTrust": {"isMfaAccepted": True, "noise": "drop"},
            },
        },
        pages={"/policies/crossTenantAccessPolicy/partners": []},
    )
    result = policies.get_cross_tenant_access_policy(fake)
    assert result["default"]["isServiceDefault"] is True
    assert result["default"]["inboundTrust"] == {"isMfaAccepted": True}
    assert result["partial"] is False


def test_pim_active_does_not_claim_group_expansion() -> None:
    fake = FakeGraph(
        pages={
            "/roleManagement/directory/roleAssignmentScheduleInstances": [
                {
                    "id": "a1",
                    "assignmentType": "Assigned",
                    "memberType": "Group",
                    "principal": {
                        "@odata.type": "#microsoft.graph.group",
                        "id": "g1",
                        "displayName": "Admins",
                    },
                    "roleDefinition": {"id": "r1", "displayName": "Global Administrator"},
                }
            ]
        }
    )
    result = roles.list_pim_active_roles(fake)
    assert result["kind"] == "active_assignment_principals"
    assert "does not expand" in result["note"].lower() or "Does not expand" in result["note"]
    assert result["assignments"][0]["principal"]["@odata.type"].endswith("group")


def test_pim_unknown_rule_type_is_preserved() -> None:
    fake = FakeGraph(
        pages={
            "/policies/roleManagementPolicyAssignments": [
                {
                    "id": "pa1",
                    "roleDefinitionId": "r1",
                    "scopeId": "/",
                    "scopeType": "DirectoryRole",
                    "policy": {
                        "id": "pol1",
                        "rules": [
                            {
                                "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
                                "id": "Enablement_Admin_Assignment",
                                "enabledRules": ["Justification", "MultiFactorAuthentication"],
                            },
                            {
                                "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyFutureRule",
                                "id": "Future",
                                "isEnabled": True,
                            },
                        ],
                    },
                }
            ]
        }
    )
    result = roles.list_pim_role_settings(fake)
    rules = result["assignments"][0]["rules"]
    assert rules[0]["enabledRules"] == ["Justification", "MultiFactorAuthentication"]
    assert rules[1]["unknown_rule_type"] is True
    assert "isApprovalRequired" not in rules[1]


def test_activation_requests_are_not_registered() -> None:
    assert "list_pim_activation_requests" not in TOOL_NAMES


def test_include_ca_result_off_by_default() -> None:
    fake = FakeGraph(
        pages={
            "/auditLogs/signIns": [
                {
                    "id": "s1",
                    "appDisplayName": "Office",
                    "conditionalAccessStatus": "success",
                    "appliedConditionalAccessPolicies": [
                        {"id": POLICY, "displayName": "MFA", "result": "success", "ipAddress": "203.0.113.9"}
                    ],
                    "ipAddress": "198.51.100.4",
                }
            ]
        }
    )
    omitted = signins.list_recent_signins(fake)
    assert "appliedConditionalAccessPolicies" not in omitted["signins"][0]
    assert omitted["include_ca_result"] is False
    assert "198.51.100.4" not in str(omitted)
    included = signins.list_recent_signins(fake, include_ca_result=True)
    policies_out = included["signins"][0]["appliedConditionalAccessPolicies"]
    assert policies_out[0]["displayName"] == "MFA"
    assert "ipAddress" not in policies_out[0]
    assert "203.0.113.9" not in str(included)


def test_role_management_audit_preset_filter() -> None:
    fake = FakeGraph(pages={"/auditLogs/directoryAudits": []})
    audits.list_directory_audits(fake, days=1, category="RoleManagement")
    assert "category eq 'RoleManagement'" in fake.calls[0][1]["$filter"]


def test_domains_and_deleted_users_project_allowlist() -> None:
    fake = FakeGraph(
        pages={
            "/domains": [{"id": "contoso.com", "isVerified": True, "password": "drop"}],
            "/directory/deletedItems/microsoft.graph.user": [
                {"id": "u1", "userPrincipalName": "gone@contoso.com", "mail": "drop"}
            ],
        }
    )
    domains = org.list_domains(fake)
    assert domains["domains"][0]["id"] == "contoso.com"
    assert "password" not in domains["domains"][0]
    deleted = users.list_deleted_users(fake)
    assert deleted["users"][0]["userPrincipalName"] == "gone@contoso.com"
    assert "mail" not in deleted["users"][0]
    assert "offboarding" in deleted["note"]


def test_get_ca_rejects_non_guid() -> None:
    fake = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="invalid_policy_id"):
        policies.get_conditional_access_policy(fake, "not-a-guid")
    assert fake.calls == []
