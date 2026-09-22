"""Conditional Access and tenant policy reads. GET-only. No user telemetry IPs."""

from __future__ import annotations

from typing import Any

from entra_mcp.allowlist import (
    AUTH_STRENGTH_FIELDS,
    CA_CONDITION_KEYS,
    CA_POLICY_FIELDS,
    CA_POLICY_MAX,
    CROSS_TENANT_PARTNER_MAX,
    NAMED_LOCATION_FIELDS,
    NAMED_LOCATION_MAX,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project
from entra_mcp.graph_client import GraphClient, encode_path_segment, is_guid

_CA_STATES = frozenset(
    {"enabled", "disabled", "enabledForReportingButNotEnforced", "all"}
)
_GRANT_KEYS = (
    "operator",
    "builtInControls",
    "customAuthenticationFactors",
    "termsOfUse",
    "authenticationStrength",
)
_SESSION_KEYS = (
    "applicationEnforcedRestrictions",
    "cloudAppSecurity",
    "signInFrequency",
    "persistentBrowser",
    "continuousAccessEvaluation",
    "disableResilienceDefaults",
    "secureSignInSession",
)
RESOLVE_HINT = (
    "GUIDs are returned as-is. Name users with get_user, groups with get_group, "
    "named locations with list_named_locations, authentication strengths with "
    "list_authentication_strengths."
)


def _subcall(client: GraphClient, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        return {"ok": True, "data": client.get(path, params=params)}
    except SanitizedGraphError as exc:
        return {"ok": False, "error": exc.message, "status_class": exc.status_class}


def _project_conditions(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in CA_CONDITION_KEYS if key in value}


def _project_controls(value: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in keys if key in value}


def project_ca_policy(item: dict[str, Any]) -> dict[str, Any]:
    row = project(item, CA_POLICY_FIELDS)
    if "conditions" in row:
        row["conditions"] = _project_conditions(row.get("conditions"))
    if "grantControls" in row:
        row["grantControls"] = _project_controls(row.get("grantControls"), _GRANT_KEYS)
    if "sessionControls" in row:
        row["sessionControls"] = _project_controls(row.get("sessionControls"), _SESSION_KEYS)
    return row


def list_conditional_access_policies(
    client: GraphClient,
    *,
    state: str = "all",
) -> dict[str, Any]:
    wanted = (state or "all").strip()
    if wanted not in _CA_STATES:
        raise SanitizedGraphError("invalid_state", status_class="4xx")
    params: dict[str, str] = {"$select": ",".join(CA_POLICY_FIELDS)}
    if wanted != "all":
        params["$filter"] = f"state eq '{wanted}'"
    items = client.collect_page(
        "/identity/conditionalAccess/policies",
        params=params,
        item_cap=CA_POLICY_MAX,
    )
    return {
        "policies": [project_ca_policy(item) for item in items],
        "state": wanted,
        "truncated": len(items) >= CA_POLICY_MAX,
        "scan_cap": CA_POLICY_MAX,
        "resolve_hint": RESOLVE_HINT,
    }


def get_conditional_access_policy(client: GraphClient, policy_id: str) -> dict[str, Any]:
    if not policy_id or not is_guid(policy_id):
        raise SanitizedGraphError("invalid_policy_id", status_class="4xx")
    data = client.get(
        f"/identity/conditionalAccess/policies/{encode_path_segment(policy_id)}",
        params={"$select": ",".join(CA_POLICY_FIELDS)},
    )
    return project_ca_policy(data)


def _project_ip_ranges(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return out
    for item in values:
        if isinstance(item, dict) and "cidrAddress" in item:
            out.append({"cidrAddress": item["cidrAddress"]})
    return out


def list_named_locations(client: GraphClient) -> dict[str, Any]:
    # Derived fields (isTrusted, ipRanges) are not on namedLocation, so $select of them is a 400.
    items = client.collect_page(
        "/identity/conditionalAccess/namedLocations",
        item_cap=NAMED_LOCATION_MAX,
    )
    locations = []
    for item in items:
        row = project(item, NAMED_LOCATION_FIELDS)
        if "ipRanges" in row:
            row["ipRanges"] = _project_ip_ranges(row.get("ipRanges"))
        locations.append(row)
    return {
        "locations": locations,
        "truncated": len(items) >= NAMED_LOCATION_MAX,
        "scan_cap": NAMED_LOCATION_MAX,
        "note": "IP ranges are Conditional Access policy configuration, not user sign-in telemetry.",
    }


def list_authentication_strengths(client: GraphClient) -> dict[str, Any]:
    items = client.collect_page(
        "/policies/authenticationStrengthPolicies",
        params={"$select": ",".join(AUTH_STRENGTH_FIELDS)},
        item_cap=100,
    )
    return {"policies": [project(item, AUTH_STRENGTH_FIELDS) for item in items]}


def _project_authz(data: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "allowInvitesFrom",
        "allowedToSignUpEmailBasedSubscriptions",
        "allowEmailVerifiedUsersToJoinOrganization",
        "blockMsolPowerShell",
        "guestUserRoleId",
        "defaultUserRolePermissions",
    )
    row = {key: data[key] for key in keys if key in data}
    perms = row.get("defaultUserRolePermissions")
    if isinstance(perms, dict):
        row["defaultUserRolePermissions"] = {
            key: perms[key]
            for key in (
                "allowedToCreateApps",
                "allowedToCreateSecurityGroups",
                "allowedToReadOtherUsers",
                "permissionGrantPoliciesAssigned",
            )
            if key in perms
        }
    return row


def get_tenant_security_settings(client: GraphClient) -> dict[str, Any]:
    defaults = _subcall(client, "/policies/identitySecurityDefaultsEnforcementPolicy")
    authz = _subcall(client, "/policies/authorizationPolicy")
    consent = _subcall(client, "/policies/adminConsentRequestPolicy")
    result: dict[str, Any] = {"complete": True}
    if defaults["ok"]:
        data = defaults["data"]
        result["securityDefaults"] = {
            key: data[key] for key in ("id", "isEnabled", "description") if key in data
        }
    else:
        result["securityDefaults"] = {"ok": False, "error": defaults["error"], "status_class": defaults["status_class"]}
        result["complete"] = False
    if authz["ok"]:
        result["authorizationPolicy"] = _project_authz(authz["data"])
    else:
        result["authorizationPolicy"] = {"ok": False, "error": authz["error"], "status_class": authz["status_class"]}
        result["complete"] = False
    if consent["ok"]:
        data = consent["data"]
        result["adminConsentRequestPolicy"] = {
            key: data[key]
            for key in ("isEnabled", "notifyReviewers", "requestDurationInDays")
            if key in data
        }
    else:
        result["adminConsentRequestPolicy"] = {
            "ok": False,
            "error": consent["error"],
            "status_class": consent["status_class"],
        }
        result["complete"] = False
    return result


def _project_targets(values: Any) -> list[dict[str, Any]]:
    out = []
    if not isinstance(values, list):
        return out
    for item in values:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                key: item[key]
                for key in ("targetType", "id", "isRegistrationRequired")
                if key in item
            }
        )
    return out


def get_authentication_methods_policy(client: GraphClient) -> dict[str, Any]:
    data = client.get("/policies/authenticationMethodsPolicy")
    configs = []
    for item in data.get("authenticationMethodConfigurations") or []:
        if not isinstance(item, dict):
            continue
        row = {key: item[key] for key in ("id", "state") if key in item}
        if "includeTargets" in item:
            row["includeTargets"] = _project_targets(item.get("includeTargets"))
        if "excludeTargets" in item:
            row["excludeTargets"] = _project_targets(item.get("excludeTargets"))
        configs.append(row)
    return {
        "id": data.get("id"),
        "displayName": data.get("displayName"),
        "description": data.get("description"),
        "registrationEnforcement": data.get("registrationEnforcement"),
        "authenticationMethodConfigurations": configs,
        "note": "Tenant authentication-method policy only. Not per-user method data.",
    }


def _project_partner(item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "tenantId",
        "isServiceProvider",
        "isInMultiTenantOrganization",
        "inboundTrust",
        "b2bCollaborationInbound",
        "b2bCollaborationOutbound",
        "b2bDirectConnectInbound",
        "b2bDirectConnectOutbound",
        "automaticUserConsentSettings",
        "invitationRedemptionIdentityProviderConfiguration",
    )
    row = {key: item[key] for key in keys if key in item}
    trust = row.get("inboundTrust")
    if isinstance(trust, dict):
        row["inboundTrust"] = {
            key: trust[key]
            for key in (
                "isMfaAccepted",
                "isCompliantDeviceAccepted",
                "isHybridAzureADJoinedDeviceAccepted",
            )
            if key in trust
        }
    return row


def get_cross_tenant_access_policy(client: GraphClient) -> dict[str, Any]:
    base = _subcall(client, "/policies/crossTenantAccessPolicy")
    default = _subcall(client, "/policies/crossTenantAccessPolicy/default")
    partial = not base["ok"] or not default["ok"]
    partners: list[dict[str, Any]] = []
    truncated = False
    partner_error = None
    try:
        items = client.collect_page(
            "/policies/crossTenantAccessPolicy/partners",
            item_cap=CROSS_TENANT_PARTNER_MAX,
        )
        partners = [_project_partner(item) for item in items]
        truncated = len(items) >= CROSS_TENANT_PARTNER_MAX
    except SanitizedGraphError as exc:
        partial = True
        partner_error = {"error": exc.message, "status_class": exc.status_class}
    default_row = None
    if default["ok"]:
        default_row = _project_partner(default["data"])
        default_row["isServiceDefault"] = bool(default["data"].get("isServiceDefault"))
    return {
        "policy": (
            {key: base["data"].get(key) for key in ("id", "displayName", "allowedCloudEndpoints") if key in base["data"]}
            if base["ok"]
            else {"ok": False, "error": base["error"], "status_class": base["status_class"]}
        ),
        "default": default_row
        if default["ok"]
        else {"ok": False, "error": default["error"], "status_class": default["status_class"]},
        "partners": partners,
        "partners_error": partner_error,
        "truncated": truncated,
        "partial": partial,
        "scan_cap": CROSS_TENANT_PARTNER_MAX,
    }
