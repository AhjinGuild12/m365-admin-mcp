"""Active directory role members. PIM-eligible and group-assigned are not included."""

from __future__ import annotations

from typing import Any

from entra_mcp.allowlist import (
    DIRECTORY_ROLE_FIELDS,
    DIRECTORY_ROLE_MEMBER_FIELDS,
    MEMBER_PAGE_CAP,
    PIM_SCHEDULE_CAP,
    PIM_SETTINGS_CAP,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project
from entra_mcp.graph_client import GraphClient, encode_path_segment, escape_odata_string, is_guid

ROLE_SCOPE = "active_direct_only"


def _project_member(item: dict[str, Any]) -> dict[str, Any]:
    return project(item, DIRECTORY_ROLE_MEMBER_FIELDS)


def _load_roles(client: GraphClient) -> list[dict[str, Any]]:
    items = client.collect_page(
        "/directoryRoles",
        params={"$select": ",".join(DIRECTORY_ROLE_FIELDS)},
        item_cap=200,
    )
    return [project(item, DIRECTORY_ROLE_FIELDS) for item in items]


def _match_role(roles: list[dict[str, Any]], role: str) -> dict[str, Any]:
    needle = role.strip().lower()
    matches = []
    for item in roles:
        display = str(item.get("displayName") or "").lower()
        template = str(item.get("roleTemplateId") or "").lower()
        object_id = str(item.get("id") or "").lower()
        if needle in {display, template, object_id}:
            matches.append(item)
    if not matches:
        raise SanitizedGraphError("role_not_found", status_class="4xx")
    if len(matches) > 1:
        raise SanitizedGraphError("multiple_matches", status_class="4xx")
    return matches[0]


def _members_for_role(client: GraphClient, role_id: str) -> list[dict[str, Any]]:
    path = f"/directoryRoles/{encode_path_segment(role_id)}/members"
    select = ",".join(f for f in DIRECTORY_ROLE_MEMBER_FIELDS if f != "@odata.type")
    items = client.collect_page(
        path,
        params={"$select": select},
        item_cap=MEMBER_PAGE_CAP,
    )
    return [_project_member(item) for item in items]


def list_directory_role_members(
    client: GraphClient,
    *,
    role: str | None = None,
    all_roles: bool = False,
) -> dict[str, Any]:
    if not all_roles and not role:
        raise SanitizedGraphError("role_required", status_class="4xx")
    roles = _load_roles(client)
    selected: list[dict[str, Any]]
    if all_roles:
        selected = roles
    else:
        assert role is not None
        selected = [_match_role(roles, role)]
    out = []
    for item in selected:
        role_id = str(item.get("id") or "")
        members = _members_for_role(client, role_id) if role_id else []
        out.append(
            {
                **item,
                "members": members,
            }
        )
    return {
        "roles": out,
        "scope": ROLE_SCOPE,
        "includes_pim_eligible": False,
        "includes_group_assigned": False,
        "note": "Active direct members only. For PIM-activated and group-assigned principals use list_pim_active_roles. That tool lists assignment principals, not every user inside a role-assigned group.",
    }


_KNOWN_RULE_SUFFIXES = (
    "ApprovalRule",
    "ExpirationRule",
    "EnablementRule",
    "NotificationRule",
    "AuthenticationContextRule",
)


def _project_principal(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {
        key: value[key]
        for key in ("id", "displayName", "userPrincipalName", "@odata.type")
        if key in value
    }


def _project_role_definition(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {
        key: value[key]
        for key in ("id", "displayName", "templateId")
        if key in value
    }


def _project_schedule(item: dict[str, Any], *, active: bool) -> dict[str, Any]:
    keys = (
        "id",
        "principalId",
        "roleDefinitionId",
        "directoryScopeId",
        "appScopeId",
        "startDateTime",
        "endDateTime",
        "memberType",
    )
    row = {key: item[key] for key in keys if key in item}
    if "principal" in item:
        row["principal"] = _project_principal(item.get("principal"))
    if "roleDefinition" in item:
        row["roleDefinition"] = _project_role_definition(item.get("roleDefinition"))
    if active and "assignmentType" in item:
        row["assignmentType"] = item["assignmentType"]
    return row


def _resolve_role_definition_id(client: GraphClient, role: str) -> str:
    if is_guid(role):
        return role
    items = client.collect_page(
        "/roleManagement/directory/roleDefinitions",
        params={"$select": "id,displayName,templateId"},
        item_cap=300,
    )
    needle = role.strip().lower()
    matches = []
    for item in items:
        display = str(item.get("displayName") or "").lower()
        template = str(item.get("templateId") or "").lower()
        object_id = str(item.get("id") or "").lower()
        if needle in {display, template, object_id}:
            matches.append(item)
    if not matches:
        raise SanitizedGraphError("role_not_found", status_class="4xx")
    if len(matches) > 1:
        raise SanitizedGraphError("multiple_matches", status_class="4xx")
    return str(matches[0].get("id") or "")


def _list_schedules(
    client: GraphClient,
    path: str,
    *,
    role: str | None,
    active: bool,
) -> dict[str, Any]:
    params: dict[str, str] = {
        "$expand": "principal,roleDefinition",
    }
    if role:
        role_id = _resolve_role_definition_id(client, role)
        params["$filter"] = f"roleDefinitionId eq '{escape_odata_string(role_id)}'"
    items = client.collect_page(path, params=params, item_cap=PIM_SCHEDULE_CAP)
    return {
        "assignments": [_project_schedule(item, active=active) for item in items],
        "truncated": len(items) >= PIM_SCHEDULE_CAP,
        "scan_cap": PIM_SCHEDULE_CAP,
        "role": role,
    }


def list_pim_eligible_roles(
    client: GraphClient,
    *,
    role: str | None = None,
) -> dict[str, Any]:
    result = _list_schedules(
        client,
        "/roleManagement/directory/roleEligibilityScheduleInstances",
        role=role,
        active=False,
    )
    result["kind"] = "eligible"
    return result


def list_pim_active_roles(
    client: GraphClient,
    *,
    role: str | None = None,
) -> dict[str, Any]:
    result = _list_schedules(
        client,
        "/roleManagement/directory/roleAssignmentScheduleInstances",
        role=role,
        active=True,
    )
    result["kind"] = "active_assignment_principals"
    result["note"] = (
        "Active assignment principals, including a group principal. "
        "Does not expand each user inside a role-assigned group."
    )
    return result


def _project_rule(rule: dict[str, Any]) -> dict[str, Any]:
    row = {
        key: rule[key]
        for key in (
            "id",
            "@odata.type",
            "isEnabled",
            "maximumDuration",
            "isExpirationRequired",
            "enabledRules",
            "target",
        )
        if key in rule
    }
    setting = rule.get("setting")
    if isinstance(setting, dict):
        slim = {
            key: setting[key]
            for key in ("isApprovalRequired", "approvalMode", "isApprovalRequiredForExtension")
            if key in setting
        }
        if slim:
            row["setting"] = slim
    odata = str(row.get("@odata.type") or "")
    if odata and not any(odata.endswith(suffix) for suffix in _KNOWN_RULE_SUFFIXES):
        row["unknown_rule_type"] = True
    return row


def list_pim_role_settings(
    client: GraphClient,
    *,
    role: str | None = None,
) -> dict[str, Any]:
    filt = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
    role_id = None
    if role:
        role_id = _resolve_role_definition_id(client, role)
        filt += f" and roleDefinitionId eq '{escape_odata_string(role_id)}'"
    items = client.collect_page(
        "/policies/roleManagementPolicyAssignments",
        params={"$filter": filt, "$expand": "policy($expand=rules)"},
        item_cap=PIM_SETTINGS_CAP,
    )
    assignments = []
    for item in items:
        policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
        rules = policy.get("rules") if isinstance(policy, dict) else None
        assignments.append(
            {
                "id": item.get("id"),
                "roleDefinitionId": item.get("roleDefinitionId"),
                "scopeId": item.get("scopeId"),
                "scopeType": item.get("scopeType"),
                "policyId": item.get("policyId") or (policy.get("id") if isinstance(policy, dict) else None),
                "rules": [
                    _project_rule(rule) for rule in (rules or []) if isinstance(rule, dict)
                ],
            }
        )
    return {
        "assignments": assignments,
        "truncated": len(items) >= PIM_SETTINGS_CAP,
        "scan_cap": PIM_SETTINGS_CAP,
        "role": role_id or role,
    }
