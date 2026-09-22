"""Service principals, app credentials (metadata only), assignments, and tenant consents."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from entra_mcp.allowlist import (
    APP_ASSIGNMENT_FIELDS,
    APP_CREDENTIAL_SCAN_FIELDS,
    APP_SCAN_MAX,
    CONSENT_GRANT_FIELDS,
    CREDENTIAL_FORBIDDEN_KEYS,
    CREDENTIAL_METADATA_FIELDS,
    DEFAULT_SEARCH_TOP,
    GRANT_SCAN_MAX,
    MAX_SEARCH_TOP,
    MEMBER_PAGE_CAP,
    OWNER_FIELDS,
    SP_FIELDS,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, strip_keys
from entra_mcp.graph_client import (
    GraphClient,
    encode_path_segment,
    escape_odata_string,
    is_guid,
    odata_eq,
)

_ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def _clamp_top(top: int | None) -> int:
    if top is None:
        return DEFAULT_SEARCH_TOP
    if top < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    return min(top, MAX_SEARCH_TOP)


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def project_credentials(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return out
    for item in values:
        if not isinstance(item, dict):
            continue
        cleaned = strip_keys(item, CREDENTIAL_FORBIDDEN_KEYS)
        out.append(project(cleaned, CREDENTIAL_METADATA_FIELDS))
    return out


def search_service_principals(
    client: GraphClient,
    query: str,
    top: int | None = None,
) -> dict[str, Any]:
    if not query or not query.strip():
        raise SanitizedGraphError("invalid_query", status_class="4xx")
    bound = _clamp_top(top)
    filt = f"startswith(displayName,'{escape_odata_string(query.strip())}')"
    items = client.collect_page(
        "/servicePrincipals",
        params={
            "$filter": filt,
            "$select": ",".join(SP_FIELDS),
            "$top": str(bound),
        },
        item_cap=bound,
    )
    return {
        "service_principals": [project(item, SP_FIELDS) for item in items],
    }


def _load_sp(client: GraphClient, service_principal: str) -> dict[str, Any]:
    path = f"/servicePrincipals/{encode_path_segment(service_principal)}"
    try:
        data = client.get(path, params={"$select": ",".join(SP_FIELDS)})
        return project(data, SP_FIELDS)
    except SanitizedGraphError as exc:
        if exc.status_class != "4xx" or not is_guid(service_principal):
            raise
        items = client.collect_page(
            "/servicePrincipals",
            params={
                "$filter": odata_eq("appId", service_principal),
                "$select": ",".join(SP_FIELDS),
                "$top": "5",
            },
            item_cap=5,
        )
        projected = [project(item, SP_FIELDS) for item in items]
        if not projected:
            raise SanitizedGraphError("4xx graph_error", status_class="4xx") from None
        if len(projected) > 1:
            raise SanitizedGraphError("multiple_matches", status_class="4xx") from None
        return projected[0]


def get_service_principal(client: GraphClient, service_principal: str) -> dict[str, Any]:
    sp = _load_sp(client, service_principal)
    sp_id = str(sp.get("id") or "")
    if not sp_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    base = f"/servicePrincipals/{encode_path_segment(sp_id)}"
    raw = client.get(
        base,
        params={
            "$select": ",".join(SP_FIELDS)
            + ",keyCredentials,passwordCredentials,oauth2PermissionScopes,appRoles"
        },
    )
    grants = client.collect_page(
        f"{base}/oauth2PermissionGrants",
        params={"$select": ",".join(CONSENT_GRANT_FIELDS)},
        item_cap=MEMBER_PAGE_CAP,
    )
    assignments = client.collect_page(
        f"{base}/appRoleAssignments",
        params={"$select": ",".join(APP_ASSIGNMENT_FIELDS)},
        item_cap=MEMBER_PAGE_CAP,
    )
    owners = client.collect_page(
        f"{base}/owners",
        params={
            "$select": ",".join(f for f in OWNER_FIELDS if f != "@odata.type"),
        },
        item_cap=MEMBER_PAGE_CAP,
    )
    result = project(raw, SP_FIELDS)
    result["keyCredentials"] = project_credentials(raw.get("keyCredentials"))
    result["passwordCredentials"] = project_credentials(raw.get("passwordCredentials"))
    result["oauth2PermissionGrants"] = [
        project(item, CONSENT_GRANT_FIELDS) for item in grants
    ]
    result["appRoleAssignments"] = [
        project(item, APP_ASSIGNMENT_FIELDS) for item in assignments
    ]
    result["owners"] = [project(item, OWNER_FIELDS) for item in owners]
    return result


def list_expiring_app_credentials(
    client: GraphClient,
    *,
    within_days: int = 90,
    scan_cap: int = APP_SCAN_MAX,
) -> dict[str, Any]:
    if within_days < 1:
        raise SanitizedGraphError("invalid_within_days", status_class="4xx")
    if scan_cap < 1:
        raise SanitizedGraphError("invalid_scan_cap", status_class="4xx")
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=within_days)
    items = client.collect_page(
        "/applications",
        params={"$select": ",".join(APP_CREDENTIAL_SCAN_FIELDS)},
        item_cap=scan_cap,
    )
    expiring: list[dict[str, Any]] = []
    for app in items:
        app_row = {
            "id": app.get("id"),
            "appId": app.get("appId"),
            "displayName": app.get("displayName"),
        }
        for kind, raw in (
            ("password", app.get("passwordCredentials")),
            ("certificate", app.get("keyCredentials")),
        ):
            for cred in project_credentials(raw):
                end = _parse_dt(cred.get("endDateTime"))
                if end is None or end > cutoff:
                    continue
                days_remaining = int((end - now).total_seconds() // 86400)
                expiring.append(
                    {
                        **app_row,
                        "credentialKind": kind,
                        **cred,
                        "expired": end <= now,
                        "daysRemaining": days_remaining,
                    }
                )
    return {
        "credentials": expiring,
        "within_days": within_days,
        "truncated": len(items) >= scan_cap,
        "scan_cap": scan_cap,
        "applications_scanned": len(items),
    }


def _resolve_user_id(client: GraphClient, user: str) -> str:
    data = client.get(
        f"/users/{encode_path_segment(user)}",
        params={"$select": "id"},
    )
    user_id = data.get("id")
    if not user_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    return str(user_id)


def _role_name_map(client: GraphClient, resource_ids: list[str]) -> dict[tuple[str, str], str]:
    names: dict[tuple[str, str], str] = {}
    seen: set[str] = set()
    for resource_id in resource_ids:
        if not resource_id or resource_id in seen:
            continue
        seen.add(resource_id)
        try:
            sp = client.get(
                f"/servicePrincipals/{encode_path_segment(resource_id)}",
                params={"$select": "id,appRoles"},
            )
        except SanitizedGraphError:
            continue
        for role in sp.get("appRoles") or []:
            if not isinstance(role, dict):
                continue
            role_id = str(role.get("id") or "")
            label = str(role.get("displayName") or role.get("value") or "")
            if role_id and label:
                names[(resource_id, role_id)] = label
    return names


def list_user_app_assignments(client: GraphClient, user: str) -> dict[str, Any]:
    user_id = _resolve_user_id(client, user)
    items = client.collect_page(
        f"/users/{encode_path_segment(user_id)}/appRoleAssignments",
        params={"$select": ",".join(APP_ASSIGNMENT_FIELDS)},
        item_cap=MEMBER_PAGE_CAP,
    )
    resource_ids = [str(item.get("resourceId") or "") for item in items]
    names = _role_name_map(client, resource_ids)
    assignments = []
    for item in items:
        row = project(item, APP_ASSIGNMENT_FIELDS)
        resource_id = str(row.get("resourceId") or "")
        role_id = str(row.get("appRoleId") or "")
        if role_id == _ZERO_GUID:
            row["appRoleName"] = "default"
        else:
            row["appRoleName"] = names.get((resource_id, role_id))
        assignments.append(row)
    return {
        "assignments": assignments,
        "user_id": user_id,
        "truncated": len(items) >= MEMBER_PAGE_CAP,
    }


def _sp_label(client: GraphClient, object_id: str, cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if object_id in cache:
        return cache[object_id]
    label: dict[str, Any] = {}
    if not object_id:
        cache[object_id] = label
        return label
    try:
        sp = client.get(
            f"/servicePrincipals/{encode_path_segment(object_id)}",
            params={"$select": "id,appId,displayName"},
        )
        label = {
            key: sp[key] for key in ("id", "appId", "displayName") if key in sp
        }
    except SanitizedGraphError:
        label = {"id": object_id}
    cache[object_id] = label
    return label


def list_tenant_wide_consents(
    client: GraphClient,
    *,
    scan_cap: int = GRANT_SCAN_MAX,
) -> dict[str, Any]:
    if scan_cap < 1:
        raise SanitizedGraphError("invalid_scan_cap", status_class="4xx")
    items = client.collect_page(
        "/oauth2PermissionGrants",
        params={
            "$filter": "consentType eq 'AllPrincipals'",
            "$select": ",".join(CONSENT_GRANT_FIELDS),
        },
        item_cap=scan_cap,
    )
    cache: dict[str, dict[str, Any]] = {}
    grants = []
    for item in items:
        row = project(item, CONSENT_GRANT_FIELDS)
        client_id = str(row.get("clientId") or "")
        resource_id = str(row.get("resourceId") or "")
        client_sp = _sp_label(client, client_id, cache)
        resource_sp = _sp_label(client, resource_id, cache)
        row["clientDisplayName"] = client_sp.get("displayName")
        row["clientAppId"] = client_sp.get("appId")
        row["resourceDisplayName"] = resource_sp.get("displayName")
        grants.append(row)
    return {
        "grants": grants,
        "consentType": "AllPrincipals",
        "truncated": len(items) >= scan_cap,
        "scan_cap": scan_cap,
        "note": "clientId is the client service-principal object id, not application appId",
    }
