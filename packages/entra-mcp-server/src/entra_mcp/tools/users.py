"""User lookup, search, group membership, stale users, manager, and reports."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from entra_mcp.allowlist import (
    DEFAULT_SEARCH_TOP,
    DELETED_USER_CAP,
    DELETED_USER_FIELDS,
    DIRECT_REPORT_FIELDS,
    GROUP_FIELDS,
    GROUP_MEMBERSHIP_PAGE_CAP,
    MANAGER_FIELDS,
    MAX_SEARCH_TOP,
    STALE_USER_FIELDS,
    TRANSITIVE_MEMBERSHIP_PAGE_CAP,
    USER_FIELDS,
    USER_SCAN_MAX,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, project_list
from entra_mcp.graph_client import (
    GraphClient,
    build_search_clause,
    encode_path_segment,
)
from entra_mcp.tools.groups import get_group

SEARCH_HEADERS = {"ConsistencyLevel": "eventual"}


def _clamp_top(top: int | None) -> int:
    if top is None:
        return DEFAULT_SEARCH_TOP
    if top < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    return min(top, MAX_SEARCH_TOP)


def get_user(client: GraphClient, user: str) -> dict[str, Any]:
    path = f"/users/{encode_path_segment(user)}"
    data = client.get(path, params={"$select": ",".join(USER_FIELDS)})
    return project(data, USER_FIELDS)


def search_users(client: GraphClient, query: str, top: int | None = None) -> dict[str, Any]:
    bound = _clamp_top(top)
    search = (
        f"{build_search_clause('displayName', query)} OR "
        f"{build_search_clause('userPrincipalName', query)}"
    )
    items = client.collect_page(
        "/users",
        params={
            "$search": search,
            "$select": ",".join(USER_FIELDS),
            "$top": str(bound),
            "$count": "true",
        },
        headers=SEARCH_HEADERS,
        item_cap=bound,
    )
    return {"users": project_list(items, USER_FIELDS)}


def list_user_groups(client: GraphClient, user: str) -> dict[str, Any]:
    path = f"/users/{encode_path_segment(user)}/memberOf"
    items = client.collect_page(
        path,
        params={"$select": ",".join(GROUP_FIELDS)},
        item_cap=GROUP_MEMBERSHIP_PAGE_CAP,
    )
    groups = [project(item, GROUP_FIELDS) for item in items if _looks_like_group(item)]
    return {"groups": groups, "membership": "direct"}


def _looks_like_group(item: dict[str, Any]) -> bool:
    odata_type = str(item.get("@odata.type", ""))
    if odata_type and odata_type.endswith("group"):
        return True
    if odata_type:
        return False
    return "displayName" in item


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


def _last_signin(activity: Any) -> datetime | None:
    if not isinstance(activity, dict):
        return None
    for key in (
        "lastSuccessfulSignInDateTime",
        "lastSignInDateTime",
        "lastNonInteractiveSignInDateTime",
    ):
        parsed = _parse_dt(activity.get(key))
        if parsed is not None:
            return parsed
    return None


def list_stale_users(
    client: GraphClient,
    *,
    days: int = 90,
    user_type: str = "all",
    enabled_only: bool = False,
    scan_cap: int = USER_SCAN_MAX,
) -> dict[str, Any]:
    if days < 1:
        raise SanitizedGraphError("invalid_days", status_class="4xx")
    kind = user_type.lower()
    if kind not in {"member", "guest", "all"}:
        raise SanitizedGraphError("invalid_user_type", status_class="4xx")
    if scan_cap < 1:
        raise SanitizedGraphError("invalid_scan_cap", status_class="4xx")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    items = client.collect_page(
        "/users",
        params={"$select": ",".join(STALE_USER_FIELDS)},
        item_cap=scan_cap,
    )
    stale: list[dict[str, Any]] = []
    for item in items:
        row = project(item, STALE_USER_FIELDS)
        if "mail" in row:
            row.pop("mail", None)
        if "otherMails" in row:
            row.pop("otherMails", None)
        actual_type = str(row.get("userType") or "Member").lower()
        if kind != "all" and actual_type != kind:
            continue
        if enabled_only and not row.get("accountEnabled"):
            continue
        last = _last_signin(row.get("signInActivity"))
        if last is not None and last >= cutoff:
            continue
        row["lastSignInDateTime"] = last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None
        stale.append(row)
    return {
        "users": stale,
        "days": days,
        "user_type": kind,
        "enabled_only": enabled_only,
        "truncated": len(items) >= scan_cap,
        "scan_cap": scan_cap,
        "users_scanned": len(items),
        "never_mail": True,
    }


def check_user_in_group(client: GraphClient, user: str, group: str) -> dict[str, Any]:
    profile = client.get(
        f"/users/{encode_path_segment(user)}",
        params={"$select": "id,userPrincipalName"},
    )
    user_id = str(profile.get("id") or "")
    if not user_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    resolved = get_group(client, group)
    group_id = str(resolved.get("id") or "")
    if not group_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    path = (
        f"/users/{encode_path_segment(user_id)}"
        "/transitiveMemberOf/microsoft.graph.group"
    )
    items = client.collect_page(
        path,
        params={
            "$select": "id,displayName",
            "$count": "true",
        },
        headers=SEARCH_HEADERS,
        item_cap=TRANSITIVE_MEMBERSHIP_PAGE_CAP,
    )
    found = None
    for item in items:
        if str(item.get("id") or "") == group_id:
            found = project(item, ("id", "displayName"))
            break
    truncated = len(items) >= TRANSITIVE_MEMBERSHIP_PAGE_CAP
    is_member = found is not None
    return {
        "is_member": is_member,
        "membership": "transitive",
        "truncated": truncated,
        "authoritative": is_member or not truncated,
        "user_id": user_id,
        "group_id": group_id,
        "group_displayName": resolved.get("displayName"),
        "matched_group": found,
    }


def get_user_manager(client: GraphClient, user: str) -> dict[str, Any]:
    profile = client.get(
        f"/users/{encode_path_segment(user)}",
        params={"$select": "id,userPrincipalName"},
    )
    user_id = str(profile.get("id") or "")
    if not user_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    try:
        data = client.get(
            f"/users/{encode_path_segment(user_id)}/manager",
            params={"$select": ",".join(f for f in MANAGER_FIELDS if f != "@odata.type")},
        )
    except SanitizedGraphError as exc:
        if exc.status_class == "4xx":
            return {"manager": None, "user_id": user_id}
        raise
    return {"manager": project(data, MANAGER_FIELDS), "user_id": user_id}


def list_user_direct_reports(client: GraphClient, user: str) -> dict[str, Any]:
    profile = client.get(
        f"/users/{encode_path_segment(user)}",
        params={"$select": "id,userPrincipalName"},
    )
    user_id = str(profile.get("id") or "")
    if not user_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    items = client.collect_page(
        f"/users/{encode_path_segment(user_id)}/directReports",
        params={
            "$select": ",".join(f for f in DIRECT_REPORT_FIELDS if f != "@odata.type"),
        },
        item_cap=GROUP_MEMBERSHIP_PAGE_CAP,
    )
    return {
        "direct_reports": [project(item, DIRECT_REPORT_FIELDS) for item in items],
        "user_id": user_id,
        "truncated": len(items) >= GROUP_MEMBERSHIP_PAGE_CAP,
    }


def list_deleted_users(client: GraphClient) -> dict[str, Any]:
    items = client.collect_page(
        "/directory/deletedItems/microsoft.graph.user",
        params={"$select": ",".join(DELETED_USER_FIELDS)},
        item_cap=DELETED_USER_CAP,
    )
    return {
        "users": [project(item, DELETED_USER_FIELDS) for item in items],
        "truncated": len(items) >= DELETED_USER_CAP,
        "scan_cap": DELETED_USER_CAP,
        "note": "Deleted directory user objects only. Not proof that offboarding is complete.",
    }
