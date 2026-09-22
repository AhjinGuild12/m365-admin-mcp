"""Device lookup, search, and reverse-traversal list_user_devices (KTD11)."""

from __future__ import annotations

import re
from typing import Any

from entra_mcp.allowlist import (
    DEFAULT_SEARCH_TOP,
    DEVICE_FIELDS,
    DEVICE_SCAN_MAX,
    MAX_SEARCH_TOP,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, project_list
from entra_mcp.graph_client import GraphClient, build_search_clause, encode_path_segment

SEARCH_HEADERS = {"ConsistencyLevel": "eventual"}
_OWNER_USER_SELECT = "id"
_EXPAND_BOTH = "registeredOwners,registeredUsers"
_EXPAND_OWNERS = "registeredOwners"
_EXPAND_USERS = "registeredUsers"
_RELATIONSHIP_OBJECT_CAP = 20


def _clamp_top(top: int | None) -> int:
    if top is None:
        return DEFAULT_SEARCH_TOP
    if top < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    return min(top, MAX_SEARCH_TOP)


def get_device(client: GraphClient, device: str) -> dict[str, Any]:
    path = f"/devices/{encode_path_segment(device)}"
    try:
        data = client.get(path, params={"$select": ",".join(DEVICE_FIELDS)})
        return project(data, DEVICE_FIELDS)
    except SanitizedGraphError:
        items = client.collect_page(
            "/devices",
            params={
                "$search": build_search_clause("displayName", device),
                "$select": ",".join(DEVICE_FIELDS),
                "$top": "5",
                "$count": "true",
            },
            headers=SEARCH_HEADERS,
            item_cap=5,
        )
        projected = project_list(items, DEVICE_FIELDS)
        if not projected:
            raise SanitizedGraphError("4xx graph_error", status_class="4xx") from None
        if len(projected) > 1:
            raise SanitizedGraphError("multiple_matches", status_class="4xx") from None
        return projected[0]


def search_devices(client: GraphClient, query: str, top: int | None = None) -> dict[str, Any]:
    bound = _clamp_top(top)
    items = client.collect_page(
        "/devices",
        params={
            "$search": build_search_clause("displayName", query),
            "$select": ",".join(DEVICE_FIELDS),
            "$top": str(bound),
            "$count": "true",
        },
        headers=SEARCH_HEADERS,
        item_cap=bound,
    )
    return {"devices": project_list(items, DEVICE_FIELDS)}


def _principal_ids(values: Any) -> set[str]:
    ids: set[str] = set()
    if not values:
        return ids
    for item in values:
        if isinstance(item, dict) and item.get("id"):
            ids.add(str(item["id"]))
    return ids


def _user_matches_device(device: dict[str, Any], user_id: str) -> bool:
    owners = _principal_ids(device.get("registeredOwners"))
    users = _principal_ids(device.get("registeredUsers"))
    return user_id in owners or user_id in users


def _looks_like_object_id(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


def _resolve_user_id(client: GraphClient, user: str) -> str:
    path = f"/users/{encode_path_segment(user)}"
    try:
        data = client.get(path, params={"$select": "id"})
        user_id = data.get("id")
        if user_id:
            return str(user_id)
    except SanitizedGraphError as exc:
        # Stage-2 probe passes the app's service-principal object id (not a user).
        if exc.status_class == "4xx" and _looks_like_object_id(user):
            return user
        raise
    if _looks_like_object_id(user):
        return user
    raise SanitizedGraphError("4xx graph_error", status_class="4xx")


def _scan_devices(
    client: GraphClient,
    *,
    expand: str,
    user_id: str,
    scan_cap: int,
    already_scanned: int,
    matched: list[dict[str, Any]],
    seen_ids: set[str],
) -> tuple[int, str | None]:
    """Scan /devices with one expand. Returns (scanned_delta, fail_reason)."""
    scanned = 0
    params = {
        "$select": ",".join(DEVICE_FIELDS),
        "$expand": f"{expand}($select={_OWNER_USER_SELECT})",
    }
    try:
        for device in client.iter_pages("/devices", params=params, item_cap=scan_cap - already_scanned):
            scanned += 1
            device_id = str(device.get("id") or "")
            if device_id and device_id not in seen_ids and _user_matches_device(device, user_id):
                matched.append(project(device, DEVICE_FIELDS))
                if device_id:
                    seen_ids.add(device_id)
            if already_scanned + scanned >= scan_cap:
                return scanned, "scan_cap"
    except SanitizedGraphError as exc:
        if exc.message.endswith("retries_exhausted") or "retries_exhausted" in exc.message:
            return scanned, "throttling_exhausted"
        return scanned, "page_error"
    return scanned, None


def list_user_devices(
    client: GraphClient,
    user: str,
    *,
    scan_cap: int = DEVICE_SCAN_MAX,
) -> dict[str, Any]:
    """Reverse traversal from /devices. App-only cannot read /users/{id}/registeredDevices."""
    user_id = _resolve_user_id(client, user)
    matched: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    reason: str | None = None
    scanned = 0
    used_two_pass = False

    params_both = {
        "$select": ",".join(DEVICE_FIELDS),
        "$expand": _EXPAND_BOTH,
    }

    try:
        for device in client.iter_pages("/devices", params=params_both, item_cap=scan_cap):
            scanned += 1
            if _user_matches_device(device, user_id):
                matched.append(project(device, DEVICE_FIELDS))
            if scanned >= scan_cap:
                reason = "scan_cap"
                break
    except SanitizedGraphError as exc:
        if "retries_exhausted" in exc.message:
            reason = "throttling_exhausted"
        elif scanned == 0 and exc.status_class == "4xx":
            used_two_pass = True
            delta, reason = _scan_devices(
                client,
                expand=_EXPAND_OWNERS,
                user_id=user_id,
                scan_cap=scan_cap,
                already_scanned=0,
                matched=matched,
                seen_ids=seen_ids,
            )
            scanned += delta
            if reason is None:
                delta2, reason = _scan_devices(
                    client,
                    expand=_EXPAND_USERS,
                    user_id=user_id,
                    scan_cap=scan_cap,
                    already_scanned=scanned,
                    matched=matched,
                    seen_ids=seen_ids,
                )
                scanned += delta2
        else:
            reason = "page_error"

    complete = reason is None
    result: dict[str, Any] = {
        "devices": matched,
        "complete": complete,
        "devices_scanned": scanned,
        "scan_cap": scan_cap,
        "relationship_object_cap": _RELATIONSHIP_OBJECT_CAP,
        "user_id": user_id,
    }
    if reason:
        result["reason"] = reason
    if used_two_pass:
        result["expand_mode"] = "two_pass"
    else:
        result["expand_mode"] = "dual"
    return result
