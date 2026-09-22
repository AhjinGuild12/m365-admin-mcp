"""Group lookup, search, and direct members (service principals omitted)."""

from __future__ import annotations

import re
from typing import Any

from entra_mcp.allowlist import (
    DEFAULT_SEARCH_TOP,
    DYNAMIC_GROUP_FIELDS,
    GROUP_FIELDS,
    MAX_SEARCH_TOP,
    MEMBER_FIELDS,
    MEMBER_PAGE_CAP,
    OWNER_FIELDS,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, project_list
from entra_mcp.graph_client import (
    GraphClient,
    build_search_clause,
    encode_path_segment,
    odata_eq,
)

SEARCH_HEADERS = {"ConsistencyLevel": "eventual"}
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SP_TYPE_SUFFIX = "servicePrincipal"


def _clamp_top(top: int | None) -> int:
    if top is None:
        return DEFAULT_SEARCH_TOP
    if top < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    return min(top, MAX_SEARCH_TOP)


def get_group(client: GraphClient, group: str) -> dict[str, Any]:
    if _GUID.match(group):
        path = f"/groups/{encode_path_segment(group)}"
        data = client.get(path, params={"$select": ",".join(GROUP_FIELDS)})
        return project(data, GROUP_FIELDS)
    items = client.collect_page(
        "/groups",
        params={
            "$filter": odata_eq("displayName", group),
            "$select": ",".join(GROUP_FIELDS),
            "$top": "5",
        },
        item_cap=5,
    )
    projected = project_list(items, GROUP_FIELDS)
    if not projected:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    if len(projected) > 1:
        raise SanitizedGraphError("multiple_matches", status_class="4xx")
    return projected[0]


def search_groups(client: GraphClient, query: str, top: int | None = None) -> dict[str, Any]:
    bound = _clamp_top(top)
    items = client.collect_page(
        "/groups",
        params={
            "$search": build_search_clause("displayName", query),
            "$select": ",".join(GROUP_FIELDS),
            "$top": str(bound),
            "$count": "true",
        },
        headers=SEARCH_HEADERS,
        item_cap=bound,
    )
    return {"groups": project_list(items, GROUP_FIELDS)}


def list_group_members(client: GraphClient, group: str) -> dict[str, Any]:
    resolved = get_group(client, group)
    group_id = resolved["id"]
    path = f"/groups/{encode_path_segment(group_id)}/members"
    items = client.collect_page(
        path,
        params={"$select": ",".join(f for f in MEMBER_FIELDS if f != "@odata.type") + ",id"},
        item_cap=MEMBER_PAGE_CAP,
    )
    members = []
    for item in items:
        odata_type = str(item.get("@odata.type", ""))
        if odata_type.endswith(_SP_TYPE_SUFFIX):
            continue
        members.append(project(item, MEMBER_FIELDS))
    return {
        "members": members,
        "service_principals_omitted": True,
        "membership": "direct",
    }


def list_group_owners(client: GraphClient, group: str) -> dict[str, Any]:
    resolved = get_group(client, group)
    group_id = resolved["id"]
    path = f"/groups/{encode_path_segment(group_id)}/owners"
    items = client.collect_page(
        path,
        params={"$select": ",".join(f for f in OWNER_FIELDS if f != "@odata.type")},
        item_cap=MEMBER_PAGE_CAP,
    )
    owners = [project(item, OWNER_FIELDS) for item in items]
    return {
        "owners": owners,
        "group_id": group_id,
        "displayName": resolved.get("displayName"),
        "ownerless": len(owners) == 0,
        "inventory": "visible_graph_v1",
        "note": (
            "Owners visible through Graph v1.0 only. v1.0 currently omits "
            "service-principal owners and owners are unavailable for some "
            "Exchange-created, distribution, or on-prem-synced groups."
        ),
    }


def list_dynamic_groups(client: GraphClient, top: int | None = None) -> dict[str, Any]:
    bound = _clamp_top(top)
    items = client.collect_page(
        "/groups",
        params={
            "$filter": "groupTypes/any(g:g eq 'DynamicMembership')",
            "$select": ",".join(DYNAMIC_GROUP_FIELDS),
            "$count": "true",
            "$top": str(bound),
        },
        headers=SEARCH_HEADERS,
        item_cap=bound,
    )
    return {
        "groups": project_list(items, DYNAMIC_GROUP_FIELDS),
        "truncated": len(items) >= bound,
    }
