"""Team inventory, settings, assigned labels, and joined teams."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient, escape_odata_string

from teams_admin_mcp.allowlist import COLLECTION_CAP, TEAMS_LIST_FILTER
from teams_admin_mcp.schemas import JOINED_TEAM_SCHEMA, LABEL_SCHEMA, TEAM_LIST_SCHEMA, TEAM_SCHEMA
from teams_admin_mcp.tools._common import clamp_top, collect_bounded, fetch_one, finalize, path_segment

_TEAM_SELECT = "id,displayName,description,visibility,createdDateTime"
_LABEL_SELECT = "id,displayName,assignedLabels,classification,visibility"


def list_teams(
    client: GraphClient,
    display_name_prefix: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """Team-enabled groups. An optional display-name prefix is verified on returned rows."""
    bound = clamp_top(top)
    filt = TEAMS_LIST_FILTER
    if display_name_prefix is not None:
        if not isinstance(display_name_prefix, str) or display_name_prefix == "":
            raise SanitizedGraphError("invalid_prefix", status_class="4xx")
        escaped = escape_odata_string(display_name_prefix)
        filt = f"{TEAMS_LIST_FILTER} and startswith(displayName,'{escaped}')"
    params = {"$filter": filt, "$select": _TEAM_SELECT, "$top": str(bound)}
    body = collect_bounded(client, "/groups", params, bound, TEAM_LIST_SCHEMA)
    if display_name_prefix is None:
        body["filter_verified"] = True
    else:
        needle = display_name_prefix.casefold()
        kept: list[dict[str, Any]] = []
        verified = True
        for row in body["items"]:
            name = row.get("displayName")
            if isinstance(name, str) and name.casefold().startswith(needle):
                kept.append(row)
            else:
                verified = False
        body["items"] = kept
        body["filter_verified"] = verified
    return finalize(body)


def get_team(client: GraphClient, team: str) -> dict[str, Any]:
    """One team: settings, guest settings, and membership summary."""
    segment = path_segment(team)
    body = fetch_one(client, f"/teams/{segment}", None, TEAM_SCHEMA, team)
    return finalize(body)


def get_team_sensitivity_labels(client: GraphClient, team: str) -> dict[str, Any]:
    """Labels assigned to the team. Group labels require Microsoft Entra ID P1.

    ``assignedLabels: []`` with ``labels_status: empty`` means the property was present and empty.
    ``assignedLabels: null`` with ``labels_status: unavailable`` means the property was absent.
    """
    segment = path_segment(team)
    body = fetch_one(
        client,
        f"/groups/{segment}",
        {"$select": _LABEL_SELECT},
        LABEL_SCHEMA,
        team,
    )
    if "assignedLabels" not in body:
        body["assignedLabels"] = None
        body["labels_status"] = "unavailable"
    elif body["assignedLabels"] == []:
        body["labels_status"] = "empty"
    else:
        body["labels_status"] = "present"
    return finalize(body)


def list_user_joined_teams(client: GraphClient, user: str) -> dict[str, Any]:
    """Teams the user is a direct member of. Callers pass an id or UPN."""
    segment = path_segment(user)
    body = collect_bounded(
        client,
        f"/users/{segment}/joinedTeams",
        None,
        COLLECTION_CAP,
        JOINED_TEAM_SCHEMA,
    )
    return finalize(body)
