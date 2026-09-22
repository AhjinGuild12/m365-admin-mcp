"""Room and room-list reads on Microsoft Graph v1.0 Places."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient

from exchange_admin_mcp.schemas import ROOM_LIST_SCHEMA, ROOM_SCHEMA
from exchange_admin_mcp.tools._common import (
    clamp_top,
    collect_bounded,
    fetch_one,
    finalize,
    path_segment,
)


def list_rooms(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    """Rooms from Places. Calendar availability is not included."""
    bound = clamp_top(top)
    path = "/places/microsoft.graph.room"
    return finalize(collect_bounded(client, path, {"$top": str(bound)}, bound, ROOM_SCHEMA))


def list_room_lists(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    """Room lists from Places. Membership is a distribution group, not this call."""
    bound = clamp_top(top)
    path = "/places/microsoft.graph.roomList"
    return finalize(
        collect_bounded(client, path, {"$top": str(bound)}, bound, ROOM_LIST_SCHEMA)
    )


def list_rooms_in_room_list(
    client: GraphClient, *, room_list: str, top: int | None = None
) -> dict[str, Any]:
    """Rooms in one room list. ``room_list`` is the list's email address."""
    bound = clamp_top(top)
    email = path_segment(room_list)
    path = f"/places/{email}/microsoft.graph.roomList/rooms"
    return finalize(collect_bounded(client, path, {"$top": str(bound)}, bound, ROOM_SCHEMA))


def get_room(client: GraphClient, *, room_id: str) -> dict[str, Any]:
    """One room by its Places id."""
    if not isinstance(room_id, str) or room_id == "" or "/" in room_id or "?" in room_id:
        raise SanitizedGraphError("invalid_path_segment", status_class="4xx")
    path = f"/places/{path_segment(room_id)}"
    return finalize(fetch_one(client, path, None, ROOM_SCHEMA, room_id))
