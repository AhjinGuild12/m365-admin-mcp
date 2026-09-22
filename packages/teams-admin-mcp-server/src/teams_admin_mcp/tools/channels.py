"""Channels and direct channel members."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient

from teams_admin_mcp.allowlist import CHANNEL_MEMBERSHIP_TYPES, COLLECTION_CAP
from teams_admin_mcp.schemas import CHANNEL_DETAIL_SCHEMA, CHANNEL_SCHEMA, MEMBER_SCHEMA
from teams_admin_mcp.tools._common import (
    clamp_top,
    classify_member_origin,
    collect_bounded,
    fetch_one,
    finalize,
    path_segment,
)

_CHANNEL_SELECT = "id,displayName,description,membershipType,isArchived,createdDateTime"


def list_channels(
    client: GraphClient,
    team: str,
    membership_type: str | None = None,
) -> dict[str, Any]:
    """Channels in a team. ``membership_type`` is standard, private, or shared."""
    if membership_type is not None and membership_type not in CHANNEL_MEMBERSHIP_TYPES:
        raise SanitizedGraphError("invalid_membership_type", status_class="4xx")
    segment = path_segment(team)
    params: dict[str, str] = {"$select": _CHANNEL_SELECT}
    if membership_type is not None:
        params["$filter"] = f"membershipType eq '{membership_type}'"
    body = collect_bounded(
        client,
        f"/teams/{segment}/channels",
        params,
        COLLECTION_CAP,
        CHANNEL_SCHEMA,
    )
    return finalize(body)


def get_channel(client: GraphClient, team: str, channel: str) -> dict[str, Any]:
    """One channel, including moderation settings."""
    team_segment = path_segment(team)
    channel_segment = path_segment(channel)
    body = fetch_one(
        client,
        f"/teams/{team_segment}/channels/{channel_segment}",
        None,
        CHANNEL_DETAIL_SCHEMA,
        channel,
    )
    return finalize(body)


def list_channel_members(
    client: GraphClient,
    team: str,
    channel: str,
    home_tenant_id: str | None,
    top: int | None = None,
) -> dict[str, Any]:
    """Direct members of the channel.

    This is not a complete effective-access audit of a shared channel.
    """
    bound = clamp_top(top)
    team_segment = path_segment(team)
    channel_segment = path_segment(channel)

    def annotate(raw: dict[str, Any], projected: dict[str, Any]) -> dict[str, Any]:
        projected = dict(projected)
        projected["member_origin"] = classify_member_origin(raw, home_tenant_id)
        return projected

    body = collect_bounded(
        client,
        f"/teams/{team_segment}/channels/{channel_segment}/members",
        {"$top": str(bound)},
        bound,
        MEMBER_SCHEMA,
        annotate=annotate,
    )
    return finalize(body)
