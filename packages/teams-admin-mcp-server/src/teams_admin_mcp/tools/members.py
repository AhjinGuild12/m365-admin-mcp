"""Team membership and owners. ``member_origin`` is computed locally, then tenant ids are stripped."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.graph_client import GraphClient

from teams_admin_mcp.allowlist import OWNER_PAGE_TOP, OWNER_SCAN_CAP
from teams_admin_mcp.schemas import MEMBER_SCHEMA
from teams_admin_mcp.tools._common import (
    clamp_top,
    classify_member_origin,
    collect_bounded,
    finalize,
    path_segment,
)


def _annotate(home_tenant_id: str | None):
    def annotate(raw: dict[str, Any], projected: dict[str, Any]) -> dict[str, Any]:
        projected = dict(projected)
        projected["member_origin"] = classify_member_origin(raw, home_tenant_id)
        return projected

    return annotate


def list_team_members(
    client: GraphClient,
    team: str,
    home_tenant_id: str | None,
    top: int | None = None,
) -> dict[str, Any]:
    """Direct team members. ``member_origin`` is home, external, or unknown.

    It describes where the member account is homed, not the tenant external-access policy.
    """
    bound = clamp_top(top)
    segment = path_segment(team)
    body = collect_bounded(
        client,
        f"/teams/{segment}/members",
        {"$top": str(bound)},
        bound,
        MEMBER_SCHEMA,
        annotate=_annotate(home_tenant_id),
    )
    return finalize(body)


def _is_owner(raw: dict[str, Any]) -> bool:
    roles = raw.get("roles")
    if not isinstance(roles, list):
        return False
    return any(isinstance(role, str) and role == "owner" for role in roles)


def list_team_owners(
    client: GraphClient,
    team: str,
    home_tenant_id: str | None,
) -> dict[str, Any]:
    """Owners filtered from team members. ``owner_count`` is null when the scan is incomplete."""
    segment = path_segment(team)
    body = collect_bounded(
        client,
        f"/teams/{segment}/members",
        {"$top": str(OWNER_PAGE_TOP)},
        OWNER_SCAN_CAP,
        MEMBER_SCHEMA,
        keep=_is_owner,
        annotate=_annotate(home_tenant_id),
    )
    body["owner_count"] = len(body["items"]) if body["complete"] else None
    return finalize(body)
