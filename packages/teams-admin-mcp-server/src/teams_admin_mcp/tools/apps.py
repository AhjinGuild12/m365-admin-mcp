"""Installed team apps and the organization app catalog."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.graph_client import GraphClient

from teams_admin_mcp.allowlist import COLLECTION_CAP
from teams_admin_mcp.schemas import CATALOG_APP_SCHEMA, INSTALLED_APP_SCHEMA
from teams_admin_mcp.tools._common import clamp_top, collect_bounded, finalize, path_segment

_ORG_FILTER = "distributionMethod eq 'organization'"


def list_team_installed_apps(client: GraphClient, team: str) -> dict[str, Any]:
    """Apps installed in a team. Descriptions are omitted."""
    segment = path_segment(team)
    body = collect_bounded(
        client,
        f"/teams/{segment}/installedApps",
        {"$expand": "teamsAppDefinition"},
        COLLECTION_CAP,
        INSTALLED_APP_SCHEMA,
    )
    return finalize(body)


def list_org_catalog_apps(client: GraphClient, top: int | None = None) -> dict[str, Any]:
    """Organization-catalog Teams apps. ``top`` is a local output cap and is never sent as ``$top``."""
    bound = clamp_top(top)
    body = collect_bounded(
        client,
        "/appCatalogs/teamsApps",
        {"$filter": _ORG_FILTER, "$expand": "appDefinitions"},
        bound,
        CATALOG_APP_SCHEMA,
    )
    return finalize(body)
