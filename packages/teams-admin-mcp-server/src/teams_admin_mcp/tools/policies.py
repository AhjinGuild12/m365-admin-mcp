"""Per-user effective Teams policy assignments. Definitions are out of scope."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.graph_client import GraphClient

from teams_admin_mcp.schemas import USER_CONFIG_SCHEMA
from teams_admin_mcp.tools._common import fetch_one, finalize, path_segment, require_guid


def get_user_teams_policy_assignments(client: GraphClient, user_id: str) -> dict[str, Any]:
    """Effective Teams policy assignments for one user object id. Global cloud only.

    A policy type absent from ``effectivePolicyAssignments`` was not returned.
    That is not proof that no policy applies. Authorization failures stay a sanitized
    ``4xx graph_error`` and are not reclassified as a cloud-capability result.
    """
    require_guid(user_id)
    segment = path_segment(user_id)
    body = fetch_one(
        client,
        f"/admin/teams/userConfigurations/{segment}",
        None,
        USER_CONFIG_SCHEMA,
        user_id,
    )
    return finalize(body)
