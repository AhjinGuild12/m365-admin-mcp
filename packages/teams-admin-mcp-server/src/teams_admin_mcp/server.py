"""MCPServer app: stdio-only, exactly the 13-tool allowlist."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.server_factory import ToolSpec, create_server, registered_tool_names, run_stdio

from teams_admin_mcp.allowlist import TOOL_NAMES
from teams_admin_mcp.tools import apps, channels, members, policies, reports, teams
from teams_admin_mcp.tools._common import finalize

_client_factory: Callable[[], GraphClient] = lambda: GraphClient(env_prefix="TEAMS_ADMIN")
_cached_client: GraphClient | None = None
_home_tenant_id: str | None = None


def home_tenant_id() -> str:
    """Read ``TEAMS_ADMIN_TENANT_ID`` once per process."""
    global _home_tenant_id
    if _home_tenant_id is None:
        _home_tenant_id = os.environ.get("TEAMS_ADMIN_TENANT_ID", "")
    return _home_tenant_id


def set_home_tenant_id(value: str | None) -> None:
    """Test hook. Pass None to read the env var again on the next call."""
    global _home_tenant_id
    _home_tenant_id = value


def get_client() -> GraphClient:
    global _cached_client
    if _cached_client is None:
        _cached_client = _client_factory()
    return _cached_client


def set_client_factory(factory: Callable[[], GraphClient] | None) -> None:
    """Test hook. Pass None to restore the default factory and drop the cache."""
    global _client_factory, _cached_client
    _cached_client = None
    _client_factory = factory or (lambda: GraphClient(env_prefix="TEAMS_ADMIN"))


def _call(fn: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return finalize(fn(get_client(), **kwargs))
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("internal_error", status_class="other") from None


def list_teams(display_name_prefix: str | None = None, top: int | None = None) -> dict[str, Any]:
    """Team-enabled groups. An optional display-name prefix is verified on returned rows."""
    return _call(teams.list_teams, display_name_prefix=display_name_prefix, top=top)


def get_team_sensitivity_labels(team: str) -> dict[str, Any]:
    """Labels assigned to the team. Group labels require Microsoft Entra ID P1.

    An empty list is verified empty. A missing property is unavailable.
    """
    return _call(teams.get_team_sensitivity_labels, team=team)


def get_team(team: str) -> dict[str, Any]:
    """One team: settings, guest settings, and membership summary."""
    return _call(teams.get_team, team=team)


def list_user_joined_teams(user: str) -> dict[str, Any]:
    """Teams the user is a direct member of. Callers pass an id or UPN."""
    return _call(teams.list_user_joined_teams, user=user)


def list_team_members(team: str, top: int | None = None) -> dict[str, Any]:
    """Direct team members. member_origin is home, external, or unknown.

    It describes where the member account is homed, not the tenant external-access policy.
    """
    return _call(members.list_team_members, team=team, home_tenant_id=home_tenant_id(), top=top)


def list_team_owners(team: str) -> dict[str, Any]:
    """Owners filtered from team members. owner_count is null when the scan is incomplete."""
    return _call(members.list_team_owners, team=team, home_tenant_id=home_tenant_id())


def list_channels(team: str, membership_type: str | None = None) -> dict[str, Any]:
    """Channels in a team. membership_type is standard, private, or shared."""
    return _call(channels.list_channels, team=team, membership_type=membership_type)


def get_channel(team: str, channel: str) -> dict[str, Any]:
    """One channel, including moderation settings."""
    return _call(channels.get_channel, team=team, channel=channel)


def list_channel_members(team: str, channel: str, top: int | None = None) -> dict[str, Any]:
    """Direct members of the channel. This is not a complete effective-access audit of a shared channel."""
    return _call(
        channels.list_channel_members,
        team=team,
        channel=channel,
        home_tenant_id=home_tenant_id(),
        top=top,
    )


def list_team_installed_apps(team: str) -> dict[str, Any]:
    """Apps installed in a team. Descriptions are omitted."""
    return _call(apps.list_team_installed_apps, team=team)


def list_org_catalog_apps(top: int | None = None) -> dict[str, Any]:
    """Organization-catalog Teams apps. top is a local cap and is never sent as $top."""
    return _call(apps.list_org_catalog_apps, top=top)


def get_user_teams_policy_assignments(user_id: str) -> dict[str, Any]:
    """Effective Teams policy assignments for one user object id. Global cloud only.

    A policy type absent from effectivePolicyAssignments was not returned.
    That is not proof that no policy applies.
    """
    return _call(policies.get_user_teams_policy_assignments, user_id=user_id)


def list_teams_team_activity(period: str) -> dict[str, Any]:
    """Team activity detail for D7, D30, D90, or D180."""
    return _call(reports.list_teams_team_activity, period=period)


_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("list_teams", list_teams, list_teams.__doc__ or ""),
    ToolSpec(
        "get_team_sensitivity_labels",
        get_team_sensitivity_labels,
        get_team_sensitivity_labels.__doc__ or "",
    ),
    ToolSpec("get_team", get_team, get_team.__doc__ or ""),
    ToolSpec("list_user_joined_teams", list_user_joined_teams, list_user_joined_teams.__doc__ or ""),
    ToolSpec("list_team_members", list_team_members, list_team_members.__doc__ or ""),
    ToolSpec("list_team_owners", list_team_owners, list_team_owners.__doc__ or ""),
    ToolSpec("list_channels", list_channels, list_channels.__doc__ or ""),
    ToolSpec("get_channel", get_channel, get_channel.__doc__ or ""),
    ToolSpec("list_channel_members", list_channel_members, list_channel_members.__doc__ or ""),
    ToolSpec("list_team_installed_apps", list_team_installed_apps, list_team_installed_apps.__doc__ or ""),
    ToolSpec("list_org_catalog_apps", list_org_catalog_apps, list_org_catalog_apps.__doc__ or ""),
    ToolSpec(
        "get_user_teams_policy_assignments",
        get_user_teams_policy_assignments,
        get_user_teams_policy_assignments.__doc__ or "",
    ),
    ToolSpec("list_teams_team_activity", list_teams_team_activity, list_teams_team_activity.__doc__ or ""),
)

mcp = create_server("teams-admin-ro", _TOOLS, declared_names=TOOL_NAMES)


def advertised_tool_names() -> tuple[str, ...]:
    return registered_tool_names(mcp)


def main() -> None:
    run_stdio(mcp)
