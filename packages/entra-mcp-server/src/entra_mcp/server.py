"""MCPServer app: stdio-only, exactly the R5 tool allowlist."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer

from entra_mcp.allowlist import TOOL_NAMES
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.graph_client import GraphClient
from entra_mcp.tools import (
    apps,
    audits,
    devices,
    groups,
    licenses,
    org,
    policies,
    roles,
    signins,
    users,
)

mcp = MCPServer("entra-ro", version="0.1.0")

_client_factory: Callable[[], GraphClient] = GraphClient
_cached_client: GraphClient | None = None


def get_client() -> GraphClient:
    global _cached_client
    if _cached_client is None:
        _cached_client = _client_factory()
    return _cached_client


def set_client_factory(factory: Callable[[], GraphClient] | None) -> None:
    """Test hook. Pass None to restore the default factory and drop the cache."""
    global _client_factory, _cached_client
    _cached_client = None
    _client_factory = factory or GraphClient


def registered_tool_names() -> tuple[str, ...]:
    # MCPServer.list_tools() is async in mcp 2.x; ToolManager is the sync registry.
    return tuple(tool.name for tool in mcp._tool_manager.list_tools())


def _call(fn: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return fn(get_client(), **kwargs)
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("internal_error", status_class="other") from None


@mcp.tool()
def get_user(user: str) -> dict[str, Any]:
    """One user's profile core fields, by UPN or object id."""
    return _call(users.get_user, user=user)


@mcp.tool()
def search_users(query: str, top: int | None = None) -> dict[str, Any]:
    """Users matching a name or UPN query, bounded."""
    return _call(users.search_users, query=query, top=top)


@mcp.tool()
def list_user_groups(user: str) -> dict[str, Any]:
    """A user's direct group memberships (memberOf, not transitive)."""
    return _call(users.list_user_groups, user=user)


@mcp.tool()
def list_stale_users(
    days: int = 90,
    user_type: str = "all",
    enabled_only: bool = False,
) -> dict[str, Any]:
    """Users with no recent sign-in (client-side scan). Never returns mail."""
    return _call(
        users.list_stale_users,
        days=days,
        user_type=user_type,
        enabled_only=enabled_only,
    )


@mcp.tool()
def check_user_in_group(user: str, group: str) -> dict[str, Any]:
    """Transitive group membership. A truncated miss is not authoritative."""
    return _call(users.check_user_in_group, user=user, group=group)


@mcp.tool()
def get_user_manager(user: str) -> dict[str, Any]:
    """A user's manager, or manager null when unset."""
    return _call(users.get_user_manager, user=user)


@mcp.tool()
def list_user_direct_reports(user: str) -> dict[str, Any]:
    """A user's directReports. Preserves @odata.type."""
    return _call(users.list_user_direct_reports, user=user)


@mcp.tool()
def get_group(group: str) -> dict[str, Any]:
    """One group's core fields, by object id or display name."""
    return _call(groups.get_group, group=group)


@mcp.tool()
def list_group_members(group: str) -> dict[str, Any]:
    """A group's direct members, bounded. Service principals are omitted in Graph v1.0."""
    return _call(groups.list_group_members, group=group)


@mcp.tool()
def search_groups(query: str, top: int | None = None) -> dict[str, Any]:
    """Groups matching a display-name query, bounded."""
    return _call(groups.search_groups, query=query, top=top)


@mcp.tool()
def list_group_owners(group: str) -> dict[str, Any]:
    """Owners visible through Graph v1.0. Not a complete owner inventory."""
    return _call(groups.list_group_owners, group=group)


@mcp.tool()
def list_dynamic_groups(top: int | None = None) -> dict[str, Any]:
    """Groups with DynamicMembership. Returns membershipRule as Graph sends it."""
    return _call(groups.list_dynamic_groups, top=top)


@mcp.tool()
def get_device(device: str) -> dict[str, Any]:
    """One device's core fields, by object id or display name."""
    return _call(devices.get_device, device=device)


@mcp.tool()
def search_devices(query: str, top: int | None = None) -> dict[str, Any]:
    """Devices matching a display-name query, bounded."""
    return _call(devices.search_devices, query=query, top=top)


@mcp.tool()
def list_user_devices(user: str) -> dict[str, Any]:
    """Devices whose registered owner or registered user is the user.

    App-only cannot read /users/{id}/registeredDevices. Completeness is within
    Graph's 20-object expand cap per relationship per device.
    """
    return _call(devices.list_user_devices, user=user)


@mcp.tool()
def list_user_signins(
    user: str,
    days: int = 1,
    top: int | None = None,
    app_id: str | None = None,
    include_ca_result: bool = False,
) -> dict[str, Any]:
    """A user's interactive sign-ins in a UTC day window. Optional app_id limits to interactive user sign-ins to that app. include_ca_result adds applied CA policies. No IP or location fields."""
    return _call(
        signins.list_user_signins,
        user=user,
        days=days,
        top=top,
        app_id=app_id,
        include_ca_result=include_ca_result,
    )


@mcp.tool()
def list_recent_signins(
    days: int = 1,
    top: int | None = None,
    app_id: str | None = None,
    include_ca_result: bool = False,
) -> dict[str, Any]:
    """Tenant interactive sign-ins in a UTC day window. Optional app_id limits to interactive user sign-ins to that app. include_ca_result adds applied CA policies. No IP or location fields."""
    return _call(
        signins.list_recent_signins,
        days=days,
        top=top,
        app_id=app_id,
        include_ca_result=include_ca_result,
    )


@mcp.tool()
def get_signin(signin_id: str, include_ca_result: bool = False) -> dict[str, Any]:
    """One interactive sign-in by id. No IP or location fields. CA policy detail is omitted unless include_ca_result is true."""
    return _call(signins.get_signin, signin_id=signin_id, include_ca_result=include_ca_result)


@mcp.tool()
def get_org_info() -> dict[str, Any]:
    """Tenant organization display info, hybrid sync timestamps, and groupSettings."""
    return _call(org.get_org_info)


@mcp.tool()
def list_subscribed_skus() -> dict[str, Any]:
    """Tenant subscribed SKUs with consumed vs prepaid units."""
    return _call(licenses.list_subscribed_skus)


@mcp.tool()
def get_user_licenses(user: str) -> dict[str, Any]:
    """A user's license details, accountEnabled, and licenseAssignmentStates errors."""
    return _call(licenses.get_user_licenses, user=user)


@mcp.tool()
def list_users_by_sku(sku: str, enabled_only: bool = False) -> dict[str, Any]:
    """Users assigned a SKU (skuId or skuPartNumber). The reclaim list."""
    return _call(licenses.list_users_by_sku, sku=sku, enabled_only=enabled_only)


@mcp.tool()
def list_license_groups() -> dict[str, Any]:
    """Groups with assigned licenses, including licenseProcessingState."""
    return _call(licenses.list_license_groups)


@mcp.tool()
def list_directory_role_members(
    role: str | None = None,
    all_roles: bool = False,
) -> dict[str, Any]:
    """Active direct directory-role members only. For PIM-activated and group-assigned principals use list_pim_active_roles."""
    return _call(roles.list_directory_role_members, role=role, all_roles=all_roles)


@mcp.tool()
def list_directory_audits(
    days: int = 1,
    top: int | None = None,
    category: str | None = None,
    target_id: str | None = None,
    activity_display_name: str | None = None,
) -> dict[str, Any]:
    """Directory audit events in a UTC day window. category RoleManagement is the read-only PIM activation evidence path. No IP or location fields."""
    return _call(
        audits.list_directory_audits,
        days=days,
        top=top,
        category=category,
        target_id=target_id,
        activity_display_name=activity_display_name,
    )


@mcp.tool()
def search_service_principals(query: str, top: int | None = None) -> dict[str, Any]:
    """Service principals whose displayName starts with query, bounded."""
    return _call(apps.search_service_principals, query=query, top=top)


@mcp.tool()
def get_service_principal(service_principal: str) -> dict[str, Any]:
    """One service principal, grants, app-role assignments, and credential metadata. Secrets are stripped."""
    return _call(apps.get_service_principal, service_principal=service_principal)


@mcp.tool()
def list_expiring_app_credentials(within_days: int = 90) -> dict[str, Any]:
    """App-registration credentials expiring within N days. Metadata only; secrets stripped."""
    return _call(apps.list_expiring_app_credentials, within_days=within_days)


@mcp.tool()
def list_user_app_assignments(user: str) -> dict[str, Any]:
    """Enterprise-app role assignments for a user."""
    return _call(apps.list_user_app_assignments, user=user)


@mcp.tool()
def list_tenant_wide_consents() -> dict[str, Any]:
    """AllPrincipals oauth2PermissionGrants. clientId is the client SP object id."""
    return _call(apps.list_tenant_wide_consents)


@mcp.tool()
def list_conditional_access_policies(state: str = "all") -> dict[str, Any]:
    """Conditional Access policies. GUIDs are returned as-is; see resolve_hint."""
    return _call(policies.list_conditional_access_policies, state=state)


@mcp.tool()
def get_conditional_access_policy(policy_id: str) -> dict[str, Any]:
    """One Conditional Access policy by id, same field projection as the list."""
    return _call(policies.get_conditional_access_policy, policy_id=policy_id)


@mcp.tool()
def list_named_locations() -> dict[str, Any]:
    """Named locations. IP ranges are policy configuration, not user sign-in telemetry."""
    return _call(policies.list_named_locations)


@mcp.tool()
def list_authentication_strengths() -> dict[str, Any]:
    """Authentication strength policies used by Conditional Access grant controls."""
    return _call(policies.list_authentication_strengths)


@mcp.tool()
def get_tenant_security_settings() -> dict[str, Any]:
    """Security defaults, authorization policy, and admin consent request policy. Partial subcall errors stay visible."""
    return _call(policies.get_tenant_security_settings)


@mcp.tool()
def get_authentication_methods_policy() -> dict[str, Any]:
    """Tenant authentication-methods policy. Not per-user methods."""
    return _call(policies.get_authentication_methods_policy)


@mcp.tool()
def get_cross_tenant_access_policy() -> dict[str, Any]:
    """Cross-tenant access base, default, and partner configurations."""
    return _call(policies.get_cross_tenant_access_policy)


@mcp.tool()
def list_pim_eligible_roles(role: str | None = None) -> dict[str, Any]:
    """PIM eligible role assignments. Requires Entra ID P2 or ID Governance and RoleManagement.Read.Directory."""
    return _call(roles.list_pim_eligible_roles, role=role)


@mcp.tool()
def list_pim_active_roles(role: str | None = None) -> dict[str, Any]:
    """Active PIM assignment principals, including group principals. Does not expand users inside a role-assigned group."""
    return _call(roles.list_pim_active_roles, role=role)


@mcp.tool()
def list_pim_role_settings(role: str | None = None) -> dict[str, Any]:
    """PIM role-management policy rules: MFA, approval, duration, justification."""
    return _call(roles.list_pim_role_settings, role=role)


@mcp.tool()
def list_domains() -> dict[str, Any]:
    """Verified and unverified tenant domains."""
    return _call(org.list_domains)


@mcp.tool()
def list_deleted_users() -> dict[str, Any]:
    """Soft-deleted directory users. Not an offboarding-completeness report."""
    return _call(users.list_deleted_users)


def assert_allowlist() -> None:
    names = registered_tool_names()
    if frozenset(names) != frozenset(TOOL_NAMES):
        raise RuntimeError("tool allowlist mismatch")


assert_allowlist()
