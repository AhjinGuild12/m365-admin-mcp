"""MCPServer app: stdio-only, exactly the seven P0 tools."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.server_factory import ToolSpec, create_server, registered_tool_names, run_stdio

from spo_admin_mcp.allowlist import TOOL_NAMES
from spo_admin_mcp.tools import site_usage, tenant_settings

_client_factory: Callable[[], GraphClient] = lambda: GraphClient(env_prefix="SPO_ADMIN")
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
    _client_factory = factory or (lambda: GraphClient(env_prefix="SPO_ADMIN"))


def _call(fn: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return fn(get_client(), **kwargs)
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("internal_error", status_class="other") from None


def get_tenant_sharing_settings() -> dict[str, Any]:
    """Tenant sharing posture from /admin/sharepoint/settings. Vanta external-sharing evidence is tenant-level."""
    return _call(tenant_settings.get_tenant_sharing_settings)


def get_tenant_access_settings() -> dict[str, Any]:
    """Legacy auth, sync-app restriction, and idle-session sign-out."""
    return _call(tenant_settings.get_tenant_access_settings)


def get_tenant_site_creation_settings() -> dict[str, Any]:
    """Site-creation and storage-limit settings."""
    return _call(tenant_settings.get_tenant_site_creation_settings)


def get_tenant_settings() -> dict[str, Any]:
    """All 29 documented v1.0 sharepointSettings properties."""
    return _call(tenant_settings.get_tenant_settings)


def list_site_usage(period: str) -> dict[str, Any]:
    """SharePoint site-usage detail for D7, D30, D90, or D180. Page-view columns are omitted."""
    return _call(site_usage.list_site_usage, period=period)


def get_site_usage(site: str, period: str) -> dict[str, Any]:
    """One usage row by exact site URL or site id.

    A capped scan that has not reached the target returns status=incomplete.
    Duplicate normalized URLs return status=ambiguous.
    A person or display-name target on a concealed report returns status=identity_unresolvable.
    """
    return _call(site_usage.get_site_usage, site=site, period=period)


def get_site_usage_summary(period: str) -> dict[str, Any]:
    """Storage and site-count summaries for one period, merged by Report Date."""
    return _call(site_usage.get_site_usage_summary, period=period)


_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_tenant_sharing_settings",
        get_tenant_sharing_settings,
        get_tenant_sharing_settings.__doc__ or "",
    ),
    ToolSpec(
        "get_tenant_access_settings",
        get_tenant_access_settings,
        get_tenant_access_settings.__doc__ or "",
    ),
    ToolSpec(
        "get_tenant_site_creation_settings",
        get_tenant_site_creation_settings,
        get_tenant_site_creation_settings.__doc__ or "",
    ),
    ToolSpec("get_tenant_settings", get_tenant_settings, get_tenant_settings.__doc__ or ""),
    ToolSpec("list_site_usage", list_site_usage, list_site_usage.__doc__ or ""),
    ToolSpec("get_site_usage", get_site_usage, get_site_usage.__doc__ or ""),
    ToolSpec("get_site_usage_summary", get_site_usage_summary, get_site_usage_summary.__doc__ or ""),
)

mcp = create_server("spo-admin-ro", _TOOLS, declared_names=TOOL_NAMES)


def advertised_tool_names() -> tuple[str, ...]:
    return registered_tool_names(mcp)


def main() -> None:
    run_stdio(mcp)
