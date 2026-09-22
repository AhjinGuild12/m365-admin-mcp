"""MCPServer app: stdio-only, exactly the R5/R10 tool allowlist via kernel factory."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.server_factory import ToolSpec, create_server, registered_tool_names, run_stdio

from intune_mcp.allowlist import DEFAULT_TOP, TOOL_NAMES
from intune_mcp.tools import apps, audit, devices, overview, policies

INTUNE_MISSING_RETRY_AFTER_SECONDS = 5.0

_client_factory: Callable[[], GraphClient] = lambda: GraphClient(
    env_prefix="INTUNE",
    missing_retry_after_seconds=INTUNE_MISSING_RETRY_AFTER_SECONDS,
)
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
    _client_factory = factory or (
        lambda: GraphClient(
            env_prefix="INTUNE",
            missing_retry_after_seconds=INTUNE_MISSING_RETRY_AFTER_SECONDS,
        )
    )


def _call(fn: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return fn(get_client(), **kwargs)
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("internal_error", status_class="other") from None


def get_intune_overview() -> dict[str, Any]:
    """Tenant Intune managed-device overview (enrolled counts by OS). Live-gate baseline read."""
    return _call(overview.get_intune_overview)


def list_managed_devices(
    operating_system: str | None = None,
    compliance_state: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """Bounded managed-device list. Optional operatingSystem / complianceState equality filters.

    Filter results are verified on returned rows only; that is not proof of server-side filtering.
    """
    return _call(
        devices.list_managed_devices,
        operating_system=operating_system,
        compliance_state=compliance_state,
        top=top if top is not None else DEFAULT_TOP,
    )


def get_managed_device(
    device_id: str | None = None,
    serial_number: str | None = None,
    device_name: str | None = None,
) -> dict[str, Any]:
    """One managed device by Intune id, or exact serialNumber / deviceName with unique resolution.

    Duplicates return status=ambiguous; an unfinished scan returns status=incomplete.
    Never returns the first match as authoritative.
    """
    return _call(
        devices.get_managed_device,
        device_id=device_id,
        serial_number=serial_number,
        device_name=device_name,
    )


def search_managed_devices(
    device_name_prefix: str | None = None,
    user_principal_name: str | None = None,
    serial_number: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """Search managed devices by startswith(deviceName) or exact UPN / serialNumber. Bounded."""
    return _call(
        devices.search_managed_devices,
        device_name_prefix=device_name_prefix,
        user_principal_name=user_principal_name,
        serial_number=serial_number,
        top=top if top is not None else DEFAULT_TOP,
    )


def list_noncompliant_devices(top: int | None = None) -> dict[str, Any]:
    """Managed devices with complianceState eq 'noncompliant'. Bounded."""
    return _call(devices.list_noncompliant_devices, top=top if top is not None else DEFAULT_TOP)


def list_detected_apps(name_prefix: str | None = None, top: int | None = None) -> dict[str, Any]:
    """Detected apps, optional displayName startswith filter. Bounded."""
    return _call(
        apps.list_detected_apps,
        name_prefix=name_prefix,
        top=top if top is not None else DEFAULT_TOP,
    )


def list_compliance_policies(top: int | None = None) -> dict[str, Any]:
    """Device compliance policies (classic Graph v1.0). Bounded."""
    return _call(policies.list_compliance_policies, top=top if top is not None else DEFAULT_TOP)


def get_compliance_policy_status(policy_id: str, top: int | None = None) -> dict[str, Any]:
    """Per-device compliance policy status for one policy. Not a per-setting diagnosis."""
    return _call(
        policies.get_compliance_policy_status,
        policy_id=policy_id,
        top=top if top is not None else DEFAULT_TOP,
    )


def list_configuration_profiles(top: int | None = None) -> dict[str, Any]:
    """Classic deviceConfigurations only. Every response sets settings_catalog_omitted=true."""
    return _call(policies.list_configuration_profiles, top=top if top is not None else DEFAULT_TOP)


def list_mobile_apps(top: int | None = None) -> dict[str, Any]:
    """Mobile apps with assignments. App subtype credential fields are excluded."""
    return _call(apps.list_mobile_apps, top=top if top is not None else DEFAULT_TOP)


def list_autopilot_devices(top: int | None = None) -> dict[str, Any]:
    """Windows Autopilot device identities. Bounded."""
    return _call(apps.list_autopilot_devices, top=top if top is not None else DEFAULT_TOP)


def list_enrollment_configurations(top: int | None = None) -> dict[str, Any]:
    """Device enrollment configurations."""
    return _call(policies.list_enrollment_configurations, top=top if top is not None else DEFAULT_TOP)


def list_intune_audit_events(days: int = 1, top: int | None = None) -> dict[str, Any]:
    """Intune audit events in a UTC day window. Actor IP and modified-property values are dropped."""
    return _call(
        audit.list_intune_audit_events,
        days=days,
        top=top if top is not None else DEFAULT_TOP,
    )


_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("get_intune_overview", get_intune_overview, get_intune_overview.__doc__ or ""),
    ToolSpec("list_managed_devices", list_managed_devices, list_managed_devices.__doc__ or ""),
    ToolSpec("get_managed_device", get_managed_device, get_managed_device.__doc__ or ""),
    ToolSpec("search_managed_devices", search_managed_devices, search_managed_devices.__doc__ or ""),
    ToolSpec("list_noncompliant_devices", list_noncompliant_devices, list_noncompliant_devices.__doc__ or ""),
    ToolSpec("list_detected_apps", list_detected_apps, list_detected_apps.__doc__ or ""),
    ToolSpec("list_compliance_policies", list_compliance_policies, list_compliance_policies.__doc__ or ""),
    ToolSpec(
        "get_compliance_policy_status",
        get_compliance_policy_status,
        get_compliance_policy_status.__doc__ or "",
    ),
    ToolSpec(
        "list_configuration_profiles",
        list_configuration_profiles,
        list_configuration_profiles.__doc__ or "",
    ),
    ToolSpec("list_mobile_apps", list_mobile_apps, list_mobile_apps.__doc__ or ""),
    ToolSpec("list_autopilot_devices", list_autopilot_devices, list_autopilot_devices.__doc__ or ""),
    ToolSpec(
        "list_enrollment_configurations",
        list_enrollment_configurations,
        list_enrollment_configurations.__doc__ or "",
    ),
    ToolSpec("list_intune_audit_events", list_intune_audit_events, list_intune_audit_events.__doc__ or ""),
)

mcp = create_server("intune-ro", _TOOLS, declared_names=TOOL_NAMES)


def advertised_tool_names() -> tuple[str, ...]:
    return registered_tool_names(mcp)


def main() -> None:
    run_stdio(mcp)
