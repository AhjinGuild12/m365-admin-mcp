"""Compliance policies, per-device policy status, configuration profiles, enrollment."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.graph_client import GraphClient, encode_path_segment

from intune_mcp.allowlist import (
    COMPLIANCE_POLICY_FIELDS,
    COMPLIANCE_STATUS_FIELDS,
    CONFIGURATION_PROFILE_FIELDS,
    ENROLLMENT_CONFIG_FIELDS,
)
from intune_mcp.schemas import (
    COMPLIANCE_POLICY_SCHEMA,
    COMPLIANCE_STATUS_SCHEMA,
    CONFIGURATION_PROFILE_SCHEMA,
    ENROLLMENT_CONFIG_SCHEMA,
)
from intune_mcp.tools._common import bounded_collect, clamp_top


def list_compliance_policies(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    bound = clamp_top(top)
    collected = bounded_collect(
        client,
        "/deviceManagement/deviceCompliancePolicies",
        params={"$select": ",".join(COMPLIANCE_POLICY_FIELDS), "$top": str(bound)},
        item_cap=bound,
        schema=COMPLIANCE_POLICY_SCHEMA,
    )
    return {
        "policies": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "status_kind": "policy_inventory",
    }


def get_compliance_policy_status(
    client: GraphClient,
    policy_id: str,
    *,
    top: int | None = None,
) -> dict[str, Any]:
    """Per-device policy status, not a per-setting diagnosis."""
    bound = clamp_top(top)
    path = (
        f"/deviceManagement/deviceCompliancePolicies/{encode_path_segment(policy_id)}/deviceStatuses"
    )
    collected = bounded_collect(
        client,
        path,
        params={"$select": ",".join(COMPLIANCE_STATUS_FIELDS), "$top": str(bound)},
        item_cap=bound,
        schema=COMPLIANCE_STATUS_SCHEMA,
    )
    return {
        "policy_id": policy_id,
        "device_statuses": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "status_kind": "per_device_policy_status",
        "per_setting_diagnosis": False,
    }


def list_configuration_profiles(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    """Classic deviceConfigurations only. Settings catalog is omitted."""
    bound = clamp_top(top)
    collected = bounded_collect(
        client,
        "/deviceManagement/deviceConfigurations",
        params={"$select": ",".join(CONFIGURATION_PROFILE_FIELDS), "$top": str(bound)},
        item_cap=bound,
        schema=CONFIGURATION_PROFILE_SCHEMA,
    )
    return {
        "profiles": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "settings_catalog_omitted": True,
    }


def list_enrollment_configurations(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    bound = clamp_top(top)
    collected = bounded_collect(
        client,
        "/deviceManagement/deviceEnrollmentConfigurations",
        params={"$select": ",".join(ENROLLMENT_CONFIG_FIELDS), "$top": str(bound)},
        item_cap=bound,
        schema=ENROLLMENT_CONFIG_SCHEMA,
    )
    return {
        "configurations": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
    }
