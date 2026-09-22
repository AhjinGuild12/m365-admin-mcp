"""Managed-device list, get, search, and noncompliant tools (KTD11)."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient, encode_path_segment, odata_eq
from m365_mcp_kernel.schema import project_then_strip

from intune_mcp.allowlist import MANAGED_DEVICE_FIELDS, validate_select
from intune_mcp.schemas import MANAGED_DEVICE_SCHEMA
from intune_mcp.tools._common import bounded_collect, clamp_top, device_banned

_SELECT = ",".join(validate_select(MANAGED_DEVICE_FIELDS))


def _device_envelope(collected: dict[str, Any], *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {
        "devices": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
    }
    if extra:
        out.update(extra)
    return out


def _row_matches_eq(row: dict[str, Any], field: str, expected: str) -> bool:
    value = row.get(field)
    return value is not None and str(value) == expected


def _verify_eq(rows: list[dict[str, Any]], field: str, expected: str) -> bool:
    return all(_row_matches_eq(row, field, expected) for row in rows)


def _verify_startswith(rows: list[dict[str, Any]], field: str, prefix: str) -> bool:
    lower = prefix.lower()
    return all(str(row.get(field) or "").lower().startswith(lower) for row in rows)


def list_managed_devices(
    client: GraphClient,
    *,
    operating_system: str | None = None,
    compliance_state: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """List managed devices. Optional equality filters are verified on returned rows."""
    bound = clamp_top(top)
    filters: list[str] = []
    if operating_system:
        filters.append(odata_eq("operatingSystem", operating_system))
    if compliance_state:
        filters.append(odata_eq("complianceState", compliance_state))
    params: dict[str, str] = {"$select": _SELECT, "$top": str(bound)}
    if filters:
        params["$filter"] = " and ".join(filters)
    collected = bounded_collect(
        client,
        "/deviceManagement/managedDevices",
        params=params,
        item_cap=bound,
        schema=MANAGED_DEVICE_SCHEMA,
        banned=device_banned(),
    )
    verified = True
    if operating_system:
        verified = verified and _verify_eq(collected["items"], "operatingSystem", operating_system)
    if compliance_state:
        verified = verified and _verify_eq(collected["items"], "complianceState", compliance_state)
    extra = {
        "returned_rows_verified": verified if filters else True,
        "filter_applied": bool(filters),
    }
    extra["returned_rows_verified_note"] = (
        "verification of returned rows, not proof of server-side filtering"
    )
    return _device_envelope(collected, extra=extra)


def get_managed_device(
    client: GraphClient,
    *,
    device_id: str | None = None,
    serial_number: str | None = None,
    device_name: str | None = None,
) -> dict[str, Any]:
    """One device by Intune id, or unique exact serialNumber / deviceName."""
    keys = [k for k in (device_id, serial_number, device_name) if k]
    if len(keys) != 1:
        raise SanitizedGraphError("invalid_lookup", status_class="4xx")
    if device_id:
        data = client.get(
            f"/deviceManagement/managedDevices/{encode_path_segment(device_id)}",
            params={"$select": _SELECT},
        )
        return project_then_strip(data, MANAGED_DEVICE_SCHEMA, device_banned())

    field = "serialNumber" if serial_number else "deviceName"
    value = serial_number or device_name or ""
    bound = HARD_LOOKUP_CAP
    collected = bounded_collect(
        client,
        "/deviceManagement/managedDevices",
        params={
            "$select": _SELECT,
            "$filter": odata_eq(field, value),
            "$top": str(bound),
        },
        item_cap=bound,
        schema=MANAGED_DEVICE_SCHEMA,
        banned=device_banned(),
    )
    matches = [d for d in collected["items"] if _row_matches_eq(d, field, value)]
    if not collected["complete"]:
        return {
            "status": "incomplete",
            "complete": False,
            "truncated": collected["truncated"],
            "items_scanned": collected["items_scanned"],
            "stop_reason": collected["stop_reason"],
        }
    if len(matches) == 0:
        raise SanitizedGraphError("not_found", status_class="4xx")
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "complete": True,
            "truncated": False,
            "items_scanned": collected["items_scanned"],
            "stop_reason": None,
            "match_count": len(matches),
        }
    return matches[0]


HARD_LOOKUP_CAP = 200


def search_managed_devices(
    client: GraphClient,
    *,
    device_name_prefix: str | None = None,
    user_principal_name: str | None = None,
    serial_number: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """startswith(deviceName) or exact UPN / serialNumber. Bounded."""
    bound = clamp_top(top)
    provided = [v for v in (device_name_prefix, user_principal_name, serial_number) if v]
    if len(provided) != 1:
        raise SanitizedGraphError("invalid_search", status_class="4xx")
    if device_name_prefix:
        escaped = device_name_prefix.replace("'", "''")
        filt = f"startswith(deviceName,'{escaped}')"
        field, expected, kind = "deviceName", device_name_prefix, "startswith"
    elif user_principal_name:
        filt = odata_eq("userPrincipalName", user_principal_name)
        field, expected, kind = "userPrincipalName", user_principal_name, "eq"
    else:
        filt = odata_eq("serialNumber", serial_number or "")
        field, expected, kind = "serialNumber", serial_number or "", "eq"
    collected = bounded_collect(
        client,
        "/deviceManagement/managedDevices",
        params={"$select": _SELECT, "$filter": filt, "$top": str(bound)},
        item_cap=bound,
        schema=MANAGED_DEVICE_SCHEMA,
        banned=device_banned(),
    )
    if kind == "startswith":
        verified = _verify_startswith(collected["items"], field, expected)
    else:
        verified = _verify_eq(collected["items"], field, expected)
    return _device_envelope(
        collected,
        extra={
            "returned_rows_verified": verified,
            "returned_rows_verified_note": (
                "verification of returned rows, not proof of server-side filtering"
            ),
        },
    )


def list_noncompliant_devices(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    return list_managed_devices(client, compliance_state="noncompliant", top=top)
