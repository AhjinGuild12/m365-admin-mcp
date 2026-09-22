"""License inventory: subscribed SKUs, per-user licenses, SKU holders, GBL groups."""

from __future__ import annotations

from typing import Any

from entra_mcp.allowlist import (
    LICENSE_ASSIGNMENT_STATE_FIELDS,
    LICENSE_DETAIL_FIELDS,
    LICENSE_GROUP_FIELDS,
    LICENSE_SCAN_MAX,
    LICENSE_USER_FIELDS,
    PREPAID_UNIT_FIELDS,
    SERVICE_PLAN_FIELDS,
    SKU_FIELDS,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project
from entra_mcp.graph_client import (
    GraphClient,
    encode_path_segment,
    is_guid,
)

SEARCH_HEADERS = {"ConsistencyLevel": "eventual"}

# Static friendly names for common Microsoft SKUs. Unknown part numbers pass through.
SKU_FRIENDLY_NAMES: dict[str, str] = {
    "SPE_E3": "Microsoft 365 E3",
    "SPE_E5": "Microsoft 365 E5",
    "SPE_F1": "Microsoft 365 F1",
    "SPE_F3": "Microsoft 365 F3",
    "ENTERPRISEPACK": "Office 365 E3",
    "ENTERPRISEPREMIUM": "Office 365 E5",
    "STANDARDPACK": "Office 365 E1",
    "SPB": "Microsoft 365 Business Premium",
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "O365_BUSINESS_ESSENTIALS": "Microsoft 365 Business Basic",
    "AAD_PREMIUM": "Entra ID P1",
    "AAD_PREMIUM_P2": "Entra ID P2",
    "EMS": "Enterprise Mobility + Security E3",
    "EMSPREMIUM": "Enterprise Mobility + Security E5",
    "INTUNE_A": "Microsoft Intune",
    "IDENTITY_THREAT_PROTECTION": "Entra ID Protection",
    "ATP_ENTERPRISE": "Defender for Office 365 P1",
    "THREAT_INTELLIGENCE": "Defender for Office 365 P2",
    "MCOSTANDARD": "Microsoft Teams",
    "MCOEV": "Phone System",
    "EXCHANGESTANDARD": "Exchange Online Plan 1",
    "EXCHANGEENTERPRISE": "Exchange Online Plan 2",
    "POWER_BI_PRO": "Power BI Pro",
    "POWER_BI_STANDARD": "Power BI Free",
    "FLOW_FREE": "Power Automate Free",
    "PROJECTPROFESSIONAL": "Project Plan 3",
    "VISIOCLIENT": "Visio Plan 2",
    "WIN_DEF_ATP": "Defender for Endpoint",
}


def _friendly_name(sku_part_number: str | None) -> str | None:
    if not sku_part_number:
        return sku_part_number
    return SKU_FRIENDLY_NAMES.get(sku_part_number, sku_part_number)


def _project_service_plans(values: Any) -> list[dict[str, Any]]:
    return [
        project(item, SERVICE_PLAN_FIELDS)
        for item in (values or [])
        if isinstance(item, dict)
    ]


def _project_sku(item: dict[str, Any]) -> dict[str, Any]:
    row = project(item, SKU_FIELDS)
    prepaid = row.get("prepaidUnits")
    if isinstance(prepaid, dict):
        row["prepaidUnits"] = project(prepaid, PREPAID_UNIT_FIELDS)
    if "servicePlans" in row:
        row["servicePlans"] = _project_service_plans(row.get("servicePlans"))
    part = row.get("skuPartNumber")
    if isinstance(part, str):
        row["friendlyName"] = _friendly_name(part)
    return row


def _project_license_details(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        row = project(item, LICENSE_DETAIL_FIELDS)
        if "servicePlans" in row:
            row["servicePlans"] = _project_service_plans(row.get("servicePlans"))
        part = row.get("skuPartNumber")
        if isinstance(part, str):
            row["friendlyName"] = _friendly_name(part)
        out.append(row)
    return out


def list_subscribed_skus(client: GraphClient) -> dict[str, Any]:
    items = client.collect_page(
        "/subscribedSkus",
        params={"$select": ",".join(SKU_FIELDS)},
        item_cap=200,
    )
    return {"skus": [_project_sku(item) for item in items]}


def get_user_licenses(client: GraphClient, user: str) -> dict[str, Any]:
    user_path = f"/users/{encode_path_segment(user)}"
    profile = client.get(
        user_path,
        params={
            "$select": ",".join(LICENSE_USER_FIELDS) + ",licenseAssignmentStates",
        },
    )
    details = client.collect_page(
        f"{user_path}/licenseDetails",
        params={"$select": ",".join(LICENSE_DETAIL_FIELDS)},
        item_cap=100,
    )
    states_raw = profile.get("licenseAssignmentStates") or []
    states = []
    for item in states_raw:
        if not isinstance(item, dict):
            continue
        states.append(project(item, LICENSE_ASSIGNMENT_STATE_FIELDS))
    projected_user = project(profile, LICENSE_USER_FIELDS)
    return {
        **projected_user,
        "licenses": _project_license_details(details),
        "licenseAssignmentStates": states,
    }


def _resolve_sku_id(client: GraphClient, sku: str) -> tuple[str, str | None]:
    items = client.collect_page(
        "/subscribedSkus",
        params={"$select": "skuId,skuPartNumber"},
        item_cap=200,
    )
    if is_guid(sku):
        for item in items:
            if str(item.get("skuId") or "").lower() == sku.lower():
                part = item.get("skuPartNumber")
                return str(item.get("skuId")), str(part) if part else None
        return sku, None
    matches = [
        item
        for item in items
        if str(item.get("skuPartNumber", "")).lower() == sku.lower()
    ]
    if not matches:
        raise SanitizedGraphError("sku_not_found", status_class="4xx")
    if len(matches) > 1:
        raise SanitizedGraphError("multiple_matches", status_class="4xx")
    sku_id = str(matches[0].get("skuId") or "")
    if not sku_id:
        raise SanitizedGraphError("sku_not_found", status_class="4xx")
    return sku_id, str(matches[0].get("skuPartNumber") or sku)


def list_users_by_sku(
    client: GraphClient,
    sku: str,
    *,
    enabled_only: bool = False,
    scan_cap: int = LICENSE_SCAN_MAX,
) -> dict[str, Any]:
    if scan_cap < 1:
        raise SanitizedGraphError("invalid_scan_cap", status_class="4xx")
    sku_id, sku_part = _resolve_sku_id(client, sku)
    filt = f"assignedLicenses/any(x:x/skuId eq {sku_id})"
    select = ",".join(LICENSE_USER_FIELDS)
    items = client.collect_page(
        "/users",
        params={
            "$filter": filt,
            "$select": select,
            "$count": "true",
        },
        headers=SEARCH_HEADERS,
        item_cap=scan_cap,
    )
    users = []
    for item in items:
        row = project(item, LICENSE_USER_FIELDS)
        if enabled_only and not row.get("accountEnabled"):
            continue
        users.append(row)
    truncated = len(items) >= scan_cap
    return {
        "users": users,
        "skuId": sku_id,
        "skuPartNumber": sku_part,
        "friendlyName": _friendly_name(sku_part) if sku_part else None,
        "enabled_only": enabled_only,
        "truncated": truncated,
        "scan_cap": scan_cap,
    }


def _group_has_licenses(item: dict[str, Any]) -> bool:
    assigned = item.get("assignedLicenses")
    return isinstance(assigned, list) and len(assigned) > 0


def _project_license_group(item: dict[str, Any]) -> dict[str, Any]:
    row = project(item, LICENSE_GROUP_FIELDS)
    assigned = row.get("assignedLicenses")
    if isinstance(assigned, list):
        slim = []
        for entry in assigned:
            if not isinstance(entry, dict):
                continue
            slim.append(
                {
                    key: entry[key]
                    for key in ("skuId", "disabledPlans")
                    if key in entry
                }
            )
        row["assignedLicenses"] = slim
    state = row.get("licenseProcessingState")
    if isinstance(state, dict):
        row["licenseProcessingState"] = {
            key: state[key] for key in ("state", "lastUpdatedDateTime") if key in state
        }
    return row


def list_license_groups(
    client: GraphClient,
    *,
    scan_cap: int = LICENSE_SCAN_MAX,
) -> dict[str, Any]:
    if scan_cap < 1:
        raise SanitizedGraphError("invalid_scan_cap", status_class="4xx")
    select = ",".join(LICENSE_GROUP_FIELDS)
    used_fallback = False
    try:
        items = client.collect_page(
            "/groups",
            params={
                "$filter": "assignedLicenses/$count ne 0",
                "$select": select,
                "$count": "true",
            },
            headers=SEARCH_HEADERS,
            item_cap=scan_cap,
        )
        groups = [_project_license_group(item) for item in items]
        truncated = len(items) >= scan_cap
    except SanitizedGraphError as exc:
        if exc.status_class != "4xx":
            raise
        used_fallback = True
        scanned = client.collect_page(
            "/groups",
            params={"$select": select},
            item_cap=scan_cap,
        )
        groups = [
            _project_license_group(item) for item in scanned if _group_has_licenses(item)
        ]
        truncated = len(scanned) >= scan_cap
    return {
        "groups": groups,
        "truncated": truncated,
        "scan_cap": scan_cap,
        "filter_mode": "fallback_scan" if used_fallback else "odata_count",
    }
