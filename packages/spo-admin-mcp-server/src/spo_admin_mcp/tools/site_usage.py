"""SharePoint site-usage reports. Period is refused before any Graph call."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.report_download import fetch_projected_report

from spo_admin_mcp.allowlist import (
    COUNTS_REPORT,
    DETAIL_REPORT,
    PAGE_VIEW_FIELDS,
    REPORT_PERIODS,
    REPORT_ROW_CAP,
    STORAGE_REPORT,
)
from spo_admin_mcp.schemas import COUNTS_ROW_SCHEMA, DETAIL_ROW_SCHEMA, STORAGE_ROW_SCHEMA
from spo_admin_mcp.tools.tenant_settings import utc_now

_HEX = frozenset("0123456789abcdef")


def _require_period(period: str) -> str:
    if not isinstance(period, str) or period not in REPORT_PERIODS:
        raise SanitizedGraphError("invalid_period", status_class="4xx")
    return period


def _cap_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    if len(rows) >= REPORT_ROW_CAP:
        return rows[:REPORT_ROW_CAP], True
    return rows, False


def _refresh(rows: list[dict[str, Any]]) -> str | None:
    for row in rows:
        value = row.get("Report Refresh Date")
        if isinstance(value, str) and value.strip():
            return value
    return None


def _deleted(row: dict[str, Any]) -> bool:
    value = str(row.get("Is Deleted", "")).strip().lower()
    return value in {"true", "yes", "1"}


def identity_visibility(rows: list[dict[str, Any]]) -> tuple[str, str]:
    """Infer concealment from owner-principal shape. The tenant setting is not read."""
    if not rows:
        return "unknown", "no rows"
    has_owner_column = any(
        "Owner Principal Name" in row or "Owner Display Name" in row for row in rows
    )
    if not has_owner_column:
        return "unknown", "owner columns absent"
    nonempty: list[str] = []
    saw_deleted_blank = False
    for row in rows:
        principal = row.get("Owner Principal Name")
        text = principal.strip() if isinstance(principal, str) else ""
        if text:
            nonempty.append(text)
        elif _deleted(row):
            saw_deleted_blank = True
    if not nonempty and saw_deleted_blank:
        return "unknown", "deleted-owner rows have an empty principal"
    if not nonempty:
        return "concealed", "owner principal blank on every row"
    emails = [item for item in nonempty if "@" in item]
    opaque = [item for item in nonempty if "@" not in item]
    if emails and not opaque:
        return "visible", "owner principal has email shape on non-empty rows"
    if opaque and not emails:
        return "concealed", "owner principal is non-email on non-empty rows"
    return "unknown", "mixed owner principal shapes"


def _report_meta(rows: list[dict[str, Any]], *, scanned: int, truncated: bool) -> dict[str, Any]:
    visibility, basis = identity_visibility(rows)
    return {
        "retrieved_at": utc_now(),
        "report_refresh_date": _refresh(rows),
        "complete": not truncated,
        "truncated": truncated,
        "items_scanned": scanned,
        "stop_reason": "item_cap" if truncated else None,
        "identity_visibility": visibility,
        "identity_visibility_basis": basis,
    }


def _load(client: GraphClient, function_name: str, period: str, schema: dict) -> tuple[list[dict[str, Any]], int, bool]:
    rows = fetch_projected_report(client, function_name, period, schema, banned=PAGE_VIEW_FIELDS)
    scanned = len(rows)
    kept, truncated = _cap_rows(rows)
    return kept, scanned, truncated


def list_site_usage(client: GraphClient, period: str) -> dict[str, Any]:
    chosen = _require_period(period)
    rows, scanned, truncated = _load(client, DETAIL_REPORT, chosen, DETAIL_ROW_SCHEMA)
    body = _report_meta(rows, scanned=scanned, truncated=truncated)
    body["period"] = chosen
    body["items"] = rows
    return body


def _is_guid(value: str) -> bool:
    parts = value.split("-")
    if [len(part) for part in parts] != [8, 4, 4, 4, 12]:
        return False
    return all(part and all(char in _HEX for char in part) for part in parts)


def _normalize_url(value: str) -> str:
    text = value.strip().split("#", 1)[0]
    if "://" not in text:
        return text.rstrip("/")
    scheme, rest = text.split("://", 1)
    if "/" in rest:
        host, path = rest.split("/", 1)
        path = "/" + path
    else:
        host, path = rest, ""
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")
    return f"{scheme.lower()}://{host.lower().rstrip('.')}{path}"


def _lookup_kind(site: str) -> str:
    if "://" in site:
        return "url"
    if _is_guid(site.strip().lower()):
        return "id"
    return "identity"


def _matches(row: dict[str, Any], site: str, kind: str) -> bool:
    if kind == "url":
        current = row.get("Site URL")
        return isinstance(current, str) and _normalize_url(current) == _normalize_url(site)
    if kind == "id":
        current = row.get("Site Id")
        return isinstance(current, str) and current.strip().lower() == site.strip().lower()
    principal = row.get("Owner Principal Name")
    display = row.get("Owner Display Name")
    needle = site.strip().casefold()
    if isinstance(principal, str) and principal.strip().casefold() == needle:
        return True
    return isinstance(display, str) and display.strip().casefold() == needle


def get_site_usage(client: GraphClient, site: str, period: str) -> dict[str, Any]:
    if not isinstance(site, str) or not site.strip():
        raise SanitizedGraphError("invalid_lookup", status_class="4xx")
    chosen = _require_period(period)
    rows, scanned, truncated = _load(client, DETAIL_REPORT, chosen, DETAIL_ROW_SCHEMA)
    meta = _report_meta(rows, scanned=scanned, truncated=truncated)
    meta["period"] = chosen
    kind = _lookup_kind(site)
    if kind == "identity" and meta["identity_visibility"] != "visible":
        meta["status"] = "identity_unresolvable"
        return meta
    matches = [row for row in rows if _matches(row, site, kind)]
    if not matches and truncated:
        meta["status"] = "incomplete"
        return meta
    if not matches:
        raise SanitizedGraphError("not_found", status_class="4xx")
    if len(matches) > 1:
        meta["status"] = "ambiguous"
        meta["match_count"] = len(matches)
        return meta
    meta["status"] = "ok"
    meta["item"] = matches[0]
    return meta


def _by_date(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        day = row.get("Report Date")
        if not isinstance(day, str) or not day.strip():
            continue
        grouped.setdefault(day, []).append(row)
    return grouped


def get_site_usage_summary(client: GraphClient, period: str) -> dict[str, Any]:
    chosen = _require_period(period)
    storage, storage_scanned, storage_truncated = _load(client, STORAGE_REPORT, chosen, STORAGE_ROW_SCHEMA)
    counts, counts_scanned, counts_truncated = _load(client, COUNTS_REPORT, chosen, COUNTS_ROW_SCHEMA)
    truncated = storage_truncated or counts_truncated
    storage_groups = _by_date(storage)
    count_groups = _by_date(counts)
    days = sorted(set(storage_groups) | set(count_groups))
    items = [
        {
            "Report Date": day,
            "storage": storage_groups.get(day, []),
            "counts": count_groups.get(day, []),
        }
        for day in days
    ]
    combined = storage + counts
    body = _report_meta(combined, scanned=storage_scanned + counts_scanned, truncated=truncated)
    body["identity_visibility"] = "unknown"
    body["identity_visibility_basis"] = "summary reports have no owner principal column"
    body["period"] = chosen
    body["items"] = items
    return body
