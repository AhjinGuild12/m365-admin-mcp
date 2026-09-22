"""Directory audit logs. IP/location fields are never returned (R5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from entra_mcp.allowlist import (
    AUDIT_DEFAULT_TOP,
    AUDIT_FIELDS,
    AUDIT_FORBIDDEN_KEYS,
    AUDIT_HARD_CAP,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, strip_keys
from entra_mcp.graph_client import GraphClient, escape_odata_string, is_guid


def _clamp_top(top: int | None) -> int:
    bound = AUDIT_DEFAULT_TOP if top is None else top
    if bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    if bound > AUDIT_HARD_CAP:
        raise SanitizedGraphError("audit_cap_exceeded", status_class="4xx")
    return bound


def _utc_window(days: int) -> tuple[str, str]:
    if days < 1:
        raise SanitizedGraphError("invalid_days", status_class="4xx")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _slim_initiated_by(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    user = value.get("user")
    app = value.get("app")
    if isinstance(user, dict):
        out["user"] = {
            key: user[key]
            for key in ("id", "displayName", "userPrincipalName")
            if key in user
        }
    if isinstance(app, dict):
        out["app"] = {
            key: app[key]
            for key in ("appId", "displayName", "servicePrincipalId")
            if key in app
        }
    return out


def _slim_targets(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return out
    for item in values:
        if not isinstance(item, dict):
            continue
        row: dict[str, Any] = {
            key: item[key]
            for key in ("id", "displayName", "type", "userPrincipalName")
            if key in item
        }
        props = item.get("modifiedProperties")
        if isinstance(props, list):
            slim_props = []
            for prop in props:
                if not isinstance(prop, dict):
                    continue
                slim_props.append(
                    {
                        key: prop[key]
                        for key in ("displayName", "oldValue", "newValue")
                        if key in prop
                    }
                )
            row["modifiedProperties"] = slim_props
        out.append(row)
    return out


def _project_audits(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        cleaned = strip_keys(item, AUDIT_FORBIDDEN_KEYS)
        row = project(cleaned, AUDIT_FIELDS)
        if "initiatedBy" in row:
            row["initiatedBy"] = _slim_initiated_by(row.get("initiatedBy"))
        if "targetResources" in row:
            row["targetResources"] = _slim_targets(row.get("targetResources"))
        out.append(row)
    return out


def list_directory_audits(
    client: GraphClient,
    *,
    days: int = 1,
    top: int | None = None,
    category: str | None = None,
    target_id: str | None = None,
    activity_display_name: str | None = None,
) -> dict[str, Any]:
    bound = _clamp_top(top)
    start, end = _utc_window(days)
    clauses = [
        f"activityDateTime ge {start}",
        f"activityDateTime lt {end}",
    ]
    if category:
        clauses.append(f"category eq '{escape_odata_string(category)}'")
    if target_id:
        if not is_guid(target_id):
            raise SanitizedGraphError("invalid_target_id", status_class="4xx")
        clauses.append(
            f"targetResources/any(t:t/id eq '{escape_odata_string(target_id)}')"
        )
    if activity_display_name:
        clauses.append(
            f"activityDisplayName eq '{escape_odata_string(activity_display_name)}'"
        )
    filt = " and ".join(clauses)
    items = client.collect_page(
        "/auditLogs/directoryAudits",
        params={
            "$filter": filt,
            "$select": ",".join(AUDIT_FIELDS),
            "$top": str(bound),
        },
        item_cap=bound,
    )
    return {
        "audits": _project_audits(items),
        "window_start_utc": start,
        "window_end_utc": end,
    }
