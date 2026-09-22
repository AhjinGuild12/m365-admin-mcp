"""Intune audit events in a UTC day window (KTD17 nested actor/resources)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient

from intune_mcp.allowlist import AUDIT_ACTOR_FORBIDDEN_KEYS, AUDIT_DEFAULT_DAYS, AUDIT_EVENT_FIELDS
from intune_mcp.schemas import AUDIT_EVENT_SCHEMA
from intune_mcp.tools._common import bounded_collect, clamp_top


def _utc_window(days: int) -> tuple[str, str]:
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise SanitizedGraphError("invalid_days", status_class="4xx")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def list_intune_audit_events(
    client: GraphClient,
    *,
    days: int = AUDIT_DEFAULT_DAYS,
    top: int | None = None,
) -> dict[str, Any]:
    bound = clamp_top(top)
    start, end = _utc_window(days)
    filt = f"activityDateTime ge {start} and activityDateTime lt {end}"
    collected = bounded_collect(
        client,
        "/deviceManagement/auditEvents",
        params={
            "$filter": filt,
            "$select": ",".join(AUDIT_EVENT_FIELDS),
            "$top": str(bound),
        },
        item_cap=bound,
        schema=AUDIT_EVENT_SCHEMA,
        banned=AUDIT_ACTOR_FORBIDDEN_KEYS,
    )
    return {
        "events": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "window_start_utc": start,
        "window_end_utc": end,
    }
