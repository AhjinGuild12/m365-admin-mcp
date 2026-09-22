"""Team activity report. Truncation at the row cap is reported, never treated as complete."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.report_download import fetch_projected_report

from teams_admin_mcp.allowlist import ACTIVITY_REPORT, REPORT_PERIODS, REPORT_ROW_CAP
from teams_admin_mcp.schemas import REPORT_ROW_SCHEMA
from teams_admin_mcp.tools._common import finalize, identity_visibility


def list_teams_team_activity(client: GraphClient, period: str) -> dict[str, Any]:
    """Team activity detail for D7, D30, D90, or D180.

    Identity visibility is an inference: this report has no user principal column.
    """
    if not isinstance(period, str) or period not in REPORT_PERIODS:
        raise SanitizedGraphError("invalid_period", status_class="4xx")
    rows = fetch_projected_report(client, ACTIVITY_REPORT, period, REPORT_ROW_SCHEMA)
    scanned = len(rows)
    truncated = scanned >= REPORT_ROW_CAP
    kept = rows[:REPORT_ROW_CAP]
    visibility, basis = identity_visibility(kept, None)
    refresh: str | None = None
    for row in kept:
        value = row.get("Report Refresh Date")
        if isinstance(value, str) and value.strip():
            refresh = value
            break
    return finalize(
        {
            "items": kept,
            "complete": not truncated,
            "truncated": truncated,
            "items_scanned": len(kept),
            "stop_reason": "item_cap" if truncated else None,
            "error_class": None,
            "report_refresh_date": refresh,
            "identity_visibility": visibility,
            "identity_visibility_basis": basis,
            "period": period,
        }
    )
