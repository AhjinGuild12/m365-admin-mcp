"""Mailbox usage and email activity reports. The download hop carries no token."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import ALLOWED_REPORT_FUNCTIONS, GraphClient
from m365_mcp_kernel.report_download import fetch_projected_report

from exchange_admin_mcp.allowlist import (
    EMAIL_ACTIVITY_COLUMNS,
    GRAPH_REPORT_FUNCTIONS,
    MAILBOX_USAGE_COLUMNS,
    REPORT_PERIODS,
    REPORT_ROW_CAP,
)
from exchange_admin_mcp.schemas import EMAIL_ACTIVITY_SCHEMA, MAILBOX_USAGE_SCHEMA
from exchange_admin_mcp.tools._common import finalize


def _report(
    client: GraphClient,
    function_name: str,
    period: str,
    schema: dict,
    columns: tuple[str, ...],
) -> dict[str, Any]:
    if function_name not in GRAPH_REPORT_FUNCTIONS or function_name not in ALLOWED_REPORT_FUNCTIONS:
        raise SanitizedGraphError("report_not_allowed", status_class="4xx")
    if not isinstance(period, str) or period not in REPORT_PERIODS:
        raise SanitizedGraphError("invalid_period", status_class="4xx")
    rows = fetch_projected_report(client, function_name, period, schema)
    scanned = len(rows)
    truncated = scanned >= REPORT_ROW_CAP
    kept = rows[:REPORT_ROW_CAP]
    for row in kept:
        extra = set(row) - set(columns)
        if extra:
            raise SanitizedGraphError("report_column_not_allowed", status_class="4xx")
    return finalize(
        {
            "items": kept,
            "complete": not truncated,
            "truncated": truncated,
            "items_scanned": len(kept),
            "stop_reason": "item_cap" if truncated else None,
            "error_class": None,
            "period": period,
        }
    )


def list_mailbox_usage_report(client: GraphClient, *, period: str) -> dict[str, Any]:
    """Mailbox usage detail for D7, D30, D90, or D180.

    Concealed user names in the tenant replace principals with hashes.
    """
    return _report(
        client,
        "getMailboxUsageDetail",
        period,
        MAILBOX_USAGE_SCHEMA,
        MAILBOX_USAGE_COLUMNS,
    )


def list_email_activity_report(client: GraphClient, *, period: str) -> dict[str, Any]:
    """Email activity by user for D7, D30, D90, or D180.

    Concealed user names in the tenant replace principals with hashes.
    """
    return _report(
        client,
        "getEmailActivityUserDetail",
        period,
        EMAIL_ACTIVITY_SCHEMA,
        EMAIL_ACTIVITY_COLUMNS,
    )
