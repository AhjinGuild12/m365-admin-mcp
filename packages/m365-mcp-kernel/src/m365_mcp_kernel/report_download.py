"""CSV row projection for Graph usage reports.

Calls ``GraphClient.fetch_report`` and projects rows. Imports no network module
(KTD2b, KTD13).
"""

from __future__ import annotations

from typing import Any, Protocol

from m365_mcp_kernel.schema import project_schema, strip_keys


class _ReportClient(Protocol):
    def fetch_report(self, function_path: str, period: str) -> list[dict[str, str]]: ...


def project_report_rows(
    rows: list[dict[str, str]],
    schema: dict[str, Any],
    *,
    banned: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        projected = project_schema(row, schema)
        if banned:
            projected = strip_keys(projected, banned)
        if isinstance(projected, dict):
            out.append(projected)
    return out


def fetch_projected_report(
    client: _ReportClient,
    function_path: str,
    period: str,
    schema: dict[str, Any],
    *,
    banned: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    rows = client.fetch_report(function_path, period)
    return project_report_rows(rows, schema, banned=banned)
