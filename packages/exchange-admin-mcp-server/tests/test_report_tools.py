from __future__ import annotations

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GRAPH_BASE, GraphClient

from exchange_admin_mcp.allowlist import EMAIL_ACTIVITY_COLUMNS, MAILBOX_USAGE_COLUMNS, REPORT_ROW_CAP
from exchange_admin_mcp.tools.reports import list_email_activity_report, list_mailbox_usage_report

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


def _csv(columns: tuple[str, ...], n: int) -> bytes:
    unknown = "Secret Column"
    lines = [",".join(columns) + "," + unknown]
    for i in range(n):
        values = ["2026-09-01" if col == "Report Refresh Date" else str(i) for col in columns]
        values.append("drop-me")
        lines.append(",".join(values))
    return ("\n".join(lines) + "\n").encode()


def _client(body: bytes) -> GraphClient:
    assert httpx is not None

    def graph(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(GRAPH_BASE + "/reports/")
        return httpx.Response(302, headers={"Location": "https://reports.office.com/data.csv"})

    def report(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") is None
        return httpx.Response(200, content=body)

    return GraphClient(
        token_provider=lambda: "test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(graph), follow_redirects=False),
        report_http_client=httpx.Client(transport=httpx.MockTransport(report), follow_redirects=False),
    )


def test_invalid_period_does_not_fetch() -> None:
    class Boom:
        def fetch_report(self, function_path: str, period: str):
            raise AssertionError("fetch_report was called")

    with pytest.raises(SanitizedGraphError, match="invalid_period"):
        list_mailbox_usage_report(Boom(), period="D1")  # type: ignore[arg-type]


@pytest.mark.skipif(httpx is None, reason="httpx missing")
def test_usage_report_second_hop_has_no_authorization() -> None:
    body = list_mailbox_usage_report(_client(_csv(MAILBOX_USAGE_COLUMNS, 1)), period="D7")
    assert body["period"] == "D7"
    assert body["items"][0]["Report Refresh Date"] == "2026-09-01"
    assert "Secret Column" not in body["items"][0]


@pytest.mark.skipif(httpx is None, reason="httpx missing")
def test_activity_report_truncates_at_row_cap() -> None:
    body = list_email_activity_report(
        _client(_csv(EMAIL_ACTIVITY_COLUMNS, REPORT_ROW_CAP)),
        period="D30",
    )
    assert body["truncated"] is True
    assert body["stop_reason"] == "item_cap"
    assert len(body["items"]) == REPORT_ROW_CAP
    assert set(body["items"][0]) <= set(EMAIL_ACTIVITY_COLUMNS)
