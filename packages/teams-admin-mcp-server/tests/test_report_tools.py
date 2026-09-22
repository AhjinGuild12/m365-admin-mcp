from __future__ import annotations

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GRAPH_BASE, GraphClient

from teams_admin_mcp.allowlist import REPORT_COLUMNS, REPORT_ROW_CAP
from teams_admin_mcp.tools.reports import list_teams_team_activity

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


def _csv(n: int) -> bytes:
    header = ",".join(REPORT_COLUMNS)
    unknown = "Secret Column"
    lines = [header + "," + unknown]
    for i in range(n):
        values = ["2026-09-01" if col == "Report Refresh Date" else str(i) for col in REPORT_COLUMNS]
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
        list_teams_team_activity(Boom(), "D1")  # type: ignore[arg-type]


@pytest.mark.skipif(httpx is None, reason="httpx missing")
@pytest.mark.parametrize(
    ("rows", "truncated"),
    [(4999, False), (5000, True), (5001, True)],
)
def test_truncation_through_kernel_parser(rows: int, truncated: bool) -> None:
    body = list_teams_team_activity(_client(_csv(rows)), "D7")
    assert body["truncated"] is truncated
    assert body["complete"] is (not truncated)
    assert body["items_scanned"] == REPORT_ROW_CAP if truncated else rows
    assert len(body["items"]) == body["items_scanned"]
    assert body["report_refresh_date"] == "2026-09-01"
    assert body["identity_visibility"] == "unknown"
    assert body["identity_visibility_basis"] == "team activity report has no user principal column"
    assert set(body["items"][0]) == set(REPORT_COLUMNS)
    assert "Secret Column" not in body["items"][0]
