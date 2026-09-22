from __future__ import annotations

import json

import httpx
import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GRAPH_BASE, MAX_REPORT_FIELD_BYTES
from m365_mcp_kernel.report_download import fetch_projected_report

REPORT_HOST = "https://reports.office.com/data.csv?s=token"
CSV_BODY = "Report Refresh Date,Site URL,Owner Principal Name\n2026-09-01,https://contoso.sharepoint.com/sites/a,admin@contoso.com\n"


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []


def _graph_302(location: str, extra_headers: dict[str, str] | None = None) -> httpx.MockTransport:
    headers = {"Location": location}
    if extra_headers:
        headers.update(extra_headers)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(GRAPH_BASE + "/reports/")
        return httpx.Response(302, headers=headers)

    return httpx.MockTransport(handler)


def _report_transport(recorder: Recorder, response: httpx.Response) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        recorder.requests.append(request)
        return response

    return httpx.MockTransport(handler)


def _clients(graph_client_factory, location: str, report_response: httpx.Response, extra_headers=None):
    recorder = Recorder()
    graph = httpx.Client(transport=_graph_302(location, extra_headers), follow_redirects=False)
    report = httpx.Client(
        transport=_report_transport(recorder, report_response),
        follow_redirects=False,
        trust_env=False,
    )
    client = graph_client_factory(http_client=graph, report_http_client=report)
    return client, recorder


def _assert_no_url_leak(exc: BaseException) -> None:
    text = str(exc)
    dumped = json.dumps({"msg": text, "cls": getattr(exc, "status_class", None)})
    assert "http://" not in dumped
    assert "https://" not in dumped
    assert "reports.office.com" not in dumped
    assert "evil.example" not in dumped
    assert "Location" not in dumped
    assert "/reports/" not in dumped
    assert "s=token" not in dumped
    assert "data.csv" not in dumped


def test_fetch_report_allowlisted_302_one_credential_free_get(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(200, content=CSV_BODY.encode("utf-8")),
    )
    rows = client.fetch_report("getSharePointSiteUsageDetail", "D7")
    assert len(rows) == 1
    assert rows[0]["Site URL"].endswith("/sites/a")
    assert len(recorder.requests) == 1
    req = recorder.requests[0]
    assert req.headers.get("Authorization") is None
    assert "authorization" not in {k.lower() for k in req.headers.keys()}
    assert req.headers.get("Cookie") is None


def test_fetch_report_http_downgrade_rejected_zero_second_hop(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "http://reports.office.com/data.csv",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getMailboxUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_userinfo_rejected_zero_second_hop(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "https://user:pass@reports.office.com/data.csv",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getMailboxUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_non_443_port_rejected(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "https://reports.office.com:8443/data.csv",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getMailboxUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_fragment_rejected(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "https://reports.office.com/data.csv#frag",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getMailboxUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_relative_location_rejected(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "/data.csv",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getMailboxUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_off_host_zero_second_hop(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        "https://evil.example/loot?x=1",
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    with pytest.raises(SanitizedGraphError, match="report_host_rejected") as exc:
        client.fetch_report("getEmailActivityUserDetail", "D30")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_second_redirect_rejected(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(302, headers={"Location": "https://reports.office.com/other"}),
    )
    with pytest.raises(SanitizedGraphError, match="report_second_redirect") as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert len(recorder.requests) == 1


def test_fetch_report_non_302_first_response(graph_client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": []})

    recorder = Recorder()
    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
        report_http_client=httpx.Client(
            transport=_report_transport(recorder, httpx.Response(200, content=b"x")),
            follow_redirects=False,
        ),
    )
    with pytest.raises(SanitizedGraphError, match="report_redirect_missing") as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert recorder.requests == []


def test_fetch_report_non_200_download(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(403, content=b"nope"),
    )
    with pytest.raises(SanitizedGraphError) as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)
    assert len(recorder.requests) == 1


def test_fetch_report_cookie_and_auth_absent_on_second_request(graph_client_factory) -> None:
    client, recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(200, content=CSV_BODY.encode()),
        extra_headers={"Set-Cookie": "session=abc; Path=/"},
    )
    client.fetch_report("getSharePointSiteUsageStorage", "D90")
    assert len(recorder.requests) == 1
    req = recorder.requests[0]
    combined = " ".join(f"{k}:{v}" for k, v in req.headers.items()).lower()
    assert "authorization" not in combined
    assert "cookie" not in combined
    assert "session=abc" not in combined
    assert "bearer" not in combined


def test_fetch_report_oversized_body(graph_client_factory, monkeypatch) -> None:
    import m365_mcp_kernel.graph_client as gc

    monkeypatch.setattr(gc, "MAX_REPORT_BYTES", 32)
    client, recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(200, content=b"a" * 64),
    )
    with pytest.raises(SanitizedGraphError, match="report_too_large") as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)


def test_fetch_report_chunked_oversized_body(graph_client_factory, monkeypatch) -> None:
    import m365_mcp_kernel.graph_client as gc

    monkeypatch.setattr(gc, "MAX_REPORT_BYTES", 16)

    class ChunkTransport(httpx.BaseTransport):
        def __init__(self, recorder: Recorder) -> None:
            self.recorder = recorder

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            self.recorder.requests.append(request)
            stream = httpx.ByteStream(b"chunk-one\n" + b"chunk-two-too-big\n")
            return httpx.Response(200, stream=stream)

    recorder = Recorder()
    client = graph_client_factory(
        http_client=httpx.Client(transport=_graph_302(REPORT_HOST), follow_redirects=False),
        report_http_client=httpx.Client(
            transport=ChunkTransport(recorder), follow_redirects=False, trust_env=False
        ),
    )
    with pytest.raises(SanitizedGraphError, match="report_too_large") as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)


def test_fetch_report_malformed_csv(graph_client_factory) -> None:
    # Unclosed quote is malformed for csv.reader(strict) — default csv may still parse.
    # A NUL in the middle of a quoted field plus broken encoding is covered by decode errors;
    # here we use a field over the field-size cap as a closed failure.
    huge = "h\n\"" + ("x" * (MAX_REPORT_FIELD_BYTES + 8))
    client, _recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(200, content=huge.encode()),
    )
    with pytest.raises(SanitizedGraphError, match="report_field_too_large|report_csv_malformed") as exc:
        client.fetch_report("getSharePointSiteUsageDetail", "D7")
    _assert_no_url_leak(exc.value)


def test_fetch_report_rejects_unknown_function_without_call(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        return httpx.Response(302, headers={"Location": REPORT_HOST})

    client = graph_client_factory(
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    with pytest.raises(SanitizedGraphError, match="report_function_rejected"):
        client.fetch_report("getTeamsUserActivityUserDetail", "D7")
    with pytest.raises(SanitizedGraphError, match="report_period_rejected"):
        client.fetch_report("getMailboxUsageDetail", "D1")
    assert n["c"] == 0


def test_report_download_projects_rows(graph_client_factory) -> None:
    client, _recorder = _clients(
        graph_client_factory,
        REPORT_HOST,
        httpx.Response(200, content=CSV_BODY.encode()),
    )
    schema = {"Report Refresh Date": True, "Site URL": True}
    rows = fetch_projected_report(client, "getSharePointSiteUsageDetail", "D7", schema)
    assert rows == [
        {
            "Report Refresh Date": "2026-09-01",
            "Site URL": "https://contoso.sharepoint.com/sites/a",
        }
    ]
    assert "Owner Principal Name" not in rows[0]
