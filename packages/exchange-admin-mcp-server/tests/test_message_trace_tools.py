from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import encode_path_segment, escape_odata_string

from exchange_admin_mcp.allowlist import HARD_CAP
from exchange_admin_mcp.server import (
    get_message_trace_details as server_details,
    list_message_traces as server_list,
    set_graph_client_factory,
)
from exchange_admin_mcp.tools.message_trace import get_message_trace_details, list_message_traces
from tests.conftest import FakeGraph, gid

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
TRACE = gid("a")
PATH = "/admin/exchange/tracing/messageTraces"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_window_too_long_makes_zero_calls() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="window_too_long"):
        list_message_traces(
            client,
            start=_iso(NOW - timedelta(days=12)),
            end=_iso(NOW),
            now=NOW,
        )
    assert client.calls == []


def test_window_in_future_makes_zero_calls() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="window_in_future"):
        list_message_traces(
            client,
            start=_iso(NOW - timedelta(days=1)),
            end=_iso(NOW + timedelta(hours=1)),
            now=NOW,
        )
    assert client.calls == []


def test_non_guid_trace_id_makes_zero_calls() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="guid_required"):
        get_message_trace_details(client, trace_id="not-a-guid", recipient="a@contoso.com")
    assert client.calls == []


def test_filter_strings_and_default_window() -> None:
    client = FakeGraph(pages={PATH: []})
    body = list_message_traces(client, sender="a@contoso.com", now=NOW)
    assert body["window"] == "default_48h"
    assert client.calls[0]["params"]["$filter"] == "senderAddress eq 'a@contoso.com'"
    assert client.calls[0]["path"] == PATH
    assert "://" not in client.calls[0]["path"]

    client = FakeGraph(pages={PATH: []})
    start = _iso(NOW - timedelta(days=2))
    end = _iso(NOW - timedelta(days=1))
    list_message_traces(
        client,
        sender="a@contoso.com",
        recipient="b@contoso.com",
        message_id="<id@contoso.com>",
        status="delivered",
        subject="invoice",
        start=start,
        end=end,
        now=NOW,
    )
    filt = client.calls[0]["params"]["$filter"]
    assert filt == (
        "senderAddress eq 'a@contoso.com'"
        " and recipientAddress eq 'b@contoso.com'"
        " and messageId eq '<id@contoso.com>'"
        " and status eq 'delivered'"
        " and contains(subject, 'invoice')"
        f" and receivedDateTime ge {start} and receivedDateTime le {end}"
    )


def test_top_never_exceeds_hard_cap_and_truncates() -> None:
    client = FakeGraph()
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        list_message_traces(client, top=HARD_CAP + 1, now=NOW)
    assert client.calls == []
    rows = [{"id": gid("b"), "subject": str(i), "fromIP": "203.0.113.5"} for i in range(HARD_CAP + 1)]
    client = FakeGraph(pages={PATH: rows})
    body = list_message_traces(client, top=HARD_CAP, now=NOW)
    assert client.calls[0]["params"]["$top"] == str(HARD_CAP)
    assert body["truncated"] is True
    assert body["stop_reason"] == "item_cap"
    assert len(body["items"]) == HARD_CAP
    assert "fromIP" not in json.dumps(body)


def test_partial_page_keeps_first_rows() -> None:
    client = FakeGraph(
        pages={PATH: [{"id": gid("c"), "subject": "one"}, {"id": gid("d"), "subject": "two"}]},
        errors={PATH: SanitizedGraphError("5xx retries_exhausted", status_class="5xx")},
        page_error_after={PATH: 1},
    )
    body = list_message_traces(client, now=NOW)
    assert body["complete"] is False
    assert body["stop_reason"] == "throttling_exhausted"
    assert body["items"][0]["subject"] == "one"


def test_recipient_quote_or_slash_is_one_encoded_segment() -> None:
    address = "o'brien/team@contoso.com"
    encoded = encode_path_segment(escape_odata_string(address))
    client = FakeGraph(pages={})
    body = get_message_trace_details(client, trace_id=TRACE, recipient=address)
    path = client.calls[0]["path"]
    assert path.startswith(PATH + "/")
    assert encoded in path
    assert "/" not in path.split("recipientAddress='", 1)[1].rstrip("')")
    assert "%2F" in path
    assert "%27" in path
    assert body["items"] == []


def test_server_call_strips_fromip_and_data() -> None:
    detail_path_prefix = PATH + "/"
    pages = {
        PATH: [
            {
                "id": TRACE,
                "senderAddress": "a@contoso.com",
                "recipientAddress": "b@contoso.com",
                "subject": "hello",
                "status": "delivered",
                "fromIP": "203.0.113.9",
                "toIP": "203.0.113.10",
                "data": "secret-blob",
            }
        ]
    }
    client = FakeGraph(pages=pages)
    listed = list_message_traces(client, now=NOW)
    set_graph_client_factory(lambda: FakeGraph(pages=pages))
    try:
        listed_via_server = server_list()
    finally:
        set_graph_client_factory(None)
    dumped = json.dumps(listed_via_server)
    assert "fromIP" not in dumped
    assert "toIP" not in dumped
    assert "data" not in dumped
    assert "203.0.113" not in dumped
    assert listed["items"][0]["subject"] == "hello"
    detail_client = FakeGraph(
        pages={
            f"{detail_path_prefix}{TRACE}/getDetailsByRecipient(recipientAddress='b%40contoso.com')": [
                {"date": "2026-09-01T00:00:00Z", "event": "receive", "data": "blob", "fromIP": "203.0.113.1"}
            ]
        }
    )
    set_graph_client_factory(lambda: detail_client)
    try:
        details = server_details(TRACE, "b@contoso.com")
    finally:
        set_graph_client_factory(None)
    dumped_details = json.dumps(details)
    assert "data" not in dumped_details
    assert "fromIP" not in dumped_details
    assert details["items"][0]["event"] == "receive"
