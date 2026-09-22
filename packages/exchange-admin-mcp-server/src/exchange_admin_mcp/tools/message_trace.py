"""Message trace on Microsoft Graph v1.0 through the kernel client."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient, encode_path_segment, escape_odata_string, odata_eq

from exchange_admin_mcp.schemas import MESSAGE_TRACE_DETAIL_SCHEMA, MESSAGE_TRACE_SCHEMA
from exchange_admin_mcp.tools._common import (
    assert_graph_prefix,
    clamp_top,
    collect_bounded,
    finalize,
    require_guid,
    validate_smtp_address,
    validate_trace_window,
)

_TRACE = "/admin/exchange/tracing/messageTraces"


def _filter(
    *,
    sender: str | None,
    recipient: str | None,
    message_id: str | None,
    status: str | None,
    subject: str | None,
    window: tuple[str, str] | None,
) -> str | None:
    parts: list[str] = []
    if sender is not None:
        parts.append(odata_eq("senderAddress", validate_smtp_address(sender)))
    if recipient is not None:
        parts.append(odata_eq("recipientAddress", validate_smtp_address(recipient)))
    if message_id is not None:
        if not isinstance(message_id, str) or message_id.strip() == "":
            raise SanitizedGraphError("invalid_message_id", status_class="4xx")
        parts.append(odata_eq("messageId", message_id))
    if status is not None:
        if not isinstance(status, str) or status.strip() == "":
            raise SanitizedGraphError("invalid_status", status_class="4xx")
        parts.append(odata_eq("status", status))
    if subject is not None:
        if not isinstance(subject, str):
            raise SanitizedGraphError("invalid_subject", status_class="4xx")
        parts.append(f"contains(subject, '{escape_odata_string(subject)}')")
    if window is not None:
        start, end = window
        parts.append(f"receivedDateTime ge {start} and receivedDateTime le {end}")
    if not parts:
        return None
    return " and ".join(parts)


def list_message_traces(
    client: GraphClient,
    *,
    sender: str | None = None,
    recipient: str | None = None,
    message_id: str | None = None,
    status: str | None = None,
    subject: str | None = None,
    start: str | None = None,
    end: str | None = None,
    top: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Message-trace summaries from Graph v1.0. IP addresses are never returned."""
    bound = clamp_top(top)
    window = validate_trace_window(start, end, now=now)
    filt = _filter(
        sender=sender,
        recipient=recipient,
        message_id=message_id,
        status=status,
        subject=subject,
        window=window,
    )
    params: dict[str, str] = {"$top": str(bound)}
    if filt is not None:
        params["$filter"] = filt
    assert_graph_prefix(_TRACE)
    body = collect_bounded(client, _TRACE, params, bound, MESSAGE_TRACE_SCHEMA)
    body["window"] = "default_48h" if window is None else {"start": window[0], "end": window[1]}
    return finalize(body)


def get_message_trace_details(
    client: GraphClient,
    *,
    trace_id: str,
    recipient: str,
    top: int | None = None,
) -> dict[str, Any]:
    """Per-recipient processing events for one trace. The detail data blob is dropped."""
    bound = clamp_top(top)
    guid = require_guid(trace_id)
    if not isinstance(recipient, str) or recipient.strip() == "":
        raise SanitizedGraphError("invalid_smtp_address", status_class="4xx")
    encoded = encode_path_segment(escape_odata_string(recipient))
    path = (
        f"{_TRACE}/{guid}/getDetailsByRecipient(recipientAddress='{encoded}')"
    )
    assert_graph_prefix(path)
    params = {"$top": str(bound)}
    return finalize(collect_bounded(client, path, params, bound, MESSAGE_TRACE_DETAIL_SCHEMA))
