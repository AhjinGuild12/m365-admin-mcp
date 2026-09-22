"""Collectors, window checks, and identifier stripping for Exchange tools."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient, encode_path_segment
from m365_mcp_kernel.schema import project_schema, strip_keys

from exchange_admin_mcp.allowlist import (
    DEFAULT_TOP,
    FORBIDDEN_KEYS,
    GRAPH_PATH_PREFIXES,
    HARD_CAP,
    MESSAGE_TRACE_MAX_AGE_DAYS,
    MESSAGE_TRACE_MAX_WINDOW_DAYS,
)

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SMTP = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_WINDOW = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clamp_top(top: int | None) -> int:
    bound = DEFAULT_TOP if top is None else top
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    if bound > HARD_CAP:
        raise SanitizedGraphError("top_cap_exceeded", status_class="4xx")
    return bound


def require_guid(value: str) -> str:
    if not isinstance(value, str) or _GUID.fullmatch(value) is None:
        raise SanitizedGraphError("guid_required", status_class="4xx")
    return value


def validate_smtp_address(value: str) -> str:
    if not isinstance(value, str) or ":" in value or _SMTP.fullmatch(value) is None:
        raise SanitizedGraphError("invalid_smtp_address", status_class="4xx")
    return value


def compose_folder_identity(mailbox: str, folder_path: str) -> str:
    """``<mailbox>:\\<FolderPath>``. The folder path may not contain ``:`` or start with ``\\``."""
    address = validate_smtp_address(mailbox)
    if (
        not isinstance(folder_path, str)
        or folder_path == ""
        or folder_path.startswith("\\")
        or ":" in folder_path
    ):
        raise SanitizedGraphError("invalid_folder_path", status_class="4xx")
    segments = folder_path.split("\\")
    if any(segment == "" for segment in segments):
        raise SanitizedGraphError("invalid_folder_path", status_class="4xx")
    return f"{address}:\\" + "\\".join(segments)


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or _WINDOW.fullmatch(value) is None:
        raise SanitizedGraphError("invalid_window", status_class="4xx")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_trace_window(
    start: str | None,
    end: str | None,
    *,
    now: datetime | None = None,
) -> tuple[str, str] | None:
    """Return the formatted bounds, or None when the API's 48-hour default applies."""
    if start is None and end is None:
        return None
    if start is None or end is None:
        raise SanitizedGraphError("invalid_window", status_class="4xx")
    start_at = _parse_utc(start)
    end_at = _parse_utc(end)
    if start_at > end_at:
        raise SanitizedGraphError("invalid_window", status_class="4xx")
    clock = now or utc_now()
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    if end_at > clock:
        raise SanitizedGraphError("window_in_future", status_class="4xx")
    if end_at - start_at > timedelta(days=MESSAGE_TRACE_MAX_WINDOW_DAYS):
        raise SanitizedGraphError("window_too_long", status_class="4xx")
    if start_at < clock - timedelta(days=MESSAGE_TRACE_MAX_AGE_DAYS):
        raise SanitizedGraphError("window_too_old", status_class="4xx")
    return (
        start_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def assert_graph_prefix(path: str) -> None:
    if not any(path.startswith(prefix) for prefix in GRAPH_PATH_PREFIXES):
        raise SanitizedGraphError("path_not_allowed", status_class="4xx")
    if "://" in path or path.startswith("http"):
        raise SanitizedGraphError("path_not_allowed", status_class="4xx")


def path_segment(value: str) -> str:
    if not isinstance(value, str) or value == "" or "/" in value or "?" in value:
        raise SanitizedGraphError("invalid_path_segment", status_class="4xx")
    return encode_path_segment(value)


def _envelope(
    items: list[dict[str, Any]],
    *,
    complete: bool,
    truncated: bool,
    scanned: int,
    stop_reason: str | None,
    error_class: str | None,
) -> dict[str, Any]:
    return {
        "items": items,
        "complete": complete,
        "truncated": truncated,
        "items_scanned": scanned,
        "stop_reason": stop_reason,
        "error_class": error_class,
    }


def collect_bounded(
    client: GraphClient,
    path: str,
    params: dict[str, str] | None,
    item_cap: int,
    schema: dict,
    keep: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Page a Graph collection. A first-page error propagates; a later one is partial."""
    assert_graph_prefix(path)
    items: list[dict[str, Any]] = []
    scanned = 0
    stop_reason: str | None = None
    error_class: str | None = None
    truncated = False
    try:
        for raw in client.iter_pages(path, params=params, headers=None):
            if not isinstance(raw, dict):
                continue
            scanned += 1
            projected = project_schema(raw, schema)
            if not isinstance(projected, dict):
                projected = {}
            if keep is None or keep(raw):
                items.append(projected)
            if scanned >= item_cap:
                truncated = True
                stop_reason = "item_cap"
                break
    except SanitizedGraphError as exc:
        if scanned == 0:
            raise
        truncated = True
        message = exc.message or ""
        if "retries_exhausted" in message or "retry_budget_exhausted" in message:
            stop_reason = "throttling_exhausted"
        else:
            stop_reason = "page_error"
        error_class = exc.status_class
    return _envelope(
        items,
        complete=stop_reason is None,
        truncated=truncated,
        scanned=scanned,
        stop_reason=stop_reason,
        error_class=error_class,
    )


def fetch_one(
    client: GraphClient,
    path: str,
    params: dict[str, str] | None,
    schema: dict,
    expected_id: str,
) -> dict[str, Any]:
    assert_graph_prefix(path)
    data = client.get(path, params=params)
    if not isinstance(data, dict) or len(data) == 0:
        raise SanitizedGraphError("not_found", status_class="4xx")
    projected = project_schema(data, schema)
    if not isinstance(projected, dict) or len(projected) == 0:
        raise SanitizedGraphError("not_found", status_class="4xx")
    got = projected.get("id")
    if not isinstance(got, str) or got.casefold() != expected_id.casefold():
        raise SanitizedGraphError("id_mismatch", status_class="4xx")
    return projected


def collect_admin(
    client: Any,
    *,
    endpoint: str,
    cmdlet: str,
    params: dict[str, Any],
    anchor: str | None,
    schema: dict,
    item_cap: int,
    keep: Callable[[dict[str, Any]], bool] | None = None,
    scan_cap: int | None = None,
    select: str | None = None,
) -> dict[str, Any]:
    """Page an Admin API cmdlet. ``scan_cap`` counts rows before ``keep``."""
    items: list[dict[str, Any]] = []
    scanned = 0
    stop_reason: str | None = None
    error_class: str | None = None
    truncated = False
    limit = scan_cap if scan_cap is not None else item_cap
    try:
        for raw in client.iter_rows(
            endpoint, cmdlet, params, anchor=anchor, select=select
        ):
            if not isinstance(raw, dict):
                continue
            scanned += 1
            projected = project_schema(raw, schema)
            if not isinstance(projected, dict):
                projected = {}
            kept = keep is None or keep(raw)
            if kept and len(items) < item_cap:
                items.append(projected)
            if scan_cap is not None and scanned >= scan_cap and len(items) < item_cap:
                truncated = True
                stop_reason = "scan_cap"
                break
            if scan_cap is None and scanned >= limit:
                truncated = True
                stop_reason = "item_cap"
                break
            if kept and len(items) >= item_cap:
                break
    except SanitizedGraphError as exc:
        if scanned == 0:
            raise
        truncated = True
        message = exc.message or ""
        if "retries_exhausted" in message or "retry_budget_exhausted" in message:
            stop_reason = "throttling_exhausted"
        else:
            stop_reason = "page_error"
        error_class = exc.status_class
    return _envelope(
        items,
        complete=stop_reason is None,
        truncated=truncated,
        scanned=scanned,
        stop_reason=stop_reason,
        error_class=error_class,
    )


def finalize(obj: Any) -> Any:
    return strip_keys(obj, FORBIDDEN_KEYS)
