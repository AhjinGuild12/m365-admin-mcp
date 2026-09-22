"""Collectors, path encoding, and identifier stripping for Teams tools."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient, encode_path_segment
from m365_mcp_kernel.schema import project_schema, strip_keys

from teams_admin_mcp.allowlist import DEFAULT_TOP, FORBIDDEN_KEYS, HARD_CAP

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def clamp_top(top: int | None) -> int:
    bound = DEFAULT_TOP if top is None else top
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    if bound > HARD_CAP:
        raise SanitizedGraphError("top_cap_exceeded", status_class="4xx")
    return bound


def path_segment(value: str) -> str:
    """Reject a segment that contains ``/`` or ``?``. ``#`` is percent-encoded."""
    if not isinstance(value, str) or value == "" or "/" in value or "?" in value:
        raise SanitizedGraphError("invalid_path_segment", status_class="4xx")
    return encode_path_segment(value)


def require_guid(value: str) -> str:
    if not isinstance(value, str) or _GUID.fullmatch(value) is None:
        raise SanitizedGraphError("guid_required", status_class="4xx")
    return value


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
    annotate: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Page a collection. A first-page error propagates; a later-page error is partial."""
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
            if annotate is not None:
                projected = annotate(raw, projected)
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
    """One resource. Empty body is ``not_found``. A different id is ``id_mismatch``."""
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


def classify_member_origin(row: dict[str, Any], home_tenant_id: str | None) -> str:
    """Where the member account is homed. Not the tenant external-access policy."""
    if not isinstance(row, dict) or "tenantId" not in row:
        return "unknown"
    tenant = row.get("tenantId")
    if not isinstance(tenant, str) or tenant.strip() == "":
        return "unknown"
    home = (home_tenant_id or "").strip()
    if home and tenant.casefold() == home.casefold():
        return "home"
    return "external"


def finalize(obj: Any) -> Any:
    return strip_keys(obj, FORBIDDEN_KEYS)


def identity_visibility(rows: list[dict[str, Any]], principal_column: str | None) -> tuple[str, str]:
    """Disclosed inference. The team activity report has no user principal column."""
    del rows, principal_column
    return "unknown", "team activity report has no user principal column"
