"""Shared bounded-list helpers for Intune tools (KTD11)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.schema import project_then_strip

from intune_mcp.allowlist import DEFAULT_TOP, HARD_CAP, MANAGED_DEVICE_FORBIDDEN_KEYS


def clamp_top(top: int | None) -> int:
    bound = DEFAULT_TOP if top is None else top
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    if bound > HARD_CAP:
        raise SanitizedGraphError("top_cap_exceeded", status_class="4xx")
    return bound


def bounded_collect(
    client: GraphClient,
    path: str,
    *,
    params: dict[str, str] | None,
    item_cap: int,
    schema: dict,
    banned: frozenset[str] | None = None,
    headers: dict[str, str] | None = None,
    keep: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    scanned = 0
    stop_reason: str | None = None
    truncated = False
    try:
        for raw in client.iter_pages(path, params=params, headers=headers, item_cap=item_cap):
            scanned += 1
            if keep is None or keep(raw):
                items.append(project_then_strip(raw, schema, banned))
            if scanned >= item_cap:
                truncated = True
                stop_reason = "item_cap"
                break
    except SanitizedGraphError as exc:
        truncated = True
        if "retries_exhausted" in exc.message:
            stop_reason = "throttling_exhausted"
        else:
            stop_reason = "page_error"
    complete = stop_reason is None
    return {
        "items": items,
        "complete": complete,
        "truncated": truncated,
        "items_scanned": scanned,
        "stop_reason": stop_reason,
    }


def device_banned() -> frozenset[str]:
    return MANAGED_DEVICE_FORBIDDEN_KEYS
