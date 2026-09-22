"""Detected apps, mobile apps (with assignments), Autopilot identities."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.schema import project_then_strip

from intune_mcp.allowlist import (
    APP_CREDENTIAL_FORBIDDEN_KEYS,
    AUTOPILOT_FIELDS,
    DETECTED_APP_FIELDS,
    MOBILE_APP_FIELDS,
)
from intune_mcp.schemas import AUTOPILOT_SCHEMA, DETECTED_APP_SCHEMA, MOBILE_APP_SCHEMA
from intune_mcp.tools._common import bounded_collect, clamp_top

_APP_SELECT = ",".join(name for name in MOBILE_APP_FIELDS if name != "assignments")


def list_detected_apps(
    client: GraphClient,
    *,
    name_prefix: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    bound = clamp_top(top)
    params: dict[str, str] = {"$select": ",".join(DETECTED_APP_FIELDS), "$top": str(bound)}
    if name_prefix:
        escaped = name_prefix.replace("'", "''")
        params["$filter"] = f"startswith(displayName,'{escaped}')"
    collected = bounded_collect(
        client,
        "/deviceManagement/detectedApps",
        params=params,
        item_cap=bound,
        schema=DETECTED_APP_SCHEMA,
    )
    verified = True
    if name_prefix:
        lower = name_prefix.lower()
        verified = all(
            str(item.get("displayName") or "").lower().startswith(lower)
            for item in collected["items"]
        )
    return {
        "apps": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "returned_rows_verified": verified,
        "returned_rows_verified_note": (
            "verification of returned rows, not proof of server-side filtering"
        ),
    }


def list_mobile_apps(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    """List mobile apps. Prefer $expand=assignments; else a second bounded call."""
    bound = clamp_top(top)
    params_expand = {
        "$select": _APP_SELECT,
        "$expand": "assignments",
        "$top": str(bound),
    }
    expand_accepted = True
    try:
        collected = bounded_collect(
            client,
            "/deviceAppManagement/mobileApps",
            params=params_expand,
            item_cap=bound,
            schema=MOBILE_APP_SCHEMA,
            banned=APP_CREDENTIAL_FORBIDDEN_KEYS,
        )
        if collected["stop_reason"] == "page_error" and collected["items_scanned"] == 0:
            expand_accepted = False
    except SanitizedGraphError:
        expand_accepted = False
        collected = {
            "items": [],
            "complete": False,
            "truncated": True,
            "items_scanned": 0,
            "stop_reason": "page_error",
        }
    if not expand_accepted:
        collected = bounded_collect(
            client,
            "/deviceAppManagement/mobileApps",
            params={"$select": _APP_SELECT, "$top": str(bound)},
            item_cap=bound,
            schema=MOBILE_APP_SCHEMA,
            banned=APP_CREDENTIAL_FORBIDDEN_KEYS,
        )
        apps = []
        for app in collected["items"]:
            app_id = str(app.get("id") or "")
            if not app_id:
                apps.append(app)
                continue
            try:
                assigns = client.collect_page(
                    f"/deviceAppManagement/mobileApps/{app_id}/assignments",
                    item_cap=HARD_ASSIGNMENT_CAP,
                )
            except SanitizedGraphError:
                assigns = []
            projected = project_then_strip(
                {**app, "assignments": assigns},
                MOBILE_APP_SCHEMA,
                APP_CREDENTIAL_FORBIDDEN_KEYS,
            )
            apps.append(projected)
        collected = {**collected, "items": apps}
    return {
        "apps": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
        "assignments_expanded": expand_accepted,
    }


HARD_ASSIGNMENT_CAP = 200


def list_autopilot_devices(client: GraphClient, *, top: int | None = None) -> dict[str, Any]:
    bound = clamp_top(top)
    collected = bounded_collect(
        client,
        "/deviceManagement/windowsAutopilotDeviceIdentities",
        params={"$select": ",".join(AUTOPILOT_FIELDS), "$top": str(bound)},
        item_cap=bound,
        schema=AUTOPILOT_SCHEMA,
    )
    return {
        "devices": collected["items"],
        "complete": collected["complete"],
        "truncated": collected["truncated"],
        "items_scanned": collected["items_scanned"],
        "stop_reason": collected["stop_reason"],
    }
