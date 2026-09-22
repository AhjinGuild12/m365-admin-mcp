"""Sign-in queries. IP/location fields are never returned (R5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from entra_mcp.allowlist import (
    APPLIED_CA_POLICY_FIELDS,
    SIGNIN_DEFAULT_TOP,
    SIGNIN_FIELDS,
    SIGNIN_FORBIDDEN_KEYS,
    SIGNIN_HARD_CAP,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project, strip_keys
from entra_mcp.graph_client import (
    GraphClient,
    encode_path_segment,
    escape_odata_string,
    is_guid,
)


def _clamp_top(top: int | None) -> int:
    bound = SIGNIN_DEFAULT_TOP if top is None else top
    if bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    if bound > SIGNIN_HARD_CAP:
        raise SanitizedGraphError("signin_cap_exceeded", status_class="4xx")
    return bound


def _utc_window(days: int) -> tuple[str, str]:
    if days < 1:
        raise SanitizedGraphError("invalid_days", status_class="4xx")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _select_fields(include_ca_result: bool) -> str:
    fields = list(SIGNIN_FIELDS)
    if include_ca_result:
        fields.append("appliedConditionalAccessPolicies")
    return ",".join(fields)


def _project_applied_ca(values: Any) -> list[dict[str, Any]]:
    out = []
    if not isinstance(values, list):
        return out
    for item in values:
        if not isinstance(item, dict):
            continue
        cleaned = strip_keys(item, SIGNIN_FORBIDDEN_KEYS)
        out.append(project(cleaned, APPLIED_CA_POLICY_FIELDS))
    return out


def _project_signins(
    items: list[dict[str, Any]],
    *,
    include_ca_result: bool = False,
) -> list[dict[str, Any]]:
    out = []
    for item in items:
        cleaned = strip_keys(item, SIGNIN_FORBIDDEN_KEYS)
        row = project(cleaned, SIGNIN_FIELDS)
        if include_ca_result:
            row["appliedConditionalAccessPolicies"] = _project_applied_ca(
                cleaned.get("appliedConditionalAccessPolicies")
            )
        out.append(row)
    return out


def _app_id_clause(app_id: str | None) -> str:
    if not app_id:
        return ""
    if not is_guid(app_id):
        raise SanitizedGraphError("invalid_app_id", status_class="4xx")
    return f" and appId eq '{escape_odata_string(app_id)}'"


def list_user_signins(
    client: GraphClient,
    user: str,
    *,
    days: int = 1,
    top: int | None = None,
    app_id: str | None = None,
    include_ca_result: bool = False,
) -> dict[str, Any]:
    bound = _clamp_top(top)
    start, end = _utc_window(days)
    user_path = f"/users/{encode_path_segment(user)}"
    profile = client.get(user_path, params={"$select": "id,userPrincipalName"})
    user_id = str(profile.get("id") or "")
    if not user_id:
        raise SanitizedGraphError("4xx graph_error", status_class="4xx")
    filt = (
        f"userId eq '{escape_odata_string(user_id)}' and "
        f"createdDateTime ge {start} and createdDateTime lt {end} and "
        f"isInteractive eq true"
        f"{_app_id_clause(app_id)}"
    )
    items = client.collect_page(
        "/auditLogs/signIns",
        params={
            "$filter": filt,
            "$select": _select_fields(include_ca_result),
            "$top": str(bound),
        },
        item_cap=bound,
    )
    result = {
        "signins": _project_signins(items, include_ca_result=include_ca_result),
        "include_ca_result": include_ca_result,
        "window_start_utc": start,
        "window_end_utc": end,
        "interactive_only": True,
        "interactive_user_signins_to_app": bool(app_id),
    }
    if app_id:
        result["app_id"] = app_id
    return result


def list_recent_signins(
    client: GraphClient,
    *,
    days: int = 1,
    top: int | None = None,
    app_id: str | None = None,
    include_ca_result: bool = False,
) -> dict[str, Any]:
    bound = _clamp_top(top)
    start, end = _utc_window(days)
    filt = (
        f"createdDateTime ge {start} and createdDateTime lt {end} and "
        f"isInteractive eq true"
        f"{_app_id_clause(app_id)}"
    )
    items = client.collect_page(
        "/auditLogs/signIns",
        params={
            "$filter": filt,
            "$select": _select_fields(include_ca_result),
            "$top": str(bound),
        },
        item_cap=bound,
    )
    result = {
        "signins": _project_signins(items, include_ca_result=include_ca_result),
        "include_ca_result": include_ca_result,
        "window_start_utc": start,
        "window_end_utc": end,
        "interactive_only": True,
        "interactive_user_signins_to_app": bool(app_id),
    }
    if app_id:
        result["app_id"] = app_id
    return result


def get_signin(
    client: GraphClient,
    signin_id: str,
    *,
    include_ca_result: bool = False,
) -> dict[str, Any]:
    if not signin_id:
        raise SanitizedGraphError("invalid_signin_id", status_class="4xx")
    data = client.get(
        f"/auditLogs/signIns/{encode_path_segment(signin_id)}",
        params={"$select": _select_fields(include_ca_result)},
    )
    projected = _project_signins([data], include_ca_result=include_ca_result)
    return projected[0] if projected else {}
