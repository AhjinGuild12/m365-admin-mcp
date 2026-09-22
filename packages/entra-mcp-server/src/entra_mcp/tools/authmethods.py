"""MFA registration report. Uses /reports/authenticationMethods/userRegistrationDetails."""

from __future__ import annotations

from typing import Any

from entra_mcp.allowlist import (
    MAX_SEARCH_TOP,
    MFA_REGISTRATION_FIELDS,
)
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project
from entra_mcp.graph_client import GraphClient

DEFAULT_TOP = 100


def _clamp_top(top: int | None) -> int:
    bound = DEFAULT_TOP if top is None else top
    if bound < 1:
        raise SanitizedGraphError("invalid_top", status_class="4xx")
    return min(bound, MAX_SEARCH_TOP)


def list_mfa_registration(
    client: GraphClient,
    *,
    unregistered_only: bool = True,
    admins_only: bool = False,
    top: int | None = None,
) -> dict[str, Any]:
    bound = _clamp_top(top)
    clauses: list[str] = []
    if unregistered_only:
        clauses.append("isMfaRegistered eq false")
    if admins_only:
        clauses.append("isAdmin eq true")
    params: dict[str, str] = {
        "$select": ",".join(MFA_REGISTRATION_FIELDS),
        "$top": str(bound),
    }
    if clauses:
        params["$filter"] = " and ".join(clauses)
    items = client.collect_page(
        "/reports/authenticationMethods/userRegistrationDetails",
        params=params,
        item_cap=bound,
    )
    return {
        "registrations": [project(item, MFA_REGISTRATION_FIELDS) for item in items],
        "unregistered_only": unregistered_only,
        "admins_only": admins_only,
        "truncated": len(items) >= bound,
    }
