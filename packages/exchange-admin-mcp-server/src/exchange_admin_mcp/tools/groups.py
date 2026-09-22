"""Distribution-group membership on the Admin API. Room lists are distribution groups."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.allowlist import EXO_PAGE_SIZE, GROUP_MEMBER_FIELDS
from exchange_admin_mcp.exo_client import ExoAdminApiClient
from exchange_admin_mcp.schemas import GROUP_MEMBER_SCHEMA
from exchange_admin_mcp.tools._common import clamp_top, collect_admin, finalize

_SELECT = ",".join(GROUP_MEMBER_FIELDS)


def _identity(value: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise SanitizedGraphError("parameter_required", status_class="4xx")
    return value


def _members(
    client: ExoAdminApiClient,
    *,
    endpoint: str,
    cmdlet: str,
    identity: str,
    top: int | None,
) -> dict[str, Any]:
    bound = clamp_top(top)
    body = collect_admin(
        client,
        endpoint=endpoint,
        cmdlet=cmdlet,
        params={"Identity": _identity(identity), "ResultSize": EXO_PAGE_SIZE},
        anchor=None,
        schema=GROUP_MEMBER_SCHEMA,
        item_cap=bound,
        select=_SELECT,
    )
    return finalize(body)


def list_distribution_group_members(
    client: ExoAdminApiClient, *, identity: str, top: int | None = None
) -> dict[str, Any]:
    """Members of one distribution group. A room list is a distribution group."""
    return _members(
        client,
        endpoint="DistributionGroupMember",
        cmdlet="Get-DistributionGroupMember",
        identity=identity,
        top=top,
    )


def list_dynamic_distribution_group_members(
    client: ExoAdminApiClient, *, identity: str, top: int | None = None
) -> dict[str, Any]:
    """Members of one dynamic distribution group."""
    return _members(
        client,
        endpoint="DynamicDistributionGroupMember",
        cmdlet="Get-DynamicDistributionGroupMember",
        identity=identity,
        top=top,
    )
