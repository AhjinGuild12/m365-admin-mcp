"""Accepted domains and organization configuration on the Admin API."""

from __future__ import annotations

from typing import Any

from exchange_admin_mcp.allowlist import ACCEPTED_DOMAIN_FIELDS, EXO_PAGE_SIZE
from exchange_admin_mcp.exo_client import ExoAdminApiClient, fetch_one_admin_api
from exchange_admin_mcp.schemas import ACCEPTED_DOMAIN_SCHEMA, ORGANIZATION_CONFIG_SCHEMA
from exchange_admin_mcp.tools._common import clamp_top, collect_admin, finalize

_DOMAIN_SELECT = ",".join(ACCEPTED_DOMAIN_FIELDS)
_ORG_SELECT = "Name,MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled,MailTipsLargeAudienceThreshold"


def list_accepted_domains(
    client: ExoAdminApiClient, *, top: int | None = None
) -> dict[str, Any]:
    """Accepted domains. Identity is optional and is not sent by this tool."""
    bound = clamp_top(top)
    body = collect_admin(
        client,
        endpoint="AcceptedDomain",
        cmdlet="Get-AcceptedDomain",
        params={"ResultSize": EXO_PAGE_SIZE},
        anchor=None,
        schema=ACCEPTED_DOMAIN_SCHEMA,
        item_cap=bound,
        select=_DOMAIN_SELECT,
    )
    return finalize(body)


def get_organization_config(client: ExoAdminApiClient) -> dict[str, Any]:
    """MailTips settings from Get-OrganizationConfig. No cmdlet parameters are sent."""
    body = fetch_one_admin_api(
        client,
        "OrganizationConfig",
        "Get-OrganizationConfig",
        None,
        ORGANIZATION_CONFIG_SCHEMA,
        None,
        select=_ORG_SELECT,
    )
    return finalize(body)
