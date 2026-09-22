"""Mailbox, delegate, and folder-permission reads on the Admin API."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.allowlist import (
    ALLOWED_RECIPIENT_TYPES,
    EXO_PAGE_SIZE,
    MAILBOX_FIELDS,
    MAILBOX_SCAN_CAP,
)
from exchange_admin_mcp.exo_client import ExoAdminApiClient, fetch_one_admin_api, smtp_anchor
from exchange_admin_mcp.schemas import FOLDER_PERMISSION_SCHEMA, MAILBOX_SCHEMA
from exchange_admin_mcp.tools._common import (
    clamp_top,
    collect_admin,
    compose_folder_identity,
    finalize,
    validate_smtp_address,
)

_MAILBOX_SELECT = ",".join(MAILBOX_FIELDS)


def list_mailboxes(
    client: ExoAdminApiClient,
    *,
    recipient_type: str = "all",
    top: int | None = None,
) -> dict[str, Any]:
    """Mailboxes whose recipient type matches. Filtering is local; the cmdlet has no type filter."""
    bound = clamp_top(top)
    if recipient_type != "all" and recipient_type not in ALLOWED_RECIPIENT_TYPES:
        raise SanitizedGraphError("invalid_recipient_type", status_class="4xx")
    wanted = None if recipient_type == "all" else ALLOWED_RECIPIENT_TYPES[recipient_type]

    def keep(raw: dict[str, Any]) -> bool:
        if wanted is None:
            return True
        return raw.get("RecipientTypeDetails") == wanted

    body = collect_admin(
        client,
        endpoint="Mailbox",
        cmdlet="Get-Mailbox",
        params={"ResultSize": EXO_PAGE_SIZE},
        anchor=None,
        schema=MAILBOX_SCHEMA,
        item_cap=bound,
        keep=keep,
        scan_cap=MAILBOX_SCAN_CAP,
        select=_MAILBOX_SELECT,
    )
    return finalize(body)


def get_mailbox(
    client: ExoAdminApiClient,
    *,
    identity: str,
    include_delegate_names: bool = False,
) -> dict[str, Any]:
    """One mailbox. Display names for Send on behalf are requested only when asked."""
    if not isinstance(identity, str) or identity.strip() == "":
        raise SanitizedGraphError("parameter_required", status_class="4xx")
    params: dict[str, Any] = {"Identity": identity}
    anchor = None
    if _looks_smtp(identity):
        anchor = smtp_anchor(identity)
    if include_delegate_names:
        params["IncludeGrantSendOnBehalfToWithDisplayNames"] = True
    try:
        body = fetch_one_admin_api(
            client,
            "Mailbox",
            "Get-Mailbox",
            params,
            MAILBOX_SCHEMA,
            anchor,
            select=_MAILBOX_SELECT,
        )
    except SanitizedGraphError as exc:
        status = getattr(exc, "status_code", None)
        if include_delegate_names and status == 400:
            raise SanitizedGraphError("parameter_unavailable", status_class="4xx") from None
        raise
    return finalize(body)


def list_mailbox_folder_permissions(
    client: ExoAdminApiClient,
    *,
    mailbox: str,
    folder_path: str = "Calendar",
    top: int | None = None,
) -> dict[str, Any]:
    """Permission entries on one mailbox folder. The default folder is Calendar."""
    bound = clamp_top(top)
    identity = compose_folder_identity(mailbox, folder_path)
    address = validate_smtp_address(mailbox)
    body = collect_admin(
        client,
        endpoint="MailboxFolderPermission",
        cmdlet="Get-MailboxFolderPermission",
        params={"Identity": identity, "ResultSize": EXO_PAGE_SIZE},
        anchor=smtp_anchor(address),
        schema=FOLDER_PERMISSION_SCHEMA,
        item_cap=bound,
        select="FolderName,User,AccessRights,SharingPermissionFlags",
    )
    return finalize(body)


def _looks_smtp(value: str) -> bool:
    return "@" in value and ":" not in value and " " not in value
