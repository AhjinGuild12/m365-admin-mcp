from __future__ import annotations

import json

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.allowlist import EXO_PAGE_SIZE, HARD_CAP, MAILBOX_SCAN_CAP
from exchange_admin_mcp.tools.mailboxes import (
    get_mailbox,
    list_mailbox_folder_permissions,
    list_mailboxes,
)
from tests.conftest import FakeExo

SECRET_GUID = "drop-me"


def _row(kind: str, index: int) -> dict:
    return {
        "DisplayName": f"Box {index}",
        "PrimarySmtpAddress": f"box{index}@contoso.com",
        "RecipientTypeDetails": kind,
        "EmailAddresses": [f"SMTP:box{index}@contoso.com"],
        "MaxSendSize": "35 MB",
        "GrantSendOnBehalfTo": ["delegate@contoso.com"],
        "Identity": f"CN=Box {index}",
        "Id": SECRET_GUID,
        "ExternalDirectoryObjectId": SECRET_GUID,
        "Guid": SECRET_GUID,
    }


def test_list_shared_mailboxes_filters_locally() -> None:
    pages = [_row("UserMailbox", 1), _row("SharedMailbox", 2), _row("RoomMailbox", 3)]
    client = FakeExo(pages={"Mailbox": pages})
    body = list_mailboxes(client, recipient_type="shared", top=5)
    call = client.calls[0]
    assert call["endpoint"] == "Mailbox"
    assert call["cmdlet"] == "Get-Mailbox"
    assert call["params"] == {"ResultSize": EXO_PAGE_SIZE}
    assert body["items_scanned"] == 3
    assert [item["PrimarySmtpAddress"] for item in body["items"]] == ["box2@contoso.com"]
    dumped = json.dumps(body)
    assert "Identity" not in dumped
    assert "ExternalDirectoryObjectId" not in dumped
    assert SECRET_GUID not in dumped
    assert body["items"][0]["GrantSendOnBehalfTo"] == ["delegate@contoso.com"]


def test_top_above_cap_and_unknown_type_make_zero_calls() -> None:
    client = FakeExo()
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        list_mailboxes(client, top=HARD_CAP + 1)
    with pytest.raises(SanitizedGraphError, match="invalid_recipient_type"):
        list_mailboxes(client, recipient_type="workspace")
    assert client.calls == []


def test_scan_cap_reports_truncated() -> None:
    rows = [_row("UserMailbox", i) for i in range(MAILBOX_SCAN_CAP)]
    client = FakeExo(pages={"Mailbox": rows})
    body = list_mailboxes(client, recipient_type="shared", top=5)
    assert body["truncated"] is True
    assert body["stop_reason"] == "scan_cap"
    assert body["items"] == []
    assert body["items_scanned"] == MAILBOX_SCAN_CAP


def test_folder_identity_and_anchor() -> None:
    client = FakeExo(
        pages={
            "MailboxFolderPermission": [
                {
                    "FolderName": "Reports",
                    "User": "ada@contoso.com",
                    "AccessRights": ["Reviewer"],
                    "Identity": "alex@contoso.com:\\Inbox\\Reports",
                    "IsValid": True,
                }
            ]
        }
    )
    body = list_mailbox_folder_permissions(
        client, mailbox="alex@contoso.com", folder_path="Inbox\\Reports", top=10
    )
    call = client.calls[0]
    assert call["endpoint"] == "MailboxFolderPermission"
    assert call["cmdlet"] == "Get-MailboxFolderPermission"
    assert call["params"]["Identity"] == "alex@contoso.com:\\Inbox\\Reports"
    assert call["anchor"] == "AAD-SMTP:alex@contoso.com"
    assert body["items"][0]["User"] == "ada@contoso.com"
    assert "Identity" not in json.dumps(body)
    assert "IsValid" not in json.dumps(body)


def test_bad_folder_path_makes_zero_calls() -> None:
    client = FakeExo()
    with pytest.raises(SanitizedGraphError, match="invalid_folder_path"):
        list_mailbox_folder_permissions(client, mailbox="alex@contoso.com", folder_path="Inbox:Secret")
    with pytest.raises(SanitizedGraphError, match="invalid_folder_path"):
        list_mailbox_folder_permissions(client, mailbox="alex@contoso.com", folder_path="\\Inbox")
    assert client.calls == []


def test_delegate_display_names_and_parameter_unavailable() -> None:
    client = FakeExo(
        pages={
            "Mailbox": [
                {
                    "DisplayName": "Alex",
                    "PrimarySmtpAddress": "alex@contoso.com",
                    "RecipientTypeDetails": "UserMailbox",
                    "GrantSendOnBehalfTo": ["ada@contoso.com"],
                    "GrantSendOnBehalfToWithDisplayNames": [
                        {"DisplayName": "Ada", "PrimarySmtpAddress": "ada@contoso.com"}
                    ],
                }
            ]
        }
    )
    body = get_mailbox(client, identity="alex@contoso.com", include_delegate_names=True)
    assert client.calls[0]["params"]["IncludeGrantSendOnBehalfToWithDisplayNames"] is True
    assert client.calls[0]["anchor"] == "AAD-SMTP:alex@contoso.com"
    assert body["items"][0]["GrantSendOnBehalfToWithDisplayNames"][0]["DisplayName"] == "Ada"

    err = SanitizedGraphError("4xx graph_error", status_class="4xx")
    err.status_code = 400  # type: ignore[attr-defined]
    failing = FakeExo(errors={"Mailbox": err})
    with pytest.raises(SanitizedGraphError, match="parameter_unavailable"):
        get_mailbox(failing, identity="alex@contoso.com", include_delegate_names=True)
