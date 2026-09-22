"""Projection schemas. A parent key never admits arbitrary children."""

from __future__ import annotations

from exchange_admin_mcp.allowlist import (
    ACCEPTED_DOMAIN_FIELDS,
    EMAIL_ACTIVITY_COLUMNS,
    FOLDER_PERMISSION_FIELDS,
    GROUP_MEMBER_FIELDS,
    MAILBOX_FIELDS,
    MAILBOX_USAGE_COLUMNS,
    MESSAGE_TRACE_DETAIL_FIELDS,
    MESSAGE_TRACE_FIELDS,
    ORGANIZATION_CONFIG_FIELDS,
    ROOM_FIELDS,
    ROOM_LIST_FIELDS,
)

_LEAF = True


def _object(fields: tuple[str, ...]) -> dict[str, bool]:
    return {name: _LEAF for name in fields}


def _mailbox() -> dict:
    schema = _object(tuple(name for name in MAILBOX_FIELDS if name not in {
        "EmailAddresses",
        "GrantSendOnBehalfTo",
        "GrantSendOnBehalfToWithDisplayNames",
    }))
    schema["EmailAddresses"] = [_LEAF]
    schema["GrantSendOnBehalfTo"] = [_LEAF]
    schema["GrantSendOnBehalfToWithDisplayNames"] = [
        {"DisplayName": _LEAF, "PrimarySmtpAddress": _LEAF}
    ]
    return schema


MESSAGE_TRACE_SCHEMA: dict = _object(MESSAGE_TRACE_FIELDS)
MESSAGE_TRACE_DETAIL_SCHEMA: dict = _object(MESSAGE_TRACE_DETAIL_FIELDS)
MAILBOX_SCHEMA: dict = _mailbox()
FOLDER_PERMISSION_SCHEMA: dict = {
    "FolderName": _LEAF,
    "User": _LEAF,
    "AccessRights": [_LEAF],
    "SharingPermissionFlags": [_LEAF],
}
GROUP_MEMBER_SCHEMA: dict = _object(GROUP_MEMBER_FIELDS)
ACCEPTED_DOMAIN_SCHEMA: dict = _object(ACCEPTED_DOMAIN_FIELDS)
ORGANIZATION_CONFIG_SCHEMA: dict = _object(ORGANIZATION_CONFIG_FIELDS)
ROOM_SCHEMA: dict = {
    **_object(tuple(name for name in ROOM_FIELDS if name != "tags")),
    "tags": [_LEAF],
}
ROOM_LIST_SCHEMA: dict = _object(ROOM_LIST_FIELDS)
MAILBOX_USAGE_SCHEMA: dict = _object(MAILBOX_USAGE_COLUMNS)
EMAIL_ACTIVITY_SCHEMA: dict = _object(EMAIL_ACTIVITY_COLUMNS)

# Folder permission fields stay aligned with the allowlist tuple.
assert set(FOLDER_PERMISSION_SCHEMA) == set(FOLDER_PERMISSION_FIELDS)

SCHEMA_BY_NAME: dict[str, dict] = {
    "message_trace": MESSAGE_TRACE_SCHEMA,
    "message_trace_detail": MESSAGE_TRACE_DETAIL_SCHEMA,
    "mailbox": MAILBOX_SCHEMA,
    "folder_permission": FOLDER_PERMISSION_SCHEMA,
    "group_member": GROUP_MEMBER_SCHEMA,
    "accepted_domain": ACCEPTED_DOMAIN_SCHEMA,
    "organization_config": ORGANIZATION_CONFIG_SCHEMA,
    "room": ROOM_SCHEMA,
    "room_list": ROOM_LIST_SCHEMA,
    "mailbox_usage": MAILBOX_USAGE_SCHEMA,
    "email_activity": EMAIL_ACTIVITY_SCHEMA,
}
