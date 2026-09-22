"""Nested schemas. A parent key never admits arbitrary children."""

from __future__ import annotations

from teams_admin_mcp.allowlist import (
    APP_DEFINITION_FIELDS,
    ASSIGNED_LABEL_FIELDS,
    CATALOG_APP_FIELDS,
    CATALOG_DEFINITION_FIELDS,
    CHANNEL_FIELDS,
    DISCOVERY_SETTINGS_FIELDS,
    FUN_SETTINGS_FIELDS,
    GUEST_SETTINGS_FIELDS,
    JOINED_TEAM_FIELDS,
    LABEL_SCALAR_FIELDS,
    MEMBER_SETTINGS_FIELDS,
    MESSAGING_SETTINGS_FIELDS,
    MODERATION_FIELDS,
    POLICY_ASSIGNMENT_FIELDS,
    REPORT_COLUMNS,
    SUMMARY_FIELDS,
    TEAM_LIST_FIELDS,
    TEAM_SCALAR_FIELDS,
    USER_CONFIG_FIELDS,
)

_LEAF = True


def _object(fields: tuple[str, ...]) -> dict[str, bool]:
    return {name: _LEAF for name in fields}


TEAM_LIST_SCHEMA: dict = _object(TEAM_LIST_FIELDS)
JOINED_TEAM_SCHEMA: dict = _object(JOINED_TEAM_FIELDS)
CHANNEL_SCHEMA: dict = _object(CHANNEL_FIELDS)
REPORT_ROW_SCHEMA: dict = _object(REPORT_COLUMNS)

MEMBER_SCHEMA: dict = {
    "id": _LEAF,
    "displayName": _LEAF,
    "userId": _LEAF,
    "email": _LEAF,
    "roles": [_LEAF],
}

TEAM_SCHEMA: dict = {
    **_object(TEAM_SCALAR_FIELDS),
    "memberSettings": _object(MEMBER_SETTINGS_FIELDS),
    "guestSettings": _object(GUEST_SETTINGS_FIELDS),
    "messagingSettings": _object(MESSAGING_SETTINGS_FIELDS),
    "funSettings": _object(FUN_SETTINGS_FIELDS),
    "discoverySettings": _object(DISCOVERY_SETTINGS_FIELDS),
    "summary": _object(SUMMARY_FIELDS),
}

LABEL_SCHEMA: dict = {
    **_object(LABEL_SCALAR_FIELDS),
    "assignedLabels": [_object(ASSIGNED_LABEL_FIELDS)],
}

CHANNEL_DETAIL_SCHEMA: dict = {
    **CHANNEL_SCHEMA,
    "moderationSettings": _object(MODERATION_FIELDS),
}

INSTALLED_APP_SCHEMA: dict = {
    "id": _LEAF,
    "teamsAppDefinition": _object(APP_DEFINITION_FIELDS),
}

CATALOG_APP_SCHEMA: dict = {
    **_object(CATALOG_APP_FIELDS),
    "appDefinitions": [_object(CATALOG_DEFINITION_FIELDS)],
}

USER_CONFIG_SCHEMA: dict = {
    **{name: _LEAF for name in USER_CONFIG_FIELDS if name != "featureTypes"},
    "featureTypes": [_LEAF],
    "effectivePolicyAssignments": [
        {
            "policyType": _LEAF,
            "policyAssignment": _object(POLICY_ASSIGNMENT_FIELDS),
        }
    ],
}

SCHEMA_BY_NAME: dict[str, dict] = {
    "team_list": TEAM_LIST_SCHEMA,
    "team": TEAM_SCHEMA,
    "labels": LABEL_SCHEMA,
    "joined_team": JOINED_TEAM_SCHEMA,
    "member": MEMBER_SCHEMA,
    "channel": CHANNEL_SCHEMA,
    "channel_detail": CHANNEL_DETAIL_SCHEMA,
    "installed_app": INSTALLED_APP_SCHEMA,
    "catalog_app": CATALOG_APP_SCHEMA,
    "user_config": USER_CONFIG_SCHEMA,
    "report_row": REPORT_ROW_SCHEMA,
}
