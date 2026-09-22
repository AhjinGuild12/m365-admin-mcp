"""Per-tool nested schemas. A parent key never admits arbitrary children."""

from __future__ import annotations

from spo_admin_mcp.allowlist import (
    ACCESS_SCALAR_FIELDS,
    COUNTS_FIELDS,
    DETAIL_FIELDS,
    IDLE_SESSION_FIELDS,
    LIST_FIELDS,
    SHARING_FIELDS,
    SITE_CREATION_FIELDS,
    STORAGE_FIELDS,
    TENANT_SETTING_NAMES,
)

_LEAF = True


def _field_schema(name: str):
    if name == "idleSessionSignOut":
        return {child: _LEAF for child in IDLE_SESSION_FIELDS}
    if name in LIST_FIELDS:
        return [_LEAF]
    return _LEAF


def _object(names: tuple[str, ...]) -> dict:
    return {name: _field_schema(name) for name in names}


SHARING_SCHEMA: dict = _object(SHARING_FIELDS)
ACCESS_SCHEMA: dict = _object(ACCESS_SCALAR_FIELDS + ("idleSessionSignOut",))
SITE_CREATION_SCHEMA: dict = _object(SITE_CREATION_FIELDS)
TENANT_SETTINGS_SCHEMA: dict = _object(TENANT_SETTING_NAMES)
DETAIL_ROW_SCHEMA: dict = _object(DETAIL_FIELDS)
STORAGE_ROW_SCHEMA: dict = _object(STORAGE_FIELDS)
COUNTS_ROW_SCHEMA: dict = _object(COUNTS_FIELDS)
