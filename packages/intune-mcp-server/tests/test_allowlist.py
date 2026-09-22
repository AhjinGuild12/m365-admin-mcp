from __future__ import annotations

import pytest

from intune_mcp.allowlist import (
    MANAGED_DEVICE_FIELDS,
    MANAGED_DEVICE_SCHEMA_PROPERTIES,
    TOOL_NAMES,
    validate_select,
)
from intune_mcp.schemas import TOOL_SCHEMAS
from m365_mcp_kernel.errors import SanitizedGraphError


def test_tool_table_has_thirteen_names() -> None:
    assert len(TOOL_NAMES) == 13
    assert len(set(TOOL_NAMES)) == 13
    assert "get_configuration_profile_status" not in TOOL_NAMES


def test_every_tool_has_a_nested_schema() -> None:
    assert set(TOOL_SCHEMAS) == set(TOOL_NAMES)


def test_managed_device_select_is_documented_schema() -> None:
    validate_select(MANAGED_DEVICE_FIELDS)
    assert set(MANAGED_DEVICE_FIELDS) <= MANAGED_DEVICE_SCHEMA_PROPERTIES


def test_ownerType_is_rejected_as_unknown_select() -> None:
    with pytest.raises(SanitizedGraphError, match="unknown_select_property"):
        validate_select(("id", "ownerType"))


def test_forbidden_keys_are_schema_properties_but_not_selected() -> None:
    assert "activationLockBypassCode" in MANAGED_DEVICE_SCHEMA_PROPERTIES
    assert "activationLockBypassCode" not in MANAGED_DEVICE_FIELDS
    assert "imei" not in MANAGED_DEVICE_FIELDS
    assert "notes" not in MANAGED_DEVICE_FIELDS
