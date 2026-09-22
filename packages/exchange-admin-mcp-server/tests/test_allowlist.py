from __future__ import annotations

import re
from pathlib import Path

from m365_mcp_kernel.graph_client import ALLOWED_REPORT_FUNCTIONS
from m365_mcp_kernel.schema import project_schema

from exchange_admin_mcp.allowlist import (
    EXO_ENDPOINTS,
    EXO_GRANTS,
    FORBIDDEN_KEYS,
    GRAPH_GRANTS,
    GRAPH_REPORT_FUNCTIONS,
    TOOL_NAMES,
)
from exchange_admin_mcp.schemas import SCHEMA_BY_NAME

SRC = Path(__file__).resolve().parents[1] / "src"


def test_tool_names_are_the_frozen_fifteen() -> None:
    assert len(TOOL_NAMES) == 15
    assert len(set(TOOL_NAMES)) == 15
    assert TOOL_NAMES[0] == "list_message_traces"
    assert TOOL_NAMES[-1] == "get_organization_config"
    assert all(name.startswith(("list_", "get_")) for name in TOOL_NAMES)


def test_grants_are_exact() -> None:
    assert GRAPH_GRANTS == (
        "ExchangeMessageTrace.Read.All",
        "Place.Read.All",
        "Reports.Read.All",
    )
    assert EXO_GRANTS == ("Exchange.ManageAsAppV2",)
    joined = " ".join(GRAPH_GRANTS + EXO_GRANTS)
    assert "ReadWrite" not in joined
    assert "Directory." not in joined
    assert not any(name.endswith(".Read") for name in GRAPH_GRANTS + EXO_GRANTS)


def test_endpoint_map_is_six_get_cmdlets() -> None:
    assert len(EXO_ENDPOINTS) == 6
    cmdlets = []
    for endpoint, mapped in EXO_ENDPOINTS.items():
        assert len(mapped) == 1
        cmdlet, params = next(iter(mapped.items()))
        assert cmdlet.startswith("Get-")
        cmdlets.append(cmdlet)
        if endpoint == "OrganizationConfig":
            assert params == frozenset()
    assert len(cmdlets) == 6
    assert len(set(cmdlets)) == 6


def test_report_functions_come_from_the_kernel() -> None:
    assert set(GRAPH_REPORT_FUNCTIONS) <= set(ALLOWED_REPORT_FUNCTIONS)
    assert "getMailboxUsageDetail" in ALLOWED_REPORT_FUNCTIONS
    assert "getEmailActivityUserDetail" in ALLOWED_REPORT_FUNCTIONS


def test_manage_as_app_without_v2_is_absent() -> None:
    blob = "\n".join(path.read_text(encoding="utf-8") for path in SRC.rglob("*.py"))
    assert re.search(r"Exchange\.ManageAsApp(?!V2)", blob) is None


def test_schema_drops_unknown_and_forbidden_keys() -> None:
    for name, schema in SCHEMA_BY_NAME.items():
        payload = {key: "kept" for key in schema}
        payload["notInContract"] = "drop-me"
        for banned in FORBIDDEN_KEYS:
            payload[banned] = "drop-me"
        projected = project_schema(payload, schema)
        assert "notInContract" not in projected, name
        for banned in FORBIDDEN_KEYS:
            assert banned not in projected, name
        assert set(projected) <= set(schema)
