from __future__ import annotations

from m365_mcp_kernel.schema import project_schema

from teams_admin_mcp.allowlist import (
    FORBIDDEN_KEYS,
    GRAPH_GRANTS,
    REPORT_COLUMNS,
    TOOL_NAMES,
)
from teams_admin_mcp.schemas import SCHEMA_BY_NAME


def test_tool_names_are_the_frozen_thirteen() -> None:
    assert len(TOOL_NAMES) == 13
    assert len(set(TOOL_NAMES)) == 13
    assert TOOL_NAMES[0] == "list_teams"
    assert TOOL_NAMES[-1] == "list_teams_team_activity"


def test_grants_are_the_frozen_nine() -> None:
    assert len(GRAPH_GRANTS) == 9
    assert len(set(GRAPH_GRANTS)) == 9
    joined = " ".join(GRAPH_GRANTS)
    assert "ReadWrite" not in joined
    assert "Directory." not in joined
    assert not any(name.endswith(".Read") for name in GRAPH_GRANTS)


def test_forbidden_keys_cover_tenant_and_telephone() -> None:
    assert FORBIDDEN_KEYS == {
        "tenantId",
        "webUrl",
        "internalId",
        "telephoneNumbers",
        "telephoneNumber",
    }


def test_report_has_eighteen_columns() -> None:
    assert len(REPORT_COLUMNS) == 18


def test_schema_parents_drop_unknown_children() -> None:
    for name, schema in SCHEMA_BY_NAME.items():
        payload = {key: "kept" for key in schema}
        payload["notInContract"] = "drop-me"
        payload["tenantId"] = "drop-me"
        projected = project_schema(payload, schema)
        assert "notInContract" not in projected, name
        assert "tenantId" not in projected, name
        assert set(projected) <= set(schema)
