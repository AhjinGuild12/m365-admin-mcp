from __future__ import annotations

import json
from pathlib import Path

from m365_mcp_kernel.network_policy import check_tree

from teams_admin_mcp.allowlist import GRAPH_GRANTS, TOOL_NAMES
from teams_admin_mcp.server import advertised_tool_names, get_team, set_client_factory, set_home_tenant_id
from tests.conftest import FakeGraph, gid

SRC = Path(__file__).resolve().parents[1] / "src" / "teams_admin_mcp"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"
TENANT = gid("0")
TEAM = gid("b")

_WRITE_PREFIXES = (
    "create",
    "update",
    "delete",
    "remove",
    "archive",
    "install",
    "assign",
    "add",
    "patch",
    "post",
)


def test_advertised_names_equal_tool_names() -> None:
    names = advertised_tool_names()
    assert set(names) == set(TOOL_NAMES)
    assert len(names) == 13
    assert not any(name.startswith(_WRITE_PREFIXES) for name in names)


def test_grants_equal_the_nine_item_set() -> None:
    assert set(GRAPH_GRANTS) == {
        "Group.Read.All",
        "TeamSettings.Read.All",
        "TeamMember.Read.All",
        "Channel.ReadBasic.All",
        "ChannelMember.Read.All",
        "TeamsAppInstallation.ReadForTeam.All",
        "AppCatalog.Read.All",
        "TeamsUserConfiguration.Read.All",
        "Reports.Read.All",
    }


def test_ast_import_policy_passes_and_catches_bypass_fixtures(tmp_path: Path) -> None:
    assert check_tree(SRC) == []
    for fixture, needle in (
        ("tool_httpx.py", "httpx"),
        ("tool_socket.py", "socket"),
        ("tool_dynamic_import.py", "__import__"),
    ):
        tree = tmp_path / fixture
        tree.mkdir()
        (tree / "evil.py").write_text((FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8")
        violations = check_tree(tree)
        assert any(needle in item.message for item in violations)


def test_stdio_entry_selects_stdio_only() -> None:
    server_src = (SRC / "server.py").read_text(encoding="utf-8")
    main_src = (SRC / "__main__.py").read_text(encoding="utf-8")
    assert "run_stdio" in server_src
    assert "streamable-http" not in server_src
    assert "streamable-http" not in main_src
    assert "FastMCP" not in server_src


def test_fixture_tenant_is_absent_from_server_output() -> None:
    client = FakeGraph(
        gets={
            f"/teams/{TEAM}": {
                "id": TEAM,
                "displayName": "Finance",
                "description": "books",
                "visibility": "private",
                "tenantId": TENANT,
                "webUrl": "https://example.test/t",
                "internalId": "hide",
                "memberSettings": {"allowCreateUpdateChannels": True, "tenantId": TENANT},
                "summary": {
                    "ownersCount": 1,
                    "membersCount": 2,
                    "guestsCount": 0,
                    "rows": [{"tenantId": TENANT, "telephoneNumber": "555"}],
                },
                "telephoneNumbers": ["555"],
            }
        }
    )
    set_home_tenant_id(TENANT)
    set_client_factory(lambda: client)
    try:
        body = get_team(TEAM)
    finally:
        set_client_factory(None)
        set_home_tenant_id(None)
    dumped = json.dumps(body)
    assert "tenantId" not in dumped
    assert "telephoneNumber" not in dumped
    assert "webUrl" not in dumped
    assert "internalId" not in dumped
    assert TENANT not in dumped
    assert body["id"] == TEAM
    assert body["displayName"] == "Finance"
