from __future__ import annotations

import json
from pathlib import Path

from m365_mcp_kernel.network_policy import check_tree

from exchange_admin_mcp.allowlist import EXO_GRANTS, GRAPH_GRANTS, TOOL_NAMES
from exchange_admin_mcp.server import (
    advertised_tool_names,
    get_mailbox,
    list_message_traces,
    set_exo_client_factory,
    set_graph_client_factory,
)
from tests.conftest import FakeExo, FakeGraph, gid

SRC = Path(__file__).resolve().parents[1] / "src" / "exchange_admin_mcp"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_bypass"
TENANT = gid("1")

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
    "set",
    "new",
)

_ABSENT = (
    "DeviceCodeCredential",
    "CertificateCredential",
    "DefaultAzureCredential",
    "InvokeCommand",
    "adminapi/beta",
    "graph.microsoft.com/beta",
    "/beta/",
)


def test_advertised_names_equal_tool_names() -> None:
    names = advertised_tool_names()
    assert set(names) == set(TOOL_NAMES)
    assert len(names) == 15
    assert not any(name.startswith(_WRITE_PREFIXES) for name in names)


def test_grants_are_exact() -> None:
    assert GRAPH_GRANTS == (
        "Calendars.Read",
        "ExchangeMessageTrace.Read.All",
        "Place.Read.All",
        "Reports.Read.All",
    )
    assert EXO_GRANTS == ("Exchange.ManageAsAppV2",)


def test_ast_import_policy_passes_and_catches_bypass_fixtures(tmp_path: Path) -> None:
    assert check_tree(SRC, allowed_network_files=frozenset({"exo_client.py"})) == []
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


def test_stdio_entry_and_forbidden_strings() -> None:
    server_src = (SRC / "server.py").read_text(encoding="utf-8")
    main_src = (SRC / "__main__.py").read_text(encoding="utf-8")
    assert "run_stdio" in server_src
    assert "streamable-http" not in server_src
    assert "streamable-http" not in main_src
    assert "FastMCP" not in server_src
    blob = "\n".join(path.read_text(encoding="utf-8") for path in SRC.rglob("*.py"))
    for needle in _ABSENT:
        assert needle not in blob
    exo = (SRC / "exo_client.py").read_text(encoding="utf-8")
    assert "graph.microsoft.com" not in exo


def test_round_trip_strips_fixture_secrets() -> None:
    graph = FakeGraph(
        pages={
            "/admin/exchange/tracing/messageTraces": [
                {
                    "id": gid("a"),
                    "subject": "hello",
                    "senderAddress": "a@contoso.com",
                    "fromIP": "203.0.113.8",
                    "toIP": "203.0.113.9",
                    "data": "blob",
                }
            ]
        }
    )
    exo = FakeExo(
        pages={
            "Mailbox": [
                {
                    "DisplayName": "Alex",
                    "PrimarySmtpAddress": "alex@contoso.com",
                    "RecipientTypeDetails": "UserMailbox",
                    "ExternalDirectoryObjectId": TENANT,
                    "Identity": f"CN={TENANT}",
                    "Id": TENANT,
                }
            ]
        }
    )
    set_graph_client_factory(lambda: graph)
    set_exo_client_factory(lambda: exo)
    try:
        trace = list_message_traces()
        mailbox = get_mailbox("alex@contoso.com")
    finally:
        set_graph_client_factory(None)
        set_exo_client_factory(None)
    dumped = json.dumps({"trace": trace, "mailbox": mailbox})
    assert TENANT not in dumped
    assert "fromIP" not in dumped
    assert "toIP" not in dumped
    assert "data" not in dumped
    assert "ExternalDirectoryObjectId" not in dumped
    assert "Identity" not in dumped
    assert trace["items"][0]["subject"] == "hello"
    assert mailbox["items"][0]["PrimarySmtpAddress"] == "alex@contoso.com"
