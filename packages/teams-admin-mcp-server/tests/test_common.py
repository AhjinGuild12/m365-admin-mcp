from __future__ import annotations

import json

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from teams_admin_mcp.schemas import MEMBER_SCHEMA
from teams_admin_mcp.tools._common import (
    clamp_top,
    classify_member_origin,
    collect_bounded,
    fetch_one,
    finalize,
    path_segment,
    require_guid,
)
from tests.conftest import FakeGraph, gid

HOME = gid("0")
OTHER = gid("a")


def test_clamp_top_bounds() -> None:
    assert clamp_top(None) == 50
    assert clamp_top(1) == 1
    assert clamp_top(200) == 200
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        clamp_top(201)
    with pytest.raises(SanitizedGraphError, match="invalid_top"):
        clamp_top(0)
    with pytest.raises(SanitizedGraphError, match="invalid_top"):
        clamp_top(True)  # type: ignore[arg-type]


def test_path_segment_encodes_hash_and_rejects_slash() -> None:
    assert path_segment("adele@contoso.com") == "adele%40contoso.com"
    assert path_segment("ada#EXT#@contoso.com") == "ada%23EXT%23%40contoso.com"
    with pytest.raises(SanitizedGraphError, match="invalid_path_segment"):
        path_segment("a/b")
    with pytest.raises(SanitizedGraphError, match="invalid_path_segment"):
        path_segment("a?b")


def test_require_guid_accepts_either_case_and_rejects_upn() -> None:
    assert require_guid(gid("A")) == gid("A")
    assert require_guid(gid("a")) == gid("a")
    with pytest.raises(SanitizedGraphError, match="guid_required"):
        require_guid("adele@contoso.com")


def test_collect_bounded_first_page_403_raises() -> None:
    client = FakeGraph(
        errors={"/teams/t/members": SanitizedGraphError("4xx graph_error", status_class="4xx")}
    )
    with pytest.raises(SanitizedGraphError, match="4xx graph_error"):
        collect_bounded(client, "/teams/t/members", None, 50, MEMBER_SCHEMA)
    assert client.calls


def test_collect_bounded_second_page_503_keeps_partial() -> None:
    client = FakeGraph(
        pages={
            "/teams/t/members": [
                {"id": "1", "displayName": "Ada", "roles": ["owner"]},
                {"id": "2", "displayName": "Bea", "roles": []},
            ]
        },
        errors={"/teams/t/members": SanitizedGraphError("5xx retries_exhausted", status_class="5xx")},
        page_error_after={"/teams/t/members": 1},
    )
    body = collect_bounded(client, "/teams/t/members", None, 50, MEMBER_SCHEMA)
    assert body["items"][0]["id"] == "1"
    assert body["complete"] is False
    assert body["stop_reason"] == "throttling_exhausted"
    assert body["error_class"] == "5xx"
    assert body["items_scanned"] == 1


def test_fetch_one_empty_mismatch_and_case() -> None:
    empty = FakeGraph(gets={"/teams/t": {}})
    with pytest.raises(SanitizedGraphError, match="not_found"):
        fetch_one(empty, "/teams/t", None, {"id": True}, "t")
    mismatch = FakeGraph(gets={"/teams/t": {"id": "other", "displayName": "X"}})
    with pytest.raises(SanitizedGraphError, match="id_mismatch"):
        fetch_one(mismatch, "/teams/t", None, {"id": True, "displayName": True}, "t")
    same = FakeGraph(gets={"/teams/t": {"id": gid("a"), "displayName": "X"}})
    body = fetch_one(same, "/teams/t", None, {"id": True, "displayName": True}, gid("A"))
    assert body["id"] == gid("a")
    assert body["displayName"] == "X"


def test_classify_member_origin() -> None:
    assert classify_member_origin({"tenantId": HOME}, HOME) == "home"
    assert classify_member_origin({"tenantId": HOME.upper()}, HOME) == "home"
    assert classify_member_origin({"tenantId": OTHER}, HOME) == "external"
    assert classify_member_origin({"displayName": "Ada"}, HOME) == "unknown"
    assert classify_member_origin({"tenantId": ""}, HOME) == "unknown"


def test_finalize_strips_tenant_id_three_levels_deep() -> None:
    payload = {
        "id": "row",
        "nested": {"tenantId": HOME, "items": [{"telephoneNumber": "555", "ok": True, "webUrl": "https://example.test"}]},
        "internalId": "hide",
        "telephoneNumbers": ["555"],
    }
    out = finalize(payload)
    dumped = json.dumps(out)
    assert "tenantId" not in dumped
    assert "telephoneNumber" not in dumped
    assert "telephoneNumbers" not in dumped
    assert "webUrl" not in dumped
    assert "internalId" not in dumped
    assert HOME not in dumped
    assert out["nested"]["items"][0]["ok"] is True
