from __future__ import annotations

from exchange_admin_mcp.tools.rooms import get_room, list_room_lists, list_rooms, list_rooms_in_room_list
from tests.conftest import FakeGraph, gid

ROOM = gid("a")


def test_room_paths_are_relative_v1_prefixes() -> None:
    rooms = FakeGraph(pages={"/places/microsoft.graph.room": [{"id": ROOM, "displayName": "Board"}]})
    body = list_rooms(rooms, top=5)
    assert rooms.calls[0]["path"] == "/places/microsoft.graph.room"
    assert rooms.calls[0]["params"]["$top"] == "5"
    assert body["items"][0]["displayName"] == "Board"

    lists = FakeGraph(pages={"/places/microsoft.graph.roomList": []})
    list_room_lists(lists)
    assert lists.calls[0]["path"] == "/places/microsoft.graph.roomList"

    email = "rooms@contoso.com"
    nested = FakeGraph(pages={})
    list_rooms_in_room_list(nested, room_list=email)
    path = nested.calls[0]["path"]
    assert path.startswith("/places/")
    assert "rooms%40contoso.com" in path
    assert path.endswith("/microsoft.graph.roomList/rooms")
    assert "://" not in path


def test_get_room_matches_id() -> None:
    client = FakeGraph(gets={f"/places/{ROOM}": {"id": ROOM, "displayName": "Board", "phone": "555"}})
    body = get_room(client, room_id=ROOM)
    assert body["id"] == ROOM
    assert body["displayName"] == "Board"
