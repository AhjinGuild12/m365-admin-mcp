from __future__ import annotations

from teams_admin_mcp.tools.apps import list_org_catalog_apps, list_team_installed_apps
from tests.conftest import FakeGraph


def test_installed_apps_keep_definition_and_drop_description() -> None:
    client = FakeGraph(
        pages={
            "/teams/team-1/installedApps": [
                {
                    "id": "inst-1",
                    "teamsAppDefinition": {
                        "teamsAppId": "app-1",
                        "displayName": "Planner",
                        "version": "1.2.3",
                        "publishingState": "published",
                        "azureADAppId": "public-app",
                        "description": "long text",
                    },
                    "description": "also drop",
                }
            ]
        }
    )
    body = list_team_installed_apps(client, "team-1")
    definition = body["items"][0]["teamsAppDefinition"]
    assert definition["azureADAppId"] == "public-app"
    assert definition["displayName"] == "Planner"
    assert "description" not in definition
    assert "description" not in body["items"][0]
    assert client.calls[0]["params"]["$expand"] == "teamsAppDefinition"


def test_catalog_sends_no_top_and_caps_locally() -> None:
    rows = [
        {
            "id": f"app-{i}",
            "externalId": f"ext-{i}",
            "displayName": f"App {i}",
            "distributionMethod": "organization",
            "description": "drop",
            "appDefinitions": [
                {
                    "id": f"def-{i}",
                    "version": "1",
                    "publishingState": "published",
                    "lastModifiedDateTime": "2026-01-01T00:00:00Z",
                    "description": "drop",
                }
            ],
        }
        for i in range(3)
    ]
    client = FakeGraph(pages={"/appCatalogs/teamsApps": rows})
    body = list_org_catalog_apps(client, top=2)
    params = client.calls[0]["params"]
    assert "$top" not in params
    assert params["$filter"] == "distributionMethod eq 'organization'"
    assert params["$expand"] == "appDefinitions"
    assert len(body["items"]) == 2
    assert body["stop_reason"] == "item_cap"
    assert body["truncated"] is True
    assert "description" not in body["items"][0]
    assert "description" not in body["items"][0]["appDefinitions"][0]
