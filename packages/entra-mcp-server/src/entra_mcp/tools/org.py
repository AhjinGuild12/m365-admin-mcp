"""Tenant organization display info, hybrid sync fields, and group settings."""

from __future__ import annotations

from typing import Any

from entra_mcp.allowlist import DOMAIN_FIELDS, GROUP_SETTING_FIELDS, ORG_FIELDS
from entra_mcp.errors import SanitizedGraphError
from entra_mcp.fields import project
from entra_mcp.graph_client import GraphClient

_SETTING_VALUE_FIELDS = ("name", "value")


def _project_group_settings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        row = project(item, GROUP_SETTING_FIELDS)
        values = row.get("values")
        if isinstance(values, list):
            row["values"] = [
                project(entry, _SETTING_VALUE_FIELDS)
                for entry in values
                if isinstance(entry, dict)
            ]
        out.append(row)
    return out


def get_org_info(client: GraphClient) -> dict[str, Any]:
    data = client.get("/organization", params={"$select": ",".join(ORG_FIELDS)})
    values = data.get("value")
    if isinstance(values, list) and values:
        org = project(values[0], ORG_FIELDS)
    elif isinstance(data, dict) and data.get("id"):
        org = project(data, ORG_FIELDS)
    else:
        raise SanitizedGraphError("empty_org", status_class="5xx")
    org.pop("onPremisesLastPasswordSyncDateTime", None)
    settings = client.collect_page(
        "/groupSettings",
        params={"$select": ",".join(GROUP_SETTING_FIELDS)},
        item_cap=50,
    )
    org["groupSettings"] = _project_group_settings(settings)
    return org


def list_domains(client: GraphClient) -> dict[str, Any]:
    items = client.collect_page(
        "/domains",
        params={"$select": ",".join(DOMAIN_FIELDS)},
        item_cap=100,
    )
    return {"domains": [project(item, DOMAIN_FIELDS) for item in items]}
