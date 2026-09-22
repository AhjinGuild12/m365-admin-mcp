"""Read-only projections of GET /admin/sharepoint/settings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.schema import project_then_strip

from spo_admin_mcp.allowlist import SETTINGS_PATH
from spo_admin_mcp.schemas import (
    ACCESS_SCHEMA,
    SHARING_SCHEMA,
    SITE_CREATION_SCHEMA,
    TENANT_SETTINGS_SCHEMA,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(client: GraphClient, schema: dict) -> dict[str, Any]:
    payload = client.get(SETTINGS_PATH)
    return {
        "retrieved_at": utc_now(),
        "settings": project_then_strip(payload, schema),
    }


def get_tenant_sharing_settings(client: GraphClient) -> dict[str, Any]:
    return _read(client, SHARING_SCHEMA)


def get_tenant_access_settings(client: GraphClient) -> dict[str, Any]:
    return _read(client, ACCESS_SCHEMA)


def get_tenant_site_creation_settings(client: GraphClient) -> dict[str, Any]:
    return _read(client, SITE_CREATION_SCHEMA)


def get_tenant_settings(client: GraphClient) -> dict[str, Any]:
    return _read(client, TENANT_SETTINGS_SCHEMA)
