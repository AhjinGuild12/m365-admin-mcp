"""get_intune_overview — live-gate baseline read."""

from __future__ import annotations

from typing import Any

from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.schema import project_then_strip

from intune_mcp.schemas import OVERVIEW_SCHEMA


def get_intune_overview(client: GraphClient) -> dict[str, Any]:
    data = client.get("/deviceManagement/managedDeviceOverview")
    return project_then_strip(data, OVERVIEW_SCHEMA)
