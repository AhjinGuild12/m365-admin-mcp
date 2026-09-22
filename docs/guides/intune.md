# Intune MCP (`packages/intune-mcp-server`)

Read-only Intune device, compliance, app, and policy inventory via Graph.

## Auth
App-only. Env prefix `INTUNE_`.

## Install
```bash
cd packages/intune-mcp-server && uv sync
```
Keep monorepo root so `m365-mcp-kernel` resolves.

## Smoke
List tools (~13) → `get_intune_overview` or `list_managed_devices`.
