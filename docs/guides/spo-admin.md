# SharePoint admin MCP (`packages/spo-admin-mcp-server`)

Read-only SharePoint Online **tenant** admin settings and site usage summaries.

## Auth
App-only. Env prefix `SPO_ADMIN_`.

## Install
```bash
cd packages/spo-admin-mcp-server && uv sync
```

## Smoke
List tools (~7) → `get_tenant_sharing_settings` / `get_tenant_settings`.
