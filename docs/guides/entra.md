# Entra MCP (`packages/entra-mcp-server`)

Read-only Microsoft Graph tools for directory, sign-in summaries (no IP/location fields), licenses, apps, Conditional Access, and PIM.

## Auth
App-only: `ClientSecretCredential`. Env prefix `ENTRA_`.

## Typical Graph application permissions
Start with what your tools need; common set includes:
`User.Read.All`, `Group.Read.All`, `GroupMember.Read.All`, `Device.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`, `Organization.Read.All`, `LicenseAssignment.Read.All`, `Application.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `Domain.Read.All`
(plus PIM schedule reads if you use PIM tools). **Admin consent required.**

## Install
```bash
cd packages/entra-mcp-server && uv sync
```
Point MCP host at `python -m entra_mcp` with `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`.

## Smoke
List tools (~42) → `get_org_info` → `list_domains`.
