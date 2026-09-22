# m365-admin-mcp

**Read-only Microsoft 365 admin MCP servers** for Claude Desktop, Cursor, and other MCP hosts.

IT admins use these so an assistant can **query** Entra ID, Intune, and SharePoint admin settings **without write access** to your tenant. You bring your own Entra app registration. This repository never ships client secrets, tokens, or tenant IDs.

**License:** MIT © Jan Medina

---

## What’s in the suite

| Status | Package | What it does | Tools (approx.) |
|--------|---------|----------------|-----------------|
| **Live** | `packages/entra-mcp-server` | Users, groups, devices, sign-ins (no IPs), licenses, apps, Conditional Access, PIM eligibility/active/settings, domains | **42** |
| **Live** | `packages/intune-mcp-server` | Managed devices, compliance, apps, configuration policies, audit | **13** |
| **Live** | `packages/spo-admin-mcp-server` | Tenant sharing / access / site-creation settings, site usage | **7** |
| Shared | `packages/m365-mcp-kernel` | Shared Graph client + network policy (used by Intune & SPO) | — |
| **Planned** | Teams admin MCP | Not in this repo yet | — |
| **Planned** | Exchange admin MCP | Not in this repo yet | — |
| **Planned** | M365 Admin center MCP | Not in this repo yet | — |

Optional hardened launchers/gates live under `ops/` (fail-closed env loading). Day-to-day install usually uses `uv` + MCP host env vars (below).

---

## Why read-only?

These servers are built for **investigation and evidence**, not change management:

- Graph calls are **GET-oriented** allowlisted tools.
- Credential type is locked to **`ClientSecretCredential`** (app-only). Interactive / device-code / `DefaultAzureCredential` paths are not used.
- No tools that create users, change groups, wipe devices, or alter CA policies.

If a tool is missing, that is usually intentional (missing Graph permission or not in the allowlist).

---

## Auth model (bring your own app)

**Not device code.** Each server authenticates as an **Entra application** with a **client secret you create** and keep **only on your machine** (MCP host env or a 0600 env file used by `ops/` launchers).

Placeholders only in docs:

| Variable pattern | Example |
|------------------|---------|
| `{PREFIX}_TENANT_ID` | `YOUR_TENANT_ID` |
| `{PREFIX}_CLIENT_ID` | `YOUR_CLIENT_ID` |
| `{PREFIX}_CLIENT_SECRET` | `YOUR_CLIENT_SECRET` |
| `{PREFIX}_SECRET_EXPIRES` | `YYYY-MM-DD` (required by hardened launcher) |

Prefixes:

- Entra → `ENTRA_`
- Intune → `INTUNE_`
- SharePoint admin → `SPO_ADMIN_`

### One-time Entra setup (per tenant)

1. **Entra admin center** → App registrations → **New registration**.
2. **Certificates & secrets** → New client secret → store it in a secret manager / local env (never commit).
3. **API permissions** → Microsoft Graph → **Application** permissions for the server you need → **Grant admin consent**.
4. Copy **Directory (tenant) ID** and **Application (client) ID** into your MCP config env.

Permission details: [docs/guides/](docs/guides/) and [docs/permissions.md](docs/permissions.md).

---

## Install (simple path)

Requirements: **Python 3.10+**, [`uv`](https://github.com/astral-sh/uv), git.

```bash
git clone https://github.com/AhjinGuild12/m365-admin-mcp.git
cd m365-admin-mcp

# Example: Entra server
cd packages/entra-mcp-server
uv sync
```

Repeat `uv sync` inside `packages/intune-mcp-server` or `packages/spo-admin-mcp-server` as needed. Intune/SPO resolve the kernel via the monorepo layout—keep the clone intact.

### Cursor / Claude Desktop MCP snippet

Add one server entry per product (stdio). Paths and command must match your machine:

```json
{
  "mcpServers": {
    "entra-ro": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/m365-admin-mcp/packages/entra-mcp-server", "python", "-m", "entra_mcp"],
      "env": {
        "ENTRA_TENANT_ID": "YOUR_TENANT_ID",
        "ENTRA_CLIENT_ID": "YOUR_CLIENT_ID",
        "ENTRA_CLIENT_SECRET": "YOUR_CLIENT_SECRET"
      }
    },
    "intune-ro": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/m365-admin-mcp/packages/intune-mcp-server", "uv", "run", "python", "-m", "intune_mcp"],
      "env": {
        "INTUNE_TENANT_ID": "YOUR_TENANT_ID",
        "INTUNE_CLIENT_ID": "YOUR_CLIENT_ID",
        "INTUNE_CLIENT_SECRET": "YOUR_CLIENT_SECRET"
      }
    },
    "spo-admin-ro": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/m365-admin-mcp/packages/spo-admin-mcp-server", "python", "-m", "spo_admin_mcp"],
      "env": {
        "SPO_ADMIN_TENANT_ID": "YOUR_TENANT_ID",
        "SPO_ADMIN_CLIENT_ID": "YOUR_CLIENT_ID",
        "SPO_ADMIN_CLIENT_SECRET": "YOUR_CLIENT_SECRET"
      }
    }
  }
}
```

If `python -m …` fails, check each package’s `pyproject.toml` / `__main__.py` for the exact module name. Prefer absolute paths.

Hardened path (optional): use `ops/*-mcp-launch.mjs` after reading `ops/` and creating a local 0600 env file—still **your** secret, never committed.

---

## Smoke checklist (after install)

Use these to confirm the install—not to dump tenant data into tickets.

**Entra**

- [ ] MCP host lists ~**42** tools for `entra-ro`.
- [ ] `get_org_info` returns your org display name.
- [ ] `list_domains` returns domains (counts OK).
- [ ] `list_conditional_access_policies` returns 200 / policy list (needs `Policy.Read.All`).

**Intune**

- [ ] MCP host lists ~**13** tools.
- [ ] `get_intune_overview` or `list_managed_devices` succeeds with Intune Graph permissions consented.

**SharePoint admin**

- [ ] MCP host lists ~**7** tools.
- [ ] `get_tenant_sharing_settings` (or `get_tenant_settings`) succeeds.

**Fail closed**

- [ ] Wrong / missing secret → server fails to start or calls return auth errors (no silent empty success).
- [ ] Repo clone contains **no** `.env` with real values.

---

## Docs

- [Entra guide](docs/guides/entra.md)
- [Intune guide](docs/guides/intune.md)
- [SharePoint admin guide](docs/guides/spo-admin.md)
- [Permissions matrix](docs/permissions.md)
- [Secret scrub checklist](docs/secret-scrub-checklist.md)

---

## Security commitments

- No client secrets, certificates, or refresh tokens in git.
- Docs use `YOUR_*` placeholders only.
- Read-only tool allowlists; do not patch in write APIs without treating it as a different product.
- Report suspected leaked secrets: rotate the Entra secret immediately and open an issue without pasting the secret.

---

## Roadmap (not shipped here)

Teams admin MCP, Exchange admin MCP, and a broader M365 Admin MCP are **planned** add-ons to this suite. This repo today is Entra + Intune + SharePoint admin only.
