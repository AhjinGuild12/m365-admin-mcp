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
| **Live** | `packages/teams-admin-mcp-server` | Teams inventory, settings and labels, members and owners, channels and channel members, installed and org apps, per-user policy assignments, team activity | **13** |
| Shared | `packages/m365-mcp-kernel` | Shared Graph client + network policy (used by Intune, SPO, and Teams) | — |
| **Live** | `packages/exchange-admin-mcp-server` | Message trace, mailboxes, rooms, folder permissions, group members, accepted domains, organization MailTips | **15** |
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
- Teams admin → `TEAMS_ADMIN_` (`TEAMS_ADMIN_TENANT_ID`, `TEAMS_ADMIN_CLIENT_ID`, `TEAMS_ADMIN_CLIENT_SECRET`, `TEAMS_ADMIN_SECRET_EXPIRES`)
- Exchange admin → `EXO_` (`EXO_TENANT_ID`, `EXO_CLIENT_ID`, `EXO_CLIENT_SECRET`, `EXO_SECRET_EXPIRES`)

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

Repeat `uv sync` inside `packages/intune-mcp-server`, `packages/spo-admin-mcp-server`, or `packages/teams-admin-mcp-server` as needed. Workloads resolve the kernel via the monorepo layout—keep the clone intact.

### Teams admin launcher install

Teams admin is wired only through the fail-closed launcher. Clone the repo, sync the kernel, then sync the package:

```bash
cd packages/m365-mcp-kernel && uv sync
cd ../teams-admin-mcp-server && uv sync
```

Create `~/.config/teams-admin-mcp/` at mode 0700 and `teams-admin-mcp.env` at mode 0600 with `YOUR_TENANT_ID`, `YOUR_CLIENT_ID`, `YOUR_CLIENT_SECRET`, and `YOUR_SECRET_EXPIRES` on the four `TEAMS_ADMIN_` variables. Then, from the clone root:

```bash
node ops/teams-admin-mcp-gate.mjs --install
```

Add one host entry. Arguments stay empty. Do not put an `env` block on the host entry. The launcher reads the 0600 file itself.

Claude (`~/.claude.json`):

```json
{
  "mcpServers": {
    "teams-admin-ro": {
      "command": "~/.config/teams-admin-mcp/bin/teams-admin-mcp-launch.mjs",
      "args": []
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.teams-admin-ro]
command = "~/.config/teams-admin-mcp/bin/teams-admin-mcp-launch.mjs"
args = []
```

Grok (`~/.grok/config.toml`):

```toml
[mcp_servers.teams-admin-ro]
command = "~/.config/teams-admin-mcp/bin/teams-admin-mcp-launch.mjs"
args = []
```

Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "teams-admin-ro": {
      "command": "~/.config/teams-admin-mcp/bin/teams-admin-mcp-launch.mjs",
      "args": []
    }
  }
}
```

### Exchange admin launcher install

Exchange admin is wired only through the fail-closed launcher. Clone the repo, sync the kernel, then sync the package:

```bash
cd packages/m365-mcp-kernel && uv sync
cd ../exchange-admin-mcp-server && uv sync
```

Create `~/.config/exchange-admin-mcp/` at mode 0700 and `exchange-admin-mcp.env` at mode 0600 with `YOUR_TENANT_ID`, `YOUR_CLIENT_ID`, `YOUR_CLIENT_SECRET`, and `YOUR_SECRET_EXPIRES` on the four `EXO_` variables. Then, from the clone root:

```bash
node ops/exchange-admin-mcp-gate.mjs --install
```

Add one host entry. Arguments stay empty. Do not put an `env` block on the host entry. The launcher reads the 0600 file itself.

Claude (`~/.claude.json`):

```json
{
  "mcpServers": {
    "exchange-admin-ro": {
      "command": "~/.config/exchange-admin-mcp/bin/exchange-admin-mcp-launch.mjs",
      "args": []
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.exchange-admin-ro]
command = "~/.config/exchange-admin-mcp/bin/exchange-admin-mcp-launch.mjs"
args = []
```

Grok (`~/.grok/config.toml`):

```toml
[mcp_servers.exchange-admin-ro]
command = "~/.config/exchange-admin-mcp/bin/exchange-admin-mcp-launch.mjs"
args = []
```

Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "exchange-admin-ro": {
      "command": "~/.config/exchange-admin-mcp/bin/exchange-admin-mcp-launch.mjs",
      "args": []
    }
  }
}
```

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

**Teams admin**

- [ ] Each host lists **13** tools for `teams-admin-ro`.
- [ ] `list_teams` returns a bounded inventory.
- [ ] `get_user_teams_policy_assignments` echoes the user object id (Global cloud).

**Exchange admin**

- [ ] Each host lists **15** tools for `exchange-admin-ro`.
- [ ] `list_message_traces` returns a bounded trace, with no IP addresses.
- [ ] `get_organization_config` returns MailTips settings after the role group reconciles.

**Fail closed**

- [ ] Wrong / missing secret → server fails to start or calls return auth errors (no silent empty success).
- [ ] Repo clone contains **no** `.env` with real values.

---

## Docs

- [Entra guide](docs/guides/entra.md)
- [Intune guide](docs/guides/intune.md)
- [SharePoint admin guide](docs/guides/spo-admin.md)
- [Teams admin guide](docs/guides/teams-admin.md)
- [Exchange admin guide](docs/guides/exchange-admin.md)
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

A broader M365 Admin MCP is a **planned** add-on. Teams admin is in this repo as `teams-admin-ro` (13 tools) and is installed only through `teams-admin-mcp-launch.mjs`. Exchange admin is in this repo as `exchange-admin-ro` (15 tools) and is installed only through `exchange-admin-mcp-launch.mjs`.

## License

MIT. See [LICENSE](LICENSE).
