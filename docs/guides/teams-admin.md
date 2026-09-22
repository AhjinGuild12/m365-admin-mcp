# Teams admin MCP (`packages/teams-admin-mcp-server`)

Read-only Microsoft Teams inventory for an IT admin. The server name is `teams-admin-ro`. It exposes 13 GET-only Graph v1.0 tools. It cannot change teams, membership, apps, or policies.

Install and host wiring go through `~/.config/teams-admin-mcp/bin/teams-admin-mcp-launch.mjs` with an empty argument list and no host `env` block. See the README. Phase B (Entra app, admin consent, 0600 env file, live smoke) is a separate step and is not performed by the offline build.

## Auth

App-only `ClientSecretCredential`. Env prefix `TEAMS_ADMIN_`: tenant id, client id, client secret, and secret expiry. Placeholders in docs are `YOUR_*` only.

## Must-have coverage

| Question | What you get | What you do not get |
|---|---|---|
| Which teams exist, and who owns them? | `list_teams`, `list_team_owners` | A scan of every ownerless team |
| Who is a direct member of a channel? | `list_channel_members` | A full effective-access audit of a shared channel |
| Guest settings on a team | `get_team` `guestSettings` plus guest count | Tenant-wide external access (`entra-ro` covers that) |
| Sensitivity label on a team | `get_team_sensitivity_labels` (`labelId`, `displayName`) | The tenant label catalog |
| Which messaging, meeting, calling, or app policy is assigned to a user? | `get_user_teams_policy_assignments` by user object id | Policy definitions or settings. A missing policy type was **not returned**. That is not "no policy applies". |
| Installed and org-published apps | `list_team_installed_apps`, `list_org_catalog_apps` | `teamsAppSettings` (no application permission) |
| How active is a team? | `list_teams_team_activity` for D7, D30, D90, D180 | User activity, device usage, call records, message bodies |

## Assigned labels need Entra ID P1

Group sensitivity labels require Microsoft Entra ID P1. `assignedLabels: []` with `labels_status: empty` means Graph returned the property and it was empty. `assignedLabels: null` with `labels_status: unavailable` means the property was absent.

## `member_origin`

`home`, `external`, or `unknown` says where the member account is homed. It is not the tenant's external-access policy. The raw `tenantId` is removed from every response.

## Policy tool is Global cloud only

`get_user_teams_policy_assignments` takes a user object id, not a UPN. It calls `/admin/teams/userConfigurations/{id}`, which Microsoft documents for the Global cloud. An authorization failure stays a sanitized `4xx graph_error`. Resolve a UPN to an object id with `entra-ro` first.

## Nine application grants

`Group.Read.All`, `TeamSettings.Read.All`, `TeamMember.Read.All`, `Channel.ReadBasic.All`, `ChannelMember.Read.All`, `TeamsAppInstallation.ReadForTeam.All`, `AppCatalog.Read.All`, `TeamsUserConfiguration.Read.All`, `Reports.Read.All`.

Admin consent is required. Do not add a tenth grant to make a probe pass. That needs a plan change.
