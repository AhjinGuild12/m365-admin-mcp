# Permissions matrix

Always use **Microsoft Graph application permissions** + **admin consent**. Exact sets depend on which tools you enable.

| Server | Prefix | Notes |
|--------|--------|--------|
| Entra | `ENTRA_` | Directory, audit/sign-in, policy, PIM, domains — see entra guide |
| Intune | `INTUNE_` | DeviceManagement / Intune Graph permissions — see package allowlist |
| SPO admin | `SPO_ADMIN_` | SharePoint tenant settings / reports — see package allowlist |
| Teams admin | `TEAMS_ADMIN_` | `Group.Read.All`, `TeamSettings.Read.All`, `TeamMember.Read.All`, `Channel.ReadBasic.All`, `ChannelMember.Read.All`, `TeamsAppInstallation.ReadForTeam.All`, `AppCatalog.Read.All`, `TeamsUserConfiguration.Read.All`, `Reports.Read.All` |
| Exchange admin | `EXO_` | Graph: `Calendars.Read`, `ExchangeMessageTrace.Read.All`, `Place.Read.All`, `Reports.Read.All`. Office 365 Exchange Online: `Exchange.ManageAsAppV2` plus the custom view-only role group described in the guide |

Do not copy another organization’s grants blindly. Least privilege: add only what your smoke tests need, then expand.
