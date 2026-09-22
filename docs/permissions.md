# Permissions matrix

Always use **Microsoft Graph application permissions** + **admin consent**. Exact sets depend on which tools you enable.

| Server | Prefix | Notes |
|--------|--------|--------|
| Entra | `ENTRA_` | Directory, audit/sign-in, policy, PIM, domains — see entra guide |
| Intune | `INTUNE_` | DeviceManagement / Intune Graph permissions — see package allowlist |
| SPO admin | `SPO_ADMIN_` | SharePoint tenant settings / reports — see package allowlist |

Do not copy another organization’s grants blindly. Least privilege: add only what your smoke tests need, then expand.
