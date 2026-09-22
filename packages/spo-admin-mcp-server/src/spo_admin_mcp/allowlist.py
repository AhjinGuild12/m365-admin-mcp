"""Authoritative P0 tool names, caps, and field allowlists."""

from __future__ import annotations

from m365_mcp_kernel.errors import SanitizedGraphError

TOOL_NAMES: tuple[str, ...] = (
    "get_tenant_sharing_settings",
    "get_tenant_access_settings",
    "get_tenant_site_creation_settings",
    "get_tenant_settings",
    "list_site_usage",
    "get_site_usage",
    "get_site_usage_summary",
)

GRAPH_GRANTS: tuple[str, ...] = (
    "Reports.Read.All",
    "SharePointTenantSettings.Read.All",
)

SETTINGS_PATH = "/admin/sharepoint/settings"
REPORT_ROW_CAP = 5000
REPORT_PERIODS: frozenset[str] = frozenset({"D7", "D30", "D90", "D180"})

SHARING_FIELDS: tuple[str, ...] = (
    "sharingCapability",
    "sharingDomainRestrictionMode",
    "sharingAllowedDomainList",
    "sharingBlockedDomainList",
    "isResharingByExternalUsersEnabled",
    "isRequireAcceptingUserToMatchInvitedUserEnabled",
)

ACCESS_SCALAR_FIELDS: tuple[str, ...] = (
    "isLegacyAuthProtocolsEnabled",
    "isUnmanagedSyncAppForTenantRestricted",
    "allowedDomainGuidsForSyncApp",
    "excludedFileExtensionsForSyncApp",
    "isMacSyncAppEnabled",
    "isSyncButtonHiddenOnPersonalSite",
)

IDLE_SESSION_FIELDS: tuple[str, ...] = (
    "isEnabled",
    "warnAfterInSeconds",
    "signOutAfterInSeconds",
)

SITE_CREATION_FIELDS: tuple[str, ...] = (
    "isSiteCreationEnabled",
    "isSiteCreationUIEnabled",
    "isSitePagesCreationEnabled",
    "siteCreationDefaultManagedPath",
    "availableManagedPathsForSiteCreation",
    "siteCreationDefaultStorageLimitInMB",
    "isSitesStorageLimitAutomatic",
    "personalSiteDefaultStorageLimitInMB",
    "deletedUserPersonalSiteRetentionPeriodInDays",
    "tenantDefaultTimezone",
)

SETTINGS_EXTRA_FIELDS: tuple[str, ...] = (
    "imageTaggingOption",
    "isCommentingOnSitePagesEnabled",
    "isFileActivityNotificationEnabled",
    "isLoopEnabled",
    "isSharePointMobileNotificationEnabled",
    "isSharePointNewsfeedEnabled",
)

LIST_FIELDS: frozenset[str] = frozenset(
    {
        "sharingAllowedDomainList",
        "sharingBlockedDomainList",
        "allowedDomainGuidsForSyncApp",
        "excludedFileExtensionsForSyncApp",
        "availableManagedPathsForSiteCreation",
    }
)

DETAIL_REPORT = "getSharePointSiteUsageDetail"
STORAGE_REPORT = "getSharePointSiteUsageStorage"
COUNTS_REPORT = "getSharePointSiteUsageSiteCounts"

DETAIL_FIELDS: tuple[str, ...] = (
    "Report Refresh Date",
    "Site Id",
    "Site URL",
    "Owner Display Name",
    "Owner Principal Name",
    "Is Deleted",
    "Last Activity Date",
    "File Count",
    "Active File Count",
    "Storage Used (Byte)",
    "Storage Allocated (Byte)",
    "Root Web Template",
    "Report Period",
)

STORAGE_FIELDS: tuple[str, ...] = (
    "Report Refresh Date",
    "Site Type",
    "Storage Used (Byte)",
    "Report Date",
)

COUNTS_FIELDS: tuple[str, ...] = (
    "Site Type",
    "Total",
    "Active",
    "Report Date",
)

PAGE_VIEW_FIELDS: frozenset[str] = frozenset(
    {
        "Page View Count",
        "Visited Page Count",
    }
)


def tenant_setting_names() -> tuple[str, ...]:
    """The documented v1.0 sharepointSettings property set. Order is stable."""
    names = (
        SHARING_FIELDS
        + ACCESS_SCALAR_FIELDS
        + ("idleSessionSignOut",)
        + SITE_CREATION_FIELDS
        + SETTINGS_EXTRA_FIELDS
    )
    if len(names) != len(set(names)):
        raise SanitizedGraphError("duplicate_setting_name", status_class="other")
    return names


TENANT_SETTING_NAMES: tuple[str, ...] = tenant_setting_names()

if len(TENANT_SETTING_NAMES) != 29:
    raise SanitizedGraphError("tenant_setting_count", status_class="other")
