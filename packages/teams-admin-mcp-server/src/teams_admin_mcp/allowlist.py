"""Frozen 13-tool / 9-grant contract for teams-admin-ro."""

from __future__ import annotations

TOOL_NAMES: tuple[str, ...] = (
    "list_teams",
    "get_team_sensitivity_labels",
    "get_team",
    "list_user_joined_teams",
    "list_team_members",
    "list_team_owners",
    "list_channels",
    "get_channel",
    "list_channel_members",
    "list_team_installed_apps",
    "list_org_catalog_apps",
    "get_user_teams_policy_assignments",
    "list_teams_team_activity",
)

GRAPH_GRANTS: tuple[str, ...] = (
    "Group.Read.All",
    "TeamSettings.Read.All",
    "TeamMember.Read.All",
    "Channel.ReadBasic.All",
    "ChannelMember.Read.All",
    "TeamsAppInstallation.ReadForTeam.All",
    "AppCatalog.Read.All",
    "TeamsUserConfiguration.Read.All",
    "Reports.Read.All",
)

DEFAULT_TOP = 50
HARD_CAP = 200
OWNER_SCAN_CAP = 5000
REPORT_ROW_CAP = 5000
COLLECTION_CAP = 200
OWNER_PAGE_TOP = 999

REPORT_PERIODS: tuple[str, ...] = ("D7", "D30", "D90", "D180")
CHANNEL_MEMBERSHIP_TYPES: tuple[str, ...] = ("standard", "private", "shared")
TEAMS_LIST_FILTER = "resourceProvisioningOptions/Any(x:x eq 'Team')"

FORBIDDEN_KEYS = frozenset(
    {"tenantId", "webUrl", "internalId", "telephoneNumbers", "telephoneNumber"}
)

TEAM_LIST_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "visibility",
    "createdDateTime",
)

TEAM_SCALAR_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "visibility",
    "isArchived",
    "classification",
    "createdDateTime",
    "isMembershipLimitedToOwners",
)

MEMBER_SETTINGS_FIELDS: tuple[str, ...] = (
    "allowCreateUpdateChannels",
    "allowDeleteChannels",
    "allowAddRemoveApps",
    "allowCreateUpdateRemoveTabs",
    "allowCreateUpdateRemoveConnectors",
)

GUEST_SETTINGS_FIELDS: tuple[str, ...] = (
    "allowCreateUpdateChannels",
    "allowDeleteChannels",
)

MESSAGING_SETTINGS_FIELDS: tuple[str, ...] = (
    "allowUserEditMessages",
    "allowUserDeleteMessages",
    "allowOwnerDeleteMessages",
    "allowTeamMentions",
    "allowChannelMentions",
)

FUN_SETTINGS_FIELDS: tuple[str, ...] = (
    "allowGiphy",
    "giphyContentRating",
    "allowStickersAndMemes",
    "allowCustomMemes",
)

DISCOVERY_SETTINGS_FIELDS: tuple[str, ...] = ("showInTeamsSearchAndSuggestions",)

SUMMARY_FIELDS: tuple[str, ...] = ("ownersCount", "membersCount", "guestsCount")

LABEL_SCALAR_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "visibility",
    "classification",
)

ASSIGNED_LABEL_FIELDS: tuple[str, ...] = ("labelId", "displayName")

JOINED_TEAM_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "isArchived",
)

MEMBER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userId",
    "email",
    "roles",
    "member_origin",
)

CHANNEL_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "membershipType",
    "isArchived",
    "createdDateTime",
)

MODERATION_FIELDS: tuple[str, ...] = (
    "userNewMessageRestriction",
    "replyRestriction",
    "allowNewMessageFromBots",
    "allowNewMessageFromConnectors",
)

APP_DEFINITION_FIELDS: tuple[str, ...] = (
    "teamsAppId",
    "displayName",
    "version",
    "publishingState",
    "azureADAppId",
)

CATALOG_APP_FIELDS: tuple[str, ...] = (
    "id",
    "externalId",
    "displayName",
    "distributionMethod",
)

CATALOG_DEFINITION_FIELDS: tuple[str, ...] = (
    "id",
    "version",
    "publishingState",
    "lastModifiedDateTime",
)

USER_CONFIG_FIELDS: tuple[str, ...] = (
    "id",
    "userPrincipalName",
    "accountType",
    "isEnterpriseVoiceEnabled",
    "featureTypes",
)

POLICY_ASSIGNMENT_FIELDS: tuple[str, ...] = (
    "displayName",
    "assignmentType",
    "policyId",
    "groupId",
)

REPORT_COLUMNS: tuple[str, ...] = (
    "Report Refresh Date",
    "Team Name",
    "Team Id",
    "Team Type",
    "Last Activity Date",
    "Report Period",
    "Active Users",
    "Active Channels",
    "Guests",
    "Reactions",
    "Meetings Organized",
    "Post Messages",
    "Reply Messages",
    "Channel Messages",
    "Urgent Messages",
    "Mentions",
    "Active Shared Channels",
    "Active External Users",
)

ACTIVITY_REPORT = "getTeamsTeamActivityDetail"
