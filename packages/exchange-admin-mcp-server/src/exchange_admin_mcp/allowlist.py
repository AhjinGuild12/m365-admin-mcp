"""Frozen 15-tool contract for exchange-admin-ro."""

from __future__ import annotations

TOOL_NAMES: tuple[str, ...] = (
    "list_message_traces",
    "get_message_trace_details",
    "list_rooms",
    "list_room_lists",
    "list_rooms_in_room_list",
    "get_room",
    "list_mailbox_usage_report",
    "list_email_activity_report",
    "list_mailboxes",
    "get_mailbox",
    "list_mailbox_folder_permissions",
    "list_distribution_group_members",
    "list_dynamic_distribution_group_members",
    "list_accepted_domains",
    "get_organization_config",
)

GRAPH_GRANTS: tuple[str, ...] = (
    "Calendars.Read",  # Jan-approved extra 2026-09-23 (room free/busy); not in original freeze
    "ExchangeMessageTrace.Read.All",
    "Place.Read.All",
    "Reports.Read.All",
)
EXO_GRANTS: tuple[str, ...] = ("Exchange.ManageAsAppV2",)

# endpoint -> {cmdlet: allowed parameter names}. One Get- cmdlet per endpoint.
EXO_ENDPOINTS: dict[str, dict[str, frozenset[str]]] = {
    "Mailbox": {
        "Get-Mailbox": frozenset(
            {"Identity", "ResultSize", "IncludeGrantSendOnBehalfToWithDisplayNames"}
        ),
    },
    "MailboxFolderPermission": {
        "Get-MailboxFolderPermission": frozenset({"Identity", "ResultSize"}),
    },
    "DistributionGroupMember": {
        "Get-DistributionGroupMember": frozenset({"Identity", "ResultSize"}),
    },
    "DynamicDistributionGroupMember": {
        "Get-DynamicDistributionGroupMember": frozenset({"Identity", "ResultSize"}),
    },
    "AcceptedDomain": {
        "Get-AcceptedDomain": frozenset({"Identity", "ResultSize"}),
    },
    "OrganizationConfig": {
        "Get-OrganizationConfig": frozenset(),
    },
}

EXO_REQUIRED_PARAMS: dict[str, frozenset[str]] = {
    "Get-MailboxFolderPermission": frozenset({"Identity"}),
    "Get-DistributionGroupMember": frozenset({"Identity"}),
    "Get-DynamicDistributionGroupMember": frozenset({"Identity"}),
}

GRAPH_PATH_PREFIXES: tuple[str, ...] = (
    "/admin/exchange/tracing/messageTraces",
    "/places/",
)

GRAPH_REPORT_FUNCTIONS: tuple[str, ...] = (
    "getMailboxUsageDetail",
    "getEmailActivityUserDetail",
)

DEFAULT_TOP = 50
HARD_CAP = 200
MAILBOX_SCAN_CAP = 5000
REPORT_ROW_CAP = 5000
EXO_PAGE_SIZE = HARD_CAP

MESSAGE_TRACE_MAX_WINDOW_DAYS = 10
MESSAGE_TRACE_MAX_AGE_DAYS = 90

REPORT_PERIODS: tuple[str, ...] = ("D7", "D30", "D90", "D180")

ALLOWED_RECIPIENT_TYPES: dict[str, str] = {
    "user": "UserMailbox",
    "shared": "SharedMailbox",
    "room": "RoomMailbox",
    "equipment": "EquipmentMailbox",
}

FORBIDDEN_KEYS = frozenset(
    {
        "fromIP",
        "toIP",
        "data",
        "ExternalDirectoryObjectId",
        "Guid",
        "Id",
        "Identity",
        "DistinguishedName",
        "LegacyExchangeDN",
        "ObjectState",
        "IsValid",
    }
)

# Graph exchangeMessageTrace, minus fromIP and toIP.
MESSAGE_TRACE_FIELDS: tuple[str, ...] = (
    "id",
    "messageId",
    "receivedDateTime",
    "senderAddress",
    "recipientAddress",
    "subject",
    "status",
    "size",
)

# exchangeMessageTraceDetail, minus data.
MESSAGE_TRACE_DETAIL_FIELDS: tuple[str, ...] = (
    "date",
    "event",
    "action",
    "detail",
)

# Get-Mailbox response overview, minus FORBIDDEN_KEYS.
MAILBOX_FIELDS: tuple[str, ...] = (
    "Name",
    "DisplayName",
    "UserPrincipalName",
    "Alias",
    "RecipientType",
    "RecipientTypeDetails",
    "EmailAddresses",
    "PrimarySmtpAddress",
    "MaxSendSize",
    "GrantSendOnBehalfTo",
    "GrantSendOnBehalfToWithDisplayNames",
)

# Get-MailboxFolderPermission response overview, minus FORBIDDEN_KEYS.
FOLDER_PERMISSION_FIELDS: tuple[str, ...] = (
    "FolderName",
    "User",
    "AccessRights",
    "SharingPermissionFlags",
)

GROUP_MEMBER_FIELDS: tuple[str, ...] = (
    "DisplayName",
    "PrimarySmtpAddress",
    "Alias",
    "RecipientType",
    "RecipientTypeDetails",
    "HiddenFromAddressListsEnabled",
    "FirstName",
    "LastName",
)

ACCEPTED_DOMAIN_FIELDS: tuple[str, ...] = (
    "DomainName",
    "DomainType",
    "Name",
    "AdminDisplayName",
)

ORGANIZATION_CONFIG_FIELDS: tuple[str, ...] = (
    "Name",
    "MailTipsAllTipsEnabled",
    "MailTipsExternalRecipientsTipsEnabled",
    "MailTipsLargeAudienceThreshold",
)

ROOM_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "emailAddress",
    "nickname",
    "building",
    "floorNumber",
    "floorLabel",
    "label",
    "capacity",
    "bookingType",
    "audioDeviceName",
    "videoDeviceName",
    "displayDeviceName",
    "isWheelChairAccessible",
    "phone",
    "placeId",
)

ROOM_LIST_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "emailAddress",
    "nickname",
    "building",
    "phone",
    "placeId",
)

MAILBOX_USAGE_COLUMNS: tuple[str, ...] = (
    "Report Refresh Date",
    "User Principal Name",
    "Display Name",
    "Is Deleted",
    "Deleted Date",
    "Created Date",
    "Last Activity Date",
    "Item Count",
    "Storage Used (Byte)",
    "Issue Warning Quota (Byte)",
    "Prohibit Send Quota (Byte)",
    "Prohibit Send/Receive Quota (Byte)",
    "Deleted Item Count",
    "Deleted Item Size (Byte)",
    "Deleted Item Quota (Byte)",
    "Has Archive",
    "Report Period",
)

EMAIL_ACTIVITY_COLUMNS: tuple[str, ...] = (
    "Report Refresh Date",
    "User Principal Name",
    "Display Name",
    "Is Deleted",
    "Deleted Date",
    "Last Activity Date",
    "Send Count",
    "Receive Count",
    "Read Count",
    "Meeting Created Count",
    "Meeting Interacted Count",
    "Assigned Products",
    "Report Period",
)
