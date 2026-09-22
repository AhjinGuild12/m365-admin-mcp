"""Authoritative v1 tool names, caps, field allowlists, and schema names (R5/R10)."""

from __future__ import annotations

from m365_mcp_kernel.errors import SanitizedGraphError

TOOL_NAMES: tuple[str, ...] = (
    "get_intune_overview",
    "list_managed_devices",
    "get_managed_device",
    "search_managed_devices",
    "list_noncompliant_devices",
    "list_detected_apps",
    "list_compliance_policies",
    "get_compliance_policy_status",
    "list_configuration_profiles",
    "list_mobile_apps",
    "list_autopilot_devices",
    "list_enrollment_configurations",
    "list_intune_audit_events",
)

# Documented microsoft.graph.managedDevice property names (Graph v1.0).
# Source: learn.microsoft.com graph-rest-1.0 intune-devices-manageddevice.
# Used to reject unknown $select names (ownerType-style) offline.
MANAGED_DEVICE_SCHEMA_PROPERTIES: frozenset[str] = frozenset(
    {
        "id",
        "userId",
        "deviceName",
        "managedDeviceOwnerType",
        "deviceActionResults",
        "enrolledDateTime",
        "lastSyncDateTime",
        "operatingSystem",
        "complianceState",
        "jailBroken",
        "managementAgent",
        "osVersion",
        "easActivated",
        "easDeviceId",
        "easActivationDateTime",
        "azureADRegistered",
        "deviceEnrollmentType",
        "activationLockBypassCode",
        "emailAddress",
        "azureADDeviceId",
        "deviceRegistrationState",
        "deviceCategoryDisplayName",
        "isSupervised",
        "exchangeLastSuccessfulSyncDateTime",
        "exchangeAccessState",
        "exchangeAccessStateReason",
        "remoteAssistanceSessionUrl",
        "remoteAssistanceSessionErrorDetails",
        "isEncrypted",
        "userPrincipalName",
        "model",
        "manufacturer",
        "imei",
        "complianceGracePeriodExpirationDateTime",
        "serialNumber",
        "phoneNumber",
        "androidSecurityPatchLevel",
        "userDisplayName",
        "configurationManagerClientEnabledFeatures",
        "wiFiMacAddress",
        "deviceHealthAttestationState",
        "subscriberCarrier",
        "meid",
        "totalStorageSpaceInBytes",
        "freeStorageSpaceInBytes",
        "managedDeviceName",
        "partnerReportedThreatState",
        "requireUserEnrollmentApproval",
        "managementCertificateExpirationDate",
        "iccid",
        "udid",
        "notes",
        "ethernetMacAddress",
        "physicalMemoryInBytes",
        "enrollmentProfileName",
    }
)

MANAGED_DEVICE_FIELDS: tuple[str, ...] = (
    "id",
    "deviceName",
    "serialNumber",
    "userPrincipalName",
    "userDisplayName",
    "operatingSystem",
    "osVersion",
    "complianceState",
    "managementAgent",
    "managedDeviceOwnerType",
    "enrolledDateTime",
    "lastSyncDateTime",
    "manufacturer",
    "model",
    "isEncrypted",
    "isSupervised",
    "jailBroken",
    "azureADDeviceId",
    "deviceCategoryDisplayName",
    "exchangeAccessState",
)

MANAGED_DEVICE_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "activationLockBypassCode",
        "notes",
        "phoneNumber",
        "imei",
        "meid",
        "iccid",
        "udid",
        "remoteAssistanceSessionUrl",
        "ethernetMacAddress",
        "wiFiMacAddress",
    }
)

OVERVIEW_FIELDS: tuple[str, ...] = (
    "id",
    "enrolledDeviceCount",
    "mdmEnrolledCount",
    "dualEnrolledDeviceCount",
    "deviceOperatingSystemSummary",
    "deviceExchangeAccessStateSummary",
)

DETECTED_APP_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "version",
    "sizeInByte",
    "deviceCount",
    "publisher",
)

COMPLIANCE_POLICY_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "version",
    "createdDateTime",
    "lastModifiedDateTime",
    "@odata.type",
)

COMPLIANCE_STATUS_FIELDS: tuple[str, ...] = (
    "id",
    "deviceDisplayName",
    "deviceId",
    "userPrincipalName",
    "userName",
    "status",
    "complianceGracePeriodExpirationDateTime",
)

CONFIGURATION_PROFILE_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "version",
    "createdDateTime",
    "lastModifiedDateTime",
    "@odata.type",
)

MOBILE_APP_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "publisher",
    "isAssigned",
    "publishingState",
    "@odata.type",
    "assignments",
)

AUTOPILOT_FIELDS: tuple[str, ...] = (
    "id",
    "serialNumber",
    "groupTag",
    "manufacturer",
    "model",
    "productKey",
    "azureAdDeviceId",
    "enrollmentState",
    "deploymentProfileAssignmentStatus",
    "displayName",
    "userPrincipalName",
)

ENROLLMENT_CONFIG_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "@odata.type",
    "priority",
    "createdDateTime",
    "lastModifiedDateTime",
    "version",
)

AUDIT_EVENT_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "componentName",
    "activity",
    "activityDateTime",
    "activityType",
    "activityResult",
    "category",
    "actor",
    "resources",
)

AUDIT_ACTOR_FORBIDDEN_KEYS: frozenset[str] = frozenset({"ipAddress", "ipAddressFromResourceProvider"})

APP_CREDENTIAL_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "encodedCertificate",
        "certificatePassword",
        "secret",
        "password",
        "key",
        "privateKey",
        "connectionString",
        "token",
        "clientSecret",
        "sharedSecret",
        "packageHash",
    }
)

DEFAULT_TOP = 50
HARD_CAP = 200
AUDIT_DEFAULT_DAYS = 1

GRAPH_GRANTS: tuple[str, ...] = (
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementServiceConfig.Read.All",
)


def validate_select(fields: tuple[str, ...], schema: frozenset[str] | None = None) -> tuple[str, ...]:
    """Reject $select names that are not documented schema properties (KTD11)."""
    names = schema if schema is not None else MANAGED_DEVICE_SCHEMA_PROPERTIES
    unknown = [name for name in fields if name not in names]
    if unknown:
        raise SanitizedGraphError("unknown_select_property", status_class="4xx")
    return fields


validate_select(MANAGED_DEVICE_FIELDS)
