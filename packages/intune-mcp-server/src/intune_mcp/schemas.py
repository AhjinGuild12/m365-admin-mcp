"""Complete per-tool nested schemas (KTD17). Parent keys never admit arbitrary children."""

from __future__ import annotations

from intune_mcp.allowlist import (
    AUDIT_EVENT_FIELDS,
    AUTOPILOT_FIELDS,
    COMPLIANCE_POLICY_FIELDS,
    COMPLIANCE_STATUS_FIELDS,
    CONFIGURATION_PROFILE_FIELDS,
    DETECTED_APP_FIELDS,
    ENROLLMENT_CONFIG_FIELDS,
    MANAGED_DEVICE_FIELDS,
    MOBILE_APP_FIELDS,
    OVERVIEW_FIELDS,
)

_LEAF = True


def _object(fields: tuple[str, ...]) -> dict[str, bool]:
    return {name: _LEAF for name in fields}


OS_SUMMARY_SCHEMA: dict = {
    "androidCount": _LEAF,
    "iosCount": _LEAF,
    "macOSCount": _LEAF,
    "windowsMobileCount": _LEAF,
    "windowsCount": _LEAF,
    "unknownCount": _LEAF,
    "androidDedicatedCount": _LEAF,
    "androidDeviceAdminCount": _LEAF,
    "androidFullyManagedCount": _LEAF,
    "androidWorkProfileCount": _LEAF,
    "androidCorporateWorkProfileCount": _LEAF,
    "configMgrDeviceCount": _LEAF,
}

EXCHANGE_SUMMARY_SCHEMA: dict = {
    "allowedDeviceCount": _LEAF,
    "blockedDeviceCount": _LEAF,
    "quarantinedDeviceCount": _LEAF,
    "unknownDeviceCount": _LEAF,
    "unavailableDeviceCount": _LEAF,
}

OVERVIEW_SCHEMA: dict = {
    **{name: _LEAF for name in OVERVIEW_FIELDS if name not in {
        "deviceOperatingSystemSummary",
        "deviceExchangeAccessStateSummary",
    }},
    "deviceOperatingSystemSummary": OS_SUMMARY_SCHEMA,
    "deviceExchangeAccessStateSummary": EXCHANGE_SUMMARY_SCHEMA,
}

MANAGED_DEVICE_SCHEMA: dict = _object(MANAGED_DEVICE_FIELDS)
DETECTED_APP_SCHEMA: dict = _object(DETECTED_APP_FIELDS)
COMPLIANCE_POLICY_SCHEMA: dict = _object(COMPLIANCE_POLICY_FIELDS)
COMPLIANCE_STATUS_SCHEMA: dict = _object(COMPLIANCE_STATUS_FIELDS)
CONFIGURATION_PROFILE_SCHEMA: dict = _object(CONFIGURATION_PROFILE_FIELDS)
ENROLLMENT_CONFIG_SCHEMA: dict = _object(ENROLLMENT_CONFIG_FIELDS)
AUTOPILOT_SCHEMA: dict = _object(AUTOPILOT_FIELDS)

ASSIGNMENT_TARGET_SCHEMA: dict = {
    "@odata.type": _LEAF,
    "deviceAndAppManagementAssignmentFilterId": _LEAF,
    "deviceAndAppManagementAssignmentFilterType": _LEAF,
    "groupId": _LEAF,
}

ASSIGNMENT_SCHEMA: dict = {
    "id": _LEAF,
    "intent": _LEAF,
    "@odata.type": _LEAF,
    "target": ASSIGNMENT_TARGET_SCHEMA,
}

MOBILE_APP_SCHEMA: dict = {
    **{name: _LEAF for name in MOBILE_APP_FIELDS if name != "assignments"},
    "assignments": [ASSIGNMENT_SCHEMA],
}

AUDIT_ACTOR_SCHEMA: dict = {
    "type": _LEAF,
    "auditActorType": _LEAF,
    "userPrincipalName": _LEAF,
    "userId": _LEAF,
    "applicationId": _LEAF,
    "applicationDisplayName": _LEAF,
    "servicePrincipalName": _LEAF,
    "servicePrincipalId": _LEAF,
    "actorType": _LEAF,
}

AUDIT_MODIFIED_PROPERTY_SCHEMA: dict = {
    "displayName": _LEAF,
}

AUDIT_RESOURCE_SCHEMA: dict = {
    "displayName": _LEAF,
    "type": _LEAF,
    "auditResourceType": _LEAF,
    "resourceId": _LEAF,
    "modifiedProperties": [AUDIT_MODIFIED_PROPERTY_SCHEMA],
}

AUDIT_EVENT_SCHEMA: dict = {
    **{name: _LEAF for name in AUDIT_EVENT_FIELDS if name not in {"actor", "resources"}},
    "actor": AUDIT_ACTOR_SCHEMA,
    "resources": [AUDIT_RESOURCE_SCHEMA],
}

TOOL_SCHEMAS: dict[str, dict] = {
    "get_intune_overview": OVERVIEW_SCHEMA,
    "list_managed_devices": MANAGED_DEVICE_SCHEMA,
    "get_managed_device": MANAGED_DEVICE_SCHEMA,
    "search_managed_devices": MANAGED_DEVICE_SCHEMA,
    "list_noncompliant_devices": MANAGED_DEVICE_SCHEMA,
    "list_detected_apps": DETECTED_APP_SCHEMA,
    "list_compliance_policies": COMPLIANCE_POLICY_SCHEMA,
    "get_compliance_policy_status": COMPLIANCE_STATUS_SCHEMA,
    "list_configuration_profiles": CONFIGURATION_PROFILE_SCHEMA,
    "list_mobile_apps": MOBILE_APP_SCHEMA,
    "list_autopilot_devices": AUTOPILOT_SCHEMA,
    "list_enrollment_configurations": ENROLLMENT_CONFIG_SCHEMA,
    "list_intune_audit_events": AUDIT_EVENT_SCHEMA,
}
