"""Authoritative v1 tool names and returned-field allowlists (R5)."""

from __future__ import annotations

TOOL_NAMES: tuple[str, ...] = (
    "get_user",
    "search_users",
    "list_user_groups",
    "list_stale_users",
    "check_user_in_group",
    "get_user_manager",
    "list_user_direct_reports",
    "get_group",
    "list_group_members",
    "search_groups",
    "list_group_owners",
    "list_dynamic_groups",
    "get_device",
    "search_devices",
    "list_user_devices",
    "list_user_signins",
    "list_recent_signins",
    "get_signin",
    "get_org_info",
    "list_subscribed_skus",
    "get_user_licenses",
    "list_users_by_sku",
    "list_license_groups",
    "list_directory_role_members",
    "list_directory_audits",
    "search_service_principals",
    "get_service_principal",
    "list_expiring_app_credentials",
    "list_user_app_assignments",
    "list_tenant_wide_consents",
    "list_conditional_access_policies",
    "get_conditional_access_policy",
    "list_named_locations",
    "list_authentication_strengths",
    "get_tenant_security_settings",
    "get_authentication_methods_policy",
    "get_cross_tenant_access_policy",
    "list_pim_eligible_roles",
    "list_pim_active_roles",
    "list_pim_role_settings",
    "list_domains",
    "list_deleted_users",
)

USER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "givenName",
    "surname",
    "jobTitle",
    "department",
    "accountEnabled",
    "userType",
    "officeLocation",
    "companyName",
)

GROUP_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "mail",
    "description",
    "securityEnabled",
    "mailEnabled",
    "groupTypes",
    "visibility",
)

MEMBER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "givenName",
    "surname",
    "@odata.type",
)

DEVICE_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "deviceId",
    "operatingSystem",
    "operatingSystemVersion",
    "trustType",
    "isManaged",
    "isCompliant",
    "accountEnabled",
    "manufacturer",
    "model",
    "approximateLastSignInDateTime",
    "registrationDateTime",
    "profileType",
)

SIGNIN_FIELDS: tuple[str, ...] = (
    "id",
    "createdDateTime",
    "userDisplayName",
    "userPrincipalName",
    "userId",
    "appDisplayName",
    "appId",
    "resourceDisplayName",
    "resourceId",
    "status",
    "clientAppUsed",
    "isInteractive",
    "correlationId",
    "conditionalAccessStatus",
    "riskDetail",
    "riskLevelDuringSignIn",
    "riskState",
)

ORG_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "tenantType",
    "verifiedDomains",
    "preferredLanguage",
    "createdDateTime",
    "countryLetterCode",
    "onPremisesSyncEnabled",
    "onPremisesLastSyncDateTime",
)

GROUP_SETTING_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "templateId",
    "values",
)

STALE_USER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "userType",
    "accountEnabled",
    "createdDateTime",
    "externalUserState",
    "signInActivity",
)

MANAGER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "jobTitle",
)

DIRECT_REPORT_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "jobTitle",
    "@odata.type",
)

OWNER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "@odata.type",
)

DYNAMIC_GROUP_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "groupTypes",
    "securityEnabled",
    "mailEnabled",
    "membershipRule",
    "membershipRuleProcessingState",
)

SKU_FIELDS: tuple[str, ...] = (
    "skuId",
    "skuPartNumber",
    "capabilityStatus",
    "prepaidUnits",
    "consumedUnits",
    "servicePlans",
    "appliesTo",
)

PREPAID_UNIT_FIELDS: tuple[str, ...] = (
    "enabled",
    "suspended",
    "warning",
)

SERVICE_PLAN_FIELDS: tuple[str, ...] = (
    "servicePlanName",
    "servicePlanId",
    "provisioningStatus",
    "appliesTo",
)

LICENSE_DETAIL_FIELDS: tuple[str, ...] = (
    "skuId",
    "skuPartNumber",
    "servicePlans",
)

LICENSE_ASSIGNMENT_STATE_FIELDS: tuple[str, ...] = (
    "skuId",
    "disabledPlans",
    "assignedByGroup",
    "state",
    "error",
    "lastUpdatedDateTime",
)

LICENSE_USER_FIELDS: tuple[str, ...] = (
    "id",
    "userPrincipalName",
    "displayName",
    "accountEnabled",
    "usageLocation",
)

LICENSE_GROUP_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "assignedLicenses",
    "licenseProcessingState",
)

DIRECTORY_ROLE_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "roleTemplateId",
    "description",
)

DIRECTORY_ROLE_MEMBER_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "@odata.type",
)

AUDIT_FIELDS: tuple[str, ...] = (
    "id",
    "activityDisplayName",
    "category",
    "result",
    "activityDateTime",
    "initiatedBy",
    "targetResources",
    "loggedByService",
    "operationType",
    "resultReason",
    "correlationId",
)

SP_FIELDS: tuple[str, ...] = (
    "id",
    "appId",
    "displayName",
    "servicePrincipalType",
    "accountEnabled",
    "appOwnerOrganizationId",
    "publisherName",
    "signInAudience",
    "tags",
)

APP_ASSIGNMENT_FIELDS: tuple[str, ...] = (
    "id",
    "resourceId",
    "resourceDisplayName",
    "appRoleId",
    "principalId",
    "principalType",
    "createdDateTime",
)

CONSENT_GRANT_FIELDS: tuple[str, ...] = (
    "id",
    "clientId",
    "consentType",
    "scope",
    "resourceId",
    "principalId",
)

APP_CREDENTIAL_SCAN_FIELDS: tuple[str, ...] = (
    "id",
    "appId",
    "displayName",
    "passwordCredentials",
    "keyCredentials",
)

CREDENTIAL_METADATA_FIELDS: tuple[str, ...] = (
    "keyId",
    "displayName",
    "startDateTime",
    "endDateTime",
    "type",
    "usage",
)

MFA_REGISTRATION_FIELDS: tuple[str, ...] = (
    "id",
    "userPrincipalName",
    "userDisplayName",
    "userType",
    "isAdmin",
    "isMfaRegistered",
    "isMfaCapable",
    "isPasswordlessCapable",
    "isSsprRegistered",
    "methodsRegistered",
    "defaultMfaMethod",
    "lastUpdatedDateTime",
)

# Dropped even if Graph returns them (R5). Nested copies are stripped too.
SIGNIN_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "ipAddress",
        "location",
        "ipAddressFromResourceProvider",
    }
)

AUDIT_FORBIDDEN_KEYS: frozenset[str] = SIGNIN_FORBIDDEN_KEYS

CREDENTIAL_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "key",
        "secretText",
        "customKeyIdentifier",
        "hint",
    }
)

DEFAULT_SEARCH_TOP = 25
MAX_SEARCH_TOP = 100
SIGNIN_DEFAULT_TOP = 50
SIGNIN_HARD_CAP = 200
AUDIT_DEFAULT_TOP = 50
AUDIT_HARD_CAP = 200
DEVICE_SCAN_MAX = 2000
LICENSE_SCAN_MAX = 2000
USER_SCAN_MAX = 2000
APP_SCAN_MAX = 2000
GROUP_SCAN_MAX = 2000
GRANT_SCAN_MAX = 500
MEMBER_PAGE_CAP = 200
GROUP_MEMBERSHIP_PAGE_CAP = 200
TRANSITIVE_MEMBERSHIP_PAGE_CAP = 500
CA_POLICY_MAX = 200
NAMED_LOCATION_MAX = 200
CROSS_TENANT_PARTNER_MAX = 200
PIM_SCHEDULE_CAP = 500
PIM_SETTINGS_CAP = 200
DELETED_USER_CAP = 200

CA_POLICY_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "state",
    "createdDateTime",
    "modifiedDateTime",
    "conditions",
    "grantControls",
    "sessionControls",
)

CA_CONDITION_KEYS: tuple[str, ...] = (
    "users",
    "applications",
    "platforms",
    "locations",
    "clientAppTypes",
    "signInRiskLevels",
    "userRiskLevels",
)

NAMED_LOCATION_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "createdDateTime",
    "modifiedDateTime",
    "@odata.type",
    "isTrusted",
    "ipRanges",
    "countriesAndRegions",
    "includeUnknownCountriesAndRegions",
)

AUTH_STRENGTH_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "description",
    "policyType",
    "allowedCombinations",
    "createdDateTime",
    "modifiedDateTime",
)

APPLIED_CA_POLICY_FIELDS: tuple[str, ...] = (
    "id",
    "displayName",
    "result",
    "enforcedGrantControls",
    "enforcedSessionControls",
)

DOMAIN_FIELDS: tuple[str, ...] = (
    "id",
    "isDefault",
    "isInitial",
    "isVerified",
    "authenticationType",
    "supportedServices",
)

DELETED_USER_FIELDS: tuple[str, ...] = (
    "id",
    "userPrincipalName",
    "displayName",
    "deletedDateTime",
)
