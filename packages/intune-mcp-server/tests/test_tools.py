from __future__ import annotations

import httpx
import pytest

from intune_mcp.server import INTUNE_MISSING_RETRY_AFTER_SECONDS
from intune_mcp.tools import apps, audit, devices, overview, policies
from m365_mcp_kernel.errors import SanitizedGraphError
from tests.conftest import FakeGraph


def _device(**overrides):
    base = {
        "id": "d1",
        "deviceName": "laptop",
        "serialNumber": "SN1",
        "userPrincipalName": "adele@contoso.com",
        "userDisplayName": "Adele",
        "operatingSystem": "macOS",
        "osVersion": "15.0",
        "complianceState": "compliant",
        "managementAgent": "mdm",
        "managedDeviceOwnerType": "company",
        "enrolledDateTime": "2026-01-01T00:00:00Z",
        "lastSyncDateTime": "2026-01-02T00:00:00Z",
        "manufacturer": "Apple",
        "model": "MacBook",
        "isEncrypted": True,
        "isSupervised": True,
        "jailBroken": "False",
        "azureADDeviceId": "aad-1",
        "deviceCategoryDisplayName": "laptops",
        "exchangeAccessState": "allowed",
        "activationLockBypassCode": "SECRET",
        "imei": "drop-imei",
        "notes": "drop-notes",
        "phoneNumber": "drop-phone",
        "ownerType": "should-never-leak",
    }
    base.update(overrides)
    return base


def test_overview_projects_nested_and_drops_unknown() -> None:
    fake = FakeGraph(
        gets={
            "/deviceManagement/managedDeviceOverview": {
                "id": "ov1",
                "enrolledDeviceCount": 3,
                "mdmEnrolledCount": 2,
                "dualEnrolledDeviceCount": 1,
                "secretField": "nope",
                "deviceOperatingSystemSummary": {
                    "macOSCount": 2,
                    "windowsCount": 1,
                    "undocumented": 9,
                },
                "deviceExchangeAccessStateSummary": {
                    "allowedDeviceCount": 3,
                    "blockedDeviceCount": 0,
                },
            }
        }
    )
    result = overview.get_intune_overview(fake)
    assert result["enrolledDeviceCount"] == 3
    assert result["deviceOperatingSystemSummary"]["macOSCount"] == 2
    assert "undocumented" not in result["deviceOperatingSystemSummary"]
    assert "secretField" not in result


def test_list_managed_devices_drops_forbidden_and_unknown() -> None:
    fake = FakeGraph(pages={"/deviceManagement/managedDevices": [_device()]})
    result = devices.list_managed_devices(fake, top=50)
    assert result["complete"] is True
    assert result["truncated"] is False
    assert result["stop_reason"] is None
    row = result["devices"][0]
    assert row["deviceName"] == "laptop"
    assert row["managedDeviceOwnerType"] == "company"
    assert "activationLockBypassCode" not in row
    assert "imei" not in row
    assert "notes" not in row
    assert "ownerType" not in row
    assert "phoneNumber" not in row


def test_unsupported_filter_returning_all_devices_sets_verified_false() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/managedDevices": [
                _device(complianceState="compliant"),
                _device(id="d2", complianceState="noncompliant", deviceName="phone"),
            ]
        }
    )
    result = devices.list_managed_devices(fake, compliance_state="noncompliant", top=50)
    assert result["returned_rows_verified"] is False
    assert result["complete"] is True


def test_cap_hit_is_incomplete_not_complete_negative() -> None:
    items = [_device(id=f"d{i}", deviceName=f"n{i}") for i in range(5)]
    fake = FakeGraph(pages={"/deviceManagement/managedDevices": items})
    result = devices.list_managed_devices(fake, top=3)
    assert result["complete"] is False
    assert result["truncated"] is True
    assert result["stop_reason"] == "item_cap"
    assert result["items_scanned"] == 3
    assert len(result["devices"]) == 3


def test_later_page_failure_is_partial() -> None:
    fake = FakeGraph(
        pages={"/deviceManagement/managedDevices": [_device(), _device(id="d2")]},
        page_errors={
            "/deviceManagement/managedDevices": SanitizedGraphError("5xx graph_error", status_class="5xx")
        },
        page_error_after={"/deviceManagement/managedDevices": 1},
    )
    result = devices.list_managed_devices(fake, top=50)
    assert result["complete"] is False
    assert result["stop_reason"] == "page_error"
    assert len(result["devices"]) == 1


def test_empty_list_is_complete_when_source_exhausted() -> None:
    fake = FakeGraph(pages={"/deviceManagement/managedDevices": []})
    result = devices.list_managed_devices(fake, top=50)
    assert result["complete"] is True
    assert result["devices"] == []
    assert result["stop_reason"] is None


def test_get_managed_device_by_id() -> None:
    fake = FakeGraph(gets={"/deviceManagement/managedDevices/d1": _device()})
    result = devices.get_managed_device(fake, device_id="d1")
    assert result["id"] == "d1"
    assert "activationLockBypassCode" not in result


def test_duplicate_serial_is_ambiguous_never_first_match() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/managedDevices": [
                _device(id="d1", serialNumber="DUP"),
                _device(id="d2", serialNumber="DUP", deviceName="other"),
            ]
        }
    )
    result = devices.get_managed_device(fake, serial_number="DUP")
    assert result["status"] == "ambiguous"
    assert result["match_count"] == 2
    assert "id" not in result


def test_unfinished_serial_scan_is_incomplete() -> None:
    items = [_device(id=f"d{i}", serialNumber="X") for i in range(200)]
    fake = FakeGraph(pages={"/deviceManagement/managedDevices": items})
    result = devices.get_managed_device(fake, serial_number="X")
    assert result["status"] == "incomplete"
    assert result["complete"] is False


def test_search_startswith_device_name() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/managedDevices": [
                _device(deviceName="lap-1"),
                _device(id="d2", deviceName="lap-2"),
            ]
        }
    )
    result = devices.search_managed_devices(fake, device_name_prefix="lap", top=50)
    assert result["returned_rows_verified"] is True
    assert len(result["devices"]) == 2


def test_list_noncompliant_uses_equality_filter() -> None:
    fake = FakeGraph(
        pages={"/deviceManagement/managedDevices": [_device(complianceState="noncompliant")]}
    )
    result = devices.list_noncompliant_devices(fake, top=50)
    assert result["devices"][0]["complianceState"] == "noncompliant"
    assert result["returned_rows_verified"] is True
    filt = fake.calls[0][1]["$filter"]
    assert "complianceState eq 'noncompliant'" in filt


def test_detected_apps_optional_prefix() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/detectedApps": [
                {
                    "id": "a1",
                    "displayName": "Chrome",
                    "version": "1",
                    "sizeInByte": 1,
                    "deviceCount": 2,
                    "publisher": "Google",
                    "secret": "nope",
                }
            ]
        }
    )
    result = apps.list_detected_apps(fake, name_prefix="Chr", top=50)
    assert result["apps"][0]["displayName"] == "Chrome"
    assert "secret" not in result["apps"][0]


def test_compliance_policies_drop_payload() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/deviceCompliancePolicies": [
                {
                    "id": "p1",
                    "displayName": "BitLocker",
                    "description": "enc",
                    "version": 1,
                    "scheduledActionsForRule": [{"secret": "drop"}],
                    "passwordRequired": True,
                }
            ]
        }
    )
    result = policies.list_compliance_policies(fake, top=50)
    assert result["policies"][0]["displayName"] == "BitLocker"
    assert "scheduledActionsForRule" not in result["policies"][0]
    assert "passwordRequired" not in result["policies"][0]


def test_compliance_policy_status_is_per_device_not_per_setting() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/deviceCompliancePolicies/p1/deviceStatuses": [
                {
                    "id": "s1",
                    "deviceDisplayName": "laptop",
                    "deviceId": "d1",
                    "userPrincipalName": "adele@contoso.com",
                    "userName": "Adele",
                    "status": "noncompliant",
                    "setting": "drop-me",
                }
            ]
        }
    )
    result = policies.get_compliance_policy_status(fake, "p1", top=50)
    assert result["per_setting_diagnosis"] is False
    assert result["status_kind"] == "per_device_policy_status"
    assert "setting" not in result["device_statuses"][0]


def test_configuration_profiles_omit_settings_catalog_and_payload() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/deviceConfigurations": [
                {
                    "id": "c1",
                    "displayName": "WiFi",
                    "omaSettings": [{"value": "secret"}],
                    "wiFiPassword": "drop",
                }
            ]
        }
    )
    result = policies.list_configuration_profiles(fake, top=50)
    assert result["settings_catalog_omitted"] is True
    assert "omaSettings" not in result["profiles"][0]
    assert "wiFiPassword" not in result["profiles"][0]


def test_mobile_apps_expand_and_drop_credentials() -> None:
    fake = FakeGraph(
        pages={
            "/deviceAppManagement/mobileApps": [
                {
                    "id": "app1",
                    "displayName": "Company Portal",
                    "publisher": "Microsoft",
                    "isAssigned": True,
                    "publishingState": "published",
                    "@odata.type": "#microsoft.graph.iosVppApp",
                    "encodedCertificate": "SECRET-CERT",
                    "assignments": [
                        {
                            "id": "as1",
                            "intent": "required",
                            "target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"},
                            "secret": "nope",
                        }
                    ],
                }
            ]
        }
    )
    result = apps.list_mobile_apps(fake, top=50)
    app = result["apps"][0]
    assert app["displayName"] == "Company Portal"
    assert "encodedCertificate" not in app
    assert app["assignments"][0]["intent"] == "required"
    assert "secret" not in app["assignments"][0]


def test_mobile_apps_fallback_when_expand_rejected() -> None:
    fake = FakeGraph(
        pages={
            "/deviceAppManagement/mobileApps": [
                {"id": "app1", "displayName": "App", "publisher": "X", "isAssigned": False}
            ],
            "/deviceAppManagement/mobileApps/app1/assignments": [
                {"id": "as1", "intent": "available"}
            ],
        },
        expand_reject="assignments",
    )
    result = apps.list_mobile_apps(fake, top=50)
    assert result["assignments_expanded"] is False
    assert result["apps"][0]["assignments"][0]["intent"] == "available"


def test_autopilot_and_enrollment() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/windowsAutopilotDeviceIdentities": [
                {"id": "ap1", "serialNumber": "AP", "groupTag": "std", "extra": "drop"}
            ],
            "/deviceManagement/deviceEnrollmentConfigurations": [
                {"id": "e1", "displayName": "Default", "payload": "drop"}
            ],
        }
    )
    ap = apps.list_autopilot_devices(fake, top=1)
    assert ap["devices"][0]["serialNumber"] == "AP"
    assert "extra" not in ap["devices"][0]
    en = policies.list_enrollment_configurations(fake, top=50)
    assert en["configurations"][0]["displayName"] == "Default"
    assert "payload" not in en["configurations"][0]


def test_audit_drops_actor_ip_and_modified_values() -> None:
    fake = FakeGraph(
        pages={
            "/deviceManagement/auditEvents": [
                {
                    "id": "ev1",
                    "displayName": "Update",
                    "componentName": "DeviceConfiguration",
                    "activity": "Patch",
                    "activityDateTime": "2026-01-01T00:00:00Z",
                    "activityType": "Patch",
                    "activityResult": "Success",
                    "category": "Device",
                    "actor": {
                        "userPrincipalName": "admin@contoso.com",
                        "applicationDisplayName": "Intune",
                        "applicationId": "app",
                        "ipAddress": "203.0.113.9",
                    },
                    "resources": [
                        {
                            "displayName": "Policy",
                            "type": "DeviceConfiguration",
                            "resourceId": "c1",
                            "modifiedProperties": [
                                {"displayName": "password", "oldValue": "a", "newValue": "b"}
                            ],
                        }
                    ],
                }
            ]
        }
    )
    result = audit.list_intune_audit_events(fake, days=1, top=50)
    actor = result["events"][0]["actor"]
    assert actor["userPrincipalName"] == "admin@contoso.com"
    assert "ipAddress" not in actor
    props = result["events"][0]["resources"][0]["modifiedProperties"]
    assert props[0]["displayName"] == "password"
    assert "oldValue" not in props[0]
    assert "newValue" not in props[0]


def test_token_failure_sanitized(graph_client_factory) -> None:
    def boom() -> str:
        raise RuntimeError("AADSTS7000215 secret https://login.microsoftonline.com/x")

    client = graph_client_factory(token_provider=boom)
    with pytest.raises(SanitizedGraphError, match="token_acquisition_failed") as exc:
        client.get("/deviceManagement/managedDeviceOverview")
    assert "AADSTS" not in str(exc.value)
    assert "login.microsoftonline" not in str(exc.value)


def test_intune_429_without_retry_after_waits_five_seconds(graph_client_factory) -> None:
    n = {"c": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["c"] += 1
        if n["c"] == 1:
            return httpx.Response(429, json={"error": "slow"})
        return httpx.Response(200, json={"id": "ov", "enrolledDeviceCount": 1})

    client = graph_client_factory(
        missing_retry_after_seconds=INTUNE_MISSING_RETRY_AFTER_SECONDS,
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    data = client.get("/deviceManagement/managedDeviceOverview")
    assert data["enrolledDeviceCount"] == 1
    assert n["c"] == 2
    assert client.sleeps == [5.0]


def test_invalid_top_refused() -> None:
    fake = FakeGraph(pages={"/deviceManagement/managedDevices": []})
    with pytest.raises(SanitizedGraphError, match="invalid_top"):
        devices.list_managed_devices(fake, top=0)
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        devices.list_managed_devices(fake, top=201)
