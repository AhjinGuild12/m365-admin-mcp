from __future__ import annotations

from spo_admin_mcp.allowlist import (
    ACCESS_SCALAR_FIELDS,
    IDLE_SESSION_FIELDS,
    SETTINGS_PATH,
    SHARING_FIELDS,
    SITE_CREATION_FIELDS,
    TENANT_SETTING_NAMES,
)
from spo_admin_mcp.tools.tenant_settings import (
    get_tenant_access_settings,
    get_tenant_settings,
    get_tenant_sharing_settings,
    get_tenant_site_creation_settings,
)


def _payload() -> dict:
    body = {name: f"value-{name}" for name in TENANT_SETTING_NAMES if name != "idleSessionSignOut"}
    for name in (
        "sharingAllowedDomainList",
        "sharingBlockedDomainList",
        "allowedDomainGuidsForSyncApp",
        "excludedFileExtensionsForSyncApp",
        "availableManagedPathsForSiteCreation",
    ):
        body[name] = ["kept", {"secret": "nope"}]
    body["idleSessionSignOut"] = {
        "isEnabled": True,
        "warnAfterInSeconds": 60,
        "signOutAfterInSeconds": 120,
        "extraNested": "drop-me",
    }
    body["notADocumentedProperty"] = "drop-me"
    body["Sites.Read.All"] = "drop-me"
    return body


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.payload = _payload()

    def get(self, path: str, params=None, headers=None, **kwargs):
        self.calls.append(path)
        return self.payload


def test_sharing_projection_drops_unlisted_fields() -> None:
    client = FakeClient()
    result = get_tenant_sharing_settings(client)
    settings = result["settings"]
    assert set(settings) == set(SHARING_FIELDS)
    assert settings["sharingAllowedDomainList"] == ["kept", {}]
    assert "notADocumentedProperty" not in settings
    assert client.calls == [SETTINGS_PATH]
    assert result["retrieved_at"].endswith("Z")


def test_access_projection_bounds_idle_session() -> None:
    result = get_tenant_access_settings(FakeClient())
    settings = result["settings"]
    assert set(settings) == set(ACCESS_SCALAR_FIELDS) | {"idleSessionSignOut"}
    assert set(settings["idleSessionSignOut"]) == set(IDLE_SESSION_FIELDS)
    assert "extraNested" not in settings["idleSessionSignOut"]


def test_site_creation_projection_drops_unlisted_fields() -> None:
    result = get_tenant_site_creation_settings(FakeClient())
    settings = result["settings"]
    assert set(settings) == set(SITE_CREATION_FIELDS)
    assert settings["availableManagedPathsForSiteCreation"] == ["kept", {}]
    assert "sharingCapability" not in settings


def test_full_projection_is_the_documented_29() -> None:
    result = get_tenant_settings(FakeClient())
    assert set(result["settings"]) == set(TENANT_SETTING_NAMES)
    assert len(result["settings"]) == 29
    assert set(result["settings"]["idleSessionSignOut"]) == set(IDLE_SESSION_FIELDS)
