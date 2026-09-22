from __future__ import annotations

from m365_mcp_kernel.schema import project_schema, project_then_strip, strip_keys

AUDIT_SCHEMA = {
    "id": True,
    "activityDateTime": True,
    "activity": True,
    "actor": {
        "userPrincipalName": True,
        "displayName": True,
        "auditActorType": True,
        "userId": True,
    },
    "resources": [
        {
            "displayName": True,
            "resourceId": True,
            "auditResourceType": True,
        }
    ],
}

POLICY_SCHEMA = {
    "id": True,
    "displayName": True,
    "assignments": [{"target": {"deviceAndAppManagementAssignmentFilterType": True}}],
}

APP_SCHEMA = {
    "id": True,
    "displayName": True,
    "assignments": [{"id": True, "intent": True}],
}

AUTO_REPLY_SCHEMA = {
    "status": True,
    "scheduledStartDateTime": {"dateTime": True, "timeZone": True},
    "scheduledEndDateTime": {"dateTime": True, "timeZone": True},
    "externalAudience": True,
}

RULE_SCHEMA = {
    "id": True,
    "displayName": True,
    "isEnabled": True,
    "sequence": True,
    "hasConditions": True,
    "actions": {
        "forwardTo": [{"emailAddress": {"address": True}}],
        "redirectTo": [{"emailAddress": {"address": True}}],
        "forwardAsAttachmentTo": [{"emailAddress": {"address": True}}],
        "delete": True,
        "moveToFolder": True,
    },
}

TRACE_DETAIL_SCHEMA = {
    "id": True,
    "messageId": True,
    "dateTime": True,
    "event": True,
    "action": True,
}

TRACE_LIST_SCHEMA = {
    "id": True,
    "messageId": True,
    "receivedDateTime": True,
    "status": True,
    "from": True,
    "toRecipients": True,
}


def test_unknown_and_forbidden_fields_dropped_at_every_depth() -> None:
    payload = {
        "id": "evt-1",
        "activity": "update",
        "secret": "nope",
        "actor": {
            "userPrincipalName": "admin@contoso.com",
            "displayName": "Admin",
            "ipAddress": "203.0.113.9",
            "userId": "u1",
            "modifiedProperties": [
                {"displayName": "Policy", "oldValue": "old-secret", "newValue": "new-secret"}
            ],
        },
        "resources": [
            {
                "displayName": "Device A",
                "resourceId": "d1",
                "extra": "drop-me",
            }
        ],
    }
    out = project_schema(payload, AUDIT_SCHEMA)
    assert "secret" not in out
    assert "ipAddress" not in out["actor"]
    assert "modifiedProperties" not in out["actor"]
    assert out["actor"]["userPrincipalName"] == "admin@contoso.com"
    assert "extra" not in out["resources"][0]
    dumped = str(out)
    assert "203.0.113.9" not in dumped
    assert "old-secret" not in dumped
    assert "new-secret" not in dumped


def test_parent_true_does_not_admit_arbitrary_children() -> None:
    schema = {"actor": True}
    out = project_schema({"actor": {"ipAddress": "1.2.3.4", "name": "x"}}, schema)
    assert out == {"actor": {}}


def test_policy_and_app_nested_credential_fields_dropped() -> None:
    policy = {
        "id": "p1",
        "displayName": "Policy",
        "omaSettings": [{"secretReferenceValueId": "cred-1", "value": "password"}],
        "assignments": [
            {
                "target": {
                    "deviceAndAppManagementAssignmentFilterType": "none",
                    "embeddedSecret": "shh",
                }
            }
        ],
    }
    out = project_schema(policy, POLICY_SCHEMA)
    assert "omaSettings" not in out
    assert "embeddedSecret" not in str(out)

    app = {
        "id": "a1",
        "displayName": "App",
        "vppToken": "token-value",
        "assignments": [{"id": "as1", "intent": "required", "secret": "x"}],
    }
    out_app = project_schema(app, APP_SCHEMA)
    assert "vppToken" not in out_app
    assert "secret" not in out_app["assignments"][0]


def test_auto_reply_bodies_dropped() -> None:
    payload = {
        "status": "scheduled",
        "internalReplyMessage": "<p>out of office internal</p>",
        "externalReplyMessage": "<p>out of office external</p>",
        "externalAudience": "all",
        "scheduledStartDateTime": {"dateTime": "2026-01-01T00:00:00", "timeZone": "UTC", "extra": 1},
    }
    out = project_schema(payload, AUTO_REPLY_SCHEMA)
    assert "internalReplyMessage" not in out
    assert "externalReplyMessage" not in out
    assert "extra" not in out["scheduledStartDateTime"]
    assert "out of office" not in str(out)


def test_rule_condition_values_dropped_action_summary_kept() -> None:
    payload = {
        "id": "r1",
        "displayName": "Forward",
        "isEnabled": True,
        "sequence": 1,
        "hasConditions": True,
        "conditions": {"sentToAddresses": ["victim@example.com"], "subjectContains": ["secret-topic"]},
        "actions": {
            "forwardTo": [{"emailAddress": {"address": "fwd@example.com", "name": "Fwd"}}],
            "delete": False,
            "moveToFolder": "Junk",
            "other": "drop",
        },
    }
    out = project_schema(payload, RULE_SCHEMA)
    assert "conditions" not in out
    assert out["actions"]["forwardTo"][0]["emailAddress"] == {"address": "fwd@example.com"}
    assert "name" not in out["actions"]["forwardTo"][0]["emailAddress"]
    assert "other" not in out["actions"]
    assert "secret-topic" not in str(out)


def test_trace_detail_keeps_only_enumerated_fields() -> None:
    payload = {
        "id": "t1",
        "messageId": "<mid>",
        "dateTime": "2026-09-01T00:00:00Z",
        "event": "Deliver",
        "action": "Delivered",
        "data": {"raw": "blob"},
        "description": "full diagnostic text",
        "ipAddress": "198.51.100.9",
    }
    out = project_schema(payload, TRACE_DETAIL_SCHEMA)
    assert set(out) == {"id", "messageId", "dateTime", "event", "action"}
    assert "data" not in out
    assert "description" not in out
    assert "ipAddress" not in out


def test_trace_list_omits_ip_fields() -> None:
    payload = {
        "id": "m1",
        "messageId": "<mid>",
        "receivedDateTime": "2026-09-01T00:00:00Z",
        "status": "Delivered",
        "from": "a@b.com",
        "toRecipients": ["c@d.com"],
        "senderIP": "192.0.2.1",
        "clientIP": "192.0.2.2",
    }
    out = project_schema(payload, TRACE_LIST_SCHEMA)
    assert "senderIP" not in out
    assert "clientIP" not in out
    assert out["from"] == "a@b.com"


def test_strip_keys_defense_in_depth_after_projection() -> None:
    projected = project_schema(
        {"id": "1", "actor": {"userPrincipalName": "a@b.com", "ipAddress": "1.1.1.1"}},
        AUDIT_SCHEMA,
    )
    banned = frozenset({"ipAddress", "modifiedProperties", "data", "description"})
    out = project_then_strip(
        {"id": "1", "actor": {"userPrincipalName": "a@b.com", "ipAddress": "1.1.1.1"}},
        AUDIT_SCHEMA,
        banned,
    )
    assert "ipAddress" not in str(out)
    assert strip_keys(projected, banned) == projected
