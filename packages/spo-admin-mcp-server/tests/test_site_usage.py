from __future__ import annotations

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from spo_admin_mcp.allowlist import DETAIL_FIELDS, REPORT_ROW_CAP
from spo_admin_mcp.tools.site_usage import (
    get_site_usage,
    get_site_usage_summary,
    list_site_usage,
)


def _detail(**overrides: str) -> dict[str, str]:
    row = {
        "Report Refresh Date": "2026-09-20",
        "Site Id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "Site URL": "https://contoso.sharepoint.com/sites/Alpha",
        "Owner Display Name": "Ada Lovelace",
        "Owner Principal Name": "ada@contoso.com",
        "Is Deleted": "False",
        "Last Activity Date": "2026-09-19",
        "File Count": "3",
        "Active File Count": "1",
        "Storage Used (Byte)": "10",
        "Storage Allocated (Byte)": "20",
        "Root Web Template": "STS",
        "Report Period": "7",
        "Page View Count": "99",
        "Visited Page Count": "5",
        "External Sharing": "yes",
    }
    row.update(overrides)
    return row


class FakeReports:
    def __init__(self, rows: dict[str, list[dict[str, str]]] | None = None) -> None:
        self.rows = rows or {}
        self.calls: list[tuple[str, str]] = []

    def fetch_report(self, function_path: str, period: str) -> list[dict[str, str]]:
        self.calls.append((function_path, period))
        return list(self.rows.get(function_path, []))


def test_empty_report() -> None:
    client = FakeReports()
    result = list_site_usage(client, "D7")
    assert result["items"] == []
    assert result["complete"] is True
    assert result["truncated"] is False
    assert result["items_scanned"] == 0
    assert result["identity_visibility"] == "unknown"
    assert result["identity_visibility_basis"] == "no rows"
    assert result["report_refresh_date"] is None


def test_visible_and_deleted_owner_rows() -> None:
    deleted = _detail(
        **{
            "Site Id": "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
            "Site URL": "https://contoso.sharepoint.com/sites/Gone",
            "Owner Display Name": "",
            "Owner Principal Name": "",
            "Is Deleted": "True",
        }
    )
    client = FakeReports({"getSharePointSiteUsageDetail": [_detail(), deleted]})
    result = list_site_usage(client, "D30")
    assert result["identity_visibility"] == "visible"
    assert "email shape" in result["identity_visibility_basis"]
    assert len(result["items"]) == 2
    assert result["items"][1]["Is Deleted"] == "True"
    assert "Page View Count" not in result["items"][0]
    assert "External Sharing" not in result["items"][0]
    assert set(result["items"][0]) == set(DETAIL_FIELDS)


def test_concealed_rows() -> None:
    hidden = _detail(
        **{
            "Owner Display Name": "",
            "Owner Principal Name": "a1b2c3d4e5",
        }
    )
    result = list_site_usage(FakeReports({"getSharePointSiteUsageDetail": [hidden]}), "D7")
    assert result["identity_visibility"] == "concealed"
    assert "non-email" in result["identity_visibility_basis"]


def test_mixed_principal_shapes_are_unknown() -> None:
    opaque = _detail(
        **{
            "Site URL": "https://contoso.sharepoint.com/sites/Beta",
            "Owner Principal Name": "deadbeef",
            "Owner Display Name": "",
        }
    )
    result = list_site_usage(FakeReports({"getSharePointSiteUsageDetail": [_detail(), opaque]}), "D7")
    assert result["identity_visibility"] == "unknown"
    assert result["identity_visibility_basis"] == "mixed owner principal shapes"


def test_cap_hit_marks_truncated() -> None:
    rows = [
        _detail(**{"Site Id": f"{index:08x}-bbbb-cccc-dddd-eeeeeeeeeeee", "Site URL": f"https://contoso.sharepoint.com/sites/{index}"})
        for index in range(REPORT_ROW_CAP)
    ]
    result = list_site_usage(FakeReports({"getSharePointSiteUsageDetail": rows}), "D90")
    assert result["truncated"] is True
    assert result["complete"] is False
    assert result["stop_reason"] == "item_cap"
    assert result["items_scanned"] == REPORT_ROW_CAP
    assert len(result["items"]) == REPORT_ROW_CAP


def test_period_outside_enum_makes_no_call() -> None:
    client = FakeReports({"getSharePointSiteUsageDetail": [_detail()]})
    with pytest.raises(SanitizedGraphError) as caught:
        list_site_usage(client, "D14")
    assert caught.value.message == "invalid_period"
    assert client.calls == []


def test_unique_url_match_ignores_one_trailing_slash() -> None:
    client = FakeReports({"getSharePointSiteUsageDetail": [_detail()]})
    result = get_site_usage(client, "https://Contoso.SharePoint.com/sites/Alpha/", "D7")
    assert result["status"] == "ok"
    assert result["item"]["Site URL"].endswith("/Alpha")


def test_duplicate_normalized_url_is_ambiguous() -> None:
    second = _detail(**{"Site URL": "https://contoso.sharepoint.com/sites/Alpha/"})
    client = FakeReports({"getSharePointSiteUsageDetail": [_detail(), second]})
    result = get_site_usage(client, "https://contoso.sharepoint.com/sites/Alpha", "D7")
    assert result["status"] == "ambiguous"
    assert result["match_count"] == 2
    assert "item" not in result


def test_missing_target_on_capped_scan_is_incomplete() -> None:
    rows = [
        _detail(**{"Site URL": f"https://contoso.sharepoint.com/sites/{index}"})
        for index in range(REPORT_ROW_CAP)
    ]
    result = get_site_usage(
        FakeReports({"getSharePointSiteUsageDetail": rows}),
        "https://contoso.sharepoint.com/sites/missing",
        "D7",
    )
    assert result["status"] == "incomplete"
    assert result["truncated"] is True


def test_concealed_identity_target_is_unresolvable() -> None:
    hidden = _detail(**{"Owner Principal Name": "abc123", "Owner Display Name": ""})
    client = FakeReports({"getSharePointSiteUsageDetail": [hidden]})
    result = get_site_usage(client, "ada@contoso.com", "D7")
    assert result["status"] == "identity_unresolvable"
    with pytest.raises(SanitizedGraphError):
        get_site_usage(FakeReports({"getSharePointSiteUsageDetail": [_detail()]}), "nobody@contoso.com", "D7")


def test_summary_merges_on_report_date_and_drops_extra_columns() -> None:
    storage = [
        {
            "Report Refresh Date": "2026-09-20",
            "Site Type": "All",
            "Storage Used (Byte)": "5",
            "Report Date": "2026-09-19",
            "Page View Count": "9",
        }
    ]
    counts = [
        {
            "Site Type": "All",
            "Total": "4",
            "Active": "2",
            "Report Date": "2026-09-19",
            "Geo Location": "NAM",
        }
    ]
    client = FakeReports(
        {
            "getSharePointSiteUsageStorage": storage,
            "getSharePointSiteUsageSiteCounts": counts,
        }
    )
    result = get_site_usage_summary(client, "D180")
    assert result["identity_visibility"] == "unknown"
    assert result["items"] == [
        {
            "Report Date": "2026-09-19",
            "storage": [
                {
                    "Report Refresh Date": "2026-09-20",
                    "Site Type": "All",
                    "Storage Used (Byte)": "5",
                    "Report Date": "2026-09-19",
                }
            ],
            "counts": [
                {
                    "Site Type": "All",
                    "Total": "4",
                    "Active": "2",
                    "Report Date": "2026-09-19",
                }
            ],
        }
    ]
    assert client.calls[0][0] == "getSharePointSiteUsageStorage"
    assert client.calls[1][0] == "getSharePointSiteUsageSiteCounts"
