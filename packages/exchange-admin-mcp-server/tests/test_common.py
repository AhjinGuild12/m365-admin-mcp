from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError

from exchange_admin_mcp.tools._common import (
    clamp_top,
    compose_folder_identity,
    require_guid,
    validate_smtp_address,
    validate_trace_window,
)
from tests.conftest import gid

NOW = datetime(2026, 9, 23, 0, 0, 0, tzinfo=timezone.utc)


def test_clamp_top_bounds() -> None:
    assert clamp_top(None) == 50
    assert clamp_top(200) == 200
    with pytest.raises(SanitizedGraphError, match="top_cap_exceeded"):
        clamp_top(201)
    with pytest.raises(SanitizedGraphError, match="invalid_top"):
        clamp_top(True)  # type: ignore[arg-type]


def test_require_guid_and_smtp() -> None:
    assert require_guid(gid("a")) == gid("a")
    with pytest.raises(SanitizedGraphError, match="guid_required"):
        require_guid("ada@contoso.com")
    assert validate_smtp_address("ada@contoso.com") == "ada@contoso.com"
    with pytest.raises(SanitizedGraphError, match="invalid_smtp_address"):
        validate_smtp_address("not-an-address")


def test_folder_identity() -> None:
    assert (
        compose_folder_identity("alex@contoso.com", "Inbox\\Reports")
        == "alex@contoso.com:\\Inbox\\Reports"
    )


def test_trace_window_tokens() -> None:
    def iso(moment: datetime) -> str:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    assert validate_trace_window(None, None, now=NOW) is None
    with pytest.raises(SanitizedGraphError, match="window_too_long"):
        validate_trace_window(iso(NOW - timedelta(days=11)), iso(NOW), now=NOW)
    with pytest.raises(SanitizedGraphError, match="window_too_old"):
        validate_trace_window(iso(NOW - timedelta(days=91)), iso(NOW - timedelta(days=90)), now=NOW)
    with pytest.raises(SanitizedGraphError, match="window_in_future"):
        validate_trace_window(iso(NOW), iso(NOW + timedelta(minutes=1)), now=NOW)
    with pytest.raises(SanitizedGraphError, match="invalid_window"):
        validate_trace_window("yesterday", iso(NOW), now=NOW)
