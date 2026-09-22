"""Sanitized errors: status class + stable message, never bodies or query strings.

Byte-copied from entra_mcp.errors then left structurally identical (KTD1).
"""

from __future__ import annotations


class SanitizedGraphError(Exception):
    """MCP-safe Graph/auth failure. ``str(err)`` contains no credential or URL."""

    def __init__(self, message: str, status_class: str | None = None) -> None:
        self.message = message
        self.status_class = status_class
        super().__init__(message)


def status_class_for(status_code: int | None) -> str:
    if status_code is None:
        return "network"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "other"


def sanitized_http_error(status_code: int | None, reason: str) -> SanitizedGraphError:
    cls = status_class_for(status_code)
    return SanitizedGraphError(f"{cls} {reason}", status_class=cls)
