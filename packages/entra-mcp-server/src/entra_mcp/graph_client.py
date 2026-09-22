"""Structurally GET-only Microsoft Graph v1.0 client (KTD2, KTD7)."""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable
import httpx
from azure.identity import ClientSecretCredential

from entra_mcp.errors import SanitizedGraphError, sanitized_http_error

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# azure-identity/msal log token-endpoint URLs and AADSTS bodies to stderr by default.
logging.getLogger("azure").setLevel(logging.CRITICAL)
logging.getLogger("msal").setLevel(logging.CRITICAL)
logging.getLogger("azure.identity").setLevel(logging.CRITICAL)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_RETRY_ATTEMPTS = 3
MAX_RETRY_WAIT_SECONDS = 60.0
TOKEN_REFRESH_SKEW_SECONDS = 60.0

SleepFn = Callable[[float], None]
TokenProvider = Callable[[], str]


_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def encode_path_segment(value: str) -> str:
    """Percent-encode a single path segment. No raw interpolation."""
    if not isinstance(value, str) or value == "":
        raise SanitizedGraphError("invalid_path_segment", status_class="4xx")
    out: list[str] = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch in _UNRESERVED:
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def escape_odata_string(value: str) -> str:
    """Escape a value for a single-quoted OData string literal."""
    return value.replace("'", "''")


def odata_eq(field: str, value: str) -> str:
    return f"{field} eq '{escape_odata_string(value)}'"


def is_guid(value: str) -> bool:
    return isinstance(value, str) and bool(_GUID_RE.fullmatch(value))


def build_search_clause(property_name: str, query: str) -> str:
    """Build one `$search` clause: "property:text" with Graph escaping."""
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{property_name}:{escaped}"'


def parse_retry_after(header: str | None, *, now: datetime | None = None) -> float | None:
    """Return wait seconds, or None if missing/malformed (no retry)."""
    if header is None:
        return None
    text = header.strip()
    if not text:
        return None
    if text.isdigit():
        return float(int(text))
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    delay = (when - current).total_seconds()
    if delay < 0:
        return 0.0
    return delay


def _assert_relative_path(path: str) -> None:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise SanitizedGraphError("invalid_path", status_class="4xx")
    if path.startswith("http://") or path.startswith("https://"):
        raise SanitizedGraphError("absolute_url_rejected", status_class="4xx")
    if "?" in path or "#" in path:
        raise SanitizedGraphError("path_query_rejected", status_class="4xx")


def assert_graph_origin(url: str) -> None:
    if not isinstance(url, str):
        raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")
    if url == GRAPH_BASE:
        return
    if url.startswith(GRAPH_BASE + "/") or url.startswith(GRAPH_BASE + "?"):
        return
    raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")


class GraphClient:
    """Public surface is GET + pagination. No POST/PATCH/PUT/DELETE."""

    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        http_client: httpx.Client | None = None,
        token_provider: TokenProvider | None = None,
        sleep: SleepFn | None = None,
    ) -> None:
        self._tenant_id = tenant_id if tenant_id is not None else os.environ.get("ENTRA_TENANT_ID", "")
        self._client_id = client_id if client_id is not None else os.environ.get("ENTRA_CLIENT_ID", "")
        self._client_secret = (
            client_secret if client_secret is not None else os.environ.get("ENTRA_CLIENT_SECRET", "")
        )
        self._token_provider = token_provider
        self._credential: ClientSecretCredential | None = None
        self._cached_token: str | None = None
        self._cached_token_expires = 0.0
        self._sleep: SleepFn = sleep or time.sleep
        if http_client is not None:
            self._http = http_client
            self._owns_http = False
        else:
            self._http = httpx.Client(
                trust_env=False,
                follow_redirects=False,
                timeout=30.0,
            )
            self._owns_http = True

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        _assert_relative_path(path)
        url = f"{GRAPH_BASE}{path}"
        return self._get_url(url, params=params, headers=headers)

    def iter_pages(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        item_cap: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        data = self.get(path, params=params, headers=headers)
        yielded = 0
        while True:
            for item in data.get("value") or []:
                if not isinstance(item, dict):
                    continue
                yield item
                yielded += 1
                if item_cap is not None and yielded >= item_cap:
                    return
            next_link = data.get("@odata.nextLink")
            if not next_link:
                return
            if not isinstance(next_link, str):
                raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")
            assert_graph_origin(next_link)
            data = self._get_url(next_link, params=None, headers=headers)

    def collect_page(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        item_cap: int | None = None,
    ) -> list[dict[str, Any]]:
        return list(self.iter_pages(path, params=params, headers=headers, item_cap=item_cap))

    def _token(self) -> str:
        now = time.time()
        if self._cached_token and now < self._cached_token_expires:
            return self._cached_token
        try:
            if self._token_provider is not None:
                token = self._token_provider()
                self._cached_token = token
                self._cached_token_expires = now + 300.0
                return token
            if self._credential is None:
                if not self._tenant_id or not self._client_id or not self._client_secret:
                    raise SanitizedGraphError("token_acquisition_failed", status_class="auth")
                self._credential = ClientSecretCredential(
                    tenant_id=self._tenant_id,
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                )
            result = self._credential.get_token(GRAPH_SCOPE)
        except SanitizedGraphError:
            raise
        except Exception:
            raise SanitizedGraphError("token_acquisition_failed", status_class="auth") from None
        self._cached_token = result.token
        expires = float(result.expires_on) - TOKEN_REFRESH_SKEW_SECONDS
        self._cached_token_expires = expires
        return result.token

    def _auth_headers(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _get_url(
        self,
        url: str,
        params: Mapping[str, str] | None,
        headers: Mapping[str, str] | None,
    ) -> dict[str, Any]:
        attempts = 0
        waited = 0.0
        while True:
            attempts += 1
            try:
                request_headers = self._auth_headers(headers)
            except SanitizedGraphError:
                raise
            except Exception:
                raise SanitizedGraphError("token_acquisition_failed", status_class="auth") from None
            try:
                response = self._http.get(
                    url,
                    params=dict(params) if params else None,
                    headers=request_headers,
                )
            except httpx.HTTPError:
                raise sanitized_http_error(None, "network_error") from None
            status = response.status_code
            if status in (429, 503, 504):
                if attempts >= MAX_RETRY_ATTEMPTS:
                    raise sanitized_http_error(status, "retries_exhausted")
                delay = parse_retry_after(response.headers.get("Retry-After"))
                if delay is None:
                    raise sanitized_http_error(status, "malformed_retry_after")
                if waited + delay > MAX_RETRY_WAIT_SECONDS:
                    raise sanitized_http_error(status, "retry_budget_exhausted")
                self._sleep(delay)
                waited += delay
                continue
            if status >= 400:
                raise sanitized_http_error(status, "graph_error")
            try:
                payload = response.json()
            except ValueError:
                raise SanitizedGraphError("invalid_json", status_class="5xx") from None
            if not isinstance(payload, dict):
                raise SanitizedGraphError("invalid_json", status_class="5xx")
            return payload
