"""Structurally GET-only Microsoft Graph v1.0 client (KTD2, KTD2b, KTD7).

Sole first-party network importer. Copied from entra_mcp.graph_client then
generalized: env prefix, origin enum {graph}, Intune missing-Retry-After
branch, and fetch_report (credential-free second hop).
"""

from __future__ import annotations

import csv
import io
import logging
import os
import time
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
from azure.identity import ClientSecretCredential

from m365_mcp_kernel.errors import SanitizedGraphError, sanitized_http_error

# azure-identity/msal log token-endpoint URLs and AADSTS bodies to stderr by default.
logging.getLogger("azure").setLevel(logging.CRITICAL)
logging.getLogger("msal").setLevel(logging.CRITICAL)
logging.getLogger("azure.identity").setLevel(logging.CRITICAL)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_RETRY_ATTEMPTS = 3
MAX_RETRY_WAIT_SECONDS = 60.0
TOKEN_REFRESH_SKEW_SECONDS = 60.0

# KTD2b — reviewed constant. A live host that differs fails closed (never learned).
REPORT_DOWNLOAD_HOSTS = frozenset({"reports.office.com"})
ALLOWED_REPORT_FUNCTIONS = frozenset(
    {
        "getSharePointSiteUsageDetail",
        "getSharePointSiteUsageStorage",
        "getSharePointSiteUsageSiteCounts",
        "getMailboxUsageDetail",
        "getEmailActivityUserDetail",
    }
)
ALLOWED_REPORT_PERIODS = frozenset({"D7", "D30", "D90", "D180"})
MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_REPORT_ROWS = 5000
MAX_REPORT_FIELD_BYTES = 64 * 1024
INTUNE_MISSING_RETRY_AFTER_SECONDS = 5.0

SleepFn = Callable[[float], None]
TokenProvider = Callable[[], str]


class Origin(str, Enum):
    """Closed origin enum. v1 admits only Graph."""

    GRAPH = "graph"


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


def _coerce_origin(origin: Origin | str) -> Origin:
    if origin is Origin.GRAPH or origin == Origin.GRAPH.value or origin == "graph":
        return Origin.GRAPH
    raise SanitizedGraphError("origin_rejected", status_class="4xx")


def assert_graph_origin(url: str) -> None:
    if not isinstance(url, str):
        raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")
    if url == GRAPH_BASE:
        return
    if url.startswith(GRAPH_BASE + "/") or url.startswith(GRAPH_BASE + "?"):
        return
    raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")


def _env(prefix: str | None, name: str, override: str | None) -> str:
    if override is not None:
        return override
    if not prefix:
        return ""
    key = f"{prefix.rstrip('_')}_{name}"
    return os.environ.get(key, "")


def _report_graph_path(function_path: str, period: str) -> str:
    if not isinstance(function_path, str) or not isinstance(period, str):
        raise SanitizedGraphError("report_function_rejected", status_class="4xx")
    name = function_path
    if name.startswith("/reports/"):
        name = name[len("/reports/") :]
    if "/" in name or "." in name or "\\" in name or " " in name:
        raise SanitizedGraphError("report_function_rejected", status_class="4xx")
    if name not in ALLOWED_REPORT_FUNCTIONS:
        raise SanitizedGraphError("report_function_rejected", status_class="4xx")
    if period not in ALLOWED_REPORT_PERIODS:
        raise SanitizedGraphError("report_period_rejected", status_class="4xx")
    return f"/reports/{name}(period='{period}')"


def validate_report_download_url(location: object) -> str:
    """Validate a 302 Location. Raises before any second request. Never echoes URL."""
    if not isinstance(location, str) or location == "":
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    try:
        parts = urlsplit(location)
    except ValueError:
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx") from None
    if parts.scheme == "" or parts.netloc == "":
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    if parts.scheme.lower() != "https":
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    if parts.username is not None or parts.password is not None:
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    if parts.fragment:
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    hostname = parts.hostname
    if hostname is None:
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    hostname = hostname.lower().rstrip(".")
    if hostname not in REPORT_DOWNLOAD_HOSTS:
        raise SanitizedGraphError("report_host_rejected", status_class="4xx")
    if parts.port is not None and parts.port != 443:
        raise SanitizedGraphError("report_redirect_rejected", status_class="4xx")
    return location


def _parse_csv_text(text: str) -> list[dict[str, str]]:
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        reader = csv.reader(io.StringIO(text, newline=""))
        rows_iter = iter(reader)
        try:
            header = next(rows_iter)
        except StopIteration:
            return []
        if not header:
            raise SanitizedGraphError("report_csv_malformed", status_class="5xx")
        out: list[dict[str, str]] = []
        for raw in rows_iter:
            if len(out) >= MAX_REPORT_ROWS:
                break
            for cell in raw:
                if isinstance(cell, str) and len(cell.encode("utf-8")) > MAX_REPORT_FIELD_BYTES:
                    raise SanitizedGraphError("report_field_too_large", status_class="5xx")
            row = {header[i]: (raw[i] if i < len(raw) else "") for i in range(len(header))}
            out.append(row)
        return out
    except csv.Error:
        raise SanitizedGraphError("report_csv_malformed", status_class="5xx") from None
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("report_csv_malformed", status_class="5xx") from None


class GraphClient:
    """Public surface is GET + pagination + fetch_report. No POST/PATCH/PUT/DELETE."""

    def __init__(
        self,
        *,
        env_prefix: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        http_client: httpx.Client | None = None,
        report_http_client: httpx.Client | None = None,
        token_provider: TokenProvider | None = None,
        sleep: SleepFn | None = None,
        missing_retry_after_seconds: float | None = None,
    ) -> None:
        self._env_prefix = env_prefix.rstrip("_") if env_prefix else None
        self._tenant_id = _env(self._env_prefix, "TENANT_ID", tenant_id)
        self._client_id = _env(self._env_prefix, "CLIENT_ID", client_id)
        self._client_secret = _env(self._env_prefix, "CLIENT_SECRET", client_secret)
        self._token_provider = token_provider
        self._credential: ClientSecretCredential | None = None
        self._cached_token: str | None = None
        self._cached_token_expires = 0.0
        self._sleep: SleepFn = sleep or time.sleep
        self._missing_retry_after_seconds = missing_retry_after_seconds
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
        if report_http_client is not None:
            self._report_http = report_http_client
            self._owns_report_http = False
        else:
            self._report_http = None
            self._owns_report_http = True

    def _report_client(self) -> httpx.Client:
        if self._report_http is None:
            self._report_http = httpx.Client(
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(10.0, read=30.0),
                headers={},
            )
            self._owns_report_http = True
        return self._report_http

    def close(self) -> None:
        if self._owns_http:
            self._http.close()
        if self._owns_report_http and self._report_http is not None:
            self._report_http.close()

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        origin: Origin | str = Origin.GRAPH,
    ) -> dict[str, Any]:
        _coerce_origin(origin)
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
        origin: Origin | str = Origin.GRAPH,
    ) -> Iterator[dict[str, Any]]:
        data = self.get(path, params=params, headers=headers, origin=origin)
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
        origin: Origin | str = Origin.GRAPH,
    ) -> list[dict[str, Any]]:
        return list(
            self.iter_pages(
                path, params=params, headers=headers, item_cap=item_cap, origin=origin
            )
        )

    def fetch_report(self, function_path: str, period: str) -> list[dict[str, str]]:
        """Authenticated GET → 302 → credential-free download (KTD2b).

        Raised errors and logs never contain URL, path, or query.
        """
        graph_path = _report_graph_path(function_path, period)
        url = f"{GRAPH_BASE}{graph_path}"
        try:
            request_headers = self._auth_headers(None)
        except SanitizedGraphError:
            raise
        except Exception:
            raise SanitizedGraphError("token_acquisition_failed", status_class="auth") from None
        try:
            response = self._http.get(url, headers=request_headers)
        except httpx.HTTPError:
            raise sanitized_http_error(None, "network_error") from None
        if response.status_code != 302:
            if response.status_code >= 400:
                raise sanitized_http_error(response.status_code, "graph_error")
            raise SanitizedGraphError("report_redirect_missing", status_class="4xx")
        location = response.headers.get("Location")
        validated = validate_report_download_url(location)
        return self._download_report(validated)

    def _download_report(self, url: str) -> list[dict[str, str]]:
        client = self._report_client()
        download_headers = {"Accept": "text/csv"}
        try:
            with client.stream(
                "GET",
                url,
                headers=download_headers,
            ) as response:
                if response.status_code != 200:
                    if 300 <= response.status_code < 400:
                        raise SanitizedGraphError("report_second_redirect", status_class="4xx")
                    raise sanitized_http_error(response.status_code, "report_download_failed")
                return self._consume_report_body(response)
        except SanitizedGraphError:
            raise
        except httpx.HTTPError:
            raise sanitized_http_error(None, "network_error") from None
        except Exception:
            raise SanitizedGraphError("report_download_failed", status_class="5xx") from None

    def _consume_report_body(self, response: httpx.Response) -> list[dict[str, str]]:
        total = 0
        chunks: list[bytes] = []
        try:
            for chunk in response.iter_bytes():
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_REPORT_BYTES:
                    raise SanitizedGraphError("report_too_large", status_class="5xx")
                chunks.append(chunk)
        except SanitizedGraphError:
            raise
        except httpx.HTTPError:
            raise sanitized_http_error(None, "network_error") from None
        try:
            text = b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise SanitizedGraphError("report_csv_malformed", status_class="5xx") from None
        rows = _parse_csv_text(text)
        if len(rows) > MAX_REPORT_ROWS:
            return rows[:MAX_REPORT_ROWS]
        return rows

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

    def _retry_delay(self, header: str | None) -> float:
        delay = parse_retry_after(header)
        if delay is not None:
            return delay
        missing = header is None or (isinstance(header, str) and header.strip() == "")
        if missing and self._missing_retry_after_seconds is not None:
            return float(self._missing_retry_after_seconds)
        raise sanitized_http_error(429, "malformed_retry_after")

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
                try:
                    delay = self._retry_delay(response.headers.get("Retry-After"))
                except SanitizedGraphError:
                    raise
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
