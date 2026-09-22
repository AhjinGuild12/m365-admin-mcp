"""Exchange Online Admin API v2.0 client. The only network module in this package."""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx
from azure.identity import ClientSecretCredential

from m365_mcp_kernel.errors import SanitizedGraphError, sanitized_http_error
from m365_mcp_kernel.graph_client import (
    MAX_RETRY_ATTEMPTS,
    MAX_RETRY_WAIT_SECONDS,
    TOKEN_REFRESH_SKEW_SECONDS,
    parse_retry_after,
)
from m365_mcp_kernel.schema import project_schema, strip_keys

from exchange_admin_mcp.allowlist import EXO_ENDPOINTS, EXO_REQUIRED_PARAMS, FORBIDDEN_KEYS

# azure-identity/msal log token-endpoint URLs and AADSTS bodies to stderr by default.
logging.getLogger("azure").setLevel(logging.CRITICAL)
logging.getLogger("msal").setLevel(logging.CRITICAL)
logging.getLogger("azure.identity").setLevel(logging.CRITICAL)

EXO_SCOPE = "https://outlook.office365.com/.default"
EXO_ORIGIN = "https://outlook.office365.com"
SYSTEM_MAILBOX_GUID = "bb558c35-97f1-4cb9-8ff7-d53741dc928c"
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SELECT = re.compile(r"^[A-Za-z][A-Za-z0-9]*(\s*,\s*[A-Za-z][A-Za-z0-9]*)*$")
_ERROR_KEYS = ("error", "Exception", "ErrorRecord")

SleepFn = Callable[[float], None]
TokenProvider = Callable[[], str]


def system_mailbox_anchor(tenant_id: str) -> str:
    return f"APP:SystemMailbox{{{SYSTEM_MAILBOX_GUID}}}@{tenant_id}"


def smtp_anchor(address: str) -> str:
    return f"AAD-SMTP:{address}"


def _env(prefix: str, name: str, override: str | None) -> str:
    if override is not None:
        return override
    import os

    return os.environ.get(f"{prefix}_{name}", "")


class _AppOnlyHttp:
    """POST-only app-only transport for outlook.office365.com. No Graph path."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.Client | None = None,
        token_provider: TokenProvider | None = None,
        sleep: SleepFn | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_provider = token_provider
        self._credential: ClientSecretCredential | None = None
        self._cached_token: str | None = None
        self._cached_token_expires = 0.0
        self._sleep = sleep or time.sleep
        self._http = http_client or httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=30.0,
        )

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
            if not self._tenant_id or not self._client_id or not self._client_secret:
                raise SanitizedGraphError("token_acquisition_failed", status_class="auth")
            if self._credential is None:
                self._credential = ClientSecretCredential(
                    tenant_id=self._tenant_id,
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                )
            result = self._credential.get_token(EXO_SCOPE)
        except SanitizedGraphError:
            raise
        except Exception:
            raise SanitizedGraphError("token_acquisition_failed", status_class="auth") from None
        self._cached_token = result.token
        self._cached_token_expires = float(result.expires_on) - TOKEN_REFRESH_SKEW_SECONDS
        return result.token

    def _retry_delay(self, header: str | None) -> float:
        delay = parse_retry_after(header)
        if delay is not None:
            return delay
        raise sanitized_http_error(429, "malformed_retry_after")

    def post_json(self, url: str, body: dict[str, Any], extra_headers: dict[str, str]) -> dict[str, Any]:
        attempts = 0
        waited = 0.0
        while True:
            attempts += 1
            try:
                token = self._token()
            except SanitizedGraphError:
                raise
            except Exception:
                raise SanitizedGraphError("token_acquisition_failed", status_class="auth") from None
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            headers.update(extra_headers)
            try:
                response = self._http.post(url, json=body, headers=headers)
            except httpx.HTTPError:
                raise sanitized_http_error(None, "network_error") from None
            status = response.status_code
            if status in (429, 503, 504):
                if attempts >= MAX_RETRY_ATTEMPTS:
                    err = sanitized_http_error(status, "retries_exhausted")
                    err.status_code = status  # type: ignore[attr-defined]
                    raise err
                delay = self._retry_delay(response.headers.get("Retry-After"))
                if waited + delay > MAX_RETRY_WAIT_SECONDS:
                    err = sanitized_http_error(status, "retry_budget_exhausted")
                    err.status_code = status  # type: ignore[attr-defined]
                    raise err
                self._sleep(delay)
                waited += delay
                continue
            if status >= 300:
                err = sanitized_http_error(status, "graph_error")
                err.status_code = status  # type: ignore[attr-defined]
                raise err
            try:
                payload = response.json()
            except ValueError:
                raise SanitizedGraphError("invalid_json", status_class="5xx") from None
            if not isinstance(payload, dict):
                raise SanitizedGraphError("invalid_json", status_class="5xx")
            return payload


class ExoAdminApiClient(_AppOnlyHttp):
    def __init__(
        self,
        *,
        env_prefix: str = "EXO",
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        http_client: httpx.Client | None = None,
        token_provider: TokenProvider | None = None,
        sleep: SleepFn | None = None,
    ) -> None:
        tenant = _env(env_prefix, "TENANT_ID", tenant_id)
        super().__init__(
            tenant_id=tenant,
            client_id=_env(env_prefix, "CLIENT_ID", client_id),
            client_secret=_env(env_prefix, "CLIENT_SECRET", client_secret),
            http_client=http_client,
            token_provider=token_provider,
            sleep=sleep,
        )
        if _GUID.fullmatch(tenant) is None:
            raise SanitizedGraphError("invalid_tenant_id", status_class="4xx")
        self.tenant_id = tenant

    def origin_prefix(self) -> str:
        return f"{EXO_ORIGIN}/adminapi/v2.0/{self.tenant_id}/"

    def resolve_anchor(self, anchor: str | None) -> str:
        if anchor is None or anchor == "":
            return system_mailbox_anchor(self.tenant_id)
        return anchor

    def _validate(self, endpoint: str, cmdlet: str, params: dict[str, Any]) -> None:
        mapped = EXO_ENDPOINTS.get(endpoint)
        if mapped is None:
            raise SanitizedGraphError("endpoint_not_allowed", status_class="4xx")
        allowed = mapped.get(cmdlet)
        if allowed is None:
            raise SanitizedGraphError("cmdlet_not_allowed", status_class="4xx")
        if not cmdlet.startswith("Get-"):
            raise SanitizedGraphError("cmdlet_not_allowed", status_class="4xx")
        unknown = set(params) - allowed
        if unknown:
            raise SanitizedGraphError("parameter_not_allowed", status_class="4xx")
        required = EXO_REQUIRED_PARAMS.get(cmdlet, frozenset())
        for name in required:
            value = params.get(name)
            if not isinstance(value, str) or value.strip() == "":
                raise SanitizedGraphError("parameter_required", status_class="4xx")

    def _url(self, endpoint: str, select: str | None) -> str:
        base = f"{EXO_ORIGIN}/adminapi/v2.0/{quote(self.tenant_id, safe='')}/{quote(endpoint, safe='')}"
        if select is None:
            return base
        if not isinstance(select, str) or _SELECT.fullmatch(select) is None:
            raise SanitizedGraphError("parameter_not_allowed", status_class="4xx")
        return base + "?$select=" + select

    def _body(self, cmdlet: str, params: dict[str, Any]) -> dict[str, Any]:
        cmdlet_input: dict[str, Any] = {"CmdletName": cmdlet}
        if params:
            cmdlet_input["Parameters"] = dict(params)
        return {"CmdletInput": cmdlet_input}

    def _rows(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if any(key in payload for key in _ERROR_KEYS):
            raise SanitizedGraphError("cmdlet_execution_failed", status_class="4xx")
        if "value" in payload:
            value = payload["value"]
            if value is None:
                return []
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                return [value]
            return []
        if any(not str(key).startswith("@") for key in payload):
            return [payload]
        return []

    def invoke(
        self,
        endpoint: str,
        cmdlet: str,
        params: dict[str, Any] | None = None,
        *,
        anchor: str | None = None,
        select: str | None = None,
    ) -> dict[str, Any]:
        clean = dict(params or {})
        self._validate(endpoint, cmdlet, clean)
        url = self._url(endpoint, select)
        headers = {"X-AnchorMailbox": self.resolve_anchor(anchor)}
        return self.post_json(url, self._body(cmdlet, clean), headers)

    def iter_rows(
        self,
        endpoint: str,
        cmdlet: str,
        params: dict[str, Any] | None = None,
        *,
        anchor: str | None = None,
        select: str | None = None,
    ):
        clean = dict(params or {})
        self._validate(endpoint, cmdlet, clean)
        url = self._url(endpoint, select)
        body = self._body(cmdlet, clean)
        headers = {"X-AnchorMailbox": self.resolve_anchor(anchor)}
        seen: set[str] = set()
        prefix = self.origin_prefix()
        while True:
            if url in seen:
                raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")
            seen.add(url)
            payload = self.post_json(url, body, headers)
            yield from self._rows(payload)
            link = payload.get("@odata.nextLink")
            if not link:
                return
            if not isinstance(link, str) or not link.startswith(prefix):
                raise SanitizedGraphError("pagination_origin_rejected", status_class="4xx")
            url = link


def fetch_one_admin_api(
    client: ExoAdminApiClient,
    endpoint: str,
    cmdlet: str,
    params: dict[str, Any] | None,
    schema: dict,
    anchor: str | None,
    *,
    select: str | None = None,
) -> dict[str, Any]:
    """Single-item envelope. An empty result is ``not_found``."""
    rows = list(
        client.iter_rows(endpoint, cmdlet, params, anchor=anchor, select=select)
    )
    if len(rows) != 1:
        raise SanitizedGraphError("not_found", status_class="4xx")
    projected = project_schema(rows[0], schema)
    if not isinstance(projected, dict) or len(projected) == 0:
        raise SanitizedGraphError("not_found", status_class="4xx")
    projected = strip_keys(projected, FORBIDDEN_KEYS)
    return {
        "items": [projected],
        "complete": True,
        "truncated": False,
        "items_scanned": 1,
        "stop_reason": None,
        "error_class": None,
    }
