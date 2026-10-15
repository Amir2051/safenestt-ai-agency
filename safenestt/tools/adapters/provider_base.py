"""
Provider base adapter for external intelligence providers.

Extends the existing ToolAdapter architecture. Provides common behavior:
- credential resolution via get_secret()
- bounded HTTP timeout
- transient retry (5xx, timeout, connection errors only)
- rate-limit handling (429 with Retry-After)
- structured provider errors
- response normalization hooks

Reuse: ToolCapability, ToolAdapter._ok(), _fail(), _provenance().
Do NOT create a competing adapter framework.
"""

from __future__ import annotations

import json
import logging
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from safenestt.tools.adapters.base import ToolAdapter
from safenestt.security.secrets import get_secret

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Structured provider errors — never include secrets in messages
# ---------------------------------------------------------------------------

class ProviderError(Exception):
    def __init__(self, code: str, message: str, action: str = "") -> None:
        self.code = code
        self.message = message
        self.action = action
        super().__init__(f"[{code}] {message}")

class ProviderUnavailable(ProviderError):
    pass

class ProviderTimeout(ProviderError):
    pass

class ProviderAuthFailed(ProviderError):
    pass

class ProviderNotFound(ProviderError):
    pass

class ProviderRateLimited(ProviderError):
    pass

class ProviderMalformedResponse(ProviderError):
    pass

class ProviderUnsupportedTarget(ProviderError):
    pass

class ProviderNotConfigured(ProviderError):
    pass

class ProviderResponseTooLarge(ProviderError):
    pass

# ---------------------------------------------------------------------------
# HTTP client — stdlib urllib, bounded timeout, size limit, redirect control
# ---------------------------------------------------------------------------

@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    url: str

    def json(self) -> dict[str, Any]:
        return json.loads(self.body)

    def retry_after(self) -> float | None:
        val = self.headers.get("Retry-After")
        if val is None:
            return None
        try:
            return float(val)
        except ValueError:
            return None


@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout: float = 10.0


class HttpClient:
    """Bounded HTTP client using stdlib urllib.

    - Timeout per request
    - Max response size (raises ProviderResponseTooLarge)
    - Configurable redirect following
    - Returns HttpResponse or raises ProviderError subclasses
    """

    def __init__(
        self,
        default_timeout: float = 10.0,
        max_response_bytes: int = 5 * 1024 * 1024,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> None:
        self.default_timeout = default_timeout
        self.max_response_bytes = max_response_bytes
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

    def request(self, spec: RequestSpec) -> HttpResponse:
        url = spec.url
        if spec.params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(spec.params)

        req = urllib.request.Request(
            url,
            data=spec.body,
            headers=dict(spec.headers),
            method=spec.method,
        )

        try:
            resp = urllib.request.urlopen(req, timeout=spec.timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read(self.max_response_bytes + 1)
            return HttpResponse(
                status=exc.code,
                headers={},
                body=body.decode("utf-8", errors="replace"),
                url=str(getattr(exc, "url", url)),
            )
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, socket.timeout):
                raise ProviderTimeout(code="timeout", message=f"Timed out after {spec.timeout}s", action="")
            raise ProviderUnavailable(code="unavailable", message=f"Connection failed: {reason}", action="")
        except socket.timeout:
            raise ProviderTimeout(code="timeout", message=f"Timed out after {spec.timeout}s", action="")
        except Exception as exc:
            raise ProviderUnavailable(code="unavailable", message=str(exc), action="")

        body_bytes = resp.read(self.max_response_bytes + 1)
        if len(body_bytes) > self.max_response_bytes:
            raise ProviderResponseTooLarge(
                code="response_too_large",
                message=f"Response exceeded {self.max_response_bytes} bytes",
                action="",
            )

        return HttpResponse(
            status=resp.status,
            headers=dict(resp.headers),
            body=body_bytes.decode("utf-8", errors="replace"),
            url=resp.url,
        )


# ---------------------------------------------------------------------------
# ProviderAdapter — extends ToolAdapter
# ---------------------------------------------------------------------------

class ProviderAdapter(ToolAdapter):
    """Base for external intelligence providers.

    Class attributes subclasses should set:
        provider_name: str
        base_url: str
        auth_header: str            (e.g. "X-Api-Key" or "Authorization")
        credentials_var: str        (env var name for the API key)
        default_timeout: float
        max_retries: int
        retry_backoff: float
        rate_limit_delay: float     (seconds between requests, 0 = none)
        max_response_bytes: int
        follow_redirects: bool
        max_redirects: int

    Required overrides:
        _build_request(action, payload, credential) -> RequestSpec | None
        _normalize_response(resp, action, payload) -> dict
        _normalize_error(status, body, action) -> dict
    """

    capabilities: list = []
    provider_name: str = "base"
    base_url: str = ""
    auth_header: str = "X-Api-Key"
    credentials_var: str = ""
    default_timeout: float = 10.0
    max_retries: int = 2
    retry_backoff: float = 1.0
    rate_limit_delay: float = 0.0
    max_response_bytes: int = 5 * 1024 * 1024  # 5 MB
    follow_redirects: bool = True
    max_redirects: int = 5

    # Status codes that warrant retry
    _RETRY_STATUSES = {429, 500, 502, 503, 504}

    def __init__(self) -> None:
        super().__init__()
        self._http = HttpClient(
            default_timeout=self.default_timeout,
            max_response_bytes=self.max_response_bytes,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
        )

    # ---- ToolAdapter overrides ----

    def execute(self, agent: Any, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        action = self._action(capability)
        tool_id = self._tool_id(capability)
        credential = self._resolve_credential()

        if credential is None and self.credentials_var and not getattr(self, 'credentials_var_optional', False):
            return self._fail(tool_id, action, "provider_not_configured", {
                "detail": f"Missing credential: {self.credentials_var}",
            })

        spec = self._build_request(action, payload, credential)
        if spec is None:
            return self._fail(tool_id, action, "unsupported_target", {
                "detail": f"Action '{action}' not supported or target type invalid",
            })

        try:
            result = self._execute_with_retry(spec, action, tool_id, payload)
        except ProviderUnsupportedTarget as exc:
            return self._fail(tool_id, action, exc.code, {"detail": exc.message})
        except ProviderError as exc:
            return self._fail(tool_id, action, exc.code, {"detail": exc.message})

        if isinstance(result, dict) and result.get("status") == "error":
            return result

        return self._ok(tool_id, action, result, self._provenance(payload))

    def health_check(self) -> dict[str, Any]:
        credential = self._resolve_credential()
        if not credential and self.credentials_var:
            return {"status": "unconfigured", "detail": f"Missing: {self.credentials_var}"}
        return {"status": "ok", "provider": self.provider_name}

    # ---- Internal ----

    @staticmethod
    def _action(capability: str) -> str:
        parts = capability.split(".")
        return parts[-1] if len(parts) >= 2 else capability

    @staticmethod
    def _tool_id(capability: str) -> str:
        parts = capability.split(".")
        return ".".join(parts[:-1]) if len(parts) >= 2 else capability

    def _resolve_credential(self) -> str | None:
        if not self.credentials_var:
            return None
        return get_secret(self.credentials_var)

    def _provenance(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build provenance metadata from the payload context."""
        return {
            k: payload[k]
            for k in ("case_id", "investigation_id", "agent_id", "agent_run_id", "task_id")
            if k in payload
        }

    def _build_request(
        self,
        action: str,
        payload: dict[str, Any],
        credential: str | None,
    ) -> RequestSpec | None:
        """Return RequestSpec or None to reject the target."""
        raise NotImplementedError

    def _normalize_response(
        self,
        resp: HttpResponse,
        action: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Convert 200 response to normalized data dict."""
        raise NotImplementedError

    def _normalize_error(
        self,
        status: int,
        body: str,
        action: str,
    ) -> dict[str, Any]:
        """Convert error status to structured error dict."""
        return {"status_code": status, "body": body[:1000], "code": "provider_error"}

    def _execute_with_retry(
        self,
        spec: RequestSpec,
        action: str,
        tool_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        last_error: ProviderError | None = None

        for attempt in range(1 + self.max_retries):
            try:
                resp = self._http.request(spec)
            except ProviderError as exc:
                last_error = exc
                if self._should_retry_exc(exc) and attempt < self.max_retries:
                    time.sleep(self.retry_backoff * (2 ** attempt))
                    continue
                return self._fail(tool_id, action, exc.code, {"detail": exc.message})

            if resp.status == 429:
                retry_after = resp.retry_after()
                if retry_after is not None and attempt < self.max_retries:
                    time.sleep(min(retry_after, self.retry_backoff * (2 ** attempt)))
                    continue
                return self._fail(tool_id, action, "rate_limited", {
                    "detail": "Rate limited",
                    "retry_after": retry_after,
                })

            if resp.status in self._RETRY_STATUSES and attempt < self.max_retries:
                time.sleep(self.retry_backoff * (2 ** attempt))
                continue

            if resp.status >= 400:
                err_data = self._normalize_error(resp.status, resp.body, action)
                # Add retries_exhausted flag when we've used all retry attempts on a server error
                if resp.status in self._RETRY_STATUSES:
                    err_data["retries_exhausted"] = True
                return self._fail(tool_id, action, err_data.get("code", "provider_error"), err_data)

            try:
                return self._normalize_response(resp, action, payload)
            except ProviderError:
                raise
            except Exception as exc:
                return self._fail(tool_id, action, "malformed_response", {"detail": str(exc)})

        if last_error is not None:
            return self._fail(tool_id, action, last_error.code, {
                "detail": last_error.message,
                "retries_exhausted": True,
            })
        return self._fail(tool_id, action, "provider_unavailable", {
            "detail": "Max retries exhausted",
        })

    @staticmethod
    def _should_retry_exc(exc: ProviderError) -> bool:
        return isinstance(exc, (ProviderTimeout, ProviderUnavailable))

    def _ok(self, tool_id: str, action: str, data: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "success",
            "data": data,
            "metadata": metadata or {},
            "warnings": [],
            "error": None,
        }

    def _fail(self, tool_id: str, action: str, error: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "error",
            "data": {},
            "metadata": metadata or {},
            "warnings": [],
            "error": error,
        }
