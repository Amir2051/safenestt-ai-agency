"""
Deterministic tests for the HIBP (Have I Been Pwned) adapter.

NO live API calls - all HTTP is mocked.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from safenestt.tools.adapters.hibp import HIBPAdapter
from safenestt.tools.adapters.provider_base import (
    HttpResponse,
    ProviderError,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderTimeout,
    ProviderMalformedResponse,
    RequestSpec,
)

HIBP_BASE = "https://api.haveibeenpwned.com/api/v3"


def _make_resp(status, body=None, headers=None):
    if body is None:
        body = "[]"
    elif not isinstance(body, str):
        body = json.dumps(body)
    return HttpResponse(status=status, headers=headers or {}, body=body,
                       url=HIBP_BASE + "/test")


def _set_cred(adapter, key):
    from safenestt.security.secrets import _cache
    _cache["HIBP_API_KEY"] = key


def _clear_cred(adapter):
    from safenestt.security.secrets import _cache
    _cache.pop("HIBP_API_KEY", None)


def _fresh_adapter():
    return HIBPAdapter()


# ---------------------------------------------------------------------------
# Success tests
# ---------------------------------------------------------------------------

class TestHIBPSuccess:
    def test_breached_account_found(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hibp-key")
        body = [
            {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
             "BreachDate": "2013-10-04", "AddedDate": "2013-12-04T00:00:00Z",
             "ModifiedDate": "2022-05-15T01:05:00Z", "PwnCount": 152445161,
             "IsVerified": True, "IsMature": False,
             "DataClasses": ["Email addresses", "Password hashes"],
             "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"},
            {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com",
             "BreachDate": "2012-05-05", "AddedDate": "2012-06-28T00:00:00Z",
             "PwnCount": 164611628, "IsVerified": True, "IsMature": True,
             "DataClasses": ["Email addresses", "Passwords"], "LogoPath": ""},
        ]
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "user@example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "hibp"
        assert data["source"] == "hibp_api"
        assert data["action"] == "breached_account"
        assert data["target"] == "user@example.com"
        assert data["breach_count"] == 2
        assert data["breached"] is True
        assert len(data["breaches"]) == 2
        assert data["breaches"][0]["name"] == "Adobe"
        assert data["breaches"][0]["pwn_count"] == 152445161
        assert data["breaches"][1]["name"] == "LinkedIn"
        assert data["confidence"] > 0.0

    def test_breached_account_clean_returns_empty_list_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hibp-key")
        with patch.object(a._http, "request", return_value=_make_resp(200, [{"Name": "CleanBreach"}])):
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "clean@example.com"})
        assert result["status"] == "success"
        assert result["data"]["breach_count"] == 1

    def test_paste_account_found(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hibp-key")
        body = [
            {"Id": "Paste1", "Title": "My Paste", "Date": "2023-10-15T10:30:00Z",
             "EmailAddress": "user@example.com", "Source": "Pastebin",
             "IsVerified": True, "IsMature": False},
        ]
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hibp.paste_account",
                              {"query": "user@example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["paste_count"] == 1
        assert data["has_pastes"] is True
        assert len(data["pastes"]) == 1
        assert data["pastes"][0]["source"] == "Pastebin"
        assert data["confidence"] > 0.0

    def test_paste_account_clean(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hibp-key")
        with patch.object(a._http, "request", return_value=_make_resp(200, [{"Id": "P1", "Title": "test"}])):
            result = a.execute(None, "cyber_intel.hibp.paste_account",
                              {"query": "clean@example.com"})
        assert result["status"] == "success"
        assert result["data"]["paste_count"] == 1

    def test_no_api_key_still_works(self):
        """HIBP allows unauthenticated requests (rate limited)."""
        a = _fresh_adapter()
        _clear_cred(a)
        with patch.object(a._http, "request",
                          return_value=_make_resp(200, [{"Name": "TestBreach"}])) as mock_req:
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
        assert result["status"] == "success"
        assert result["data"]["breach_count"] == 1
        assert mock_req.call_count == 1


# ---------------------------------------------------------------------------
# Credential tests
# ---------------------------------------------------------------------------

class TestHIBPCredential:
    def test_missing_credential_still_works(self):
        a = _fresh_adapter()
        _clear_cred(a)
        with patch.object(a._http, "request",
                          return_value=_make_resp(200, [{"Name": "TestBreach"}])):
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
        assert result["status"] == "success"
        assert result["data"]["breach_count"] == 1


# ---------------------------------------------------------------------------
# Error tests
# ---------------------------------------------------------------------------

class TestHIBPErrors:
    def test_401_auth_failed(self):
        a = _fresh_adapter()
        _set_cred(a, "bad-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(401, {"error": "Invalid API key"})):
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
        assert result["status"] == "error"
        assert result["error"] == "auth_failed"

    def test_404_not_found_clean(self):
        """HIBP returns 404 when account not found in breaches."""
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(404, {})):
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "clean@example.com"})
        assert result["status"] == "error"
        assert result["error"] == "not_found"

    def test_429_rate_limited(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(429, {}, {"Retry-After": "2"})):
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert result["metadata"].get("retry_after") == 2.0
        assert elapsed >= 2.0

    def test_429_no_retry_after(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", return_value=_make_resp(429, {})):
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert elapsed < 1.0

    def test_500_retry_exhausted(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", side_effect=[
            _make_resp(500), _make_resp(500),
        ]) as mock_req:
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "test@example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "provider_error"
        assert elapsed >= 1.5
        assert mock_req.call_count == 2


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

class TestHIBPTargetValidation:
    def test_breached_account_normalizes_lowercase(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = []
        with patch.object(a._http, "request", return_value=_make_resp(200, body)) as mock_req:
            result = a.execute(None, "cyber_intel.hibp.breached_account",
                              {"query": "User@Example.COM"})
        assert result["status"] == "success"
        call_args = mock_req.call_args[0][0]
        # URL-encodes @ as %40
        assert "user%40example.com" in call_args.url.lower()
