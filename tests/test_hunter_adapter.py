"""
Deterministic tests for the Hunter.io adapter.

NO live API calls - all HTTP is mocked.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from safenestt.tools.adapters.hunter import HunterAdapter
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

HUNTER_BASE = "https://api.hunter.io/v2"


def _make_resp(status, body=None, headers=None):
    if body is None:
        body = "{}"
    elif not isinstance(body, str):
        body = json.dumps(body)
    return HttpResponse(status=status, headers=headers or {}, body=body,
                       url=HUNTER_BASE + "/test")


def _set_cred(adapter, key):
    from safenestt.security.secrets import _cache
    _cache["HUNTER_API_KEY"] = key
    _cache["HUNTER_EMAIL"] = "test@example.com"


def _clear_cred(adapter):
    from safenestt.security.secrets import _cache
    _cache.pop("HUNTER_API_KEY", None)
    _cache.pop("HUNTER_EMAIL", None)
    import os
    os.environ.pop("HUNTER_API_KEY", None)
    os.environ.pop("HUNTER_EMAIL", None)


def _fresh_adapter():
    return HunterAdapter()


# ---------------------------------------------------------------------------
# Success tests
# ---------------------------------------------------------------------------

class TestHunterSuccess:
    def test_email_verifier_safely_deliverable(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hunter-key")
        body = {
            "data": {
                "meta": {"params": {"email": "user@example.com"}},
                "attr": {
                    "email": "user@example.com",
                    "status": "safely_deliverable",
                    "score": 0.91,
                    "confidence": "high",
                    "gibberish": False,
                    "disposable": False,
                    "webmail": False,
                    "valid_semantically": True,
                    "valid_server": True,
                    "mail_server": "mail.example.com",
                    "smtp_provider": "Example SMTP",
                    "verification_token": "abc123",
                },
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "hunter"
        assert data["source"] == "hunter_api"
        assert data["action"] == "email_verifier"
        assert data["target"] == "user@example.com"
        assert data["email"] == "user@example.com"
        assert data["status"] == "safely_deliverable"
        assert data["score"] == 0.91
        assert data["confidence"] == "high"
        assert data["gibberish"] is False
        assert data["disposable"] is False

    def test_email_verifier_deceptive(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hunter-key")
        body = {
            "data": {
                "attr": {
                    "email": "fake@test.com",
                    "status": "deceptive",
                    "score": 0.15,
                    "confidence": "low",
                    "gibberish": False,
                    "disposable": True,
                    "webmail": False,
                    "valid_semantically": False,
                    "valid_server": False,
                }
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "fake@test.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["status"] == "deceptive"
        assert data["score"] == 0.15
        assert data["disposable"] is True

    def test_domain_search(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hunter-key")
        body = {
            "data": {
                "meta": {"params": {"domain": "example.com"}},
                "domain": {
                    "domain": "example.com",
                    "organization": "Example Corp",
                    "industry": "Technology",
                    "country": "US",
                    "email_count": 1250,
                    "absorption_rate": 0.85,
                    "emails": [
                        {
                            "value": "admin@example.com",
                            "first_name": "Admin",
                            "last_name": "User",
                            "position": "IT Manager",
                            "company": "Example Corp",
                            "email_status": "safely_deliverable",
                            "confidence": 0.85,
                            "is_disposable": False,
                            "is_webmail": False,
                            "is_catchall": True,
                            "is_null": False,
                        },
                        {
                            "value": "support@example.com",
                            "first_name": "Support",
                            "last_name": "Team",
                            "position": "Support",
                            "company": "Example Corp",
                            "email_status": "catch_all",
                            "confidence": 0.70,
                            "is_disposable": False,
                            "is_webmail": False,
                            "is_catchall": True,
                            "is_null": False,
                        },
                    ]
                }
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hunter.domain_search",
                              {"query": "example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "hunter"
        assert data["source"] == "hunter_api"
        assert data["action"] == "domain_search"
        assert data["target"] == "example.com"
        assert data["domain"] == "example.com"
        assert data["organization"] == "Example Corp"
        assert data["industry"] == "Technology"
        assert data["country"] == "US"
        assert data["email_count"] == 1250
        assert data["absorption_rate"] == 0.85
        assert len(data["emails"]) == 2
        assert data["emails"][0]["value"] == "admin@example.com"
        assert data["emails"][0]["position"] == "IT Manager"
        assert data["emails"][1]["email_status"] == "catch_all"

    def test_domain_search_empty_emails(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-hunter-key")
        body = {
            "data": {
                "domain": {
                    "domain": "empty.com",
                    "organization": "",
                    "industry": "",
                    "country": "",
                    "email_count": 0,
                    "absorption_rate": 0,
                    "emails": [],
                }
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.hunter.domain_search",
                              {"query": "empty.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["email_count"] == 0
        assert data["emails"] == []


# ---------------------------------------------------------------------------
# Credential tests
# ---------------------------------------------------------------------------

class TestHunterConfig:
    def test_missing_credential_returns_error(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.execute(None, "cyber_intel.hunter.email_verifier",
                          {"query": "user@example.com"})
        assert result["status"] == "error"
        assert result["error"] == "provider_not_configured"
        assert "HUNTER_API_KEY" in result["metadata"]["detail"]

    def test_missing_credential_skips_http(self):
        a = _fresh_adapter()
        _clear_cred(a)
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
        mock_req.assert_not_called()

    def test_health_check_not_configured(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.health_check()
        assert result["status"] == "unconfigured"
        assert "HUNTER_API_KEY" in result["detail"]

    def test_health_check_configured(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        result = a.health_check()
        assert result["status"] == "ok"
        assert result["provider"] == "hunter"


# ---------------------------------------------------------------------------
# Auth / error tests
# ---------------------------------------------------------------------------

class TestHunterErrors:
    def test_401_auth_failed(self):
        a = _fresh_adapter()
        _set_cred(a, "bad-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(401, {"error": "Invalid API key"})):
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
        assert result["status"] == "error"
        assert result["error"] == "auth_failed"

    def test_403_forbidden(self):
        a = _fresh_adapter()
        _set_cred(a, "key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(403, {"error": "Plan required"})):
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
        assert result["status"] == "error"
        assert result["error"] in ("auth_failed", "forbidden")

    def test_404_not_found(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(404, {"error": "Not found"})):
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "nonexistent@test.com"})
        assert result["status"] == "error"
        assert result["error"] == "not_found"

    def test_429_rate_limited(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(429, {}, {"Retry-After": "0.1"})):
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert elapsed >= 0.1

    def test_500_retry_exhausted(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", side_effect=[
            _make_resp(500), _make_resp(500),
        ]) as mock_req:
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "user@example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "provider_error"
        assert elapsed >= 1.0
        assert mock_req.call_count == 2


# ---------------------------------------------------------------------------
# Target validation tests
# ---------------------------------------------------------------------------

class TestHunterTargetValidation:
    def test_email_verifier_rejects_non_email(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "not-an-email"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"

    def test_domain_search_rejects_non_domain(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.hunter.domain_search",
                              {"query": "not-a-domain"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"

    def test_email_verifier_accepts_valid_email(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "attr": {
                    "email": "test@test.com",
                    "status": "safely_deliverable",
                    "score": 0.9,
                }
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)) as mock_req:
            result = a.execute(None, "cyber_intel.hunter.email_verifier",
                              {"query": "test@test.com"})
        assert result["status"] == "success"
        assert mock_req.call_count == 1

    def test_domain_search_accepts_valid_domain(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "domain": {
                    "domain": "example.com",
                    "email_count": 10,
                    "emails": [],
                }
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)) as mock_req:
            result = a.execute(None, "cyber_intel.hunter.domain_search",
                              {"query": "example.com"})
        assert result["status"] == "success"
        assert mock_req.call_count == 1
