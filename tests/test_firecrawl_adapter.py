"""
Deterministic tests for the Firecrawl adapter.

NO live API calls — all HTTP is mocked via urllib.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from safenestt.tools.adapters.firecrawl import FirecrawlAdapter
from safenestt.tools.adapters.provider_base import (
    HttpResponse,
    ProviderAuthFailed,
    ProviderError,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    ProviderMalformedResponse,
    ProviderUnsupportedTarget,
    RequestSpec,
)

FIRECRAWL_BASE = "https://api.firecrawl.dev/v1"


def _make_resp(status, body=None, headers=None):
    if body is None:
        body = "{}"
    elif not isinstance(body, str):
        body = json.dumps(body)
    return HttpResponse(status=status, headers=headers or {}, body=body,
                       url=FIRECRAWL_BASE + "/test")


def _set_cred(adapter, key):
    from safenestt.security.secrets import _cache
    _cache["FIRECRAWL_API_KEY"] = key


def _clear_cred(adapter):
    from safenestt.security.secrets import _cache
    _cache.pop("FIRECRAWL_API_KEY", None)
    _cache.pop("HUNTER_API_KEY", None)
    _cache.pop("HUNTER_EMAIL", None)
    import os
    os.environ.pop("FIRECRAWL_API_KEY", None)
    os.environ.pop("HUNTER_API_KEY", None)


def _clear_hunter_cred(adapter):
    from safenestt.security.secrets import _cache
    _cache.pop("HUNTER_API_KEY", None)
    _cache.pop("HUNTER_EMAIL", None)
    import os
    os.environ.pop("HUNTER_API_KEY", None)
    os.environ.pop("HUNTER_EMAIL", None)


def _fresh_adapter():
    return FirecrawlAdapter()


# ---------------------------------------------------------------------------
# Success tests
# ---------------------------------------------------------------------------

class TestFirecrawlSuccess:
    def test_url_scrape_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-fc-key")
        body = {
            "url": "https://example.com",
            "final_url": "https://example.com",
            "content": "<html><body>Hello World</body></html>",
            "metadata": {"content-type": "text/html", "title": "Example Domain"},
            "status": 200,
            "html_len": 1024,
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "firecrawl"
        assert data["source"] == "firecrawl_api"
        assert data["action"] == "url_scrape"
        assert data["requested_url"] == "https://example.com"
        assert data["url"] == "https://example.com"
        assert data["status_code"] == 200
        assert data["title"] == "Example Domain"
        assert data["content_type"] == "text/html"

    def test_url_scrape_404(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-fc-key")
        body = {
            "url": "https://example.com/missing",
            "content": "",
            "metadata": {"content-type": "text/html"},
            "status": 404,
            "html_len": 0,
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com/missing"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["status_code"] == 404

    def test_web_search_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-fc-key")
        body = {
            "query": "safe site",
            "data": [
                {"url": "https://example.com", "title": "Example Domain",
                 "description": "A test site"},
                {"url": "https://example.org", "title": "Example Org",
                 "description": "Another test site"},
            ],
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.firecrawl.web_search",
                              {"query": "safe site"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "firecrawl"
        assert data["source"] == "firecrawl_api"
        assert data["action"] == "web_search"
        assert len(data["results"]) == 2
        assert data["results"][0]["url"] == "https://example.com"


# ---------------------------------------------------------------------------
# Credential / config tests
# ---------------------------------------------------------------------------

class TestFirecrawlConfig:
    def test_missing_credential_returns_error(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                          {"query": "https://example.com"})
        assert result["status"] == "error"
        assert result["error"] == "provider_not_configured"
        assert "FIRECRAWL_API_KEY" in result["metadata"]["detail"]

    def test_missing_credential_skips_http(self):
        a = _fresh_adapter()
        _clear_cred(a)
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
        mock_req.assert_not_called()

    def test_health_check_not_configured(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.health_check()
        assert result["status"] == "unconfigured"
        assert "FIRECRAWL_API_KEY" in result["detail"]

    def test_health_check_configured(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        result = a.health_check()
        assert result["status"] == "ok"
        assert result["provider"] == "firecrawl"


# ---------------------------------------------------------------------------
# Auth / rate-limit tests
# ---------------------------------------------------------------------------

class TestFirecrawlErrors:
    def test_401_auth_failed(self):
        a = _fresh_adapter()
        _set_cred(a, "bad-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(401, {"error": "Invalid API key"})):
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
        assert result["status"] == "error"
        assert result["error"] == "auth_failed"

    def test_403_forbidden(self):
        a = _fresh_adapter()
        _set_cred(a, "key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(403, {"error": "Plan upgrade required"})):
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
        assert result["status"] == "error"
        assert result["error"] in ("auth_failed", "forbidden")

    def test_429_rate_limited(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request",
                          return_value=_make_resp(429, {}, {"Retry-After": "2"})):
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
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
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert elapsed < 1.0


# ---------------------------------------------------------------------------
# Retry tests
# ---------------------------------------------------------------------------

class TestFirecrawlRetry:
    def test_503_retry_then_success(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        good_body = {"url": "https://example.com", "content": "ok", "status": 200, "html_len": 0}
        with patch.object(a._http, "request", side_effect=[
            _make_resp(503),
            _make_resp(503),
            _make_resp(200, good_body),
        ]) as mock_req:
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
        assert result["status"] == "success"
        assert mock_req.call_count == 3

    def test_500_retry_exhausted(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", side_effect=[
            _make_resp(500),
            _make_resp(500),
            _make_resp(500),
        ]) as mock_req:
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.firecrawl.url_scrape",
                              {"query": "https://example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "provider_error"
        assert elapsed >= 1.5
        assert mock_req.call_count == 3


# ---------------------------------------------------------------------------
# SSRF protection tests
# ---------------------------------------------------------------------------

class TestFirecrawlSSRF:
    def test_ssrf_localhost_blocked(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with pytest.raises(ProviderUnsupportedTarget) as exc_info:
            a.execute(None, "cyber_intel.firecrawl.url_scrape",
                      {"query": "http://localhost/admin"})
        assert exc_info.value.code == "ssrf_blocked"

    def test_ssrf_private_ip_blocked(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with pytest.raises(ProviderUnsupportedTarget) as exc_info:
            a.execute(None, "cyber_intel.firecrawl.url_scrape",
                      {"query": "http://192.168.1.1/admin"})
        assert exc_info.value.code == "ssrf_blocked"

    def test_ssrf_127_blocked(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with pytest.raises(ProviderUnsupportedTarget) as exc_info:
            a.execute(None, "cyber_intel.firecrawl.url_scrape",
                      {"query": "http://127.0.0.1/test"})
        assert exc_info.value.code == "ssrf_blocked"

    def test_ssrf_link_local_blocked(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with pytest.raises(ProviderUnsupportedTarget) as exc_info:
            a.execute(None, "cyber_intel.firecrawl.url_scrape",
                      {"query": "http://169.254.0.1/test"})
        assert exc_info.value.code == "ssrf_blocked"

    def test_ssrf_ipv6_local_blocked(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with pytest.raises(ProviderUnsupportedTarget) as exc_info:
            a.execute(None, "cyber_intel.firecrawl.url_scrape",
                      {"query": "http://[::1]/test"})
        assert exc_info.value.code == "ssrf_blocked"