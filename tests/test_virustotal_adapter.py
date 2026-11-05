"""
Deterministic tests for the VirusTotal API v3 adapter.
NO live API calls - all HTTP is mocked.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from safenestt.tools.adapters.virustotal import VirusTotalAdapter
from safenestt.tools.adapters.provider_base import (
    HttpResponse,
    ProviderError,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderTimeout,
    ProviderMalformedResponse,
    ProviderUnsupportedTarget,
    ProviderNotConfigured,
    ProviderResponseTooLarge,
    RequestSpec,
)

VT_BASE = "https://www.virustotal.com/api/v3"


def _make_resp(status, body=None, headers=None):
    if body is None:
        body = "{}"
    elif not isinstance(body, str):
        body = json.dumps(body)
    return HttpResponse(status=status, headers=headers or {}, body=body,
                       url=VT_BASE + "/test")


def _set_cred(adapter, key):
    from safenestt.security.secrets import _cache
    _cache["VT_API_KEY"] = key


def _clear_cred(adapter):
    from safenestt.security.secrets import _cache
    _cache.pop("VT_API_KEY", None)


def _fresh_adapter():
    return VirusTotalAdapter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestVTBase:
    def test_capability_names(self):
        a = _fresh_adapter()
        caps = a.capabilities
        assert len(caps) == 1
        cap = caps[0]
        assert cap.tool_id == "cyber_intel.virustotal"
        assert cap.provider == "virustotal"
        assert set(cap.actions) == {"domain_report", "ip_report", "url_report", "file_report"}
        assert cap.required_permissions == ["intel.read", "threat.read"]
        assert cap.timeout_seconds == 15.0
        assert cap.retry_max == 2

    def test_provider_name(self):
        a = _fresh_adapter()
        assert a.provider_name == "virustotal"
        assert a.base_url == VT_BASE
        assert a.auth_header == "x-apikey"
        assert a.credentials_var == "VT_API_KEY"
        assert a.default_timeout == 15.0
        assert a.max_retries == 2

    def test_health_check_not_configured(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.health_check()
        assert result["status"] == "unconfigured"
        assert "VT_API_KEY" in result["detail"]

    def test_health_check_configured(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        result = a.health_check()
        assert result["status"] == "ok"
        assert result["provider"] == "virustotal"


class TestVTSuccess:
    def test_domain_report_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "id": "example.com",
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 70, "undetected": 15, "total": 92},
                    "last_analysis_date": 1690000000,
                    "domain": "example.com",
                    "registrar": "NAMECHEAP",
                    "creation_date": 1234567890,
                    "last_update": 1690000000,
                    "organization": "Example Org",
                    "country": "US",
                    "subdomains": ["www.example.com", "mail.example.com"],
                },
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["provider"] == "virustotal"
        assert data["source"] == "virustotal_api"
        assert data["action"] == "domain_report"
        assert data["target"] == "example.com"
        assert data["domain"] == "example.com"
        assert data["registrar"] == "NAMECHEAP"
        assert data["confidence"] >= 0.05
        assert data["detection_ratio"]["malicious"] == 5

    def test_ip_report_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "id": "1.1.1.1",
                "type": "ip-address",
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10, "total": 70},
                    "ip": "1.1.1.1",
                    "as_owner": "Cloudflare",
                    "asn": 13335,
                    "continent": "Oceania",
                    "country": "AU",
                    "reputation": 0,
                },
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.virustotal.ip_report", {"query": "1.1.1.1"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["ip"] == "1.1.1.1"
        assert data["as_owner"] == "Cloudflare"
        assert data["confidence"] == 0.0

    def test_url_report_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "id": "abc123",
                "type": "url",
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 50, "undetected": 5, "total": 58},
                    "url": "https://evil.com/malware",
                    "scan_date": 1690000000,
                    "last_final_url": "https://evil.com/final",
                    "page_title": "Malicious Page",
                    "reputation": -1.0,
                },
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.virustotal.url_report", {"query": "https://evil.com/malware"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["url"] == "https://evil.com/malware"
        assert data["page_title"] == "Malicious Page"
        assert data["confidence"] >= 0.03

    def test_file_report_200(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {
                "id": "abcdef1234567890",
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {"malicious": 10, "suspicious": 3, "harmless": 40, "undetected": 7, "total": 60},
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "meaningful_name": "malware.exe",
                    "type_tag": "Win32 EXE",
                    "size": 1024,
                    "first_seen": 1690000000,
                    "tags": ["trojan", "remote-access-trojan"],
                },
            }
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.virustotal.file_report", {"query": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
        assert result["status"] == "success"
        data = result["data"]
        assert data["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert data["file_type"] == "Win32 EXE"
        assert data["confidence"] >= 0.1


class TestVTCredential:
    def test_missing_credential_returns_error(self):
        a = _fresh_adapter()
        _clear_cred(a)
        result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        assert result["status"] == "error"
        assert result["error"] == "provider_not_configured"
        assert "VT_API_KEY" in result["metadata"]["detail"]

    def test_missing_credential_skips_http(self):
        a = _fresh_adapter()
        _clear_cred(a)
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        mock_req.assert_not_called()


class TestVTAuth:
    def test_401_auth_failed(self):
        a = _fresh_adapter()
        _set_cred(a, "bad-key")
        with patch.object(a._http, "request", return_value=_make_resp(401, {"error": "Wrong API key"})):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        assert result["status"] == "error"
        assert result["error"] == "auth_failed"

    def test_403_forbidden(self):
        a = _fresh_adapter()
        _set_cred(a, "key")
        with patch.object(a._http, "request", return_value=_make_resp(403, {"error": "forbidden"})):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        assert result["status"] == "error"
        assert result["error"] in ("auth_failed", "forbidden")


class TestVTNotFound:
    def test_404(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", return_value=_make_resp(404, {"error": "Not found"})):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "nonexistent.xyz"})
        assert result["status"] == "error"
        assert result["error"] == "not_found"


class VTRateLimit:
    def test_429_with_retry_after(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", return_value=_make_resp(429, {}, {"Retry-After": "2"})):
            import time
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert result["metadata"].get("retry_after") == 2.0
        assert elapsed >= 2.0

    def test_429_without_retry_after(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", return_value=_make_resp(429, {})):
            import time
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "rate_limited"
        assert elapsed < 1.0


class VTRetry:
    def test_503_retry_then_success(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        good_body = {
            "data": {"id": "test.com", "type": "domain", "attributes": {"last_analysis_stats": {"total": 10, "malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 0}}}
        }
        with patch.object(a._http, "request", side_effect=[
            _make_resp(503),
            _make_resp(503),
            _make_resp(200, good_body),
        ]) as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "test.com"})
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
            import time
            start = time.monotonic()
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
            elapsed = time.monotonic() - start
        assert result["status"] == "error"
        assert result["error"] == "provider_error"
        assert elapsed >= 1.5


class VTTargetValidation:
    def test_domain_rejects_ip(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "192.168.1.1"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"

    def test_ip_rejects_domain(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.ip_report", {"query": "example.com"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"

    def test_url_rejects_non_url(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.url_report", {"query": "not-a-url"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"

    def test_file_rejects_non_hash(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request") as mock_req:
            result = a.execute(None, "cyber_intel.virustotal.file_report", {"query": "not-a-hash"})
        mock_req.assert_not_called()
        assert result["status"] == "error"
        assert result["error"] == "unsupported_target"


class VTMalformed:
    def test_non_json_response(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        with patch.object(a._http, "request", return_value=HttpResponse(status=200, headers={}, body="not json", url=VT_BASE)):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {"query": "example.com"})
        assert result["status"] == "error"
        assert result["error"] == "malformed_response"


class VTProvenance:
    def test_provenance_preserved(self):
        a = _fresh_adapter()
        _set_cred(a, "fake-key")
        body = {
            "data": {"id": "test.com", "type": "domain", "attributes": {"last_analysis_stats": {"total": 1, "malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 0}}}
        }
        with patch.object(a._http, "request", return_value=_make_resp(200, body)):
            result = a.execute(None, "cyber_intel.virustotal.domain_report", {
                "query": "test.com",
                "case_id": "case-1",
                "investigation_id": "inv-1",
                "agent_id": "threat",
                "agent_run_id": "run-1",
            })
        assert result["status"] == "success"
        assert result["metadata"]["case_id"] == "case-1"
        assert result["metadata"]["investigation_id"] == "inv-1"
