"""
Firecrawl adapter for SafeNestT web intelligence.

Credential: FIRECRAWL_API_KEY

Firecrawl API v1:
- Base: https://api.firecrawl.dev/v1
- Auth: Authorization: Bearer <api_key>
- Endpoints:
  - POST /websites/scan — crawl a website
  - POST /websites/{url}/scrape — scrape a single URL
  - POST /websites/search?q=... — web search

CRITICAL SECURITY: User-supplied URLs are UNTRUSTED.
SSRF protection must be applied before any HTTP request.
"""

from __future__ import annotations

import json
import logging
import re
import socket
from typing import Any
from urllib.parse import urlparse

from safenestt.schemas.tools import ToolCapability
from safenestt.tools.adapters.provider_base import (
    ProviderAdapter,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderError,
    ProviderMalformedResponse,
    ProviderUnavailable,
    ProviderUnsupportedTarget,
    ProviderNotConfigured,
    ProviderResponseTooLarge,
    RequestSpec,
    HttpClient,
)

logger = logging.getLogger(__name__)

FIRECRAWL_BASE = "https://api.firecrawl.dev/v1"

# SSRF protection: block private, loopback, link-local, reserved ranges
_LOCALHOST_DNS = {"localhost", "local", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}
_PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
)


def _resolve_dns(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses. Returns list of IP strings."""
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({addr[4][0] for addr in addrs})
    except socket.gaierror:
        return []


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved/loopback."""
    if ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    # IPv4 private ranges
    if ip.startswith(_PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("169.254."):  # link-local
        return True
    if ip.startswith("100.64."):  # CGNAT
        return True
    # IPv4 loopback
    if ip.startswith("127."):
        return True
    # IPv6 — allow global unicast addresses (start with 2001::/32 etc)
    # The original check was too broad: it blocked ALL IPv6 except 2001:: 
    # Fix: only block truly private/loopback IPv6
    if ":" in ip:
        # Block ::1 (loopback), fc00::/7 (unique local), fe80::/10 (link-local)
        if ip == "::1" or ip.startswith("::1"):
            return True
        if ip.startswith("fc") or ip.startswith("fd"):  # fc00::/7 unique local
            return True
        if ip.startswith("fe80") or ip.startswith("fe9"):  # fe80::/10 link-local
            return True
        if ip.startswith("ff"):  # ff00::/8 multicast
            return True
        return False
    return False


def _validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL for SSRF safety.

    Returns (is_safe, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"

    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme: {parsed.scheme}"

    # Hostname check
    hostname = parsed.hostname or ""
    if not hostname:
        return False, "URL has no hostname"

    # Lowercase for comparison
    host_lower = hostname.lower()

    # Blocklisted hostnames
    if host_lower in _LOCALHOST_DNS or host_lower.startswith("127."):
        return False, f"Blocked: localhost/loopback hostname '{hostname}'"

    # Blocklisted IP literals in URL
    if host_lower.startswith("10.") or host_lower.startswith("172.") or host_lower.startswith("192.168."):
        return False, f"Blocked: private IPv4 literal '{hostname}'"
    if host_lower.startswith("169.254.") or host_lower.startswith("100.64."):
        return False, f"Blocked: link-local/CGNAT '{hostname}'"
    if host_lower in ("::1", "[::1]", "0.0.0.0", "[" + "::1" + "]"):
        return False, f"Blocked: IPv6 loopback '{hostname}'"
    if host_lower.startswith("fc") or host_lower.startswith("fe80"):
        return False, f"Blocked: IPv6 private/link-local '{hostname}'"

    # DNS resolution check
    ips = _resolve_dns(hostname)
    if not ips:
        return False, f"Could not resolve hostname '{hostname}'"

    for ip in ips:
        if _is_private_ip(ip):
            return False, f"Blocked: hostname '{hostname}' resolves to private IP {ip}"

    return True, ""


class FirecrawlAdapter(ProviderAdapter):
    """Firecrawl web scraping/search adapter.

    Actions:
        url_scrape:  POST /websites/{url}/scrape
        web_search:  POST /websites/search?q=...
    """

    provider_name = "firecrawl"
    base_url = FIRECRAWL_BASE
    auth_header = "Authorization"
    credentials_var = "FIRECRAWL_API_KEY"
    default_timeout = 15.0
    max_retries = 2
    retry_backoff = 1.0
    rate_limit_delay = 0.0
    max_response_bytes = 10 * 1024 * 1024  # 10 MB — generous for web content
    follow_redirects = False  # We handle redirects manually for SSRF safety
    max_redirects = 10

    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.firecrawl",
            name="Firecrawl",
            description="Scrape or crawl web pages for investigation intelligence.",
            provider="firecrawl",
            actions=["url_scrape", "web_search"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Full URL to scrape"},
                    "query_type": {"type": "string", "enum": ["url", "search"], "default": "url"},
                    "params": {"type": "object", "description": "Optional scrape parameters (json)"},
                },
                "required": ["query"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read"],
            auth_requirement="env",
            error_behavior="record_and_continue",
            provenance=True,
            timeout_seconds=15.0,
            retry_max=2,
        ),
    ]

    def _build_request(self, action, payload, credential):
        query = str(payload.get("query", "")).strip()
        if not query:
            return None

        headers = {"Authorization": f"Bearer {credential}"} if credential else {}

        if action == "url_scrape":
            # Validate URL for SSRF
            is_safe, error = _validate_url(query)
            if not is_safe:
                raise ProviderUnsupportedTarget(code="ssrf_blocked", message=error, action=action)
            # Firecrawl expects the URL as part of the path or body
            # POST /websites/{url}/scrape — but URL in path needs encoding
            encoded_url = query.replace("/", "%2F").replace(":", "%3A").replace("?", "%3F").replace("=", "%3D")
            url = f"{FIRECRAWL_BASE}/websites/{encoded_url}/scrape"
            params = payload.get("params") or {}
            body = {
                "url": query,
                **params,
            }
            return RequestSpec(
                method="POST",
                url=url,
                headers=headers,
                params={},
                body=json.dumps(body).encode("utf-8"),
                timeout=self.default_timeout,
            )

        if action == "web_search":
            params = {"q": query}
            extra = payload.get("params") or {}
            params.update(extra)
            return RequestSpec(
                method="POST",
                url=f"{FIRECRAWL_BASE}/websites/search",
                headers=headers,
                params={},
                body=json.dumps(params).encode("utf-8"),
                timeout=self.default_timeout,
            )

        return None

    def _normalize_response(self, resp, action, payload):
        data = resp.json()
        result = {
            "provider": "firecrawl",
            "source": "firecrawl_api",
            "action": action,
            "requested_url": payload.get("query", ""),
            "observed_at": None,
            "raw": data,
        }

        if action == "url_scrape":
            result.update(self._normalize_scrape(data))
        elif action == "web_search":
            result.update(self._normalize_search(data))

        return result

    def _normalize_scrape(self, data):
        content = data.get("content", "") or ""
        metadata = data.get("metadata", {}) or {}
        return {
            "url": data.get("url", data.get("original_url", "")),
            "final_url": data.get("final_url", data.get("url", "")),
            "content": content[:50000],  # truncate very long content
            "content_type": metadata.get("content-type", ""),
            "status_code": data.get("status"),
            "title": metadata.get("title", ""),
            "html_len": len(content),
        }

    def _normalize_search(self, data):
        results = data.get("data", []) or []
        return {
            "query": data.get("query", ""),
            "results": [
                {
                    "url": r.get("url", ""),
                    "title": r.get("title", ""),
                    "description": r.get("description", "")[:500],
                }
                for r in results[:50]
            ],
            "total": len(results),
        }

    def _normalize_error(self, status, body, action):
        body_str = str(body)
        if status == 401:
            return {"code": "auth_failed", "detail": "Firecrawl API key invalid"}
        if status == 403:
            return {"code": "forbidden", "detail": "Firecrawl: access forbidden"}
        if status == 429:
            return {"code": "rate_limited", "detail": "Firecrawl rate limit exceeded", "retry_after": None}
        if status == 400:
            # Check for SSRF-related errors from Firecrawl itself
            if "ssrf" in body_str.lower() or "private" in body_str.lower():
                return {"code": "ssrf_blocked", "detail": body_str[:300]}
            return {"code": "validation_error", "detail": body_str[:300]}
        if status == 404:
            return {"code": "not_found", "detail": f"Firecrawl: resource not found"}
        return {"code": "provider_error", "detail": f"Firecrawl error {status}: {body_str[:200]}"}
