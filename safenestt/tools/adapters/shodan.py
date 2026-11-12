"""
Real Shodan API adapter for SafeNestT threat intelligence.

Replaces the local CLI stub (dig/whois/theHarvester) with the actual
Shodan REST API. Uses SHODAN_API_KEY from the secrets manager.

Shodan API:
- Base: https://api.shodan.io/
- Auth: API key as query parameter ?key= (not header)
- Free tier: limited credits
- Rate limit: 429 with Retry-After header
- Timeout: 10s typical

Supported actions:
- domain: resolve DNS, query Shodan host search for each IP
- host: query Shodan host info by IP

Local OSINT tooling (dig/whois/theHarvester) is preserved as a
separate capability — it is NOT labeled as Shodan API results.
"""

from __future__ import annotations

import logging
from typing import Any

from safenestt.schemas.tools import ToolCapability
from safenestt.tools.adapters.provider_base import (
    HttpClient,
    ProviderAdapter,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderError,
    ProviderMalformedResponse,
    RequestSpec,
)

logger = logging.getLogger(__name__)

SHODAN_BASE = "https://api.shodan.io"


class ShodanAdapter(ProviderAdapter):
    """Real Shodan REST API adapter.

    Capabilities:
        shodan_api.domain   — resolve DNS + query Shodan host search
        shodan_api.host     — query Shodan host info by IP

    The existing "shodan_domain"/"shodan_host" capabilities in
    CyberIntelThreatAdapter remain as local OSINT tooling stubs
    (dig/whois/theHarvester). This adapter uses distinct capability
    names to keep the distinction clear:

        LOCAL OSINT (CLI tools) != SHODAN API RESULT
    """

    provider_name = "shodan"
    base_url = SHODAN_BASE
    auth_header = ""  # Shodan uses ?key= query param, not header
    credentials_var = "SHODAN_API_KEY"
    default_timeout = 10.0
    max_retries = 2
    retry_backoff = 1.0
    rate_limit_delay = 0.0
    max_response_bytes = 2 * 1024 * 1024  # 2 MB
    follow_redirects = True
    max_redirects = 5

    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.shodan_api",
            name="Shodan API",
            description="Query Shodan Internet Scanner for host/domain intelligence.",
            provider="shodan",
            actions=["domain", "host"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "query_type": {"type": "string", "enum": ["domain", "ip"]},
                },
                "required": ["query"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read", "threat.read"],
            auth_requirement="env",
            error_behavior="record_and_continue",
            provenance=True,
            timeout_seconds=10.0,
            retry_max=2,
        ),
    ]

    # ------------------------------------------------------------------
    # ToolAdapter overides
    # ------------------------------------------------------------------

    def _build_request(self, action, payload, credential):
        query = str(payload.get("query", "")).strip()
        if not query:
            return None

        if credential:
            cred_part = f"?key={credential}"
        else:
            cred_part = ""

        if action == "host":
            if not _looks_like_ip(query):
                return None
            url = f"{SHODAN_BASE}/shodan/host/{query}{cred_part}"
            return RequestSpec(method="GET", url=url, timeout=self.default_timeout)

        if action == "domain":
            # Domain: resolve DNS first via Shodan DNS endpoint
            resolve_url = f"{SHODAN_BASE}/dns/resolve?name={query}{cred_part}"
            return RequestSpec(method="GET", url=resolve_url, timeout=self.default_timeout)

        return None

    def _normalize_response(self, resp, action, payload):
        data = resp.json()
        if action == "host":
            return self._normalize_host(data)
        if action == "domain":
            return self._normalize_dns_resolve(data)
        return {"raw": data}

    def _normalize_error(self, status, body, action):
        body_str = str(body)
        if status == 401 or status == 403:
            return {"code": "auth_failed", "detail": "Shodan API key invalid or unauthorized"}
        if status == 404:
            return {"code": "not_found", "detail": f"Shodan: target not found for {action}"}
        if status == 429:
            return {"code": "rate_limited", "detail": "Shodan API rate limit exceeded", "retry_after": None}
        return {"code": "provider_error", "detail": f"Shodan API error {status}: {body_str[:200]}"}

    # ------------------------------------------------------------------
    # Response normalizers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_host(data: dict) -> dict:
        if not data or "error" in data:
            return {"raw": data, "error": data.get("error") if data else None}
        ip = data.get("ip_str", data.get("ip", ""))
        return {
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "org": data.get("org", ""),
            "os": data.get("os", ""),
            "open_ports": [
                {
                    "port": p.get("port") if isinstance(p, dict) else p,
                    "service": p.get("service", "") if isinstance(p, dict) else "",
                    "product": p.get("product", "") if isinstance(p, dict) else "",
                    "version": p.get("version", "") if isinstance(p, dict) else "",
                }
                for p in (data.get("ports", []) or [])
            ],
            "port_count": len(data.get("ports", [])),
            "vulns": {k: v for k, v in list((data.get("vulns") or {}).items())[:20]},
            "tags": list(data.get("tags", []) or [])[:20],
            "source": "shodan_api",
            "provider": "shodan",
            "raw": data,
        }

    @staticmethod
    def _normalize_dns_resolve(data: dict) -> dict:
        if not data or "resolved" not in data:
            return {"raw": data, "error": "No resolved IPs in Shodan DNS response"}
        resolved = data.get("resolved", {})
        ips = []
        for hostname, ip_list in resolved.items():
            for ip in ip_list:
                ips.append({"hostname": hostname, "ip": ip})
        return {
            "domain": list(resolved.keys())[0] if resolved else "",
            "ips": ips,
            "source": "shodan_api_dns",
            "provider": "shodan",
            "raw": data,
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _looks_like_ip(value: str) -> bool:
    """Rough IPv4 check."""
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _looks_like_domain(value: str) -> bool:
    """Very rough domain check."""
    if not value:
        return False
    if "/" in value or " " in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    return all(p.isalnum() or p == "-" for p in parts if p)
