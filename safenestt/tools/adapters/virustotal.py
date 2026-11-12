"""
VirusTotal API v3 adapter for SafeNestT threat intelligence.

Credential: VT_API_KEY
Base: https://www.virustotal.com/api/v3/

Supports: domain_report, ip_report, url_report, file_report

Free tier: 4 req/min, 500 req/day. Rate-limit handling is critical.
All results are EXTERNAL_INTELLIGENCE — never investigator conclusions.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

from safenestt.schemas.tools import ToolCapability
from safenestt.tools.adapters.provider_base import (
    ProviderAdapter,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderError,
    ProviderMalformedResponse,
    RequestSpec,
)

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAdapter(ProviderAdapter):
    """VirusTotal API v3 adapter."""

    provider_name = "virustotal"
    base_url = VT_BASE
    auth_header = "x-apikey"
    credentials_var = "VT_API_KEY"
    default_timeout = 15.0
    max_retries = 2
    retry_backoff = 1.5
    rate_limit_delay = 0.0
    max_response_bytes = 5 * 1024 * 1024
    follow_redirects = True
    max_redirects = 3

    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.virustotal",
            name="VirusTotal",
            description="Query VirusTotal for domain/IP/URL/file reputation intelligence.",
            provider="virustotal",
            actions=["domain_report", "ip_report", "url_report", "file_report"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "query_type": {
                        "type": "string",
                        "enum": ["domain", "ip", "url", "file"],
                    },
                },
                "required": ["query"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read", "threat.read"],
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

        headers = {"x-apikey": credential} if credential else {}

        if action == "domain_report":
            if not _looks_like_domain(query):
                return None
            url = f"{VT_BASE}/domains/{quote(query, safe='')}"
            return RequestSpec(method="GET", url=url, headers=headers, timeout=self.default_timeout)

        if action == "ip_report":
            if not _looks_like_ip(query):
                return None
            url = f"{VT_BASE}/ip-addresses/{quote(query, safe='')}"
            return RequestSpec(method="GET", url=url, headers=headers, timeout=self.default_timeout)

        if action == "url_report":
            if not _looks_like_url(query):
                return None
            url = f"{VT_BASE}/urls/{quote(query, safe='')}"
            return RequestSpec(method="GET", url=url, headers=headers, timeout=self.default_timeout)

        if action == "file_report":
            if not _looks_like_hash(query):
                return None
            url = f"{VT_BASE}/files/{quote(query, safe='')}"
            return RequestSpec(method="GET", url=url, headers=headers, timeout=self.default_timeout)

        return None

    def _normalize_response(self, resp, action, payload):
        data = resp.json()
        vt_data = data.get("data", {})
        attributes = vt_data.get("attributes", {})
        relationships = vt_data.get("relationships", {})

        result = {
            "provider": "virustotal",
            "source": "virustotal_api",
            "action": action,
            "target": payload.get("query", ""),
            "observed_at": attributes.get("last_analysis_date") or attributes.get("first_submission_date"),
            "raw": data,
        }

        # Detection statistics
        stats = attributes.get("last_analysis_stats", {})
        result["last_analysis_stats"] = stats
        total = stats.get("total", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        result["detection_ratio"] = {
            "total": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
        result["confidence"] = _confidence_from_stats(stats)

        # Attributes by action
        if action == "domain_report":
            result.update(_normalize_domain_attrs(attributes))
        elif action == "ip_report":
            result.update(_normalize_ip_attrs(attributes))
        elif action == "url_report":
            result.update(_normalize_url_attrs(attributes))
        elif action == "file_report":
            result.update(_normalize_file_attrs(attributes))

        # Relationships
        if relationships:
            result["relationships"] = _normalize_relationships(relationships)

        return result

    def _normalize_error(self, status, body, action):
        body_str = str(body)
        if status == 401:
            return {"code": "auth_failed", "detail": "VirusTotal API key invalid"}
        if status == 403:
            return {"code": "forbidden", "detail": "VirusTotal: access forbidden"}
        if status == 404:
            return {"code": "not_found", "detail": f"VirusTotal: {action} target not found"}
        if status == 429:
            return {"code": "rate_limited", "detail": "VirusTotal rate limit exceeded", "retry_after": None}
        return {"code": "provider_error", "detail": f"VT error {status}: {body_str[:200]}"}

    def execute(self, agent, capability, payload):
        """Override to inject auth header properly (provider_base uses it)."""
        return super().execute(agent, capability, payload)


def _normalize_domain_attrs(attrs):
    return {
        "domain": attrs.get("domain", ""),
        "registrar": attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date"),
        "last_update": attrs.get("last_update"),
        "organization": attrs.get("organization", ""),
        "country": attrs.get("country", ""),
        "subdomains": attrs.get("subdomains", [])[:50],
        "meaningful_requests": attrs.get("meaningful_requests", [])[:20],
        "referrer_files": attrs.get("referrer_files", [])[:20],
    }

def _normalize_ip_attrs(attrs):
    return {
        "ip": attrs.get("ip", ""),
        "as_owner": attrs.get("as_owner", ""),
        "asn": attrs.get("asn"),
        "continent": attrs.get("continent", ""),
        "country": attrs.get("country", ""),
        "region": attrs.get("region", ""),
        "city": attrs.get("city", ""),
        "reputation": attrs.get("reputation"),
    }

def _normalize_url_attrs(attrs):
    return {
        "url": attrs.get("url", ""),
        "scan_date": attrs.get("scan_date"),
        "last_final_url": attrs.get("last_final_url", ""),
        "page_title": attrs.get("page_title", ""),
        "content_type": attrs.get("content_type", ""),
        "tags": attrs.get("tags", [])[:20],
        "reputation": attrs.get("reputation"),
        "keywords": attrs.get("keywords", [])[:20],
    }

def _normalize_file_attrs(attrs):
    return {
        "md5": attrs.get("md5", ""),
        "sha1": attrs.get("sha1", ""),
        "sha256": attrs.get("sha256", ""),
        "filename": attrs.get("meaningful_name") or attrs.get("name", ""),
        "file_type": attrs.get("type_tag", ""),
        "size": attrs.get("size", 0),
        "scan_date": attrs.get("first_seen"),
        "tags": attrs.get("tags", [])[:20],
    }

def _normalize_relationships(relationships):
    result = {}
    for rel_name, rel_data in list(relationships.items())[:10]:
        items = rel_data.get("data", [])
        result[rel_name] = [
            {"id": item.get("id", ""), "type": item.get("type", "")}
            for item in (items if isinstance(items, list) else [items])
        ][:20]
    return result

def _confidence_from_stats(stats):
    total = stats.get("total", 0)
    if total == 0:
        return 0.0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    ratio = (malicious + suspicious) / total
    return round(min(1.0, max(0.0, ratio)), 3)

def _looks_like_domain(value):
    if not value:
        return False
    if "/" in value or " " in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    return all(p.isalnum() or p == "-" for p in parts if p)

def _looks_like_ip(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def _looks_like_url(value):
    return value.startswith("http://") or value.startswith("https://")

def _looks_like_hash(value):
    if not value:
        return False
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        return False
    return 32 <= len(value) <= 64
