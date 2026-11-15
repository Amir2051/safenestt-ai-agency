"""
Hunter.io API adapter for SafeNestT identity intelligence.

Credential: HUNTER_API_KEY

Hunter API v2: https://api.hunter.io/v2/

Supported actions:
- email_verifier: GET /email-verifier?email=... — verify email address, get score/confidence
- domain_search: GET /domain-search?domain=... — discover email addresses associated with a domain

Free tier: 50 searches/month (varies by plan). Rate-limit handling needed.

All results are EXTERNAL_INTELLIGENCE — never investigator conclusions.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

from safenestt.schemas.tools import ToolCapability
from safenestt.tools.adapters.provider_base import (
    HttpClient,
    ProviderAdapter,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderError,
    ProviderMalformedResponse,
    RequestSpec,
)

logger = logging.getLogger(__name__)

HUNTER_BASE = "https://api.hunter.io/v2"


class HunterAdapter(ProviderAdapter):
    """Hunter.io API v2 adapter.

    Use cases:
    - email_verifier: verify an email address, get deliverability score
    - domain_search: find email addresses associated with a domain
    """

    provider_name = "hunter"
    base_url = HUNTER_BASE
    auth_header = "Authorization"  # Hunter uses Bearer token
    credentials_var = "HUNTER_API_KEY"
    default_timeout = 10.0
    max_retries = 1
    retry_backoff = 1.0
    rate_limit_delay = 0.0
    max_response_bytes = 500 * 1024  # 500 KB — Hunter responses are small
    follow_redirects = True
    max_redirects = 3

    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.hunter",
            name="Hunter.io",
            description="Verify email addresses and discover emails associated with domains.",
            provider="hunter",
            actions=["email_verifier", "domain_search"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Email address or domain to query"},
                    "query_type": {"type": "string", "enum": ["email", "domain"], "default": "email"},
                },
                "required": ["query"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read"],
            auth_requirement="env",
            error_behavior="record_and_continue",
            provenance=True,
            timeout_seconds=10.0,
            retry_max=1,
        ),
    ]

    def _build_request(self, action, payload, credential):
        query = str(payload.get("query", "")).strip()
        if not query:
            return None

        headers = {}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"

        if action == "email_verifier":
            if not _looks_like_email(query):
                return None
            params = {"email": query}
            url = f"{HUNTER_BASE}/email-verifier"
            return RequestSpec(method="GET", url=url, headers=headers, params=params, timeout=self.default_timeout)

        if action == "domain_search":
            if not _looks_like_domain(query):
                return None
            params = {"domain": query}
            url = f"{HUNTER_BASE}/domain-search"
            return RequestSpec(method="GET", url=url, headers=headers, params=params, timeout=self.default_timeout)

        return None

    def _normalize_response(self, resp, action, payload):
        data = resp.json()
        result = {
            "provider": "hunter",
            "source": "hunter_api",
            "action": action,
            "target": payload.get("query", ""),
            "observed_at": None,
            "raw": data,
        }

        if action == "email_verifier":
            result.update(_normalize_email_verifier(data))
        elif action == "domain_search":
            result.update(_normalize_domain_search(data))

        return result

    def _normalize_error(self, status, body, action):
        body_str = str(body)
        if status == 401:
            return {"code": "auth_failed", "detail": "Hunter: invalid API key"}
        if status == 403:
            return {"code": "forbidden", "detail": "Hunter: access forbidden"}
        if status == 429:
            return {"code": "rate_limited", "detail": "Hunter rate limit exceeded", "retry_after": None}
        if status == 404:
            return {"code": "not_found", "detail": f"Hunter: resource not found for {action}"}
        return {"code": "provider_error", "detail": f"Hunter error {status}: {body_str[:200]}"}

    def execute(self, agent, capability, payload):
        return super().execute(agent, capability, payload)


def _normalize_email_verifier(data):
    """Normalize Hunter email-verifier response."""
    meta = data.get("data", {}).get("meta", {})
    attrs = data.get("data", {}).get("attr", {})

    return {
        "email": attrs.get("email", ""),
        "status": attrs.get("status", ""),
        "score": attrs.get("score", 0),
        "confidence": attrs.get("confidence", ""),
        "gibberish": attrs.get("gibberish", False),
        "disposable": attrs.get("disposable", False),
        "webmail": attrs.get("webmail", False),
        "valid_semantically": attrs.get("valid_semantically", False),
        "valid_server": attrs.get("valid_server", False),
        "mail_server": attrs.get("mail_server", ""),
        "smtp_provider": attrs.get("smtp_provider", ""),
        "verification_token": attrs.get("verification_token", ""),
    }


def _normalize_domain_search(data):
    """Normalize Hunter domain-search response."""
    meta = data.get("data", {}).get("meta", {})
    attrs = data.get("data", {}).get("domain", {})

    emails = attrs.get("emails", []) or []
    parsed_emails = []
    for e in emails[:50]:
        ae = e.get("value", "")
        if ae:
            parsed_emails.append({
                "value": ae,
                "first_name": e.get("first_name", ""),
                "last_name": e.get("last_name", ""),
                "position": e.get("position", ""),
                "company": e.get("company", ""),
                "phone_number": e.get("phone_number", ""),
                "email_status": e.get("email_status", ""),
                "confidence": e.get("confidence", 0),
                "is_disposable": e.get("is_disposable", False),
                "is_webmail": e.get("is_webmail", False),
                "is_catchall": e.get("is_catchall", False),
                "is_null": e.get("is_null", False),
            })

    return {
        "domain": attrs.get("domain", ""),
        "organization": attrs.get("organization", ""),
        "industry": attrs.get("industry", ""),
        "country": attrs.get("country", ""),
        "email_count": attrs.get("email_count", 0),
        "absorption_rate": attrs.get("absorption_rate", 0),
        "emails": parsed_emails,
    }


def _looks_like_email(value):
    """Very rough email check — contains @."""
    if not value:
        return False
    return "@" in value and "." in value.split("@")[-1]

def _looks_like_domain(value):
    if not value:
        return False
    if "/" in value or " " in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    return all(p.isalnum() or p == "-" for p in parts if p)
