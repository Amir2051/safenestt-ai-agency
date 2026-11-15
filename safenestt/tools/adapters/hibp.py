"""
Have I Been Pwned (HIBP) API adapter for SafeNestT identity intelligence.

Credential: HIBP_API_KEY (optional — some endpoints allow unauthenticated access
but with very strict rate limits: 1 request per 1500 seconds without a key).

HIBP API v3: https://haveibeenpwned.com/API/v3/

Supported actions:
- breached_account: GET /breachedaccount/{account} — check if account (email/username) was in breaches
- paste_account:    GET /pasteaccount/{account} — check if account appears in pastes

IMPORTANT:
- HIBP's breached account endpoint WITHOUT an API key allows only 1 request per 1500 seconds.
- With an API key, rate limits are more generous (varies, typically 1000-10000/hour depending on plan).
- The account parameter should be the email address, username, or phone number.
- For password breach checking (k-anonymity), DO NOT send plaintext passwords — only the first 5
  characters of the SHA1 hash. However, SafeNestT's current scope is account/breach lookup, not
  password verification. Only implement k-anonymity if there's a concrete investigation use case.

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

HIBP_BASE = "https://api.haveibeenpwned.com/api/v3"


class HIBPAdapter(ProviderAdapter):
    """HIBP API v3 adapter.

    Without a credential, only the breached account endpoint works with
    very strict rate limiting (1 req / 1500 seconds). With a key, rate
    limits are more generous.

    For SafeNestT, the primary use case is checking whether an email
    address has been involved in known data breaches.
    """

    provider_name = "hibp"
    base_url = HIBP_BASE
    auth_header = "hibp-api-key"  # HIBP uses custom header, not Bearer
    credentials_var = "HIBP_API_KEY"
    default_timeout = 10.0
    max_retries = 1  # HIBP is strict on rate — don't hammer
    retry_backoff = 2.0
    rate_limit_delay = 0.0  # Let 429 Retry-After handle it
    max_response_bytes = 1 * 1024 * 1024  # 1 MB — breach data can be large
    follow_redirects = True
    max_redirects = 3

    credentials_var_optional = True  # Some endpoints work without a key (rate-limited)

    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.hibp",
            name="Have I Been Pwned",
            description="Check if accounts have been exposed in known data breaches.",
            provider="hibp",
            actions=["breached_account", "paste_account"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Email address or username to check"},
                    "query_type": {"type": "string", "enum": ["email", "username"], "default": "email"},
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
        query = str(payload.get("query", "")).strip().lower()
        if not query:
            return None

        # HIBP requires the account to be URL-encoded
        encoded_account = quote(query, safe="")

        headers = {}
        if credential:
            headers["hibp-api-key"] = credential

        url = f"{HIBP_BASE}/{action}/{encoded_account}"
        return RequestSpec(method="GET", url=url, headers=headers, timeout=self.default_timeout)

    def _normalize_response(self, resp, action, payload):
        data = resp.json()
        query = payload.get("query", "")

        result = {
            "provider": "hibp",
            "source": "hibp_api",
            "action": action,
            "target": query,
            "observed_at": None,
            "raw": data,
        }

        if action == "breached_account":
            breaches = data if isinstance(data, list) else []
            result.update({
                "breaches": [
                    {
                        "name": b.get("Name", ""),
                        "title": b.get("Title", ""),
                        "domain": b.get("Domain", ""),
                        "breach_date": b.get("BreachDate", ""),
                        "added_date": b.get("AddedDate", ""),
                        "modified_date": b.get("ModifiedDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "is_verified": b.get("IsVerified", False),
                        "is_mature": b.get("IsMature", False),
                        "data_classes": b.get("DataClasses", [])[:20],
                        "logo_path": b.get("LogoPath", ""),
                    }
                    for b in breaches[:50]
                ],
                "breach_count": len(breaches),
                "breached": len(breaches) > 0,
            })
            result["confidence"] = _confidence_from_breaches(breaches)

        elif action == "paste_account":
            pastes = data if isinstance(data, list) else []
            result.update({
                "pastes": [
                    {
                        "id": p.get("Id", ""),
                        "title": p.get("Title", ""),
                        "date": p.get("Date", ""),
                        "email_address": p.get("EmailAddress", query),
                        "source": p.get("Source", ""),
                        "is_verified": p.get("IsVerified", False),
                        "is_mature": p.get("IsMature", False),
                    }
                    for p in pastes[:50]
                ],
                "paste_count": len(pastes),
                "has_pastes": len(pastes) > 0,
            })
            result["confidence"] = _confidence_from_pastes(pastes)

        return result

    def _normalize_error(self, status, body, action):
        body_str = str(body)
        if status == 401:
            return {"code": "auth_failed", "detail": "HIBP: invalid API key"}
        if status == 403:
            return {"code": "forbidden", "detail": "HIBP: access forbidden"}
        if status == 429:
            return {"code": "rate_limited", "detail": "HIBP rate limit exceeded", "retry_after": None}
        if status == 404:
            return {"code": "not_found", "detail": f"HIBP: no data found for {action} — account may be clean"}
        return {"code": "provider_error", "detail": f"HIBP error {status}: {body_str[:200]}"}

    def execute(self, agent, capability, payload):
        """HIBP requires special handling for the breached account endpoint:
        - Without API key, the rate limit is 1 request per 1500 seconds.
        - We set max_retries=1 and rely on the 429 handler.
        """
        return super().execute(agent, capability, payload)


def _confidence_from_breaches(breaches):
    """Confidence based on number and severity of breaches."""
    if not breaches:
        return 0.0
    verified = sum(1 for b in breaches if b.get("IsVerified", False))
    count = len(breaches)
    # More breaches + verified = higher confidence
    score = min(1.0, (count * 0.15) + (verified * 0.1))
    return round(score, 3)

def _confidence_from_pastes(pastes):
    if not pastes:
        return 0.0
    verified = sum(1 for p in pastes if p.get("IsVerified", False))
    score = min(1.0, (len(pastes) * 0.1) + (verified * 0.05))
    return round(score, 3)
