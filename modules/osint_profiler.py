"""OSINT Profiler module for SafeNestT investigation engine.

Provides public-source OSINT lookups for indicators:
email, domain, IP, username, phone.

Uses DuckDuckGo search (DDGS) as the primary data source.
Also supports phone/email reputation scoring.

This module is tenant-agnostic: it takes a query and query_type
and returns results. No hardcoded state or tenant-specific config.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_hash(value: str) -> str:
    """Return a one-way hash of the value for logging without exposing PII."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _web_search(query: str, limit: int = 5) -> dict[str, Any]:
    """Perform a web search using DuckDuckGo (DDGS).

    Returns a dict with:
    - data: {"web": [{"title", "url", "description"}, ...]}
    """
    try:
        from ddgs import DDGS
        results = list(DDGS().text(query, max_results=limit))
        return {
            "data": {
                "web": [
                    {
                        "title": r.get("title", ""),
                        "url": r.get("href", r.get("url", "")),
                        "description": r.get("body", r.get("description", "")),
                    }
                    for r in results
                ]
            }
        }
    except ImportError:
        return {"data": {"web": []}}
    except Exception:
        return {"data": {"web": []}}


def run_osint_profile(query: str, query_type: str) -> dict[str, Any]:
    """Run an OSINT profile on the given query.

    Args:
        query: The indicator value (email, domain, IP, etc.)
        query_type: One of: email, domain, ip, username, phone

    Returns a dict with:
    - query, query_type, timestamp, sources, risk_score, risk_level,
      findings, limitations

    This function is stateless and tenant-safe.
    """
    findings: dict[str, Any] = {}
    sources: list[str] = []
    risk_score = 0

    # Always run web search for the query
    search_query = f"{query_type} {query}"
    result = _web_search(search_query, limit=5)
    sources.append("web_search")
    web_results = result.get("data", {}).get("web", [])
    findings["web_search"] = {
        "count": len(web_results),
        "titles": [r.get("title", "") for r in web_results[:5]],
        "urls": [r.get("url", "") for r in web_results[:5]],
        "descriptions": [r.get("description", "") for r in web_results[:5]],
    }
    if len(web_results) > 3:
        risk_score = min(70, len(web_results) * 10)
    elif len(web_results) > 0:
        risk_score = 30

    # Type-specific enrichment
    if query_type == "phone":
        _enrich_phone(query, findings, sources)
    elif query_type == "email":
        _enrich_email(query, findings, sources)
    elif query_type == "domain":
        _enrich_domain(query, findings, sources)
    elif query_type == "username":
        _enrich_username(query, findings, sources)
    elif query_type == "ip":
        _enrich_ip(query, findings, sources)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "unknown"

    return {
        "query": query,
        "query_type": query_type,
        "timestamp": _now(),
        "sources": sources,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "limitations": [
            "OSINT results are public-source signals, not verified legal facts.",
            "Web search results may be outdated or incomplete.",
            "Absence of results does not mean the target is clean.",
            "All findings require human verification before legal use.",
        ],
    }


def _enrich_phone(query: str, findings: dict, sources: list) -> None:
    """Enrich phone number with reputation signals."""
    for fmt in [query, query.replace("+1", ""), query.replace("-", " "), query.replace(" ", "")]:
        try:
            result = _web_search(f"phone number {fmt}", limit=3)
            sources.append(f"phone_search")
            web_results = result.get("data", {}).get("web", [])
            if web_results:
                findings[f"phone"] = {
                    "count": len(web_results),
                    "titles": [r.get("title", "") for r in web_results[:3]],
                }
                if len(web_results) > 1:
                    break
        except Exception:
            pass


def _enrich_email(query: str, findings: dict, sources: list) -> None:
    """Enrich email with breach/leak signals."""
    try:
        result = _web_search(f"email {query} breach leak", limit=3)
        sources.append("email_search")
        web_results = result.get("data", {}).get("web", [])
        findings["email_search"] = {
            "count": len(web_results),
            "titles": [r.get("title", "") for r in web_results[:3]],
        }
        if len(web_results) > 0:
            findings["email_risk"] = "Potential breach references found"
    except Exception as exc:
        findings["email_search"] = {"error": str(exc)}


def _enrich_domain(query: str, findings: dict, sources: list) -> None:
    """Enrich domain with whois and reputation signals."""
    try:
        result = _web_search(f"domain {query} whois", limit=3)
        sources.append("domain_search")
        web_results = result.get("data", {}).get("web", [])
        findings["domain_search"] = {
            "count": len(web_results),
            "titles": [r.get("title", "") for r in web_results[:3]],
        }
    except Exception as exc:
        findings["domain_search"] = {"error": str(exc)}


def _enrich_username(query: str, findings: dict, sources: list) -> None:
    """Enrich username with social media signals."""
    try:
        result = _web_search(f"username {query} social media", limit=3)
        sources.append("username_search")
        web_results = result.get("data", {}).get("web", [])
        findings["username_search"] = {
            "count": len(web_results),
            "titles": [r.get("title", "") for r in web_results[:3]],
        }
    except Exception as exc:
        findings["username_search"] = {"error": str(exc)}


def _enrich_ip(query: str, findings: dict, sources: list) -> None:
    """Enrich IP with location/reputation signals."""
    try:
        result = _web_search(f"IP address {query} whois location", limit=3)
        sources.append("ip_search")
        web_results = result.get("data", {}).get("web", [])
        findings["ip_search"] = {
            "count": len(web_results),
            "titles": [r.get("title", "") for r in web_results[:3]],
        }
    except Exception as exc:
        findings["ip_search"] = {"error": str(exc)}


def check_shodan_domain(domain: str) -> dict[str, Any]:
    """Check domain reputation using dig + whois + theHarvester."""
    import subprocess
    data: dict[str, Any] = {"domain": domain, "dns": [], "whois": None, "subdomains": []}
    errors: list[str] = []

    # dig lookup
    try:
        result = subprocess.run(["dig", domain, "A", "+short"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            data["dns"] = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
    except Exception as exc:
        errors.append(f"dig: {exc}")

    # whois lookup
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            whois_info = {}
            for line in lines:
                if ":" in line and not line.startswith("%"):
                    key, _, value = line.partition(":")
                    whois_info[key.strip()] = value.strip()
            data["whois"] = whois_info
    except Exception as exc:
        errors.append(f"whois: {exc}")

    # theHarvester passive subdomain discovery
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "google,bing,duckduckgo", "-l", "50"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("[*]"):
                    continue
                if "." in domain and domain in line and " " not in line:
                    subdomain = line.strip()
                    if subdomain not in data["subdomains"]:
                        data["subdomains"].append(subdomain)
    except Exception as exc:
        errors.append(f"theHarvester: {exc}")

    if errors:
        data["_errors"] = errors

    return {"data": data, "status": "success" if (data["dns"] or data["whois"]) else "partial"}


def check_shodan_host(ip: str) -> dict[str, Any]:
    """Check host/IP using dig reverse + whois."""
    import subprocess
    data: dict[str, Any] = {"ip": ip, "reverse_dns": None, "whois": None}
    errors: list[str] = []

    # Reverse DNS
    try:
        result = subprocess.run(["dig", "-x", ip, "+short"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            data["reverse_dns"] = result.stdout.strip().splitlines()[0].strip()
    except Exception as exc:
        errors.append(f"dig: {exc}")

    # whois
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            whois_info = {}
            for line in lines:
                if ":" in line and not line.startswith("%"):
                    key, _, value = line.partition(":")
                    whois_info[key.strip()] = value.strip()
            data["whois"] = whois_info
    except Exception as exc:
        errors.append(f"whois: {exc}")

    if errors:
        data["_errors"] = errors

    return {"data": data, "status": "success" if data["reverse_dns"] or data["whois"] else "partial"}


def score_reputation(value: str, value_type: str) -> dict[str, Any]:
    """Score the reputation of an email or phone number.

    Args:
        value: The indicator value
        type: "email" or "phone"

    Returns a dict with:
    - value, type, timestamp, risk_score, risk_level, signals, summary,
      limitations

    Stateless and tenant-safe.
    """
    signals: list[dict[str, Any]] = []
    risk_score = 0

    search_query = f"{value_type} {value}"
    result = _web_search(search_query, limit=5)
    web_results = result.get("data", {}).get("web", [])

    if web_results:
        signals.append({
            "type": "web_presence",
            "count": len(web_results),
            "description": f"Found {len(web_results)} web results",
        })
        risk_score = min(70, len(web_results) * 10)
    else:
        signals.append({
            "type": "web_presence",
            "count": 0,
            "description": "No web results found",
        })

    # Spam/fraud signals for phone
    if value_type == "phone":
        try:
            result = _web_search(f"{value} spam fraud scam", limit=3)
            web_results = result.get("data", {}).get("web", [])
            spam_count = sum(1 for r in web_results if any(
                w in (r.get("title", "") + r.get("description", "")).lower()
                for w in ["spam", "fraud", "scam", "telemarketer"]
            ))
            if spam_count > 0:
                signals.append({"type": "spam_fraud", "count": spam_count,
                                "description": f"Found {spam_count} spam/fraud references"})
                risk_score = max(risk_score, 60)
        except Exception:
            pass

    # Breach/leak signals for email
    if value_type == "email":
        try:
            result = _web_search(f"{value} spam leak breach", limit=3)
            web_results = result.get("data", {}).get("web", [])
            breach_count = sum(1 for r in web_results if any(
                w in (r.get("title", "") + r.get("description", "")).lower()
                for w in ["breach", "leak", "compromised", "pwned"]
            ))
            if breach_count > 0:
                signals.append({"type": "breach", "count": breach_count,
                                "description": f"Found {breach_count} breach references"})
                risk_score = max(risk_score, 60)
        except Exception:
            pass

    if risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "unknown"

    return {
        "value": value,
        "type": value_type,
        "timestamp": _now(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "summary": {"signal_count": len(signals), "risk_level": risk_level},
        "limitations": [
            "Reputation scoring reflects external API signals and heuristics only.",
            "Web search results may be outdated or incomplete.",
            "Absence of results does not mean the target is clean.",
            "All findings require human verification before legal use.",
        ],
    }


def _run_sync(coro):
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        return loop.run_until_complete(coro)
