"""Classify a raw investigation target into the indicator type it actually is.

Base44 sends a bare target string (often a crypto wallet). It used to be filed
as ``{"domain": target}`` unconditionally, so wallet cases ran DNS / Shodan /
WHOIS lookups that cannot resolve a wallet, and never reached the crypto lane
(CryptoAgent + Etherscan trace). The value's own shape decides the type here.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_EVM_ADDRESS = re.compile(r"^0x[a-fA-F0-9]{40}$")
_EVM_TX = re.compile(r"^0x[a-fA-F0-9]{64}$")
_BTC_ADDRESS = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_TRON_ADDRESS = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_BTC_TX = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_HOST = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$")
_PHONE = re.compile(r"^\+?[\d\s().-]{7,20}$")


def _host(value: str) -> str:
    raw = value if "://" in value else f"http://{value}"
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def classify_indicator(value: object) -> tuple[str, str] | None:
    """Return ``(indicator_key, normalized_value)`` or ``None`` for unusable input.

    Keys match what the orchestrator routes on: wallet_address,
    transaction_hash, email, ip_address, domain, phone.
    """
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    if _EVM_ADDRESS.match(v) or _BTC_ADDRESS.match(v) or _TRON_ADDRESS.match(v):
        return "wallet_address", v
    if _EVM_TX.match(v) or _BTC_TX.match(v):
        return "transaction_hash", v
    if _EMAIL.match(v):
        return "email", v.lower()
    if _IPV4.match(v):
        return "ip_address", v
    if " " not in v:
        host = _host(v)
        if host and _HOST.match(host):
            return "domain", host
    digits = sum(ch.isdigit() for ch in v)
    if _PHONE.match(v) and digits >= 7:
        return "phone", v
    return None


def chain_for_value(value: str) -> str | None:
    """Best-effort chain hint for a wallet / transaction value."""
    if _EVM_ADDRESS.match(value) or _EVM_TX.match(value):
        return "ethereum"
    if _BTC_ADDRESS.match(value):
        return "bitcoin"
    if _TRON_ADDRESS.match(value):
        return "tron"
    return None
