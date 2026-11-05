"""Classify a raw investigation target into the indicator type it actually is.

Base44 sends a bare target string (often a crypto wallet). It used to be filed
as ``{"domain": target}`` unconditionally, so wallet cases ran DNS / Shodan /
WHOIS lookups that cannot resolve a wallet, and never reached the crypto lane
(CryptoAgent + Etherscan trace). The value's own shape decides the type here.

Keys returned match what the orchestrator routes on: wallet_address,
transaction_hash, email, ip_address, domain, phone, username.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

_EVM_ADDRESS = re.compile(r"^0[xX][a-fA-F0-9]{40}$")
_EVM_TX = re.compile(r"^0[xX][a-fA-F0-9]{64}$")
_BTC_ADDRESS = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_TRON_ADDRESS = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_BARE_TX = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL = re.compile(r"^[^\s@/:]+@[^\s@/:]+\.[^\s@/:]+$")
_HOST = re.compile(r"^([a-z0-9-]+\.)+([a-z]{2,}|xn--[a-z0-9-]+)$")
_PHONE = re.compile(r"^\+?[\d\s().-]{7,24}$")
_PHONE_EXT = re.compile(r"\s*(ext\.?|extension|x)\s*\d{1,6}$", re.IGNORECASE)
_DATE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$|^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$")
_URI_SCHEME_WALLET = re.compile(r"^(ethereum|bitcoin|tron):(?P<addr>[^?@/]+)", re.IGNORECASE)

# Profile / messaging hosts: the account is in the path, the host is the platform.
_SOCIAL_HOSTS = {
    "instagram.com", "tiktok.com", "facebook.com", "fb.com", "m.facebook.com", "x.com",
    "twitter.com", "threads.net", "linkedin.com", "youtube.com", "t.me", "telegram.me",
    "wa.me", "snapchat.com", "reddit.com", "pinterest.com", "github.com", "discord.gg",
    "discord.com", "medium.com", "linktr.ee",
}
# Block-explorer hosts: the wallet / tx is in the path.
_EXPLORER_HINT = re.compile(r"(scan|explorer|blockchain|blockchair|mempool|tronscan)", re.IGNORECASE)
# Not DNS-resolvable "domains" (ENS etc.).
_NON_DNS_TLDS = {"eth", "crypto", "nft", "wallet", "x", "bnb", "sol"}


def _wallet_or_tx(v: str) -> tuple[str, str] | None:
    if _EVM_ADDRESS.match(v):
        return "wallet_address", "0x" + v[2:]
    if _EVM_TX.match(v):
        return "transaction_hash", "0x" + v[2:]
    if _BTC_ADDRESS.match(v) or (v.isupper() and v.lower().startswith("bc1") and _BTC_ADDRESS.match(v.lower())):
        return "wallet_address", v.lower() if v.lower().startswith("bc1") else v
    if _TRON_ADDRESS.match(v):
        return "wallet_address", v
    if _BARE_TX.match(v):
        return "transaction_hash", v.lower()
    return None


def _ip(v: str) -> str | None:
    try:
        return str(ipaddress.ip_address(v.strip("[]")))
    except ValueError:
        return None


def _phone(v: str) -> str | None:
    core = _PHONE_EXT.sub("", v).strip()
    if _DATE.match(core) or not _PHONE.match(core):
        return None
    digits = sum(ch.isdigit() for ch in core)
    formatted = any(ch in core for ch in "+ ()-")
    # Bare digit runs are only phones when long enough to be a full number.
    if digits < 7 or (not formatted and digits < 10):
        return None
    return v


def _from_url(v: str) -> tuple[str, str] | None:
    raw = v if "://" in v else f"http://{v}"
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    path_parts = [unquote(p) for p in parsed.path.split("/") if p]
    # A wallet / tx pasted as an explorer (or any) link: classify what's in the path.
    if _EXPLORER_HINT.search(host) or any(_wallet_or_tx(p) for p in path_parts):
        for part in reversed(path_parts):
            hit = _wallet_or_tx(part)
            if hit:
                return hit
    ip = _ip(host)
    if ip:
        return "ip_address", ip
    if host.startswith("www."):
        host = host[4:]
    if host in _SOCIAL_HOSTS:
        handle = next((p.lstrip("@") for p in path_parts if p.lstrip("@") and p not in {"in", "user", "u", "channel", "c", "profile.php"}), "")
        # The platform's own domain says nothing about the suspect; keep the account.
        return ("username", handle) if handle else None
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if ascii_host.rsplit(".", 1)[-1] in _NON_DNS_TLDS:
        return None
    if _HOST.match(ascii_host):
        return "domain", ascii_host
    return None


def classify_indicator(value: object) -> tuple[str, str] | None:
    """Return ``(indicator_key, normalized_value)`` or ``None`` for unusable input."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    hit = _wallet_or_tx(v)
    if hit:
        return hit
    m = _URI_SCHEME_WALLET.match(v)
    if m:
        return _wallet_or_tx(m.group("addr"))
    ip = _ip(v)
    if ip:
        return "ip_address", ip
    # URLs before emails: "tiktok.com/@scam.er" and "https://user@host/" are not emails.
    if "/" not in v and _EMAIL.match(v):
        return "email", v.lower()
    if " " not in v and ("." in v or "/" in v):
        hit = _from_url(v)
        if hit:
            return hit
    phone = _phone(v)
    if phone:
        return "phone", phone
    return None


def chain_for_value(value: str) -> str | None:
    """Chain hint in the crypto adapter's vocabulary ("eth", "btc", "tron").

    ``None`` when the shape doesn't say (e.g. a bare 64-hex hash): callers keep
    their default.
    """
    v = (value or "").strip()
    if _EVM_ADDRESS.match(v) or _EVM_TX.match(v):
        return "eth"
    if _BTC_ADDRESS.match(v) or _BTC_ADDRESS.match(v.lower()):
        return "btc"
    if _TRON_ADDRESS.match(v):
        return "tron"
    return None
