"""Regression: a target is routed by what it is. A wallet must reach the crypto
lane, never domain lookups; social / explorer links and odd formats must not be
mis-keyed or silently dropped."""
import json

import pytest

from safenestt.investigations.indicators import chain_for_value, classify_indicator
from safenestt.investigations.investigator import _case_context, _chain_hint

WALLET = "0x56810093085DA36d91e49ED0dE77Bf71110320DB"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
TRON = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"


@pytest.mark.parametrize(
    "raw, expected",
    [
        (WALLET, ("wallet_address", WALLET)),
        ("0X56810093085DA36d91e49ED0dE77Bf71110320DB", ("wallet_address", WALLET)),
        (BTC, ("wallet_address", BTC)),
        (BTC.upper(), ("wallet_address", BTC)),
        (TRON, ("wallet_address", TRON)),
        ("0x" + "ab" * 32, ("transaction_hash", "0x" + "ab" * 32)),
        (f"https://etherscan.io/address/{WALLET}", ("wallet_address", WALLET)),
        (f"ethereum:{WALLET}", ("wallet_address", WALLET)),
        ("Scam@Example.COM", ("email", "scam@example.com")),
        ("a+b@x.com", ("email", "a+b@x.com")),
        ("203.0.113.9", ("ip_address", "203.0.113.9")),
        ("2001:db8::1", ("ip_address", "2001:db8::1")),
        ("http://1.2.3.4/login", ("ip_address", "1.2.3.4")),
        ("192.168.1.1:8080", ("ip_address", "192.168.1.1")),
        ("https://www.dmenergy.example/login", ("domain", "dmenergy.example")),
        ("https://user@evil.com/", ("domain", "evil.com")),
        ("münchen.de", ("domain", "xn--mnchen-3ya.de")),
        ("https://www.tiktok.com/@scam.er", ("username", "scam.er")),
        ("instagram.com/someuser", ("username", "someuser")),
        ("t.me/scammer", ("username", "scammer")),
        ("+1 (555) 010-2345", ("phone", "+1 (555) 010-2345")),
        ("(555) 010-2345 ext 12", ("phone", "(555) 010-2345 ext 12")),
        ("vitalik.eth", None),
        ("@scammer123", None),
        ("2024-01-15", None),
        ("12345678", None),
        ("just some words", None),
        ("", None),
        (None, None),
    ],
)
def test_classifies_by_shape(raw, expected):
    assert classify_indicator(raw) == expected


def test_chain_hint_uses_adapter_vocabulary():
    assert chain_for_value(WALLET) == "eth"
    assert chain_for_value(BTC) == "btc"
    assert chain_for_value(TRON) == "tron"
    assert chain_for_value("ab" * 32) is None  # ambiguous: keep the caller's default
    assert _chain_hint({"wallet_address": BTC}) == "btc"
    assert _chain_hint({"domain": "x.example"}) is None


def test_bare_wallet_target_is_not_a_domain():
    _, indicators, _ = _case_context(WALLET)
    assert indicators == {"wallet_address": WALLET}


def test_bare_domain_target_still_works():
    _, indicators, _ = _case_context("https://dmenergy.example")
    assert indicators == {"domain": "dmenergy.example"}


def test_free_text_target_has_no_fake_indicator():
    _, indicators, _ = _case_context("victim lost funds to an investment scam")
    assert indicators == {}


def test_case_json_website_field_is_classified():
    case = {"description": "case", "intake": {"subjects": [{"website_social_media": WALLET}]}}
    _, indicators, _ = _case_context(json.dumps(case))
    assert indicators == {"wallet_address": WALLET}


def test_case_json_keeps_values_the_classifier_cannot_place():
    # Before the classifier these were passed through raw; they must not be lost.
    case = {"intake": {"subjects": [{"ip_address": "2001:db8::1", "phone": "1-800-FLOWERS",
                                     "website_social_media": "https://www.tiktok.com/@scam.er"}]}}
    _, indicators, _ = _case_context(json.dumps(case))
    assert indicators["ip_address"] == "2001:db8::1"
    assert indicators["phone"] == "1-800-FLOWERS"
    assert indicators["username"] == "scam.er"
    assert "email" not in indicators
