"""Regression: a wallet target must route to the crypto lane, never to domain lookups."""
from safenestt.investigations.indicators import chain_for_value, classify_indicator
from safenestt.investigations.investigator import _case_context

WALLET = "0x56810093085DA36d91e49ED0dE77Bf71110320DB"


def test_classifies_by_shape():
    assert classify_indicator(WALLET) == ("wallet_address", WALLET)
    assert classify_indicator("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")[0] == "wallet_address"
    assert classify_indicator("TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7")[0] == "wallet_address"
    assert classify_indicator("0x" + "ab" * 32)[0] == "transaction_hash"
    assert classify_indicator("Scam@Example.COM") == ("email", "scam@example.com")
    assert classify_indicator("203.0.113.9") == ("ip_address", "203.0.113.9")
    assert classify_indicator("https://www.dmenergy.example/login") == ("domain", "dmenergy.example")
    assert classify_indicator("+1 (555) 010-2345")[0] == "phone"
    assert classify_indicator("") is None
    assert classify_indicator("just some words") is None
    assert classify_indicator(None) is None


def test_chain_hint():
    assert chain_for_value(WALLET) == "ethereum"
    assert chain_for_value("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "bitcoin"
    assert chain_for_value("TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7") == "tron"


def test_bare_wallet_target_is_not_a_domain():
    _, indicators, _ = _case_context(WALLET)
    assert indicators == {"wallet_address": WALLET}
    assert "domain" not in indicators


def test_bare_domain_target_still_works():
    _, indicators, _ = _case_context("https://dmenergy.example")
    assert indicators == {"domain": "dmenergy.example"}


def test_free_text_target_has_no_fake_indicator():
    _, indicators, _ = _case_context("victim lost funds to an investment scam")
    assert indicators == {}


def test_case_json_website_field_is_classified():
    import json
    case = {"description": "case", "intake": {"subjects": [{"website_social_media": WALLET}]}}
    _, indicators, _ = _case_context(json.dumps(case))
    assert indicators.get("wallet_address") == WALLET
    assert "domain" not in indicators
