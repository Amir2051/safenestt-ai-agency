"""
Minimal deterministic tests for the Etherscan/crypto_tracer module.

Tests the trace_wallet() function contract that CryptoAgent depends on,
plus the EtherscanAdapter ToolAdapter class.

NO live API calls - all HTTP is mocked.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from safenestt.tools.adapters.provider_base import (
    HttpResponse,
    ProviderAuthFailed,
    ProviderRateLimited,
    ProviderError,
)

ETHERSCAN_BASE = "https://api.etherscan.io/api"


def _make_resp(status, body=None):
    if body is None:
        body = '{"status":"1","message":"OK","result":"0"}'
    elif not isinstance(body, str):
        body = json.dumps(body)
    return HttpResponse(status=status, headers={}, body=body, url=ETHERSCAN_BASE)


def _set_cred(key):
    from safenestt.security.secrets import _cache
    _cache["ETHERSCAN_API_KEY"] = key


def _clear_cred():
    from safenestt.security.secrets import _cache
    _cache.pop("ETHERSCAN_API_KEY", None)


# ===================================================================
# trace_wallet() function tests
# ===================================================================


class TestTraceWallet:
    def test_missing_credential_returns_not_configured(self):
        _clear_cred()
        from modules.crypto_tracer import trace_wallet
        # Also guard against environment variable interference:
        # if ETHERSCAN_API_KEY is set in the environment, get_secret would
        # return it even after cache clear. Patch to be certain.
        import os
        orig = os.environ.get("ETHERSCAN_API_KEY")
        if orig is not None:
            os.environ["ETHERSCAN_API_KEY"] = ""
        try:
            result = trace_wallet("0xabc123def456")
        finally:
            if orig is not None:
                os.environ["ETHERSCAN_API_KEY"] = orig
            elif "ETHERSCAN_API_KEY" in os.environ:
                del os.environ["ETHERSCAN_API_KEY"]
        assert result["status"] == "provider_not_configured"
        assert "ETHERSCAN_API_KEY" in result["error"]

    def test_btc_chain_not_implemented(self):
        _set_cred("fake-key")
        from modules.crypto_tracer import trace_wallet
        result = trace_wallet("0xabc123def456", chain="btc")
        assert result["status"] == "not_implemented"
        assert "btc" in result["error"]
        assert result["supported_chains"] == ["eth"]

    def test_eth_wallet_success(self):
        _set_cred("fake-etherscan-key")

        from modules.crypto_tracer import trace_wallet
        from safenestt.tools.adapters.provider_base import HttpClient

        balance_body = {"status": "1", "message": "OK", "result": "1000000000000000000"}
        normal_tx_body = {
            "result": [
                {"hash": "0xabc123", "nonce": "1", "blockNumber": "1000000",
                 "from": "0xFromAddress", "to": "0xToAddress",
                 "value": "1000000000000000000", "gasUsed": "21000",
                 "gasPrice": "1000000000", "isError": "0",
                 "timeStamp": "1690000000", "input": "0x"},
            ]
        }
        token_tx_body = {"result": []}

        with patch("modules.crypto_tracer.HttpClient") as mock_http_cls:
            mock_http = MagicMock()
            mock_http_cls.return_value = mock_http
            mock_http.request.side_effect = [
                _make_resp(200, balance_body),
                _make_resp(200, normal_tx_body),
                _make_resp(200, token_tx_body),
            ]
            result = trace_wallet("0xabc123def456")
        assert result["status"] == "success"
        data = result["data"]
        assert data["address"] == "0xabc123def456"
        assert data["balance_eth"] == pytest.approx(1.0, abs=0.001)
        assert data["transaction_count"] == 1

    def test_eth_wallet_no_data(self):
        """Wallet with 0 balance and no transactions returns success (0.0 is not None)."""
        _set_cred("fake-etherscan-key")

        from modules.crypto_tracer import trace_wallet
        from safenestt.tools.adapters.provider_base import HttpClient

        balance_body = {"status": "0", "message": "OK", "result": "0"}
        empty_tx_body = {"result": []}

        with patch("modules.crypto_tracer.HttpClient") as mock_http_cls:
            mock_http = MagicMock()
            mock_http_cls.return_value = mock_http
            mock_http.request.side_effect = [
                _make_resp(200, balance_body),
                _make_resp(200, empty_tx_body),
                _make_resp(200, empty_tx_body),
            ]
            result = trace_wallet("0x000000000000000000000000")
        assert result["status"] == "success"
        assert result["data"]["transaction_count"] == 0

    def test_eth_wallet_401_auth_failed(self):
        _set_cred("bad-key")

        from modules.crypto_tracer import trace_wallet
        from safenestt.tools.adapters.provider_base import HttpClient

        error_body = {"status": "0", "message": "Invalid API Key"}

        with patch("modules.crypto_tracer.HttpClient") as mock_http_cls:
            mock_http = MagicMock()
            mock_http_cls.return_value = mock_http
            mock_http.request.side_effect = [
                _make_resp(401, error_body),
                _make_resp(200, {"result": []}),
                _make_resp(200, {"result": []}),
            ]
            result = trace_wallet("0xabc123def456")
        assert result["status"] == "auth_failed"
        # Error format: "Etherscan: <message from API>" — matches actual implementation
        assert "invalid" in result["error"].lower()

    def test_eth_wallet_500_provider_error(self):
        """Non-200 responses that aren't 401/429 raise ProviderError."""
        _set_cred("fake-key")

        from modules.crypto_tracer import trace_wallet
        from safenestt.tools.adapters.provider_base import HttpClient

        with patch("modules.crypto_tracer.HttpClient") as mock_http_cls:
            mock_http = MagicMock()
            mock_http_cls.return_value = mock_http
            mock_http.request.side_effect = [
                _make_resp(500, {"message": "Internal error"}),
                _make_resp(200, {"result": []}),
                _make_resp(200, {"result": []}),
            ]
            result = trace_wallet("0xabc123def456")
        assert result["status"] == "provider_error"
        assert "Internal error" in result["error"]

    def test_eth_wallet_truncates_100_transactions(self):
        """Transaction list is capped at 100."""
        _set_cred("fake-etherscan-key")

        from modules.crypto_tracer import trace_wallet
        from safenestt.tools.adapters.provider_base import HttpClient

        balance_body = {"status": "1", "message": "OK", "result": "0"}
        many_txs = {"result": [
            {"hash": f"0xtx{i:064x}", "nonce": str(i), "blockNumber": "1000000",
             "from": "0xFrom", "to": "0xTo", "value": "1", "isError": "0"}
            for i in range(150)
        ]}

        with patch("modules.crypto_tracer.HttpClient") as mock_http_cls:
            mock_http = MagicMock()
            mock_http_cls.return_value = mock_http
            mock_http.request.side_effect = [
                _make_resp(200, balance_body),
                _make_resp(200, many_txs),
                _make_resp(200, {"result": []}),
            ]
            result = trace_wallet("0xabc123def456")
        data = result["data"]
        assert data["transaction_count"] == 100
        assert len(data["transactions"]) == 100

    def test_wei_conversion_helpers(self):
        from modules.crypto_tracer import _wei_to_eth, _wei_to_gwei
        assert _wei_to_eth("1000000000000000000") == pytest.approx(1.0, abs=0.001)
        assert _wei_to_eth("0") == 0.0
        assert _wei_to_gwei("1000000000") == pytest.approx(1.0, abs=0.001)
        assert _wei_to_gwei("0") == 0.0

