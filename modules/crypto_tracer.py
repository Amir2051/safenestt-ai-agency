"""
Etherscan API adapter + crypto tracer module for SafeNestT blockchain intelligence.

Credential: ETHERSCAN_API_KEY

Etherscan API: https://api.etherscan.io/api

Supports Ethereum blockchain data:
- trace_wallet: wallet balance + transaction history

This module CREATES the missing `modules.crypto_tracer` contract that
CryptoAgent depends on. The existing CyberIntelCryptoAdapter imports:

    module = __import__("modules.crypto_tracer", fromlist=["trace_wallet"])
    fn = getattr(module, "trace_wallet", None)
    result = fn(address, chain)

This module provides exactly that contract.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from safenestt.tools.adapters.provider_base import (
    HttpClient,
    ProviderError,
    ProviderAuthFailed,
    ProviderNotFound,
    ProviderRateLimited,
    ProviderMalformedResponse,
    RequestSpec,
)

logger = logging.getLogger(__name__)

ETHERSCAN_BASE = "https://api.etherscan.io/api"


def trace_wallet(address: str, chain: str = "eth") -> dict[str, Any]:
    """Trace a crypto wallet address.

    This is the function that CryptoAgent's CyberIntelCryptoAdapter calls.
    Provides wallet balance and transaction history for supported chains.

    Args:
        address: Wallet address (0x-prefixed hex for ETH)
        chain: Blockchain identifier (eth, btc, bnb, tron)

    Returns:
        dict with status, data (wallet info + transactions), or error
    """
    if chain.lower() == "eth":
        return _trace_eth_wallet(address)
    else:
        return {
            "status": "not_implemented",
            "data": {},
            "error": f"Chain '{chain}' not supported. Only 'eth' is currently available.",
            "supported_chains": ["eth"],
        }


def _trace_eth_wallet(address: str) -> dict[str, Any]:
    """Trace an Ethereum wallet via Etherscan API."""
    credential = _get_etherscan_key()
    if not credential:
        return {
            "status": "provider_not_configured",
            "data": {},
            "error": "Missing credential: ETHERSCAN_API_KEY",
            "supported_chains": ["eth"],
        }

    http = HttpClient(default_timeout=15.0, max_response_bytes=5 * 1024 * 1024)

    # Normalize address
    address = address.lower().strip()
    if not address.startswith("0x"):
        address = "0x" + address

    # Fetch balance + transactions in parallel via sequential calls
    try:
        balance_result = _fetch_etherscan(http, credential, "account", "balance", address)
        normal_tx_result = _fetch_etherscan(http, credential, "account", "txlist", address)
        token_tx_result = _fetch_etherscan(http, credential, "account", "tokentx", address)
    except ProviderError as exc:
        return {
            "status": exc.code,
            "data": {},
            "error": exc.message,
            "supported_chains": ["eth"],
        }

    # Parse balance
    balance = 0.0
    if balance_result.get("status") == "1":
        result_data = balance_result.get("result", "0")
        try:
            balance = int(result_data) / 1e18  # wei to ETH
        except (ValueError, TypeError):
            pass

    # Parse transactions
    transactions = _parse_txlist(normal_tx_result.get("result", []))
    token_transactions = _parse_txlist(token_tx_result.get("result", []))

    return {
        "status": "success" if balance is not None or transactions or token_transactions else "no_data",
        "data": {
            "address": address,
            "chain": "eth",
            "balance_eth": balance,
            "balance_wei": balance_result.get("result", "0") if balance_result.get("status") == "1" else "0",
            "transactions": transactions,
            "token_transactions": token_transactions,
            "transaction_count": len(transactions),
            "token_transaction_count": len(token_transactions),
            "source": "etherscan_api",
            "provider": "etherscan",
        },
        "error": None,
        "supported_chains": ["eth"],
    }


def _fetch_etherscan(http, api_key, module, action, address):
    """Make a single Etherscan API call."""
    params = {
        "module": module,
        "action": action,
        "address": address,
        "apikey": api_key,
    }
    url = f"{ETHERSCAN_BASE}?{urlencode(params)}"
    spec = RequestSpec(method="GET", url=url, timeout=15.0)
    resp = http.request(spec)

    if resp.status != 200:
        body = resp.body
        if resp.status == 401:
            raise ProviderAuthFailed(code="auth_failed", message="Etherscan: invalid API key", action="")
        if resp.status == 429:
            raise ProviderRateLimited(code="rate_limited", message="Etherscan rate limit exceeded", action="")
        try:
            data = json.loads(body)
            message = data.get("message", "Unknown error")
        except Exception:
            message = body[:200]
        raise ProviderError(code="provider_error", message=f"Etherscan error: {message}", action="")

    return json.loads(resp.body)


def _parse_txlist(tx_list):
    """Parse Etherscan transaction list into normalized format."""
    if not tx_list or not isinstance(tx_list, list):
        return []
    if isinstance(tx_list, dict) and tx_list.get("message") == "No transactions found":
        return []

    result = []
    for tx in tx_list[:100]:  # limit to 100 most recent
        if not isinstance(tx, dict):
            continue
        # Etherscan tx fields vary; extract common ones
        result.append({
            "hash": tx.get("hash", ""),
            "nonce": tx.get("nonce"),
            "block_hash": tx.get("blockHash", ""),
            "block_number": tx.get("blockNumber"),
            "transaction_index": tx.get("transactionIndex"),
            "from_address": tx.get("from", tx.get("from", "")),
            "to_address": tx.get("to", tx.get("to", "")),
            "value_wei": tx.get("value", "0"),
            "value_eth": _wei_to_eth(tx.get("value", "0")),
            "gas_used": tx.get("gasUsed"),
            "gas_price_wei": tx.get("gasPrice", "0"),
            "gas_price_gwei": _wei_to_gwei(tx.get("gasPrice", "0")),
            "transaction_fee_wei": tx.get("transactionFee", tx.get("gasUsed", "0")),
            "input_data": tx.get("input", "")[:500],
            "contract_address": tx.get("contractAddress", ""),
            "status": tx.get("isError", "0") == "0" and "success" or "failed",
            "timestamp": tx.get("timeStamp"),
        })
    return result


def _wei_to_eth(wei_value):
    try:
        return int(wei_value) / 1e18
    except (ValueError, TypeError):
        return 0.0

def _wei_to_gwei(wei_value):
    try:
        return int(wei_value) / 1e9
    except (ValueError, TypeError):
        return 0.0

def _get_etherscan_key():
    """Resolve Etherscan API key from secrets manager."""
    try:
        from safenestt.security.secrets import get_secret
        return get_secret("ETHERSCAN_API_KEY")
    except Exception:
        return None


# Also provide a direct HTTP adapter class for the ToolAdapter pattern
# (used if we want to wire Etherscan as a ToolAdapter in the future)

from safenestt.schemas.tools import ToolCapability
from safenestt.tools.adapters.base import ToolAdapter

class EtherscanAdapter(ToolAdapter):
    """Etherscan API adapter following the existing ToolAdapter pattern.

    This is an alternative to the trace_wallet() function above.
    The CryptoAgent currently uses the function-based approach.
    """

    provider_name = "etherscan"
    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.etherscan",
            name="Etherscan",
            description="Query Etherscan for Ethereum blockchain data.",
            provider="etherscan",
            actions=["trace_wallet"],
            input_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "ETH wallet address"},
                    "chain": {"type": "string", "enum": ["eth"], "default": "eth"},
                },
                "required": ["address"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read", "crypto.read"],
            auth_requirement="env",
            error_behavior="record_and_continue",
            provenance=True,
            timeout_seconds=15.0,
            retry_max=2,
        ),
    ]

    def execute(self, agent, capability, payload):
        action = capability.split(".")[-1] if "." in capability else capability
        # Accept both "trace_wallet" (capability name) and "wallet_trace" (orchestrator routing)
        if action not in ("trace_wallet", "wallet_trace"):
            return self._fail("cyber_intel.etherscan", action, "unsupported_action")

        address = str(payload.get("address", "")).strip()
        chain = str(payload.get("chain", "eth")).strip().lower()

        if chain != "eth":
            return self._fail("cyber_intel.etherscan", action, "not_implemented", {
                "detail": f"Chain '{chain}' not supported. Only 'eth'.",
            })

        # Use the trace_wallet function
        result = trace_wallet(address, chain)
        status = result.get("status", "error")
        data = result.get("data", {})
        error = result.get("error")

        if status == "success" or status == "no_data":
            safe_data = dict(data)
            safe_data.pop("raw", None)
            # Attach target so the orchestrator finding generator has a meaningful
            # address in the title without inventing values or duplicating logic.
            safe_data.setdefault("target", address)
            # Derive confidence from the wallet balance/activity. Zero balance and
            # zero transactions → 0.0; non-trivial balance → up to 0.95.
            existing_conf = safe_data.get("confidence")
            if existing_conf is not None:
                safe_data["confidence"] = float(existing_conf)
            elif status == "success" and isinstance(safe_data.get("balance_eth"), (int, float)) and safe_data["balance_eth"] > 0:
                safe_data["confidence"] = min(0.95, 0.3 + min(safe_data["balance_eth"], 100.0) * 0.006)
            else:
                safe_data["confidence"] = 0.0
            return self._ok("cyber_intel.etherscan", action, safe_data, {
                "provider": "etherscan",
                "source": "etherscan_api",
                "chain": chain,
                "collected_at": datetime.utcnow().isoformat(),
            })
        else:
            return self._fail("cyber_intel.etherscan", action, status or "error", {
                "detail": error,
            })

    @staticmethod
    def _ok(tool_id, action, data, metadata=None):
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "success",
            "data": data,
            "metadata": metadata or {},
            "warnings": [],
            "error": None,
        }

    @staticmethod
    def _fail(tool_id, action, error, metadata=None):
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "error",
            "data": {},
            "metadata": metadata or {},
            "warnings": [],
            "error": error,
        }
