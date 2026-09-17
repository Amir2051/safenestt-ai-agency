from __future__ import annotations

from typing import Any

from safenestt.schemas.tools import ToolCapability, ToolInput, ToolOutput
from safenestt.tools.adapters.base import ToolAdapter


class CyberIntelCryptoAdapter(ToolAdapter):
    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.crypto_trace",
            name="Crypto Tracer",
            description="Trace wallet activity for ETH, BTC, BNB, or TRON.",
            provider="cyber_intel",
            actions=["trace_wallet"],
            input_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "chain": {"type": "string", "enum": ["eth", "btc", "bnb", "tron"]},
                },
                "required": ["address"],
            },
            output_schema={"type": "object"},
            required_permissions=["intel.read", "crypto.read"],
            auth_requirement="env",
        ),
    ]

    def execute(self, agent: Any, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        action = capability.split(".", 2)[2] if "." in capability else capability
        if action != "trace_wallet":
            return self._fail("cyber_intel.crypto_trace", action, f"Unsupported action: {action}")

        try:
            module = __import__("modules.crypto_tracer", fromlist=["trace_wallet"])
        except Exception as exc:
            return self._fail("cyber_intel.crypto_trace", action, f"Import failed: {exc}")

        fn = getattr(module, "trace_wallet", None)
        if not fn:
            return self._fail("cyber_intel.crypto_trace", action, "trace_wallet not available")

        address = str(payload.get("address", "")).strip()
        chain = str(payload.get("chain", "eth")).strip().lower()
        if not address:
            return self._fail("cyber_intel.crypto_trace", action, "Missing address")

        try:
            result = self._run_sync(fn(address, chain))
        except Exception as exc:
            return self._fail("cyber_intel.crypto_trace", action, str(exc))

        safe_result = dict(result or {})
        safe_result.pop("raw_response", None)
        return self._ok("cyber_intel.crypto_trace", action, safe_result, self._provenance(payload))

    @staticmethod
    def _run_sync(coro):
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        else:
            return loop.run_until_complete(coro)

    @staticmethod
    def _provenance(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "case_id": payload.get("case_id"),
            "investigation_id": payload.get("investigation_id"),
            "agent_id": payload.get("agent_id"),
            "agent_run_id": payload.get("agent_run_id"),
        }
