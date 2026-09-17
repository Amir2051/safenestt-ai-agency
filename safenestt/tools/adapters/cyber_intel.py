from __future__ import annotations

import importlib
import sys
from typing import Any

from safenestt.schemas.tools import ToolCapability, ToolInput, ToolOutput
from safenestt.tools.adapters.base import ToolAdapter


class CyberIntelOSINTAdapter(ToolAdapter):
    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.osint_profile",
            name="OSINT Profile",
            description="Profile an indicator: email, domain, IP, username, or phone.",
            provider="cyber_intel",
            actions=["email", "domain", "ip", "username", "phone"],
            input_schema={"type": "object", "properties": {"query": {"type": "string"}, "query_type": {"type": "string"}}},
            output_schema={"type": "object"},
            required_permissions=["intel.read"],
            auth_requirement="env",
        ),
        ToolCapability(
            tool_id="cyber_intel.reputation_score",
            name="Reputation Score",
            description="Score reputation for an email or phone number.",
            provider="cyber_intel",
            actions=["email", "phone"],
            input_schema={"type": "object", "properties": {"value": {"type": "string"}, "value_type": {"type": "string"}}},
            output_schema={"type": "object"},
            required_permissions=["intel.read"],
            auth_requirement="env",
        ),
    ]

    def __init__(self, module_path: str = "modules.osint_profiler") -> None:
        self._module_path = module_path
        self._module = self._load()

    def _load(self):
        try:
            return importlib.import_module(self._module_path)
        except Exception as exc:  # pragma: no cover - adapter hardening
            raise RuntimeError(f"Failed to load cyber-intel module {self._module_path}: {exc}") from exc

    def execute(self, agent: Any, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        tool_id = "cyber_intel.osint_profile"
        if capability == "cyber_intel.reputation_score.email":
            action = "email"
            fn = getattr(self._module, "score_reputation", None)
            if fn is None:
                return self._fail(tool_id, action, "score_reputation not available")
            try:
                result = self._run_sync(fn(payload["value"], "email"))
            except Exception as exc:
                return self._fail(tool_id, action, str(exc))
            return self._ok(tool_id, action, self._normalize_reputation(result), self._provenance(payload))

        if capability == "cyber_intel.reputation_score.phone":
            action = "phone"
            fn = getattr(self._module, "score_reputation", None)
            if fn is None:
                return self._fail(tool_id, action, "score_reputation not available")
            try:
                result = self._run_sync(fn(payload["value"], "phone"))
            except Exception as exc:
                return self._fail(tool_id, action, str(exc))
            return self._ok(tool_id, action, self._normalize_reputation(result), self._provenance(payload))

        if capability.startswith("cyber_intel.osint_profile."):
            action = capability.split(".", 2)[2]
        else:
            return self._fail(tool_id, capability, "Unsupported capability")

        fn = getattr(self._module, "run_osint_profile", None)
        if fn is None:
            return self._fail(tool_id, action, "run_osint_profile not available")
        try:
            result = self._run_sync(fn(payload["query"], action))
        except Exception as exc:
            return self._fail(tool_id, action, str(exc))
        return self._ok(tool_id, action, self._normalize_profile(result), self._provenance(payload))

    @staticmethod
    def _run_sync(coro):
        if callable(coro):
            return coro()
        return coro

    @staticmethod
    def _provenance(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "case_id": payload.get("case_id"),
            "investigation_id": payload.get("investigation_id"),
            "agent_id": payload.get("agent_id"),
            "agent_run_id": payload.get("agent_run_id"),
        }

    @staticmethod
    def _normalize_profile(result: dict[str, Any]) -> dict[str, Any]:
        return {
            "query": result.get("query"),
            "query_type": result.get("query_type"),
            "timestamp": result.get("timestamp"),
            "sources": result.get("sources") or [],
            "risk_score": result.get("risk_score"),
            "findings": result.get("findings") or {},
            "limitations": ["OSINT results are public-source signals, not verified legal facts."],
        }

    @staticmethod
    def _normalize_reputation(result: dict[str, Any]) -> dict[str, Any]:
        return {
            "value": result.get("value"),
            "type": result.get("type"),
            "timestamp": result.get("timestamp"),
            "risk_score": result.get("risk_score"),
            "risk_level": result.get("risk_level"),
            "signals": result.get("signals") or [],
            "summary": result.get("summary") or {},
            "limitations": ["Reputation scoring reflects external API signals and heuristics only."],
        }
