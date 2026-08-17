from __future__ import annotations

from typing import Any

from safenestt.orchestrator import Orchestrator
from safenestt.registry import AgentRecord, agent_registry


class AgencyOrchestrator(Orchestrator):
    def classify(self, payload: dict[str, Any]) -> str:
        if "investigate" in payload.get("intent", ""):
            return "investigation"
        if "build" in payload.get("intent", "") or "code" in payload.get("intent", ""):
            return "engineering"
        if "market" in payload.get("intent", ""):
            return "marketing"
        return "general"
