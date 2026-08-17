from __future__ import annotations

from typing import Any

from safenestt.registry import AgentRecord, AgentStatus, RiskLevel, agent_registry
from safenestt.security.permissions import PermissionManager


def default_tool_contract() -> dict[str, Any]:
    return {
        "id": "",
        "name": "",
        "category": "external",
        "risk_level": "LOW",
        "required_permissions": [],
        "authentication_required": False,
        "enabled": False,
        "status": "NOT_CONFIGURED",
        "timeout_seconds": 30,
        "retry": {"attempts": 2, "backoff_seconds": 1},
        "rate_limit": {"scope": "agent", "limit": 10, "window_seconds": 60},
    }


class ToolInterface:
    def __init__(self, permission_manager: PermissionManager | None = None) -> None:
        self.permission_manager = permission_manager or PermissionManager()

    def execute(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        decision = self.permission_manager.evaluate_execution(agent, capability, payload)
        if not decision.allowed or decision.requires_approval:
            return {"decision": "DENY" if not decision.allowed else "REQUIRE_APPROVAL", "reason": decision.reason, "risk_level": decision.risk_level.value}
        return {"decision": "ALLOW", "tool_contract": default_tool_contract()}


tool_interface = ToolInterface()
