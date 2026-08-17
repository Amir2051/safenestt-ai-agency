from __future__ import annotations

from typing import Any

from safenestt.registry import AgentRecord, RiskLevel
from safenestt.security.permissions import AuthorizationDecision, PermissionManager


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


class Adapter:
    def execute(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("adapter must not execute denied requests")


class ToolInterface:
    def __init__(self, permission_manager: PermissionManager | None = None, adapter: Adapter | None = None) -> None:
        self.permission_manager = permission_manager or PermissionManager()
        self.adapter = adapter or Adapter()

    def authorize(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any] | None = None) -> AuthorizationDecision:
        return self.permission_manager.authorize(agent, capability)

    def execute(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        decision = self.permission_manager.authorize(agent, capability)
        response = {
            "decision": decision.decision,
            "reason": decision.reason,
            "agent_id": decision.agent_id,
            "tool_id": decision.tool_id,
            "action": decision.action,
            "risk": decision.risk.value,
            "required_permission": decision.required_permission,
            "approval_required": decision.approval_required,
            "approval_id": decision.approval_id,
        }
        if decision.decision != "ALLOW":
            return response
        return response | {"tool_contract": default_tool_contract(), "result": self.adapter.execute(agent, capability, payload)}


tool_interface = ToolInterface()
