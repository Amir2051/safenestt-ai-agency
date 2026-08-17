from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from safenestt.registry import AgentRecord, RiskLevel
from safenestt.security.audit import AuditEvent, audit
from safenestt.security.redaction import redact


@dataclass
class PermissionDecision:
    allowed: bool
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False


@dataclass
class PermissionManager:
    granted_permissions: dict[str, set[str]] = field(default_factory=dict)
    allowed_permissions: set[str] = field(default_factory=set)

    def grant(self, subject_id: str, permissions: list[str]) -> None:
        if not self.allowed_permissions:
            self.granted_permissions.setdefault(subject_id, set()).update(permissions)
            return
        allowed = {perm for perm in permissions if perm in self.allowed_permissions}
        self.granted_permissions.setdefault(subject_id, set()).update(allowed)

    def authorize(self, agent: AgentRecord | None, capability: str) -> PermissionDecision:
        if agent is None:
            return PermissionDecision(allowed=False, reason="missing_agent", risk_level=RiskLevel.LOW)
        agent_perms = self.granted_permissions.get(agent.agent_id, set())
        if capability not in agent_perms and "*" not in agent_perms:
            return PermissionDecision(allowed=False, reason="missing_permission", risk_level=RiskLevel.LOW)
        return PermissionDecision(allowed=True, reason="authorized", risk_level=agent.risk_level)

    def evaluate_execution(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> PermissionDecision:
        decision = self.authorize(agent, capability)
        if not decision.allowed:
            audit.record(AuditEvent(event_id="permission-deny", actor_type="agent", actor_id=agent.agent_id if agent else None, action=capability, decision="DENY", risk_level=decision.risk_level, detail=decision.reason))
            return decision
        if decision.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
            decision.requires_approval = True
            audit.record(AuditEvent(event_id="approval-required", actor_type="agent", actor_id=agent.agent_id if agent else None, action=capability, decision="REQUIRE_APPROVAL", risk_level=decision.risk_level, detail="approval_required"))
            return decision
        audit.record(AuditEvent(event_id="permission-allow", actor_type="agent", actor_id=agent.agent_id if agent else None, action=capability, decision="ALLOW", risk_level=decision.risk_level))
        return decision


permission_manager = PermissionManager()
