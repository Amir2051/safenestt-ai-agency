from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from safenestt.registry import AgentRecord, AgentStatus, RiskLevel
from safenestt.security.audit import AuditEvent, AuditLogger, audit
from safenestt.security.redaction import redact


@dataclass
class AuthorizationDecision:
    decision: str
    reason: str
    agent_id: str | None
    tool_id: str | None
    action: str | None
    risk: RiskLevel
    required_permission: str | None
    approval_required: bool
    approval_id: str | None = None


@dataclass
class PermissionManager:
    granted_permissions: dict[str, set[str]] = field(default_factory=dict)
    allowed_permissions: set[str] = field(default_factory=set)
    audit_logger: AuditLogger = field(default_factory=AuditLogger)
    approval_store: dict[str, dict[str, Any]] = field(default_factory=dict)

    def grant(self, subject_id: str, permissions: list[str]) -> None:
        raise PermissionError("grant is not supported in M1.4")

    def revoke(self, subject_id: str, permissions: list[str]) -> None:
        raise PermissionError("revoke is not supported in M1.4")

    def _emit(self, event: AuditEvent) -> None:
        self.audit_logger.record(AuditEvent(**redact(event.__dict__)))

    def _parse_capability(self, capability: str) -> tuple[str, str | None]:
        if not isinstance(capability, str) or not capability.strip():
            return "", None
        if capability.startswith("tools."):
            parts = capability.split(".", 2)
            if len(parts) != 3 or not parts[1] or not parts[2]:
                return capability, None
            return capability, f"tools.{parts[1]}.{parts[2]}"
        return capability, capability

    def _load_agent(self, agent: AgentRecord | None) -> tuple[AgentRecord | None, str | None, bool]:
        if agent is None:
            return None, None, True
        agent_id = getattr(agent, "agent_id", None)
        enabled = bool(getattr(agent, "enabled", False))
        status = getattr(agent, "status", None)
        active = enabled and (status is None or getattr(status, "value", str(status)) == AgentStatus.ACTIVE.value)
        return agent, agent_id, active

    def authorize(self, agent: AgentRecord | None, capability: str) -> AuthorizationDecision:
        loaded_agent, agent_id, active = self._load_agent(agent)
        tool_id, required_permission = self._parse_capability(capability)

        if loaded_agent is None or agent_id is None:
            decision = AuthorizationDecision(
                decision="DENY",
                reason="missing_agent",
                agent_id=None,
                tool_id=tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=required_permission,
                approval_required=False,
            )
            self._emit(AuditEvent(event_id="auth-deny", actor_type="system", actor_id=None, action=capability, decision="DENY", risk_level=RiskLevel.LOW, detail="missing_agent"))
            return decision

        if not active:
            decision = AuthorizationDecision(
                decision="DENY",
                reason="agent_inactive",
                agent_id=agent_id,
                tool_id=tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=required_permission,
                approval_required=False,
            )
            self._emit(AuditEvent(event_id="auth-deny", actor_type="agent", actor_id=agent_id, action=capability, decision="DENY", risk_level=RiskLevel.LOW, detail="agent_inactive"))
            return decision

        if required_permission is None:
            decision = AuthorizationDecision(
                decision="DENY",
                reason="invalid_capability",
                agent_id=agent_id,
                tool_id=tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=None,
                approval_required=False,
            )
            self._emit(AuditEvent(event_id="auth-deny", actor_type="agent", actor_id=agent_id, action=capability, decision="DENY", risk_level=RiskLevel.LOW, detail="invalid_capability"))
            return decision

        granted = self.granted_permissions.get(agent_id, set())
        allowed = required_permission in granted or "*" in granted
        if not allowed:
            decision = AuthorizationDecision(
                decision="DENY",
                reason="missing_permission",
                agent_id=agent_id,
                tool_id=tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=required_permission,
                approval_required=False,
            )
            self._emit(AuditEvent(event_id="auth-deny", actor_type="agent", actor_id=agent_id, action=capability, decision="DENY", risk_level=RiskLevel.LOW, detail="missing_permission", metadata={"required_permission": required_permission}))
            return decision

        risk = getattr(agent, "risk_level", RiskLevel.LOW)
        if not isinstance(risk, RiskLevel):
            try:
                risk = RiskLevel[str(risk)]
            except Exception:
                risk = RiskLevel.LOW

        requires_approval = risk in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
        approval_id = None
        if requires_approval:
            approval_id = f"approval-{agent_id}-{required_permission}"
            explicit = self.approval_store.get(approval_id)
            if not explicit or not explicit.get("approved"):
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason="approval_required",
                    agent_id=agent_id,
                    tool_id=tool_id,
                    action=capability,
                    risk=risk,
                    required_permission=required_permission,
                    approval_required=True,
                    approval_id=approval_id,
                )
                self._emit(AuditEvent(event_id="auth-approval-required", actor_type="agent", actor_id=agent_id, action=capability, decision="DENY", risk_level=risk, detail="approval_required", metadata={"approval_id": approval_id, "required_permission": required_permission}))
                return decision

            approval_id = explicit.get("approval_id") or approval_id

        decision = AuthorizationDecision(
            decision="ALLOW",
            reason="authorized",
            agent_id=agent_id,
            tool_id=tool_id,
            action=capability,
            risk=risk,
            required_permission=required_permission,
            approval_required=requires_approval,
            approval_id=approval_id,
        )
        self._emit(AuditEvent(event_id="auth-allow", actor_type="agent", actor_id=agent_id, action=capability, decision="ALLOW", risk_level=risk, detail="authorized", metadata={"required_permission": required_permission, "approval_required": requires_approval}))
        return decision

    def evaluate_execution(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> AuthorizationDecision:
        return self.authorize(agent, capability)

    def record_approval(self, approval_id: str, approved: bool, metadata: dict[str, Any] | None = None) -> None:
        self.approval_store[approval_id] = {
            "approval_id": approval_id,
            "approved": bool(approved),
            "metadata": metadata or {},
        }


permission_manager = PermissionManager()
