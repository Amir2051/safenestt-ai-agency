from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from safenestt.registry import AgentRecord, RiskLevel
from safenestt.security.approval import ApprovalService, InMemoryApprovalRepository
from safenestt.security.audit import AuditEvent
from safenestt.persistence.store import PersistentAuditLogger
from safenestt.security.permissions import AuthorizationDecision, PermissionManager
from safenestt.security.rate_limit import RateLimitService


@dataclass
class PipelineDecision:
    decision: str
    reason: str
    requires_approval: bool
    rate_limited: bool
    redacted_metadata: dict[str, Any]


class SecurityPipeline:
    def __init__(
        self,
        permission_manager: PermissionManager | None = None,
        approval_service: ApprovalService | None = None,
        rate_limit_service: RateLimitService | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        self.permission_manager = permission_manager or PermissionManager()
        self.approval_service = approval_service or ApprovalService(InMemoryApprovalRepository())
        self.rate_limit_service = rate_limit_service or RateLimitService()
        self.audit_logger = audit_logger or PersistentAuditLogger()

    def authorize(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any] | None = None, *, organization_id: str | None = None, tool_id: str | None = None, provider: str | None = None, model: str | None = None) -> PipelineDecision:
        rate_key = f"{getattr(agent, 'agent_id', 'unknown')}:{capability}"
        rate = self.rate_limit_service.enforce("tool", rate_key)
        if not rate.allowed:
            self.audit_logger.record(
                AuditEvent(
                    event_id=f"rate-deny-{rate_key}",
                    actor_type="system",
                    actor_id=getattr(agent, "agent_id", None),
                    action=capability,
                    decision="DENY",
                    risk_level=RiskLevel.LOW,
                    detail="rate_limit_exceeded",
                    metadata={"scope": rate.scope, "limit": rate.limit, "reset_at": rate.reset_at},
                )
            )
            return PipelineDecision(decision="DENY", reason="rate_limit_exceeded", requires_approval=False, rate_limited=True, redacted_metadata={"scope": rate.scope, "limit": rate.limit, "reset_at": rate.reset_at})

        auth = self.permission_manager.authorize(agent, capability)
        if auth.decision != "ALLOW":
            self.audit_logger.record(
                AuditEvent(
                    event_id=f"auth-deny-{getattr(agent, 'agent_id', 'unknown')}-{capability}",
                    actor_type="agent",
                    actor_id=auth.agent_id,
                    action=capability,
                    decision="DENY",
                    risk_level=auth.risk,
                    resource_type="tool",
                    resource_id=tool_id or auth.tool_id,
                    detail=auth.reason,
                    metadata={"approval_id": auth.approval_id},
                )
            )
            return PipelineDecision(decision="DENY", reason=auth.reason, requires_approval=auth.approval_required, rate_limited=False, redacted_metadata={"approval_id": auth.approval_id})

        if auth.approval_required and auth.approval_id:
            if not self.approval_service.is_approved(auth.approval_id, organization_id=organization_id):
                self.audit_logger.record(
                    AuditEvent(
                        event_id=f"approval-required-{auth.approval_id}",
                        actor_type="agent",
                        actor_id=auth.agent_id,
                        action=capability,
                        decision="DENY",
                        risk_level=auth.risk,
                        resource_type="tool",
                        resource_id=auth.tool_id,
                        detail="approval_required",
                        metadata={"approval_id": auth.approval_id, "required_permission": auth.required_permission},
                    )
                )
                return PipelineDecision(decision="DENY", reason="approval_required", requires_approval=True, rate_limited=False, redacted_metadata={"approval_id": auth.approval_id, "required_permission": auth.required_permission})

        return PipelineDecision(decision="ALLOW", reason="authorized", requires_approval=auth.approval_required, rate_limited=False, redacted_metadata={"approval_id": auth.approval_id})

    def record_model_event(self, provider: str, model: str, action: str, decision: str, *, organization_id: str | None = None, result_status: str | None = None, metadata: dict[str, Any] | None = None) -> AuditEvent:
        event = AuditEvent(
            event_id=f"model-{action}-{datetime.utcnow().timestamp()}",
            actor_type="model",
            actor_id=model,
            action=action,
            decision=decision,
            risk_level=RiskLevel.LOW,
            resource_type="model",
            resource_id=model,
            metadata=metadata or {},
            approval_id=None,
        )
        event.provider = provider
        event.model = model
        event.result_status = result_status
        self.audit_logger.record(event)
        return event
