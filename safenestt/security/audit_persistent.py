from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.security.redaction import redact


class AuditEventRecord:
    def __init__(
        self,
        event_id: str,
        timestamp: datetime,
        organization_id: str | None,
        actor_type: str,
        actor_id: str | None,
        action: str,
        decision: str,
        risk: str,
        approval_id: str | None,
        provider: str | None,
        model: str | None,
        result_status: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        self.event_id = event_id
        self.timestamp = timestamp
        self.organization_id = organization_id
        self.actor_type = actor_type
        self.actor_id = actor_id
        self.action = action
        self.decision = decision
        self.risk = risk
        self.approval_id = approval_id
        self.provider = provider
        self.model = model
        self.result_status = result_status
        self.metadata = metadata

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "organization_id": self.organization_id,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "action": self.action,
            "decision": self.decision,
            "risk": self.risk,
            "approval_id": self.approval_id,
            "provider": self.provider,
            "model": self.model,
            "result_status": self.result_status,
            "metadata": self.metadata,
        }


class AuditEventBuilder:
    def __init__(self, event_id: str, timestamp: datetime, organization_id: str | None) -> None:
        self.event_id = event_id
        self.timestamp = timestamp
        self.organization_id = organization_id
        self.actor_type: str | None = None
        self.actor_id: str | None = None
        self.action: str | None = None
        self.decision: str | None = None
        self.risk: str | None = None
        self.approval_id: str | None = None
        self.provider: str | None = None
        self.model: str | None = None
        self.result_status: str | None = None
        self.metadata: dict[str, Any] | None = None

    def with_actor(self, actor_type: str, actor_id: str | None) -> "AuditEventBuilder":
        self.actor_type = actor_type
        self.actor_id = actor_id
        return self

    def with_action(self, action: str) -> "AuditEventBuilder":
        self.action = action
        return self

    def with_decision(self, decision: str) -> "AuditEventBuilder":
        self.decision = decision
        return self

    def with_risk(self, risk: str) -> "AuditEventBuilder":
        self.risk = risk
        return self

    def with_approval_id(self, approval_id: str | None) -> "AuditEventBuilder":
        self.approval_id = approval_id
        return self

    def with_provider(self, provider: str | None) -> "AuditEventBuilder":
        self.provider = provider
        return self

    def with_model(self, model: str | None) -> "AuditEventBuilder":
        self.model = model
        return self

    def with_result_status(self, result_status: str | None) -> "AuditEventBuilder":
        self.result_status = result_status
        return self

    def with_metadata(self, metadata: dict[str, Any] | None) -> "AuditEventBuilder":
        self.metadata = redact(metadata or {})
        return self

    def build(self) -> AuditEventRecord:
        return AuditEventRecord(
            event_id=self.event_id,
            timestamp=self.timestamp,
            organization_id=self.organization_id,
            actor_type=self.actor_type or "",
            actor_id=self.actor_id,
            action=self.action or "",
            decision=self.decision or "",
            risk=self.risk or "",
            approval_id=self.approval_id,
            provider=self.provider,
            model=self.model,
            result_status=self.result_status,
            metadata=self.metadata,
        )


class AuditRepository(ABC):
    @abstractmethod
    def append(self, record: AuditEventRecord) -> AuditEventRecord:
        raise NotImplementedError

    @abstractmethod
    def recent(self, *, organization_id: str | None = None, limit: int = 100) -> list[AuditEventRecord]:
        raise NotImplementedError

    @abstractmethod
    def list_by_actor(self, actor_id: str, *, organization_id: str | None = None) -> list[AuditEventRecord]:
        raise NotImplementedError


@dataclass
class InMemoryAuditStore:
    events: list[AuditEventRecord] = field(default_factory=list)

    def append(self, record: AuditEventRecord) -> AuditEventRecord:
        self.events.append(record)
        return record

    def recent(self, limit: int = 100) -> list[AuditEventRecord]:
        return self.events[-limit:]


class InMemoryAuditRepository(AuditRepository):
    def __init__(self, store: InMemoryAuditStore | None = None) -> None:
        self.store = store or InMemoryAuditStore()

    def append(self, record: AuditEventRecord) -> AuditEventRecord:
        return self.store.append(record)

    def _tenant_filter(self, record: AuditEventRecord, organization_id: str | None) -> bool:
        if record.organization_id and organization_id and record.organization_id != organization_id:
            return False
        return True

    def recent(self, *, organization_id: str | None = None, limit: int = 100) -> list[AuditEventRecord]:
        return [record for record in self.store.recent(limit) if self._tenant_filter(record, organization_id)][-limit:]

    def list_by_actor(self, actor_id: str, *, organization_id: str | None = None) -> list[AuditEventRecord]:
        return [record for record in self.store.events if record.actor_id == actor_id and self._tenant_filter(record, organization_id)]


class AuditService:
    def __init__(self, repository: AuditRepository | None = None, clock: Any = None) -> None:
        self.repository = repository or InMemoryAuditRepository()
        self.clock = clock or datetime
        self._seq = 0

    def record(self, organization_id: str | None, **kwargs: Any) -> AuditEventRecord:
        self._seq += 1
        event_id = f"audit-{self._seq:06d}"
        builder = AuditEventBuilder(event_id=event_id, timestamp=self.clock.utcnow(), organization_id=organization_id)
        if "actor_type" in kwargs:
            builder.with_actor(kwargs["actor_type"], kwargs.get("actor_id"))
        if "action" in kwargs:
            builder.with_action(kwargs["action"])
        if "decision" in kwargs:
            builder.with_decision(kwargs["decision"])
        if "risk" in kwargs:
            builder.with_risk(kwargs["risk"])
        if "approval_id" in kwargs:
            builder.with_approval_id(kwargs["approval_id"])
        if "provider" in kwargs:
            builder.with_provider(kwargs["provider"])
        if "model" in kwargs:
            builder.with_model(kwargs["model"])
        if "result_status" in kwargs:
            builder.with_result_status(kwargs["result_status"])
        if "metadata" in kwargs:
            builder.with_metadata(kwargs["metadata"])
        return self.repository.append(builder.build())
