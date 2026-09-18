from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_APPROVED = "approved"
APPROVAL_STATUS_REJECTED = "rejected"
APPROVAL_STATUS_EXPIRED = "expired"
APPROVAL_STATUS_CANCELLED = "cancelled"


@dataclass
class ApprovalRecord:
    approval_id: str
    agent_id: str
    tool_id: str
    action: str
    requested_capability: str
    risk_level: str
    requester_context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expiration_at: datetime | None = None
    decision_at: datetime | None = None
    approver_identity: str | None = None
    status: str = APPROVAL_STATUS_PENDING
    redacted_metadata: dict[str, Any] = field(default_factory=dict)
    organization_id: str | None = None


class ApprovalRepository(ABC):
    @abstractmethod
    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        raise NotImplementedError

    @abstractmethod
    def get(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        raise NotImplementedError

    @abstractmethod
    def approve(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> ApprovalRecord | None:
        raise NotImplementedError

    @abstractmethod
    def reject(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> ApprovalRecord | None:
        raise NotImplementedError

    @abstractmethod
    def cancel(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        raise NotImplementedError

    @abstractmethod
    def expire(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        raise NotImplementedError

    @abstractmethod
    def list_pending(self, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        raise NotImplementedError

    @abstractmethod
    def list_for_agent(self, agent_id: str, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        raise NotImplementedError

    @abstractmethod
    def list_for_tool(self, tool_id: str, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        raise NotImplementedError


@dataclass
class InMemoryApprovalStore:
    records: dict[str, ApprovalRecord] = field(default_factory=dict)
    next_seq: int = 0

    def next_id(self) -> str:
        self.next_seq += 1
        return f"approval-{self.next_seq:06d}"

    def add(self, record: ApprovalRecord) -> ApprovalRecord:
        self.records[record.approval_id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        return self.records.get(approval_id)


class InMemoryApprovalRepository(ApprovalRepository):
    def __init__(self, store: InMemoryApprovalStore | None = None) -> None:
        self.store = store or InMemoryApprovalStore()

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        existing = self.store.get(record.approval_id)
        if existing:
            raise ValueError("approval already exists")
        return self.store.add(record)

    def _require_tenant(self, record: ApprovalRecord | None, organization_id: str | None) -> ApprovalRecord | None:
        if record is None:
            return None
        if record.organization_id and organization_id and record.organization_id != organization_id:
            return None
        return record

    def get(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        record = self.store.get(approval_id)
        return self._require_tenant(record, organization_id)

    def _transition(self, approval_id: str, status: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        record = self.get(approval_id, organization_id=organization_id)
        if not record or record.status != APPROVAL_STATUS_PENDING:
            return None
        record.status = status
        record.decision_at = datetime.utcnow()
        self.store.add(record)
        return record

    def approve(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> ApprovalRecord | None:
        record = self._transition(approval_id, APPROVAL_STATUS_APPROVED, organization_id=organization_id)
        if not record:
            return None
        record.approver_identity = approver_identity
        record.redacted_metadata.update(metadata or {})
        return record

    def reject(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> ApprovalRecord | None:
        record = self._transition(approval_id, APPROVAL_STATUS_REJECTED, organization_id=organization_id)
        if not record:
            return None
        record.approver_identity = approver_identity
        record.redacted_metadata.update(metadata or {})
        return record

    def cancel(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        return self._transition(approval_id, APPROVAL_STATUS_CANCELLED, organization_id=organization_id)

    def expire(self, approval_id: str, *, organization_id: str | None = None) -> ApprovalRecord | None:
        return self._transition(approval_id, APPROVAL_STATUS_EXPIRED, organization_id=organization_id)

    def list_for_agent(self, agent_id: str, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        return [record for record in self.store.records.values() if record.agent_id == agent_id and self._require_tenant(record, organization_id) is not None]

    def list_for_tool(self, tool_id: str, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        return [record for record in self.store.records.values() if record.tool_id == tool_id and self._require_tenant(record, organization_id) is not None]

    def list_pending(self, *, organization_id: str | None = None) -> list[ApprovalRecord]:
        return [record for record in self.store.records.values() if record.status == "pending" and self._require_tenant(record, organization_id) is not None]


class ApprovalService:
    def __init__(self, repository: ApprovalRepository | None = None) -> None:
        self.repository = repository or InMemoryApprovalRepository()

    def request(self, *, agent_id: str, tool_id: str, action: str, requested_capability: str, risk_level: str, organization_id: str | None = None, expiration_at: datetime | None = None, requester_context: dict[str, Any] | None = None) -> ApprovalRecord:
        approval_id = f"approval-{agent_id}-{tool_id}-{action}"
        record = ApprovalRecord(
            approval_id=approval_id,
            agent_id=agent_id,
            tool_id=tool_id,
            action=action,
            requested_capability=requested_capability,
            risk_level=risk_level,
            organization_id=organization_id,
            expiration_at=expiration_at,
            requester_context=requester_context or {},
        )
        return self.repository.create(record)

    def record_decision(self, approval_id: str, approved: bool, *, organization_id: str | None = None, approver_identity: str | None = None, metadata: dict[str, Any] | None = None) -> ApprovalRecord | None:
        if approved:
            return self.repository.approve(approval_id, approver_identity=approver_identity, metadata=metadata, organization_id=organization_id)
        return self.repository.reject(approval_id, approver_identity=approver_identity, metadata=metadata, organization_id=organization_id)

    def is_approved(self, approval_id: str, *, organization_id: str | None = None) -> bool:
        record = self.repository.get(approval_id, organization_id=organization_id)
        if not record:
            return False
        if record.status != APPROVAL_STATUS_APPROVED:
            return False
        if record.expiration_at and record.expiration_at < datetime.utcnow():
            self.repository.expire(approval_id, organization_id=organization_id)
            return False
        return True
