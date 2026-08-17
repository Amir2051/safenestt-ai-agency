from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.security.redaction import redact


@dataclass
class ToolRunRecord:
    tool_run_id: str
    investigation_id: str
    tool_id: str
    action: str
    payload: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    executed_at: datetime = field(default_factory=datetime.utcnow)
    redacted_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceRecord:
    investigation_id: str
    evidence_id: str
    source: str
    source_type: str
    target: str
    observed_at: datetime = field(default_factory=datetime.utcnow)
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    provenance: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tool_run_id: str | None = None


class InvalidStatusError(Exception):
    pass


class InvestigationRecord:
    VALID_STATUSES = {
        "QUEUED",
        "RUNNING",
        "WAITING_FOR_TOOL",
        "VERIFYING",
        "CALCULATING_RISK",
        "COMPLETED",
        "FAILED",
        "CANCELLED",
        "ANALYZING",
    }
    TRANSITIONS = {
        "QUEUED": {"RUNNING", "CANCELLED", "FAILED"},
        "RUNNING": {"ANALYZING", "WAITING_FOR_TOOL", "VERIFYING", "FAILED", "CANCELLED"},
        "ANALYZING": {"WAITING_FOR_TOOL", "FAILED", "CANCELLED"},
        "WAITING_FOR_TOOL": {"RUNNING", "VERIFYING", "FAILED", "CANCELLED"},
        "VERIFYING": {"CALCULATING_RISK", "FAILED", "CANCELLED"},
        "CALCULATING_RISK": {"COMPLETED", "FAILED", "CANCELLED"},
        "COMPLETED": set(),
        "FAILED": set(),
        "CANCELLED": set(),
    }

    def __init__(self, investigation_id: str, tenant_id: str | None = None, created_by: str | None = None, target: str | None = None, type: str | None = None, status: str = "QUEUED", created_at: datetime | None = None, updated_at: datetime | None = None, error: dict[str, Any] | None = None) -> None:
        self.investigation_id = investigation_id
        self.tenant_id = tenant_id
        self.created_by = created_by
        self.target = target
        self.type = type
        self.status = status
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
        self.error = error

    def mark(self, status: str) -> None:
        if status not in self.VALID_STATUSES:
            raise InvalidStatusError(f"Invalid status: {status}")
        allowed = self.TRANSITIONS.get(self.status, set())
        if status not in allowed and status != self.status:
            raise InvalidStatusError(f"Cannot transition from {self.status} to {status}")
        self.status = status
        self.updated_at = datetime.utcnow()


@dataclass
class FindingRecord:
    investigation_id: str
    finding_id: str
    claim: str
    evidence_ids: list[str] = field(default_factory=list)
    reality_status: str = "AI_INFERENCE"
    risk_score: float = 0.0
    factors: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
