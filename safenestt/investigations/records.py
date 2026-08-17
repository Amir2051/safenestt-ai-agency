from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


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


@dataclass
class InvestigationRecord:
    investigation_id: str
    tenant_id: str | None = None
    created_by: str | None = None
    target: str | None = None
    type: str | None = None
    status: str = "QUEUED"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def mark(self, status: str) -> None:
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
