from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from safenestt.persistence.models import (
    AgentRunModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ReportModel,
)
from safenestt.security.encryption import encrypt_value, decrypt_value

logger = logging.getLogger(__name__)


def _encrypt_field(value: Any) -> str | None:
    """Encrypt a sensitive field value."""
    if value is None:
        return None
    return encrypt_value(value)


def _decrypt_field(encrypted: str | None) -> Any:
    """Decrypt a sensitive field value."""
    if encrypted is None:
        return None
    return decrypt_value(encrypted)


class InvestigationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, record: Any) -> Any:
        model = InvestigationModel(
            investigation_id=record.investigation_id,
            case_id=getattr(record, "case_id", None),
            tenant_id=record.tenant_id,
            created_by=record.created_by,
            target=_encrypt_field(record.target),
            type=record.type,
            status=record.status,
            risk_level=None,
            current_stage=None,
            error=record.error,
            meta=None,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )
        self._session.add(model)
        self._session.flush()
        return record

    def get(self, investigation_id: str) -> Any | None:
        model = self._session.execute(
            select(InvestigationModel).where(InvestigationModel.investigation_id == investigation_id)
        ).scalar_one_or_none()
        return self._to_record(model) if model else None

    def update(self, record: Any) -> Any:
        model = self._session.execute(
            select(InvestigationModel).where(InvestigationModel.investigation_id == record.investigation_id)
        ).scalar_one_or_none()
        if not model:
            return None
        model.status = record.status
        model.updated_at = datetime.now(UTC)
        model.risk_level = getattr(record, "risk_level", None)
        model.current_stage = getattr(record, "current_stage", None)
        model.error = record.error
        return record

    def list_by_tenant(self, tenant_id: str | None = None, status: str | None = None) -> list[Any]:
        query = select(InvestigationModel)
        if tenant_id:
            query = query.where(InvestigationModel.tenant_id == tenant_id)
        if status:
            query = query.where(InvestigationModel.status == status)
        return [self._to_record(m) for m in self._session.execute(query).scalars().all()]

    @staticmethod
    def _to_record(model: InvestigationModel) -> Any:
        from safenestt.investigations.records import InvestigationRecord
        record = InvestigationRecord(
            investigation_id=model.investigation_id,
            tenant_id=model.tenant_id,
            created_by=model.created_by,
            target=_decrypt_field(model.target),
            type=model.type,
            status=model.status,
            created_at=model.created_at,
            updated_at=model.updated_at,
            error=model.error,
        )
        return record


class AgentRunRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, investigation_id: str, run_id: str, agent_type: str, model_provider: str | None = None, model_name: str | None = None) -> AgentRunModel:
        model = AgentRunModel(
            run_id=run_id,
            investigation_id=investigation_id,
            agent_type=agent_type,
            status="running",
            started_at=datetime.now(UTC),
            model_provider=model_provider,
            model_name=model_name,
        )
        self._session.add(model)
        self._session.flush()
        return model

    def complete(self, run_id: str, outputs: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> AgentRunModel | None:
        model = self._session.execute(
            select(AgentRunModel).where(AgentRunModel.run_id == run_id)
        ).scalar_one_or_none()
        if not model:
            return None
        model.status = "failed" if error else "completed"
        model.completed_at = datetime.now(UTC)
        model.outputs = _encrypt_field(outputs) if outputs else None
        model.error = error
        return model

    def increment_retry(self, run_id: str) -> AgentRunModel | None:
        model = self._session.execute(
            select(AgentRunModel).where(AgentRunModel.run_id == run_id)
        ).scalar_one_or_none()
        if not model:
            return None
        model.retry_count += 1
        return model

    def list_by_investigation(self, investigation_id: str) -> list[AgentRunModel]:
        return list(
            self._session.execute(
                select(AgentRunModel).where(AgentRunModel.investigation_id == investigation_id).order_by(AgentRunModel.created_at.asc())
            ).scalars().all()
        )


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, investigation_id: str, finding: Any) -> Any:
            model = FindingModel(
                finding_id=finding.finding_id,
                investigation_id=investigation_id,
                agent=getattr(finding, "agent", None),
                finding_type="AI_INFERENCE",
                claim=_encrypt_field(finding.claim) if hasattr(finding, "claim") else _encrypt_field(str(finding)),
                severity=getattr(finding, "severity", None),
                confidence=getattr(finding, "confidence", 0.0),
                source=getattr(finding, "source", None),
                evidence_ids=getattr(finding, "evidence_ids", []) or [],
                reality_status=getattr(finding, "reality_status", "AI_INFERENCE"),
                risk_score=getattr(finding, "risk_score", 0.0),
                factors=getattr(finding, "factors", {}) or {},
                meta=None,
            )
            self._session.add(model)
            self._session.flush()
            return finding

    def list_by_investigation(self, investigation_id: str) -> list[FindingModel]:
        return list(
            self._session.execute(
                select(FindingModel).where(FindingModel.investigation_id == investigation_id)
            ).scalars().all()
        )


class EvidenceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, investigation_id: str, evidence: Any) -> Any:
        model = EvidenceModel(
            evidence_id=evidence.evidence_id,
            investigation_id=investigation_id,
            source=evidence.source,
            source_type=evidence.source_type,
            target=_encrypt_field(evidence.target),
            observed_at=evidence.observed_at,
            data=_encrypt_field(evidence.data),
            confidence=evidence.confidence,
            provenance=evidence.provenance,
            integrity_hash=self._hash_evidence(evidence),
            meta=evidence.metadata,
            tool_run_id=evidence.tool_run_id,
        )
        self._session.add(model)
        self._session.flush()
        return evidence

    def list_by_investigation(self, investigation_id: str) -> list[EvidenceModel]:
        return list(
            self._session.execute(
                select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id)
            ).scalars().all()
        )

    @staticmethod
    def _hash_evidence(evidence: Any) -> str:
        raw = f"{evidence.evidence_id}:{evidence.source}:{evidence.target}:{evidence.observed_at.isoformat() if isinstance(evidence.observed_at, datetime) else str(evidence.observed_at)}"
        return hashlib.sha256(raw.encode()).hexdigest()


class ReportRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, investigation_id: str, report_id: str) -> ReportModel:
        model = ReportModel(report_id=report_id, investigation_id=investigation_id)
        self._session.add(model)
        return model

    def update_review(self, report_id: str, review_state: str, approval_state: str | None = None) -> ReportModel | None:
        model = self._session.execute(
            select(ReportModel).where(ReportModel.report_id == report_id)
        ).scalar_one_or_none()
        if not model:
            return None
        model.review_state = review_state
        if approval_state:
            model.approval_state = approval_state
        model.version += 1
        return model

    def update_submission(self, report_id: str, submitted_state: str) -> ReportModel | None:
        model = self._session.execute(
            select(ReportModel).where(ReportModel.report_id == report_id)
        ).scalar_one_or_none()
        if not model:
            return None
        model.submitted_state = submitted_state
        model.version += 1
        return model

    def get_by_investigation(self, investigation_id: str) -> ReportModel | None:
        return self._session.execute(
            select(ReportModel).where(ReportModel.investigation_id == investigation_id)
        ).scalar_one_or_none()


class AuditEventRepository:
    """Tamper-evident audit logging with hash-chain integrity.

    Each audit row stores a chain_hash computed from the previous row's
    chain_hash concatenated with this row's critical data fields. This
    creates a hash chain similar to a blockchain — tampering with any
    historical row invalidates all subsequent hashes.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _compute_hash(previous_hash: str | None, event_data: str) -> str:
        """Compute chain hash from previous hash + event data."""
        if previous_hash:
            return hashlib.sha256(f"{previous_hash}:{event_data}".encode()).hexdigest()
        return hashlib.sha256(f"GENESIS:{event_data}".encode()).hexdigest()

    def _get_previous_hash(self) -> str | None:
        """Get the chain_hash of the most recent audit event."""
        result = self._session.execute(
            select(AuditEventModel.chain_hash).order_by(AuditEventModel.id.desc()).limit(1)
        ).scalar_one_or_none()
        return result

    def record(self, event: Any) -> Any:
        # Get investigation_id from the event or its metadata
        inv_id = getattr(event, "investigation_id", None)
        if inv_id is None and hasattr(event, "metadata") and event.metadata:
            inv_id = event.metadata.get("investigation_id")

        # Build hash chain
        previous_hash = self._get_previous_hash()
        event_data = f"{event.event_id}:{event.actor_type}:{event.actor_id}:{event.action}:{event.decision}"
        chain_hash = self._compute_hash(previous_hash, event_data)

        model = AuditEventModel(
            event_id=event.event_id,
            investigation_id=inv_id,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            action=event.action,
            decision=event.decision,
            risk_level=getattr(event, "risk_level", "LOW"),
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            detail=event.detail,
            meta=self._safe_metadata(event.metadata) or {},
            chain_hash=chain_hash,
        )

        self._session.add(model)
        self._session.flush()
        return event

    def list_all(self, limit: int = 1000) -> list[AuditEventModel]:
        """Get all audit events ordered by ID (chain order)."""
        return list(
            self._session.execute(
                select(AuditEventModel).order_by(AuditEventModel.id).limit(limit)
            ).scalars().all()
        )

    def list_by_investigation(self, investigation_id: str, limit: int = 100) -> list[AuditEventModel]:
        return list(
            self._session.execute(
                select(AuditEventModel)
                .where(AuditEventModel.investigation_id == investigation_id)
                .order_by(AuditEventModel.created_at.desc())
                .limit(limit)
            ).scalars().all()
        )

    @classmethod
    def verify_chain_integrity(cls, events: list[Any]) -> tuple[bool, str]:
        """Verify the hash chain integrity of audit events.

        Returns (is_valid, message).
        """
        if not events:
            return True, "No events to verify"

        previous_hash = None
        for event in events:
            event_data = f"{event.event_id}:{event.actor_type}:{event.actor_id}:{event.action}:{event.decision}"
            expected_hash = cls._compute_hash(previous_hash, event_data)
            stored_hash = event.chain_hash

            if stored_hash != expected_hash:
                return False, (
                    f"Chain broken at event {event.event_id} (id={event.id}): "
                    f"expected {expected_hash[:16]}... got {stored_hash[:16]}..."
                )
            previous_hash = expected_hash

        return True, f"Chain integrity verified for {len(events)} events"

    @staticmethod
    def _safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
        if not metadata:
            return None
        return {k: v for k, v in metadata.items() if k not in {"api_key", "apikey", "Authorization", "token", "password", "secret", "private_key"}}
