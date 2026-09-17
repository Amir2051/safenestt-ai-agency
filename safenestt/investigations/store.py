"""Production API store backed by PostgreSQL with RLS, encryption, and audit.

CRITICAL: This store uses session-bound tenant context for RLS.
Instead of passing tenant_id directly to session_scope (which could be spoofed),
we pass the API key hash. The SECURITY DEFINER function establish_tenant_context()
validates the key hash and records (pg_backend_pid(), tenant_id) server-side.
"""
from __future__ import annotations

import uuid
from datetime import datetime, UTC
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.persistence.engine import session_scope, create_engine
from safenestt.persistence.models import (
    AgentRunModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ReportModel,
    Base,
)
from safenestt.security.encryption import encrypt_value
from safenestt.security.audit import audit, AuditEvent


class TenantIsolationError(PermissionError):
    """Raised when a cross-tenant access attempt is detected."""
    pass


class PersistentInvestigationStore:
    """PostgreSQL-backed store with RLS, encryption, and audit logging.
    
    Uses session-bound tenant context: the API key hash is passed to
    session_scope(), which calls establish_tenant_context() to validate
    and record the tenant context server-side.
    """
    
    def __init__(self, api_key_hash: str | None = None, tenant_id: str | None = None):
        self._api_key_hash = api_key_hash
        self._tenant_id = tenant_id  # Only used for bypass operations
    
    def _session(self):
        """Get a session scope with tenant context established."""
        return session_scope(self._api_key_hash)
    
    def create_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            model = InvestigationModel(
                investigation_id=record.investigation_id,
                tenant_id=record.tenant_id,
                created_by=record.created_by,
                target=encrypt_value(record.target),
                type=record.type,
                status=record.status,
                created_at=record.created_at,
                updated_at=record.updated_at,
            )
            session.add(model)
            session.flush()
            
            # Audit the creation
            audit_event = AuditEvent(
                event_id=f"inv-create-{record.investigation_id}",
                actor_type="api",
                actor_id=record.created_by,
                action="investigation.create",
                decision="ALLOW",
            )
            audit.record(audit_event)
            
            return record
    
    def get_investigation(self, investigation_id: str) -> InvestigationRecord | None:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            from sqlalchemy import select
            result = session.execute(
                select(InvestigationModel).where(
                    InvestigationModel.investigation_id == investigation_id
                )
            ).scalar_one_or_none()
            
            if result is None:
                return None
            
            return InvestigationRecord(
                investigation_id=result.investigation_id,
                tenant_id=result.tenant_id,
                created_by=result.created_by,
                target=result.target,
                type=result.type,
                status=result.status,
                created_at=result.created_at,
                updated_at=result.updated_at,
            )
    
    def update_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            from sqlalchemy import select
            result = session.execute(
                select(InvestigationModel).where(
                    InvestigationModel.investigation_id == record.investigation_id
                )
            ).scalar_one_or_none()
            
            if result is None:
                raise TenantIsolationError(
                    f"investigation {record.investigation_id} not found or access denied"
                )
            
            result.status = record.status
            result.updated_at = datetime.now(UTC)
            if record.error:
                result.error = record.error
            session.flush()
            
            return record
    
    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            model = EvidenceModel(
                evidence_id=evidence.evidence_id,
                investigation_id=evidence.investigation_id,
                source=evidence.source,
                source_type=evidence.source_type,
                target=evidence.target,
                observed_at=evidence.observed_at,
                data=evidence.data,
                confidence=evidence.confidence,
                tool_run_id=evidence.tool_run_id,
            )
            session.add(model)
            session.flush()
            
            return evidence
    
    def list_evidence(self, investigation_id: str) -> list[EvidenceRecord]:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            from sqlalchemy import select
            results = session.execute(
                select(EvidenceModel).where(
                    EvidenceModel.investigation_id == investigation_id
                )
            ).scalars().all()
            
            return [
                EvidenceRecord(
                    investigation_id=r.investigation_id,
                    evidence_id=r.evidence_id,
                    source=r.source,
                    source_type=r.source_type,
                    target=r.target,
                    observed_at=r.observed_at,
                    data=r.data or {},
                    confidence=r.confidence or 0.0,
                    tool_run_id=r.tool_run_id,
                )
                for r in results
            ]
    
    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            model = FindingModel(
                finding_id=finding.finding_id,
                investigation_id=finding.investigation_id,
                claim=finding.claim,
                evidence_ids=finding.evidence_ids,
                reality_status=finding.reality_status,
                risk_score=finding.risk_score,
                factors=finding.factors,
            )
            session.add(model)
            session.flush()
            
            return finding
    
    def list_findings(self, investigation_id: str) -> list[FindingRecord]:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            from sqlalchemy import select
            results = session.execute(
                select(FindingModel).where(
                    FindingModel.investigation_id == investigation_id
                )
            ).scalars().all()
            
            return [
                FindingRecord(
                    investigation_id=r.investigation_id,
                    finding_id=r.finding_id,
                    claim=r.claim,
                    evidence_ids=r.evidence_ids or [],
                    reality_status=r.reality_status or "AI_INFERENCE",
                    risk_score=r.risk_score or 0.0,
                    factors=r.factors or {},
                )
                for r in results
            ]
    
    def list_investigations(self) -> list[InvestigationRecord]:
        if not self._api_key_hash:
            raise TenantIsolationError("API key required for database access")
        
        with self._session() as session:
            from sqlalchemy import select
            results = session.execute(
                select(InvestigationModel)
            ).scalars().all()
            
            return [
                InvestigationRecord(
                    investigation_id=r.investigation_id,
                    tenant_id=r.tenant_id,
                    created_by=r.created_by,
                    target=r.target,
                    type=r.type,
                    status=r.status,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
                for r in results
            ]


def ensure_schema() -> None:
    """Create all tables if they don't exist using the app engine.
    
    NOTE: In production, schema is created by the `migrate` job which runs
    as the owner role. This function is for development/testing only.
    """
    engine = create_engine()
    Base.metadata.create_all(engine)
    
    try:
        from safenestt.persistence.rls import apply_rls_policies
        apply_rls_policies(engine)
    except Exception:
        pass
