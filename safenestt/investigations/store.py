"""Production API store backed by PostgreSQL with RLS, encryption, and audit."""
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
    """PostgreSQL-backed store with RLS, encryption, and audit logging."""
    
    def __init__(self, tenant_id: str | None = None):
        self._tenant_id = tenant_id
    
    def _require_tenant(self) -> str:
        if not self._tenant_id:
            raise TenantIsolationError("Tenant context required for database access")
        return self._tenant_id
    
    def create_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
            model = InvestigationModel(
                investigation_id=record.investigation_id,
                tenant_id=tenant_id,
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
        """Get investigation by ID. Raises TenantIsolationError if record exists but belongs to another tenant.
        
        Uses a SECURITY DEFINER function to detect cross-tenant access without needing owner credentials.
        """
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
            from sqlalchemy import select
            result = session.execute(
                select(InvestigationModel).where(
                    InvestigationModel.investigation_id == investigation_id
                )
            ).scalar_one_or_none()
            
            if result is None:
                # Use SECURITY DEFINER function to check cross-tenant access
                # This runs with elevated privileges but only returns a boolean
                from sqlalchemy import text
                is_cross_tenant = session.execute(
                    text("SELECT check_cross_tenant_access(:id, :tid)"),
                    {"id": investigation_id, "tid": tenant_id}
                ).scalar()
                
                if is_cross_tenant:
                    raise TenantIsolationError(
                        f"investigation {investigation_id} not accessible for tenant {tenant_id}"
                    )
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
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
            from sqlalchemy import select
            result = session.execute(
                select(InvestigationModel).where(
                    InvestigationModel.investigation_id == record.investigation_id
                )
            ).scalar_one_or_none()
            
            if result is None:
                raise TenantIsolationError(
                    f"investigation {record.investigation_id} not found for tenant {tenant_id}"
                )
            
            result.status = record.status
            result.updated_at = datetime.now(UTC)
            if record.error:
                result.error = record.error
            session.flush()
            
            return record
    
    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
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
        """List evidence for an investigation. Raises TenantIsolationError if investigation belongs to another tenant."""
        tenant_id = self._require_tenant()
        
        # First verify the investigation belongs to this tenant
        inv = self.get_investigation(investigation_id)
        if inv is None:
            return []
        
        with session_scope(tenant_id) as session:
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
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
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
        tenant_id = self._require_tenant()
        
        # First verify the investigation belongs to this tenant
        inv = self.get_investigation(investigation_id)
        if inv is None:
            return []
        
        with session_scope(tenant_id) as session:
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
        tenant_id = self._require_tenant()
        
        with session_scope(tenant_id) as session:
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
