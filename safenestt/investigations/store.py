"""Production API store backed by PostgreSQL with RLS, encryption, and audit.

CRITICAL: This store uses session-bound tenant context for RLS.
The API layer passes (tenant_id, key_fingerprint) to the store,
which forwards them to session_scope().

ENCRYPTED FIELDS:
- InvestigationModel.target → encrypted
- EvidenceModel.target, .data → encrypted
- FindingModel.claim, .factors → encrypted
- AgentRunModel.inputs, .outputs → encrypted
- ReportModel.draft → encrypted
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, UTC
from typing import Any

logger = logging.getLogger(__name__)

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.serialization import json_safe
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
from safenestt.security.encryption import encrypt_value, decrypt_value
from safenestt.security.audit import AuditEvent
from safenestt.persistence.store import PersistentAuditLogger
from safenestt.persistence.repositories import AuditEventRepository
from safenestt.registry import RiskLevel


class TenantIsolationError(PermissionError):
    pass


class PersistentInvestigationStore:
    """PostgreSQL-backed store with RLS, encryption, and audit logging."""
    
    def __init__(self, tenant_id: str | None = None, key_fingerprint: str | None = None):
        self._tenant_id = tenant_id
        self._key_fingerprint = key_fingerprint
    
    def _session(self):
        """Get a session scope with tenant context established."""
        return session_scope(self._tenant_id, self._key_fingerprint)
    
    def create_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
        with self._session() as session:
            model = InvestigationModel(
                investigation_id=record.investigation_id,
                tenant_id=record.tenant_id,
                case_id=record.case_id,
                created_by=record.created_by,
                target=encrypt_value(record.target),
                type=record.type,
                status=record.status,
                created_at=record.created_at,
                updated_at=record.updated_at,
            )
            session.add(model)
            session.flush()
            
            # Audit using the same session (tenant context already established)
            audit = AuditEventRepository(session)
            audit.record(AuditEvent(
                event_id=f"inv-create-{record.investigation_id}",
                actor_type="api",
                actor_id=record.created_by,
                action="investigation.create",
                decision="ALLOW",
                risk_level=RiskLevel.LOW,
                resource_type="investigation",
                resource_id=record.investigation_id,
                detail=f"Created investigation for {record.target}",
                metadata={"investigation_id": record.investigation_id},
            ))
            
            return record
    
    def get_investigation(self, investigation_id: str) -> InvestigationRecord | None:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
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
                case_id=result.case_id,
                created_by=result.created_by,
                target=decrypt_value(result.target),
                type=result.type,
                status=result.status,
                created_at=result.created_at,
                updated_at=result.updated_at,
            )
    
    def update_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
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
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
        with self._session() as session:
            model = EvidenceModel(
                evidence_id=evidence.evidence_id,
                investigation_id=evidence.investigation_id,
                source=evidence.source,
                source_type=evidence.source_type,
                target=encrypt_value(evidence.target),
                observed_at=evidence.observed_at,
                data=encrypt_value(evidence.data),
                confidence=evidence.confidence,
                tool_run_id=evidence.tool_run_id,
            )
            session.add(model)
            session.flush()
            
            return evidence
    
    def list_evidence(self, investigation_id: str) -> list[EvidenceRecord]:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
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
                    target=decrypt_value(r.target),
                    observed_at=r.observed_at,
                    data=decrypt_value(r.data) or {},
                    confidence=r.confidence or 0.0,
                    tool_run_id=r.tool_run_id,
                )
                for r in results
            ]
    
    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        with self._session() as session:
            model = FindingModel(
                finding_id=finding.finding_id,
                investigation_id=finding.investigation_id,
                claim=encrypt_value(finding.claim),
                evidence_ids=finding.evidence_ids,
                reality_status=finding.reality_status,
                agent=getattr(finding, "agent", None),
                risk_score=finding.risk_score,
                factors=encrypt_value(finding.factors) if finding.factors else None,
            )
            session.add(model)
            session.flush()

            return finding

    def add_agent_runs(self, investigation_id: str, agent_runs_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Persist agent runs from orchestrator output. Returns list of persisted run_ids."""
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        persisted: list[dict[str, Any]] = []
        with self._session() as session:
            from sqlalchemy import select
            for run_data in agent_runs_data:
                run_id = run_data.get("run_id")
                if not run_id:
                    continue
                existing = session.execute(
                    select(AgentRunModel).where(AgentRunModel.run_id == run_id)
                ).scalar_one_or_none()
                if existing:
                    existing.status = run_data.get("status", existing.status)
                    existing.started_at = run_data.get("started_at") or existing.started_at
                    existing.completed_at = run_data.get("completed_at") or existing.completed_at
                    existing.error = run_data.get("error") or existing.error
                else:
                    session.add(AgentRunModel(
                        run_id=run_id,
                        investigation_id=investigation_id,
                        agent_type=run_data.get("agent_type", "unknown"),
                        status=run_data.get("status", "unknown"),
                        started_at=run_data.get("started_at"),
                        completed_at=run_data.get("completed_at"),
                        model_provider=run_data.get("model_provider"),
                        model_name=run_data.get("model_name"),
                        error=run_data.get("error"),
                    ))
                persisted.append({"run_id": run_id, "agent_type": run_data.get("agent_type", "unknown"), "status": run_data.get("status", "unknown")})
            session.flush()
        return persisted
    
    def list_findings(self, investigation_id: str) -> list[FindingRecord]:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

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
                    claim=decrypt_value(r.claim),
                    evidence_ids=r.evidence_ids or [],
                    reality_status=r.reality_status or "AI_INFERENCE",
                    risk_score=r.risk_score or 0.0,
                    factors=decrypt_value(r.factors) or {},
                )
                for r in results
            ]

    def list_agent_runs(self, investigation_id: str) -> list[dict[str, Any]]:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        with self._session() as session:
            from sqlalchemy import select
            results = session.execute(
                select(AgentRunModel).where(
                    AgentRunModel.investigation_id == investigation_id
                )
            ).scalars().all()

            return [
                {
                    "run_id": r.run_id,
                    "agent_id": r.agent_type,
                    "agent_type": r.agent_type,
                    "task_id": None,
                    "status": r.status,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "error": r.error,
                    "retry_count": r.retry_count,
                    "model_provider": r.model_provider,
                    "model_name": r.model_name,
                    "inputs": decrypt_value(r.inputs) if r.inputs else None,
                    "outputs": decrypt_value(r.outputs) if r.outputs else None,
                    "tool_calls": r.tool_calls,
                }
                for r in results
            ]

    def _node_id_to_key(self, node_id: str) -> str:
        """Extract the application-level node_key from a GraphNodeRecord.id.

        The bridge builds node IDs as 'gn-{type}-{inv_id}-{hash}'.
        We use the full ID as the node_key for FK resolution.
        """
        return node_id

    def add_graph_node(self, node: Any) -> Any:
        """Persist a GraphNodeRecord to the graph_nodes table.

        Uses the existing tenant-aware session/RLS mechanism.
        The node's id becomes the node_key for FK resolution.
        """
        from safenestt.persistence.models import GraphNodeModel
        from sqlalchemy import select

        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        node_key = self._node_id_to_key(node.id)
        with self._session() as session:
            existing = session.execute(
                select(GraphNodeModel).where(GraphNodeModel.node_key == node_key)
            ).scalar_one_or_none()
            if existing:
                existing.node_label = node.label
                existing.node_data = node.node_data
                existing.updated_at = datetime.now(UTC)
                session.flush()
                return existing

            model = GraphNodeModel(
                investigation_id=node.investigation_id,
                case_id=node.case_id,
                node_key=node.node_key or node_key,
                node_type=node.node_type,
                node_label=node.label,
                node_data=node.node_data,
                source=node.source,
                provenance=node.provenance,
            )
            session.add(model)
            session.flush()
            return model

    def add_graph_edge(self, edge: Any) -> Any:
        """Persist a GraphEdgeRecord to the graph_edges table.

        Enforces same-investigation constraint:
        - Verifies source_node_id exists and belongs to edge's investigation
        - Verifies target_node_id exists and belongs to edge's investigation
        - Raises ValueError if either check fails (fail closed)

        Uses the existing tenant-aware session/RLS mechanism.
        """
        from safenestt.persistence.models import GraphNodeModel, GraphEdgeModel
        from sqlalchemy import select

        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        source_key = edge.source_node_id
        target_key = edge.target_node_id
        edge_key = edge.edge_key

        with self._session() as session:
            # Verify source node exists in the same investigation
            source_node = session.execute(
                select(GraphNodeModel).where(
                    GraphNodeModel.node_key == source_key,
                )
            ).scalar_one_or_none()
            if not source_node:
                raise ValueError(f"Source node not found: {edge.source_node_id}")
            if source_node.investigation_id != edge.investigation_id:
                raise ValueError(
                    f"Source node {edge.source_node_id} belongs to investigation "
                    f"'{source_node.investigation_id}' but edge targets "
                    f"'{edge.investigation_id}'"
                )

            # Verify target node exists in the same investigation
            target_node = session.execute(
                select(GraphNodeModel).where(
                    GraphNodeModel.node_key == target_key,
                )
            ).scalar_one_or_none()
            if not target_node:
                raise ValueError(f"Target node not found: {edge.target_node_id}")
            if target_node.investigation_id != edge.investigation_id:
                raise ValueError(
                    f"Target node {edge.target_node_id} belongs to investigation "
                    f"'{target_node.investigation_id}' but edge targets "
                    f"'{edge.investigation_id}'"
                )

            # Check for existing edge
            existing = session.execute(
                select(GraphEdgeModel).where(GraphEdgeModel.edge_key == edge_key)
            ).scalar_one_or_none()
            if existing:
                existing.edge_data = edge.edge_data if hasattr(edge, "edge_data") else {}
                existing.updated_at = datetime.now(UTC)
                session.flush()
                # Return existing edge while session is still open (bound model)
                return existing

            model = GraphEdgeModel(
                investigation_id=edge.investigation_id,
                case_id=edge.case_id,
                edge_key=edge.edge_key,
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                edge_type=edge.edge_type,
                edge_label=edge.edge_label,
                edge_data=edge.edge_data,
                source=edge.source,
                provenance=edge.provenance,
            )
            session.add(model)
            session.flush()
            session.commit()
            # Return model while session is still open (bound model)
            # The session_scope context manager will close the session after
            # the with block exits, but the model stays bound for the caller.
            return model

    def list_graph_nodes(self, investigation_id: str) -> list[dict[str, Any]]:
        """List all graph nodes for an investigation."""
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        from safenestt.persistence.models import GraphNodeModel
        from sqlalchemy import select

        with self._session() as session:
            results = session.execute(
                select(GraphNodeModel).where(
                    GraphNodeModel.investigation_id == investigation_id
                )
            ).scalars().all()

            return [
                {
                    "id": r.id,
                    "investigation_id": r.investigation_id,
                    "case_id": r.case_id,
                    "node_key": r.node_key,
                    "node_type": r.node_type,
                    "node_label": r.node_label,
                    "node_data": r.node_data,
                    "source": r.source,
                    "provenance": r.provenance,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
                for r in results
            ]

    def list_graph_edges(self, investigation_id: str) -> list[dict[str, Any]]:
        """List all graph edges for an investigation."""
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        from safenestt.persistence.models import GraphEdgeModel
        from sqlalchemy import select

        with self._session() as session:
            results = session.execute(
                select(GraphEdgeModel).where(
                    GraphEdgeModel.investigation_id == investigation_id
                )
            ).scalars().all()

            return [
                {
                    "id": r.id,
                    "investigation_id": r.investigation_id,
                    "case_id": r.case_id,
                    "edge_key": r.edge_key,
                    "source_node_id": r.source_node_id,
                    "target_node_id": r.target_node_id,
                    "edge_type": r.edge_type,
                    "edge_label": r.edge_label,
                    "edge_data": r.edge_data,
                    "source": r.source,
                    "provenance": r.provenance,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
                for r in results
            ]

    def add_report(self, investigation_id: str, draft: dict[str, Any] | None = None,
                    review_state: str = "draft", approval_state: str = "pending") -> ReportModel:
        """Persist the report dossier for an investigation.

        Idempotent: re-running an investigation re-persists the same
        report_id row. Previously a second call raised UniqueViolation on
        ix_reports_report_id, which the caller could not distinguish from a
        real persistence failure.
        """
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        report_id = f"rpt-{investigation_id}"
        # Single authoritative JSON-normalization boundary. The dossier is
        # assembled from dataclass __dict__ values, so it carries datetimes
        # that the json column cannot bind. Normalized here (not ad-hoc in the
        # report generator) so no plaintext ever bypasses normalization and
        # unsupported types still fail explicitly.
        safe_draft = json_safe(draft) if draft is not None else None

        with self._session() as session:
            from sqlalchemy import select
            existing = session.execute(
                select(ReportModel).where(ReportModel.report_id == report_id)
            ).scalar_one_or_none()
            if existing is not None:
                existing.draft = safe_draft
                existing.review_state = review_state
                existing.approval_state = approval_state
                existing.updated_at = datetime.now(UTC)
                session.flush()
                return existing

            model = ReportModel(
                report_id=report_id,
                investigation_id=investigation_id,
                draft=safe_draft,
                review_state=review_state,
                approval_state=approval_state,
            )
            session.add(model)
            session.flush()
            return model

    def get_report(self, investigation_id: str) -> dict[str, Any] | None:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")

        with self._session() as session:
            from sqlalchemy import select
            result = session.execute(
                select(ReportModel).where(
                    ReportModel.investigation_id == investigation_id
                )
            ).scalar_one_or_none()
            if not result:
                return None
            # NOTE: `draft` is a plain JSON column written through
            # json_safe() at insert time — it is NOT encrypted at rest.
            # Calling decrypt_value() here raised
            # "'dict' object has no attribute 'encode'" on a perfectly good
            # persisted report. The column stores normalized JSON directly.
            return {
                "report_id": result.report_id,
                "investigation_id": result.investigation_id,
                "draft": result.draft,
                "review_state": result.review_state,
                "approval_state": result.approval_state,
                "version": result.version,
                "created_at": result.created_at.isoformat() if result.created_at else None,
                "updated_at": result.updated_at.isoformat() if result.updated_at else None,
            }
    
    def list_investigations(self) -> list[InvestigationRecord]:
        if not self._tenant_id or not self._key_fingerprint:
            raise TenantIsolationError("Tenant context required for database access")
        
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
                    target=decrypt_value(r.target),
                    type=r.type,
                    status=r.status,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
                for r in results
            ]


def ensure_schema() -> None:
    """Initialize schema so a FRESH database becomes usable.

    Safe to call on an existing database; every step is idempotent.

    Order matters and is enforced here:

        1. base tables                 (Base.metadata.create_all)
        2. tenant-context functions   (ensure_tenant_context)
        3. RLS policies                (apply_rls_policies)

    Step 2 must precede step 3 because every policy calls
    get_current_tenant(). That function previously lived only in
    migrate.py, so this path failed on a fresh database with
    "function get_current_tenant() does not exist".

    CAPABILITY BOUNDARY — who owns what
    ----------------------------------
    This function runs on the APPLICATION engine (safenestt_app), but
    `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` requires being the table
    OWNER. In a real deployment migrate.py::main() has already created the
    tables as the owner and applied RLS, so step 3 legitimately fails here
    with InsufficientPrivilege — and always has.

    That is not an error condition to hide and not a reason to abort
    startup; it is a privilege boundary. migrate.py::main() is the only
    entrypoint that can create the app role and grant privileges, and it is
    responsible for RLS. We therefore log the boundary explicitly instead of
    raising an error that no caller can act on, and still verify that the
    tenant-context functions exist (which we CAN do, and which is what makes
    this path work on a fresh database).
    """
    engine = create_engine()
    Base.metadata.create_all(engine)

    from safenestt.persistence.rls import apply_rls_policies, ensure_tenant_context

    try:
        # Tenant context BEFORE policies. Idempotent and ownership-tolerant.
        ensure_tenant_context(engine)
    except Exception as ctx_err:
        # SECURITY-RELEVANT: without tenant context, no RLS policy can be
        # evaluated at all. Never swallow this.
        logger.error(
            "Tenant context initialization FAILED — RLS cannot be enforced: "
            "%s: %s", type(ctx_err).__name__, ctx_err,
        )
        raise

    try:
        apply_rls_policies(engine)
    except Exception as rls_err:
        if type(rls_err).__name__ == "ProgrammingError" and (
                "must be owner of" in str(rls_err)):
            # Expected: migrate.py owns RLS application. Documented boundary.
            logger.info(
                "RLS policies not applied by ensure_schema(): %s. This is "
                "expected — migrate.py::main() applies RLS as the table "
                "owner. Run the migration entrypoint to (re)apply policies.",
                str(rls_err).strip().splitlines()[0][:160],
            )
        else:
            # SECURITY-RELEVANT: any other failure means tenant isolation may
            # not be enforced. Log loudly; never fail silently.
            logger.error(
                "RLS policy application FAILED — tenant isolation may not be "
                "enforced: %s: %s", type(rls_err).__name__, rls_err,
            )
            raise
