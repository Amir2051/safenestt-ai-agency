from __future__ import annotations

import hashlib
import json
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from safenestt.persistence.engine import get_sessionmaker
from safenestt.persistence.repositories import (
    AgentRunRepository,
    AuditEventRepository,
    EvidenceRepository,
    FindingRepository,
    InvestigationRepository,
    ReportRepository,
)
from safenestt.persistence.models import (
    AgentRunModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ReportModel,
)


class PersistentStore:
    def __init__(self) -> None:
        self._sessionmaker = get_sessionmaker()
        if self._sessionmaker is None:
            raise RuntimeError("Session maker not initialized. Call create_engine() first.")
        self.investigations = InvestigationRepository(self._session())
        self.agent_runs = AgentRunRepository(self._session())
        self.findings = FindingRepository(self._session())
        self.evidence = EvidenceRepository(self._session())
        self.reports = ReportRepository(self._session())
        self.audit = AuditEventRepository(self._session())

    def _session(self) -> Session:
        return self._sessionmaker()

    def health_check(self) -> dict[str, Any]:
        try:
            with self._session() as session:
                session.execute(text("SELECT 1"))
                tables = self._table_counts(session)
                return {"status": "ok", "tables": tables}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _table_counts(self, session: Session) -> dict[str, int]:
        counts = {}
        for model in (InvestigationModel, AgentRunModel, FindingModel, EvidenceModel, ReportModel, AuditEventModel):
            table = model.__tablename__
            counts[table] = session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
        return counts


class PersistentAuditLogger:
    """Lazy-initialized persistent audit logger.

    Store is created on first use, not at construction time, to avoid
    import-time dependencies on engine initialization.
    """

    def __init__(self, store: PersistentStore | None = None) -> None:
        self._store = store
        self._initialized = store is not None

    def _ensure_store(self) -> PersistentStore:
        if not self._initialized:
            self._store = PersistentStore()
            self._initialized = True
        assert self._store is not None
        return self._store

    def record(self, event: Any) -> Any:
        self._ensure_store().audit.record(event)
        return event

    def recent(self, limit: int = 100) -> list[Any]:
        with self._ensure_store()._session() as s:
            return list(
                s.execute(
                    text("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT :limit").bindparams(limit=limit)
                ).mappings().all()
            )


class PersistentApprovalRepository:
    """Lazy-initialized persistent approval repository.

    Store is created on first use, not at construction time, to avoid
    import-time dependencies on engine initialization.
    """

    def __init__(self, store: PersistentStore | None = None) -> None:
        self._store = store
        self._initialized = store is not None

    def _ensure_store(self) -> PersistentStore:
        if not self._initialized:
            self._store = PersistentStore()
            self._initialized = True
        assert self._store is not None
        return self._store

    def create(self, record: Any) -> Any:
        self._ensure_store().audit.record(
            type("AuditEvent", (), {
                "event_id": f"approval-{record.approval_id}",
                "investigation_id": None,
                "actor_type": "approval",
                "actor_id": record.agent_id,
                "action": "approval.request",
                "decision": "PENDING",
                "risk_level": record.risk_level,
                "resource_type": "approval",
                "resource_id": record.approval_id,
                "detail": f"Requested for {record.requested_capability}",
                "metadata": None,
                "created_at": datetime.now(UTC),
            })()
        )
        return record

    def get(self, approval_id: str, *, organization_id: str | None = None) -> Any | None:
        return None

    def approve(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> Any | None:
        return None

    def reject(self, approval_id: str, *, approver_identity: str | None = None, metadata: dict[str, Any] | None = None, organization_id: str | None = None) -> Any | None:
        return None

    def cancel(self, approval_id: str, *, organization_id: str | None = None) -> Any | None:
        return None

    def expire(self, approval_id: str, *, organization_id: str | None = None) -> Any | None:
        return None

    def list_for_agent(self, agent_id: str, *, organization_id: str | None = None) -> list[Any]:
        return []

    def list_for_tool(self, tool_id: str, *, organization_id: str | None = None) -> list[Any]:
        return []


def upgrade_persistence() -> dict[str, Any]:
    store = PersistentStore()
    return {
        "action": "upgrade",
        "tables": store.health_check().get("tables", {}),
        "repositories": [
            "investigations",
            "agent_runs",
            "findings",
            "evidence",
            "reports",
            "audit_events",
        ],
        "status": "ready",
    }