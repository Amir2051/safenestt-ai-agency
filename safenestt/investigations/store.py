from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord


class TenantIsolationError(PermissionError):
    """Raised when a cross-tenant access attempt is detected."""
    pass


class InvestigationStore:
    def __init__(self) -> None:
        self._investigations: dict[str, InvestigationRecord] = {}
        self._evidence: dict[str, list[EvidenceRecord]] = {}
        self._findings: dict[str, list[FindingRecord]] = {}

    def create_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        self._investigations[record.investigation_id] = record
        self._evidence.setdefault(record.investigation_id, [])
        self._findings.setdefault(record.investigation_id, [])
        return record

    def get_investigation(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self._investigations.get(investigation_id)
        if record is None:
            return None
        if tenant_id is not None and record.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"investigation {investigation_id} not found for tenant {tenant_id}"
            )
        return record

    def update_investigation(self, record: InvestigationRecord, tenant_id: str | None = None) -> InvestigationRecord:
        if tenant_id is not None and record.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"investigation {record.investigation_id} not found for tenant {tenant_id}"
            )
        self._investigations[record.investigation_id] = record
        return record

    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        self._evidence.setdefault(evidence.investigation_id, []).append(evidence)
        inv = self._investigations.get(evidence.investigation_id)
        if inv:
            inv.updated_at = datetime.utcnow()
        return evidence

    def list_evidence(self, investigation_id: str, tenant_id: str | None = None) -> list[EvidenceRecord]:
        inv = self._investigations.get(investigation_id)
        if inv is None:
            return []
        if tenant_id is not None and inv.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"investigation {investigation_id} not found for tenant {tenant_id}"
            )
        return list(self._evidence.get(investigation_id, []))

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        self._findings.setdefault(finding.investigation_id, []).append(finding)
        inv = self._investigations.get(finding.investigation_id)
        if inv:
            inv.updated_at = datetime.utcnow()
        return finding

    def list_findings(self, investigation_id: str, tenant_id: str | None = None) -> list[FindingRecord]:
        inv = self._investigations.get(investigation_id)
        if inv is None:
            return []
        if tenant_id is not None and inv.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"investigation {investigation_id} not found for tenant {tenant_id}"
            )
        return list(self._findings.get(investigation_id, []))

    def list_investigations(self, tenant_id: str | None = None) -> list[InvestigationRecord]:
        records = list(self._investigations.values())
        if tenant_id is not None:
            records = [r for r in records if r.tenant_id == tenant_id]
        return records


class InvestigationService:
    def __init__(self, store: InvestigationStore | None = None) -> None:
        self.store = store or InvestigationStore()

    def create(self, *, investigation_id: str, target: str, tenant_id: str | None = None, created_by: str | None = None, type: str = "domain") -> InvestigationRecord:
        record = InvestigationRecord(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            created_by=created_by,
            target=target,
            type=type,
            status="QUEUED",
        )
        return self.store.create_investigation(record)

    def get_investigation(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        return self.store.get_investigation(investigation_id, tenant_id=tenant_id)

    def start(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("RUNNING")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def complete(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("COMPLETED")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def fail(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("FAILED")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def analyzing(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("ANALYZING")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def waiting(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("WAITING_FOR_TOOL")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def verifying(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("VERIFYING")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def calculating_risk(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("CALCULATING_RISK")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def cancel(self, investigation_id: str, tenant_id: str | None = None) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id, tenant_id=tenant_id)
        if not record:
            return None
        record.mark("CANCELLED")
        return self.store.update_investigation(record, tenant_id=tenant_id)

    def list_evidence(self, investigation_id: str, tenant_id: str | None = None) -> list[EvidenceRecord]:
        return self.store.list_evidence(investigation_id, tenant_id=tenant_id)

    def list_findings(self, investigation_id: str, tenant_id: str | None = None) -> list[FindingRecord]:
        return self.store.list_findings(investigation_id, tenant_id=tenant_id)

    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        return self.store.add_evidence(evidence)

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        return self.store.add_finding(finding)

    def list_investigations(self, tenant_id: str | None = None) -> list[InvestigationRecord]:
        return self.store.list_investigations(tenant_id=tenant_id)
