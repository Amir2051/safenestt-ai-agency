from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord


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

    def get_investigation(self, investigation_id: str) -> InvestigationRecord | None:
        return self._investigations.get(investigation_id)

    def update_investigation(self, record: InvestigationRecord) -> InvestigationRecord:
        self._investigations[record.investigation_id] = record
        return record

    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        self._evidence.setdefault(evidence.investigation_id, []).append(evidence)
        inv = self._investigations.get(evidence.investigation_id)
        if inv:
            inv.updated_at = datetime.utcnow()
        return evidence

    def list_evidence(self, investigation_id: str) -> list[EvidenceRecord]:
        return list(self._evidence.get(investigation_id, []))

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        self._findings.setdefault(finding.investigation_id, []).append(finding)
        inv = self._investigations.get(finding.investigation_id)
        if inv:
            inv.updated_at = datetime.utcnow()
        return finding

    def list_findings(self, investigation_id: str) -> list[FindingRecord]:
        return list(self._findings.get(investigation_id, []))


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

    def get_investigation(self, investigation_id: str) -> InvestigationRecord | None:
        return self.store.get_investigation(investigation_id)

    def start(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("RUNNING")
        return self.store.update_investigation(record)

    def complete(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("COMPLETED")
        return self.store.update_investigation(record)

    def fail(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("FAILED")
        return self.store.update_investigation(record)

    def analyzing(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("ANALYZING")
        return self.store.update_investigation(record)

    def waiting(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("WAITING_FOR_TOOL")
        return self.store.update_investigation(record)

    def verifying(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("VERIFYING")
        return self.store.update_investigation(record)

    def calculating_risk(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("CALCULATING_RISK")
        return self.store.update_investigation(record)

    def cancel(self, investigation_id: str) -> InvestigationRecord | None:
        record = self.store.get_investigation(investigation_id)
        if not record:
            return None
        record.mark("CANCELLED")
        return self.store.update_investigation(record)

    def list_evidence(self, investigation_id: str) -> list[EvidenceRecord]:
        return self.store.list_evidence(investigation_id)

    def list_findings(self, investigation_id: str) -> list[FindingRecord]:
        return self.store.list_findings(investigation_id)

    def add_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        return self.store.add_evidence(evidence)

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        return self.store.add_finding(finding)
