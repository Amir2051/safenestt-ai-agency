from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from safenestt.investigations.records import FindingRecord


@dataclass
class RealityResult:
    finding_id: str
    reality_status: str
    contradictions: list[str]
    unsupported_claims: list[str]
    evidence_supported_claims: list[str]


class RealityChecker:
    def __init__(self, evidence_lookup=None) -> None:
        self.evidence_lookup = evidence_lookup

    def evaluate(self, finding: FindingRecord) -> RealityResult:
        supported: list[str] = []
        unsupported: list[str] = []
        contradictions: list[str] = []
        if not finding.evidence_ids:
            unsupported.append(finding.claim)
            return RealityResult(
                finding_id=finding.finding_id,
                reality_status="AI_INFERENCE",
                contradictions=contradictions,
                unsupported_claims=unsupported,
                evidence_supported_claims=supported,
            )
        if self.evidence_lookup is not None:
            missing = [evidence_id for evidence_id in finding.evidence_ids if self.evidence_lookup(finding.investigation_id, evidence_id) is None]
            if missing:
                unsupported.append(finding.claim)
                return RealityResult(
                    finding_id=finding.finding_id,
                    reality_status="AI_INFERENCE",
                    contradictions=contradictions,
                    unsupported_claims=unsupported,
                    evidence_supported_claims=supported,
                )
        supported.append(finding.claim)
        return RealityResult(
            finding_id=finding.finding_id,
            reality_status="EVIDENCE_SUPPORTED",
            contradictions=contradictions,
            unsupported_claims=unsupported,
            evidence_supported_claims=supported,
        )
