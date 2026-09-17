from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance


class EvidenceAgent(BaseAgent):
    role = "evidence"
    allowed_tools = []

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        evidence_refs = inputs.get("evidence_ids") or []
        findings: list[Finding] = []
        findings.append(Finding(
            finding_id="",
            finding_type="VERIFIED_EVIDENCE",
            title="Evidence intake registered",
            description=f"Registered {len(evidence_refs)} evidence item(s) for processing.",
            confidence=0.95,
            status="open",
            requires_human_review=False,
            provenance=self._provenance(run),
            metadata={"evidence_count": len(evidence_refs), "evidence_ids": evidence_refs},
        ))
        run.outputs = {"evidence_count": len(evidence_refs)}
        return self.complete(run, {"findings": [self._serialize(f) for f in findings]})

    def _provenance(self, run: AgentRun) -> Provenance:
        return Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            source="platform.evidence",
        )

    @staticmethod
    def _serialize(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
