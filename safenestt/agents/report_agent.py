from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance


class ReportAgent(BaseAgent):
    role = "report"
    allowed_tools = []

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        approved_findings = inputs.get("approved_findings") or []
        findings: list[Finding] = []
        for item in approved_findings:
            findings.append(Finding(
                finding_id="",
                finding_type="INVESTIGATOR_CONCLUSION",
                title=f"Approved finding: {item.get('title') or item.get('finding_type')}",
                description=item.get("description") or "Investigator-approved finding included in report.",
                confidence=float(item.get("confidence") or 0.0),
                status="completed",
                requires_human_review=False,
                provenance=self._provenance(run),
                metadata={"source_finding_type": item.get("finding_type"), "limitations": ["Report reflects approved findings only."]},
            ))
        run.outputs = {"report_finding_count": len(findings)}
        return self.complete(run, {"findings": [self._serialize(f) for f in findings]})

    def _provenance(self, run: AgentRun) -> Provenance:
        return Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            source="platform.report",
        )

    @staticmethod
    def _serialize(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
