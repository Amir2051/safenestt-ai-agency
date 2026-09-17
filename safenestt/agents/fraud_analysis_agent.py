from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance


class FraudAnalysisAgent(BaseAgent):
    role = "fraud_analysis"
    allowed_tools = []

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        agent_findings = inputs.get("agent_findings") or []
        findings: list[Finding] = []
        if agent_findings:
            findings.append(Finding(
                finding_id="",
                finding_type="AI_INFERENCE",
                title="Correlated fraud hypothesis",
                description="Aggregated agent findings suggest correlated indicators requiring investigator review.",
                confidence=0.55,
                status="open",
                requires_human_review=True,
                provenance=self._provenance(run),
                metadata={"agent_finding_count": len(agent_findings), "limitations": ["This is AI-generated inference, not verified evidence."]},
            ))
        run.outputs = {"hypothesis_count": len(findings)}
        return self.complete(run, {"findings": [self._serialize(f) for f in findings]})

    def _provenance(self, run: AgentRun) -> Provenance:
        return Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            source="ai.fraud_analysis",
        )

    @staticmethod
    def _serialize(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
