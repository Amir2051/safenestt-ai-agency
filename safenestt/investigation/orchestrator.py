from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from safenestt.agents.crypto_agent import CryptoAgent
from safenestt.agents.evidence_agent import EvidenceAgent
from safenestt.agents.fraud_analysis_agent import FraudAnalysisAgent
from safenestt.agents.osint_agent import OsintAgent
from safenestt.agents.report_agent import ReportAgent
from safenestt.agents.threat_intel_agent import ThreatIntelAgent
from safenestt.registry import AgentRecord, AgentStatus
from safenestt.schemas.findings import AgentRun, Finding, Investigation, Provenance
from safenestt.security.permissions import PermissionManager


class InvestigationOrchestrator:
    def __init__(self, permission_manager: PermissionManager | None = None) -> None:
        self.permission_manager = permission_manager or PermissionManager()

    def orchestrate(self, investigation: Investigation, inputs: dict[str, Any]) -> dict[str, Any]:
        indicators = inputs.get("indicators") or {}
        evidence_ids = inputs.get("evidence_ids") or []
        runs: list[AgentRun] = []
        findings: list[Finding] = []

        if evidence_ids:
            evidence_run = self._run_agent(EvidenceAgent, investigation, "evidence", {"evidence_ids": evidence_ids, **inputs})
            runs.append(evidence_run)
            findings.extend(self._findings_from_run(evidence_run))

        osint_indicators = {k: v for k, v in indicators.items() if k in {"email", "domain", "ip_address", "username", "phone"} and v}
        if osint_indicators:
            osint_run = self._run_agent(OsintAgent, investigation, "osint", {"indicators": osint_indicators, **inputs})
            runs.append(osint_run)
            findings.extend(self._findings_from_run(osint_run))

        threat_indicators = {k: v for k, v in indicators.items() if k in {"domain", "ip_address"} and v}
        if threat_indicators:
            threat_run = self._run_agent(ThreatIntelAgent, investigation, "threat_intel", {"indicators": threat_indicators, **inputs})
            runs.append(threat_run)
            findings.extend(self._findings_from_run(threat_run))

        crypto_indicators = {k: v for k, v in indicators.items() if k in {"wallet_address", "transaction_hash"} and v}
        if crypto_indicators:
            chain = str(inputs.get("chain") or "eth").strip().lower()
            crypto_run = self._run_agent(CryptoAgent, investigation, "crypto", {"indicators": crypto_indicators, "chain": chain, **inputs})
            runs.append(crypto_run)
            findings.extend(self._findings_from_run(crypto_run))

        if findings:
            fraud_run = self._run_agent(
                FraudAnalysisAgent,
                investigation,
                "fraud_analysis",
                {"agent_findings": [self._serialize_finding(f) for f in findings], **inputs},
            )
            runs.append(fraud_run)
            findings.extend(self._findings_from_run(fraud_run))

        approved = [f for f in findings if f.status == "approved"]
        if not approved and findings:
            approved = findings[:1]

        if approved:
            report_run = self._run_agent(ReportAgent, investigation, "report", {"approved_findings": [self._serialize_finding(f) for f in approved], **inputs})
            runs.append(report_run)
            findings.extend(self._findings_from_run(report_run))

        return {
            "investigation_id": investigation.investigation_id,
            "status": "completed",
            "agent_runs": [self._serialize_run(r) for r in runs],
            "findings": [self._serialize_finding(f) for f in findings],
            "approved_findings": len(approved),
        }

    def _run_agent(self, agent_cls, investigation: Investigation, role: str, inputs: dict[str, Any]) -> AgentRun:
        agent_id = inputs.get(f"{role}_agent_id") or role
        run_id = f"run-{uuid.uuid4()}"
        run = AgentRun(run_id=run_id, agent_id=agent_id, task_id=inputs.get("task_id"), inputs=inputs)
        agent = agent_cls.__new__(agent_cls)
        agent.role = role
        agent.allowed_tools = getattr(agent_cls, "allowed_tools", [])
        agent.agent = AgentRecord(
            agent_id=agent_id,
            name=f"{role.capitalize()} Agent",
            capabilities=agent.allowed_tools,
            status=AgentStatus.ACTIVE,
            enabled=True,
        )
        agent.permission_manager = self.permission_manager
        from safenestt.tools.interface import ToolInterface
        agent.tool_interface = ToolInterface(permission_manager=self.permission_manager)
        # Initialize adapter if the agent class defines one (for agents created via __new__)
        if hasattr(agent_cls, 'adapter_cls'):
            agent.adapter = agent_cls.adapter_cls()
        # Grant permissions for this agent's capabilities before execution
        for cap in agent.allowed_tools:
            self.permission_manager.granted_permissions.setdefault(agent_id, set()).add(cap)
        return agent.execute(run, inputs)

    @staticmethod
    def _findings_from_run(run: AgentRun) -> list[Finding]:
        outputs = run.outputs or {}
        raw = outputs.get("findings") or []
        findings: list[Finding] = []
        for item in raw:
            if isinstance(item, dict):
                provenance_data = item.get("provenance") or {}
                if isinstance(provenance_data, dict):
                    provenance = Provenance(**provenance_data)
                else:
                    provenance = None
                findings.append(Finding(
                    finding_id=item.get("finding_id", ""),
                    finding_type=item.get("finding_type", "AI_INFERENCE"),
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    confidence=float(item.get("confidence") or 0.0),
                    status=item.get("status", "open"),
                    requires_human_review=bool(item.get("requires_human_review", True)),
                    provenance=provenance,
                    metadata=item.get("metadata") or {},
                ))
        return findings

    @staticmethod
    def _serialize_run(run: AgentRun) -> dict[str, Any]:
        return {
            "run_id": run.run_id,
            "agent_id": run.agent_id,
            "task_id": run.task_id,
            "status": run.status,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "error": run.error,
            "retry_count": run.retry_count,
            "tool_calls": run.tool_calls,
        }

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
