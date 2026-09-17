from __future__ import annotations

import pytest

from safenestt.agents.base import AgentRun
from safenestt.agents.crypto_agent import CryptoAgent
from safenestt.agents.evidence_agent import EvidenceAgent
from safenestt.agents.fraud_analysis_agent import FraudAnalysisAgent
from safenestt.agents.osint_agent import OsintAgent
from safenestt.agents.report_agent import ReportAgent
from safenestt.agents.threat_intel_agent import ThreatIntelAgent
from safenestt.investigation.orchestrator import InvestigationOrchestrator
from safenestt.registry import AgentRecord, AgentStatus, RiskLevel
from safenestt.schemas.findings import Investigation
from safenestt.security.permissions import PermissionManager


class FakeAgentRecord:
    agent_id = "test-agent"
    organization_id = "org-1"
    capabilities = []
    status = AgentStatus.ACTIVE
    risk_level = RiskLevel.LOW
    enabled = True


def _permission_manager():
    pm = PermissionManager()
    for agent_id in ["test-agent", "evidence", "osint", "threat_intel", "crypto", "fraud_analysis", "report"]:
        pm.granted_permissions[agent_id] = {"intel.read", "threat.read", "crypto.read", "*"}
    return pm


def _run_inputs(case_id: str = "case-1", investigation_id: str = "inv-1"):
    return {"case_id": case_id, "investigation_id": investigation_id, "created_by": "user-1"}


def test_osint_agent_returns_external_intelligence_findings():
    agent = OsintAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-1", agent_id="osint")
    result = agent.execute(run, {"indicators": {"email": "user@example.com"}, **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert all(f["finding_type"] == "EXTERNAL_INTELLIGENCE" for f in findings)


def test_threat_intel_agent_handles_domain():
    agent = ThreatIntelAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-2", agent_id="threat_intel")
    result = agent.execute(run, {"indicators": {"domain": "example.com"}, **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings, "Expected at least one finding from threat intel"
    # shodan_domain via dig+whois should return real data
    shodan_findings = [f for f in findings if "shodan_domain" in f.get("title", "")]
    assert shodan_findings, f"Expected shodan_domain finding, got: {[f.get('title') for f in findings]}"
    assert shodan_findings[0]["finding_type"] == "EXTERNAL_INTELLIGENCE"
    assert shodan_findings[0]["confidence"] > 0, "Shodan should return data for example.com"


def test_crypto_agent_handles_wallet():
    agent = CryptoAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-3", agent_id="crypto")
    result = agent.execute(run, {"indicators": {"wallet_address": "0xabc123"}, **_run_inputs()})
    assert result.status == "completed"


def test_evidence_agent_creates_verified_findings():
    agent = EvidenceAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-4", agent_id="evidence")
    result = agent.execute(run, {"evidence_ids": ["ev-1"], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "VERIFIED_EVIDENCE"


def test_fraud_analysis_marks_inference_only():
    agent = FraudAnalysisAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-5", agent_id="fraud_analysis")
    result = agent.execute(run, {"agent_findings": [{"title": "x"}], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "AI_INFERENCE"


def test_report_agent_requires_approved_findings():
    agent = ReportAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-6", agent_id="report")
    result = agent.execute(run, {"approved_findings": [{"title": "ok", "confidence": 1.0}], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "INVESTIGATOR_CONCLUSION"


def test_orchestrator_runs_conditional_agents():
    orchestrator = InvestigationOrchestrator(permission_manager=_permission_manager())
    investigation = Investigation(investigation_id="inv-1", case_id="case-1")
    inputs = {
        "indicators": {"email": "user@example.com", "wallet_address": "0xabc", "domain": "example.com"},
        "evidence_ids": ["ev-1"],
        **_run_inputs(),
    }
    result = orchestrator.orchestrate(investigation, inputs)
    assert result["status"] == "completed"
    assert result["findings"]
    assert result["approved_findings"] >= 0
