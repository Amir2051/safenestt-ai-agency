from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
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
from safenestt.security.audit import AuditLogger


class FakeAgentRecord:
    agent_id = "test-agent"
    organization_id = "org-1"
    capabilities = []
    status = AgentStatus.ACTIVE
    risk_level = RiskLevel.LOW
    enabled = True


def _permission_manager():
    # Agent unit tests verify agent behavior, not audit persistence — use the
    # in-memory audit logger so they don't require a tenant-scoped DB session.
    pm = PermissionManager(audit_logger=AuditLogger())
    for agent_id in ["test-agent", "evidence", "osint", "threat_intel", "crypto", "fraud_analysis", "report"]:
        pm.granted_permissions[agent_id] = {"intel.read", "threat.read", "crypto.read", "*"}
    return pm


def _run_inputs(case_id: str = "case-1", investigation_id: str = "inv-1"):
    return {"case_id": case_id, "investigation_id": investigation_id, "created_by": "user-1"}


# ---------------------------------------------------------------------------
# Mock external DNS/WHOIS lookups used by osint_profiler and cyber_intel_threat
# ---------------------------------------------------------------------------

def _make_shodan_mock(query: str):
    """Return mock data that looks like a successful shodan_domain lookup."""
    return {
        "data": {
            "domain": query,
            "registrar": {"name": "MarkMonitor", "created": "2005-01-01"},
            "dns": {"a": ["93.184.216.34"], "mx": ["10 inbound.example.com"]},
            "whois": {"registrar": "MarkMonitor", "created_date": "2005-01-01"},
            "http": {"status": 200, "title": "Example Domain"},
            "source": "shodan_domain",
            "summary": f"DNS and WHOIS data for {query}",
        },
        "status": "success",
        "tool_id": "cyber_intel.threat_intel",
    }


def _make_osint_mock(query: str, query_type: str):
    """Return mock data that looks like a successful osint_profiler run."""
    return {
        "findings": {
            "whois": {"count": 1, "titles": [f"{query} registration"], "urls": []},
            "dns": {"count": 2, "titles": [], "urls": [f"https://{query}/"]},
        },
        "query": query,
        "query_type": query_type,
        "timestamp": "2026-01-01T00:00:00Z",
    }


@pytest.fixture(autouse=True)
def _mock_external_lookups(monkeypatch):
    """Stub external DNS/WHOIS/OSINT lookups for deterministic fast tests."""
    # Mock check_shodan_domain (used by threat_intel_agent for shodan_domain)
    def mock_shodan_domain(query: str):
        return _make_shodan_mock(query)

    # Mock check_shodan_host (used by threat_intel_agent for shodan_host)
    def mock_shodan_host(query: str):
        return _make_shodan_mock(query)

    # Mock run_osint_profile (used by osint_agent as fallback)
    def mock_run_osint(query: str, query_type: str):
        return _make_osint_mock(query, query_type)

    # Mock scan_dehashed_sync and scan_paste_sites_sync (used by threat_intel_agent)
    def mock_dehashed(query: str, query_type: str):
        return [{"source": "dehashed", "query": query, "type": query_type, "count": 0}]

    def mock_paste(query: str):
        return [{"source": "paste_sites", "query": query, "count": 0}]

    monkeypatch.setattr("modules.osint_profiler.check_shodan_domain", mock_shodan_domain)
    monkeypatch.setattr("modules.osint_profiler.check_shodan_host", mock_shodan_host)
    monkeypatch.setattr("modules.osint_profiler.run_osint_profile", mock_run_osint)
    monkeypatch.setattr("modules.darkweb_monitor.scan_dehashed_sync", mock_dehashed)
    monkeypatch.setattr("modules.darkweb_monitor.scan_paste_sites_sync", mock_paste)


def test_osint_agent_returns_external_intelligence_findings() -> None:
    agent = OsintAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-1", agent_id="osint")
    result = agent.execute(run, {"indicators": {"email": "user@example.com"}, **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert all(f["finding_type"] == "EXTERNAL_INTELLIGENCE" for f in findings)


def test_threat_intel_agent_handles_domain() -> None:
    agent = ThreatIntelAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-2", agent_id="threat_intel")
    result = agent.execute(run, {"indicators": {"domain": "example.com"}, **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings, "Expected at least one finding from threat intel"
    # shodan_domain via mock should return data
    shodan_findings = [f for f in findings if "shodan_domain" in f.get("title", "")]
    assert shodan_findings, f"Expected shodan_domain finding, got: {[f.get('title') for f in findings]}"
    assert shodan_findings[0]["finding_type"] == "EXTERNAL_INTELLIGENCE"
    assert shodan_findings[0]["confidence"] > 0, "Shodan should return data for example.com"


def test_crypto_agent_handles_wallet() -> None:
    agent = CryptoAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-3", agent_id="crypto")
    result = agent.execute(run, {"indicators": {"wallet_address": "0xabc123"}, **_run_inputs()})
    assert result.status == "completed"


def test_evidence_agent_creates_verified_findings() -> None:
    agent = EvidenceAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-4", agent_id="evidence")
    result = agent.execute(run, {"evidence_ids": ["ev-1"], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "VERIFIED_EVIDENCE"


def test_fraud_analysis_marks_inference_only() -> None:
    agent = FraudAnalysisAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-5", agent_id="fraud_analysis")
    result = agent.execute(run, {"agent_findings": [{"title": "x"}], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "AI_INFERENCE"


def test_report_agent_requires_approved_findings() -> None:
    agent = ReportAgent(FakeAgentRecord(), permission_manager=_permission_manager())
    run = AgentRun(run_id="run-6", agent_id="report")
    result = agent.execute(run, {"approved_findings": [{"title": "ok", "confidence": 1.0}], **_run_inputs()})
    assert result.status == "completed"
    findings = result.outputs.get("findings") or []
    assert findings
    assert findings[0]["finding_type"] == "INVESTIGATOR_CONCLUSION"


def test_orchestrator_runs_conditional_agents() -> None:
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
