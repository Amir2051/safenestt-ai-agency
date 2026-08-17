from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.risk import calculate_risk
from safenestt.investigations.store import InvestigationService
from safenestt.investigations.reality import RealityChecker
from safenestt.model.provider import ModelProvider, ModelRequest, ModelResponse
from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel
from safenestt.security.approval import ApprovalService
from safenestt.security.audit import AuditEvent, AuditLogger
from safenestt.security.pipeline import SecurityPipeline
from safenestt.security.permissions import PermissionManager
from safenestt.security.rate_limit import RateLimitService
from safenestt.tools.dns import DNSAdapter
from safenestt.tools.interface import ToolInterface
from safenestt.tools.manifest import ToolManifest
from safenestt.tools.registry import tool_registry


MAX_TOOL_CALLS = 5


def _now() -> datetime:
    return datetime.utcnow()


def _stable_id() -> str:
    return str(uuid.uuid4())


def _build_prompt(target: str, context: dict[str, Any] | None) -> str:
    ctx = context or {}
    return (
        "You are SafeNestT AI investigator. Target: " + target + ". "
        "Return JSON only with keys plan: list[str], findings: list[dict[str, Any]], finished: bool."
    )


def _parse_model_json(response: ModelResponse) -> dict[str, Any]:
    if not response.content:
        return {"plan": ["dns.lookup.lookup"], "findings": [], "finished": False}
    content = response.content.strip()
    if content.startswith("```"):
        content = "\n".join(content.splitlines()[1:])
    if content.endswith("```"):
        content = "\n".join(content.splitlines()[:-1])
    import json
    try:
        parsed = json.loads(content.strip())
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {"plan": ["dns.lookup.lookup"], "findings": [{"claim": content[:240]}], "finished": True}


def run_investigation(*, target: str, tenant_id: str | None = None, created_by: str | None = None, model_provider: ModelProvider | None = None, dry_run: bool = False) -> dict[str, Any]:
    permission_manager = PermissionManager()
    pipeline = SecurityPipeline(permission_manager=permission_manager, approval_service=ApprovalService(), rate_limit_service=RateLimitService(), audit_logger=AuditLogger())
    tool_interface = ToolInterface(permission_manager=permission_manager)
    store = InvestigationService()
    checker = RealityChecker()
    agent = AgentRecord(agent_id="investigator", name="Investigator", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.dns.lookup.lookup"], risk_level=RiskLevel.LOW)

    investigation_id = _stable_id()
    record = store.create(investigation_id=investigation_id, target=target, tenant_id=tenant_id, created_by=created_by, type="domain")
    store.start(investigation_id)
    store.analyzing(investigation_id)

    provider = model_provider or ModelProvider()
    health = provider.health_check()
    if health.warnings and "provider_not_configured" in health.warnings:
        store.fail(investigation_id)
        return {
            "investigation_id": investigation_id,
            "status": "FAILED",
            "error": {"code": "not_configured", "message": "Live model provider is not configured. Set MODEL_API_KEY/MODEL_BASE_URL."},
            "findings": store.list_findings(investigation_id),
            "evidence": [evidence.__dict__ for evidence in store.list_evidence(investigation_id)],
        }

    prompt = _build_prompt(target, {"investigation_id": investigation_id})
    plan_response = provider.generate(ModelRequest(prompt=prompt, model=getattr(provider, "default_model", None) or "unknown", response_format="json"))
    plan = _parse_model_json(plan_response)

    dns_manifest = tool_registry.get("dns.lookup")
    permission_manager.granted_permissions[agent.agent_id] = {"tools.dns.lookup.lookup"}
    adapter = DNSAdapter()

    evidence_items: list[EvidenceRecord] = []
    findings: list[FindingRecord] = []
    tool_calls = 0
    pending_plan = plan.get("plan", [])[:MAX_TOOL_CALLS]
    while tool_calls < MAX_TOOL_CALLS and pending_plan:
        action = pending_plan.pop(0)
        capability = f"tools.{action}"
        tool_calls += 1
        pipeline_decision = pipeline.authorize(agent, capability, payload={"target": target}, organization_id=tenant_id, tool_id="dns.lookup", provider=getattr(provider, "provider_name", None), model=getattr(provider, "default_model", None))
        if pipeline_decision.decision != "ALLOW":
            findings.append(FindingRecord(investigation_id=investigation_id, finding_id=_stable_id(), claim=f"Tool request denied: {capability}", reality_status="AI_INFERENCE", factors={"reason": pipeline_decision.reason}))
            store.add_finding(findings[-1])
            break
        manifest = dns_manifest or ToolManifest(tool_id="dns.lookup", name="DNS Lookup", description="", provider="dns", actions=["lookup"], enabled=True, risk_level="LOW")
        result = tool_interface.execute(agent, capability, {"target": target}, manifest=manifest, adapter=adapter)
        tool_result = result.get("result", {}) if isinstance(result, dict) else {}
        evidence = EvidenceRecord(
            investigation_id=investigation_id,
            evidence_id=_stable_id(),
            source=manifest.tool_id,
            source_type="tool",
            target=target,
            observed_at=_now(),
            data=tool_result.get("data", {}),
            confidence=1.0 if tool_result.get("status") == "success" else 0.0,
            provenance="dns.lookup",
        )
        evidence_items.append(evidence)
        store.add_evidence(evidence)
        evidence_summary = "; ".join([str(item.data) for item in evidence_items[-2:]])
        followup = provider.generate(ModelRequest(prompt=f"Target: {target}. Evidence so far: {evidence_summary}. Return JSON with plan, findings, finished.", model=getattr(provider, "default_model", None) or "unknown", response_format="json"))
        parsed = _parse_model_json(followup)
        pending_plan = parsed.get("plan", [])[: MAX_TOOL_CALLS - tool_calls]
        if parsed.get("finished"):
            break

    for raw in plan.get("findings", []):
        claim = raw.get("claim") if isinstance(raw, dict) else str(raw)
        if not claim:
            continue
        finding = FindingRecord(investigation_id=investigation_id, finding_id=_stable_id(), claim=claim, evidence_ids=[item.evidence_id for item in evidence_items])
        evaluated = checker.evaluate(finding)
        finding.reality_status = evaluated.reality_status
        findings.append(finding)
        store.add_finding(finding)

    if not findings:
        fallback = FindingRecord(investigation_id=investigation_id, finding_id=_stable_id(), claim="No findings produced by model", evidence_ids=[item.evidence_id for item in evidence_items])
        evaluated = checker.evaluate(fallback)
        fallback.reality_status = evaluated.reality_status
        findings.append(fallback)
        store.add_finding(fallback)

    risk = calculate_risk(findings)
    store.complete(investigation_id)
    return {
        "investigation_id": investigation_id,
        "status": "COMPLETED",
        "target": target,
        "tenant_id": tenant_id,
        "created_by": created_by,
        "tool_calls": tool_calls,
        "evidence": [evidence.__dict__ for evidence in evidence_items],
        "findings": [finding.__dict__ for finding in findings],
        "risk": risk,
        "model_provider": getattr(provider, "provider_name", None),
        "model": getattr(provider, "default_model", None),
    }
