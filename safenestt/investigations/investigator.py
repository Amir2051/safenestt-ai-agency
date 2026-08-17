from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord, InvalidStatusError
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
from safenestt.security.redaction import redact
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


def run_investigation(*, investigation_id: str, target: str, tenant_id: str | None = None, created_by: str | None = None, model_provider: ModelProvider | None = None, store: InvestigationService | None = None, dry_run: bool = False) -> dict[str, Any]:
    store = store or InvestigationService()
    permission_manager = PermissionManager()
    pipeline = SecurityPipeline(permission_manager=permission_manager, approval_service=ApprovalService(), rate_limit_service=RateLimitService(), audit_logger=AuditLogger())
    tool_interface = ToolInterface(permission_manager=permission_manager)
    checker = RealityChecker(evidence_lookup=lambda investigation_id, evidence_id: next((e for e in store.list_evidence(investigation_id) if e.evidence_id == evidence_id), None))
    agent = AgentRecord(agent_id="investigator", name="Investigator", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.dns.lookup.lookup"], risk_level=RiskLevel.LOW)

    record = store.get_investigation(investigation_id)
    if not record:
        record = InvestigationRecord(investigation_id=investigation_id, tenant_id=tenant_id, created_by=created_by, target=target, type="domain", status="QUEUED")
        record = store.store.create_investigation(record)
    record.mark("RUNNING")
    record = store.store.update_investigation(record)
    record.mark("ANALYZING")
    record = store.store.update_investigation(record)

    provider = model_provider or ModelProvider()
    model_error: dict[str, Any] | None = None
    health = provider.health_check()
    if health.warnings and "provider_not_configured" in health.warnings:
        model_error = {"code": "not_configured", "message": "Live model provider is not configured. Set MODEL_API_KEY/MODEL_BASE_URL."}
    if model_error:
        record.error = model_error
        try:
            record.mark("FAILED")
        except InvalidStatusError:
            pass
        store.store.update_investigation(record)
        return {
            "investigation_id": investigation_id,
            "status": record.status,
            "target": target,
            "tenant_id": tenant_id,
            "created_by": created_by,
            "tool_calls": 0,
            "evidence": [],
            "findings": [],
            "risk": calculate_risk([]),
            "model_provider": getattr(provider, "provider_name", None),
            "model": getattr(provider, "default_model", None),
            "error": model_error,
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
        record.mark("WAITING_FOR_TOOL")
        record = store.store.update_investigation(record)
        tool_calls += 1
        pipeline_decision = pipeline.authorize(agent, capability, payload={"target": target}, organization_id=tenant_id, tool_id="dns.lookup", provider=getattr(provider, "provider_name", None), model=getattr(provider, "default_model", None))
        if pipeline_decision.decision != "ALLOW":
            finding = FindingRecord(investigation_id=investigation_id, finding_id=_stable_id(), claim=f"Tool request denied: {capability}", reality_status="AI_INFERENCE", factors={"reason": pipeline_decision.reason})
            evaluated = checker.evaluate(finding)
            finding.reality_status = evaluated.reality_status
            findings.append(finding)
            store.add_finding(finding)
            record.error = {"code": "TOOL_DENIED", "message": pipeline_decision.reason}
            try:
                record.mark("FAILED")
            except InvalidStatusError:
                pass
            store.store.update_investigation(record)
            break
        manifest = dns_manifest or ToolManifest(tool_id="dns.lookup", name="DNS Lookup", description="", provider="dns", actions=["lookup"], enabled=True, risk_level="LOW")
        result = tool_interface.execute(agent, capability, {"target": target}, manifest=manifest, adapter=adapter)
        tool_result = result.get("result", {}) if isinstance(result, dict) else {}
        tool_run_id = _stable_id()
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
            metadata={
                "tool_run_id": tool_run_id,
                "tool_action": capability,
                "tool_status": tool_result.get("status"),
                "tool_error": tool_result.get("error"),
                "redacted_metadata": redact(tool_result.get("metadata", {})),
            },
            tool_run_id=tool_run_id,
        )
        evidence_items.append(evidence)
        store.add_evidence(evidence)
        record.mark("VERIFYING")
        record = store.store.update_investigation(record)
        evidence_summary = "; ".join([str(item.data) for item in evidence_items[-2:]])
        followup = provider.generate(ModelRequest(prompt=f"Target: {target}. Evidence so far: {evidence_summary}. Return JSON with plan, findings, finished.", model=getattr(provider, "default_model", None) or "unknown", response_format="json"))
        parsed = _parse_model_json(followup)
        pending_plan = parsed.get("plan", [])[: MAX_TOOL_CALLS - tool_calls]
        if parsed.get("finished"):
            break

    record.mark("VERIFYING")
    record = store.store.update_investigation(record)
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

    record.mark("CALCULATING_RISK")
    record = store.store.update_investigation(record)
    risk = calculate_risk(findings)
    record.mark("COMPLETED")
    record = store.store.update_investigation(record)
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
