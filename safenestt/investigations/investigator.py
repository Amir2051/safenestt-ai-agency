from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord, InvalidStatusError
from safenestt.investigations.risk import calculate_risk
from safenestt.investigations.store import PersistentInvestigationStore, TenantIsolationError
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
            plan = parsed.get("plan", [])
            if isinstance(plan, list):
                validated: list[str] = []
                for action in plan:
                    if not isinstance(action, str) or not action.strip():
                        continue
                    action = action.strip()
                    if not action.startswith("tools."):
                        continue
                    parts = action.split(".")
                    if len(parts) < 3 or not parts[1] or not parts[-1]:
                        continue
                    validated.append(action)
                parsed["plan"] = validated or ["dns.lookup.lookup"]
            findings = parsed.get("findings", [])
            if not isinstance(findings, list):
                parsed["findings"] = []
            return parsed
    except Exception:
        pass
    return {"plan": ["dns.lookup.lookup"], "findings": [{"claim": content[:240]}], "finished": True}


def _case_context(target: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    try:
        parsed = __import__("json").loads(target)
        if not isinstance(parsed, dict):
            raise ValueError
    except Exception:
        return target, {"domain": target}, {}
    indicators: dict[str, Any] = {}
    intake = parsed.get("intake") or {}
    complainant_email = intake.get("complainant_email")
    complainant_phone = intake.get("complainant_phone")
    if complainant_email: indicators["email"] = complainant_email
    if complainant_phone: indicators["phone"] = complainant_phone
    for subject in intake.get("subjects") or []:
        for key, indicator_key in (("email", "email"), ("phone", "phone"), ("ip_address", "ip_address"), ("website_social_media", "domain")):
            value = subject.get(key) if isinstance(subject, dict) else None
            if value and indicator_key not in indicators:
                indicators[indicator_key] = value
    for transaction in intake.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        if transaction.get("recipient_wallet_address") and "wallet_address" not in indicators:
            indicators["wallet_address"] = transaction["recipient_wallet_address"]
        if transaction.get("transaction_id_hash") and "transaction_hash" not in indicators:
            indicators["transaction_hash"] = transaction["transaction_id_hash"]
    return str(parsed.get("description") or target), indicators, parsed


def run_investigation(*, investigation_id: str, target: str, tenant_id: str | None = None, created_by: str | None = None, model_provider: ModelProvider | None = None, store: PersistentInvestigationStore | None = None, dry_run: bool = False, api_key_hash: str | None = None) -> dict[str, Any]:
    if store is None:
        store = PersistentInvestigationStore(api_key_hash=api_key_hash)
    permission_manager = PermissionManager()
    pipeline = SecurityPipeline(permission_manager=permission_manager, approval_service=ApprovalService(), rate_limit_service=RateLimitService(), audit_logger=AuditLogger())
    tool_interface = ToolInterface(permission_manager=permission_manager)
    checker = RealityChecker(evidence_lookup=lambda investigation_id, evidence_id: next((e for e in store.list_evidence(investigation_id) if e.evidence_id == evidence_id), None))
    agent = AgentRecord(agent_id="investigator", name="Investigator", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.dns.lookup.lookup"], risk_level=RiskLevel.LOW)

    # Get or create the investigation record with tenant isolation
    try:
        record = store.get_investigation(investigation_id)
    except TenantIsolationError:
        record = None
    if not record:
        record = InvestigationRecord(investigation_id=investigation_id, tenant_id=tenant_id, created_by=created_by, target=target, type="domain", status="QUEUED")
        record = store.create_investigation(record)
    elif record.status in {"FAILED", "CANCELLED"}:
        record.mark("QUEUED")
        record.error = None
        record = store.update_investigation(record)
    record.mark("RUNNING")
    record = store.update_investigation(record)

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
        store.update_investigation(record)
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

    # ---- Multi-agent orchestration ----
    from safenestt.investigation.orchestrator import InvestigationOrchestrator
    from safenestt.schemas.findings import Investigation

    investigation_schema = Investigation(
        investigation_id=investigation_id,
        case_id=investigation_id,
        status="running",
    )

    human_target, indicators, case_context = _case_context(record.target or target)
    orchestrator = InvestigationOrchestrator(permission_manager=PermissionManager())
    orchestrator_inputs: dict[str, Any] = {
        "target": human_target,
        "investigation_id": investigation_id,
        "case_id": investigation_id,
        "created_by": created_by,
        "tenant_id": tenant_id,
        "indicators": indicators,
        "case_context": case_context,
    }

    try:
        orch_result = orchestrator.orchestrate(investigation_schema, orchestrator_inputs)
    except Exception as exc:
        record.error = {"code": "orchestration_failed", "message": str(exc)}
        try:
            record.mark("FAILED")
        except InvalidStatusError:
            pass
        store.update_investigation(record)
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
            "error": record.error,
        }

    model_response = provider.generate(ModelRequest(
        prompt=("You are the senior SafeNestT fraud investigator. Review the multi-agent findings below. "
                "Do not invent facts. Return a concise investigation synthesis and next steps.\n" +
                __import__("json").dumps(orch_result.get("findings", []), default=str)[:12000]),
        model=getattr(provider, "default_model", None),
        temperature=0.1,
        max_tokens=1200,
        response_format="json_object",
    ))
    if model_response.error:
        record.error = {"code": "model_synthesis_failed", "message": model_response.error.message}
        record.mark("FAILED")
        store.update_investigation(record)
        return {"investigation_id": investigation_id, "status": "FAILED", "target": target, "tenant_id": tenant_id, "created_by": created_by, "tool_calls": 0, "evidence": [], "findings": [], "risk": calculate_risk([]), "model_provider": getattr(provider, "provider_name", None), "model": getattr(provider, "default_model", None), "error": record.error}

    model_claim = (model_response.content or "").strip()
    # ---- Transform orchestrator output to API format ----
    evidence_items: list[EvidenceRecord] = []
    findings: list[FindingRecord] = []
    tool_calls = 0

    for run_data in orch_result.get("agent_runs", []):
        tool_calls += len(run_data.get("tool_calls", []))

    for finding_data in orch_result.get("findings", []):
        finding_id = finding_data.get("finding_id") or _stable_id()
        evidence_ids = finding_data.get("evidence_ids") or []
        # Create evidence from tool_calls if not already present
        for run_data in orch_result.get("agent_runs", []):
            for tc in run_data.get("tool_calls", []):
                if tc.get("status") == "ALLOW":
                    ev_id = _stable_id()
                    evidence_ids.append(ev_id)
                    evidence_items.append(EvidenceRecord(
                        investigation_id=investigation_id,
                        evidence_id=ev_id,
                        source=tc.get("capability", "unknown"),
                        source_type="tool",
                        target=target,
                        observed_at=_now(),
                        data={"tool_call": tc},
                        confidence=0.7 if tc.get("tool_status") == "success" else 0.0,
                        provenance=tc.get("capability"),
                        tool_run_id=_stable_id(),
                    ))
        finding = FindingRecord(
            investigation_id=investigation_id,
            finding_id=finding_id,
            claim=finding_data.get("description") or finding_data.get("title", "Orchestrator finding"),
            evidence_ids=evidence_ids,
            reality_status="AI_INFERENCE",
            risk_score=finding_data.get("confidence", 0.0),
        )
        evaluated = checker.evaluate(finding)
        finding.reality_status = evaluated.reality_status
        findings.append(finding)

    # Store evidence and findings
    for ev in evidence_items:
        store.add_evidence(ev)
    for finding in findings:
        store.add_finding(finding)

    if model_claim:
        model_finding = FindingRecord(
            investigation_id=investigation_id,
            finding_id=_stable_id(),
            claim=model_claim[:4000],
            evidence_ids=[item.evidence_id for item in evidence_items],
            reality_status="AI_INFERENCE",
            risk_score=0.5,
            factors={"model": getattr(provider, "default_model", None), "provider": getattr(provider, "provider_name", None)},
        )
        store.add_finding(model_finding)
        findings.append(model_finding)

    if not findings:
        fallback = FindingRecord(investigation_id=investigation_id, finding_id=_stable_id(), claim="No findings produced by orchestrator", evidence_ids=[item.evidence_id for item in evidence_items])
        evaluated = checker.evaluate(fallback)
        fallback.reality_status = evaluated.reality_status
        findings.append(fallback)
        store.add_finding(fallback)

    record.mark("VERIFYING")
    record = store.update_investigation(record)
    record.mark("CALCULATING_RISK")
    record = store.update_investigation(record)
    risk = calculate_risk(findings)
    record.mark("COMPLETED")
    record = store.update_investigation(record)

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
