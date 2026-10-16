from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

from safenestt.agents.crypto_agent import CryptoAgent
from safenestt.agents.evidence_agent import EvidenceAgent
from safenestt.agents.fraud_analysis_agent import FraudAnalysisAgent
from safenestt.agents.osint_agent import OsintAgent
from safenestt.agents.report_agent import ReportAgent
from safenestt.agents.threat_intel_agent import ThreatIntelAgent
from safenestt.registry import AgentRecord, AgentStatus
from safenestt.schemas.findings import AgentRun, Finding, Investigation, Provenance
from safenestt.security.audit import AuditEvent
from safenestt.security.permissions import PermissionManager

# External intelligence provider adapters (Phase 3)
from safenestt.tools.adapters.shodan import ShodanAdapter
from safenestt.tools.adapters.virustotal import VirusTotalAdapter
from safenestt.tools.adapters.firecrawl import FirecrawlAdapter
from safenestt.tools.adapters.hibp import HIBPAdapter as HibpAdapter
from safenestt.tools.adapters.hunter import HunterAdapter
from modules.crypto_tracer import EtherscanAdapter  # Etherscan lives in modules/, not adapters/


def _has_substantive_payload(value: Any) -> bool:
    """Reject empty provider envelopes as findings; keep them visible in agent-run output."""
    ignored = {"source", "query", "domain", "target", "timestamp", "collected_at", "count", "summary", "confidence", "score", "status", "message"}
    if value is None or value is False or value == 0:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(
            _has_substantive_payload(v)
            for k, v in value.items()
            if str(k).lower() not in ignored and not str(k).startswith("_")
        )
    if isinstance(value, (list, tuple, set)):
        return any(_has_substantive_payload(v) for v in value)
    return bool(value)


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

        # ---- External intelligence provider adapters (Phase 3) ----
        # Run providers alongside agents; provider failures never crash the investigation.
        providers = self._resolve_providers()
        provider_findings = self._run_providers_for_indicators(
            providers, indicators, investigation, inputs
        )
        for pf in provider_findings:
            runs.append(pf["run"])
            findings.extend(pf["findings"])

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

    # ---- Provider adapter resolution (Phase 3) ----

    def _resolve_providers(self) -> dict[str, Any]:
        """Instantiate all external intelligence provider adapters.

        Provider failures are caught and recorded, never crash the investigation.
        """
        providers: dict[str, Any] = {}
        provider_cls_map = [
            ("shodan", ShodanAdapter),
            ("virustotal", VirusTotalAdapter),
            ("firecrawl", FirecrawlAdapter),
            ("hibp", HibpAdapter),
            ("hunter", HunterAdapter),
            ("etherscan", EtherscanAdapter),
        ]
        for name, cls in provider_cls_map:
            try:
                providers[name] = cls()
            except Exception as exc:
                providers[name] = None
        return providers

    def _run_provider(
        self,
        provider: Any,
        capability: str,
        payload: dict[str, Any],
        run_id: str,
        agent_id: str,
    ) -> dict[str, Any] | None:
        """Run a single provider adapter with error containment.

        Provider failures are recorded but never crash the investigation.
        Emits an audit event for the provider execution.
        """
        if provider is None:
            return None
        start = datetime.now(UTC)
        try:
            result = provider.execute(None, capability, payload)
        except Exception as exc:
            result = {
                "status": "error",
                "error": f"provider_{getattr(provider, 'provider_name', 'unknown')}: {exc}",
                "data": {},
                "metadata": {},
            }
        # Emit audit event for provider execution
        try:
            latency_ms = int((datetime.now(UTC) - start).total_seconds() * 1000)
            status_label = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
            AuditEvent(
                event_id=f"provider-{agent_id}-{run_id}",
                actor_type="provider",
                actor_id=agent_id,
                action=capability,
                decision="ALLOW" if status_label == "success" else "DENY",
                risk_level="LOW",
                resource_type="provider_execution",
                resource_id=run_id,
                detail=f"Provider {getattr(provider, 'provider_name', 'unknown')} executed {capability}: {status_label}",
                metadata={
                    "provider": getattr(provider, "provider_name", "unknown"),
                    "capability": capability,
                    "target": payload.get("query", ""),
                    "status": status_label,
                    "latency_ms": latency_ms,
                    "case_id": payload.get("case_id"),
                    "investigation_id": payload.get("investigation_id"),
                    "tool_id": payload.get("tool_id"),
                },
            )
        except Exception as audit_err:
            # Audit emission is security-relevant: an audit failure must never
            # crash an investigation, but it must never be invisible either.
            logger.warning(
                "provider_audit_emit_failed provider=%s capability=%s error=%s",
                getattr(provider, "provider_name", "unknown"), capability,
                type(audit_err).__name__,
            )
        return result

    def _provider_findings_from_result(
        self,
        result: dict[str, Any],
        investigation: Investigation,
        run_id: str,
        agent_id: str,
        capability: str,
    ) -> list[Finding]:
        """Convert a provider adapter result into Finding records.

        Provider results use EXTERNAL_INTELLIGENCE classification.
        Provenance is populated from the full context propagated in the payload.
        """
        if not isinstance(result, dict):
            return []
        if result.get("status") != "success":
            return []
        data = result.get("data", {})
        if not isinstance(data, dict) or not _has_substantive_payload(data):
            # Empty/negative provider responses remain in agent_runs, but are not
            # promoted to threat findings merely because the request succeeded.
            return []

        findings: list[Finding] = []
        provider_name = result.get("metadata", {}).get("provider", "external")
        action = result.get("action", "unknown")
        target = data.get("target", data.get("address", data.get("query", "")))
        confidence = float(data.get("confidence", data.get("score", 0.0)) or 0.0)

        title = f"{provider_name}: {action} for {target}"
        if data.get("breached"):
            title = f"{provider_name}: {target} found in {data.get('breach_count', 0)} breach(es)"
        elif data.get("has_pastes") and data.get("paste_count", 0) > 0:
            title = f"{provider_name}: {target} found in {data.get('paste_count', 0)} paste(s)"

        # Collect evidence references from provider data (e.g., HIBP breach names)
        evidence_refs: list[str] = []
        if isinstance(data.get("breaches"), list):
            for b in data["breaches"][:5]:
                evidence_refs.append(f"hibp://breach/{b.get('name', 'unknown')}/{target}")
        if isinstance(data.get("pastes"), list):
            for p in data["pastes"][:5]:
                evidence_refs.append(f"hibp://paste/{p.get('id', 'unknown')}/{target}")

        # Extract source_timestamp from provider data if available
        source_timestamp: str | None = None
        if isinstance(data.get("last_analysis_date"), str):
            source_timestamp = data["last_analysis_date"]
        elif isinstance(data.get("breach_date"), str):
            source_timestamp = data["breach_date"]

        # Build complete provenance from propagated context + provider data
        provenance = Provenance(
            case_id=result.get("metadata", {}).get("case_id", investigation.case_id),
            investigation_id=result.get("metadata", {}).get("investigation_id", investigation.investigation_id),
            organization_id=result.get("metadata", {}).get("organization_id"),
            created_by=result.get("metadata", {}).get("created_by"),
            agent_id=agent_id,
            agent_run_id=run_id,
            task_id=result.get("metadata", {}).get("task_id"),
            tool_id=capability,
            provider=provider_name,
            source=data.get("source", f"{provider_name}_api"),
            source_timestamp=source_timestamp,
            collected_timestamp=result.get("metadata", {}).get("collected_at") or datetime.now(UTC).isoformat(),
            evidence_refs=evidence_refs if evidence_refs else [],
            entity_refs=[],
            indicator_refs=[f"{action}:{target}"],
        )

        findings.append(Finding(
            finding_id="",
            finding_type="EXTERNAL_INTELLIGENCE",
            title=title,
            description=self._provider_description(data, action, provider_name),
            confidence=confidence,
            status="open",
            requires_human_review=True,
            provenance=provenance,
            metadata={
                "provider_result": result,
                "action": action,
                "provider": provider_name,
            },
        ))
        return findings

    def _provider_tool_calls(
        self,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Build a tool_call dict from a successful provider result.

        This is consumed by the investigator transform loop (investigator.py)
        to persist provider results as EvidenceRecord entries.
        """
        if not isinstance(result, dict):
            return None
        data = result.get("data", {})
        if not isinstance(data, dict):
            return None
        return {
            "tool_id": result.get("tool_id", ""),
            "action": result.get("action", ""),
            "status": result.get("status", "success"),
            "tool_status": "ALLOW",
            "result": {
                "provider": result.get("metadata", {}).get("provider", ""),
                "source": result.get("metadata", {}).get("source", ""),
                "target": data.get("target", data.get("address", data.get("query", ""))),
                "confidence": float(data.get("confidence", data.get("score", 0.0)) or 0.0),
                "data": data,
            },
        }

    def _provider_description(self, data: dict, action: str, provider: str) -> str:
        """Build a human-readable description from provider result data."""
        parts = []
        if action == "breached_account":
            count = data.get("breach_count", 0)
            if count == 0:
                parts.append(f"{provider}: No known breaches found for this account.")
            else:
                parts.append(f"{provider}: Account appears in {count} known data breach(es).")
                names = [b.get("name", "?") for b in data.get("breaches", [])[:5]]
                if names:
                    parts.append(f"Breaches: {', '.join(names)}")
        elif action == "paste_account":
            count = data.get("paste_count", 0)
            if count == 0:
                parts.append(f"{provider}: No known paste exposures found for this account.")
            else:
                parts.append(f"{provider}: Account appears in {count} paste site(s).")
        elif action in ("domain_report", "ip_report", "file_report"):
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                parts.append(f"{provider}: {malicious} vendor(s) flagged this target as malicious.")
            else:
                parts.append(f"{provider}: No malicious detections for this target.")
        elif action in ("email_verifier", "domain_search"):
            status = data.get("status", data.get("email_status", ""))
            if status:
                parts.append(f"{provider}: Email verification status: {status}.")
        elif action in ("url_scrape", "web_search", "crawl_url"):
            if action == "web_search":
                count = len(data.get("results", []))
                parts.append(f"{provider}: Found {count} result(s) for the query.")
            else:
                parts.append(f"{provider}: Retrieved data from {data.get('url', data.get('final_url', 'target'))}.")
        else:
            parts.append(f"{provider}: External intelligence result for {action}.")
        return " ".join(parts)

    def _run_providers_for_indicators(
        self,
        providers: dict[str, Any],
        indicators: dict[str, Any],
        investigation: Investigation,
        inputs: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Run relevant provider adapters for each indicator type.

        Provider failures are contained — each provider runs independently
        and a failure in one never prevents others from running.
        Returns a list of dicts with 'run' (AgentRun-like) and 'findings' (list).
        """
        import uuid as _uuid
        from safenestt.schemas.findings import AgentRun

        results: list[dict[str, Any]] = []
        indicator_providers: dict[str, list[tuple[str, str]]] = {
            "email": [
                ("hibp", "cyber_intel.hibp.breached_account"),
                ("hibp", "cyber_intel.hibp.paste_account"),
                ("hunter", "cyber_intel.hunter.email_verifier"),
            ],
            "domain": [
                ("shodan", "cyber_intel.shodan.domain"),
                ("virustotal", "cyber_intel.virustotal.domain_report"),
                ("firecrawl", "cyber_intel.firecrawl.web_search"),
                ("hunter", "cyber_intel.hunter.domain_search"),
            ],
            "ip_address": [
                ("shodan", "cyber_intel.shodan.host"),
                ("virustotal", "cyber_intel.virustotal.ip_report"),
            ],
            "wallet_address": [
                ("etherscan", "cyber_intel.etherscan.wallet_trace"),
            ],
            "transaction_hash": [
                ("etherscan", "cyber_intel.etherscan.wallet_trace"),
            ],
        }

        for indicator_type, value in indicators.items():
            if not value:
                continue
            provider_list = indicator_providers.get(indicator_type, [])
            for prov_name, capability in provider_list:
                provider = providers.get(prov_name)
                if provider is None:
                    continue
                run_id = f"prov-{prov_name}-{_uuid.uuid4()}"
                agent_id = f"provider-{prov_name}"
                run = AgentRun(
                    run_id=run_id,
                    agent_id=agent_id,
                    task_id=inputs.get("task_id"),
                    inputs={"indicator_type": indicator_type, "value": value},
                )
                # Propagate full context into provider payload for provenance.
                # Investigation carries case_id/investigation_id; organization_id
                # comes from the API layer via inputs (investigator.py injects it).
                payload = {
                    "query": str(value),
                    "indicator_type": indicator_type,
                    "case_id": investigation.case_id,
                    "investigation_id": investigation.investigation_id,
                    "organization_id": inputs.get("organization_id"),
                    "agent_id": agent_id,
                    "agent_run_id": run_id,
                    "task_id": inputs.get("task_id"),
                    "tool_id": capability,
                }
                result = self._run_provider(provider, capability, payload, run_id, agent_id)
                run.outputs = {"provider_result": result}
                # Build tool_calls from successful provider results so the
                # investigator transform loop can persist them as evidence.
                tool_calls: list[dict[str, Any]] = []
                if result and isinstance(result, dict) and result.get("status") == "success":
                    run.status = "completed"
                    tc = self._provider_tool_calls(result)
                    if tc:
                        tool_calls.append(tc)
                else:
                    run.status = "failed"
                    # Structured provider-failure recording (Blocker 6).
                    # Previously a failed run carried NO error at all, so
                    # persisted agent_runs showed status=failed with
                    # error=null — impossible to triage. Provider failures are
                    # recoverable (other providers still run) but must be
                    # attributable: record code, provider, capability, and
                    # whether the cause was configuration/credential related.
                    err = result.get("error") if isinstance(result, dict) else None
                    # error is a structured JSON string so it fits the
                    # `str | None` contract while still carrying the
                    # provider / capability / failure_class detail.
                    run.error = json.dumps({
                        "code": err if isinstance(err, str) and err else (
                            result.get("status", "unknown")
                            if isinstance(result, dict) else "no_result"
                        ),
                        "provider": prov_name,
                        "capability": capability,
                        "indicator_type": indicator_type,
                        "failure_class": (
                            "configuration"
                            if isinstance(result, dict) and result.get("error") in (
                                "provider_not_configured",
                                "credential_missing",
                                "not_implemented",
                            )
                            else "provider"
                        ),
                    })
                run.tool_calls = tool_calls
                findings = self._provider_findings_from_result(
                    result, investigation, run_id, agent_id, capability
                ) if result else []
                results.append({"run": run, "findings": findings})

        return results

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
