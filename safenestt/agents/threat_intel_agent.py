from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance
from safenestt.tools.adapters.cyber_intel_threat import CyberIntelThreatAdapter


class ThreatIntelAgent(BaseAgent):
    role = "threat_intel"
    adapter_cls = CyberIntelThreatAdapter
    allowed_tools = [
        "cyber_intel.threat_intel.dehashed_search",
        "cyber_intel.threat_intel.darkweb_paste",
        "cyber_intel.threat_intel.shodan_domain",
        "cyber_intel.threat_intel.shodan_host",
    ]

    def __init__(self, agent, permission_manager=None):
        super().__init__(agent, permission_manager)
        self.adapter = CyberIntelThreatAdapter()

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        indicators = inputs.get("indicators") or {}
        findings: list[Finding] = []
        tool_calls: list[dict[str, Any]] = []

        domain = indicators.get("domain")
        ip = indicators.get("ip_address")
        query = domain or ip or inputs.get("query")

        tasks = []
        if domain:
            tasks.append(("cyber_intel.threat_intel.shodan_domain", {"query": domain, "query_type": "domain"}))
        if ip:
            tasks.append(("cyber_intel.threat_intel.shodan_host", {"query": ip, "query_type": "ip"}))
        if query:
            tasks.append(("cyber_intel.threat_intel.dehashed_search", {"query": query, "query_type": "domain" if domain else "email"}))
            tasks.append(("cyber_intel.threat_intel.darkweb_paste", {"query": query}))

        for capability, payload in tasks:
            if not self._allowed(capability):
                continue
            auth = self._authorize(capability)
            if auth.decision != "ALLOW":
                tool_calls.append({"capability": capability, "status": "denied", "reason": auth.reason})
                continue
            # Call adapter directly with context
            result = self.adapter.execute(self.agent, capability, {**payload, **self._context_payload(run)})
            tool_calls.append(self._sanitize_tool_call(capability, result))
            finding = self._to_finding(run, capability, result)
            if finding:
                findings.append(finding)

        run.tool_calls = tool_calls
        return self.complete(run, {"findings": [self._serialize_finding(f) for f in findings]})

    def _context_payload(self, run: AgentRun) -> dict[str, Any]:
        return {
            "case_id": run.inputs.get("case_id"),
            "investigation_id": run.inputs.get("investigation_id"),
            "agent_id": run.agent_id,
            "agent_run_id": run.run_id,
        }

    def _sanitize_tool_call(self, capability: str, result: dict[str, Any]) -> dict[str, Any]:
        safe = dict(result)
        safe.pop("metadata", None)
        return {"capability": capability, "status": safe.get("status"), "tool_status": safe.get("status")}

    def _to_finding(self, run: AgentRun, capability: str, result: dict[str, Any]) -> Finding | None:
        data = result.get("data") or {}
        status = result.get("status")
        source = data.get("source", "cyber_intel")
        if status == "success":
            description = data.get("summary") or f"Threat intel lookup for {capability}"
            confidence = 0.65
            limitations = ["Threat intelligence requires corroboration before use in proceedings."]
        elif status == "partial":
            description = f"Threat intel lookup partial for {capability} (source: {source})"
            confidence = 0.3
            limitations = data.get("_errors", ["Partial data returned"])
        else:
            description = f"Threat intel lookup failed or returned no data for {capability}."
            confidence = 0.0
            limitations = ["External lookup did not return usable data; do not treat absence as negative evidence."]
        provenance = Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            tool_id=result.get("tool_id") or capability.split(".")[1],
            provider="cyber_intel",
            source=f"cyber_intel.threat_intel.{source}",
            source_timestamp=data.get("timestamp"),
            evidence_refs=[],
            entity_refs=[],
            indicator_refs=[],
        )
        return Finding(
            finding_id="",
            finding_type="EXTERNAL_INTELLIGENCE",
            title=f"Threat intel: {capability}",
            description=description,
            confidence=confidence,
            status="open",
            requires_human_review=True,
            provenance=provenance,
            metadata={"capability": capability, "tool_data": data, "limitations": limitations},
        )

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
