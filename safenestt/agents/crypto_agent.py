from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance
from safenestt.tools.adapters.cyber_intel_crypto import CyberIntelCryptoAdapter


class CryptoAgent(BaseAgent):
    role = "crypto"
    allowed_tools = [
        "cyber_intel.crypto_trace.trace_wallet",
    ]

    def __init__(self, agent, permission_manager=None):
        super().__init__(agent, permission_manager)
        self.adapter = CyberIntelCryptoAdapter()

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        indicators = inputs.get("indicators") or {}
        findings: list[Finding] = []
        tool_calls: list[dict[str, Any]] = []

        wallet = indicators.get("wallet_address")
        tx_hash = indicators.get("transaction_hash")
        chain = str(inputs.get("chain") or "eth").strip().lower()

        checks = []
        if wallet:
            checks.append({"address": wallet, "chain": chain})
        if tx_hash and not wallet:
            checks.append({"address": tx_hash, "chain": chain})

        for item in checks:
            capability = "cyber_intel.crypto_trace.trace_wallet"
            if not self._allowed(capability):
                continue
            auth = self._authorize(capability)
            if auth.decision != "ALLOW":
                tool_calls.append({"capability": capability, "status": "denied", "reason": auth.reason})
                continue
            payload = {
                "address": item["address"],
                "chain": item["chain"],
                **self._context_payload(run),
            }
            result = self._execute_tool(capability, payload)
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
        return {"capability": capability, "status": safe.get("decision"), "tool_status": (safe.get("result") or {}).get("status")}

    def _to_finding(self, run: AgentRun, capability: str, result: dict[str, Any]) -> Finding | None:
        tool_result = (result.get("result") or {})
        data = tool_result.get("data") or {}
        status = tool_result.get("status")
        if status == "success":
            description = data.get("summary") or f"Crypto trace result for {data.get('address')}"
            confidence = 0.75
            limitations = ["Blockchain tracing shows on-chain activity only; off-chain relationships require additional investigation."]
        else:
            description = f"Crypto trace failed or returned no data for {data.get('address')}."
            confidence = 0.0
            limitations = ["External lookup did not return usable data; do not treat absence as negative evidence."]
        provenance = Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            tool_id=tool_result.get("tool_id") or "crypto_trace",
            provider="cyber_intel",
            source="cyber_intel.crypto",
            source_timestamp=data.get("timestamp"),
            evidence_refs=[],
            entity_refs=[addr for addr in [data.get("address")] if isinstance(addr, str)],
            indicator_refs=[],
        )
        return Finding(
            finding_id="",
            finding_type="EXTERNAL_INTELLIGENCE",
            title=f"Crypto trace: {data.get('chain')} {data.get('address')}",
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
