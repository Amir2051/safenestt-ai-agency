from __future__ import annotations

from typing import Any

from safenestt.agents.base import BaseAgent, AgentRun
from safenestt.schemas.findings import Finding, Provenance
from safenestt.tools.adapters.cyber_intel import CyberIntelOSINTAdapter

# Import osint_profiler as fallback when cyber_intel is unavailable
try:
    from modules.osint_profiler import run_osint_profile, score_reputation as _score_reputation
    HAS_OSINT_PROFILER = True
except ImportError:
    HAS_OSINT_PROFILER = False


class OsintAgent(BaseAgent):
    role = "osint"
    allowed_tools = [
        "cyber_intel.osint_profile.email",
        "cyber_intel.osint_profile.domain",
        "cyber_intel.osint_profile.ip",
        "cyber_intel.osint_profile.username",
        "cyber_intel.osint_profile.phone",
        "cyber_intel.reputation_score.email",
        "cyber_intel.reputation_score.phone",
    ]

    def __init__(self, agent, permission_manager=None):
        super().__init__(agent, permission_manager)
        self.adapter = CyberIntelOSINTAdapter()

    def execute(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run = self.run(run, inputs)
        indicators = inputs.get("indicators") or {}
        findings: list[Finding] = []
        tool_calls: list[dict[str, Any]] = []

        email = indicators.get("email")
        domain = indicators.get("domain")
        ip = indicators.get("ip_address")
        username = indicators.get("username")
        phone = indicators.get("phone")

        checks = []
        if email:
            checks.append(("cyber_intel.reputation_score.email", {"value": email, "value_type": "email"}))
            checks.append(("cyber_intel.osint_profile.email", {"query": email, "query_type": "email"}))
        if domain:
            checks.append(("cyber_intel.osint_profile.domain", {"query": domain, "query_type": "domain"}))
        if ip:
            checks.append(("cyber_intel.osint_profile.ip", {"query": ip, "query_type": "ip"}))
        if username:
            checks.append(("cyber_intel.osint_profile.username", {"query": username, "query_type": "username"}))
        if phone:
            checks.append(("cyber_intel.reputation_score.phone", {"value": phone, "value_type": "phone"}))

        if not checks:
            return self.complete(run, {"message": "no_osint_indicators", "findings": []})

        # Track which capabilities need osint_profiler fallback
        profiler_fallbacks: list[tuple[str, dict[str, Any]]] = []

        for capability, payload in checks:
            if not self._allowed(capability):
                continue
            auth = self._authorize(capability)
            if auth.decision != "ALLOW":
                tool_calls.append({"capability": capability, "status": "denied", "reason": auth.reason})
                continue
            payload_with_ctx = {**payload, **self._context_payload(run)}
            result = self._execute_tool(capability, payload_with_ctx)
            # If cyber_intel returns no useful data, fall back to osint_profiler
            if self._needs_fallback(result):
                if HAS_OSINT_PROFILER:
                    query_type = payload.get("query_type") or payload.get("value_type")
                    query = payload.get("query") or payload.get("value")
                    if query and query_type:
                        profiler_result = run_osint_profile(query, query_type)
                        # Only use profiler if it returned useful data
                        if self._has_useful_osint_data(profiler_result):
                            result = {
                                "decision": "ALLOW",
                                "reason": "authorized",
                                "result": {
                                    "status": "success",
                                    "data": profiler_result,
                                    "source": "osint_profiler",
                                },
                            }
                        else:
                            # Profiler also returned no data; keep original result
                            # but mark it as no_data so findings reflect reality
                            result = {
                                "decision": "ALLOW",
                                "reason": "authorized",
                                "result": {
                                    "status": "no_data",
                                    "data": {},
                                    "source": "osint_profiler",
                                    "error": "No OSINT data available from any source",
                                },
                            }
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

    @staticmethod
    def _sanitize_tool_call(capability: str, result: dict[str, Any]) -> dict[str, Any]:
        safe = dict(result)
        safe.pop("metadata", None)
        # Also pop internal keys added by fallback logic
        safe.pop("source", None)
        return {
            "capability": capability,
            "status": safe.get("decision") or safe.get("result", {}).get("status"),
            "tool_status": (safe.get("result") or {}).get("status"),
            "source": (safe.get("result") or {}).get("source"),
        }

    def _to_finding(self, run: AgentRun, capability: str, result: dict[str, Any]) -> Finding | None:
        tool_result = (result.get("result") or {})
        data = tool_result.get("data") or {}
        metadata = tool_result.get("metadata") or {}
        source = tool_result.get("source", "cyber_intel")
        status = tool_result.get("status")

        # Determine description based on source and status
        if status == "success" and data:
            description = data.get("summary") or data.get("narrative") or f"OSINT lookup for {capability}"
            confidence = self._confidence_from_tool_status(status)
            limitations = data.get("limitations") or ["External OSINT signals require human verification."]
        elif status == "no_data":
            description = f"OSINT lookup returned no data for {capability} (source: {source})."
            confidence = 0.0
            limitations = ["No OSINT data available from any source; do not treat absence as negative evidence."]
        else:
            description = f"OSINT lookup failed or returned no data for {capability}."
            confidence = 0.0
            limitations = ["External lookup did not return usable data; do not treat absence as negative evidence."]

        # Use source-appropriate provider/tool_id
        provider = source if source != "cyber_intel" else "cyber_intel"
        tool_id = tool_result.get("tool_id") or capability.split(".")[1]

        provenance = Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
            tool_id=tool_id,
            provider=provider,
            source=f"{source}.osint",
            source_timestamp=data.get("timestamp") or metadata.get("timestamp"),
            evidence_refs=[],
            entity_refs=[],
            indicator_refs=[],
        )
        return Finding(
            finding_id="",
            finding_type="EXTERNAL_INTELLIGENCE",
            title=f"OSINT result: {capability} (source: {source})",
            description=description,
            confidence=confidence,
            status="open",
            requires_human_review=True,
            provenance=provenance,
            metadata={"capability": capability, "tool_data": data, "source": source, "limitations": limitations},
        )

    @staticmethod
    def _confidence_from_tool_status(status: str | None) -> float:
        if status == "success":
            return 0.7
        if status == "error":
            return 0.0
        return 0.3

    @staticmethod
    def _has_useful_osint_data(profiler_result: dict[str, Any]) -> bool:
        """Check if osint_profiler returned usable data."""
        if not profiler_result:
            return False
        findings = profiler_result.get("findings")
        if not findings:
            return False
        # Check if any source has actual data (non-empty titles/URLs/descriptions)
        for source_name, source_data in findings.items():
            if isinstance(source_data, dict):
                count = source_data.get("count", 0)
                titles = source_data.get("titles", [])
                urls = source_data.get("urls", [])
                if count > 0 or titles or urls:
                    return True
        return False

    @staticmethod
    def _needs_fallback(result: dict[str, Any]) -> bool:
        """Determine if cyber_intel result needs osint_profiler fallback."""
        # No result dict at all
        if not isinstance(result, dict):
            return True
        # Permission denied
        if result.get("decision") == "DENY":
            return True
        # Error from cyber_intel
        tool_result = result.get("result")
        if not isinstance(tool_result, dict):
            return True
        status = tool_result.get("status")
        if status in ("error", "denied", "no_data"):
            return True
        # Success but empty data
        if status == "success":
            data = tool_result.get("data")
            if not data:
                return True
            # Check if data has useful content
            if isinstance(data, dict):
                findings = data.get("findings")
                if not findings:
                    return True
                # Empty findings dict
                if isinstance(findings, dict) and not any(
                    isinstance(v, dict) and v.get("count", 0) > 0
                    for v in findings.values()
                ):
                    return True
        return False

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict[str, Any]:
        data = finding.__dict__.copy()
        if finding.provenance:
            data["provenance"] = finding.provenance.__dict__
        return data
