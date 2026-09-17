from __future__ import annotations

from typing import Any

from safenestt.schemas.tools import ToolCapability, ToolInput, ToolOutput
from safenestt.tools.adapters.base import ToolAdapter


class CyberIntelThreatAdapter(ToolAdapter):
    capabilities = [
        ToolCapability(
            tool_id="cyber_intel.threat_intel",
            name="Threat Intelligence",
            description="Query threat/exposure signals from DeHashed, Shodan, or paste sources.",
            provider="cyber_intel",
            actions=["dehashed_search", "darkweb_paste", "shodan_domain", "shodan_host"],
            input_schema={"type": "object", "properties": {"query": {"type": "string"}, "query_type": {"type": "string"}}},
            output_schema={"type": "object"},
            required_permissions=["intel.read", "threat.read"],
            auth_requirement="env",
        ),
    ]

    def execute(self, agent: Any, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        action = capability.split(".", 2)[2] if "." in capability else capability

        if action == "dehashed_search":
            return self._run_dehashed(payload)
        if action == "darkweb_paste":
            return self._run_darkweb_paste(payload)
        if action in ("shodan_domain", "shodan_host"):
            return self._run_shodan(payload, action)

        return self._fail("cyber_intel.threat_intel", action, f"Unsupported action: {action}")

    def _run_dehashed(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run DeHashed search — requires API key."""
        keyword = payload.get("query", "")
        keyword_type = payload.get("query_type", "email")
        try:
            from modules.darkweb_monitor import scan_dehashed_sync
            items = scan_dehashed_sync(keyword, keyword_type)
        except ImportError as exc:
            return self._fail("cyber_intel.threat_intel", "dehashed_search", f"Module unavailable: {exc}")
        except Exception as exc:
            return self._fail("cyber_intel.threat_intel", "dehashed_search", str(exc))
        return self._ok("cyber_intel.threat_intel", "dehashed_search", {"items": items, "source": "dehashed"}, self._provenance(payload))

    def _run_darkweb_paste(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run Ahmia paste search — no key needed."""
        keyword = payload.get("query", "")
        try:
            from modules.darkweb_monitor import scan_paste_sites_sync
            items = scan_paste_sites_sync(keyword)
        except ImportError as exc:
            return self._fail("cyber_intel.threat_intel", "darkweb_paste", f"Module unavailable: {exc}")
        except Exception as exc:
            return self._fail("cyber_intel.threat_intel", "darkweb_paste", str(exc))
        return self._ok("cyber_intel.threat_intel", "darkweb_paste", {"items": items, "source": "paste_sites"}, self._provenance(payload))

    def _run_shodan(self, payload: dict[str, Any], action: str) -> dict[str, Any]:
        """Run shodan_domain or shodan_host via osint_profiler (dig+whois+theHarvester)."""
        query = payload.get("query", "")
        try:
            from modules.osint_profiler import check_shodan_domain, check_shodan_host
            if action == "shodan_domain":
                fn = check_shodan_domain
            else:
                fn = check_shodan_host
            result = fn(query)
        except ImportError as exc:
            return self._fail("cyber_intel.threat_intel", action, f"Module unavailable: {exc}")
        except Exception as exc:
            return self._fail("cyber_intel.threat_intel", action, str(exc))
        return self._ok("cyber_intel.threat_intel", action, result.get("data") or {}, self._provenance(payload))

    @staticmethod
    def _provenance(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "case_id": payload.get("case_id"),
            "investigation_id": payload.get("investigation_id"),
            "agent_id": payload.get("agent_id"),
            "agent_run_id": payload.get("agent_run_id"),
        }
