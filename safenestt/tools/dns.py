from __future__ import annotations

from typing import Any

from safenestt.tools.manifest import ToolManifest, default_tool_manifest
from safenestt.tools.registry import tool_registry
from safenestt.tools.result import ToolResult


def _normalize_domain(target: str) -> str:
    value = target.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0]


class DNSAdapter:
    def execute(self, agent, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        target = _normalize_domain(str(payload.get("target", "")))
        if not target:
            return ToolResult(tool_id="dns.lookup", action=capability, status="error", error="missing_target").__dict__ | {}
        try:
            import dns.resolver
            answers = dns.resolver.resolve(target, "A")
            records = [rdata.to_text() for rdata in answers]
            return ToolResult(tool_id="dns.lookup", action=capability, status="success", data={"domain": target, "records": records}).__dict__ | {}
        except Exception as exc:
            return ToolResult(tool_id="dns.lookup", action=capability, status="error", error=str(exc), data={"domain": target}).__dict__ | {}


class DNSReverseAdapter:
    def execute(self, agent, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        target = _normalize_domain(str(payload.get("target", "")))
        if not target:
            return ToolResult(tool_id="dns.reverse", action=capability, status="error", error="missing_target").__dict__ | {}
        try:
            import dns.reversename
            import dns.resolver
            rev = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(rev, "PTR")
            records = [rdata.to_text() for rdata in answers]
            return ToolResult(tool_id="dns.reverse", action=capability, status="success", data={"target": target, "records": records}).__dict__ | {}
        except Exception as exc:
            return ToolResult(tool_id="dns.reverse", action=capability, status="error", error=str(exc), data={"target": target}).__dict__ | {}


dns_lookup_manifest = ToolManifest(
    tool_id="dns.lookup",
    name="DNS Lookup",
    description="Resolve A records for a domain",
    provider="dns",
    actions=["lookup"],
    risk_level="LOW",
    required_permissions=["tools.dns.lookup"],
    rate_limit={"scope": "agent", "limit": 10, "window_seconds": 60},
    configuration_schema={"target": "str"},
    enabled=True,
    version="1.0.0",
)

dns_reverse_manifest = ToolManifest(
    tool_id="dns.reverse",
    name="DNS Reverse",
    description="Reverse lookup for an IP",
    provider="dns",
    actions=["reverse"],
    risk_level="LOW",
    required_permissions=["tools.dns.reverse"],
    rate_limit={"scope": "agent", "limit": 10, "window_seconds": 60},
    configuration_schema={"target": "str"},
    enabled=True,
    version="1.0.0",
)

for manifest in (dns_lookup_manifest, dns_reverse_manifest):
    try:
        tool_registry.register(manifest)
    except ValueError:
        pass
