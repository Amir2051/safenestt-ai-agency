from __future__ import annotations

from typing import Any

from safenestt.registry import AgentRecord, RiskLevel
from safenestt.security.permissions import AuthorizationDecision, PermissionManager
from safenestt.security.redaction import redact
from safenestt.tools.manifest import ToolManifest, default_tool_manifest
from safenestt.tools.result import ToolResult


class Adapter:
    def execute(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("adapter must not execute denied requests")


class ToolInterface:
    def __init__(self, permission_manager: PermissionManager | None = None, *, adapter: Adapter | None = None) -> None:
        self.permission_manager = permission_manager or PermissionManager()
        self.adapter = adapter or Adapter()

    def validate(self, manifest: ToolManifest | None, capability: str, payload: dict[str, Any] | None) -> AuthorizationDecision:
        if manifest is None:
            return AuthorizationDecision(
                decision="DENY",
                reason="missing_manifest",
                agent_id=None,
                tool_id=None,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=None,
                approval_required=False,
            )
        if not manifest.enabled:
            return AuthorizationDecision(
                decision="DENY",
                reason="tool_disabled",
                agent_id=None,
                tool_id=manifest.tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=manifest.required_permissions[0] if manifest.required_permissions else None,
                approval_required=False,
            )
        if not capability.startswith(f"tools.{manifest.tool_id}."):
            return AuthorizationDecision(
                decision="DENY",
                reason="unknown_tool",
                agent_id=None,
                tool_id=manifest.tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=manifest.required_permissions[0] if manifest.required_permissions else None,
                approval_required=False,
            )
        action = capability[len(f"tools.{manifest.tool_id}."):]
        if action not in manifest.actions:
            return AuthorizationDecision(
                decision="DENY",
                reason="unknown_action",
                agent_id=None,
                tool_id=manifest.tool_id,
                action=capability,
                risk=RiskLevel.LOW,
                required_permission=manifest.required_permissions[0] if manifest.required_permissions else None,
                approval_required=False,
            )
        return AuthorizationDecision(
            decision="ALLOW",
            reason="manifest_valid",
            agent_id=None,
            tool_id=manifest.tool_id,
            action=capability,
            risk=RiskLevel[str(manifest.risk_level)] if isinstance(manifest.risk_level, str) else manifest.risk_level,
            required_permission=manifest.required_permissions[0] if manifest.required_permissions else None,
            approval_required=False,
        )

    def authorize(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any] | None = None) -> AuthorizationDecision:
        return self.permission_manager.authorize(agent, capability)

    def execute(self, agent: AgentRecord | None, capability: str, payload: dict[str, Any], manifest: ToolManifest | None = None, adapter: Adapter | None = None) -> dict[str, Any]:
        validation = self.validate(manifest, capability, payload)
        if validation.decision != "ALLOW":
            return {
                "decision": validation.decision,
                "reason": validation.reason,
                "agent_id": validation.agent_id,
                "tool_id": validation.tool_id,
                "action": validation.action,
                "risk": validation.risk.value,
                "required_permission": validation.required_permission,
                "approval_required": validation.approval_required,
                "approval_id": validation.approval_id,
            }
        if not isinstance(payload, dict):
            return {
                "decision": "DENY",
                "reason": "invalid_arguments",
                "agent_id": None,
                "tool_id": manifest.tool_id if manifest else None,
                "action": capability,
                "risk": RiskLevel.LOW.value,
                "required_permission": validation.required_permission,
                "approval_required": False,
                "approval_id": None,
            }
        auth = self.authorize(agent, capability, payload)
        if auth.decision != "ALLOW":
            return {
                "decision": auth.decision,
                "reason": auth.reason,
                "agent_id": auth.agent_id,
                "tool_id": auth.tool_id,
                "action": auth.action,
                "risk": auth.risk.value,
                "required_permission": auth.required_permission,
                "approval_required": auth.approval_required,
                "approval_id": auth.approval_id,
            }
        provider = adapter if adapter is not None else self.adapter
        try:
            provider_result = provider.execute(agent, capability, payload)
        except Exception as exc:  # pragma: no cover - error normalization
            provider_result = ToolResult(
                tool_id=manifest.tool_id if manifest else "",
                action=capability,
                status="error",
                error=str(exc),
            ).__dict__ | {}
        if not isinstance(provider_result, dict):
            provider_result = ToolResult(
                tool_id=manifest.tool_id if manifest else "",
                action=capability,
                status="error",
                error="malformed_provider_response",
            ).__dict__ | {}
        tool_result = ToolResult(
            tool_id=manifest.tool_id if manifest else provider_result.get("tool_id", ""),
            action=capability,
            status=provider_result.get("status", "success"),
            data=provider_result.get("data", {}),
            metadata=redact(provider_result.get("metadata", {})),
            warnings=provider_result.get("warnings", []),
            error=provider_result.get("error"),
        )
        return {
            "decision": "ALLOW",
            "reason": "authorized",
            "agent_id": auth.agent_id,
            "tool_id": tool_result.tool_id,
            "action": tool_result.action,
            "risk": auth.risk.value,
            "required_permission": auth.required_permission,
            "approval_required": auth.approval_required,
            "approval_id": auth.approval_id,
            "result": tool_result.__dict__,
        }


tool_interface = ToolInterface()
