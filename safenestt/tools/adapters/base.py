from __future__ import annotations

from typing import Any

from safenestt.schemas.tools import ToolCapability, ToolInput, ToolOutput


class ToolAdapter:
    """Base adapter interface for external intelligence tools."""

    capabilities: list[ToolCapability] = []

    def validate_input(self, payload: dict[str, Any], capability: str) -> ToolOutput:
        return ToolOutput(
            tool_id="base",
            action=capability,
            status="error",
            error="validate_input not implemented",
        )

    def health_check(self) -> dict[str, Any]:
        return {"status": "unknown"}

    def execute(self, agent: Any, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def _ok(self, tool_id: str, action: str, data: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "success",
            "data": data,
            "metadata": metadata or {},
            "warnings": [],
            "error": None,
        }

    def _fail(self, tool_id: str, action: str, error: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "tool_id": tool_id,
            "action": action,
            "status": "error",
            "data": {},
            "metadata": metadata or {},
            "warnings": [],
            "error": error,
        }
