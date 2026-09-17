from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from safenestt.registry import AgentRecord
from safenestt.schemas.findings import AgentRun, Finding, Provenance
from safenestt.security.permissions import AuthorizationDecision, PermissionManager
from safenestt.tools.interface import ToolInterface
from safenestt.tools.registry import tool_registry


@dataclass
class AgentContext:
    agent: AgentRecord
    permission_manager: PermissionManager | None = None
    tool_interface: ToolInterface | None = None
    run: AgentRun | None = None

    def __post_init__(self) -> None:
        if self.tool_interface is None:
            self.tool_interface = ToolInterface(permission_manager=self.permission_manager)


class BaseAgent:
    role: str = "base"
    allowed_tools: list[str] = []

    def __init__(self, agent: AgentRecord, permission_manager: PermissionManager | None = None) -> None:
        self.agent = agent
        self.permission_manager = permission_manager or PermissionManager()
        self.tool_interface = ToolInterface(permission_manager=self.permission_manager)

    def _authorize(self, capability: str) -> AuthorizationDecision:
        return self.tool_interface.authorize(self.agent, capability)

    def _execute_tool(self, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.tool_interface.execute(self.agent, capability, payload)

    def _allowed(self, capability: str) -> bool:
        if not self.allowed_tools:
            return True
        return any(capability.startswith(f"tools.{tool}.") or capability == tool for tool in self.allowed_tools)

    def run(self, run: AgentRun, inputs: dict[str, Any]) -> AgentRun:
        run.status = "running"
        run.started_at = _now_iso()
        run.inputs = self._sanitized_inputs(inputs)
        return run

    def complete(self, run: AgentRun, outputs: dict[str, Any] | None = None) -> AgentRun:
        run.status = "completed"
        run.completed_at = _now_iso()
        if outputs:
            run.outputs = outputs
        return run

    def fail(self, run: AgentRun, error: str) -> AgentRun:
        run.status = "failed"
        run.completed_at = _now_iso()
        run.error = error
        return run

    def _sanitized_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in inputs.items() if "secret" not in k.lower() and "token" not in k.lower() and "password" not in k.lower()}

    def _finding_provenance(self, run: AgentRun) -> Provenance:
        return Provenance(
            case_id=str(run.inputs.get("case_id") or ""),
            investigation_id=str(run.inputs.get("investigation_id") or ""),
            created_by=str(run.inputs.get("created_by") or ""),
            agent_id=run.agent_id,
            agent_run_id=run.run_id,
            task_id=run.task_id,
        )


def _now_iso() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()
