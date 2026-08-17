from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel, agent_registry
from safenestt.security.audit import AuditEvent, AuditLogger, audit


class TaskStatus(str, Enum):
    RECEIVED = "received"
    CLASSIFYING = "classifying"
    PLANNING = "planning"
    ASSIGNED = "assigned"
    EXECUTING = "executing"
    HANDOFF = "handoff"
    REVIEW = "review"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    task_id: str
    title: str
    payload: dict[str, Any] = field(default_factory=dict)
    assigned_agent_id: str | None = None
    status: TaskStatus = TaskStatus.RECEIVED
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    result: dict[str, Any] | None = None
    handoff_chain: list[str] = field(default_factory=list)
    metadata: dict[str, Any] | None = None
    failure_reason: str | None = None


class Orchestrator:
    def __init__(self, registry: AgentRegistry | None = None, audit_logger: AuditLogger | None = None) -> None:
        self.registry = registry or agent_registry
        self.audit = audit_logger or audit

    def classify(self, payload: dict[str, Any]) -> str:
        intent = payload.get("intent")
        if isinstance(intent, str) and intent.strip():
            return intent.strip().lower()
        return "general"

    def _transition(self, task: Task, status: TaskStatus, detail: str | None = None) -> None:
        task.status = status
        task.updated_at = datetime.utcnow()
        if detail:
            task.metadata = task.metadata or {}
            task.metadata["last_transition"] = detail

    def _record(self, task: Task, action: str, decision: str, risk_level: RiskLevel = RiskLevel.LOW, detail: str | None = None) -> None:
        self.audit.record(
            AuditEvent(
                event_id=f"task-{task.task_id}-{action}",
                actor_type="orchestrator",
                actor_id=task.assigned_agent_id,
                action=action,
                decision=decision,
                risk_level=risk_level,
                resource_type="task",
                resource_id=task.task_id,
                detail=detail,
                metadata={"status": task.status.value},
            )
        )

    def select_agent(self, intent: str) -> AgentRecord | None:
        candidates = [agent for agent in self.registry.enabled_agents() if intent in agent.capabilities]
        if not candidates:
            candidates = self.registry.enabled_agents()
        return candidates[0] if candidates else None

    def plan(self, task: Task) -> dict[str, Any]:
        self._transition(task, TaskStatus.CLASSIFYING, "intent-classified")
        intent = self.classify(task.payload)
        self._transition(task, TaskStatus.PLANNING, "planning-started")
        agent = self.select_agent(intent)
        task.assigned_agent_id = agent.agent_id if agent else None
        self._transition(task, TaskStatus.ASSIGNED, "agent-assigned")
        self._record(task, "plan", "ASSIGN" if agent else "NO_CANDIDATE", agent.risk_level if agent else RiskLevel.LOW)
        return {
            "task_id": task.task_id,
            "assigned_agent_id": task.assigned_agent_id,
            "intent": intent,
            "status": task.status.value,
        }

    def execute(self, task: Task, result: dict[str, Any] | None = None) -> dict[str, Any]:
        if task.status not in {TaskStatus.ASSIGNED, TaskStatus.EXECUTING}:
            self._transition(task, TaskStatus.FAILED, "execute-rejected")
            task.failure_reason = "invalid_state_for_execution"
            self._record(task, "execute", "REJECT", RiskLevel.MEDIUM, task.failure_reason)
            return {"task_id": task.task_id, "status": task.status.value, "reason": task.failure_reason}
        self._transition(task, TaskStatus.EXECUTING, "execution-started")
        self._record(task, "execute", "EXECUTE")
        if result is not None:
            task.result = result
            self._transition(task, TaskStatus.REVIEW, "execution-completed")
            self._record(task, "review", "REVIEW")
        return {"task_id": task.task_id, "status": task.status.value}

    def handoff(self, task: Task, target_agent_id: str) -> dict[str, Any]:
        if task.assigned_agent_id:
            task.handoff_chain.append(task.assigned_agent_id)
        target = self.registry.get(target_agent_id)
        if target is None:
            self._transition(task, TaskStatus.FAILED, "handoff-rejected")
            task.failure_reason = f"unknown_target_agent:{target_agent_id}"
            self._record(task, "handoff", "REJECT", RiskLevel.HIGH, task.failure_reason)
            return {"task_id": task.task_id, "status": task.status.value, "reason": task.failure_reason}
        task.assigned_agent_id = target_agent_id
        self._transition(task, TaskStatus.HANDOFF, "handoff-completed")
        self._record(task, "handoff", "HANDOFF", target.risk_level, ",".join(task.handoff_chain))
        return {"task_id": task.task_id, "handoff_to": target_agent_id, "chain": task.handoff_chain, "status": task.status.value}

    def complete(self, task: Task, result: dict[str, Any]) -> dict[str, Any]:
        task.result = result
        self._transition(task, TaskStatus.COMPLETED, "task-completed")
        self._record(task, "complete", "COMPLETE")
        return {"status": "completed", "task_id": task.task_id, "result": result}

    def fail(self, task: Task, reason: str) -> dict[str, Any]:
        task.failure_reason = reason
        self._transition(task, TaskStatus.FAILED, "task-failed")
        self._record(task, "fail", "FAIL", RiskLevel.HIGH, reason)
        return {"status": "failed", "task_id": task.task_id, "reason": reason}

    def cancel(self, task: Task) -> dict[str, Any]:
        terminal_states = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}
        if task.status in terminal_states:
            self._record(task, "cancel", "REJECT", detail="already-terminal")
            return {"task_id": task.task_id, "status": task.status.value, "reason": "already-terminal"}
        self._transition(task, TaskStatus.CANCELLED, "task-cancelled")
        self._record(task, "cancel", "CANCEL")
        return {"task_id": task.task_id, "status": task.status.value}


orchestrator = Orchestrator()
