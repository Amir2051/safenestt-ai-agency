from __future__ import annotations

import pytest

from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel, agent_registry
from safenestt.orchestrator import Task, TaskStatus, Orchestrator
from safenestt.security.audit import AuditEvent, AuditLogger, audit
from safenestt.security.permissions import PermissionDecision, PermissionManager, permission_manager
from safenestt.security.redaction import redact
from safenestt.security.isolation import production_isolation_check, repo_root
from safenestt.tools.interface import ToolInterface
from safenestt.memory.provider import MemoryRecord, StubMemoryProvider, memory_provider


class DummyAgent:
    def __init__(self, agent_id: str, capabilities: list[str], risk_level: RiskLevel = RiskLevel.LOW):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.risk_level = risk_level


class FakeAgentRecord:
    def __init__(self, agent_id: str, capabilities: list[str], risk_level: RiskLevel = RiskLevel.LOW):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.risk_level = risk_level

def test_registry_register_and_get():
    registry = AgentRegistry()
    agent = AgentRecord(agent_id="a1", name="Agent One")
    registry.register(agent)
    assert registry.get("a1") is agent


def test_registry_enabled_agents():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="a1", name="A1", enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="a2", name="A2", enabled=False, status=AgentStatus.ACTIVE))
    enabled = registry.enabled_agents()
    assert len(enabled) == 1
    assert enabled[0].agent_id == "a1"


def test_registry_duplicate_registration_rejected():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="a1", name="Agent One"))
    with pytest.raises(ValueError):
        registry.register(AgentRecord(agent_id="a1", name="Agent One Again"))


def test_registry_list_by_department():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="a1", name="A1", department="engineering", enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="a2", name="A2", department="security", enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="a3", name="A3", department="engineering", enabled=True, status=AgentStatus.SUSPENDED))
    engineering = registry.list_by_department("engineering")
    assert [agent.agent_id for agent in engineering] == ["a1", "a3"]
    security = registry.list_by_department("security")
    assert [agent.agent_id for agent in security] == ["a2"]


def test_registry_defaults_no_implicit_permission_elevation():
    registry = AgentRegistry()
    agent = AgentRecord(agent_id="a1", name="Agent One")
    registry.register(agent)
    assert agent.permissions == []
    assert agent.enabled is False
    assert agent.status == AgentStatus.DRAFT
    assert agent.risk_level == RiskLevel.LOW


# Agent loader


def test_load_core_team_returns_thirteen_approved_roster_agents():
    from safenestt.agent_loader import load_approved_roster

    registry = AgentRegistry()
    loaded = load_approved_roster(registry=registry)

    assert len(loaded) == 13
    assert {agent.agent_id for agent in loaded} == {
        "orchestrator",
        "chief-of-staff",
        "ai-engineer",
        "backend-engineer",
        "frontend-engineer",
        "security-researcher",
        "osint-investigator",
        "fraud-investigator",
        "identity-graph-operator",
        "product-manager",
        "marketing-strategist",
        "sales-strategist",
        "qa-reality-checker",
    }
    assert {agent.name for agent in loaded} == {
        "AI Agency Orchestrator",
        "Chief of Staff",
        "AI Engineer",
        "Backend Engineer",
        "Frontend Engineer",
        "Security Researcher",
        "OSINT Investigator",
        "Fraud Investigator",
        "Identity Graph Operator",
        "Product Manager",
        "Marketing Strategist",
        "Sales Strategist",
        "QA / Reality Checker",
    }


def test_loader_does_not_activate_unknown_upstream_agents():
    from safenestt.agent_loader import load_approved_roster

    registry = AgentRegistry()
    load_approved_roster(registry=registry)
    loaded_names = {agent.name for agent in registry.all()}

    assert "Reality Checker" not in loaded_names
    assert "Agents Orchestrator" not in loaded_names


def test_loader_placeholders_have_explicit_safenestt_source():
    from safenestt.agent_loader import load_approved_roster

    registry = AgentRegistry()
    load_approved_roster(registry=registry)
    placeholder_ids = {"osint-investigator", "fraud-investigator", "marketing-strategist", "sales-strategist"}
    for agent in registry.all():
        if agent.agent_id in placeholder_ids:
            assert agent.source == "safenestt-placeholder"
            assert agent.status == AgentStatus.DRAFT
            assert agent.enabled is False


def test_loader_reuses_stable_ids_across_reloads():
    from safenestt.agent_loader import load_approved_roster

    registry = AgentRegistry()
    first = {agent.agent_id: agent.name for agent in load_approved_roster(registry=registry)}
    registry._agents.clear()
    second = {agent.agent_id: agent.name for agent in load_approved_roster(registry=registry)}

    assert first == second


# Orchestrator

def test_orchestrator_plan_selects_agent():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="e1", name="Engineer", capabilities=["engineering"], enabled=True, status=AgentStatus.ACTIVE))
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Build app", payload={"intent": "engineering"})
    plan = orch.plan(task)
    assert plan["assigned_agent_id"] == "e1"
    assert plan["status"] == TaskStatus.ASSIGNED.value


def test_orchestrator_handoff():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="e1", name="Engineer", capabilities=["engineering"], enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="s1", name="Security", capabilities=["security"], enabled=True, status=AgentStatus.ACTIVE))
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Build", payload={"intent": "engineering"})
    orch.plan(task)
    handoff = orch.handoff(task, "s1")
    assert task.assigned_agent_id == "s1"
    assert task.handoff_chain == ["e1"]
    assert handoff["status"] == TaskStatus.HANDOFF.value


def test_orchestrator_execute_rejects_invalid_state():
    registry = AgentRegistry()
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Invalid", payload={"intent": "general"})
    result = orch.execute(task)
    assert result["status"] == TaskStatus.FAILED.value
    assert result["reason"] == "invalid_state_for_execution"


def test_orchestrator_cancel_after_completion_rejected():
    registry = AgentRegistry()
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Done", payload={"intent": "general"})
    orch.complete(task, {"ok": True})
    result = orch.cancel(task)
    assert result["status"] == TaskStatus.COMPLETED.value
    assert result["reason"] == "already-terminal"


def test_orchestrator_fail_and_complete():
    registry = AgentRegistry()
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Work", payload={"intent": "general"})
    orch.plan(task)
    fail = orch.fail(task, "timeout")
    assert fail["status"] == TaskStatus.FAILED.value
    assert fail["reason"] == "timeout"
    assert orch.audit.recent()[-1].action == "fail"


def test_orchestrator_handoff_chain_tracking():
    registry = AgentRegistry()
    registry.register(AgentRecord(agent_id="e1", name="Engineer", capabilities=["engineering"], enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="s1", name="Security", capabilities=["security"], enabled=True, status=AgentStatus.ACTIVE))
    registry.register(AgentRecord(agent_id="r1", name="Reviewer", capabilities=["review"], enabled=True, status=AgentStatus.ACTIVE))
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Build", payload={"intent": "engineering"})
    orch.plan(task)
    orch.handoff(task, "s1")
    orch.handoff(task, "r1")
    assert task.assigned_agent_id == "r1"
    assert task.handoff_chain == ["e1", "s1"]
    assert orch.audit.recent()[-1].metadata["status"] == TaskStatus.HANDOFF.value


def test_orchestrator_rejects_unknown_handoff_target():
    registry = AgentRegistry()
    orch = Orchestrator(registry, AuditLogger())
    task = Task(task_id="t1", title="Work", payload={"intent": "general"})
    orch.plan(task)
    result = orch.handoff(task, "unknown-agent")
    assert result["status"] == TaskStatus.FAILED.value
    assert "unknown_target_agent" in result["reason"]


# Permissions

def test_permission_manager_authorize():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    pm.grant("a1", ["tools.web.search"])
    assert pm.authorize(agent, "tools.web.search").allowed is True
    assert pm.authorize(agent, "tools.shell.execute").allowed is False


def test_permission_evaluate_execution_low_allows():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    pm.grant("a1", ["tools.web.search"])
    decision = pm.evaluate_execution(agent, "tools.web.search", {"query": "test"})
    assert decision.allowed is True
    assert decision.requires_approval is False


def test_permission_evaluate_execution_high_requires_approval():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.HIGH)
    pm.grant("a1", ["tools.shell.execute"])
    decision = pm.evaluate_execution(agent, "tools.shell.execute", {"command": "ls"})
    assert decision.requires_approval is True


# Audit

def test_audit_logger_records():
    logger = AuditLogger()
    event = AuditEvent(event_id="e1", actor_type="agent", actor_id="a1", action="tool.execute", decision="ALLOW")
    logger.record(event)
    assert logger.recent()[0].event_id == "e1"


# Redaction

def test_redact_api_key():
    assert redact({"api_key": "abc"}) == {"api_key": "[REDACTED]"}


def test_redact_nested():
    assert redact({"user": {"password": "x"}}) == {"user": {"password": "[REDACTED]"}}


# Isolation

def test_production_isolation_check_true_when_missing():
    assert production_isolation_check() is True


# Tool interface

def test_tool_interface_denies_without_permission():
    tool = ToolInterface(permission_manager)
    decision = tool.execute(None, "tools.web.search", {"query": "test"})
    assert decision["decision"] == "DENY"


# Agent loader module import

def test_agent_loader_importable():
    from safenestt.agent_loader import load_approved_roster, load_core_team  # noqa: F401

    assert callable(load_approved_roster)
    assert callable(load_core_team)


# Memory

def test_stub_memory_provider():
    provider = StubMemoryProvider()
    record = MemoryRecord(memory_id="m1", owner_type="agent", owner_id="a1", scope="task", content={"key": "value"})
    provider.add(record)
    results = provider.query("a1", "task")
    assert results == [record]
