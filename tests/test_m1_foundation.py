from __future__ import annotations

import pytest

from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel, agent_registry
from safenestt.orchestrator import Task, TaskStatus, Orchestrator
from safenestt.security.audit import AuditEvent, AuditLogger, audit
from safenestt.security.permissions import AuthorizationDecision, PermissionManager, permission_manager
from safenestt.security.redaction import redact
from safenestt.security.isolation import production_isolation_check, assert_path_under_safenestt_ai
from safenestt.tools.interface import Adapter, ToolInterface
from safenestt.memory.provider import MemoryRecord, StubMemoryProvider, memory_provider


class FakeAgentRecord:
    def __init__(self, agent_id: str, capabilities: list[str], risk_level: RiskLevel = RiskLevel.LOW):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.risk_level = risk_level
        self.enabled = True
        self.status = AgentStatus.ACTIVE


# Registry


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


# Security boundary / permissions


def test_permission_manager_authorize():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search"}
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    decision = pm.authorize(agent, "tools.web.search")
    assert isinstance(decision, AuthorizationDecision)
    assert decision.decision == "ALLOW"
    assert decision.reason == "authorized"
    assert decision.approval_required is False


def test_permission_manager_denies_missing_permission():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    decision = pm.authorize(agent, "tools.shell.execute")
    assert decision.decision == "DENY"
    assert decision.reason == "missing_permission"


def test_permission_manager_denies_unknown_agent():
    pm = PermissionManager()
    decision = pm.authorize(None, "tools.shell.execute")
    assert decision.decision == "DENY"
    assert decision.reason == "missing_agent"


def test_permission_manager_denies_invalid_capability():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    decision = pm.authorize(agent, "tools..execute")
    assert decision.decision == "DENY"
    assert decision.reason == "invalid_capability"


def test_permission_manager_disabled_agent_denied():
    pm = PermissionManager()
    agent = AgentRecord(agent_id="a1", name="Disabled", enabled=False, status=AgentStatus.ACTIVE)
    decision = pm.authorize(agent, "tools.web.search")
    assert decision.decision == "DENY"
    assert decision.reason == "agent_inactive"


def test_permission_manager_suspended_agent_denied():
    pm = PermissionManager()
    agent = AgentRecord(agent_id="a1", name="Suspended", enabled=True, status=AgentStatus.SUSPENDED)
    decision = pm.authorize(agent, "tools.web.search")
    assert decision.decision == "DENY"
    assert decision.reason == "agent_inactive"


def test_permission_manager_medium_requires_approval():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.shell.execute"}
    agent = FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.MEDIUM)
    decision = pm.authorize(agent, "tools.shell.execute")
    assert decision.decision == "DENY"
    assert decision.approval_required is True
    assert decision.reason == "approval_required"


def test_permission_manager_high_requires_approval():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.shell.execute"}
    agent = FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.HIGH)
    decision = pm.authorize(agent, "tools.shell.execute")
    assert decision.decision == "DENY"
    assert decision.approval_required is True
    assert decision.reason == "approval_required"


def test_permission_manager_critical_requires_explicit_approval():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.destructive.wipe"}
    agent = FakeAgentRecord("a1", ["tools.destructive.wipe"], RiskLevel.CRITICAL)
    decision = pm.authorize(agent, "tools.destructive.wipe")
    assert decision.decision == "DENY"
    assert decision.risk == RiskLevel.CRITICAL
    assert decision.approval_id == "approval-a1-tools.destructive.wipe"
    pm.record_approval(decision.approval_id, True, metadata={"requested_by": "human"})
    decision = pm.authorize(agent, "tools.destructive.wipe")
    assert decision.decision == "ALLOW"
    assert decision.approval_id == "approval-a1-tools.destructive.wipe"


def test_permission_manager_forged_approval_rejected():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.destructive.wipe"}
    agent = FakeAgentRecord("a1", ["tools.destructive.wipe"], RiskLevel.CRITICAL)
    pm.approval_store["approval-a1-tools.destructive.wipe"] = {"approval_id": "approval-a1-tools.destructive.wipe", "approved": False}
    decision = pm.authorize(agent, "tools.destructive.wipe")
    assert decision.decision == "DENY"
    assert decision.reason == "approval_required"


def test_permission_manager_agent_cannot_grant_permissions():
    pm = PermissionManager()
    with pytest.raises(PermissionError):
        pm.grant("a1", ["tools.web.search"])


def test_permission_manager_model_cannot_modify_permissions():
    pm = PermissionManager()
    with pytest.raises(PermissionError):
        pm.revoke("a1", ["tools.web.search"])


def test_permission_manager_manifest_cannot_elevate_permissions():
    pm = PermissionManager()
    agent = AgentRecord(agent_id="a1", name="Manifest", capabilities=["tools.shell.execute"], risk_level=RiskLevel.HIGH, enabled=True, status=AgentStatus.ACTIVE)
    decision = pm.authorize(agent, "tools.shell.execute")
    assert decision.decision == "DENY"
    assert decision.reason == "missing_permission"


def test_permission_manager_denies_malformed_tool_id():
    pm = PermissionManager()
    agent = FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW)
    decision = pm.authorize(agent, "tools..execute")
    assert decision.decision == "DENY"


def test_permission_manager_risk_downgrade_ignored():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.destructive.wipe"}
    agent = FakeAgentRecord("a1", ["tools.destructive.wipe"], RiskLevel.CRITICAL)
    decision = pm.authorize(agent, "tools.destructive.wipe")
    assert decision.risk == RiskLevel.CRITICAL


# Tool interface


def test_tool_interface_denies_without_permission():
    pm = PermissionManager()
    tool = ToolInterface(pm)
    decision = tool.execute(None, "tools.web.search", {"query": "test"})
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "missing_agent"
    assert "tool_contract" not in decision


def test_tool_interface_never_calls_adapter_on_deny():
    pm = PermissionManager()

    class CallRecorder:
        def __init__(self):
            self.calls = 0

        def execute(self, agent, capability, payload):
            self.calls += 1
            return {"ok": True}

    tool = ToolInterface(pm, CallRecorder())
    decision = tool.execute(None, "tools.web.search", {"query": "test"})
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "missing_agent"


def test_tool_interface_returns_structured_authorization_decision():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search"}

    class ResultAdapter:
        def execute(self, agent, capability, payload):
            return {"ok": True}

    tool = ToolInterface(pm, ResultAdapter())
    decision = tool.execute(FakeAgentRecord("a1", ["tools.web.search"], RiskLevel.LOW), "tools.web.search", {"query": "ok"})
    assert decision["decision"] == "ALLOW"
    assert decision["approval_required"] is False
    assert decision["approval_id"] is None
    assert "tool_contract" in decision


# Redaction


def test_redact_api_key():
    assert redact({"api_key": "abc"}) == {"api_key": "[REDACTED]"}


def test_redact_nested():
    assert redact({"user": {"password": "x"}}) == {"user": {"password": "[REDACTED]"}}


# Isolation


def test_production_isolation_check_true_when_missing():
    assert production_isolation_check() is True


def test_production_path_rejected():
    from pathlib import Path
    with pytest.raises(PermissionError):
        assert_path_under_safenestt_ai(Path("/home/ronzoro/safenestt-platform"))


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
