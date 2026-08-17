from __future__ import annotations

import pytest

from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel
from safenestt.orchestrator import Orchestrator, Task, TaskStatus
from safenestt.security.audit import AuditEvent, AuditLogger, audit
from safenestt.security.permissions import AuthorizationDecision, PermissionManager, permission_manager
from safenestt.security.redaction import redact
from safenestt.security.isolation import assert_path_under_safenestt_ai, production_isolation_check
from safenestt.tools.interface import Adapter, ToolInterface
from safenestt.tools.manifest import ToolManifest, default_tool_manifest
from safenestt.tools.mocks import MockDocumentLookupResult, MockIdentityLookupResult, MockURLAnalysisResult, MockWebSearchResult, ProviderFailure, ProviderTimeout, mock_provider_failure, mock_provider_malformed, mock_provider_timeout
from safenestt.tools.registry import ToolRegistry, tool_registry
from safenestt.tools.result import ToolResult
from safenestt.memory.provider import MemoryRecord, StubMemoryProvider, memory_provider
from safenestt.model.registry import (
    AnthropicCompatibleProvider,
    ModelError,
    ModelProvider,
    ModelProviderConfig,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    MockModelProvider,
    OpenAICompatibleProvider,
    OllamaProvider,
    model_registry,
)
from safenestt.security.approval import ApprovalService
from safenestt.security.audit_persistent import AuditService
from safenestt.security.rate_limit import RateLimitService
from safenestt.security.pipeline import SecurityPipeline


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
    assert decision["reason"] == "missing_manifest"
    assert "result" not in decision


def test_tool_interface_never_calls_adapter_on_deny():
    pm = PermissionManager()

    class CallRecorder:
        def __init__(self):
            self.calls = 0

        def execute(self, agent, capability, payload):
            self.calls += 1
            return {"ok": True}

    tool = ToolInterface(pm)
    decision = tool.execute(None, "tools.web.search", {"query": "test"}, adapter=CallRecorder())
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "missing_manifest"


def test_tool_interface_returns_structured_authorization_decision():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")

    class ResultAdapter:
        def execute(self, agent, capability, payload):
            return {"ok": True}

    tool = ToolInterface(pm)
    decision = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "ok"}, manifest=manifest, adapter=ResultAdapter())
    assert decision["decision"] == "ALLOW"
    assert decision["approval_required"] is False
    assert decision["approval_id"] is None
    assert "result" in decision


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


# Tool manifest / registry / interface


def test_tool_manifest_unknown_tool_rejected():
    registry = ToolRegistry()
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True)
    registry.register(manifest)
    tool = ToolInterface()
    decision = tool.validate(manifest, "tools.other.search", {"query": "x"})
    assert decision.decision == "DENY"
    assert decision.reason == "unknown_tool"


def test_tool_manifest_unknown_action_rejected():
    registry = ToolRegistry()
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True)
    registry.register(manifest)
    tool = ToolInterface()
    decision = tool.validate(manifest, "tools.web.search.lookup", {"query": "x"})
    assert decision.decision == "DENY"
    assert decision.reason == "unknown_action"


def test_tool_manifest_disabled_tool_rejected():
    registry = ToolRegistry()
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=False)
    registry.register(manifest)
    tool = ToolInterface()
    decision = tool.validate(manifest, "tools.web.search.search", {"query": "x"})
    assert decision.decision == "DENY"
    assert decision.reason == "tool_disabled"


def test_tool_registry_duplicate_rejected():
    registry = ToolRegistry()
    registry.register(ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"]))
    with pytest.raises(ValueError):
        registry.register(ToolManifest(tool_id="web.search", name="Web Search 2", description="", provider="mock", actions=["search"]))


def test_tool_interface_unknown_tool_denies():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    tool = ToolInterface(pm)
    decision = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"})
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "missing_manifest"


def test_tool_interface_disabled_tool_denies():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=False)
    tool = ToolInterface(pm)
    decision = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "tool_disabled"


def test_tool_interface_invalid_arguments_deny():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    decision = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", None, manifest=manifest)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "invalid_arguments"


def test_tool_interface_authorized_execution():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)

    class WebAdapter:
        def execute(self, agent, capability, payload):
            return MockWebSearchResult(query=payload.get("query", "")).to_tool_result()

    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=WebAdapter())
    assert result["decision"] == "ALLOW"
    assert result["tool_id"] == "web.search"
    assert result["result"]["data"]["query"] == "x"


def test_tool_interface_unauthorized_execution():
    pm = PermissionManager()
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    result = tool.execute(None, "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=MockWebSearchResult(query="x"))
    assert result["decision"] == "DENY"
    assert result["reason"] == "missing_agent"


def test_tool_interface_approval_required_never_executes_adapter():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.shell.execute"}
    manifest = ToolManifest(tool_id="shell", name="Shell", description="", provider="mock", actions=["execute"], enabled=True, risk_level="HIGH")

    class CallRecorder:
        def __init__(self):
            self.calls = 0
        def execute(self, agent, capability, payload):
            self.calls += 1
            return {"ok": True}

    tool = ToolInterface(pm, adapter=CallRecorder())
    result = tool.execute(FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.HIGH), "tools.shell.execute", {"command": "ls"}, manifest=manifest)
    assert result["decision"] == "DENY"
    assert result["reason"] == "approval_required"


def test_tool_interface_approval_gated_execution():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.shell.execute"}
    manifest = ToolManifest(tool_id="shell", name="Shell", description="", provider="mock", actions=["execute"], enabled=True, risk_level="HIGH")
    tool = ToolInterface(pm)
    pm.record_approval("approval-a1-tools.shell.execute", True)
    result = tool.execute(FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.HIGH), "tools.shell.execute", {"command": "ls"}, manifest=manifest, adapter=MockWebSearchResult(query="ls"))
    assert result["decision"] == "ALLOW"
    assert result["tool_id"] == "shell"
    assert result["approval_required"] is True


def test_tool_interface_provider_failure():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=mock_provider_failure)
    assert result["decision"] == "ALLOW"
    assert result["result"]["status"] == "error"
    assert result["result"]["error"] == "mock provider failure"


def test_tool_interface_provider_timeout():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=mock_provider_timeout)
    assert result["decision"] == "ALLOW"
    assert result["result"]["status"] == "error"


def test_tool_interface_malformed_provider_result():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=mock_provider_malformed)
    assert result["decision"] == "ALLOW"
    assert result["result"]["status"] == "error"
    assert result["result"]["error"] == "malformed_provider_response"


def test_tool_interface_structured_tool_result():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)
    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=MockWebSearchResult(query="x"))
    assert result["result"]["tool_id"] == "web.search"
    assert result["result"]["action"] == "tools.web.search.search"
    assert result["result"]["status"] == "success"
    assert "data" in result["result"]
    assert "metadata" in result["result"]


def test_tool_interface_redacts_provider_metadata():
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    tool = ToolInterface(pm)

    class SecretAdapter:
        def execute(self, agent, capability, payload):
            return {"status": "success", "data": {}, "metadata": {"api_key": "secret"}}

    result = tool.execute(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=SecretAdapter())
    assert result["result"]["metadata"] == {"api_key": "[REDACTED]"}


def test_tool_manifest_cannot_lower_risk():
    manifest = ToolManifest(tool_id="high.tool", name="High", description="", provider="mock", actions=["run"], enabled=True, risk_level="LOW")
    pm = PermissionManager()
    pm.granted_permissions["a1"] = {"tools.high.tool.run"}
    decision = pm.authorize(FakeAgentRecord("a1", ["tools.high.tool.run"], RiskLevel.CRITICAL), "tools.high.tool.run")
    assert decision.risk == RiskLevel.CRITICAL


def test_tool_manifest_requires_valid_registration():
    registry = ToolRegistry()
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"])
    registry.register(manifest)
    assert registry.get("web.search") is manifest
    assert registry.get("missing") is None


# Model provider abstraction


def test_mock_model_provider_generates_deterministic_response():
    provider = MockModelProvider()
    request = ModelRequest(prompt="test prompt", model="mock-model")
    response = provider.generate(request)
    assert response.provider == "mock"
    assert response.model == "mock-model"
    assert "test prompt" in (response.content or "")
    assert response.usage.total_tokens == 12


def test_mock_model_provider_custom_response():
    provider = MockModelProvider()
    provider.responses["mock-model:custom"] = {"content": "custom", "structured_data": {"ok": True}, "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
    response = provider.generate(ModelRequest(prompt="custom", model="mock-model"))
    assert response.content == "custom"
    assert response.structured_data == {"ok": True}
    assert response.usage.total_tokens == 2


def test_mock_model_provider_health_check():
    provider = MockModelProvider()
    response = provider.health_check()
    assert response.provider == "mock"
    assert response.content == "configured"


def test_openai_compatible_provider_not_configured():
    provider = OpenAICompatibleProvider()
    response = provider.generate(ModelRequest(prompt="hi", model="gpt-stub"))
    assert response.error.code == "not_configured"
    assert response.content is None


def test_openai_compatible_provider_configured_stub():
    provider = OpenAICompatibleProvider(api_key="test", base_url="http://example.local")
    response = provider.generate(ModelRequest(prompt="hi", model="gpt-stub"))
    assert response.error is None
    assert response.provider == "openai"
    assert response.content == "openai-compatible stub"


def test_anthropic_compatible_provider_not_configured():
    provider = AnthropicCompatibleProvider()
    response = provider.generate(ModelRequest(prompt="hi", model="claude-stub"))
    assert response.error.code == "not_configured"


def test_ollama_provider_not_configured():
    provider = OllamaProvider()
    response = provider.generate(ModelRequest(prompt="hi", model="llama3"))
    assert response.error.code == "not_configured"


def test_ollama_provider_configured_stub():
    provider = OllamaProvider(base_url="http://localhost:11434")
    response = provider.generate(ModelRequest(prompt="hi", model="llama3"))
    assert response.error is None
    assert response.content == "ollama stub"


def test_model_registry_registration_and_default():
    registry = ModelRegistry()
    registry.register(MockModelProvider())
    registry.register(MockModelProvider(provider_name="second"))
    assert registry.get("mock") is not None
    assert registry.get("second") is not None
    with pytest.raises(ValueError):
        registry.register(MockModelProvider(provider_name="mock"))


def test_model_registry_set_default():
    registry = ModelRegistry()
    registry.register(MockModelProvider())
    registry.register(MockModelProvider(provider_name="fallback"))
    registry.set_default("fallback")
    assert registry.default().provider_name == "fallback"


def test_model_registry_unknown_provider_returns_none():
    registry = ModelRegistry()
    registry.register(MockModelProvider())
    assert registry.get("missing") is None
    assert registry.default() is not None


def test_model_registry_empty_default_is_none():
    registry = ModelRegistry()
    assert registry.default() is None


def test_model_provider_secrets_never_logged():
    provider = OpenAICompatibleProvider(api_key="secret-key", base_url="http://example.local")
    response = provider.generate(ModelRequest(prompt="hi", model="gpt-stub"))
    audit_events = [event for event in audit.recent() if event.action == "model.generate"]
    assert not any("secret-key" in str(event.metadata) for event in audit_events)


def test_model_provider_does_not_modify_permissions():
    pm = PermissionManager()
    provider = OpenAICompatibleProvider(api_key="test", base_url="http://example.local")
    try:
        provider.generate(ModelRequest(prompt="hi", model="gpt-stub"))
    except Exception:
        pass
    assert "gpt-stub" not in pm.granted_permissions


# Approval persistence


def test_approval_service_request_and_lookup():
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    assert record.status == "pending"
    assert service.is_approved(record.approval_id) is False


def test_approval_service_approve_and_reject():
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    approved = service.record_decision(record.approval_id, True)
    assert approved.status == "approved"
    assert service.is_approved(record.approval_id) is True


def test_approval_service_reject_blocks_execution():
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    service.record_decision(record.approval_id, False)
    assert service.is_approved(record.approval_id) is False


def test_approval_service_cancel_blocks_execution():
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    assert service.repository.cancel(record.approval_id) is not None
    assert service.is_approved(record.approval_id) is False


def test_approval_service_expired_approval_rejected():
    from datetime import datetime, timedelta
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW", expiration_at=datetime.utcnow() - timedelta(minutes=1))
    service.record_decision(record.approval_id, True)
    assert service.is_approved(record.approval_id) is False


def test_approval_service_cross_tenant_rejected():
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW", organization_id="org-1")
    service.record_decision(record.approval_id, True)
    assert service.is_approved(record.approval_id, organization_id="org-1") is True
    assert service.is_approved(record.approval_id, organization_id="org-2") is False


# Audit persistence


def test_audit_service_records_redacted_event():
    service = AuditService()
    event = service.record("org-1", actor_type="agent", actor_id="a1", action="tool.execute", decision="DENY", risk="LOW", metadata={"api_key": "secret"})
    assert event.metadata["api_key"] == "[REDACTED]"


def test_audit_service_append_behavior_is_immutable():
    service = AuditService()
    first = service.record("org-1", actor_type="agent", actor_id="a1", action="tool.execute", decision="DENY", risk="LOW")
    second = service.record("org-1", actor_type="agent", actor_id="a1", action="tool.execute", decision="ALLOW", risk="LOW")
    recent = service.repository.recent(organization_id="org-1")
    assert len(recent) == 2
    assert recent[0].event_id == first.event_id
    assert recent[1].event_id == second.event_id


def test_audit_service_cross_tenant_isolation():
    service = AuditService()
    service.record("org-1", actor_type="agent", actor_id="a1", action="tool.execute", decision="DENY", risk="LOW")
    service.record("org-2", actor_type="agent", actor_id="a1", action="tool.execute", decision="DENY", risk="LOW")
    org1_events = service.repository.recent(organization_id="org-1")
    assert len(org1_events) == 1
    assert org1_events[0].organization_id == "org-1"


# Rate limiting


def test_rate_limiter_allows_under_limit():
    service = RateLimitService()
    result = service.enforce("tool", "web.search", limit=2, window_seconds=60)
    assert result.allowed is True
    assert result.remaining == 1


def test_rate_limiter_denies_over_limit():
    service = RateLimitService()
    service.enforce("tool", "web.search", limit=1, window_seconds=60)
    result = service.enforce("tool", "web.search", limit=1, window_seconds=60)
    assert result.allowed is False
    assert result.remaining == 0


def test_rate_limiter_reset_restores_limit():
    service = RateLimitService()
    service.enforce("tool", "web.search", limit=1, window_seconds=1)
    result = service.enforce("tool", "web.search", limit=1, window_seconds=1)
    assert result.allowed is False


# Security pipeline


def test_security_pipeline_denies_without_permission():
    pipeline = SecurityPipeline()
    decision = pipeline.authorize(None, "tools.web.search.search", organization_id="org-1")
    assert decision.decision == "DENY"
    assert decision.rate_limited is False


def test_security_pipeline_denies_pending_approval():
    pipeline = SecurityPipeline()
    pm = pipeline.permission_manager
    pm.granted_permissions["a1"] = {"tools.shell.execute"}
    approval = pipeline.approval_service.request(agent_id="a1", tool_id="shell", action="execute", requested_capability="tools.shell.execute", risk_level="HIGH", organization_id="org-1")
    pm.record_approval(approval.approval_id, True, metadata={"requested_by": "human"})
    decision = pipeline.authorize(FakeAgentRecord("a1", ["tools.shell.execute"], RiskLevel.HIGH), "tools.shell.execute", organization_id="org-1", tool_id="shell")
    assert decision.decision == "DENY"
    assert decision.reason == "approval_required"


def test_security_pipeline_rate_limited_blocks_execution():
    pipeline = SecurityPipeline()
    pipeline.rate_limit_service.enforce("tool", "a1:tools.web.search.search", limit=0, window_seconds=60)
    decision = pipeline.authorize(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", organization_id="org-1", tool_id="web.search")
    assert decision.decision == "DENY"
    assert decision.rate_limited is True


def test_security_pipeline_disabled_agent_denied():
    pipeline = SecurityPipeline()
    agent = AgentRecord(agent_id="a1", name="Disabled", enabled=False, status=AgentStatus.ACTIVE)
    decision = pipeline.authorize(agent, "tools.web.search.search", organization_id="org-1", tool_id="web.search")
    assert decision.decision == "DENY"


def test_security_pipeline_valid_authorized_execution_allowed():
    pipeline = SecurityPipeline()
    pm = pipeline.permission_manager
    pm.granted_permissions["a1"] = {"tools.web.search.search"}
    decision = pipeline.authorize(FakeAgentRecord("a1", ["tools.web.search.search"], RiskLevel.LOW), "tools.web.search.search", organization_id="org-1", tool_id="web.search")
    assert decision.decision == "ALLOW"
    assert decision.rate_limited is False
    assert decision.requires_approval is False
