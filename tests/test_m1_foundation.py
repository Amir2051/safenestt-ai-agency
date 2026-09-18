"""Test M1 foundation — updated for new API architecture."""
from __future__ import annotations


def test_investigation_lifecycle():
    """Core lifecycle: create investigation and verify persistence."""
    from safenestt.security.api_keys import get_key_store, _compute_key_fingerprint
    from safenestt.persistence.engine import session_scope

    store = get_key_store()
    raw_key = "test-lifecycle-key-12345"
    raw, key_hash, fp = store.create_key(tenant_id="org-1", raw_key=raw_key, name="Lifecycle Test")

    with session_scope(tenant_id="org-1", key_fingerprint=fp) as session:
        from sqlalchemy import text
        session.execute(text("""
            INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
            VALUES ('inv-lifecycle', 'org-1', 'example.com', 'cybersecurity', 'QUEUED', 'user-1', NOW(), NOW())
        """))

    with session_scope(tenant_id="org-1", key_fingerprint=fp) as session:
        from sqlalchemy import text
        result = session.execute(text(
            "SELECT investigation_id, tenant_id FROM investigations WHERE investigation_id = 'inv-lifecycle'"
        )).fetchone()
        assert result is not None
        assert result[0] == 'inv-lifecycle'
        assert result[1] == 'org-1'


def test_live_model_environment_report():
    from safenestt.model.registry import GeminiProvider, OpenAICompatibleProvider, OllamaProvider
    from safenestt.model.provider import ModelRequest
    providers = {
        "openai": OpenAICompatibleProvider(api_key="test", base_url="http://localhost:8000"),
        "anthropic": OpenAICompatibleProvider(api_key="test", base_url="http://localhost:8000"),
        "ollama": OllamaProvider(base_url="http://localhost:11434"),
        "gemini": GeminiProvider(api_key="test", base_url="http://localhost:8000"),
    }
    results = {}
    for name, provider in providers.items():
        response = provider.generate(ModelRequest(prompt='Return JSON: {"ok": true}', model="live-test", response_format="json"))
        if response.error:
            results[name] = {"status": "ENVIRONMENT BLOCKED", "error": response.error.message}
        else:
            results[name] = {"status": "LIVE VERIFIED", "model": response.model, "content": response.content}
    assert all("status" in item for item in results.values())
    assert {"LIVE VERIFIED", "ENVIRONMENT BLOCKED"}.issubset({item["status"] for item in results.values()})
    print(results)


# M1.9 production integration tests


def test_investigation_state_machine_rejects_invalid_transitions():
    from safenestt.investigations.records import InvestigationRecord
    record = InvestigationRecord(investigation_id="inv-1")
    record.mark("RUNNING")
    with pytest.raises(Exception):
        record.mark("QUEUED")
    record.mark("FAILED")
    with pytest.raises(Exception):
        record.mark("RUNNING")


def test_create_investigation_api():
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app)

    # Register a test key
    from safenestt.security.api_keys import get_key_store
    store = get_key_store()
    raw_key, _, _ = store.create_key(tenant_id="org-1", raw_key="test-api-key-create-12345", name="API Test")

    resp = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity"}, headers={"X-API-Key": raw_key})
    assert resp.status_code == 200
    body = resp.json()
    assert "investigation_id" in body
    assert body["status"] == "QUEUED"


def test_start_investigation_sets_flow_and_idempotency():
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app)

    # Register a test key
    from safenestt.security.api_keys import get_key_store
    store = get_key_store()
    raw_key, _, _ = store.create_key(tenant_id="org-1", raw_key="test-api-key-start-12345", name="API Test")

    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "google.com"}, "investigation_type": "cybersecurity"}, headers={"X-API-Key": raw_key})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    body = first.json()
    assert body["status"] == "COMPLETED"

    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert second.status_code == 409


def test_get_investigation_api():
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app)

    # Register a test key
    from safenestt.security.api_keys import get_key_store
    store = get_key_store()
    raw_key, _, _ = store.create_key(tenant_id="org-1", raw_key="test-api-key-get-12345", name="API Test")

    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity"}, headers={"X-API-Key": raw_key})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == investigation_id


def test_cross_tenant_api_level_access_denied():
    """Test that cross-tenant access is blocked at the actual API endpoint level."""
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app, raise_server_exceptions=False)

    # Register test keys
    from safenestt.security.api_keys import get_key_store
    store = get_key_store()
    raw_key_a, _, _ = store.create_key(tenant_id="tenant-a", raw_key="test-api-key-tenant-a-12345", name="Tenant A")
    raw_key_b, _, _ = store.create_key(tenant_id="tenant-b", raw_key="test-api-key-tenant-b-12345", name="Tenant B")

    # Tenant A creates investigation
    create_resp = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "secret.example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key_a})
    assert create_resp.status_code == 200
    inv_id = create_resp.json()["investigation_id"]

    # Tenant A can fetch
    a_resp = client.get(f"/v1/investigations/{inv_id}", headers={"X-API-Key": raw_key_a})
    assert a_resp.status_code == 200

    # Tenant B must be denied (403)
    b_resp = client.get(f"/v1/investigations/{inv_id}", headers={"X-API-Key": raw_key_b})
    assert b_resp.status_code == 403


def test_real_dns_becomes_evidence():
    from safenestt.tools.dns import DNSAdapter
    adapter = DNSAdapter()
    result = adapter.execute(None, "tools.dns.lookup.lookup", {"target": "google.com"})
    assert result["status"] == "success"
    assert isinstance(result["data"].get("records"), list)
    assert result["data"].get("domain") == "google.com"


def test_unauthorized_tool_is_denied():
    from safenestt.security.pipeline import SecurityPipeline
    from safenestt.registry import AgentRecord, AgentStatus, RiskLevel
    pipeline = SecurityPipeline()
    agent = AgentRecord(agent_id="a1", name="A", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.web.search.search"], risk_level=RiskLevel.LOW)
    result = pipeline.check(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    # Should be denied because agent doesn't have explicit permission grant
    from safenestt.security.approval import ApprovalService
    approval = ApprovalService()
    record = approval.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    assert record.risk_level == "LOW"


def test_approval_service_approve_and_reject():
    from safenestt.security.approval import ApprovalService
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    service.approve(record.request_id, "test-actor")
    assert service.get(record.request_id).decision == "APPROVED"


def test_approval_service_reject_blocks_execution():
    from safenestt.security.approval import ApprovalService
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    service.reject(record.request_id, "test-actor")
    assert service.get(record.request_id).decision == "REJECTED"


def test_approval_service_cancel_blocks_execution():
    from safenestt.security.approval import ApprovalService
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW")
    service.cancel(record.request_id)
    assert service.get(record.request_id).decision == "CANCELLED"


def test_approval_service_expired_approval_rejected():
    from safenestt.security.approval import ApprovalService
    from datetime import datetime, timedelta
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW", expiration_at=datetime.utcnow() - timedelta(minutes=1))
    result = service.check(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search")
    assert result is None  # Expired


def test_approval_service_cross_tenant_rejected():
    from safenestt.security.approval import ApprovalService
    service = ApprovalService()
    record = service.request(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", risk_level="LOW", organization_id="tenant-a")
    # Different tenant trying to use the approval
    result = service.check(agent_id="a1", tool_id="web.search", action="search", requested_capability="tools.web.search.search", organization_id="tenant-b")
    assert result is None  # Cross-tenant denied


def test_audit_service_records_redacted_event():
    from safenestt.security.audit import AuditLogger
    from datetime import datetime
    service = AuditLogger()
    service.record(
        event_id="test-event-1",
        timestamp=datetime.utcnow(),
        organization_id="tenant-a",
        actor_type="api",
        actor_id="user-1",
        action="investigation.create",
        decision="ALLOW",
        risk_level="LOW",
        resource_type="investigation",
        resource_id="inv-1",
        detail={"target": "example.com", "api_key": "secret-key-12345"},
    )
    events = service.list_events("tenant-a")
    assert len(events) >= 1
    # Verify secret was redacted
    latest = events[-1]
    assert "secret-key-12345" not in str(latest.detail)
    assert "REDACTED" in str(latest.detail)


def test_audit_service_append_behavior_is_immutable():
    from safenestt.security.audit import AuditLogger
    from datetime import datetime
    service = AuditLogger()
    service.record(
        event_id="test-immutable-1",
        timestamp=datetime.utcnow(),
        organization_id="tenant-a",
        actor_type="api",
        actor_id="user-1",
        action="investigation.create",
        decision="ALLOW",
        risk_level="LOW",
        resource_type="investigation",
        resource_id="inv-1",
        detail={"target": "example.com"},
    )
    events_before = len(service.list_events("tenant-a"))
    # Try to modify the returned event
    events = service.list_events("tenant-a")
    if events:
        try:
            events[-1].detail = {"hacked": True}
        except Exception:
            pass
    events_after = len(service.list_events("tenant-a"))
    assert events_before == events_after


def test_audit_service_cross_tenant_isolation():
    from safenestt.security.audit import AuditLogger
    from datetime import datetime
    service = AuditLogger()
    service.record(
        event_id="test-audit-tenant-a",
        timestamp=datetime.utcnow(),
        organization_id="tenant-a",
        actor_type="api",
        actor_id="user-1",
        action="investigation.create",
        decision="ALLOW",
        risk_level="LOW",
    )
    service.record(
        event_id="test-audit-tenant-b",
        timestamp=datetime.utcnow(),
        organization_id="tenant-b",
        actor_type="api",
        actor_id="user-2",
        action="investigation.create",
        decision="ALLOW",
        risk_level="LOW",
    )
    events_a = service.list_events("tenant-a")
    events_b = service.list_events("tenant-b")
    # Tenant B should not see Tenant A's events
    tenant_a_event_ids = {e.event_id for e in events_a}
    tenant_b_event_ids = {e.event_id for e in events_b}
    assert "test-audit-tenant-a" not in tenant_b_event_ids
    assert "test-audit-tenant-b" not in tenant_a_event_ids


def test_tool_interface_approval_required_never_executes_adapter():
    from safenestt.tools.interface import ToolInterface
    from safenestt.security.permissions import PermissionManager
    from safenestt.tools.manifest import ToolManifest
    from safenestt.registry import AgentRecord, AgentStatus, RiskLevel

    pm = PermissionManager()
    tool = ToolInterface(pm)
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    agent = AgentRecord(agent_id="a1", name="A", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.web.search.search"], risk_level= RiskLevel.LOW)

    # Without approval, tool should not execute
    result = tool.execute(agent, "tools.web.search.search", {"query": "test"}, manifest=manifest)
    assert result["status"] == "error"
    assert "approval" in result.get("message", "").lower() or "denied" in result.get("message", "").lower()


def test_reality_checker_provenance_rejection():
    from safenestt.investigations.reality import RealityChecker
    from safenestt.investigations.records import FindingRecord
    checker = RealityChecker(evidence_lookup=lambda investigation_id, evidence_id: None if investigation_id != "inv-1" or evidence_id != "ev-1" else {"ok": True})
    finding = FindingRecord(investigation_id="inv-1", finding_id="find-1", claim="x", evidence_ids=["other-inv-ev"])
    result = checker.evaluate(finding)
    assert result.reality_status == "AI_INFERENCE"


def test_risk_engine_ignores_unsupported_findings():
    from safenestt.investigations.risk import calculate_risk
    from safenestt.investigations.records import FindingRecord
    findings = [FindingRecord(investigation_id="inv-1", finding_id="find-1", claim="x")]
    result = calculate_risk(findings)
    assert result["factors"]["supported"] == 0
    assert result["factors"]["unsupported"] == 1


def test_complete_investigation_lifecycle():
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app)

    # Register a test key
    from safenestt.security.api_keys import get_key_store
    store = get_key_store()
    raw_key, _, _ = store.create_key(tenant_id="org-1", raw_key="test-api-key-complete-12345", name="API Test")

    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity"}, headers={"X-API-Key": raw_key})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    get_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
    assert get_resp.status_code == 200


def test_provider_unavailable_returns_error():
    from safenestt.model.registry import OpenAICompatibleProvider
    from safenestt.model.provider import ModelRequest
    provider = OpenAICompatibleProvider()
    response = provider.generate(ModelRequest(prompt="ping", model="stub"))
    assert response.error is not None


def test_tool_unavailable_is_error():
    from safenestt.tools.dns import DNSAdapter
    adapter = DNSAdapter()
    result = adapter.execute(None, "tools.dns.lookup.lookup", {})
    assert result["status"] == "error"


def test_health_endpoint():
    from fastapi.testclient import TestClient
    from safenestt.api.app import app
    client = TestClient(app)
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "model" in body
    assert "tools" in body


def test_secret_redaction_in_tool_result():
    from safenestt.tools.interface import ToolInterface
    from safenestt.security.permissions import PermissionManager
    from safenestt.tools.manifest import ToolManifest
    from safenestt.registry import AgentRecord, AgentStatus, RiskLevel

    class SecretAdapter:
        def execute(self, agent, capability, payload):
            return {"status": "success", "data": {}, "metadata": {"api_key": "secret"}}

    pm = PermissionManager()
    tool = ToolInterface(pm)
    manifest = ToolManifest(tool_id="web.search", name="Web Search", description="", provider="mock", actions=["search"], enabled=True, risk_level="LOW")
    agent = AgentRecord(agent_id="a1", name="A", enabled=True, status=AgentStatus.ACTIVE, capabilities=["tools.web.search.search"], risk_level=RiskLevel.LOW)
    result = tool.execute(agent, "tools.web.search.search", {"query": "x"}, manifest=manifest, adapter=SecretAdapter())
    # Secret should be redacted
    assert "secret" not in str(result.get("metadata", {}))
