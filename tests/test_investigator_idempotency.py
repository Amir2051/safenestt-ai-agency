from __future__ import annotations

from fastapi.testclient import TestClient

from safenestt.api.app import app


def test_failed_investigation_can_be_rerun():
    client = TestClient(app)
    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity", "tenant_id": "test-tenant"})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    first = client.post(f"/v1/investigations/{investigation_id}/start?tenant_id=test-tenant")
    assert first.status_code == 200
    assert first.json()["investigation_id"] == investigation_id

    second = client.post(f"/v1/investigations/{investigation_id}/start?tenant_id=test-tenant")
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "invalid_state"


def test_completed_investigation_blocks_duplicate_start():
    client = TestClient(app)
    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity", "tenant_id": "test-tenant"})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    first = client.post(f"/v1/investigations/{investigation_id}/start?tenant_id=test-tenant")
    assert first.status_code == 200
    assert first.json()["status"] == "COMPLETED"

    second = client.post(f"/v1/investigations/{investigation_id}/start?tenant_id=test-tenant")
    assert second.status_code == 409
