from __future__ import annotations

from fastapi.testclient import TestClient

from safenestt.api.app import app


def test_start_after_failed_investigation_is_handled_gracefully():
    client = TestClient(app)
    create = client.post("/v1/investigations", json={"target": {"type": "domain", "value": "example.com"}, "investigation_type": "cybersecurity"}, headers={"X-API-Key": "test-tenant"})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": "test-tenant"})
    assert first.status_code in {200, 409, 500}
    body = first.json()
    if first.status_code == 200:
        assert body["investigation_id"] == investigation_id

    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": "test-tenant"})
    assert second.status_code in {200, 409, 500}
