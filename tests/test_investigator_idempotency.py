from __future__ import annotations

import time

from fastapi.testclient import TestClient

from safenestt.api.app import app
from safenestt.security.api_keys import get_key_store


def _make_client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def _register_key(tenant_id: str, raw_key: str) -> str:
    store = get_key_store()
    raw, _, _ = store.create_key(tenant_id=tenant_id, raw_key=raw_key, name="Test")
    return raw


def test_failed_investigation_can_be_rerun() -> None:
    """A FAILED investigation can be rerun (transition FAILED → QUEUED → RUNNING)."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-failed-reenlist-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Start the investigation
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    assert first.json()["investigation_id"] == investigation_id

    # Wait for it to reach terminal state
    for _ in range(20):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200:
            status = status_resp.json().get("status", "")
            if status in {"COMPLETED", "FAILED"}:
                break

    # Now try to start again — should get 409 (already terminal)
    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "invalid_state"


def test_completed_investigation_blocks_duplicate_start() -> None:
    """A COMPLETED investigation cannot be started again."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-completed-block-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    # Start and wait for COMPLETED
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200

    for _ in range(20):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200 and status_resp.json().get("status") == "COMPLETED":
            break

    # Duplicate start should be rejected
    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert second.status_code == 409
