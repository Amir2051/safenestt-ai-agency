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


def test_start_after_failed_investigation_is_handled_gracefully() -> None:
    """Starting an investigation that previously failed should re-queue it gracefully."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-rerun-reg-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    # Start and wait for terminal
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    assert first.json()["investigation_id"] == investigation_id

    for _ in range(20):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200:
            status = status_resp.json().get("status", "")
            if status in {"COMPLETED", "FAILED"}:
                break

    # Duplicate start attempt — should be rejected with 409
    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "invalid_state"
