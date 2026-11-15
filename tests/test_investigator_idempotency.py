from __future__ import annotations

import time

from fastapi.testclient import TestClient

from safenestt.api.app import app
from safenestt.investigations.records import InvestigationRecord
from safenestt.security.api_keys import get_key_store


def _make_client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def _register_key(tenant_id: str, raw_key: str) -> str:
    store = get_key_store()
    raw, _, _ = store.create_key(tenant_id=tenant_id, raw_key=raw_key, name="Test")
    return raw


def _wait_for_status(
    client: TestClient,
    investigation_id: str,
    raw_key: str,
    expected: set[str],
) -> str:
    status = ""
    for _ in range(20):
        time.sleep(2)
        resp = client.get(
            f"/v1/investigations/{investigation_id}",
            headers={"X-API-Key": raw_key},
        )
        if resp.status_code == 200:
            status = resp.json().get("status", "")
            if status in expected:
                break
    return status


def test_completed_investigation_can_be_rerun() -> None:
    """A terminal investigation run can be requeued for another run."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-completed-rerun-12345")

    create = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "example.com"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": raw_key},
    )
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    first = client.post(
        f"/v1/investigations/{investigation_id}/start",
        headers={"X-API-Key": raw_key},
    )
    assert first.status_code == 200

    status = _wait_for_status(
        client, investigation_id, raw_key, {"COMPLETED", "FAILED"}
    )
    assert status in {"COMPLETED", "FAILED"}, f"unexpected terminal status: {status}"

    second = client.post(
        f"/v1/investigations/{investigation_id}/start",
        headers={"X-API-Key": raw_key},
        json={
            "target": {"type": "domain", "value": "example.org"},
            "targets": [{"type": "domain", "value": "example.org"}],
            "narrative": "Updated case information",
        },
    )
    assert second.status_code == 200
    assert second.json()["investigation_id"] == investigation_id


def test_completed_state_allows_requeue() -> None:
    """The state machine permits terminal runs to be requeued."""
    transitions = InvestigationRecord.TRANSITIONS
    assert "QUEUED" in transitions["COMPLETED"]
    assert "QUEUED" in transitions["FAILED"]
    assert "QUEUED" in transitions["CANCELLED"]
    assert "QUEUED" not in transitions["COMPLETED_WITH_ERRORS"]
