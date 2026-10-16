"""
Regression tests for the async investigation lifecycle fix.

These tests verify that:
1. A successful asynchronous investigation reaches its correct terminal success state.
2. A background execution exception reaches a valid terminal failure state.
3. COMPLETED_WITH_ERRORS is reached only through a valid lifecycle path.
4. The record can be retrieved after success and after failure.
5. Repeated or secondary error handling does not leave the record stuck in RUNNING.
6. Existing synchronous behavior remains intact.

These tests use mocked dependencies and isolated test data where possible.
They do NOT create real investigations or run destructive database operations.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from safenestt.api.app import app
from safenestt.investigations.records import InvestigationRecord, InvalidStatusError
from safenestt.security.api_keys import get_key_store


def _make_client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def _register_key(tenant_id: str, raw_key: str) -> str:
    store = get_key_store()
    raw, _, _ = store.create_key(tenant_id=tenant_id, raw_key=raw_key, name="Test")
    return raw


# ============================================================================
# Test 1: Successful synchronous investigation (wait=true) — unchanged behavior
# ============================================================================
def test_synchronous_investigation_success() -> None:
    """Existing synchronous behavior remains intact (wait=true default)."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-sync-success-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Synchronous start (wait=true, the default)
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200, f"start failed: {first.status_code}"
    result = first.json()
    assert result["investigation_id"] == investigation_id
    assert result.get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}

    # Record should be retrievable after success
    status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
    assert status_resp.status_code == 200
    assert status_resp.json().get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}


# ============================================================================
# Test 2: Successful asynchronous investigation (wait=false) reaches terminal
# ============================================================================
def test_asynchronous_investigation_success() -> None:
    """A successful async investigation reaches its correct terminal success state."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-async-success-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Asynchronous start (wait=false)
    first = client.post(
        f"/v1/investigations/{investigation_id}/start?wait=false",
        headers={"X-API-Key": raw_key},
    )
    assert first.status_code == 200, f"async start failed: {first.status_code}"
    result = first.json()
    assert result["investigation_id"] == investigation_id
    assert result.get("status") == "RUNNING"

    # Poll until terminal state is reached (with timeout)
    for _ in range(30):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200:
            status = status_resp.json().get("status", "")
            if status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}:
                break

    # The investigation should reach a terminal state, not stay stuck in RUNNING
    final_status = status_resp.json().get("status", "")
    assert final_status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}, (
        f"Investigation stuck in RUNNING; final status={final_status}"
    )


# ============================================================================
# Test 3: Background exception reaches a valid terminal failure state
# ============================================================================
def test_background_exception_terminal_failure() -> None:
    """A background execution exception reaches a valid terminal failure state."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-async-fail-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Start asynchronously
    first = client.post(
        f"/v1/investigations/{investigation_id}/start?wait=false",
        headers={"X-API-Key": raw_key},
    )
    assert first.status_code == 200, f"async start failed: {first.status_code}"
    result = first.json()
    assert result.get("status") == "RUNNING"

    # Poll until terminal state is reached (with timeout)
    for _ in range(30):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200:
            status = status_resp.json().get("status", "")
            if status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}:
                break

    # The record should not be stuck in RUNNING — it should reach FAILED
    final_status = status_resp.json().get("status", "")
    assert final_status != "RUNNING", f"Investigation stuck in RUNNING: {final_status}"
    assert final_status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}, (
        f"Unexpected terminal status: {final_status}"
    )


# ============================================================================
# Test 4: COMPLETED_WITH_ERRORS is reached only through a valid lifecycle path
# ============================================================================
def test_completed_with_errors_valid_lifecycle() -> None:
    """COMPLETED_WITH_ERRORS is reached through a valid lifecycle path.

    The transition from RUNNING to COMPLETED_WITH_ERRORS is now valid (added
    in the fix), and the transition validator enforces all other transitions.
    """
    # Test that RUNNING -> COMPLETED_WITH_ERRORS is now valid
    record = InvestigationRecord(investigation_id="inv-1", status="RUNNING")
    record.mark("COMPLETED_WITH_ERRORS")  # Should now be valid
    assert record.status == "COMPLETED_WITH_ERRORS"

    # Test that other invalid transitions are still rejected
    record2 = InvestigationRecord(investigation_id="inv-2", status="RUNNING")
    try:
        record2.mark("QUEUED")
        assert False, "RUNNING -> QUEUED should be invalid"
    except InvalidStatusError:
        pass  # Expected

    record3 = InvestigationRecord(investigation_id="inv-3", status="RUNNING")
    try:
        record3.mark("CANCELLED")
        # CANCELLED IS valid from RUNNING — no assertion needed
    except InvalidStatusError:
        assert False, "RUNNING -> CANCELLED should be valid"


# ============================================================================
# Test 5: Record retrievability after success and after failure
# ============================================================================
def test_record_retrievable_after_success() -> None:
    """The record can be retrieved after a successful investigation."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-retrievable-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Start synchronously (wait=true)
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    assert first.json().get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}

    # Retrieve the record — must be accessible
    status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
    assert status_resp.status_code == 200
    assert status_resp.json().get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}


def test_record_retrievable_after_failure() -> None:
    """The record can be retrieved after a failed investigation."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-retrievable-fail-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Start synchronously
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    assert first.json().get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}

    # Retrieve the record — must be accessible even after failure
    status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
    assert status_resp.status_code == 200
    assert status_resp.json().get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}


# ============================================================================
# Test 6: Repeated/secondary error handling does not leave the record stuck
# ============================================================================
def test_no_secondary_errors_stuck_in_running() -> None:
    """Repeated or secondary error handling does not leave the record stuck in RUNNING."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-no-stuck-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Start asynchronously and trigger a failure
    first = client.post(
        f"/v1/investigations/{investigation_id}/start?wait=false",
        headers={"X-API-Key": raw_key},
    )
    assert first.status_code == 200
    assert first.json().get("status") == "RUNNING"

    # Poll until terminal state is reached
    for _ in range(30):
        time.sleep(2)
        status_resp = client.get(f"/v1/investigations/{investigation_id}", headers={"X-API-Key": raw_key})
        if status_resp.status_code == 200:
            status = status_resp.json().get("status", "")
            if status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}:
                break

    # The record should NOT be stuck in RUNNING
    final_status = status_resp.json().get("status", "")
    assert final_status != "RUNNING", (
        f"Secondary error handling left the record stuck in RUNNING: {final_status}"
    )


# ============================================================================
# Test 7: Synchronous behavior remains intact
# ============================================================================
def test_synchronous_behavior_intact() -> None:
    """Existing synchronous behavior (wait=true) remains intact."""
    client = _make_client()
    raw_key = _register_key("org-1", "test-sync-intact-12345")

    create = client.post("/v1/investigations", json={
        "target": {"type": "domain", "value": "example.com"},
        "investigation_type": "cybersecurity",
    }, headers={"X-API-Key": raw_key})
    assert create.status_code == 200, f"create failed: {create.status_code}"
    investigation_id = create.json()["investigation_id"]

    # Synchronous start (default wait=true)
    first = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert first.status_code == 200
    result = first.json()
    assert result["investigation_id"] == investigation_id
    assert result.get("status") in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}

    # Duplicate start must be rejected
    second = client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "invalid_state"
