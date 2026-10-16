"""Blocker 4 — long-running /start lifecycle.

Proves an investigation started with ?wait=false keeps running and completes
AFTER the initiating HTTP request has already returned, so no caller depends
on holding an open connection for the duration of the investigation.
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "54322")
os.environ.setdefault("DB_NAME", "safenestt_ai_test")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "postgres")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "postgres")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

import hashlib
import uuid

import pytest
from sqlalchemy import text

from safenestt.investigations.records import InvestigationRecord
from safenestt.investigations.store import PersistentInvestigationStore
from safenestt.persistence.engine import create_engine

TENANT = "safenestt-longrun-test"
RUN_ID = uuid.uuid4().hex[:12]
RAW_KEY = "test-longrun-" + RUN_ID
FINGERPRINT = hashlib.sha256(RAW_KEY.encode()).hexdigest()
KEY_HASH = "sha256:" + hashlib.sha256(("h-" + RUN_ID).encode()).hexdigest()

TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"}


def _register_key():
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "55432")),
        user=os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_test"),
        password=os.environ.get("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only"),
        dbname=os.environ["DB_NAME"], sslmode="disable",
    )
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO api_keys (key_hash, key_fingerprint, tenant_id, name, "
        "active, revoked, scopes, use_count, created_at) "
        "VALUES (%s,%s,%s,'longrun-test',TRUE,FALSE,'[\"read\",\"write\"]'::json,0,NOW()) "
        "ON CONFLICT (key_fingerprint) DO UPDATE SET active=TRUE, revoked=FALSE",
        (KEY_HASH, FINGERPRINT, TENANT))
    conn.commit()
    cur.close()
    conn.close()


def _ctx(store: PersistentInvestigationStore):
    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t,:f)"),
                  {"t": TENANT, "f": FINGERPRINT})


@pytest.fixture()
def store():
    _register_key()
    st = PersistentInvestigationStore(tenant_id=TENANT, key_fingerprint=FINGERPRINT)
    _ctx(st)
    return st


def test_blocker4_async_start_returns_before_completion(store, monkeypatch):
    """POST /start?wait=false acknowledges immediately; work continues after."""
    import importlib
    # NB: `import safenestt.api.app as m` binds the FastAPI *instance* because
    # app.py rebinds the package attribute `app`. importlib gets the module.
    app_mod = importlib.import_module("safenestt.api.app")
    from fastapi.testclient import TestClient

    inv_id = f"inv-lr-{uuid.uuid4().hex[:10]}"
    rec = InvestigationRecord(investigation_id=inv_id, tenant_id=TENANT,
                              target="example.com", type="web",
                              case_id=f"case-lr-{uuid.uuid4().hex[:6]}")
    store.create_investigation(rec)

    gate = {"release": False}

    def slow_run(**kwargs):
        # Simulate a long pipeline; the HTTP response must not wait for this.
        while not gate["release"]:
            time.sleep(0.05)
        kwargs["store"].add_report(investigation_id=inv_id, draft={"done": True})
        return {"investigation_id": inv_id, "status": "COMPLETED"}

    monkeypatch.setattr(app_mod, "run_investigation", slow_run)
    # Override the auth dependency the route actually declares.
    from safenestt.api.app import get_api_context as real_get_api_context
    app_mod.app.dependency_overrides[real_get_api_context] = (
        lambda: (TENANT, FINGERPRINT))

    client = TestClient(app_mod.app)
    t0 = time.monotonic()
    r = client.post(f"/v1/investigations/{inv_id}/start?wait=false")
    elapsed = time.monotonic() - t0

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "RUNNING"
    assert body["accepted"] is True
    assert elapsed < 5, f"ack took {elapsed:.1f}s — still blocking"

    # The investigation is mid-flight after the request returned.
    assert store.get_investigation(inv_id).status == "RUNNING"

    # Release the simulated long pipeline; it must still complete afterwards.
    gate["release"] = True
    deadline = time.time() + 15
    persisted = None
    while time.time() < deadline:
        _ctx(store)
        eng = create_engine()
        with eng.connect() as c:
            c.execute(text("SELECT establish_tenant_context(:t,:f)"),
                      {"t": TENANT, "f": FINGERPRINT})
            persisted = c.execute(
                text("SELECT COUNT(*) FROM reports WHERE investigation_id=:i"),
                {"i": inv_id}).scalar()
        if persisted:
            break
        time.sleep(0.2)
    assert persisted == 1, "background work did not persist after the request returned"


def test_blocker4_start_is_idempotent_after_completion(store):
    """A second /start on a non-QUEUED investigation is rejected with 409."""
    from fastapi.testclient import TestClient
    import importlib
    app_mod = importlib.import_module("safenestt.api.app")

    inv_id = f"inv-idem-{uuid.uuid4().hex[:10]}"
    rec = InvestigationRecord(investigation_id=inv_id, tenant_id=TENANT,
                              target="example.com", type="web")
    store.create_investigation(rec)
    # move the record to RUNNING so a second /start is rejected
    rec.mark("RUNNING")
    store.update_investigation(rec)

    app_mod.app.dependency_overrides[app_mod.get_api_context] = (
        lambda: (TENANT, FINGERPRINT))
    client = TestClient(app_mod.app)
    r = client.post(f"/v1/investigations/{inv_id}/start")
    assert r.status_code == 409, r.text