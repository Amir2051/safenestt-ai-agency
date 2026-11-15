"""Regression: tenant identity cannot be spoofed via the app.current_tenant GUC.

CodeRabbit PR#3 (CWE-639 / IDOR): get_current_tenant() must read ONLY the
PID-bound, fingerprint-verified public._tenant_context table -- never a
caller-settable GUC. These tests fail on the vulnerable revision that returned
current_setting('app.current_tenant', true), which let any app-role session
impersonate any tenant with a plain SET / set_config and bypass every RLS policy.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from safenestt.persistence.engine import create_engine, session_scope
from safenestt.security.api_keys import get_key_store, _compute_key_fingerprint


@pytest.fixture
def victim_data():
    test_id = uuid.uuid4().hex[:8]
    store = get_key_store()
    raw = f"spoof-victim-{test_id}"
    store.create_key(tenant_id="tenant-victim", raw_key=raw, name="Victim Key")
    fp = _compute_key_fingerprint(raw)
    inv = f"inv-victim-{test_id}"
    with session_scope(tenant_id="tenant-victim", key_fingerprint=fp) as session:
        session.execute(
            text(
                """
                INSERT INTO investigations
                    (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
                VALUES
                    (:inv, 'tenant-victim', 'secret-victim', 'cybersecurity', 'QUEUED', 'user-victim', NOW(), NOW())
                ON CONFLICT DO NOTHING
                """
            ),
            {"inv": inv},
        )
    return {"tenant": "tenant-victim", "inv": inv, "fp": fp}


def test_guc_set_does_not_grant_tenant(victim_data):
    """A forged `SET app.current_tenant` must NOT change get_current_tenant()."""
    eng = create_engine()
    with eng.connect() as conn:
        conn.execute(text("SELECT clear_tenant_context()"))
        conn.execute(
            text("SELECT set_config('app.current_tenant', :t, false)"),
            {"t": victim_data["tenant"]},
        )
        who = conn.execute(text("SELECT get_current_tenant()")).scalar()
        assert who == "", f"GUC spoof leaked tenant identity: {who!r}"


def test_guc_spoof_cannot_read_victim_rows(victim_data):
    """With only a forged GUC (no established context), RLS returns no rows."""
    eng = create_engine()
    with eng.connect() as conn:
        conn.execute(text("SELECT clear_tenant_context()"))
        conn.execute(
            text("SELECT set_config('app.current_tenant', :t, false)"),
            {"t": victim_data["tenant"]},
        )
        rows = conn.execute(
            text("SELECT investigation_id FROM investigations WHERE investigation_id = :inv"),
            {"inv": victim_data["inv"]},
        ).fetchall()
        assert rows == [], f"GUC spoof read victim rows: {rows}"


def test_established_context_still_resolves(victim_data):
    """Sanity: the legitimate PID-bound path still resolves the tenant and its rows."""
    with session_scope(tenant_id="tenant-victim", key_fingerprint=victim_data["fp"]) as session:
        who = session.execute(text("SELECT get_current_tenant()")).scalar()
        assert who == "tenant-victim"
        row = session.execute(
            text("SELECT tenant_id FROM investigations WHERE investigation_id = :inv"),
            {"inv": victim_data["inv"]},
        ).fetchone()
        assert row is not None and row[0] == "tenant-victim"
