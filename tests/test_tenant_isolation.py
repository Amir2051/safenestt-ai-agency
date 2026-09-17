"""Tenant isolation tests — ISSUE 1.

Tests verify that session-bound tenant context prevents tenant impersonation.
"""
from __future__ import annotations

import os
import pytest
from sqlalchemy import text

from safenestt.persistence.engine import create_engine, session_scope, get_owner_engine
from safenestt.security.api_keys import get_key_store, _compute_key_fingerprint


@pytest.fixture(scope="module")
def engine():
    eng = create_engine()
    yield eng


@pytest.fixture(autouse=True)
def _test_tenant_data():
    """Create fresh test data for each test."""
    import uuid
    test_id = uuid.uuid4().hex[:8]
    
    store = get_key_store()
    
    raw_alpha = f"test-key-alpha-{test_id}"
    raw_beta = f"test-key-beta-{test_id}"
    
    store.create_key(tenant_id="tenant-alpha", raw_key=raw_alpha, name="Alpha Key")
    store.create_key(tenant_id="tenant-beta", raw_key=raw_beta, name="Beta Key")
    
    fp_alpha = _compute_key_fingerprint(raw_alpha)
    fp_beta = _compute_key_fingerprint(raw_beta)
    
    inv_alpha = f"inv-alpha-{test_id}"
    inv_beta = f"inv-beta-{test_id}"
    
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=fp_alpha) as session:
        session.execute(text("""
            INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
            VALUES (:inv_id, 'tenant-alpha', 'secret-alpha', 'cybersecurity', 'QUEUED', 'user-alpha', NOW(), NOW())
            ON CONFLICT DO NOTHING
        """), {"inv_id": inv_alpha})
    
    with session_scope(tenant_id="tenant-beta", key_fingerprint=fp_beta) as session:
        session.execute(text("""
            INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
            VALUES (:inv_id, 'tenant-beta', 'secret-beta', 'cybersecurity', 'QUEUED', 'user-beta', NOW(), NOW())
            ON CONFLICT DO NOTHING
        """), {"inv_id": inv_beta})
    
    yield {
        "alpha": {"raw": raw_alpha, "fp": fp_alpha, "tenant": "tenant-alpha", "inv_id": inv_alpha},
        "beta": {"raw": raw_beta, "fp": fp_beta, "tenant": "tenant-beta", "inv_id": inv_beta},
    }


def test_same_tenant_access(_test_tenant_data):
    """A valid key can access its own tenant's data."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        result = session.execute(text("""
            SELECT investigation_id, tenant_id FROM investigations 
            WHERE investigation_id = :inv_id
        """), {"inv_id": _test_tenant_data["alpha"]["inv_id"]}).fetchone()
        
        assert result is not None
        assert result[1] == 'tenant-alpha'


def test_cross_tenant_read_blocked(_test_tenant_data):
    """A key CANNOT read another tenant's data via RLS."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        result = session.execute(text("""
            SELECT investigation_id FROM investigations 
            WHERE investigation_id = :inv_id
        """), {"inv_id": _test_tenant_data["beta"]["inv_id"]}).fetchone()
        
        assert result is None


def test_cross_tenant_write_blocked(_test_tenant_data):
    """A key CANNOT insert data for another tenant."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        with pytest.raises(Exception) as exc_info:
            session.execute(text("""
                INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
                VALUES ('inv-fake', 'tenant-beta', 'fake-data', 'cybersecurity', 'QUEUED', 'attacker', NOW(), NOW())
            """))
            session.commit()
        
        assert "row-level security" in str(exc_info.value).lower()


def test_direct_set_guc_bypassed(_test_tenant_data):
    """Direct SET app.current_tenant_id does NOT bypass RLS."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        session.execute(text("SET app.current_tenant_id = 'tenant-beta'"))
        session.execute(text("SELECT set_config('app.current_tenant_id', 'tenant-beta', FALSE)"))
        
        result = session.execute(text("""
            SELECT investigation_id FROM investigations 
            WHERE investigation_id = :inv_id
        """), {"inv_id": _test_tenant_data["beta"]["inv_id"]}).fetchone()
        
        assert result is None


def test_disable_rls_blocked(_test_tenant_data):
    """App role CANNOT disable RLS."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        with pytest.raises(Exception) as exc_info:
            session.execute(text("ALTER TABLE investigations DISABLE ROW LEVEL SECURITY"))
            session.commit()
        
        assert "must be owner" in str(exc_info.value)


def test_set_role_blocked(_test_tenant_data):
    """App role CANNOT do SET ROLE to postgres."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        with pytest.raises(Exception) as exc_info:
            session.execute(text("SET ROLE postgres"))
            session.commit()
        
        assert "permission denied" in str(exc_info.value).lower()


def test_wrong_fingerprint_blocked(_test_tenant_data):
    """establish_tenant_context with wrong fingerprint is rejected."""
    with pytest.raises(Exception) as exc_info:
        with session_scope(tenant_id="tenant-beta", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
            pass  # Should fail on context establishment
        
        assert "Invalid API key" in str(exc_info.value) or "tenant mismatch" in str(exc_info.value)


def test_api_key_revocation_blocks_access(_test_tenant_data):
    """Revoking a key immediately blocks access."""
    store = get_key_store()
    
    is_valid, _, _, _ = store.validate_key(_test_tenant_data["alpha"]["raw"])
    assert is_valid
    
    store.revoke_key(_test_tenant_data["alpha"]["raw"])
    
    is_valid, _, _, metadata = store.validate_key(_test_tenant_data["alpha"]["raw"])
    assert not is_valid
    assert metadata.get("error") == "key_revoked"


def test_api_key_expiry_blocks_access():
    """Expired keys are immediately rejected."""
    store = get_key_store()
    
    from datetime import datetime, timedelta, UTC
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    
    raw_key, _, _ = store.create_key(
        tenant_id="tenant-expired",
        raw_key="expired-key-12345",
        expires_at=past
    )
    
    is_valid, _, _, metadata = store.validate_key(raw_key)
    assert not is_valid
    assert metadata.get("error") == "key_expired"


def test_cross_tenant_insert_does_not_leak(_test_tenant_data):
    """An insert with wrong tenant_id is still filtered by RLS."""
    with get_owner_engine().connect() as conn:
        conn.execute(text("""
            INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
            VALUES ('inv-wrong-tenant', 'tenant-beta', 'wrong-data', 'cybersecurity', 'QUEUED', 'attacker', NOW(), NOW())
            ON CONFLICT DO NOTHING
        """))
        conn.commit()
    
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        result = session.execute(text("""
            SELECT investigation_id FROM investigations 
            WHERE investigation_id = 'inv-wrong-tenant'
        """)).fetchone()
        
        assert result is None


def test_get_current_tenant_returns_correct_tenant(_test_tenant_data):
    """get_current_tenant() returns the tenant for the current session."""
    with session_scope(tenant_id="tenant-alpha", key_fingerprint=_test_tenant_data["alpha"]["fp"]) as session:
        result = session.execute(text("SELECT get_current_tenant()")).scalar()
        assert result == 'tenant-alpha'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
