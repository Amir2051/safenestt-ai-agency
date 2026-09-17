"""Tests for durable API-key lifecycle — ISSUE 2."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, UTC

from safenestt.persistence.models import APIKeyModel, APIKeyAuditModel


def test_key_creation_returns_argon2_hash():
    """Keys are stored as Argon2id hashes, never plaintext."""
    from safenestt.security.api_keys import get_key_store, _compute_argon2_hash, _compute_key_fingerprint
    
    store = get_key_store()
    raw_key = 'test-key-lifecycle-12345'
    
    raw, argon2_hash, fingerprint = store.create_key(
        tenant_id='tenant-lifecycle',
        raw_key=raw_key,
        name='Test Key'
    )
    
    # Verify format
    assert argon2_hash.startswith('$argon2id$')
    assert fingerprint == _compute_key_fingerprint(raw_key)
    
    # Verify we can validate the key
    is_valid, tenant_id, fp2, meta = store.validate_key(raw_key)
    assert is_valid
    assert tenant_id == 'tenant-lifecycle'
    assert fp2 == fingerprint


def test_key_revocation_blocks_validation():
    """Revoked keys are immediately rejected."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    raw_key = 'test-revoke-lifecycle-12345'
    
    store.create_key(tenant_id='tenant-revoke', raw_key=raw_key)
    
    is_valid, _, _, _ = store.validate_key(raw_key)
    assert is_valid
    
    result = store.revoke_key(raw_key)
    assert result is True
    
    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get('error') == 'key_revoked'


def test_key_expiry_blocks_validation():
    """Expired keys are rejected at validation time."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    raw_key = 'test-expiry-lifecycle-12345'
    
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    store.create_key(tenant_id='tenant-expiry', raw_key=raw_key, expires_at=past)
    
    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get('error') == 'key_expired'


def test_key_rotation():
    """Key rotation creates new key and revokes old."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    raw_key = 'test-rotate-lifecycle-12345'
    
    store.create_key(tenant_id='tenant-rotate', raw_key=raw_key)
    
    new_raw, new_hash, new_fp = store.rotate_key(raw_key, 'tenant-rotate')
    
    # Old key should be revoked
    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get('error') == 'key_revoked'
    
    # New key should work
    is_valid, tenant_id, fp2, _ = store.validate_key(new_raw)
    assert is_valid
    assert tenant_id == 'tenant-rotate'


def test_audit_history_tracked():
    """Key operations are recorded in audit log."""
    from safenestt.security.api_keys import get_key_store, _api_key_session
    
    store = get_key_store()
    raw_key = 'test-audit-lifecycle-12345'
    
    raw, key_hash, fp = store.create_key(tenant_id='tenant-audit', raw_key=raw_key, actor='test-suite')
    
    # Get the key ID
    with _api_key_session() as session:
        key_record = session.query(APIKeyModel).filter(
            APIKeyModel.key_fingerprint == fp
        ).first()
        assert key_record is not None
        key_id = key_record.id
    
    # Revoke
    store.revoke_key(raw_key, actor='test-suite')
    
    # Check audit history
    history = store.get_audit_history(key_id)
    assert len(history) >= 2  # create + revoke
    actions = [h['action'] for h in history]
    assert 'create' in actions
    assert 'revoke' in actions


def test_cleanup_expired_keys():
    """Expired keys can be cleaned up."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    
    # Create an already-expired key
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    raw_key = 'test-cleanup-12345'
    store.create_key(tenant_id='tenant-cleanup', raw_key=raw_key, expires_at=past)
    
    count = store.cleanup_expired()
    assert count >= 1
    
    # Key should now be inactive
    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid


def test_invalid_key_not_found():
    """Non-existent keys return key_not_found error."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    is_valid, _, _, meta = store.validate_key('this-key-does-not-exist-xyz')
    assert not is_valid
    assert meta.get('error') == 'key_not_found'


def test_cross_tenant_key_isolation():
    """Keys from different tenants cannot access each other's data."""
    from safenestt.security.api_keys import get_key_store
    from safenestt.persistence.engine import session_scope
    
    store = get_key_store()
    
    # Create two keys for different tenants
    raw_tenant_a = 'test-key-tenant-a-12345'
    raw_tenant_b = 'test-key-tenant-b-67890'
    
    store.create_key(tenant_id='tenant-a-cross', raw_key=raw_tenant_a)
    store.create_key(tenant_id='tenant-b-cross', raw_key=raw_tenant_b)
    
    # Get fingerprints
    _, _, fp_a, _ = store.validate_key(raw_tenant_a)
    _, _, fp_b, _ = store.validate_key(raw_tenant_b)
    
    # Create data for tenant-a
    with session_scope(tenant_id='tenant-a-cross', key_fingerprint=fp_a) as session:
        from sqlalchemy import text
        session.execute(text("""
            INSERT INTO investigations (investigation_id, tenant_id, target, type, status, created_by, created_at, updated_at)
            VALUES ('inv-a-1', 'tenant-a-cross', 'secret-a', 'cybersecurity', 'QUEUED', 'user-a', NOW(), NOW())
            ON CONFLICT DO NOTHING
        """))
    
    # Tenant-b key should NOT see tenant-a's data
    with session_scope(tenant_id='tenant-b-cross', key_fingerprint=fp_b) as session:
        from sqlalchemy import text
        result = session.execute(text("""
            SELECT investigation_id FROM investigations 
            WHERE investigation_id = 'inv-a-1'
        """)).fetchone()
        assert result is None
