"""Tests for security fixes — updated for new API key lifecycle."""
from __future__ import annotations

import os
import pytest


def test_production_rejects_default_encryption_key():
    """Production mode MUST reject keys that match known default patterns."""
    from cryptography.fernet import Fernet
    from safenestt.security import encryption
    
    original_mode = os.environ.get("MODE")
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    
    try:
        os.environ["MODE"] = "production"
        
        default_keys = [
            "test-key",
            "dev-key",
            "default-key",
            "changeme",
            "secret",
            "placeholder",
            "demo",
            "sample",
            "00000000000000000000000000000000",
            "password",
        ]
        
        for key in default_keys:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = key
            import importlib
            importlib.reload(encryption)
            
            with pytest.raises(RuntimeError, match="does not meet production security"):
                encryption._get_fernet()
    
    finally:
        if original_mode is None:
            os.environ.pop("MODE", None)
        else:
            os.environ["MODE"] = original_mode
        
        if original_key is None:
            os.environ.pop("SAFENESTT_ENCRYPTION_KEY", None)
        else:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = original_key
        
        import importlib
        importlib.reload(encryption)


def test_production_accepts_strong_encryption_key():
    """Production mode MUST accept a valid Fernet key."""
    from safenestt.security import encryption
    from cryptography.fernet import Fernet
    
    original_mode = os.environ.get("MODE")
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    
    try:
        os.environ["MODE"] = "production"
        strong_key = Fernet.generate_key().decode()
        os.environ["SAFENESTT_ENCRYPTION_KEY"] = strong_key
        
        import importlib
        importlib.reload(encryption)
        
        assert encryption.is_encryption_enabled()
    
    finally:
        if original_mode is None:
            os.environ.pop("MODE", None)
        else:
            os.environ["MODE"] = original_mode
        
        if original_key is None:
            os.environ.pop("SAFENESTT_ENCRYPTION_KEY", None)
        else:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = original_key
        
        import importlib
        importlib.reload(encryption)


def test_api_key_hashing():
    """API keys should be hashed, never stored in plaintext."""
    from safenestt.security.api_keys import _compute_argon2_hash, generate_api_key, verify_api_key
    
    raw_key, key_hash, fingerprint = generate_api_key()
    
    # Hashed key should not contain the raw key
    assert raw_key != key_hash
    assert raw_key not in key_hash
    
    # Verification should work
    assert verify_api_key(raw_key, key_hash)
    assert not verify_api_key("wrong-key", key_hash)


def test_api_key_revocation():
    """Revoked keys should be rejected."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    raw_key = "test-revoke-me-12345"
    
    store.create_key(tenant_id="test-tenant", raw_key=raw_key)
    
    is_valid, _, _, _ = store.validate_key(raw_key)
    assert is_valid
    
    store.revoke_key(raw_key)
    
    is_valid, _, _, metadata = store.validate_key(raw_key)
    assert not is_valid
    assert metadata.get("error") == "key_revoked"


def test_api_key_registry():
    """API key registry should validate keys and return tenant_id."""
    from safenestt.security.api_keys import get_key_store
    
    store = get_key_store()
    raw_key = "test-registry-key-12345"
    
    store.create_key(
        tenant_id="test-tenant",
        raw_key=raw_key,
        expires_at=None,
        scopes=["read", "write"]
    )
    
    is_valid, tenant_id, fingerprint, metadata = store.validate_key(raw_key)
    assert is_valid
    assert tenant_id == "test-tenant"
    assert "read" in metadata["scopes"]


def test_api_key_expiry():
    """Expired keys should be rejected."""
    from safenestt.security.api_keys import get_key_store
    from datetime import datetime, timedelta, UTC
    
    store = get_key_store()
    
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    raw_key, _, _ = store.create_key(
        tenant_id="tenant-expired",
        raw_key="expired-key-12345",
        expires_at=past
    )
    
    is_valid, _, _, metadata = store.validate_key(raw_key)
    assert not is_valid
    assert metadata.get("error") == "key_expired"


def test_per_key_rate_limiting():
    """Rate limiting should be per-API-key, not per-tenant."""
    from safenestt.security.rate_limit import RateLimitService, RateLimitScope
    
    service = RateLimitService()
    
    key1 = "key-1"
    key2 = "key-2"
    
    # Exhaust key1
    for _ in range(10):
        service.enforce(
            scope=RateLimitScope.API_KEY,
            key=key1,
            limit=10,
            window_seconds=60
        )
    
    # key1 should be blocked
    result = service.enforce(
        scope=RateLimitScope.API_KEY,
        key=key1,
        limit=10,
        window_seconds=60
    )
    assert not result.allowed
    
    # key2 should still be allowed
    result = service.enforce(
        scope=RateLimitScope.API_KEY,
        key=key2,
        limit=10,
        window_seconds=60
    )
    assert result.allowed
