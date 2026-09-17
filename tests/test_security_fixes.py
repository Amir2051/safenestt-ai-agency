"""Tests for encryption key validation in production mode."""
from __future__ import annotations

import os
import pytest


def test_production_rejects_default_encryption_key():
    """Production mode MUST reject keys that match known default patterns."""
    from safenestt.security import encryption
    
    # Save original values
    original_mode = os.environ.get("MODE")
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    
    try:
        os.environ["MODE"] = "production"
        
        # Test with known default keys
        default_keys = [
            "test",
            "test-key",
            "dev",
            "development",
            "default",
            "default-key",
            "changeme",
            "secret",
            "00000000000000000000000000000000",
            "password",
            "demo",
            "sample",
            "placeholder",
        ]
        
        for key in default_keys:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = key
            # Reload module to pick up new env var
            import importlib
            importlib.reload(encryption)
            
            with pytest.raises(RuntimeError, match="does not meet production security"):
                encryption.is_encryption_enabled()
    
    finally:
        # Restore original values
        if original_mode is None:
            os.environ.pop("MODE", None)
        else:
            os.environ["MODE"] = original_mode
        
        if original_key is None:
            os.environ.pop("SAFENESTT_ENCRYPTION_KEY", None)
        else:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = original_key
        
        # Reload module to restore state
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


def test_development_accepts_any_key():
    """Development mode is permissive (no default key rejection)."""
    from safenestt.security import encryption
    
    original_mode = os.environ.get("MODE")
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    
    try:
        os.environ["MODE"] = "development"
        os.environ["SAFENESTT_ENCRYPTION_KEY"] = "test-key"
        
        import importlib
        importlib.reload(encryption)
        
        # Should NOT raise, even with a weak key
        # is_encryption_enabled() will try to create Fernet and may fail silently
        # but it won't raise RuntimeError
        result = encryption.is_encryption_enabled()
        # Result depends on whether the key is valid Fernet format
    
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
    from safenestt.security.api_keys import _hash_key, generate_api_key, verify_api_key
    
    raw_key, hashed_key = generate_api_key()
    
    # Hashed key should not contain the raw key
    assert raw_key != hashed_key
    assert raw_key not in hashed_key
    
    # Verification should work
    assert verify_api_key(raw_key, hashed_key)
    assert not verify_api_key("wrong-key", hashed_key)


def test_api_key_revocation():
    """Revoked keys should be rejected."""
    from safenestt.security.api_keys import RevocationList
    
    rl = RevocationList()
    raw_key = "test-key-123"
    
    assert not rl.is_revoked(raw_key)
    
    rl.revoke(raw_key)
    assert rl.is_revoked(raw_key)


def test_api_key_registry():
    """API key registry should validate keys and return tenant_id."""
    from safenestt.security.api_keys import APIKeyRegistry
    
    registry = APIKeyRegistry()
    raw_key = "test-key-456"
    
    # Register a key
    hashed = registry.register_key(
        tenant_id="test-tenant",
        raw_key=raw_key,
        expires_at=None,
        scopes=["read", "write"]
    )
    
    # Validate
    is_valid, tenant_id, metadata = registry.validate_key(raw_key)
    assert is_valid
    assert tenant_id == "test-tenant"
    assert "read" in metadata["scopes"]
    
    # Revoke and verify rejection
    registry.revoke_key(raw_key)
    is_valid, _, metadata = registry.validate_key(raw_key)
    assert not is_valid
    assert metadata["error"] == "key_revoked"


def test_api_key_expiry():
    """Expired keys should be rejected."""
    from safenestt.security.api_keys import APIKeyRegistry
    from datetime import datetime, timedelta, UTC
    
    registry = APIKeyRegistry()
    raw_key = "test-key-expired"
    
    # Register with past expiry
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    registry.register_key(
        tenant_id="test-tenant",
        raw_key=raw_key,
        expires_at=past
    )
    
    is_valid, _, metadata = registry.validate_key(raw_key)
    assert not is_valid
    assert metadata["error"] == "key_expired"


def test_per_key_rate_limiting():
    """Rate limiting should be per-API-key, not per-tenant."""
    from safenestt.security.rate_limit import RateLimitService, RateLimitScope
    
    service = RateLimitService()
    
    # Different API keys should have separate rate limits
    key1 = "key-1"
    key2 = "key-2"
    
    # Exhaust key1
    for _ in range(10):
        result = service.enforce(
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
