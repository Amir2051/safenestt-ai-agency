"""PostgreSQL-backed API key storage with Argon2id hashing."""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, UTC
from typing import Any, Generator

from safenestt.persistence.engine import create_engine, get_engine
from safenestt.persistence.models import APIKeyModel

logger = logging.getLogger(__name__)

# Fixed pepper - read at module load
_API_KEY_PEPPER = os.getenv("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

# Import argon2 at module level with proper error handling
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False
    _PH = None


def _compute_argon2_hash(key: str) -> str:
    """Compute Argon2id hash for secure storage."""
    if _ARGON2_AVAILABLE:
        return _PH.hash(f"{_API_KEY_PEPPER}:{key}")
    else:
        logger.warning("argon2-cffi not installed, using SHA-256 fallback (INSECURE)")
        salt = os.getenv("API_KEY_SALT", "safenestt-salt")
        return f"sha256:{hashlib.sha256(f'{salt}:{key}'.encode()).hexdigest()}"


def _compute_key_fingerprint(key: str) -> str:
    """Compute SHA-256 fingerprint for server-side lookup."""
    return hashlib.sha256(key.encode()).hexdigest()


def _verify_key(key: str, key_hash: str) -> bool:
    """Verify an API key against a stored hash (constant-time).
    
    Returns True if the key matches, False otherwise.
    """
    if _ARGON2_AVAILABLE:
        try:
            return _PH.verify(key_hash, f"{_API_KEY_PEPPER}:{key}")
        except VerifyMismatchError:
            return False
    else:
        salt = os.getenv("API_KEY_SALT", "safenestt-salt")
        expected = f"sha256:{hashlib.sha256(f'{salt}:{key}'.encode()).hexdigest()}"
        return secrets.compare_digest(expected, key_hash)


def generate_api_key(prefix: str = "sn_live_") -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, key_hash, key_fingerprint)."""
    random_part = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{random_part}"
    argon2_hash = _compute_argon2_hash(raw_key)
    fingerprint = _compute_key_fingerprint(raw_key)
    return raw_key, argon2_hash, fingerprint


def verify_api_key(raw_key: str, key_hash: str) -> bool:
    """Verify a raw API key against a stored Argon2id hash."""
    return _verify_key(raw_key, key_hash)


@contextmanager
def _api_key_session() -> Generator:
    """Session scope for API key operations."""
    from sqlalchemy.orm import sessionmaker
    engine = get_engine()
    if engine is None:
        engine = create_engine()
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class APIKeyStore:
    """PostgreSQL-backed API key store with Argon2id hashing."""
    
    def create_key(
        self,
        tenant_id: str,
        raw_key: str | None = None,
        name: str | None = None,
        expires_at: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[str, str, str]:
        """Create a new API key. Returns (raw_key, key_hash, key_fingerprint)."""
        if raw_key is None:
            raw_key, key_hash, fingerprint = generate_api_key()
        else:
            key_hash = _compute_argon2_hash(raw_key)
            fingerprint = _compute_key_fingerprint(raw_key)
        
        with _api_key_session() as session:
            parsed_expires = None
            if expires_at:
                try:
                    parsed_expires = datetime.fromisoformat(expires_at)
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid expiry format: {expires_at}")
            
            model = APIKeyModel(
                key_hash=key_hash,
                key_fingerprint=fingerprint,
                tenant_id=tenant_id,
                name=name,
                active=True,
                revoked=False,
                expires_at=parsed_expires,
                scopes=scopes or ["read", "write"],
            )
            session.add(model)
            session.flush()
        
        return raw_key, key_hash, fingerprint
    
    def revoke_key(self, raw_key: str) -> bool:
        """Revoke an API key by its raw value."""
        with _api_key_session() as session:
            candidates = session.query(APIKeyModel).filter(
                APIKeyModel.active == True,
            ).all()
            
            for key_record in candidates:
                if _verify_key(raw_key, key_record.key_hash):
                    key_record.revoked = True
                    key_record.revoked_at = datetime.now(UTC)
                    key_record.active = False
                    session.flush()
                    return True
            
            return False
    
    def validate_key(self, raw_key: str) -> tuple[bool, str, str, dict[str, Any]]:
        """Validate an API key. Returns (is_valid, tenant_id, key_fingerprint, metadata)."""
        with _api_key_session() as session:
            now = datetime.now(UTC)
            all_keys = session.query(APIKeyModel).all()
            
            for key_record in all_keys:
                if _verify_key(raw_key, key_record.key_hash):
                    if key_record.revoked:
                        return False, "", "", {"error": "key_revoked"}
                    
                    # Check expiry - handle both aware and naive datetimes
                    if key_record.expires_at:
                        try:
                            expires_at = key_record.expires_at
                            # If offset-naive, assume UTC
                            if expires_at.tzinfo is None:
                                from datetime import timezone
                                expires_at = expires_at.replace(tzinfo=timezone.utc)
                            if datetime.now(UTC) > expires_at:
                                return False, "", "", {"error": "key_expired"}
                        except (ValueError, TypeError):
                            # Invalid expiry format — fail closed
                            return False, "", "", {"error": "key_expired"}
                    
                    if not key_record.active:
                        return False, "", "", {"error": "key_inactive"}
                    
                    fingerprint = _compute_key_fingerprint(raw_key)
                    
                    key_record.last_used_at = now
                    key_record.use_count = (key_record.use_count or 0) + 1
                    session.flush()
                    
                    return True, key_record.tenant_id, fingerprint, {
                        "name": key_record.name,
                        "scopes": key_record.scopes or [],
                        "created_at": key_record.created_at,
                        "expires_at": key_record.expires_at,
                    }
            
            return False, "", "", {"error": "key_not_found"}
    
    def rotate_key(self, old_raw_key: str, tenant_id: str) -> tuple[str, str, str]:
        """Rotate an API key: create new, revoke old."""
        is_valid, _, _, _ = self.validate_key(old_raw_key)
        if not is_valid:
            raise ValueError("Invalid or expired key")
        
        self.revoke_key(old_raw_key)
        return self.create_key(tenant_id=tenant_id)


_key_store = APIKeyStore()


def get_key_store() -> APIKeyStore:
    """Get the global API key store."""
    return _key_store
