"""PostgreSQL-backed API key storage with Argon2id hashing and audit logging.

KEY DESIGN:
- key_hash: Argon2id (memory-hard, constant-time verification)
- key_fingerprint: SHA-256 (deterministic, for fast server-side lookup)
- api_keys table: stores hashed keys, never plaintext
- api_key_audit table: tracks all key lifecycle events

PRODUCTION REQUIREMENTS:
- All keys must be registered in PostgreSQL
- No fallback to raw-key-as-tenant (rejected in all modes)
- Revocation is immediate and persistent across all workers
- Expiry is enforced at validation time (fail closed on parse errors)
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, UTC
from typing import Any, Generator

from safenestt.persistence.engine import create_engine, get_engine
from safenestt.persistence.models import APIKeyModel, APIKeyAuditModel

logger = logging.getLogger(__name__)

# Fixed pepper - read at module load
_API_KEY_PEPPER = os.getenv("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

# Import argon2 at module level
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
    """Verify an API key against a stored hash (constant-time)."""
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


def _record_audit(session: Any, api_key_id: int, action: str, actor: str | None = None, details: dict | None = None) -> None:
    """Record an audit event for an API key operation."""
    audit = APIKeyAuditModel(
        api_key_id=api_key_id,
        action=action,
        actor=actor or "system",
        details=details or {},
    )
    session.add(audit)


class APIKeyStore:
    """PostgreSQL-backed API key store with Argon2id hashing and audit logging."""
    
    def create_key(
        self,
        tenant_id: str,
        raw_key: str | None = None,
        name: str | None = None,
        expires_at: str | None = None,
        scopes: list[str] | None = None,
        actor: str | None = None,
    ) -> tuple[str, str, str]:
        """Create a new API key. Returns (raw_key, key_hash, key_fingerprint).
        
        Records an audit event for the creation.
        """
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
            
            # Record audit event
            _record_audit(session, model.id, "create", actor, {"tenant_id": tenant_id})
        
        return raw_key, key_hash, fingerprint
    
    def revoke_key(self, raw_key: str, actor: str | None = None) -> bool:
        """Revoke an API key by its raw value.
        
        Records an audit event for the revocation.
        Returns True if the key was found and revoked, False otherwise.
        """
        with _api_key_session() as session:
            candidates = session.query(APIKeyModel).filter(
                APIKeyModel.active == True,
            ).all()
            
            for key_record in candidates:
                if _verify_key(raw_key, key_record.key_hash):
                    key_record.revoked = True
                    key_record.revoked_at = datetime.now(UTC)
                    key_record.active = False
                    
                    # Record audit event
                    _record_audit(session, key_record.id, "revoke", actor)
                    session.flush()
                    return True
            
            return False
    
    def validate_key(self, raw_key: str, actor: str | None = None) -> tuple[bool, str, str, dict[str, Any]]:
        """Validate an API key. Returns (is_valid, tenant_id, key_fingerprint, metadata).
        
        Records audit events for both successful and failed validations.
        Checks ALL keys so revoked keys return key_revoked error.
        Uses constant-time Argon2id verification.
        """
        with _api_key_session() as session:
            now = datetime.now(UTC)
            all_keys = session.query(APIKeyModel).all()
            
            for key_record in all_keys:
                if _verify_key(raw_key, key_record.key_hash):
                    if key_record.revoked:
                        _record_audit(session, key_record.id, "validate_revoked", actor)
                        return False, "", "", {"error": "key_revoked"}
                    
                    if key_record.expires_at:
                        try:
                            expires_at = key_record.expires_at
                            if expires_at.tzinfo is None:
                                from datetime import timezone
                                expires_at = expires_at.replace(tzinfo=timezone.utc)
                            if datetime.now(UTC) > expires_at:
                                _record_audit(session, key_record.id, "validate_expired", actor)
                                return False, "", "", {"error": "key_expired"}
                        except (ValueError, TypeError):
                            _record_audit(session, key_record.id, "validate_invalid_expiry", actor)
                            return False, "", "", {"error": "key_expired"}
                    
                    if not key_record.active:
                        _record_audit(session, key_record.id, "validate_inactive", actor)
                        return False, "", "", {"error": "key_inactive"}
                    
                    fingerprint = _compute_key_fingerprint(raw_key)
                    
                    key_record.last_used_at = now
                    key_record.use_count = (key_record.use_count or 0) + 1
                    
                    _record_audit(session, key_record.id, "validate_success", actor)
                    session.flush()
                    
                    return True, key_record.tenant_id, fingerprint, {
                        "name": key_record.name,
                        "scopes": key_record.scopes or [],
                        "created_at": key_record.created_at,
                        "expires_at": key_record.expires_at,
                    }
            
            # Don't record audit for not_found (no valid key_id)
            return False, "", "", {"error": "key_not_found"}
    
    def rotate_key(self, old_raw_key: str, tenant_id: str, actor: str | None = None) -> tuple[str, str, str]:
        """Rotate an API key: create new key, revoke old one.
        
        Records audit events for both revocation and creation.
        """
        is_valid, _, _, _ = self.validate_key(old_raw_key, actor)
        if not is_valid:
            raise ValueError("Invalid or expired key")
        
        self.revoke_key(old_raw_key, actor)
        return self.create_key(tenant_id=tenant_id, actor=actor)
    
    def list_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        """List all API keys for a tenant (without hashes)."""
        with _api_key_session() as session:
            keys = session.query(APIKeyModel).filter(
                APIKeyModel.tenant_id == tenant_id,
            ).all()
            
            return [
                {
                    "id": k.id,
                    "name": k.name,
                    "active": k.active,
                    "revoked": k.revoked,
                    "expires_at": k.expires_at,
                    "scopes": k.scopes,
                    "created_at": k.created_at,
                    "last_used_at": k.last_used_at,
                    "use_count": k.use_count,
                }
                for k in keys
            ]
    
    def get_audit_history(self, api_key_id: int) -> list[dict[str, Any]]:
        """Get audit history for an API key."""
        with _api_key_session() as session:
            events = session.query(APIKeyAuditModel).filter(
                APIKeyAuditModel.api_key_id == api_key_id,
            ).order_by(APIKeyAuditModel.created_at.desc()).all()
            
            return [
                {
                    "id": e.id,
                    "action": e.action,
                    "actor": e.actor,
                    "details": e.details,
                    "created_at": e.created_at,
                }
                for e in events
            ]
    
    def cleanup_expired(self) -> int:
        """Deactivate expired keys. Returns count of deactivated keys."""
        with _api_key_session() as session:
            now = datetime.now(UTC)
            expired = session.query(APIKeyModel).filter(
                APIKeyModel.active == True,
            ).all()
            
            count = 0
            for key in expired:
                if key.expires_at:
                    try:
                        expires_at = key.expires_at
                        if expires_at.tzinfo is None:
                            from datetime import timezone
                            expires_at = expires_at.replace(tzinfo=timezone.utc)
                        if expires_at < now:
                            key.active = False
                            _record_audit(session, key.id, "cleanup_expired", "system")
                            count += 1
                    except (ValueError, TypeError):
                        pass
            
            session.flush()
            return count


_key_store = APIKeyStore()


def get_key_store() -> APIKeyStore:
    """Get the global API key store."""
    return _key_store
