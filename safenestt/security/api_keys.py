"""API key lifecycle management: hashing, expiry, revocation.

API keys are NEVER stored in plaintext — only SHA-256 hashes are kept.
Each key has an optional expiry and can be revoked at any time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, UTC
from typing import Any

logger = logging.getLogger(__name__)


def _hash_key(key: str) -> str:
    """Hash an API key using SHA-256 with a salt."""
    salt = os.getenv("API_KEY_SALT", "safenestt-default-salt-change-in-production")
    return hashlib.sha256(f"{salt}:{key}".encode()).hexdigest()


def generate_api_key(prefix: str = "sn_live_") -> tuple[str, str]:
    """Generate a new API key. Returns (raw_key, hashed_key).
    
    The raw_key is shown ONCE to the user. The hashed_key is stored.
    """
    random_part = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{random_part}"
    hashed_key = _hash_key(raw_key)
    return raw_key, hashed_key


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    """Verify a raw API key against a stored hash."""
    return secrets.compare_digest(_hash_key(raw_key), hashed_key)


class RevocationList:
    """Simple in-memory revocation list. In production, use Redis or DB."""
    
    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._load_from_env()
    
    def _load_from_env(self) -> None:
        """Load revoked keys from environment variable (JSON list)."""
        revoked_json = os.getenv("REVOKED_API_KEYS", "[]")
        try:
            revoked_list = json.loads(revoked_json)
            self._revoked = {_hash_key(k) for k in revoked_list}
        except (json.JSONDecodeError, TypeError):
            self._revoked = set()
    
    def revoke(self, raw_key: str) -> None:
        """Revoke an API key."""
        hashed = _hash_key(raw_key)
        self._revoked.add(hashed)
        logger.info("API key revoked (hash: %s...)", hashed[:12])
    
    def is_revoked(self, raw_key: str) -> bool:
        """Check if an API key is revoked."""
        return _hash_key(raw_key) in self._revoked
    
    def get_revoked_hashes(self) -> set[str]:
        """Get all revoked key hashes (for inspection)."""
        return self._revoked.copy()


class APIKeyRegistry:
    """Registry of active API keys with tenant mapping and expiry.
    
    In production, this would be backed by a database. For now, uses
    environment-based configuration with hashed storage.
    """
    
    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}  # hashed_key -> {tenant_id, expires_at, scopes}
        self._revocation_list = RevocationList()
        self._load_from_env()
    
    def _load_from_env(self) -> None:
        """Load API keys from environment variable (JSON dict).
        
        Format: {"<hashed_key>": {"tenant_id": "...", "expires_at": "...", "scopes": [...]}}
        """
        keys_json = os.getenv("API_KEYS", "{}")
        try:
            keys_data = json.loads(keys_json)
            for hashed_key, metadata in keys_data.items():
                self._keys[hashed_key] = {
                    "tenant_id": metadata.get("tenant_id", "unknown"),
                    "expires_at": metadata.get("expires_at"),  # ISO format or None
                    "scopes": metadata.get("scopes", ["read", "write"]),
                }
        except (json.JSONDecodeError, TypeError):
            self._keys = {}
    
    def register_key(self, tenant_id: str, raw_key: str, 
                     expires_at: str | None = None, 
                     scopes: list[str] | None = None) -> str:
        """Register a new API key for a tenant. Returns the hashed key."""
        hashed = _hash_key(raw_key)
        self._keys[hashed] = {
            "tenant_id": tenant_id,
            "expires_at": expires_at,
            "scopes": scopes or ["read", "write"],
        }
        return hashed
    
    def validate_key(self, raw_key: str) -> tuple[bool, str, dict[str, Any]]:
        """Validate an API key.
        
        Returns: (is_valid, tenant_id, metadata)
        is_revoked checks the revocation list.
        """
        hashed = _hash_key(raw_key)
        
        # Check revocation first
        if self._revocation_list.is_revoked(raw_key):
            return False, "", {"error": "key_revoked"}
        
        # Check if key exists
        if hashed not in self._keys:
            return False, "", {"error": "key_not_found"}
        
        metadata = self._keys[hashed]
        
        # Check expiry
        expires_at = metadata.get("expires_at")
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at)
                if datetime.now(UTC) > expiry:
                    return False, "", {"error": "key_expired"}
            except (ValueError, TypeError):
                pass  # Invalid expiry format, treat as no expiry
        
        return True, metadata["tenant_id"], metadata
    
    def revoke_key(self, raw_key: str) -> None:
        """Revoke an API key."""
        self._revocation_list.revoke(raw_key)


# Global singleton
_key_registry = APIKeyRegistry()


def get_key_registry() -> APIKeyRegistry:
    """Get the global API key registry."""
    return _key_registry
