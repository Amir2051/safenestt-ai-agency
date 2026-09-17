"""Encryption utilities for sensitive data at rest.

Uses Fernet symmetric encryption (from cryptography library) with keys
loaded from environment variables. Keys are NEVER stored in the database.

Sensitive fields that should be encrypted:
- EvidenceModel.data (evidence content)
- FindingModel.claim (finding descriptions)
- InvestigationModel.target (investigation targets)
- AgentRunModel.inputs/outputs (agent I/O)
- ReportModel.draft (report content)
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Default/public key patterns that MUST NEVER be used in production
# These are well-known test keys that should be rejected
_DEFAULT_KEYS = {
    "test", "testing", "test-key", "test_key", "testkey",
    "dev", "development", "dev-key", "dev_key", "devkey",
    "default", "default-key", "default_key", "defaultkey",
    "placeholder", "sample", "demo",
    "00000000000000000000000000000000",
    "changeme", "change-me", "change_me",
    "secret", "my-secret", "my_secret",
    "12345", "12345678", "password",
}

# Minimum key length (Fernet keys are 44 chars base64-encoded = 32 bytes)
_MIN_KEY_LENGTH = 32


def _has_sufficient_entropy(key: str) -> bool:
    """Check if a key has sufficient entropy (not just repeated characters).
    
    Returns False if the key is mostly the same character repeated.
    """
    if len(key) < 8:
        return False
    
    # Count unique characters
    unique_chars = len(set(key))
    
    # A key with fewer than 5 unique characters out of 32+ is suspicious
    if unique_chars < 5:
        return False
    
    # Check for highly repetitive patterns (e.g., "AAAAAAAAAAAAAAAA")
    from collections import Counter
    char_counts = Counter(key)
    most_common_count = char_counts.most_common(1)[0][1]
    
    # If the most common character makes up more than 50% of the key, it's weak
    if most_common_count / len(key) > 0.5:
        return False
    
    return True


def _is_valid_key(key: str) -> bool:
    """Validate that an encryption key meets production security standards.
    
    Returns False if the key:
    - Is empty or None
    - Matches a known default/test pattern
    - Is too short
    - Contains common placeholder patterns
    - Has insufficient entropy (repeated characters)
    """
    if not key or not isinstance(key, str):
        return False
    
    key = key.strip()
    
    if len(key) < _MIN_KEY_LENGTH:
        return False
    
    # Check against known default patterns
    key_lower = key.lower()
    if key_lower in _DEFAULT_KEYS:
        return False
    
    # Check for common placeholder patterns (regardless of length)
    for pattern in ["test", "dev", "default", "changeme", "secret", "placeholder", "demo", "sample"]:
        if pattern in key_lower:
            return False
    
    # Check entropy
    if not _has_sufficient_entropy(key):
        return False
    
    return True


def _get_fernet():
    """Get Fernet instance from the configured key."""
    raw_key = os.getenv("SAFENESTT_ENCRYPTION_KEY")
    if not raw_key:
        return None
    
    # In production, reject default/weak keys
    if os.getenv("MODE") == "production" and not _is_valid_key(raw_key):
        raise RuntimeError(
            f"FATAL: SAFENESTT_ENCRYPTION_KEY is set but does not meet production security requirements. "
            f"Key must be at least {_MIN_KEY_LENGTH} characters, have sufficient entropy, "
            f"and not match a known default pattern. "
            f"Generate a strong key with: python -c \"from safenestt.security.encryption import generate_key; print(generate_key())\""
        )
    
    try:
        from cryptography.fernet import Fernet
        # Ensure key is valid Fernet key (32 bytes base64-encoded)
        key = raw_key.strip()
        # If key is raw bytes, base64 encode it
        if len(key) == 32:
            key = base64.urlsafe_b64encode(key.encode()).decode()
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        logger.error("Failed to initialize encryption: %s", exc)
        return None


def encrypt_value(value: Any) -> str | None:
    """Encrypt a value for storage. Returns base64-encoded ciphertext."""
    if value is None:
        return None
    fernet = _get_fernet()
    if fernet is None:
        # Encryption not configured — store plaintext (dev mode only)
        if os.getenv("MODE") == "production":
            raise RuntimeError("Cannot store unencrypted data in production")
        logger.warning("Encryption key not configured, storing plaintext")
        return value if isinstance(value, str) else json.dumps(value)
    try:
        if isinstance(value, str):
            data = value.encode("utf-8")
        else:
            data = json.dumps(value).encode("utf-8")
        encrypted = fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")
    except Exception as exc:
        logger.error("Encryption failed: %s", exc)
        raise


def decrypt_value(encrypted: str | None) -> Any:
    """Decrypt a value from storage."""
    if encrypted is None:
        return None
    fernet = _get_fernet()
    if fernet is None:
        # Try to parse as JSON, otherwise return as-is
        try:
            return json.loads(encrypted)
        except (json.JSONDecodeError, TypeError):
            return encrypted
    try:
        data = base64.urlsafe_b64decode(encrypted.encode("ascii"))
        decrypted = fernet.decrypt(data)
        text = decrypted.decode("utf-8")
        # Try JSON parse, fall back to string
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    except Exception as exc:
        logger.error("Decryption failed: %s", exc)
        raise


def is_encryption_enabled() -> bool:
    """Check if encryption is properly configured."""
    return _get_fernet() is not None


def generate_key() -> str:
    """Generate a new encryption key. Use this to create a key for env."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("ascii")
