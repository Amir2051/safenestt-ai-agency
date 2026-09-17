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

# Encryption key loaded from environment — never stored in DB
_ENCRYPTION_KEY = os.getenv("SAFENESTT_ENCRYPTION_KEY")


def _get_fernet():
    """Get Fernet instance from the configured key."""
    if not _ENCRYPTION_KEY:
        return None
    try:
        from cryptography.fernet import Fernet
        # Ensure key is valid Fernet key (32 bytes base64-encoded)
        key = _ENCRYPTION_KEY.strip()
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
        # Encryption not configured — store plaintext (dev mode)
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
