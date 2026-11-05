"""Tests for durable API-key lifecycle — ISSUE 2."""
from __future__ import annotations

import os
import uuid
import pytest
from datetime import datetime, timedelta, UTC

# Ensure DB connection uses local test DB before any imports that call get_secret().
os.environ["DB_HOST"] = "127.0.0.1"
# PORT ISOLATION (2026-10-04): was 54322, the PRODUCTION Postgres port. Use the
# dedicated test instance on 55432 so this module cannot accidentally hit
# production (which previously broke the full-suite unique constraint because
# test_api_key_lifecycle seeds api_keys with deterministic key_fingerprints
# into the production database).
os.environ["DB_PORT"] = os.environ.get("DB_PORT") or "55432"
os.environ["DB_NAME"] = "safenestt_ai_test"
os.environ["DB_SSL_MODE"] = "disable"
# Match the test-role password that conftest.py and the test container use,
# NOT postgres (production default).
os.environ["SAFENESTT_OWNER_PASSWORD"] = os.getenv("SAFENESTT_TEST_PASSWORD", "safenestt_test_local_only")
os.environ["SAFENESTT_DB_PASSWORD"] = os.getenv("SAFENESTT_TEST_PASSWORD", "safenestt_test_local_only")
os.environ["SAFENESTT_OWNER_DATABASE_URL"] = (
    f"postgresql://safenestt_owner_test:{os.getenv('SAFENESTT_TEST_PASSWORD', 'safenestt_test_local_only')}@127.0.0.1:{os.environ['DB_PORT']}/safenestt_ai_test"
)
os.environ["SAFENESTT_DATABASE_URL"] = (
    f"postgresql://safenestt_app:{os.getenv('SAFENESTT_TEST_PASSWORD', 'safenestt_test_local_only')}@127.0.0.1:{os.environ['DB_PORT']}/safenestt_ai_test"
)
os.environ["DATABASE_URL"] = f"postgresql://safenestt_app:{os.getenv('SAFENESTT_TEST_PASSWORD', 'safenestt_test_local_only')}@127.0.0.1:{os.environ['DB_PORT']}/safenestt_ai_test"

from safenestt.persistence.models import APIKeyModel, APIKeyAuditModel


def test_key_creation_returns_argon2_hash():
    """Keys are stored as Argon2id hashes, never plaintext."""
    from safenestt.security.api_keys import get_key_store, _compute_argon2_hash, _compute_key_fingerprint

    store = get_key_store()
    raw_key = "test-key-lifecycle-12345"

    raw, argon2_hash, fingerprint = store.create_key(
        tenant_id="tenant-lifecycle",
        raw_key=raw_key,
        name="Test Key",
    )

    # Verify format
    assert argon2_hash.startswith("$argon2id$")
    assert fingerprint == _compute_key_fingerprint(raw_key)

    # Verify we can validate the key
    is_valid, tenant_id, fp2, meta = store.validate_key(raw_key)
    assert is_valid
    assert tenant_id == "tenant-lifecycle"
    assert fp2 == fingerprint


def test_key_revocation_blocks_validation():
    """Revoked keys are immediately rejected."""
    from safenestt.security.api_keys import get_key_store

    store = get_key_store()
    raw_key = f"test-revoke-lifecycle-{uuid.uuid4().hex[:8]}"

    store.create_key(tenant_id="tenant-revoke", raw_key=raw_key)

    is_valid, _, _, _ = store.validate_key(raw_key)
    assert is_valid

    result = store.revoke_key(raw_key)
    assert result is True

    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get("error") == "key_revoked"


def test_key_expiry_blocks_validation():
    """Expired keys are rejected at validation time."""
    from safenestt.security.api_keys import get_key_store

    store = get_key_store()
    raw_key = f"test-expiry-lifecycle-{uuid.uuid4().hex[:8]}"

    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    store.create_key(tenant_id="tenant-expiry", raw_key=raw_key, expires_at=past)

    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get("error") == "key_expired"


def test_key_rotation():
    """Key rotation creates new key and revokes old."""
    from safenestt.security.api_keys import get_key_store

    store = get_key_store()
    raw_key = f"test-rotate-lifecycle-{uuid.uuid4().hex[:8]}"

    store.create_key(tenant_id="tenant-rotate", raw_key=raw_key)

    new_raw, new_hash, new_fp = store.rotate_key(raw_key, "tenant-rotate")

    # Old key should be revoked
    is_valid, _, _, meta = store.validate_key(raw_key)
    assert not is_valid
    assert meta.get("error") == "key_revoked"

    # New key should work
    is_valid, _, _, _ = store.validate_key(new_raw)
    assert is_valid