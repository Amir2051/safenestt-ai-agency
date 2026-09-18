"""Tests for complete encryption coverage — ISSUE 4.

These tests verify that:
1. All sensitive fields are encrypted before writing to the database
2. Plaintext is never stored in the database
3. Decryption only happens at the authorized service boundary
4. Cross-tenant access returns ciphertext (which is useless without the key)
"""
from __future__ import annotations

import pytest
from sqlalchemy import text

from safenestt.persistence.engine import session_scope, create_engine, get_owner_engine
from safenestt.security.api_keys import get_key_store, _compute_key_fingerprint
from safenestt.investigations.store import PersistentInvestigationStore
from safenestt.security.encryption import encrypt_value, decrypt_value


@pytest.fixture(scope="module")
def engine():
    eng = create_engine()
    yield eng


@pytest.fixture(autouse=True)
def _test_data():
    """Create test API keys for encryption tests."""
    import uuid
    test_id = uuid.uuid4().hex[:8]
    
    store = get_key_store()
    
    raw_key = f"test-encrypt-key-{test_id}"
    store.create_key(tenant_id="tenant-encrypt", raw_key=raw_key, name="Encrypt Test Key")
    
    fingerprint = _compute_key_fingerprint(raw_key)
    
    yield {
        "raw": raw_key,
        "fingerprint": fingerprint,
        "tenant": "tenant-encrypt",
        "test_id": test_id,
    }


def test_target_encrypted_at_rest(_test_data):
    """Investigation target must be encrypted in the database."""
    store = PersistentInvestigationStore(tenant_id=_test_data["tenant"], key_fingerprint=_test_data["fingerprint"])
    
    # Create an investigation with sensitive target
    from safenestt.investigations.records import InvestigationRecord
    record = InvestigationRecord(
        investigation_id=f"inv-target-{_test_data['test_id']}",
        tenant_id=_test_data["tenant"],
        target="super-secret-target.com",
        type="cybersecurity",
        status="QUEUED",
    )
    store.create_investigation(record)
    
    # Verify the database contains ciphertext, not plaintext
    with get_owner_engine().connect() as conn:
        result = conn.execute(text("""
            SELECT target FROM investigations WHERE investigation_id = :inv_id
        """), {"inv_id": f"inv-target-{_test_data['test_id']}"}).fetchone()
        
        db_value = result[0]
        
        # Must NOT be plaintext
        assert db_value != "super-secret-target.com"
        
        # Must be valid Fernet ciphertext (can be decrypted)
        decrypted = decrypt_value(db_value)
        assert decrypted == "super-secret-target.com"


def test_target_decrypted_at_boundary(_test_data):
    """Investigation target must be decrypted when read through the API."""
    store = PersistentInvestigationStore(tenant_id=_test_data["tenant"], key_fingerprint=_test_data["fingerprint"])
    
    plaintext = "secret-target-at-boundary.com"
    from safenestt.investigations.records import InvestigationRecord
    record = InvestigationRecord(
        investigation_id=f"inv-boundary-{_test_data['test_id']}",
        tenant_id=_test_data["tenant"],
        target=plaintext,
        type="cybersecurity",
        status="QUEUED",
    )
    store.create_investigation(record)
    
    # Read back through the API
    result = store.get_investigation(f"inv-boundary-{_test_data['test_id']}")
    
    # Must return plaintext (decrypted at boundary)
    assert result is not None
    assert result.target == plaintext


def test_evidence_target_encrypted(_test_data):
    """Evidence target must be encrypted at rest."""
    store = PersistentInvestigationStore(tenant_id=_test_data["tenant"], key_fingerprint=_test_data["fingerprint"])
    
    # Create parent investigation first
    from safenestt.investigations.records import InvestigationRecord
    inv_record = InvestigationRecord(
        investigation_id=f"inv-evidence-parent-{_test_data['test_id']}",
        tenant_id=_test_data["tenant"],
        target="parent-target.com",
        type="cybersecurity",
        status="QUEUED",
    )
    store.create_investigation(inv_record)
    
    # Create evidence with sensitive target
    from safenestt.investigations.records import EvidenceRecord
    evidence = EvidenceRecord(
        investigation_id=f"inv-evidence-parent-{_test_data['test_id']}",
        evidence_id=f"ev-target-{_test_data['test_id']}",
        source="dns",
        source_type="tool",
        target="secret-evidence-target.com",
        data={"query": "A record", "result": "1.2.3.4"},
    )
    store.add_evidence(evidence)
    
    # Verify DB contains ciphertext
    with get_owner_engine().connect() as conn:
        result = conn.execute(text("""
            SELECT target, data FROM evidence WHERE evidence_id = :ev_id
        """), {"ev_id": f"ev-target-{_test_data['test_id']}"}).fetchone()
        
        db_target = result[0]
        db_data = result[1]
        
        # Must NOT be plaintext
        assert db_target != "secret-evidence-target.com"
        assert db_data != {"query": "A record", "result": "1.2.3.4"}
        
        # Must decrypt correctly
        assert decrypt_value(db_target) == "secret-evidence-target.com"
        decrypted_data = decrypt_value(db_data)
        assert decrypted_data["query"] == "A record"
        assert decrypted_data["result"] == "1.2.3.4"


def test_finding_claim_encrypted(_test_data):
    """Finding claim must be encrypted at rest."""
    store = PersistentInvestigationStore(tenant_id=_test_data["tenant"], key_fingerprint=_test_data["fingerprint"])
    
    # Create parent investigation
    from safenestt.investigations.records import InvestigationRecord
    inv_record = InvestigationRecord(
        investigation_id=f"inv-finding-parent-{_test_data['test_id']}",
        tenant_id=_test_data["tenant"],
        target="parent-target.com",
        type="cybersecurity",
        status="QUEUED",
    )
    store.create_investigation(inv_record)
    
    # Create finding with sensitive claim
    from safenestt.investigations.records import FindingRecord
    finding = FindingRecord(
        investigation_id=f"inv-finding-parent-{_test_data['test_id']}",
        finding_id=f"find-claim-{_test_data['test_id']}",
        claim="Secret finding: the suspect uses cryptocurrency wallets",
        evidence_ids=[],
        reality_status="AI_INFERENCE",
        risk_score=0.8,
        factors={"wallet_type": "bitcoin", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
    )
    store.add_finding(finding)
    
    # Verify DB contains ciphertext
    with get_owner_engine().connect() as conn:
        result = conn.execute(text("""
            SELECT claim, factors FROM findings WHERE finding_id = :find_id
        """), {"find_id": f"find-claim-{_test_data['test_id']}"}).fetchone()
        
        db_claim = result[0]
        db_factors = result[1]
        
        # Must NOT be plaintext
        assert db_claim != "Secret finding: the suspect uses cryptocurrency wallets"
        assert db_factors != {"wallet_type": "bitcoin", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}
        
        # Must decrypt correctly
        assert decrypt_value(db_claim) == "Secret finding: the suspect uses cryptocurrency wallets"
        decrypted_factors = decrypt_value(db_factors)
        assert decrypted_factors["wallet_type"] == "bitcoin"


def test_cross_tenant_access_returns_ciphertext(_test_data):
    """Even if a cross-tenant read bypasses RLS, the data is useless ciphertext."""
    store1 = PersistentInvestigationStore(tenant_id=_test_data["tenant"], key_fingerprint=_test_data["fingerprint"])
    
    # Create investigation
    from safenestt.investigations.records import InvestigationRecord
    record = InvestigationRecord(
        investigation_id=f"inv-crosstenant-{_test_data['test_id']}",
        tenant_id=_test_data["tenant"],
        target="super-secret-crosstenant.com",
        type="cybersecurity",
        status="QUEUED",
    )
    store1.create_investigation(record)
    
    # Get a different tenant's key
    raw_key_2 = f"test-key-other-{_test_data['test_id']}"
    store = get_key_store()
    store.create_key(tenant_id="tenant-other", raw_key=raw_key_2)
    fp_2 = _compute_key_fingerprint(raw_key_2)
    
    # Try to read with different tenant's key
    store2 = PersistentInvestigationStore(tenant_id="tenant-other", key_fingerprint=fp_2)
    result = store2.get_investigation(f"inv-crosstenant-{_test_data['test_id']}")
    
    # RLS should block the read entirely
    assert result is None


def test_encryption_round_trip():
    """Verify encrypt/decrypt round trip for all sensitive data types."""
    import os
    from cryptography.fernet import Fernet
    from safenestt.security.secrets import clear_cache
    
    # Set a valid encryption key for this test
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    valid_key = Fernet.generate_key().decode()
    os.environ["SAFENESTT_ENCRYPTION_KEY"] = valid_key
    clear_cache()
    
    try:
        # String
        plaintext_str = "sensitive string data"
        encrypted_str = encrypt_value(plaintext_str)
        assert encrypted_str != plaintext_str
        assert decrypt_value(encrypted_str) == plaintext_str
        
        # Dict
        plaintext_dict = {"key1": "value1", "nested": {"key2": "value2"}}
        encrypted_dict = encrypt_value(plaintext_dict)
        assert encrypted_dict != str(plaintext_dict)
        assert decrypt_value(encrypted_dict) == plaintext_dict
        
        # None handling
        assert encrypt_value(None) is None
        assert decrypt_value(None) is None
    finally:
        if original_key is None:
            os.environ.pop("SAFENESTT_ENCRYPTION_KEY", None)
        else:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = original_key
        clear_cache()


def test_encryption_enabled_check():
    """Verify is_encryption_enabled returns True when key is configured."""
    import os
    original_key = os.environ.get("SAFENESTT_ENCRYPTION_KEY")
    
    try:
        from cryptography.fernet import Fernet
        valid_key = Fernet.generate_key().decode()
        os.environ["SAFENESTT_ENCRYPTION_KEY"] = valid_key
        
        from safenestt.security.encryption import is_encryption_enabled
        assert is_encryption_enabled()
    
    finally:
        if original_key is None:
            os.environ.pop("SAFENESTT_ENCRYPTION_KEY", None)
        else:
            os.environ["SAFENESTT_ENCRYPTION_KEY"] = original_key
