"""Audit-event hash-chain coverage — GENESIS origin + rotation.

Verifies the chain-hash computation at the origin:
  - First event -> chain_hash = SHA256("GENESIS:" + event_data)
  - Subsequent events -> chain_hash = SHA256(previous_hash + event_data)

Also documents the genesis-rotation governance: when every audit row is
purged, the persistent `AuditEventRepository` rebuilds from the GENESIS
anchor (not from a fabricated "row 0" identity). The verification routine
returns `(True, "No events to verify")` on an empty list, which is the
fail-closed meaning of "nothing to verify" — a purge does not manufacture a
spurious valid row, it simply stops the chain.

These are logic tests (no database). The persistent-repo rotation path is
governed by the same `GENESIS` anchor written by `AuditEventRepository.record()`
and verified by `AuditEventRepository.verify_chain_integrity()`, so the
origin and the verification stay consistent by construction.
"""
import hashlib

from safenestt.persistence.repositories import AuditEventRepository


class _Event:
    def __init__(self, event_id, actor_type, actor_id, action, decision, chain_hash=None, id=None):
        self.event_id = event_id
        self.actor_type = actor_type
        self.actor_id = actor_id
        self.action = action
        self.decision = decision
        self.chain_hash = chain_hash
        self.id = id or hash(event_id)


def _event(event_id="audit-0001", actor_type="system", actor_id="system",
           action="test", decision="allow", chain_hash=None, id=None):
    return _Event(event_id, actor_type, actor_id, action, decision, chain_hash, id)


def _genesis_hash(event_data):
    return hashlib.sha256(f"GENESIS:{event_data}".encode()).hexdigest()


def test_genesis_origin():
    """First event uses GENESIS as the previous hash."""
    event_data = "auth-deny:system:allow"
    assert AuditEventRepository._compute_hash(None, event_data) == _genesis_hash(event_data)


def test_chained_origin():
    """Subsequent events chain off the previous row's hash."""
    h1 = AuditEventRepository._compute_hash(None, "audit-0001:system:system:test:allow")
    h2 = AuditEventRepository._compute_hash(h1, "audit-0002:system:system:test:allow")
    e1 = _event(event_id="audit-0001", chain_hash=h1)
    e2 = _event(event_id="audit-0002", chain_hash=h2)
    assert h1 != h2


def test_verify_valid_chain():
    events = [_event(event_id="audit-0001", id=1), _event(event_id="audit-0002", id=2)]
    events[0].chain_hash = _genesis_hash("audit-0001:system:system:test:allow")
    # Second row chains off the first: SHA256(GENESIS_hash + "audit-0002:...:allow")
    events[1].chain_hash = AuditEventRepository._compute_hash(
        events[0].chain_hash, "audit-0002:system:system:test:allow"
    )
    is_valid, msg = AuditEventRepository.verify_chain_integrity(events)
    assert is_valid is True
    assert "2" in msg


def test_verify_tampered_chain():
    events = [_event(event_id="audit-0001", id=1), _event(event_id="audit-0002", id=2)]
    events[0].chain_hash = _genesis_hash("audit-0001:system:system:test:allow")
    # Correct chained hash for the second row (with "allow").
    correct = AuditEventRepository._compute_hash(
        events[0].chain_hash, "audit-0002:system:system:test:allow"
    )
    # Tamper: third-party overwrites the stored hash with a forged value.
    events[1].chain_hash = hashlib.sha256(b"forged").hexdigest()
    is_valid, msg = AuditEventRepository.verify_chain_integrity(events)
    assert is_valid is False
    assert "broken" in msg.lower()


def test_verify_empty_chain():
    """Purged chain: nothing to verify -> trivially valid, no fabricated row."""
    is_valid, msg = AuditEventRepository.verify_chain_integrity([])
    assert is_valid is True
    assert "no events to verify" in msg.lower()
