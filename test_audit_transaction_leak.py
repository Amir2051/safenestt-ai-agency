"""Regression tests: AuditEventRepository.record() must never leak a transaction.

THE BUG
-------
``record()`` did ``session.add()`` + ``session.flush()`` and returned. ``flush()``
opens a transaction; nothing committed or rolled it back. On the investigation path
that session is long-lived, so the transaction stayed open holding
``RowExclusiveLock`` on ``audit_events_id_seq``. Every later audit INSERT blocked on
it, so a single leaked transaction wedged the whole engine.

Observed in production: a backend ``idle in transaction`` for 15+ hours blocking all
``INSERT INTO audit_events``; terminating it let work resume, then a different backend
leaked within seconds.

Design note: these tests deliberately do NOT wait on PostgreSQL locks. They assert on
``Session.in_transaction()`` -- a direct, deterministic signal that a transaction was
left open -- plus rollback and hash-chain integrity.
"""
from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from safenestt.persistence.models import AuditEventModel, Base
from safenestt.persistence.repositories import AuditEventRepository
from safenestt.security.audit import AuditEvent


@pytest.fixture()
def session(tmp_path):
    # SQLite keeps this hermetic and fast; transaction state is engine-agnostic and
    # is exactly what Session.in_transaction() reports.
    eng = create_engine(f"sqlite:///{tmp_path/'audit.db'}")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables["audit_events"]])
    s = Session(eng)
    yield s
    s.close()
    eng.dispose()


def _event(**kw):
    base = dict(event_id=f"evt-{uuid.uuid4().hex[:8]}", actor_type="system",
                actor_id="tester", action="investigation_started",
                decision="ALLOW", risk_level="LOW", resource_type="investigation",
                resource_id=None, detail=None, metadata=None)
    base.update(kw)
    return AuditEvent(**base)


def test_successful_audit_write_leaves_no_open_transaction(session):
    """The core regression: a completed audit write must not stay in a transaction."""
    AuditEventRepository(session).record(_event())

    assert not session.in_transaction(), (
        "record() returned with an open transaction; on the investigation path this "
        "holds RowExclusiveLock on audit_events_id_seq and blocks all later audit writes")
    assert session.execute(select(AuditEventModel)).scalars().all(), "event was not persisted"


def test_failed_audit_write_rolls_back(session):
    """A duplicate event_id violates the unique index; the transaction must be closed."""
    repo = AuditEventRepository(session)
    repo.record(_event(event_id="dup-1"))
    assert not session.in_transaction()

    # actor_type is NOT NULL -> a genuine constraint failure (a duplicate event_id
    # is now disambiguated by record(), so it would no longer fail here).
    with pytest.raises(IntegrityError):
        repo.record(_event(event_id="dup-1-b", actor_type=None))

    assert not session.in_transaction(), (
        "a failed audit write left the transaction open; this is the exact state "
        "that blocked every subsequent investigation")
    # Only the first event survives.
    assert len(session.execute(select(AuditEventModel)).scalars().all()) == 1


def test_next_audit_write_succeeds_immediately_after_failure(session):
    """No blocking, no waiting: the next write works straight away."""
    repo = AuditEventRepository(session)
    repo.record(_event(event_id="dup-2"))
    with pytest.raises(IntegrityError):
        repo.record(_event(event_id="dup-2-b", actor_type=None))

    # A second "investigation" writes immediately.
    AuditEventRepository(session).record(_event(event_id="second-inv"))

    assert not session.in_transaction()
    ids = [e.event_id for e in session.execute(
        select(AuditEventModel).order_by(AuditEventModel.id)).scalars().all()]
    assert ids == ["dup-2", "second-inv"]


def test_hash_chain_still_links_across_events(session):
    """Hash-chain semantics must be unchanged by the commit/rollback fix."""
    r = AuditEventRepository(session)
    r.record(_event(event_id="chain-a"))
    r.record(_event(event_id="chain-b"))

    rows = session.execute(
        text("SELECT event_id, chain_hash FROM audit_events ORDER BY id")).all()
    assert [x[0] for x in rows] == ["chain-a", "chain-b"]

    # Each hash is sha256(previous_hash + event_data).
    first = hashlib.sha256(
        b"GENESIS:chain-a:system:tester:investigation_started:ALLOW").hexdigest()
    assert rows[0][1] == first, "genesis hash changed"
    second = hashlib.sha256(
        f"{first}:chain-b:system:tester:investigation_started:ALLOW".encode()).hexdigest()
    assert rows[1][1] == second, "chain no longer links to its predecessor"


def test_repeated_writes_never_leave_a_transaction_open(session):
    """The engine writes audit events constantly; none may leak."""
    repo = AuditEventRepository(session)
    for i in range(25):
        repo.record(_event(event_id=f"bulk-{i}"))
        assert not session.in_transaction(), f"transaction open after write {i}"

# ---------------------------------------------------------------------------
# PART 1 regression: deterministic caller event_ids must not collide
# ---------------------------------------------------------------------------
def test_repeated_identical_event_ids_are_disambiguated(session):
    """permissions.py emits a hardcoded "auth-deny"; repeats must still persist."""
    repo = AuditEventRepository(session)
    for _ in range(5):
        repo.record(_event(event_id="auth-deny", decision="DENY"))

    rows = session.execute(
        text("SELECT event_id FROM audit_events ORDER BY id")).scalars().all()
    assert len(rows) == 5, f"only {len(rows)} of 5 events persisted"
    assert len(set(rows)) == 5, f"duplicate event_id persisted: {rows}"
    # First occurrence keeps its stable id so existing lookups still work.
    assert rows[0] == "auth-deny"


def test_sequential_distinct_events_keep_their_ids(session):
    """Non-colliding ids must be left completely untouched."""
    repo = AuditEventRepository(session)
    repo.record(_event(event_id="rate-deny-key1"))
    repo.record(_event(event_id="rate-deny-key2"))
    rows = session.execute(
        text("SELECT event_id FROM audit_events ORDER BY id")).scalars().all()
    assert rows == ["rate-deny-key1", "rate-deny-key2"], "ids were altered unnecessarily"


def test_retried_investigation_does_not_reuse_event_ids(session):
    """A retry re-emits the same deterministic ids; all must survive."""
    repo = AuditEventRepository(session)
    for _ in range(3):          # three attempts of the same investigation
        repo.record(_event(event_id="auth-deny-agent-cap", metadata={"investigation_id": "inv-1"}))
    rows = session.execute(
        text("SELECT event_id FROM audit_events ORDER BY id")).scalars().all()
    assert len(rows) == 3 and len(set(rows)) == 3


def test_concurrent_audit_writes_cannot_collide(session):
    """Two threads, each with its OWN session, writing the same deterministic id.

    A Session is not thread-safe, so each writer gets its own -- this mirrors real
    concurrent requests, where each holds a separate connection.
    """
    import threading
    bind = session.get_bind()
    errors = []

    def writer():
        s = Session(bind)          # own session == own connection
        try:
            for _ in range(4):
                AuditEventRepository(s).record(_event(event_id="auth-deny"))
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            s.close()

    threads = [threading.Thread(target=writer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not t.is_alive(), "a writer blocked instead of completing"
    assert not errors, f"concurrent writes raised: {errors}"
    rows = session.execute(text("SELECT event_id FROM audit_events")).scalars().all()
    assert len(rows) == 8, f"expected 8 events, got {len(rows)}"
    assert len(set(rows)) == len(rows), f"duplicate event_id persisted: {rows}"


def test_hash_chain_preserved_with_disambiguated_ids(session):
    """Collision handling must not break the chain."""
    r = AuditEventRepository(session)
    r.record(_event(event_id="auth-deny"))
    r.record(_event(event_id="auth-deny"))
    rows = session.execute(
        text("SELECT event_id, chain_hash FROM audit_events ORDER BY id")).all()
    assert rows[0][1] != rows[1][1], "second event reused the first's hash"
    first = hashlib.sha256(b"GENESIS:auth-deny:system:tester:investigation_started:ALLOW").hexdigest()
    assert rows[0][1] == first, "genesis hash changed for a disambiguated write"
