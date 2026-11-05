"""Regression tests for the report-persistence JSON serialization boundary.

Root cause these cover:
    TypeError: Object of type datetime is not JSON serializable
raised when the report dossier (assembled from dataclass __dict__ values) was
bound into the PostgreSQL `json` column.

Run ONLY this directory. `tests/conftest.py` has an autouse TRUNCATE-ALL
fixture that would destroy preserved investigations, diagnostic rows, and API
keys.
"""
from __future__ import annotations

import os

os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "54322")
os.environ.setdefault("DB_NAME", "safenestt_ai_test")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "postgres")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "postgres")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

import datetime as dt
import enum
import hashlib
import json
import uuid

import pytest
from sqlalchemy import text

from safenestt.investigations.serialization import (
    JSONSerializationError,
    json_safe,
    json_safe_text,
)

TENANT = "safenestt-serialize-test"
RUN_ID = uuid.uuid4().hex[:12]
RAW_KEY = "test-serialize-" + RUN_ID
FINGERPRINT = hashlib.sha256(RAW_KEY.encode()).hexdigest()
KEY_HASH = "sha256:" + hashlib.sha256(("h-" + RUN_ID).encode()).hexdigest()


# =============================================================
# Pure normalization tests (no DB)
# =============================================================

class _Colour(enum.Enum):
    RED = "red"
    BLUE = "blue"


def test_datetime_becomes_iso8601():
    v = dt.datetime(2026, 10, 1, 12, 30, 45, tzinfo=dt.timezone.utc)
    out = json_safe({"observed_at": v})
    assert out["observed_at"] == "2026-10-01T12:30:45+00:00"
    # Round-trippable and semantically recognizable.
    assert dt.datetime.fromisoformat(out["observed_at"]) == v


def test_naive_datetime_iso8601():
    out = json_safe({"t": dt.datetime(2026, 1, 2, 3, 4, 5)})
    assert out["t"] == "2026-01-02T03:04:05"


def test_date_becomes_iso8601():
    out = json_safe({"d": dt.date(2026, 10, 1)})
    assert out["d"] == "2026-10-01"
    assert dt.date.fromisoformat(out["d"]) == dt.date(2026, 10, 1)


def test_time_becomes_iso8601():
    out = json_safe({"t": dt.time(23, 59, 59)})
    assert out["t"] == "23:59:59"


def test_uuid_becomes_string():
    u = uuid.uuid4()
    assert json_safe({"id": u})["id"] == str(u)


def test_enum_uses_value_not_repr():
    assert json_safe({"c": _Colour.RED})["c"] == "red"


def test_nested_datetime_deep_in_structure():
    payload = {
        "dossier": {
            "evidence": [
                {"observed_at": dt.datetime(2026, 5, 5, 1, 2, 3),
                 "meta": {"seen": [dt.datetime(2026, 6, 6, 7, 8, 9)]}}
            ],
            "risk": {"score": 72.58, "generated": dt.datetime(2026, 7, 7)},
        }
    }
    out = json_safe(payload)
    ev = out["dossier"]["evidence"][0]
    assert ev["observed_at"] == "2026-05-05T01:02:03"
    assert ev["meta"]["seen"] == ["2026-06-06T07:08:09"]
    assert out["dossier"]["risk"]["generated"] == "2026-07-07T00:00:00"
    # and it is now JSON-serializable end to end
    json.dumps(out)


def test_primitives_unchanged():
    p = {"a": 1, "b": 1.5, "c": "s", "d": True, "e": None}
    assert json_safe(p) == p


def test_tuples_and_sets_become_lists():
    out = json_safe({"t": (1, 2), "s": {3}})
    assert isinstance(out["t"], list) and out["t"] == [1, 2]
    assert isinstance(out["s"], list) and out["s"] == [3]


def test_non_string_keys_normalized():
    out = json_safe({uuid.uuid4(): 1, 5: 2})
    assert all(isinstance(k, str) for k in out)


def test_unsupported_object_fails_explicitly():
    class Weird:
        pass

    with pytest.raises(JSONSerializationError) as exc:
        json_safe({"bad": Weird()})
    assert "Weird" in str(exc.value)
    assert "bad" in str(exc.value)  # path is reported


def test_unsupported_nested_path_reported():
    class Weird:
        pass

    with pytest.raises(JSONSerializationError) as exc:
        json_safe({"a": {"b": [1, {"c": Weird()}]}})
    assert "$.a.b[1].c" in str(exc.value)


def test_recursive_structure_fails_loudly_not_stack_overflow():
    d: dict = {}
    d["self"] = d
    with pytest.raises(JSONSerializationError):
        json_safe(d)


def test_json_safe_text_roundtrip():
    txt = json_safe_text({"when": dt.datetime(2026, 3, 3, 3, 3, 3)})
    assert json.loads(txt)["when"] == "2026-03-03T03:03:03"


# =============================================================
# DB-backed persistence tests
# =============================================================

_db_ready = False


def _db_ok() -> bool:
    global _db_ready
    if _db_ready:
        return True
    try:
        from safenestt.persistence.engine import create_engine
        eng = create_engine()
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        _db_ready = True
    except Exception:
        return False
    return _db_ready


requires_db = pytest.mark.skipif(not _db_ok(), reason="PostgreSQL not available")


@pytest.fixture()
def store():
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "55432")),
        user=os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_test"),
        password=os.environ.get("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only"),
        dbname=os.environ["DB_NAME"], sslmode="disable",
    )
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO api_keys (key_hash, key_fingerprint, tenant_id, name, "
        "active, revoked, scopes, use_count, created_at) "
        "VALUES (%s,%s,%s,'serialize-test',TRUE,FALSE,'[\"read\",\"write\"]'::json,0,NOW()) "
        "ON CONFLICT (key_fingerprint) DO UPDATE SET active=TRUE, revoked=FALSE",
        (KEY_HASH, FINGERPRINT, TENANT))
    conn.commit()
    cur.close()
    conn.close()

    from safenestt.investigations.records import InvestigationRecord
    from safenestt.investigations.store import PersistentInvestigationStore
    from safenestt.persistence.engine import create_engine

    st = PersistentInvestigationStore(tenant_id=TENANT, key_fingerprint=FINGERPRINT)
    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
    return st


def _new_inv(store, prefix="inv-ser"):
    from safenestt.investigations.records import InvestigationRecord
    rec = InvestigationRecord(
        investigation_id=f"{prefix}-{uuid.uuid4().hex[:10]}",
        tenant_id=TENANT, target="example.com", type="web",
        case_id=f"case-ser-{uuid.uuid4().hex[:8]}")
    store.create_investigation(rec)
    return rec


@requires_db
def test_dossier_with_datetime_persists_and_reads_back(store):
    """The exact blocker: a dossier carrying datetimes must persist."""
    rec = _new_inv(store)
    dossier = {
        "target": "example.com",
        "generated_at": dt.datetime(2026, 10, 1, 12, 0, 0),
        "evidence": [
            {"evidence_id": "ev-1", "observed_at": dt.datetime(2026, 9, 30, 8, 15, 0),
             "confidence": 0.65},
        ],
        "risk": {"score": 72.58, "level": "HIGH"},
    }
    store.add_report(investigation_id=rec.investigation_id, draft=dossier)

    row = store.get_report(rec.investigation_id)
    assert row is not None, "persisted report not retrievable"
    draft = row["draft"]
    assert draft["risk"]["score"] == 72.58
    assert draft["generated_at"] == "2026-10-01T12:00:00"
    assert draft["evidence"][0]["observed_at"] == "2026-09-30T08:15:00"
    assert dt.datetime.fromisoformat(draft["generated_at"]).year == 2026


@requires_db
def test_rerun_is_idempotent_single_row(store):
    rec = _new_inv(store)
    d1 = {"v": 1, "when": dt.datetime(2026, 1, 1)}
    d2 = {"v": 2, "when": dt.datetime(2026, 1, 2)}
    store.add_report(investigation_id=rec.investigation_id, draft=d1)
    store.add_report(investigation_id=rec.investigation_id, draft=d1)
    store.add_report(investigation_id=rec.investigation_id, draft=d2)

    from safenestt.persistence.engine import create_engine
    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
        n = c.execute(text("SELECT COUNT(*) FROM reports WHERE investigation_id=:i"),
                      {"i": rec.investigation_id}).scalar()
    assert n == 1, f"rerun produced {n} report rows"
    row = store.get_report(rec.investigation_id)
    assert row["draft"]["v"] == 2  # latest write wins, single row


@requires_db
def test_unsupported_type_fails_persisted_report_not_silently(store):
    """Normalization failure must raise, not write '<object at 0x...>'."""
    rec = _new_inv(store)

    class Weird:
        pass

    with pytest.raises(JSONSerializationError):
        store.add_report(investigation_id=rec.investigation_id,
                         draft={"bad": Weird()})

    from safenestt.persistence.engine import create_engine
    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
        n = c.execute(text("SELECT COUNT(*) FROM reports WHERE investigation_id=:i"),
                      {"i": rec.investigation_id}).scalar()
    assert n == 0, "a failed normalization still wrote a row"


@requires_db
def test_real_dossier_from_generator_persists(store):
    """The genuine dossier shape (built by build_dossier_intelligence)."""
    from safenestt.investigations.intelligence import build_dossier_intelligence

    rec = _new_inv(store, prefix="inv-real")
    ev = [{"evidence_id": "ev-x", "source": "tool", "source_type": "tool",
           "observed_at": dt.datetime(2026, 10, 1, 9, 0, 0), "confidence": 0.7,
           "data": {}}]
    fnd = [{"finding_id": "f-1", "claim": "c", "evidence_ids": ["ev-x"],
            "reality_status": "AI_INFERENCE", "risk_score": 0.5,
            "confidence": 0.5, "created_at": dt.datetime(2026, 10, 1, 9, 1, 0)}]
    intel = build_dossier_intelligence("example.com", fnd, ev)
    store.add_report(investigation_id=rec.investigation_id,
                     draft=intel["dossier"])
    row = store.get_report(rec.investigation_id)
    assert row and row["draft"]["target"] == "example.com"
    assert "findings" in row["draft"] and "risk" in row["draft"]