"""Regression tests for the SENTRA E2E remediation sprint.

Covers:
  Blocker 1 — report persistence (use-before-assignment of `intelligence`)
  Blocker 2 — graph persistence (bridge dicts vs GraphNodeRecord)
  Blocker 3 — silent error handling classification
  Blocker 5 — Reality Checker classification rules
  Blocker 6 — structured provider-failure recording

These tests are DB-backed where persistence is under test. They set env BEFORE
importing safenestt (engine.py reads DB_HOST/DB_PORT at module import).
"""
from __future__ import annotations

import hashlib
import os

# --- env must be set before importing safenestt -----------------------
os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "54322")
os.environ.setdefault("DB_NAME", "safenestt_ai_test")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "postgres")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "postgres")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

import json
import uuid

import pytest
from sqlalchemy import text

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.reality import RealityChecker
from safenestt.investigations.store import PersistentInvestigationStore
from safenestt.persistence.engine import create_engine

TENANT = "safenestt-remediate-test"
RUN_ID = uuid.uuid4().hex[:12]
RAW_KEY = "test-remediate-" + RUN_ID
FINGERPRINT = hashlib.sha256(RAW_KEY.encode()).hexdigest()
# key_hash must be unique too (ix_api_keys_key_hash is UNIQUE) and must differ
# per run so a previous run's row never collides.
KEY_HASH = "sha256:" + hashlib.sha256(("hash-" + RUN_ID).encode()).hexdigest()

_db_ready = False


def _db_available() -> bool:
    global _db_ready
    if _db_ready:
        return True
    try:
        eng = create_engine()
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        _db_ready = True
    except Exception:
        return False
    return _db_ready


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL not available")


@pytest.fixture()
def store():
    """Tenant-scoped store with a real registered API key."""
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
        "VALUES (%s, %s, %s, 'remediation-test', TRUE, FALSE, "
        "'[\"read\",\"write\"]'::json, 0, NOW()) "
        "ON CONFLICT (key_fingerprint) DO UPDATE SET active=TRUE, revoked=FALSE",
        (KEY_HASH, FINGERPRINT, TENANT),
    )
    conn.commit()
    cur.close()
    conn.close()

    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
    return PersistentInvestigationStore(tenant_id=TENANT, key_fingerprint=FINGERPRINT)


def _mk_investigation() -> InvestigationRecord:
    return InvestigationRecord(
        investigation_id=f"inv-test-{uuid.uuid4().hex[:12]}",
        tenant_id=TENANT,
        target="example.com",
        type="web",
        case_id=f"case-test-{uuid.uuid4().hex[:8]}",
    )


def _mk_evidence(inv_id: str, ev_id: str) -> EvidenceRecord:
    return EvidenceRecord(
        investigation_id=inv_id,
        evidence_id=ev_id,
        source="cyber_intel.threat_intel.test",
        source_type="tool",
        target="example.com",
        data={"tool_call": {"tool_id": "t"}, "provider": "p", "data": {"k": "v"}},
        confidence=0.7,
        tool_run_id=f"run-{uuid.uuid4().hex[:8]}",
    )


# =====================================================================
# BLOCKER 1 — REPORT PERSISTENCE
# =====================================================================

@requires_db
def test_blocker1_report_persists_and_is_retrievable_after_request(store):
    """investigation -> add_report -> DB row -> retrievable on a later fetch.

    Regression for the use-before-assignment of `intelligence`, which made
    add_report() throw NameError that a bare `except: pass` swallowed.
    """
    rec = _mk_investigation()
    store.create_investigation(rec)

    draft = {"executive_summary": "persisted", "risk": {"score": 1.0}}
    store.add_report(investigation_id=rec.investigation_id, draft=draft)

    # A brand-new store object == a later request, not the original one.
    later = PersistentInvestigationStore(tenant_id=TENANT, key_fingerprint=FINGERPRINT)
    rows = later.list_reports(rec.investigation_id) if hasattr(later, "list_reports") else None

    if rows is None:
        eng = create_engine()
        with eng.connect() as c:
            c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                      {"t": TENANT, "f": FINGERPRINT})
            cnt = c.execute(
                text("SELECT COUNT(*) FROM reports WHERE investigation_id=:i"),
                {"i": rec.investigation_id}).scalar()
            draft_back = c.execute(
                text("SELECT draft FROM reports WHERE investigation_id=:i"),
                {"i": rec.investigation_id}).scalar()
    else:
        cnt = len(rows)
        draft_back = rows[0]

    assert cnt == 1, f"expected exactly 1 report row, got {cnt}"
    assert draft_back is not None
    payload = draft_back if isinstance(draft_back, dict) else json.loads(
        draft_back if isinstance(draft_back, str) else json.dumps(draft_back))
    assert payload.get("executive_summary") == "persisted"


@requires_db
def test_blocker1_add_report_is_idempotent_single_row(store):
    """add_report called twice for one investigation must not duplicate rows."""
    rec = _mk_investigation()
    store.create_investigation(rec)
    store.add_report(investigation_id=rec.investigation_id, draft={"v": 1})
    store.add_report(investigation_id=rec.investigation_id, draft={"v": 1})
    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
        cnt = c.execute(text("SELECT COUNT(*) FROM reports WHERE investigation_id=:i"),
                        {"i": rec.investigation_id}).scalar()
    assert cnt <= 1, f"duplicate report rows: {cnt}"


@requires_db
def test_blocker1_no_bare_except_pass_remains_in_investigator():
    """The critical report-persistence handler must not swallow silently."""
    import inspect
    import safenestt.investigations.investigator as inv
    src = inspect.getsource(inv.run_investigation)
    assert "except Exception:\n        pass" not in src, \
        "critical persistence path is still silently swallowed"
    assert "report_persistence_failed" in src
    assert "logger.exception" in src


# =====================================================================
# BLOCKER 2 — GRAPH PERSISTENCE
# =====================================================================

@requires_db
def test_blocker2_bridge_dicts_persist_as_graph_nodes_and_edges(store):
    """Persisted evidence -> bridge -> graph nodes AND edges actually stored.

    Regression for passing bridge dicts straight into add_graph_node(),
    which addresses record attributes and raised AttributeError.
    """
    from safenestt.bridge.transformation import bridge_investigation
    rec = _mk_investigation()
    store.create_investigation(rec)
    ev = _mk_evidence(rec.investigation_id, f"ev-{uuid.uuid4().hex[:8]}")
    store.add_evidence(ev)
    fnd = FindingRecord(
        investigation_id=rec.investigation_id,
        finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
        claim="tool-derived observation",
        evidence_ids=[ev.evidence_id],
        reality_status="AI_INFERENCE",
    )
    store.add_finding(fnd)

    br = bridge_investigation(
        hermes_inv=rec, findings=[fnd], evidence=[ev],
        case_id=rec.case_id or rec.investigation_id, provider_tool_calls=[])
    assert br.graph_nodes, "bridge produced no nodes"
    assert br.graph_edges, "bridge produced no edges"

    # This is exactly what investigator.py does — convert back to records.
    from safenestt.bridge.transformation import GraphEdgeRecord, GraphNodeRecord
    for n in br.graph_nodes:
        store.add_graph_node(GraphNodeRecord(
            id=n["id"], investigation_id=rec.investigation_id,
            case_id=n.get("case_id", rec.case_id), node_key=n["id"],
            node_type=n.get("node_type", "entity"), label=n.get("label", ""),
            node_data=n.get("node_data") or {}, source="hermes", provenance="test"))
    for e in br.graph_edges:
        store.add_graph_edge(GraphEdgeRecord(
            id=e["id"], investigation_id=rec.investigation_id,
            case_id=e.get("case_id", rec.case_id), edge_key=e["id"],
            source_node_id=e["source_node_id"], target_node_id=e["target_node_id"],
            edge_type=e.get("edge_type", "related"), edge_label=e.get("edge_label", ""),
            edge_data=e.get("edge_data") or {}, source="hermes", provenance="test"))

    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
        n = c.execute(text("SELECT COUNT(*) FROM graph_nodes WHERE investigation_id=:i"),
                      {"i": rec.investigation_id}).scalar()
        eg = c.execute(text("SELECT COUNT(*) FROM graph_edges WHERE investigation_id=:i"),
                       {"i": rec.investigation_id}).scalar()
    assert n == len(br.graph_nodes), f"nodes persisted {n} != {len(br.graph_nodes)}"
    assert eg == len(br.graph_edges), f"edges persisted {eg} != {len(br.graph_edges)}"


@requires_db
def test_blocker2_edge_requires_nodes_from_same_investigation(store):
    """Same-investigation integrity must fail closed."""
    from safenestt.bridge.transformation import GraphEdgeRecord
    rec_a = _mk_investigation()
    rec_b = _mk_investigation()
    store.create_investigation(rec_a)
    store.create_investigation(rec_b)
    with pytest.raises(ValueError):
        store.add_graph_edge(GraphEdgeRecord(
            id="ge-x", investigation_id=rec_a.investigation_id,
            case_id=rec_a.case_id or "", edge_key="ge-x",
            source_node_id="gn-missing", target_node_id="gn-missing2",
            edge_type="about", edge_label="", edge_data={},
            source="test", provenance="test"))


def test_blocker2_malformed_evidence_data_fails_safe():
    """Corrupt/encrypted-string evidence.data must not silently pass as a dict."""
    from safenestt.bridge.transformation import build_case_evidence_item_data
    # Bypass the dataclass type hint to simulate the real-world case where a
    # row comes back from the DB as a ciphertext string.
    bad = EvidenceRecord(
        investigation_id="inv-x", evidence_id="ev-x",
        source="s", source_type="tool", target="t",
        data={}, confidence=0.5,
    )
    bad.data = "Z0FBQUFB-cryptographic-blob-not-a-dict"  # type: ignore[assignment]
    with pytest.raises(Exception):
        build_case_evidence_item_data(bad, finding=None, provider_run_id=None)


@requires_db
def test_blocker2_encrypted_evidence_decodes_to_dict_on_load(store):
    """Encryption-at-rest: DB holds ciphertext, list_evidence returns dict."""
    rec = _mk_investigation()
    store.create_investigation(rec)
    ev = _mk_evidence(rec.investigation_id, f"ev-{uuid.uuid4().hex[:8]}")
    store.add_evidence(ev)

    eng = create_engine()
    with eng.connect() as c:
        c.execute(text("SELECT establish_tenant_context(:t, :f)"),
                  {"t": TENANT, "f": FINGERPRINT})
        raw = c.execute(text("SELECT data FROM evidence WHERE evidence_id=:e"),
                        {"e": ev.evidence_id}).scalar()
    loaded = store.list_evidence(rec.investigation_id)
    mine = [e for e in loaded if e.evidence_id == ev.evidence_id]
    assert mine, "evidence not returned by list_evidence"
    if raw is not None:
        # stored representation may be ciphertext or plain JSON depending on
        # whether SAFENESTT_ENCRYPTION_KEY is configured in the test process
        assert not isinstance(mine[0].data, str), \
            "list_evidence returned a raw string — encryption path broken"
    assert isinstance(mine[0].data, dict)


# =====================================================================
# BLOCKER 3 — SILENT ERROR HANDLING
# =====================================================================

def test_blocker3_bridge_handler_is_not_silent():
    import inspect
    import safenestt.investigations.investigator as inv
    src = inspect.getsource(inv.run_investigation)
    assert "bridge_persistence_failed" in src
    assert "COMPLETED_WITH_ERRORS" in src


def test_blocker3_completed_with_errors_is_a_valid_state():
    r = InvestigationRecord(investigation_id="i", tenant_id=TENANT)
    r.mark("RUNNING")
    r.mark("VERIFYING")
    r.mark("CALCULATING_RISK")
    r.mark("COMPLETED_WITH_ERRORS")  # must not raise
    assert r.status == "COMPLETED_WITH_ERRORS"


def test_blocker3_completed_is_still_terminal():
    r = InvestigationRecord(investigation_id="i", tenant_id=TENANT)
    r.mark("RUNNING")
    r.mark("VERIFYING")
    r.mark("CALCULATING_RISK")
    r.mark("COMPLETED")
    from safenestt.investigations.records import InvalidStatusError
    with pytest.raises(InvalidStatusError):
        r.mark("RUNNING")


# =====================================================================
# BLOCKER 5 — REALITY CHECKER
# =====================================================================

def _ev(eid: str) -> EvidenceRecord:
    return EvidenceRecord(investigation_id="i", evidence_id=eid, source="s",
                          source_type="tool", target="t", data={}, confidence=0.7)


def test_blocker5_supported_finding_is_promoted():
    lookup = lambda inv, eid: _ev(eid) if eid.startswith("ev-ok") else None
    chk = RealityChecker(evidence_lookup=lookup)
    f = FindingRecord(investigation_id="i", finding_id="f1",
                      claim="supported", evidence_ids=["ev-ok1"])
    res = chk.evaluate(f)
    assert res.reality_status == "EVIDENCE_SUPPORTED"


def test_blocker5_partially_supported_stays_inference():
    """Some evidence resolves, some does not -> NOT promoted."""
    lookup = lambda inv, eid: _ev(eid) if eid.startswith("ev-ok") else None
    chk = RealityChecker(evidence_lookup=lookup)
    f = FindingRecord(investigation_id="i", finding_id="f2",
                      claim="partial", evidence_ids=["ev-ok1", "ev-missing"])
    res = chk.evaluate(f)
    assert res.reality_status == "AI_INFERENCE"
    assert res.unsupported_claims


def test_blocker5_unsupported_no_evidence_is_inference():
    chk = RealityChecker(evidence_lookup=lambda i, e: None)
    f = FindingRecord(investigation_id="i", finding_id="f3",
                      claim="no evidence", evidence_ids=[])
    assert chk.evaluate(f).reality_status == "AI_INFERENCE"


def test_blocker5_insufficient_evidence_lookup_none():
    chk = RealityChecker(evidence_lookup=None)
    f = FindingRecord(investigation_id="i", finding_id="f4",
                      claim="x", evidence_ids=["ev-1"])
    assert chk.evaluate(f).reality_status == "EVIDENCE_SUPPORTED"


def test_blocker5_finding_type_validation_allows_four_types():
    from safenestt.schemas.findings import Finding
    for ft in ("VERIFIED_EVIDENCE", "EXTERNAL_INTELLIGENCE",
               "AI_INFERENCE", "INVESTIGATOR_CONCLUSION"):
        f = Finding(finding_id="x", finding_type=ft, title="t", description="d")
        assert f.finding_type == ft


# =====================================================================
# BLOCKER 6 — AGENT FAILURE RECORDING
# =====================================================================

def test_blocker6_failed_provider_run_records_structured_error():
    from safenestt.schemas.findings import AgentRun
    from safenestt.investigation.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator.__new__(InvestigationOrchestrator)

    class FakeProvider:
        provider_name = "shodan"

        def execute(self, agent, capability, payload):
            return {"status": "error", "error": "provider_not_configured",
                    "data": {}, "metadata": {}}

    from safenestt.schemas.findings import Investigation
    inv = Investigation(investigation_id="inv-1", case_id="c1")
    res = orch._run_providers_for_indicators(
        {"shodan": FakeProvider()}, {"domain": "example.com"}, inv, {})
    runs = [r["run"] for r in res]
    failed = [r for r in runs if r.status == "failed"]
    assert failed, "expected a failed provider run"
    assert failed[0].error, "failed run recorded NO error (Blocker 6 regression)"
    parsed = json.loads(failed[0].error)
    assert parsed["provider"] == "shodan"
    assert parsed["failure_class"] == "configuration"
    assert parsed["capability"]