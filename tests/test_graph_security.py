"""LIVE DATABASE TESTS — Graph edge security with RLS verification.

Matches the existing test_persistence.py pattern: single database,
table-level cleanup, owner credentials for DDL, app credentials for tests.
"""
from __future__ import annotations

import hashlib
import os
import sys
import uuid

import psycopg2
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Importable regardless of how pytest was invoked (see test_persistence.py).
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

import isolation_guard  # noqa: E402

from safenestt.persistence.models import Base  # noqa: E402
from safenestt.persistence.rls import apply_rls_policies  # noqa: E402

# SECURITY FIX: driver spec is explicit (psycopg2) because the SQLAlchemy 2.1
# default driver (psycopg) is not installed in the test environment.
_OWNER_PASS = os.getenv("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only")
_APP_PASS = os.getenv("SAFENESTT_DB_PASSWORD", os.getenv("DB_PASSWORD", "safenestt_app_pass"))
_DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
_DB_PORT = os.getenv("SAFENESTT_TEST_PORT", "55432")
# SECURITY FIX: was `os.getenv("DB_NAME", "safenestt_ai")` — the default was the
# PRODUCTION database, so any run without DB_NAME exported targeted production.
# The name now comes from the shared allowlist-validated guard.
_DB_NAME = isolation_guard.assert_test_db_configured()

# SQLAlchemy URL for create_engine (uses +psycopg2 driver spec)
_OWNER_URL = f"postgresql+psycopg2://safenestt_owner_test:{_OWNER_PASS}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
_APP_URL = f"postgresql+psycopg2://safenestt_app:{_APP_PASS}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"

# Plain DSN for psycopg2.connect (no SQLAlchemy driver spec; psycopg2 expects
# the standard libpq URI format without the +psycopg2 driver suffix)
_OWNER_DSN = f"postgresql://safenestt_owner_test:{_OWNER_PASS}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
_APP_DSN = f"postgresql://safenestt_app:{_APP_PASS}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"

# Assert the isolation guard on the SQLAlchemy URLs
isolation_guard.assert_test_dsn(_OWNER_URL, caller="test_graph_security._OWNER_URL")
isolation_guard.assert_test_dsn(_APP_URL, caller="test_graph_security._APP_URL")
isolation_guard.assert_test_dsn(_OWNER_DSN, caller="test_graph_security._OWNER_DSN")
isolation_guard.assert_test_dsn(_APP_DSN, caller="test_graph_security._APP_DSN")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fp(raw_key: str) -> str:
    """SHA-256 fingerprint matching the application's key hashing."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _make_app_session():
    """Create a new session connected as safenestt_app (single connection, no pooling).
    
    RLS tenant context is bound to session-scoped GUC app.current_tenant (set
    via set_config(..., false) in establish_tenant_context). StaticPool reuses
    a single connection so tenant context persists across tests.

    NOTE: No checkin listener is registered. The tenant GUC is session-scoped
    (set_config(..., false) = persist for the whole session), so it survives
    commits and pool checkin cycles. A checkin RESET listener would wipe the
    GUC immediately after establish_tenant() commits, making every subsequent
    RLS-protected statement see an empty tenant (the 20-failure regression).
    """
    from sqlalchemy.pool import StaticPool
    from sqlalchemy import create_engine
    engine = create_engine(_APP_URL, poolclass=StaticPool)
    Session = sessionmaker(bind=engine)
    return Session(), engine


def establish_tenant(session, tenant_id: str, raw_key: str):
    """Call establish_tenant_context() with a tenant_id and raw key.
    
    The server-side function verifies the fingerprint matches an active key.
    
    NOTE: commits the transaction so the tenant context is visible to the
    RLS policies on subsequent statements.
    """
    fp = _fp(raw_key)
    session.execute(
        text("SELECT establish_tenant_context(:tid, :fp)"),
        {"tid": tenant_id, "fp": fp},
    )
    session.commit()


# ---------------------------------------------------------------------------
# Fixture: fresh tables + api_keys
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db():
    """Drop and recreate tables; seed api_keys for tenant context.

    Matches test_persistence.py: only drops main tables (not _tenant_context
    or the SECURITY DEFINER functions — those persist).
    """
    # Drop only main tables — preserve _tenant_context and functions
    conn = psycopg2.connect(_OWNER_DSN)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(
        "DROP TABLE IF EXISTS "
        "graph_edges, graph_nodes, reports, evidence, findings, "
        "agent_runs, investigations, api_key_audit, api_keys, "
        "audit_events CASCADE"
    )
    cur.close()
    conn.close()

    # Create tables
    owner_engine = create_engine(_OWNER_URL)
    Base.metadata.create_all(owner_engine)

    # Apply RLS policies (existing function from rls.py)
    apply_rls_policies(owner_engine)

    # Create _tenant_context table (needed by establish_tenant_context function)
    # This table is NOT in Base.metadata — created by migrate.py only
    conn = psycopg2.connect(_OWNER_DSN)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS _tenant_context (
            backend_pid integer NOT NULL,
            tenant_id text NOT NULL,
            key_fingerprint text NOT NULL,
            established_at timestamp without time zone DEFAULT NOW(),
            expires_at timestamp without time zone NOT NULL,
            PRIMARY KEY (backend_pid)
        );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tenant_context_expires ON _tenant_context (expires_at)")
    cur.execute("REVOKE ALL ON _tenant_context FROM safenestt_app")
    cur.execute("REVOKE ALL ON _tenant_context FROM PUBLIC")
    cur.close()
    conn.close()

    # Grant privileges to safenestt_app
    conn2 = psycopg2.connect(_OWNER_DSN)
    conn2.autocommit = True
    cur2 = conn2.cursor()
    cur2.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        "TO safenestt_app"
    )
    cur2.execute(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app"
    )
    cur2.close()
    conn2.close()

    # Seed api_keys for test tenants
    app_engine = create_engine(_APP_URL)
    Session = sessionmaker(bind=app_engine)
    session = Session()
    try:
        for tenant_id in ["ten-edge-1", "ten-edge-2", "ten-edge-3"]:
            raw_key = f"test-key-for-{tenant_id}"
            fp = _fp(raw_key)
            h = hashlib.sha256(raw_key.encode()).hexdigest()
            session.execute(
                text(
                    "INSERT INTO api_keys "
                    "(key_hash, key_fingerprint, name, tenant_id, active, "
                    "scopes, created_at, last_used_at, use_count, "
                    "expires_at, revoked, revoked_at) "
                    "VALUES "
                    "(:kh, :fp, :name, :tid, true, '{}', now(), NULL, 0, "
                    "NULL, false, NULL)"
                ),
                {
                    "kh": h,
                    "fp": fp,
                    "name": f"RLS Edge Test Key ({tenant_id})",
                    "tid": tenant_id,
                },
            )
        session.commit()
    finally:
        session.close()

    yield _APP_URL


# ===========================================================================
# TEST SUITE
# ===========================================================================


class TestGraphNodeRLS:
    """Verify RLS blocks all operations across tenants on graph_nodes."""

    def test_select_cross_tenant_blocked(self):
        """Tenant A cannot SELECT graph_nodes belonging to Tenant B."""
        raw1 = "test-key-for-ten-edge-1"
        raw2 = "test-key-for-ten-edge-2"
        raw2 = "test-key-for-ten-edge-2"

        s1, eng1 = _make_app_session()
        try:
            establish_tenant(s1, "ten-edge-1", raw1)
            s1.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-1', 'case-cross-1', 'ten-edge-1', 'running', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-1', 'case-cross-1', 'gn-cross-1', 'entity', 'cross tenant node', "
                     "'{}', 'test', 'test', now(), now())")
            )
            s1.commit()
        finally:
            s1.close()
            eng1.dispose()

        # Tenant 2 tries to SELECT — blocked by RLS
        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-2", raw2)
            result = s2.execute(
                text("SELECT COUNT(*) FROM graph_nodes WHERE node_key = 'gn-cross-1'")
            )
            count = result.scalar()
            assert count == 0, (
                f"RLS FAILED: cross-tenant SELECT returned {count} rows, expected 0"
            )
        finally:
            s2.close()
            eng2.dispose()

    def test_insert_cross_tenant_blocked(self):
        """Tenant A cannot INSERT graph_nodes for Tenant B's investigation."""
        raw1 = "test-key-for-ten-edge-1"
        raw2 = "test-key-for-ten-edge-2"

        # Tenant 2 creates the investigation (tenant context must match)
        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-2", raw2)
            s2.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-2', 'case-cross-2', 'ten-edge-2', 'running', now(), now())")
            )
            s2.commit()
        finally:
            s2.close()
            eng2.dispose()

        # Tenant 1 tries to insert in tenant 2's investigation
        s3, eng3 = _make_app_session()
        try:
            establish_tenant(s3, "ten-edge-1", raw1)
            try:
                s3.execute(
                    text("INSERT INTO graph_nodes "
                         "(investigation_id, case_id, node_key, node_type, node_label, "
                         "node_data, source, provenance, created_at, updated_at) "
                         "VALUES "
                         "('inv-cross-2', 'case-cross-2', 'gn-cross-2', 'entity', 'cross tenant insert', "
                         "'{}', 'test', 'test', now(), now())")
                )
                s3.commit()
                assert False, "RLS FAILED: cross-tenant INSERT should have been blocked"
            except Exception as exc:
                exc_str = str(exc).lower()
                assert any(w in exc_str for w in ("permission", "violates", "denied", "policy")), (
                    f"Unexpected error: {exc}"
                )
        finally:
            s3.close()
            eng3.dispose()

    def test_update_cross_tenant_blocked(self):
        """Tenant A cannot UPDATE graph_nodes belonging to Tenant B."""
        raw2 = "test-key-for-ten-edge-2"

        s1, eng1 = _make_app_session()
        try:
            establish_tenant(s1, "ten-edge-2", raw2)
            s1.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-3', 'case-cross-3', 'ten-edge-2', 'running', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-3', 'case-cross-3', 'gn-cross-3', 'entity', 'protected node', "
                     "'{}', 'test', 'test', now(), now())")
            )
            s1.commit()
        finally:
            s1.close()
            eng1.dispose()

        # Tenant 1 tries to UPDATE — blocked by RLS. verify 0 rows affected
        # (RLS denies cross-tenant rows without raising an error).
        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-1", "test-key-for-ten-edge-1")
            try:
                s2.execute(
                    text(
                        "UPDATE graph_nodes "
                        "SET node_label = 'tampered by tenant 1' "
                        "WHERE investigation_id = 'inv-cross-3' AND node_key = 'gn-cross-3'"
                    )
                )
                s2.commit()
                # RLS blocks cross-tenant UPDATEs by matching no rows
                assert s2.execute(
                    text("SELECT COUNT(*) FROM graph_nodes WHERE investigation_id = 'inv-cross-3' AND node_key = 'gn-cross-3'")
                ).scalar() == 0, "RLS FAILED: cross-tenant UPDATE should have been blocked"
            except Exception as exc:
                exc_str = str(exc).lower()
                assert any(w in exc_str for w in ("permission", "violates", "denied", "policy")), (
                    f"Unexpected error: {exc}"
                )
        finally:
            s2.close()
            eng2.dispose()

    def test_delete_cross_tenant_blocked(self):
        """Tenant A cannot DELETE graph_nodes belonging to Tenant B."""
        raw2 = "test-key-for-ten-edge-2"

        s1, eng1 = _make_app_session()
        try:
            establish_tenant(s1, "ten-edge-2", raw2)
            s1.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-4', 'case-cross-4', 'ten-edge-2', 'running', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-cross-4', 'case-cross-4', 'gn-cross-4', 'entity', 'must survive', "
                     "'{}', 'test', 'test', now(), now())")
            )
            s1.commit()
        finally:
            s1.close()
            eng1.dispose()

        # Tenant 1 tries to DELETE — blocked by RLS. verify 0 rows affected
        # (RLS denies cross-tenant rows without raising an error).
        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-1", "test-key-for-ten-edge-1")
            try:
                s2.execute(
                    text(
                        "DELETE FROM graph_nodes "
                        "WHERE investigation_id = 'inv-cross-4' AND node_key = 'gn-cross-4'"
                    )
                )
                s2.commit()
                # RLS blocks cross-tenant DELETEs by matching no rows
                cnt = s2.execute(
                    text(
                        "SELECT COUNT(*) FROM graph_nodes WHERE investigation_id = 'inv-cross-4' AND node_key = 'gn-cross-4'"
                    )
                ).scalar()
                assert cnt == 0, "RLS FAILED: cross-tenant DELETE should have been blocked"
            except Exception as exc:
                exc_str = str(exc).lower()
                assert any(w in exc_str for w in ("permission", "violates", "denied", "policy")), (
                    f"Unexpected error: {exc}"
                )
        finally:
            s2.close()
            eng2.dispose()

        # Verify node still exists
        s3, eng3 = _make_app_session()
        try:
            establish_tenant(s3, "ten-edge-2", raw2)
            cnt = s3.execute(
                text("SELECT COUNT(*) FROM graph_nodes WHERE node_key = 'gn-cross-4'")
            ).scalar()
            assert cnt == 1, "Node should still exist after blocked DELETE"
        finally:
            s3.close()
            eng3.dispose()


class TestGraphEdgeRLS:
    """Verify RLS blocks all operations across tenants on graph_edges."""

    def test_select_cross_tenant_blocked(self):
        """Tenant A cannot SELECT graph_edges belonging to Tenant B."""
        raw2 = "test-key-for-ten-edge-2"

        s1, eng1 = _make_app_session()
        try:
            establish_tenant(s1, "ten-edge-2", raw2)
            s1.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-e-cross', 'case-e-cross', 'ten-edge-2', 'running', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-e-cross', 'case-e-cross', 'src-e-cross', 'entity', 'src', "
                     "'{}', 'test', 'test', now(), now()), "
                     "('inv-e-cross', 'case-e-cross', 'tgt-e-cross', 'evidence', 'tgt', "
                     "'{}', 'test', 'test', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_edges "
                     "(investigation_id, case_id, edge_key, source_node_id, "
                     "target_node_id, edge_type, edge_label, edge_data, "
                     "source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-e-cross', 'case-e-cross', 'ge-cross-e', 'src-e-cross', 'tgt-e-cross', 'about', "
                     "'test-label', '{}', 'test', 'test', now(), now())")
            )
            s1.commit()
        finally:
            s1.close()
            eng1.dispose()

        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-1", "test-key-for-ten-edge-1")
            result = s2.execute(
                text("SELECT COUNT(*) FROM graph_edges WHERE edge_key = 'ge-cross-e'")
            )
            count = result.scalar()
            assert count == 0, (
                f"RLS FAILED: cross-tenant SELECT on graph_edges returned {count}, expected 0"
            )
        finally:
            s2.close()
            eng2.dispose()

    def test_insert_cross_tenant_blocked(self):
        """Tenant A cannot INSERT graph_edges for Tenant B's investigation."""
        raw2 = "test-key-for-ten-edge-2"

        s1, eng1 = _make_app_session()
        try:
            establish_tenant(s1, "ten-edge-2", raw2)
            s1.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "('inv-f-cross', 'case-f-cross', 'ten-edge-2', 'running', now(), now())")
            )
            s1.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "('inv-f-cross', 'case-f-cross', 'src-f-cross', 'entity', 'src', "
                     "'{}', 'test', 'test', now(), now()), "
                     "('inv-f-cross', 'case-f-cross', 'tgt-f-cross', 'evidence', 'tgt', "
                     "'{}', 'test', 'test', now(), now())")
            )
            s1.commit()
        finally:
            s1.close()
            eng1.dispose()

        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-1", "test-key-for-ten-edge-1")
            try:
                s2.execute(
                    text("INSERT INTO graph_edges "
                         "(investigation_id, case_id, edge_key, source_node_id, "
                         "target_node_id, edge_type, edge_label, edge_data, "
                         "source, provenance, created_at, updated_at) "
                         "VALUES "
                         "('inv-f-cross', 'case-f-cross', 'ge-cross-f', 'src-f-cross', 'tgt-f-cross', "
                         "'about', null, '{}', 'test', 'test', now(), now())")
                )
                s2.commit()
                assert False, "RLS FAILED: cross-tenant graph_edges INSERT should have been blocked"
            except Exception as exc:
                exc_str = str(exc).lower()
                assert any(w in exc_str for w in ("permission", "violates", "denied", "policy")), (
                    f"Unexpected error: {exc}"
                )
        finally:
            s2.close()
            eng2.dispose()


class TestSameInvestigationEdgeValidation:
    """Verify add_graph_edge rejects cross-investigation edges at app level."""

    def test_valid_same_investigation_edge(self):
        """Edge within same investigation: PASS."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-valid-{uuid.uuid4().hex[:8]}"
        n1 = f"gn-valid-s-{uuid.uuid4().hex[:8]}"
        n2 = f"gn-valid-t-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-valid', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-valid', :n1, 'entity', 'node1', "
                     "'{}', 'test', 'test', now(), now()), "
                     "(:inv, 'case-valid', :n2, 'evidence', 'node2', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "n1": n1, "n2": n2},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_id,
                "case_id": "case-valid",
                "edge_key": "valid-edge",
                "source_node_id": n1,
                "target_node_id": n2,
                "edge_type": "about",
                "edge_label": "links",
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            store.add_graph_edge(edge)
            s.commit()

            result = s.execute(
                text("SELECT COUNT(*) FROM graph_edges WHERE edge_key = 'valid-edge'")
            )
            assert result.scalar() == 1, "Valid same-investigation edge should be inserted"
        finally:
            s.close()
            eng.dispose()

    def test_cross_investigation_source_rejected(self):
        """Source node from investigation A + edge for investigation B: REJECT."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_a = f"inv-xs-{uuid.uuid4().hex[:8]}"
        inv_b = f"inv-ys-{uuid.uuid4().hex[:8]}"
        node_a = f"gn-xs-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xs', 'ten-edge-1', 'running', now(), now()), "
                     "(:ib, 'case-ys', 'ten-edge-1', 'running', now(), now())"),
                {"ia": inv_a, "ib": inv_b},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xs', :na, 'entity', 'src_a', "
                     "'{}', 'test', 'test', now(), now())"),
                {"ia": inv_a, "na": node_a},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_b,
                "case_id": "case-ys",
                "edge_key": "cross-src-edge",
                "source_node_id": node_a,
                "target_node_id": "nonexistent",
                "edge_type": "about",
                "edge_label": None,
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            with pytest.raises(ValueError, match="belongs to investigation"):
                store.add_graph_edge(edge)
        finally:
            s.close()
            eng.dispose()

    def test_cross_investigation_target_rejected(self):
        """Target node from investigation A + edge for investigation B: REJECT."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_a = f"inv-xt-{uuid.uuid4().hex[:8]}"
        inv_b = f"inv-yt-{uuid.uuid4().hex[:8]}"
        node_a = f"gn-xt-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xt', 'ten-edge-1', 'running', now(), now()), "
                     "(:ib, 'case-yt', 'ten-edge-1', 'running', now(), now())"),
                {"ia": inv_a, "ib": inv_b},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xt', :na, 'evidence', 'tgt_a', "
                     "'{}', 'test', 'test', now(), now())"),
                {"ia": inv_a, "na": node_a},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_b,
                "case_id": "case-yt",
                "edge_key": "cross-tgt-edge",
                "source_node_id": "nonexistent",
                "target_node_id": node_a,
                "edge_type": "about",
                "edge_label": None,
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            with pytest.raises(ValueError, match="Source node not found: nonexistent"):
                store.add_graph_edge(edge)
        finally:
            s.close()
            eng.dispose()

    def test_both_nodes_cross_investigation_rejected(self):
        """Both nodes from investigation A + edge for investigation B: REJECT."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_a = f"inv-xb-{uuid.uuid4().hex[:8]}"
        inv_b = f"inv-yb-{uuid.uuid4().hex[:8]}"
        node_a1 = f"gn-xb1-{uuid.uuid4().hex[:8]}"
        node_a2 = f"gn-xb2-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xb', 'ten-edge-1', 'running', now(), now()), "
                     "(:ib, 'case-yb', 'ten-edge-1', 'running', now(), now())"),
                {"ia": inv_a, "ib": inv_b},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-xb', :n1, 'entity', 'n1', "
                     "'{}', 'test', 'test', now(), now()), "
                     "(:ia, 'case-xb', :n2, 'evidence', 'n2', "
                     "'{}', 'test', 'test', now(), now())"),
                {"ia": inv_a, "n1": node_a1, "n2": node_a2},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_b,
                "case_id": "case-yb",
                "edge_key": "cross-both-edge",
                "source_node_id": node_a1,
                "target_node_id": node_a2,
                "edge_type": "about",
                "edge_label": None,
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            with pytest.raises(ValueError):
                store.add_graph_edge(edge)
        finally:
            s.close()
            eng.dispose()

    def test_nonexistent_source_rejected(self):
        """Nonexistent source node: REJECT."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-ns-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-ns', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_id,
                "case_id": "case-ns",
                "edge_key": "no-src-edge",
                "source_node_id": "does-not-exist-at-all",
                "target_node_id": "also-does-not-exist",
                "edge_type": "about",
                "edge_label": None,
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            with pytest.raises(ValueError, match="Source node not found: does-not-exist-at-all"):
                store.add_graph_edge(edge)
        finally:
            s.close()
            eng.dispose()

    def test_nonexistent_target_rejected(self):
        """Nonexistent target node: REJECT."""
        from safenestt.investigations.store import PersistentInvestigationStore

        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-nt-{uuid.uuid4().hex[:8]}"
        node_exists = f"gn-nt-exists-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-nt', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-nt', :n, 'entity', 'exists', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "n": node_exists},
            )
            s.commit()

            store = PersistentInvestigationStore(tenant_id="ten-edge-1", key_fingerprint=_fp(raw1))
            edge = type("Edge", (), {
                "investigation_id": inv_id,
                "case_id": "case-nt",
                "edge_key": "no-tgt-edge",
                "source_node_id": node_exists,
                "target_node_id": "does-not-exist-either",
                "edge_type": "about",
                "edge_label": None,
                "edge_data": None,
                "source": "test",
                "provenance": "test",
            })()
            store._session = lambda: s
            with pytest.raises(ValueError, match="Target node not found: does-not-exist-either"):
                store.add_graph_edge(edge)
        finally:
            s.close()
            eng.dispose()


class TestCompositeFKValidation:
    """Validate composite FK design before migration applies it."""

    def test_node_key_equals_id_by_default(self):
        """Verify that when store creates a node, node_key equals the generated id.

        The store uses node_key = edge.node_key or the generated id.
        For edges created via add_graph_edge, source_node_id = edge.source_node_id
        which must match an existing node_key in graph_nodes.

        If node_key is the generated SERIAL id, then a composite FK on
        (investigation_id, node_key) references the primary key — valid SQL.
        """
        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-fk-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-fk', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-fk', 'app-stable-key-1', 'entity', 'test', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id},
            )
            s.commit()

            result = s.execute(
                text("SELECT id, node_key FROM graph_nodes WHERE node_key = 'app-stable-key-1'")
            )
            row = result.fetchone()
            assert row is not None, "Node should exist"
            # node_key is application-provided, id is SERIAL PK — they can differ.
            # Composite FK (investigation_id, node_key) references UNIQUE(investigation_id, node_key)
            # which already exists on graph_nodes. Valid SQL.
        finally:
            s.close()
            eng.dispose()

    def test_composite_fk_would_work_with_current_edges(self):
        """Verify that if we applied the composite FK now, existing same-investigation
        edges would pass the FK check."""
        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-fk2-{uuid.uuid4().hex[:8]}"
        n1 = f"gn-fk2-s-{uuid.uuid4().hex[:8]}"
        n2 = f"gn-fk2-t-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-fk2', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-fk2', :n1, 'entity', 'n1', "
                     "'{}', 'test', 'test', now(), now()), "
                     "(:inv, 'case-fk2', :n2, 'evidence', 'n2', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "n1": n1, "n2": n2},
            )
            s.execute(
                text("INSERT INTO graph_edges "
                     "(investigation_id, case_id, edge_key, source_node_id, "
                     "target_node_id, edge_type, edge_label, edge_data, "
                     "source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-fk2', 'ge-fk2', :n1, :n2, 'about', "
                     "'test-label', '{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "n1": n1, "n2": n2},
            )
            s.commit()

            result = s.execute(
                text("SELECT COUNT(*) FROM graph_nodes "
                     "WHERE investigation_id = :inv "
                     "AND node_key IN (:n1, :n2)"),
                {"inv": inv_id, "n1": n1, "n2": n2},
            )
            count = result.scalar()
            assert count == 2, (
                f"Composite FK check simulation: only {count}/2 nodes found "
                "in graph_nodes with matching (investigation_id, node_key)"
            )
        finally:
            s.close()
            eng.dispose()

    def test_composite_fk_would_block_cross_investigation_edge(self):
        """Verify that the composite FK would reject an edge where source node
        belongs to a different investigation."""
        raw1 = "test-key-for-ten-edge-1"
        inv_a = f"inv-fk3a-{uuid.uuid4().hex[:8]}"
        inv_b = f"inv-fk3b-{uuid.uuid4().hex[:8]}"
        node_in_a = f"gn-fk3a-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-fk3a', 'ten-edge-1', 'running', now(), now()), "
                     "(:ib, 'case-fk3b', 'ten-edge-1', 'running', now(), now())"),
                {"ia": inv_a, "ib": inv_b},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:ia, 'case-fk3a', :node, 'entity', 'in_a', "
                     "'{}', 'test', 'test', now(), now())"),
                {"ia": inv_a, "node": node_in_a},
            )
            s.commit()

            # Simulate FK check
            result = s.execute(
                text("SELECT COUNT(*) FROM graph_nodes "
                     "WHERE investigation_id = :inv_b "
                     "AND node_key = :node_key"),
                {"inv_b": inv_b, "node_key": node_in_a},
            )
            count = result.scalar()
            assert count == 0, (
                "Node exists but under DIFFERENT investigation_id. "
                "Composite FK (investigation_id, source_node_id) REFERENCES "
                "(investigation_id, node_key) would correctly REJECT this edge."
            )
        finally:
            s.close()
            eng.dispose()


class TestTenantMappingCaseId:
    """Verify case_id semantics and tenant mapping."""

    def test_case_id_is_base44_case_id_not_investigation_id(self):
        """Confirm case_id stores the originating Base44 case ID, not investigation_id."""
        raw1 = "test-key-for-ten-edge-1"
        base44_case_id = "bc-12345"
        investigation_id = f"inv-caseid-{uuid.uuid4().hex[:12]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:iid, :cid, 'ten-edge-1', 'running', now(), now())"),
                {"iid": investigation_id, "cid": base44_case_id},
            )
            s.commit()

            result = s.execute(
                text("SELECT investigation_id, case_id FROM investigations "
                     "WHERE investigation_id = :iid"),
                {"iid": investigation_id},
            )
            row = result.fetchone()
            assert row is not None
            assert row.case_id == base44_case_id, (
                f"case_id should be '{base44_case_id}' (Base44 case ID), "
                f"not investigation_id '{investigation_id}'"
            )
            assert row.investigation_id == investigation_id
            assert row.case_id != row.investigation_id, (
                "case_id MUST NOT equal investigation_id"
            )
        finally:
            s.close()
            eng.dispose()

    def test_tenant_mapping_is_via_api_key_not_cases_table(self):
        """Verify tenant_id comes from api_keys, not from cases table."""
        raw1 = "test-key-for-ten-edge-1"

        s, eng = _make_app_session()
        try:
            # Check that cases table does not exist
            cur = s.connection().connection.cursor()
            cur.execute(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='cases')"
            )
            cases_exists = cur.fetchone()[0]
            assert not cases_exists, "cases table should not exist"

            establish_tenant(s, "ten-edge-1", raw1)
            result = s.execute(text("SELECT get_current_tenant() AS tenant"))
            tenant = result.scalar()
            assert tenant == "ten-edge-1", (
                f"Expected 'ten-edge-1' from api_keys, got '{tenant}'"
            )

            # Verify tenant comes from api_keys
            result2 = s.execute(
                text("SELECT tenant_id FROM api_keys "
                     "WHERE key_fingerprint = :fp"),
                {"fp": _fp(raw1)},
            )
            owner = result2.scalar()
            assert owner == "ten-edge-1"
        finally:
            s.close()
            eng.dispose()

    def test_graph_nodes_use_correct_case_id(self):
        """Verify graph_nodes.case_id stores the Base44 case ID."""
        raw1 = "test-key-for-ten-edge-1"
        base44_case = "bc-99999"
        inv_id = f"inv-graphcase-{uuid.uuid4().hex[:8]}"
        node_key = f"gn-graphcase-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, :bc, 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id, "bc": base44_case},
            )
            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, :bc, :nk, 'entity', 'test', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "bc": base44_case, "nk": node_key},
            )
            s.commit()

            result = s.execute(
                text("SELECT investigation_id, case_id, node_key "
                     "FROM graph_nodes WHERE node_key = :nk"),
                {"nk": node_key},
            )
            row = result.fetchone()
            assert row is not None
            assert row.case_id == base44_case, (
                f"graph_nodes.case_id should be '{base44_case}', got '{row.case_id}'"
            )
            assert row.investigation_id == inv_id
            assert row.case_id != row.investigation_id
        finally:
            s.close()
            eng.dispose()


class TestForceRowSecurityDoesNotBreakAppWrites:
    """Verify FORCE ROW LEVEL SECURITY does not break legitimate app writes."""

    def test_safenestt_app_is_not_superuser(self):
        """Confirm safenestt_app does not have SUPERUSER, so RLS applies to it."""
        s, eng = _make_app_session()
        try:
            result = s.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = 'safenestt_app'")
            )
            superuser = result.scalar()
            assert superuser is not True, (
                "safenestt_app should NOT be superuser, so RLS will apply to it"
            )
        finally:
            s.close()
            eng.dispose()

    def test_app_session_connects_as_safenestt_app(self):
        """Verify the test session connects as safenestt_app."""
        s, eng = _make_app_session()
        try:
            result = s.execute(text("SELECT current_user"))
            user = result.scalar()
            assert user == "safenestt_app", (
                f"Expected safenestt_app, got {user}. "
                "RLS policies apply to non-superuser roles."
            )
        finally:
            s.close()
            eng.dispose()

    def test_force_rls_allows_legitimate_inserts(self):
        """Once FORCE ROW LEVEL SECURITY is on, the app can still insert
        graph_nodes in its own tenant's investigation."""
        raw1 = "test-key-for-ten-edge-1"
        inv_id = f"inv-force-{uuid.uuid4().hex[:8]}"
        nkey = f"gn-force-{uuid.uuid4().hex[:8]}"

        s, eng = _make_app_session()
        try:
            establish_tenant(s, "ten-edge-1", raw1)
            s.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-force', 'ten-edge-1', 'running', now(), now())"),
                {"inv": inv_id},
            )
            s.commit()

            s.execute(
                text("INSERT INTO graph_nodes "
                     "(investigation_id, case_id, node_key, node_type, node_label, "
                     "node_data, source, provenance, created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-force', :nk, 'entity', 'legit', "
                     "'{}', 'test', 'test', now(), now())"),
                {"inv": inv_id, "nk": nkey},
            )
            s.commit()

            result = s.execute(
                text("SELECT COUNT(*) FROM graph_nodes "
                     "WHERE investigation_id = :inv AND node_key = :nk"),
                {"inv": inv_id, "nk": nkey},
            )
            count = result.scalar()
            assert count == 1, (
                "Legitimate insert within tenant's investigation should succeed "
                "even with FORCE ROW LEVEL SECURITY enabled"
            )
        finally:
            s.close()
            eng.dispose()

    def test_force_rls_blocks_inserts_in_wrong_tenant(self):
        """Even if the app tries to insert a graph_node in another tenant's
        investigation, FORCE RLS blocks it (defense-in-depth).

        Creates the target investigation as tenant 2, then tenant 1 tries
        to insert a graph_node into it — should be blocked by RLS.
        """
        raw1 = "test-key-for-ten-edge-1"
        raw2 = "test-key-for-ten-edge-2"
        inv_other = f"inv-force-other-{uuid.uuid4().hex[:8]}"

        # Create the investigation as tenant 2 (using owner connection)
        s_owner, eng_owner = _make_app_session()
        try:
            establish_tenant(s_owner, "ten-edge-2", raw2)
            s_owner.execute(
                text("INSERT INTO investigations "
                     "(investigation_id, case_id, tenant_id, status, "
                     "created_at, updated_at) "
                     "VALUES "
                     "(:inv, 'case-force-other', 'ten-edge-2', 'running', now(), now())"),
                {"inv": inv_other},
            )
            s_owner.commit()
        finally:
            s_owner.close()
            eng_owner.dispose()

        # Tenant 1 tries to insert a node in tenant 2's investigation
        # RLS should block this because tenant_id='ten-edge-2' != get_current_tenant()='ten-edge-1'
        s2, eng2 = _make_app_session()
        try:
            establish_tenant(s2, "ten-edge-1", raw1)
            try:
                s2.execute(
                    text("INSERT INTO graph_nodes "
                         "(investigation_id, case_id, node_key, node_type, node_label, "
                         "node_data, source, provenance, created_at, updated_at) "
                         "VALUES "
                         "(:inv, 'case-force-other', 'gn-force-blocked', 'entity', 'blocked', "
                         "'{}', 'test', 'test', now(), now())"),
                    {"inv": inv_other},
                )
                s2.commit()
                assert False, "RLS FAILED: insert in wrong tenant should have been blocked"
            except Exception as exc:
                exc_str = str(exc).lower()
                assert any(w in exc_str for w in ("permission", "violates", "denied", "policy")), (
                    f"Unexpected error: {exc}"
                )
        finally:
            s2.close()
            eng2.dispose()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=30"])
