"""NON-DESTRUCTIVE graph RLS security tests.

Covers migration 002_graph_rls_tenant_isolation.sql.

SAFETY
------
These tests never TRUNCATE. They create their own two-tenant fixture
investigation (own unique ids each run) and remove only rows they created.
Existing investigations, their graph rows, reports, evidence, findings,
agent runs, and every api_keys row are left untouched.

Do NOT run the `tests/` suite for this module — its autouse TRUNCATE-ALL
fixture would destroy production-adjacent data.
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

import hashlib
import uuid

import psycopg2
import pytest

from sqlalchemy import text

# PORT + ROLE ISOLATION (2026-10-04): both DSNs hardcoded port 54322 — the
# PRODUCTION Postgres port — and the `safenestt_app` role with the production
# password. On the dedicated test instance that combination does not exist, and
# pointing it at production would place this module's INSERT/UPDATE/DELETE
# workload directly on live data.
#
# Host/port/role/password now come from the environment, which conftest and
# scripts/run-tests-isolated.sh populate with the TEST instance's values.
_HOST = os.environ.get("DB_HOST", "127.0.0.1")
_PORT = int(os.environ.get("DB_PORT", "55432"))
_PW = os.environ.get("SAFENESTT_DB_PASSWORD", "safenestt_test_local_only")

APP_DSN = dict(host=_HOST, port=_PORT, user="safenestt_app",
               password=_PW, dbname=os.environ["DB_NAME"], sslmode="disable")
OWNER_DSN = dict(host=_HOST, port=_PORT,
                 user=os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test"),
                 password=_PW, dbname=os.environ["DB_NAME"], sslmode="disable")

RUN = uuid.uuid4().hex[:10]
TENANT_A = f"graphsec-a-{RUN}"
TENANT_B = f"graphsec-b-{RUN}"
INV_A = f"inv-gs-a-{RUN}"
INV_B = f"inv-gs-b-{RUN}"
FP_A = hashlib.sha256(f"k-{RUN}-a".encode()).hexdigest()
FP_B = hashlib.sha256(f"k-{RUN}-b".encode()).hexdigest()
HASH_A = "sha256:" + hashlib.sha256(f"ha-{RUN}-a".encode()).hexdigest()
HASH_B = "sha256:" + hashlib.sha256(f"hb-{RUN}-b".encode()).hexdigest()

NODE_A = f"gn-sec-{RUN}"
NODE_A2 = f"gn-sec2-{RUN}"
EDGE_A = f"ge-sec-{RUN}"


def owner_conn():
    return psycopg2.connect(**OWNER_DSN)


def app_conn():
    """Connection as the NON-SUPERUSER application role."""
    return psycopg2.connect(**APP_DSN)


def set_ctx(conn, tenant, fingerprint):
    with conn.cursor() as cur:
        cur.execute("SELECT establish_tenant_context(%s,%s)", (tenant, fingerprint))


@pytest.fixture(scope="module")
def fixture_graph():
    """Two tenants, each with one investigation; tenant A also gets graph rows."""
    c = owner_conn()
    c.autocommit = False
    cur = c.cursor()
    for fp, kh, ten in ((FP_A, HASH_A, TENANT_A), (FP_B, HASH_B, TENANT_B)):
        cur.execute(
            "INSERT INTO api_keys (key_hash,key_fingerprint,tenant_id,name,active,"
            "revoked,scopes,use_count,created_at) VALUES "
            "(%s,%s,%s,'graph-security-fixture',TRUE,FALSE,'[\"read\",\"write\"]'::json,0,NOW())",
            (kh, fp, ten))
    for inv, ten in ((INV_A, TENANT_A), (INV_B, TENANT_B)):
        cur.execute(
            "INSERT INTO investigations (investigation_id,tenant_id,target,type,status,"
            "created_at,updated_at) VALUES (%s,%s,'example.com','web','COMPLETED',NOW(),NOW())",
            (inv, ten))
    ts = "NOW()"
    cur.execute(f"""
        INSERT INTO graph_nodes (investigation_id,case_id,node_key,node_type,node_label,
                                 node_data,source,provenance,created_at,updated_at)
        VALUES (%s,'case-a',%s,'evidence','n1','{{}}'::json,'test','graphsec',{ts},{ts}),
               (%s,'case-a',%s,'evidence','n2','{{}}'::json,'test','graphsec',{ts},{ts})
    """, (INV_A, NODE_A, INV_A, NODE_A2))
    cur.execute(f"""
        INSERT INTO graph_edges (investigation_id,case_id,edge_key,source_node_id,
                                 target_node_id,edge_type,edge_label,edge_data,source,
                                 provenance,created_at,updated_at)
        VALUES (%s,'case-a',%s,%s,%s,'supported_by','e','{{}}'::json,'test','graphsec',{ts},{ts})
    """, (INV_A, EDGE_A, NODE_A, NODE_A2))
    c.commit()

    yield {"node_a": NODE_A, "node_a2": NODE_A2, "edge_a": EDGE_A}

    # Clean up ONLY what this fixture created.
    cur.execute("DELETE FROM graph_edges WHERE edge_key=%s", (EDGE_A,))
    cur.execute("DELETE FROM graph_nodes WHERE node_key IN (%s,%s)", (NODE_A, NODE_A2))
    cur.execute("DELETE FROM investigations WHERE investigation_id IN (%s,%s)", (INV_A, INV_B))
    cur.execute("DELETE FROM api_keys WHERE key_fingerprint IN (%s,%s)", (FP_A, FP_B))
    c.commit()
    cur.close()
    c.close()


# ---------------------------------------------------------------------
# SELECT
# ---------------------------------------------------------------------

def test_same_tenant_select_allowed(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_A, FP_A)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 2
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 1
    c.close()


def test_foreign_tenant_select_denied(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 0, "foreign tenant saw graph_nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 0, "foreign tenant saw graph_edges"
    c.close()


def test_missing_tenant_context_sees_nothing(fixture_graph):
    """No establish_tenant_context call at all -> fail closed."""
    c = app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 0, "no-context connection saw graph_nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 0, "no-context connection saw graph_edges"
    c.close()


def test_empty_tenant_context_string_is_fail_closed(fixture_graph):
    c = app_conn()
    with c.cursor() as cur:
        cur.execute("SET app.current_tenant_id = ''")
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (INV_A,))
        assert cur.fetchone()[0] == 0
    c.close()


# ---------------------------------------------------------------------
# INSERT
# ---------------------------------------------------------------------

def test_same_tenant_insert_allowed(fixture_graph):
    key = f"gn-ins-{uuid.uuid4().hex[:10]}"
    c = app_conn(); set_ctx(c, TENANT_A, FP_A)
    with c.cursor() as cur:
        cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
            node_type,node_label,node_data,source,provenance,created_at,updated_at)
            VALUES (%s,'case-a',%s,'entity','ok','{}'::json,'test','sec',NOW(),NOW())""",
                    (INV_A, key))
        cur.execute("SELECT count(*) FROM graph_nodes WHERE node_key=%s", (key,))
        assert cur.fetchone()[0] == 1
    c.close()
    _owner_cleanup_nodes([key])


def test_foreign_tenant_insert_denied(fixture_graph):
    key = f"gn-bad-{uuid.uuid4().hex[:10]}"
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
                node_type,node_label,node_data,source,provenance,created_at,updated_at)
                VALUES (%s,'case-a',%s,'entity','x','{}'::json,'test','sec',NOW(),NOW())""",
                        (INV_A, key))
    c.rollback(); c.close()
    assert _owner_count_nodes(key) == 0, "denied INSERT still landed a row"


def test_missing_context_insert_denied(fixture_graph):
    key = f"gn-noctx-{uuid.uuid4().hex[:10]}"
    c = app_conn()
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
                node_type,node_label,node_data,source,provenance,created_at,updated_at)
                VALUES (%s,'case-a',%s,'entity','x','{}'::json,'test','sec',NOW(),NOW())""",
                        (INV_A, key))
    c.rollback(); c.close()
    assert _owner_count_nodes(key) == 0


# ---------------------------------------------------------------------
# UPDATE
# ---------------------------------------------------------------------

def test_same_tenant_update_allowed(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_A, FP_A)
    with c.cursor() as cur:
        cur.execute("UPDATE graph_nodes SET node_label='mutated' WHERE node_key=%s",
                    (NODE_A,))
        assert cur.rowcount == 1
        cur.execute("SELECT node_label FROM graph_nodes WHERE node_key=%s", (NODE_A,))
        assert cur.fetchone()[0] == "mutated"
    c.commit(); c.close()
    _owner_restore_label(NODE_A, "n1")


def test_foreign_tenant_update_denied(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with c.cursor() as cur:
        cur.execute("UPDATE graph_nodes SET node_label='hijacked' WHERE node_key=%s",
                    (NODE_A,))
        assert cur.rowcount == 0, "foreign tenant updated a graph node"
    c.commit(); c.close()
    assert _owner_label(NODE_A) == "n1", "label was changed despite 0 rows"


# ---------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------

def test_same_tenant_delete_allowed(fixture_graph):
    key = f"gn-del-{uuid.uuid4().hex[:10]}"
    c = app_conn(); set_ctx(c, TENANT_A, FP_A)
    with c.cursor() as cur:
        cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
            node_type,node_label,node_data,source,provenance,created_at,updated_at)
            VALUES (%s,'case-a',%s,'entity','todel','{}'::json,'test','sec',NOW(),NOW())""",
                    (INV_A, key))
        cur.execute("DELETE FROM graph_nodes WHERE node_key=%s", (key,))
        assert cur.rowcount == 1
    c.commit(); c.close()
    assert _owner_count_nodes(key) == 0


def test_foreign_tenant_delete_denied(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with c.cursor() as cur:
        cur.execute("DELETE FROM graph_nodes WHERE node_key=%s", (NODE_A,))
        assert cur.rowcount == 0, "foreign tenant deleted a graph node"
    c.commit(); c.close()
    assert _owner_count_nodes(NODE_A) == 1, "fixture node was destroyed"


# ---------------------------------------------------------------------
# Cross-investigation edge protection
# ---------------------------------------------------------------------

def test_cross_investigation_edge_rejected_by_app_layer(fixture_graph):
    """Application-layer guard in PersistentInvestigationStore.add_graph_edge."""
    from safenestt.bridge.transformation import GraphEdgeRecord
    from safenestt.investigations.store import (
        PersistentInvestigationStore, TenantIsolationError)

    oc = owner_conn()
    with oc.cursor() as cur:
        cur.execute("SELECT establish_tenant_context(%s,%s)", (TENANT_A, FP_A))
    store = PersistentInvestigationStore(tenant_id=TENANT_A, key_fingerprint=FP_A)
    with pytest.raises((ValueError, TenantIsolationError)):
        store.add_graph_edge(GraphEdgeRecord(
            id=f"ge-x-{uuid.uuid4().hex[:8]}",
            investigation_id=INV_B,   # node belongs to INV_A
            case_id="case-a", edge_key=f"ge-x-{uuid.uuid4().hex[:8]}",
            source_node_id=NODE_A, target_node_id=NODE_A2,
            edge_type="supported_by", edge_label="", edge_data={},
            source="test", provenance="test"))
    oc.close()


def test_cross_tenant_edge_insert_denied(fixture_graph):
    key = f"ge-bad-{uuid.uuid4().hex[:10]}"
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("""INSERT INTO graph_edges (investigation_id,case_id,edge_key,
                source_node_id,target_node_id,edge_type,edge_label,edge_data,source,
                provenance,created_at,updated_at)
                VALUES (%s,'case-a',%s,%s,%s,'supported_by','x','{}'::json,'test',
                        'sec',NOW(),NOW())""", (INV_A, key, NODE_A, NODE_A2))
    c.rollback(); c.close()
    assert _owner_count_edges(key) == 0


# ---------------------------------------------------------------------
# Owner / superuser behaviour
# ---------------------------------------------------------------------

def test_force_rls_enabled_and_bypassrls_documented():
    """Document the actual owner/superuser behaviour rather than assuming it.

    Findings on this database:
      - `postgres` is NOT a superuser (rolsuper = false).
      - It DOES carry the BYPASSRLS attribute (rolbypassrls = true).
      - It is the owner of graph_nodes / graph_edges.

    FORCE ROW LEVEL SECURITY binds the table OWNER to policy, but it does NOT
    override the BYPASSRLS role attribute. So the owner/service connection
    still reads every graph row regardless of tenant context.

    This is intentional and matches the pre-existing model for every other
    table in this schema (investigations, evidence, findings, reports,
    agent_runs all share it). The control for service-role writes is the
    application layer: PersistentInvestigationStore requires an explicit
    tenant_id + key_fingerprint and derives tenant from the validated API key
    — it never accepts a caller-supplied tenant.
    """
    c = owner_conn()
    with c.cursor() as cur:
        cur.execute("SELECT current_user, usesuper FROM pg_user WHERE usename=current_user")
        user, is_super = cur.fetchone()
        cur.execute("SELECT rolbypassrls FROM pg_roles WHERE rolname=%s", (user,))
        bypass = cur.fetchone()[0]
        cur.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname='graph_nodes'")
        forced_nodes = cur.fetchone()[0]
        cur.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname='graph_edges'")
        forced_edges = cur.fetchone()[0]
        cur.execute("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname='graph_nodes'")
        owner = cur.fetchone()[0]
    c.close()

    assert forced_nodes is True, "FORCE RLS missing on graph_nodes"
    assert forced_edges is True, "FORCE RLS missing on graph_edges"
    assert owner == user
    # Documented, asserted facts about this environment.
    #
    # The test instance is provisioned by scripts/provision-test-app-role.sh to
    # MIRROR production's security posture, because this test exists to pin
    # down production's owner/BYPASSRLS behaviour:
    #     - the owner role is NOT a superuser (rolsuper = false)
    #     - it DOES carry BYPASSRLS (rolbypassrls = true)
    # A stock postgres image creates a SUPERUSER owner, which would make this
    # assertion fail for a reason unrelated to RLS. The provisioning script
    # strips SUPERUSER from the owner role in the test instance and grants
    # BYPASSRLS explicitly, so the documented behaviour is genuinely exercised.
    assert is_super is False, (
        "expected the owner role to be non-superuser; the test instance must be "
        "provisioned by scripts/provision-test-app-role.sh to mirror production "
        "(NOSUPERUSER + BYPASSRLS). Got current_user=%r rolsuper=%r" % (user, is_super)
    )
    assert bypass is True, "expected owner to carry BYPASSRLS (documented bypass)"


def test_app_role_is_bound_by_rls():
    """The application role must have neither superuser nor bypassrls."""
    c = app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
        sup, byp = cur.fetchone()
    c.close()
    assert sup is False and byp is False, \
        "application role must not be able to bypass RLS"


# ---------------------------------------------------------------------
# Existing production E2E rows
# ---------------------------------------------------------------------

E2E_INV = "c4b40fc73ed94f56bd2d4823e3701a34"


def test_existing_e2e_graph_visible_to_correct_tenant():
    c = app_conn()
    set_ctx(c, "safenestt-platform", _fp_for("safenestt-platform"))
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (E2E_INV,))
        assert cur.fetchone()[0] == 21, "correct tenant lost access to E2E graph nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id=%s", (E2E_INV,))
        assert cur.fetchone()[0] == 15, "correct tenant lost access to E2E graph edges"
    c.close()


def test_existing_e2e_graph_hidden_from_foreign_tenant(fixture_graph):
    c = app_conn(); set_ctx(c, TENANT_B, FP_B)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id=%s", (E2E_INV,))
        assert cur.fetchone()[0] == 0, "foreign tenant can see E2E graph nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id=%s", (E2E_INV,))
        assert cur.fetchone()[0] == 0, "foreign tenant can see E2E graph edges"
    c.close()


# ---------------------------------------------------------------------
# owner helpers (used only to assert that a denied write did not land)
# ---------------------------------------------------------------------

def _owner_count_nodes(key):
    c = owner_conn()
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE node_key=%s", (key,))
        n = cur.fetchone()[0]
    c.close()
    return n


def _owner_count_edges(key):
    c = owner_conn()
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_edges WHERE edge_key=%s", (key,))
        n = cur.fetchone()[0]
    c.close()
    return n


def _owner_label(key):
    c = owner_conn()
    with c.cursor() as cur:
        cur.execute("SELECT node_label FROM graph_nodes WHERE node_key=%s", (key,))
        row = cur.fetchone()
    c.close()
    return row[0] if row else None


def _owner_restore_label(key, label):
    c = owner_conn(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute("UPDATE graph_nodes SET node_label=%s WHERE node_key=%s", (label, key))
    c.close()


def _owner_cleanup_nodes(keys):
    c = owner_conn(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute("DELETE FROM graph_nodes WHERE node_key = ANY(%s)", (keys,))
    c.close()


def _fp_for(tenant):
    c = owner_conn()
    with c.cursor() as cur:
        cur.execute("SELECT key_fingerprint FROM api_keys "
                    "WHERE tenant_id=%s AND active AND NOT revoked LIMIT 1", (tenant,))
        row = cur.fetchone()
    c.close()
    if not row:
        pytest.skip(f"no active key for tenant {tenant}")
    return row[0]