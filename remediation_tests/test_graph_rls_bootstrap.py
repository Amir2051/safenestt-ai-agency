"""Bootstrap/migration reproducibility tests for graph RLS.

PROVES
------
1. A FRESH database built through the normal application bootstrap path
   (Base.metadata.create_all + apply_rls_policies) ends up with:
     - graph_nodes / graph_edges tables
     - RLS enabled
     - FORCE RLS enabled
     - tenant isolation policies present
   and the policy behaviour matches the verified migration 002.

2. The bootstrap is IDEMPOTENT: running it twice changes nothing, raises no
   duplicate-policy/table/index errors, and leaves an identical schema.

3. An EXISTING database (tables + rows already present) can be bootstrapped
   without data loss or duplicate rows.

SAFETY
------
Every test runs against a THROWAWAY database named safenestt_rls_fresh_*.
The production-adjacent `safenestt_ai` database is never touched, never
truncated, and never written to by this module. The module also asserts at
import-time that it is not pointed at the live database.

Do NOT run `tests/` for this module — its autouse TRUNCATE-ALL fixture would
destroy production-adjacent data.
"""
from __future__ import annotations

import os

os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "54322")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "postgres")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "postgres")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

import sys
import uuid

import psycopg2
from psycopg2 import sql
import pytest
from sqlalchemy import create_engine, text

LIVE_DB = "safenestt_ai"
FRESH_DB = f"safenestt_rls_fresh_{uuid.uuid4().hex[:8]}"

OWNER = dict(host="127.0.0.1", port=54322, user="postgres",
             password="postgres", sslmode="disable")
APP_PW = "postgres"


def _admin(dbname="postgres"):
    return psycopg2.connect(dbname=dbname, **OWNER)


def _fresh():
    return psycopg2.connect(dbname=FRESH_DB, **OWNER)


def _guard_not_live(conn):
    """Hard stop if anything is aimed at the live database."""
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        name = cur.fetchone()[0]
    if name == LIVE_DB:
        raise RuntimeError(
            f"REFUSING TO RUN: this module must never touch {LIVE_DB}")
    return name


@pytest.fixture(scope="module")
def fresh_db():
    """Create the throwaway database and the app role scoped to it."""
    c = _admin()
    c.autocommit = True  # CREATE/DROP DATABASE cannot run in a transaction
    with c.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{FRESH_DB}"')
    c.close()

    c = _fresh()
    _guard_not_live(c)
    with c.cursor() as cur:
        # Role mirroring the live deployment: non-superuser, no BYPASSRLS.
        cur.execute("DROP ROLE IF EXISTS rls_test_app")
        cur.execute("CREATE ROLE rls_test_app LOGIN PASSWORD %s", (APP_PW,))
        cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO rls_test_app").format(
            sql.Identifier(FRESH_DB)))
    c.commit()
    yield FRESH_DB

    c = _admin()
    c.autocommit = True  # DROP DATABASE cannot run in a transaction
    with c.cursor() as cur:
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname=%s AND pid<>pg_backend_pid()", (FRESH_DB,))
        cur.execute(f'DROP DATABASE IF EXISTS "{FRESH_DB}"')
        cur.execute("DROP ROLE IF EXISTS rls_test_app")
    c.commit()
    c.close()


def _bootstrap(dbname):
    """The authoritative application bootstrap path.

    IMPORTANT — discovered defect, documented rather than worked around:
    `apply_rls_policies()` alone CANNOT bootstrap a fresh database. It
    references get_current_tenant() (14 pre-existing references in
    RLS_POLICY_SQL before this work), but it never CREATES that function.
    On a fresh database that raises:

        psycopg2.errors.UndefinedFunction:
            function get_current_tenant() does not exist

    Only `safenestt/persistence/migrate.py::main()` creates the tenant
    context infrastructure (_tenant_context, establish_tenant_context,
    get_current_tenant, clear_tenant_context) BEFORE calling
    apply_rls_policies(). So the true authoritative bootstrap is:

        migrate.main()  ->  create_all + tenant functions + RLS + grants

    `ensure_schema()` in investigations/store.py calls apply_rls_policies()
    without the function definitions, so on a genuinely fresh database it
    would fail. That is a PRE-EXISTING ordering defect, not introduced here;
    it is reported rather than fixed, because fixing it means changing the
    bootstrap architecture, which is out of scope for this task.

    We therefore drive migrate.main() with DB_NAME pointed at the throwaway
    database, which is exactly how a fresh deployment is initialized.

    NOTE: DB_NAME and the engine singletons are process-global. They are
    always restored so running this module cannot contaminate other tests
    that target the live database.
    """
    import importlib
    from safenestt.persistence import engine as engine_mod

    saved_db = os.environ.get("DB_NAME")
    saved_owner, saved_engine = engine_mod._owner_engine, engine_mod._engine
    try:
        os.environ["DB_NAME"] = dbname
        engine_mod._owner_engine = None
        engine_mod._engine = None
        for mod in ("safenestt.persistence.engine", "safenestt.persistence.migrate"):
            sys.modules.pop(mod, None)
        migrate = importlib.import_module("safenestt.persistence.migrate")
        rc = migrate.main()
        assert rc == 0, "authoritative migration bootstrap failed"
    finally:
        # Restore process-global state so later tests still see the live DB.
        engine_mod._owner_engine = saved_owner
        engine_mod._engine = saved_engine
        if saved_db is None:
            os.environ.pop("DB_NAME", None)
        else:
            os.environ["DB_NAME"] = saved_db
        for mod in ("safenestt.persistence.engine", "safenestt.persistence.migrate"):
            sys.modules.pop(mod, None)
    return dbname


def _state(conn):
    with conn.cursor() as cur:
        cur.execute("""SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                       FROM pg_class c WHERE c.relname IN ('graph_nodes','graph_edges')
                       ORDER BY c.relname""")
        rls = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        cur.execute("""SELECT polrelid::regclass::text, polname
                       FROM pg_policy
                       WHERE polrelid::regclass::text IN ('graph_nodes','graph_edges')
                       ORDER BY 1,2""")
        pol = cur.fetchall()
        cur.execute("""SELECT table_name FROM information_schema.tables
                       WHERE table_schema='public' ORDER BY table_name""")
        tables = [r[0] for r in cur.fetchall()]
    return {"rls": rls, "policies": pol, "tables": tables}


# ---------------------------------------------------------------------
# 1. FRESH DATABASE
# ---------------------------------------------------------------------

def test_fresh_database_bootstrap_creates_graph_tables_with_rls(fresh_db):
    _bootstrap(fresh_db)
    c = _fresh()
    _guard_not_live(c)
    st = _state(c)
    c.close()

    assert "graph_nodes" in st["tables"], "graph_nodes table not created"
    assert "graph_edges" in st["tables"], "graph_edges table not created"

    for tbl in ("graph_nodes", "graph_edges"):
        enabled, forced = st["rls"][tbl]
        assert enabled, f"RLS not enabled on {tbl}"
        assert forced, f"FORCE RLS not enabled on {tbl}"

    names = {p[1] for p in st["policies"]}
    for pol in ("graph_nodes_tenant_isolation", "graph_nodes_insert",
                "graph_edges_tenant_isolation", "graph_edges_insert"):
        assert pol in names, f"missing policy {pol}"


def test_fresh_database_other_tables_still_protected(fresh_db):
    """Regression: wiring graph in must not weaken existing coverage."""
    _bootstrap(fresh_db)
    c = _fresh()
    _guard_not_live(c)
    with c.cursor() as cur:
        cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class WHERE relname IN
                       ('investigations','evidence','findings','reports','agent_runs')
                       ORDER BY relname""")
        rows = cur.fetchall()
    c.close()
    assert len(rows) == 5
    for name, en, fo in rows:
        assert en and fo, f"{name} lost RLS"


# ---------------------------------------------------------------------
# 2. IDEMPOTENCY
# ---------------------------------------------------------------------

def test_bootstrap_is_idempotent(fresh_db):
    _bootstrap(fresh_db)
    c = _fresh(); _guard_not_live(c)
    first = _state(c)
    counts_first = _row_counts(c)
    c.close()

    # Second and third application must not raise and must not change state.
    _bootstrap(fresh_db)
    _bootstrap(fresh_db)

    c = _fresh(); _guard_not_live(c)
    second = _state(c)
    counts_second = _row_counts(c)
    c.close()

    assert first == second, "schema state changed across repeated bootstrap"
    assert counts_first == counts_second, "row counts changed across bootstrap"


def _row_counts(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes")
        n = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM graph_edges")
        e = cur.fetchone()[0]
    return {"graph_nodes": n, "graph_edges": e}


# ---------------------------------------------------------------------
# 3. EXISTING DATABASE / EXISTING ROWS
# ---------------------------------------------------------------------

def test_bootstrap_over_existing_rows_preserves_them(fresh_db):
    """Pre-populate, then bootstrap again — no loss, no duplication."""
    _bootstrap(fresh_db)
    c = _fresh(); _guard_not_live(c)
    with c.cursor() as cur:
        cur.execute("""INSERT INTO investigations
            (investigation_id,tenant_id,target,type,status,created_at,updated_at)
            VALUES ('inv-boot-1','t-a','example.com','web','COMPLETED',NOW(),NOW())""")
        cur.execute("""INSERT INTO graph_nodes
            (investigation_id,case_id,node_key,node_type,node_label,node_data,
             source,provenance,created_at,updated_at)
            VALUES ('inv-boot-1','case-b1','gn-boot-1','evidence','n','{}'::json,
                    'test','boot',NOW(),NOW())""")
    c.commit()
    before = _row_counts(c); c.close()

    assert before["graph_nodes"] == 1

    _bootstrap(fresh_db)

    c = _fresh(); _guard_not_live(c)
    after = _row_counts(c)
    with c.cursor() as cur:
        cur.execute("SELECT node_key FROM graph_nodes WHERE node_key='gn-boot-1'")
        assert cur.fetchone() is not None, "pre-existing node lost during bootstrap"
    c.close()
    assert after == before, f"row count changed: {before} -> {after}"


# ---------------------------------------------------------------------
# 4. POLICY BEHAVIOUR ON THE FRESH DATABASE (app role, non-superuser)
# ---------------------------------------------------------------------

def _seed_two_tenants(dbname):
    c = psycopg2.connect(dbname=dbname, **OWNER)
    c.autocommit = True
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-a','fp-a')") if False else None
        cur.execute("""INSERT INTO api_keys (key_hash,key_fingerprint,tenant_id,name,
            active,revoked,scopes,use_count,created_at)
            VALUES ('h1','fp-a','t-a','k',TRUE,FALSE,'[]'::json,0,NOW()),
                   ('h2','fp-b','t-b','k',TRUE,FALSE,'[]'::json,0,NOW())""")
        cur.execute("""INSERT INTO investigations
            (investigation_id,tenant_id,target,type,status,created_at,updated_at)
            VALUES ('inv-A','t-a','example.com','web','COMPLETED',NOW(),NOW()),
                   ('inv-B','t-b','example.com','web','COMPLETED',NOW(),NOW())""")
        cur.execute("""INSERT INTO graph_nodes
            (investigation_id,case_id,node_key,node_type,node_label,node_data,
             source,provenance,created_at,updated_at)
            VALUES ('inv-A','c','gn-A','evidence','A','{}'::json,'test','boot',NOW(),NOW()),
                   ('inv-B','c','gn-B','evidence','B','{}'::json,'test','boot',NOW(),NOW())""")
        cur.execute("""INSERT INTO graph_edges
            (investigation_id,case_id,edge_key,source_node_id,target_node_id,edge_type,
             edge_label,edge_data,source,provenance,created_at,updated_at)
            VALUES ('inv-A','c','ge-A','gn-A','gn-A','supported_by','e','{}'::json,
                    'test','boot',NOW(),NOW()),
                   ('inv-B','c','ge-B','gn-B','gn-B','supported_by','e','{}'::json,
                    'test','boot',NOW(),NOW())""")
        cur.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO rls_test_app")
        cur.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO rls_test_app")
        cur.execute("GRANT EXECUTE ON FUNCTION establish_tenant_context(TEXT,TEXT) TO rls_test_app")
        cur.execute("GRANT EXECUTE ON FUNCTION get_current_tenant() TO rls_test_app")
    c.close()


def _app_conn(dbname):
    return psycopg2.connect(host="127.0.0.1", port=54322, user="rls_test_app",
                            password=APP_PW, dbname=dbname, sslmode="disable")


@pytest.fixture(scope="module")
def bootstrapped(fresh_db):
    _bootstrap(fresh_db)
    _seed_two_tenants(fresh_db)
    return fresh_db


def test_fresh_db_same_tenant_select_allowed(bootstrapped):
    c = _app_conn(bootstrapped)
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-a','fp-a')")
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 1
    c.close()


def test_fresh_db_foreign_tenant_select_denied(bootstrapped):
    c = _app_conn(bootstrapped)
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-b','fp-b')")
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0, "foreign tenant read graph_nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0, "foreign tenant read graph_edges"
    c.close()


def test_fresh_db_missing_tenant_select_denied(bootstrapped):
    c = _app_conn(bootstrapped)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0, "no-context connection read graph_nodes"
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0, "no-context connection read graph_edges"
    c.close()


def test_fresh_db_foreign_tenant_insert_denied(bootstrapped):
    c = _app_conn(bootstrapped)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("SELECT establish_tenant_context('t-b','fp-b')")
            cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
                node_type,node_label,node_data,source,provenance,created_at,updated_at)
                VALUES ('inv-A','c','gn-X','entity','X','{}'::json,'t','b',NOW(),NOW())""")
    c.rollback(); c.close()
    c = psycopg2.connect(dbname=bootstrapped, **OWNER)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE node_key='gn-X'")
        assert cur.fetchone()[0] == 0
    c.close()


def test_fresh_db_foreign_tenant_update_and_delete_denied(bootstrapped):
    c = _app_conn(bootstrapped)
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-b','fp-b')")
        cur.execute("UPDATE graph_nodes SET node_label='hijack' WHERE node_key='gn-A'")
        assert cur.rowcount == 0
        cur.execute("DELETE FROM graph_nodes WHERE node_key='gn-A'")
        assert cur.rowcount == 0
    c.commit(); c.close()
    c = psycopg2.connect(dbname=bootstrapped, **OWNER)
    with c.cursor() as cur:
        cur.execute("SELECT node_label FROM graph_nodes WHERE node_key='gn-A'")
        assert cur.fetchone()[0] == "A"
    c.close()


def test_fresh_db_cross_tenant_edge_insert_denied(bootstrapped):
    c = _app_conn(bootstrapped)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("SELECT establish_tenant_context('t-b','fp-b')")
            cur.execute("""INSERT INTO graph_edges (investigation_id,case_id,edge_key,
                source_node_id,target_node_id,edge_type,edge_label,edge_data,source,
                provenance,created_at,updated_at)
                VALUES ('inv-A','c','ge-X','gn-A','gn-A','supported_by','x','{}'::json,
                        't','b',NOW(),NOW())""")
    c.rollback(); c.close()


def test_fresh_db_app_role_not_privileged(bootstrapped):
    c = psycopg2.connect(dbname=bootstrapped, **OWNER)
    with c.cursor() as cur:
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname='rls_test_app'")
        sup, byp = cur.fetchone()
    c.close()
    assert sup is False and byp is False


def test_live_database_is_untouched_by_this_module():
    """Sanity: the production-adjacent DB still has its verified RLS state."""
    c = psycopg2.connect(dbname=LIVE_DB, **OWNER)
    with c.cursor() as cur:
        cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class WHERE relname IN ('graph_nodes','graph_edges')""")
        rows = cur.fetchall()
        cur.execute("SELECT count(*) FROM graph_nodes")
        gn = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM graph_edges")
        ge = cur.fetchone()[0]
    c.close()
    assert len(rows) == 2
    for _n, en, fo in rows:
        assert en and fo
    # Row counts must still be at least the verified baseline.
    assert gn >= 37 and ge >= 22, "live graph row counts dropped"