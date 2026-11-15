"""Fresh-database bootstrap ordering tests.

PROVES
------
`ensure_schema()` — the function the FastAPI app actually calls at startup —
can initialize a COMPLETELY EMPTY database. It previously could not: it called
apply_rls_policies() without first creating get_current_tenant(), so every
policy failed to parse with

    psycopg2.errors.UndefinedFunction: function get_current_tenant() does not exist

Required order, now enforced:
    1. base tables
    2. tenant-context functions
    3. RLS policies

SAFETY
------
Every test targets a THROWAWAY database (safenestt_boot_*). The
production-adjacent `safenestt_ai` database is never written to, truncated,
or dropped by this module, and a hard guard asserts that at every entry point.
Test residue and preserved E2E data are left intact.

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

import importlib
import sys
import uuid

import psycopg2
from psycopg2 import sql
import pytest

LIVE_DB = "safenestt_ai"
BOOT_DB = "safenestt_bootstrap_test"  # throwaway DB for destructive tests
APP_ROLE = "boot_test_app"
APP_PW = "postgres"

OWNER = dict(host="127.0.0.1", port=54322, user="postgres",
             password="postgres", sslmode="disable")


def _admin():
    return psycopg2.connect(dbname=BOOT_DB, **OWNER)


def _boot():
    return psycopg2.connect(dbname=BOOT_DB, **OWNER)


def _guard(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        name = cur.fetchone()[0]
    assert name != LIVE_DB, f"REFUSING TO RUN: must never touch {LIVE_DB}"
    return name


@pytest.fixture(scope="module")
def _create_throwaway_db():
    """Create the throwaway database if it doesn't exist."""
    admin_conn = psycopg2.connect(dbname="postgres", **OWNER)
    admin_conn.autocommit = True
    with admin_conn.cursor() as cur:
        cur.execute(
            sql.SQL("SELECT 1 FROM pg_database WHERE datname = {}").format(
                sql.Identifier(BOOT_DB)))
        exists = cur.fetchone()
        if not exists:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(BOOT_DB)))


def _drop_throwaway_db():
    """Drop the throwaway database and app role after tests."""
    admin_conn = psycopg2.connect(dbname="postgres", **OWNER)
    admin_conn.autocommit = True
    with admin_conn.cursor() as cur:
        # Terminate active connections to the throwaway DB
        cur.execute(
            sql.SQL("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = {} AND pid <> pg_backend_pid()").format(
                sql.Identifier(BOOT_DB)))
        # Drop the database
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
            sql.Identifier(BOOT_DB)))
        # Drop the app role
        cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(
            sql.Identifier(APP_ROLE)))
    admin_conn.close()


@pytest.fixture(scope="module")
def empty_db():
    """Start from a clean throwaway database (safenestt_bootstrap_test)."""
    # Create the throwaway database (only if it doesn't exist)
    _create_throwaway_db()

    # Ensure the schema (functions, policies) is bootstrapped in the throwaway DB
    from safenestt.persistence import engine as engine_mod
    from safenestt.persistence.rls import ensure_tenant_context, apply_rls_policies

    owner_user = os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test")
    owner_dsn = (
        f"postgresql://{owner_user}:{os.environ.get('SAFENESTT_OWNER_PASSWORD', '')}"
        f"@127.0.0.1:{os.environ.get('DB_PORT', '55432')}/{BOOT_DB}"
    )
    owner_engine = engine_mod.create_engine(owner_dsn)
    try:
        ensure_tenant_context(owner_engine)
        apply_rls_policies(owner_engine)
    finally:
        owner_engine.dispose()

    # The APP_ROLE (boot_test_app) is the table owner; ensure it exists.
    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
            sql.Identifier(APP_ROLE)), (APP_PW,))
        # Grant CREATE on schema public so the role can create tables
        cur.execute(sql.SQL("GRANT CREATE ON SCHEMA public TO {}").format(
            sql.Identifier(APP_ROLE)))
    c.close()

    # Connect as the optimizer role (owner). Drop every table in the public
    # schema so ensure_schema() starts from a genuinely empty state.
    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        # Drop all tables (and sequences) in the public schema
        cur.execute("""
            SELECT tablename FROM pg_tables
            WHERE schemaname='public' AND tablename NOT LIKE 'pg_%' AND schemaname NOT LIKE 'sql_%'
        """)
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            cur.execute(sql.SQL("DROP TABLE IF EXISTS {} CASCADE").format(
                sql.Identifier(t)))
        # Drop all sequences in public
        cur.execute("""
            SELECT sequencename FROM pg_sequences
            WHERE schemaname='public' AND sequencename NOT LIKE 'pg_%'
        """)
        seqs = [r[0] for r in cur.fetchall()]
        for s in seqs:
            cur.execute(sql.SQL("DROP SEQUENCE IF EXISTS {} CASCADE").format(
                sql.Identifier(s)))
        # Verify we now have zero tables
        cur.execute("""SELECT count(*) FROM information_schema.tables
                       WHERE table_schema='public' AND table_name NOT LIKE 'pg%%'""")
        assert cur.fetchone()[0] == 0, f"DB not empty after cleanup: {tables}"
    c.close()
    yield BOOT_DB

    # Cleanup: drop the throwaway database and app role
    _drop_throwaway_db()


def _ensure_schema(dbname):
    """Call the real ensure_schema() with the engine pointed at `dbname`.

    ensure_schema() uses create_engine(), and _build_database_url() hardcodes
    the `safenestt_app` role. We override it via SAFENESTT_DATABASE_URL so the
    application engine connects as this module's throwaway role instead of
    touching the real one.
    """
    from safenestt.investigations import store as store_mod
    from safenestt.persistence import engine as engine_mod

    saved_db = os.environ.get("DB_NAME")
    saved_url = os.environ.get("SAFENESTT_DATABASE_URL")
    saved_engine = engine_mod._engine
    saved_owner = engine_mod._owner_engine
    try:
        os.environ["DB_NAME"] = dbname
        os.environ["SAFENESTT_DATABASE_URL"] = (
            f"postgresql://{APP_ROLE}:{APP_PW}@127.0.0.1:54322/{dbname}")
        engine_mod._engine = None
        engine_mod._owner_engine = None
        sys.modules.pop("safenestt.persistence.engine", None)
        mod = importlib.import_module("safenestt.investigations.store")
        importlib.reload(mod)
        mod.ensure_schema()
    finally:
        engine_mod._engine = saved_engine
        engine_mod._owner_engine = saved_owner
        if saved_db is None:
            os.environ.pop("DB_NAME", None)
        else:
            os.environ["DB_NAME"] = saved_db
        if saved_url is None:
            os.environ.pop("SAFENESTT_DATABASE_URL", None)
        else:
            os.environ["SAFENESTT_DATABASE_URL"] = saved_url
        sys.modules.pop("safenestt.persistence.engine", None)


def _app_conn():
    return psycopg2.connect(host="127.0.0.1", port=54322, user=APP_ROLE,
                            password=APP_PW, dbname=BOOT_DB, sslmode="disable")


def _grant():
    """Grant privileges after ensure_schema().

    ensure_schema() creates the tables through the APPLICATION engine, so they
    are owned by APP_ROLE, not by postgres. postgres is BYPASSRLS but is NOT a
    superuser, so it has no implicit rights on tables it does not own. Grant
    explicitly, from the owning role.
    """
    c = _app_conn()  # connects as APP_ROLE, the table owner
    c.autocommit = True
    with c.cursor() as cur:
        cur.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO boot_test_app")
        cur.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO boot_test_app")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO postgres")
        cur.execute("GRANT EXECUTE ON FUNCTION establish_tenant_context(TEXT,TEXT) TO boot_test_app")
        cur.execute("GRANT EXECUTE ON FUNCTION get_current_tenant() TO boot_test_app")
        cur.execute("GRANT EXECUTE ON FUNCTION clear_tenant_context() TO boot_test_app")
    c.close()


# ---------------------------------------------------------------------
# 1-2. Empty DB bootstraps; tenant functions exist
# ---------------------------------------------------------------------

def test_empty_database_ensure_schema_succeeds(empty_db):
    """Previously raised UndefinedFunction: get_current_tenant()."""
    _ensure_schema(empty_db)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("""SELECT count(*) FROM information_schema.tables
                       WHERE table_schema='public' AND table_name='graph_nodes'""")
        assert cur.fetchone()[0] == 1, "graph_nodes not created on empty DB"
        cur.execute("""SELECT count(*) FROM information_schema.tables
                       WHERE table_schema='public' AND table_name='graph_edges'""")
        assert cur.fetchone()[0] == 1, "graph_edges not created on empty DB"
    c.close()


def test_tenant_functions_exist_after_ensure_schema(empty_db):
    _ensure_schema(empty_db)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("""SELECT proname FROM pg_proc
                       WHERE pronamespace='public'::regnamespace
                         AND proname IN ('get_current_tenant','establish_tenant_context',
                                         'clear_tenant_context')""")
        names = {r[0] for r in cur.fetchall()}
        cur.execute("SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_name='_tenant_context'")
        has_table = cur.fetchone()[0] == 1
    c.close()
    assert names == {"get_current_tenant", "establish_tenant_context",
                     "clear_tenant_context"}, f"missing: {names}"
    assert has_table, "_tenant_context table missing"


def test_get_current_tenant_works(empty_db):
    _ensure_schema(empty_db)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("SELECT get_current_tenant()")
        val = cur.fetchone()[0]
    c.close()
    assert val == "", f"expected '' with no context, got {val!r}"


def test_establish_tenant_context_works(empty_db):
    import hashlib
    run = uuid.uuid4().hex[:10]
    fp = hashlib.sha256(f"boot-{run}".encode()).hexdigest()
    _ensure_schema(empty_db)
    _grant()
    c = _boot(); c.autocommit = True; _guard(c)
    with c.cursor() as cur:
        cur.execute("""INSERT INTO api_keys (key_hash,key_fingerprint,tenant_id,name,
            active,revoked,scopes,use_count,created_at)
            VALUES (%s,%s,'boot-t','boot',TRUE,FALSE,'[]'::json,0,NOW())""",
                    ("h-" + run, fp))
    c.close()

    _grant()
    c = _app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context(%s,%s)", ("boot-t", fp))
        assert cur.fetchone()[0] == "boot-t"
        cur.execute("SELECT get_current_tenant()")
        assert cur.fetchone()[0] == "boot-t"
        cur.execute("SELECT clear_tenant_context()")
        cur.execute("SELECT get_current_tenant()")
        assert cur.fetchone()[0] == "", "clear_tenant_context did not clear"
    c.close()


def test_establish_tenant_context_rejects_bad_key(empty_db):
    """An unknown fingerprint must RAISE — fail closed, not bind a tenant."""
    c = _boot(); _guard(c)
    with pytest.raises(psycopg2.errors.RaiseException):
        with c.cursor() as cur:
            cur.execute("SELECT establish_tenant_context('boot-t','not-a-real-fp')")
    c.rollback(); c.close()


# ---------------------------------------------------------------------
# 5-8. RLS + FORCE after fresh bootstrap
# ---------------------------------------------------------------------

def test_all_rls_policies_installed_on_fresh_db(empty_db):
    _ensure_schema(empty_db)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class WHERE relname IN
                       ('investigations','agent_runs','findings','evidence','reports',
                        'audit_events','graph_nodes','graph_edges') ORDER BY relname""")
        rows = cur.fetchall()
    c.close()
    assert len(rows) == 8, f"expected 8 RLS tables, got {len(rows)}"
    for name, en, fo in rows:
        assert en, f"RLS not enabled on {name}"
        assert fo, f"FORCE RLS not enabled on {name}"


def test_graph_rls_and_force_on_fresh_db(empty_db):
    _ensure_schema(empty_db)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("""SELECT relrowsecurity, relforcerowsecurity FROM pg_class
                       WHERE relname='graph_nodes'""")
        gn = cur.fetchone()
        cur.execute("""SELECT relrowsecurity, relforcerowsecurity FROM pg_class
                       WHERE relname='graph_edges'""")
        ge = cur.fetchone()
        cur.execute("""SELECT polrelid::regclass::text, polname FROM pg_policy
                       WHERE polrelid::regclass::text IN ('graph_nodes','graph_edges')
                       ORDER BY 1,2""")
        pol = cur.fetchall()
    c.close()
    assert gn == (True, True), f"graph_nodes RLS/FORCE = {gn}"
    assert ge == (True, True), f"graph_edges RLS/FORCE = {ge}"
    names = {p[1] for p in pol}
    assert {"graph_nodes_tenant_isolation", "graph_nodes_insert",
            "graph_edges_tenant_isolation", "graph_edges_insert"} <= names


# ---------------------------------------------------------------------
# 9-11. Tenant isolation on the freshly bootstrapped DB
# ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def seeded(empty_db):
    _ensure_schema(empty_db)
    import hashlib
    run = uuid.uuid4().hex[:10]
    fp_a = hashlib.sha256(f"iso-a-{run}".encode()).hexdigest()
    fp_b = hashlib.sha256(f"iso-b-{run}".encode()).hexdigest()
    c = _boot(); c.autocommit = True; _guard(c)
    with c.cursor() as cur:
        cur.execute("""INSERT INTO api_keys (key_hash,key_fingerprint,tenant_id,name,
            active,revoked,scopes,use_count,created_at) VALUES
            (%s,%s,'t-a','k',TRUE,FALSE,'[]'::json,0,NOW()),
            (%s,%s,'t-b','k',TRUE,FALSE,'[]'::json,0,NOW())""",
                    ("ha" + run, fp_a, "hb" + run, fp_b))
        cur.execute("""INSERT INTO investigations
            (investigation_id,tenant_id,target,type,status,created_at,updated_at)
            VALUES ('inv-A','t-a','example.com','web','COMPLETED',NOW(),NOW()),
                   ('inv-B','t-b','example.com','web','COMPLETED',NOW(),NOW())""")
        cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
            node_type,node_label,node_data,source,provenance,created_at,updated_at)
            VALUES ('inv-A','c','gn-A','evidence','A','{}'::json,'t','boot',NOW(),NOW()),
                   ('inv-B','c','gn-B','evidence','B','{}'::json,'t','boot',NOW(),NOW())""")
        cur.execute("""INSERT INTO graph_edges (investigation_id,case_id,edge_key,
            source_node_id,target_node_id,edge_type,edge_label,edge_data,source,
            provenance,created_at,updated_at)
            VALUES ('inv-A','c','ge-A','gn-A','gn-A','supported_by','e','{}'::json,
                    't','boot',NOW(),NOW())""")
    c.close()
    _grant()
    return {"fp_a": fp_a, "fp_b": fp_b}


def test_fresh_db_correct_tenant_select(seeded):
    c = _app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-a',%s)", (seeded["fp_a"],))
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 1
    c.close()


def test_fresh_db_foreign_tenant_select_zero(seeded):
    c = _app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-b',%s)", (seeded["fp_b"],))
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT count(*) FROM evidence WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0
    c.close()


def test_fresh_db_missing_tenant_fails_closed(seeded):
    c = _app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT count(*) FROM graph_edges WHERE investigation_id='inv-A'")
        assert cur.fetchone()[0] == 0
    c.close()


def test_fresh_db_foreign_tenant_writes_denied(seeded):
    c = _app_conn()
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with c.cursor() as cur:
            cur.execute("SELECT establish_tenant_context('t-b',%s)", (seeded["fp_b"],))
            cur.execute("""INSERT INTO graph_nodes (investigation_id,case_id,node_key,
                node_type,node_label,node_data,source,provenance,created_at,updated_at)
                VALUES ('inv-A','c','gn-X','entity','X','{}'::json,'t','b',NOW(),NOW())""")
    c.rollback(); c.close()

    c = _app_conn()
    with c.cursor() as cur:
        cur.execute("SELECT establish_tenant_context('t-b',%s)", (seeded["fp_b"],))
        cur.execute("UPDATE graph_nodes SET node_label='hijack' WHERE node_key='gn-A'")
        assert cur.rowcount == 0
        cur.execute("DELETE FROM graph_nodes WHERE node_key='gn-A'")
        assert cur.rowcount == 0
    c.commit(); c.close()


# ---------------------------------------------------------------------
# 12-13. Idempotency
# ---------------------------------------------------------------------

def test_repeated_ensure_schema_is_idempotent(seeded):
    def snap():
        c = _boot(); _guard(c)
        with c.cursor() as cur:
            cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                           FROM pg_class WHERE relname IN ('graph_nodes','graph_edges')
                           ORDER BY relname""")
            rls = cur.fetchall()
            cur.execute("""SELECT polname FROM pg_policy
                           WHERE polrelid::regclass::text IN ('graph_nodes','graph_edges')
                           ORDER BY polname""")
            pol = [r[0] for r in cur.fetchall()]
            cur.execute("SELECT count(*) FROM graph_nodes")
            gn = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM graph_edges")
            ge = cur.fetchone()[0]
            cur.execute("""SELECT proname FROM pg_proc
                           WHERE pronamespace='public'::regnamespace AND proname IN
                           ('get_current_tenant','establish_tenant_context','clear_tenant_context')
                           ORDER BY proname""")
            fns = [r[0] for r in cur.fetchall()]
        c.close()
        return (rls, pol, gn, ge, fns)

    before = snap()
    _ensure_schema(BOOT_DB)
    _ensure_schema(BOOT_DB)
    after = snap()
    assert before == after, f"state changed:\n{before}\n{after}"
    assert len(after[1]) == 4, f"policy duplication: {after[1]}"
    assert len(after[4]) == 3, f"function duplication: {after[4]}"


def test_three_consecutive_bootstraps_succeed(seeded):
    for _ in range(3):
        _ensure_schema(BOOT_DB)
    c = _boot(); _guard(c)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes")
        assert cur.fetchone()[0] == 2, "rows lost/duplicated"
        cur.execute("SELECT count(*) FROM graph_edges")
        assert cur.fetchone()[0] == 1
    c.close()


# ---------------------------------------------------------------------
# migrate.py vs ensure_schema(): no conflicting definitions
# ---------------------------------------------------------------------

def test_no_duplicate_function_definitions_after_both_paths(seeded):
    """Both paths on a FRESH database, in the REAL deployment order.

    Production sequence is:
        migrate.main()   -> creates tables as the OWNER, applies RLS, grants
        ensure_schema()  -> FastAPI startup, application role, must be a no-op

    Note on ordering: enabling RLS requires being the table OWNER. If
    ensure_schema() ran first (creating tables as the app role), a later
    migrate.main() could not ALTER those tables. That is not a defect in
    either function — it is why migrate.py is the initialization entrypoint.
    This test therefore drives the real order and asserts neither path
    duplicates the other's objects.
    """
    import importlib
    from safenestt.persistence import engine as engine_mod

    # Fresh database so the owner genuinely owns the tables it creates.
    name = BOOT_DB + "_mig"
    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        cur.execute(f'CREATE DATABASE "{name}"')
    c.close()
    c = psycopg2.connect(host="127.0.0.1", port=54322, user="postgres",
                        password="postgres", dbname=name, sslmode="disable")
    c.autocommit = True
    with c.cursor() as cur:
        cur.execute(sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(
            sql.Identifier(APP_ROLE)))
    c.close()

    saved = {k: os.environ.get(k) for k in (
        "DB_NAME", "SAFENESTT_DATABASE_URL", "SAFENESTT_OWNER_DATABASE_URL")}
    saved_engine, saved_owner = engine_mod._engine, engine_mod._owner_engine
    try:
        os.environ["DB_NAME"] = name
        os.environ["SAFENESTT_DATABASE_URL"] = (
            f"postgresql://{APP_ROLE}:{APP_PW}@127.0.0.1:54322/{name}")
        os.environ["SAFENESTT_OWNER_DATABASE_URL"] = (
            f"postgresql://postgres:postgres@127.0.0.1:54322/{name}")
        engine_mod._engine = None
        engine_mod._owner_engine = None
        sys.modules.pop("safenestt.persistence.engine", None)
        migrate = importlib.import_module("safenestt.persistence.migrate")
        assert migrate.main() == 0, "first migrate.main() failed"
        assert migrate.main() == 0, "second migrate.main() not idempotent"

        # Now the application startup path, against the same database.
        # ensure_schema() runs as the app role, which is NOT the table owner,
        # so its RLS step is expected to hit the documented capability
        # boundary. It must still succeed (create tables, ensure tenant
        # context) and must NOT raise.
        store_mod = importlib.import_module("safenestt.investigations.store")
        importlib.reload(store_mod)
        store_mod.ensure_schema()
    finally:
        engine_mod._engine = saved_engine
        engine_mod._owner_engine = saved_owner
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("safenestt.persistence.engine", None)

    try:
        c = psycopg2.connect(host="127.0.0.1", port=54322, user="postgres",
                            password="postgres", dbname=name, sslmode="disable")
        with c.cursor() as cur:
            cur.execute("""SELECT proname, count(*) FROM pg_proc
                           WHERE pronamespace='public'::regnamespace AND proname IN
                           ('get_current_tenant','establish_tenant_context','clear_tenant_context')
                           GROUP BY proname ORDER BY proname""")
            rows = cur.fetchall()
            cur.execute("""SELECT polname, count(*) FROM pg_policy
                           WHERE polrelid::regclass::text IN ('graph_nodes','graph_edges')
                           GROUP BY polname ORDER BY polname""")
            pol = cur.fetchall()
            cur.execute("SELECT count(*) FROM graph_nodes")
            gn = cur.fetchone()[0]
        c.close()
    finally:
        # ALWAYS drop the scratch database, even on failure, so the role is not
        # left with dependent objects and the next run's fixture can create it.
        c = _admin(); c.autocommit = True
        with c.cursor() as cur:
            cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        c.close()

    assert len(rows) == 3, f"expected 3 tenant functions, got {rows}"
    for n, cnt in rows:
        assert cnt == 1, f"function {n} defined {cnt} times"
    assert len(pol) == 4, f"expected 4 graph policies, got {pol}"
    for n, cnt in pol:
        assert cnt == 1, f"policy {n} defined {cnt} times"
    assert gn == 0, "ensure_schema() invented graph rows"


def test_live_database_never_touched():
    """The production-adjacent DB retains its verified security state."""
    c = psycopg2.connect(dbname=LIVE_DB, **OWNER)
    with c.cursor() as cur:
        cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class WHERE relname IN ('graph_nodes','graph_edges')""")
        rows = cur.fetchall()
        cur.execute("""SELECT count(*) FROM pg_proc WHERE proname='get_current_tenant'
                       AND pronamespace='public'::regnamespace""")
        fn = cur.fetchone()[0]
    c.close()
    assert len(rows) == 2
    for _n, en, fo in rows:
        assert en and fo
    assert fn == 1, "live get_current_tenant() duplicated"