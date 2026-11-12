"""Env bootstrap for the remediation regression suite.

IMPORTANT: this directory deliberately has NO dependency on tests/conftest.py.
That conftest has an autouse TRUNCATE-ALL fixture which would destroy the
preserved E2E investigation (and every api_keys row, including the
production key). The remediation tests create their own tenant-scoped rows
and clean up only what they create.
"""
from __future__ import annotations

import os
import sys

# The isolation guard lives in tests/, which this directory deliberately does
# NOT import (see module docstring — it must not inherit tests/conftest.py's
# autouse TRUNCATE-ALL fixture). The guard module itself has no such fixture,
# so importing it directly is safe and gives this suite the same connection-
# level protection.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.join(_REPO_ROOT, "tests")
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
# PORT ISOLATION (2026-10-04): was 54322, the PRODUCTION Postgres port. Now
# defaults to the dedicated test instance on 55432 (see
# docker-compose.test-db.yml). Port isolation matters because every database-
# name barrier can be defeated by a refactor that hardcodes a URL; a different
# server cannot be reached by accident.
os.environ.setdefault("DB_PORT", "55432")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "safenestt_test_local_only")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")
os.environ.setdefault("PYTHONPATH", "/home/ronzoro/safenestt-ai")

# SECURITY FIX (2026-10-04): DB_NAME previously defaulted to the PRODUCTION
# database "safenestt_ai" in this file AND in test_e2e_remediation.py,
# test_graph_rls_security.py, test_long_running_start.py and
# test_report_serialization.py. Those modules connect with
# psycopg2.connect(dbname="safenestt_ai") and, in test_graph_rls_security.py,
# perform INSERT/UPDATE/DELETE/DDL against it.
#
# These are integration tests that were written against live data. They must not
# be able to reach it implicitly: a default that points at production is the same
# defect class that destroyed production. Point them at the throwaway test
# database and install the same connection-level guard used by tests/.
#
# NOTE: these four modules assert on rows that exist only in the live database.
# After this change they will fail against the test database. That is the
# correct, visible outcome — they need dedicated fixtures or an explicit,
# separately-reviewed opt-in to run against live data. Silently connecting to
# production is not an acceptable default.
os.environ.setdefault("DB_NAME", "safenestt_ai_test")

import isolation_guard  # noqa: E402

# Establish URL variables for the ISOLATED instance BEFORE anything calls
# get_owner_engine().
#
# tests/conftest.py and remediation_tests/conftest.py both load when a single
# pytest invocation spans both directories. They share the process-global engine
# singletons in safenestt.persistence.engine, and they bootstrap the schema with
# DIFFERENT roles:
#     tests/             -> owner role  (the instance superuser)
#     remediation_tests/ -> owner role  (safenestt_owner_test, NOSUPERUSER)
# Whichever loads second would otherwise inherit the first one's cached
# singletons and run DDL as the wrong role, producing
# "must be owner of function establish_tenant_context".
#
# Setting all three URL variables here to the isolated instance's roles makes
# the outcome order-independent: whichever conftest is active, get_owner_engine()
# and create_engine() resolve to the same isolated server and a role that owns
# the schema.
_TEST_PORT = os.environ.get("DB_PORT", "55432")
_TEST_DB = os.environ.get("DB_NAME", "safenestt_ai_test")
_TEST_PW = os.environ.get("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only")
_OWNER_ROLE = os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test")
os.environ["SAFENESTT_OWNER_DATABASE_URL"] = (
    f"postgresql://{_OWNER_ROLE}:{_TEST_PW}@127.0.0.1:{_TEST_PORT}/{_TEST_DB}"
)
os.environ["SAFENESTT_DATABASE_URL"] = (
    f"postgresql://safenestt_app:{_TEST_PW}@127.0.0.1:{_TEST_PORT}/{_TEST_DB}"
)
os.environ["DATABASE_URL"] = os.environ["SAFENESTT_DATABASE_URL"]

# Refuse to start if the environment itself names production.
isolation_guard.assert_no_production_env()
# Intercept psycopg2.connect / sqlalchemy.create_engine for this suite too.
isolation_guard.install()
print(
    f"[remediation conftest] isolation guard ACTIVE; "
    f"DB_NAME={os.environ.get('DB_NAME')}",
    file=sys.stderr,
)

# ---------------------------------------------------------------------
# TEST ISOLATION
#
# Two modules (test_fresh_bootstrap.py, test_graph_rls_bootstrap.py) point
# the SENTRA engine at a THROWAWAY database. That mutates process-global
# state: the engine singletons, DB_NAME / SAFENESTT_DATABASE_URL /
# SAFENESTT_OWNER_DATABASE_URL, and the sys.modules entry for the engine
# module. Left behind, that leaks into other modules that lazily import
# create_engine() and sends them at the throwaway database. This fixture
# snapshots and restores all of it around every test, so the suite is
# order-independent and can never contaminate the live database.
# ---------------------------------------------------------------------

import sys

import pytest

_WATCHED_ENV = (
    "DB_NAME",
    "SAFENESTT_DATABASE_URL",
    "SAFENESTT_OWNER_DATABASE_URL",
    "DATABASE_URL",
)
_WATCHED_MODULES = ("safenestt.persistence.engine",)


# ---------------------------------------------------------------------------
# SCHEMA BOOTSTRAP — session-scoped, idempotent
# ---------------------------------------------------------------------------
# The four DB-backed remediation modules (test_e2e_remediation,
# test_graph_rls_security, test_long_running_start, test_report_serialization)
# each insert their own api_keys row and create their own uniquely-identified
# investigations. They do NOT read any pre-existing investigation, report or
# graph row — but they DID assume the schema already existed, which in practice
# meant "whatever happens to be in the connected database". That is an implicit
# dependency on production state.
#
# This fixture makes the schema explicit and self-contained: it is created in
# the TEST database, once per session, and is a no-op when already present. It
# never truncates and never touches any database outside the allowlist.
#
# migrate.py::main() is used rather than ensure_schema() because RLS
# ENABLE/FORCE requires table ownership, and ensure_schema() runs as the
# application role (which does not own the tables it creates).
@pytest.fixture(scope="session", autouse=True)
def _bootstrap_test_schema():
    """Create the schema + RLS in the test database once per session."""
    db_name = isolation_guard.assert_test_db_configured()

    # Connect as the test instance's dedicated OWNER role. It is created with
    # production's posture (NOSUPERUSER + BYPASSRLS) by
    # scripts/provision-test-app-role.sh, so the schema created here is owned by
    # a role with the same attributes production's owner has. That is what makes
    # the FORCE-RLS-vs-BYPASSRLS assertions meaningful.
    owner_user = os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test")
    owner_dsn = (
        f"postgresql://{owner_user}:{os.environ.get('SAFENESTT_OWNER_PASSWORD', '')}"
        f"@127.0.0.1:{os.environ.get('DB_PORT', '55432')}/{db_name}"
    )
    # Defence in depth: refuse before connecting if this is not the test DB.
    isolation_guard.assert_test_dsn(owner_dsn, caller="remediation schema bootstrap")

    from sqlalchemy import create_engine as sa_create_engine

    from safenestt.persistence.models import Base

    engine = sa_create_engine(owner_dsn)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()

    # RLS is a separate step: it needs the tenant-context functions first.
    # Imported here rather than at module scope so a failure surfaces as a
    # fixture error instead of breaking collection of the whole directory.
    from safenestt.persistence import engine as engine_mod
    from safenestt.persistence.rls import apply_rls_policies, ensure_tenant_context

    owner_engine = engine_mod.create_engine(owner_dsn)
    try:
        # Adopt any pre-existing tenant-context functions BEFORE calling
        # ensure_tenant_context(), which repairs a stale definition by issuing
        # "DROP FUNCTION IF EXISTS" — that requires ownership.
        #
        # On a database created by a previous session (or by the bootstrap
        # superuser) those functions are owned by someone else, so the drop
        # fails with "must be owner of function". Adopting them first makes
        # this fixture idempotent: the suite passes on EVERY run, not only the
        # first. This ordering is load-bearing — it must precede
        # ensure_tenant_context() below.
        # NOTE: adoption of pre-existing tenant-context functions is done by
        # scripts/provision-test-app-role.sh, which runs as the bootstrap
        # SUPERUSER. It cannot be done here: this session runs as
        # ${owner_user}, which is deliberately NOSUPERUSER, and PostgreSQL
        # does not allow a non-superuser to take ownership of an object owned
        # by another role ("must be owner of function").
        ensure_tenant_context(owner_engine)
        apply_rls_policies(owner_engine)
        with owner_engine.connect() as conn:
            from sqlalchemy import text

            for table in (
                "investigations", "evidence", "findings", "agent_runs",
                "reports", "graph_nodes", "graph_edges", "audit_events",
            ):
                conn.execute(text(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY"))
                conn.execute(text(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"))
            conn.commit()
    finally:
        engine_mod._engine = None
        engine_mod._sessionmaker = None
        engine_mod._owner_engine = None

    # GRANTS ARE NOT ISSUED HERE.
    #
    # Granting on tables owned by safenestt_owner_test to safenestt_app needs
    # either superuser or membership in safenestt_app. This session is
    # deliberately NOSUPERUSER, so a GRANT here fails with "permission denied".
    #
    # All grants — schema CREATE, table DML, sequence usage, default privileges
    # — are issued once as the bootstrap superuser by
    # scripts/provision-test-app-role.sh. This fixture only creates schema.
    #
    # OWNERSHIP CONSISTENCY: this fixture MUST run as the same role that
    # provisions the instance. tests/conftest.py bootstraps with a different
    # role, and both directories can load in one pytest process. If they use
    # different owners, whichever loads second inherits the first one's cached
    # engine singletons and fails with "must be owner of function
    # establish_tenant_context" — ensure_tenant_context() repairs definitions
    # with DROP FUNCTION, which requires ownership. Both conftests therefore use
    # SAFENESTT_TEST_OWNER_USER (default safenestt_owner_test).

    print(f"[remediation conftest] schema bootstrapped in {db_name}", file=sys.stderr)


@pytest.fixture(autouse=True)
def _isolate_engine_state():
    """Restore engine singletons, env and sys.modules after EVERY test.

    The two throwaway-database modules mutate process-global state. This
    guarantees the restore runs before the next test module is imported,
    regardless of ordering.
    """
    _snapshot.clear()
    _snapshot.update({
        "env": {k: os.environ.get(k) for k in _WATCHED_ENV},
        "engine": sys.modules.get("safenestt.persistence.engine"),
    })
    try:
        yield
    finally:
        try:
            from safenestt.persistence import engine as engine_mod
            engine_mod._engine = None
            engine_mod._owner_engine = None
            engine_mod._sessionmaker = None
        except Exception:
            pass
        original = _snapshot.get("engine")
        if original is not None:
            sys.modules["safenestt.persistence.engine"] = original
        for k, v in (_snapshot.get("env") or {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


_snapshot: dict = {}