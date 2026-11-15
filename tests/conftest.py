from __future__ import annotations

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
tests_dir = os.path.dirname(os.path.abspath(__file__))
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

# ===========================================================================
# TEST-ISOLATION BARRIER — INSTALLED FIRST, BEFORE ANY DB IMPORT
# ===========================================================================
# On 2026-10-04 this suite destroyed the production database: conftest set
# DB_NAME correctly and the old guard (which only read os.environ["DB_NAME"])
# passed, but tests/test_persistence.py built its OWN DSN with a hardcoded
# "/safenestt_ai" and ran DROP TABLE ... CASCADE from an autouse fixture.
#
# The env-var guard could not catch that. isolation_guard enforces the
# invariant at the CONNECTION boundary, so a module cannot opt out by
# constructing its own DSN. This must run before any test module is collected,
# because module-level DSN constants are built at collection time.
import pytest  # noqa: E402  (needed for UsageError on the gate below)

import isolation_guard  # noqa: E402
from isolation_guard import (  # noqa: E402
    ProductionDatabaseAccessError,
    assert_no_production_env,
    install as install_isolation_guard,
    resolve_test_db_name,
)

try:
    assert_no_production_env()
except ProductionDatabaseAccessError as _exc:
    # Fail the entire session before any connection can be attempted.
    raise pytest.UsageError(
        f"REFUSING TO RUN TESTS: {_exc}"
    ) from _exc

# IMPORTANT: Set DB env vars BEFORE importing any safenestt modules that call
# get_secret() or create_engine() at module level.
#
# Every URL is derived from resolve_test_db_name(). There is no hardcoded
# database name anywhere in this file, and none may be added: a literal
# "safenestt_ai" here would be the exact defect that caused the 2026-10-04
# data loss.
os.environ["DB_HOST"] = os.environ.get("DB_HOST", "127.0.0.1")
# PORT ISOLATION (2026-10-04). This used to be 54322 — the port the PRODUCTION
# PostgreSQL container publishes. Every test shared a server with production and
# differed only by database name, so any barrier that checked the name alone was
# one refactor away from a production connection.
#
# The default is now the DEDICATED test instance (container
# safenestt-test-postgres, defined in docker-compose.test-db.yml) on 55432.
#
# An already-exported DB_PORT is respected so callers (notably
# scripts/run-tests-isolated.sh and CI) stay in control. The production PORT is
# never a default here; if a caller explicitly sets it, that is their decision
# and the database-name barriers still apply.
os.environ["DB_PORT"] = os.environ.get("DB_PORT") or os.environ.get(
    "SAFENESTT_TEST_PORT", "55432"
)
_TEST_DB = resolve_test_db_name()
os.environ["DB_NAME"] = _TEST_DB
os.environ["DB_SSL_MODE"] = "disable"
# OWNER ROLE CONSISTENCY.
#
# This directory and remediation_tests/ can both load in one pytest process and
# they share the process-global engine singletons in safenestt.persistence.engine.
# They MUST therefore bootstrap with the SAME role: ensure_tenant_context()
# repairs definitions with DROP FUNCTION, which requires ownership, so a second
# conftest running as a different role inherits the first one's cached engine
# and fails with "must be owner of function establish_tenant_context".
#
# The role is safenestt_owner_test: NOSUPERUSER + BYPASSRLS, which mirrors
# production's owner posture (rolsuper=f, rolbypassrls=t) so the RLS assertions
# are meaningful. It is created by scripts/provision-test-app-role.sh, which is
# also where all GRANTs happen — a NOSUPERUSER cannot grant on tables it owns.
_TEST_PORT = os.environ["DB_PORT"]
_TEST_PW = os.environ.get("SAFENESTT_TEST_PASSWORD", "safenestt_test_local_only")
_OWNER_ROLE = os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test")
os.environ["SAFENESTT_OWNER_PASSWORD"] = _TEST_PW
os.environ["SAFENESTT_DB_PASSWORD"] = _TEST_PW
os.environ["SAFENESTT_OWNER_DATABASE_URL"] = (
    f"postgresql+psycopg2://{_OWNER_ROLE}:{_TEST_PW}@127.0.0.1:{_TEST_PORT}/{_TEST_DB}"
)
os.environ["SAFENESTT_DATABASE_URL"] = (
    f"postgresql+psycopg2://safenestt_app:{_TEST_PW}@127.0.0.1:{_TEST_PORT}/{_TEST_DB}"
)
os.environ["DATABASE_URL"] = os.environ["SAFENESTT_DATABASE_URL"]

# Patch psycopg2.connect / sqlalchemy.create_engine /
# safenestt.persistence.engine.create_engine so ANY connection to a
# non-allowlisted database raises instead of opening a socket.
install_isolation_guard()
print(f"[conftest] isolation guard ACTIVE; test database = {_TEST_DB}", file=sys.stderr)

import safenestt  # noqa: E402
import safenestt.security.permissions as _permissions_mod  # noqa: E402

from safenestt.persistence.engine import create_engine, get_owner_engine  # noqa: E402
from safenestt.security.secrets import clear_cache  # noqa: E402

try:
    create_engine()
    print("[conftest] DB engine initialized", file=sys.stderr)
except Exception as exc:
    print(f"[conftest] DB engine init failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# PRODUCTION SAFETY GUARD
# ---------------------------------------------------------------------------
# This fixture TRUNCATEs every table using the OWNER engine (which bypasses RLS),
# so it is destructive by design.
#
# HISTORY — this guard was INSUFFICIENT and that is why production was lost on
# 2026-10-04. It inspected only os.environ["DB_NAME"]. tests/test_persistence.py
# never read DB_NAME; it built its own OWNER_URL with a hardcoded
# "/safenestt_ai" and dropped the tables. This function returned "safe" while
# the module connected to production.
#
# The env-var check is RETAINED as defence in depth, but it is no longer the
# primary barrier. The primary barrier is isolation_guard.install() above, which
# intercepts psycopg2.connect / sqlalchemy.create_engine at the connection
# boundary. This function can no longer be the thing that fails open, because
# the connection itself is refused before a socket is opened.
_ALLOWED_TEST_DB_NAMES = isolation_guard.ALLOWED_TEST_DB_NAMES
_ALLOWED_TEST_DB_PREFIXES = isolation_guard.ALLOWED_TEST_DB_PREFIXES
_PRODUCTION_DB_NAMES = isolation_guard.PRODUCTION_DB_NAMES


def assert_safe_test_database(db_name: str | None = None) -> str:
    """Fail closed unless the target database is an approved throwaway.

    Defence in depth behind isolation_guard. This checks the *declared*
    database; the connection guard independently checks the *actual* DSN.
    """
    resolved = (db_name if db_name is not None else os.environ.get("DB_NAME") or "").strip()
    if not resolved:
        raise RuntimeError(
            "REFUSING DESTRUCTIVE TEST FIXTURE: cannot determine target database. "
            "Set DB_NAME to an approved test database. Approved: "
            f"{sorted(_ALLOWED_TEST_DB_NAMES)} or a name prefixed "
            f"{list(_ALLOWED_TEST_DB_PREFIXES)}."
        )
    if resolved in _PRODUCTION_DB_NAMES:
        raise RuntimeError(
            f"REFUSING DESTRUCTIVE TEST FIXTURE: production database identity detected ({resolved!r}). "
            "This fixture truncates all tables using the OWNER engine and must never target production."
        )
    if resolved in _ALLOWED_TEST_DB_NAMES or resolved.startswith(_ALLOWED_TEST_DB_PREFIXES):
        return resolved
    raise RuntimeError(
        f"REFUSING DESTRUCTIVE TEST FIXTURE: unapproved database {resolved!r}. "
        f"Approved: {sorted(_ALLOWED_TEST_DB_NAMES)} or prefix {list(_ALLOWED_TEST_DB_PREFIXES)}."
    )


@pytest.fixture(autouse=True)
def _clean_test_db():
    """Clean test data before each test.

    CRITICAL: Uses OWNER engine for schema setup AND truncation because
    the app role cannot truncate tables it doesn't own.
    The app engine is only used for actual test operations (via session_scope).
    """
    # FAIL-CLOSED: must execute before any engine creation or TRUNCATE.
    assert_safe_test_database()

    import gc
    gc.collect()

    from safenestt.persistence.models import Base
    from sqlalchemy import text, inspect as sa_inspect

    # Use owner engine for ALL setup and cleanup operations
    owner_engine = get_owner_engine()

    # Create schema
    Base.metadata.create_all(owner_engine)

    # Apply RLS policies
    try:
        from safenestt.persistence.rls import apply_rls_policies
        apply_rls_policies(owner_engine)
    except Exception:
        pass

    # Truncate ALL tables (including the api_keys / api_key_audit tables that
    # fresh_db previously left in place) using OWNER engine (the app role cannot
    # truncate tables it doesn't own). Truncating api_key_audit before api_keys
    # keeps the foreign key order valid with CASCADE.
    #
    # This is the isolation boundary that prevents api_keys.key_fingerprint
    # duplicate rows from persisting across tests, which is what caused the
    # regression tests to fail with "duplicate key value violates unique
    # constraint \"ix_api_keys_key_fingerprint\"".
    with owner_engine.connect() as conn:
        inspector = sa_inspect(owner_engine)
        existing_tables = inspector.get_table_names()
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in existing_tables:
                conn.execute(text(f"TRUNCATE TABLE {table.name} CASCADE"))
        # Clear the session-bound tenant context so no stale binding survives a
        # failed/patched test into the next one.
        conn.execute(text("DELETE FROM public._tenant_context"))
        conn.commit()

        # Graph-edge security tests require an api_keys row whose key_fingerprint
        # matches establish_tenant_context(tenant_id, key_fingerprint). The
        # _clean_test_db fixture truncates api_keys to a pristine empty table, so
        # without this seed the DB-backed graph-edge tests fail with
        # "Invalid API key or tenant mismatch" raised by establish_tenant_context
        # at test setup. This seed is test-only and must never touch production.
        from hashlib import sha256

        def _fp(tenant_id: str) -> str:
            return sha256(f"test-key-for-{tenant_id}".encode()).hexdigest()

        owner_engine = get_owner_engine()
        with owner_engine.connect() as conn:
            existing = conn.execute(
                text(
                    "SELECT COUNT(*) FROM api_keys "
                    "WHERE tenant_id = :tid AND key_fingerprint = :fp"
                ),
                {"tid": "test-tenant-graph-sec", "fp": _fp("test-tenant-graph-sec")},
            ).scalar()
            if existing == 0:
                conn.execute(
                    text(
                        "INSERT INTO api_keys (key_hash, key_fingerprint, tenant_id, active, revoked, "
                        "scopes, created_at, use_count) "
                        "VALUES (:kh, :fp, :tid, TRUE, FALSE, '[]'::json, NOW(), 0)"
                    ),
                    {
                        "kh": _fp("test-tenant-graph-sec"),
                        "fp": _fp("test-tenant-graph-sec"),
                        "tid": "test-tenant-graph-sec",
                    },
                )
                conn.commit()
        owner_engine.dispose()

        yield

@pytest.fixture(scope="function")
def database_session() -> Generator[psycopg2.extensions.connection, None, None]:
    """A live PostgreSQL connection (owner role) for test modules that need one.

    Provided by conftest.py so that test modules can open their own
    connections without constructing a DSN that bypasses isolation_guard.
    The connection defaults to the test database (safenestt_ai_test) on the
    dedicated test port, matching the rest of the suite.
    """
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("SAFENESTT_TEST_PORT", "55432")),
        user=os.environ.get("SAFENESTT_TEST_OWNER_USER", "safenestt_owner_test"),
        password=os.environ.get("SAFENESTT_TEST_PASSWORD", "safenestt_test_local_only"),
        dbname=os.environ.get("DB_NAME", "safenestt_ai_test"),
        sslmode="disable",
    )
    conn.autocommit = True
    yield conn
    conn.close()



print("[conftest] safenestt:", safenestt.__file__, file=sys.stderr)
print("[conftest] permissions:", _permissions_mod.__file__, file=sys.stderr)


@pytest.fixture(autouse=True)
def _reset_provider_cache():
    """Clear provider credential cache between tests to prevent env leakage.

    Tests like TestFirecrawlConfig::test_missing_credential_* rely on
    get_secret() returning None, but a prior test class may have cached
    the key in _cache.  Reset the cache before each test.
    """
    from safenestt.security.secrets import _cache
    keys_to_clear = [
        "FIRECRAWL_API_KEY",
        "HUNTER_API_KEY",
        "HUNTER_EMAIL",
        "SHODAN_API_KEY",
        "VT_API_KEY",
        "HIBP_API_KEY",
        "ETHERSCAN_API_KEY",
    ]
    for key in keys_to_clear:
        _cache.pop(key, None)
    yield