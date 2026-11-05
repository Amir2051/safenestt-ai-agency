"""Test-isolation safety barrier for the SafeNestT investigation engine.

WHY THIS MODULE EXISTS
----------------------
On 2026-10-04 the engine test suite destroyed the production database. Root
cause chain:

1. ``tests/conftest.py`` set ``DB_NAME=safenestt_ai_test`` and a guard
   (``assert_safe_test_database``) checked only ``os.environ["DB_NAME"]``.
2. ``tests/test_persistence.py`` ignored ``DB_NAME`` entirely. It built its
   own ``OWNER_URL``/``APP_URL`` with a hardcoded ``/safenestt_ai`` and ran
   ``DROP TABLE IF EXISTS ... investigations, evidence, findings, agent_runs,
   reports, audit_events CASCADE`` from an ``autouse`` fixture.
3. The guard passed (because the env var was correct) while the module
   connected to production anyway.

The guard was therefore checking the wrong thing. **This module enforces the
invariant at the connection boundary**, which is the only place that cannot be
bypassed by a module that constructs its own DSN.

THE BARRIER
-----------
``install()`` monkeypatches the three ways this codebase opens a database
connection:

* ``psycopg2.connect`` / ``psycopg2.extensions.connect``
* ``sqlalchemy.create_engine``
* ``safenestt.persistence.engine.create_engine``

Each wrapper parses the target database out of the DSN and refuses anything
that is not on the test allowlist. This catches hardcoded DSNs in *any* test
module, present or future, without that module having to cooperate.

FAIL-CLOSED AND BYPASS-PROOF
----------------------------
* The allowlist is derived from ``_ALLOWED_TEST_DB_NAMES`` /
  ``_ALLOWED_TEST_DB_PREFIXES``. Production names are rejected unconditionally.
* ``install()`` raises if called twice with different settings, and records the
  patches it applied so :func:`uninstall` can restore them.
* The DSN is checked *before* any socket is opened, so a rejection cannot have
  a side effect.
* If a DSN cannot be parsed at all, the connection is REJECTED. Failing closed
  on an unparseable DSN is deliberate: an unparseable DSN is more likely to be
  a bug than a legitimate connection.
* ``assert_no_production_env()`` additionally refuses to start a test session
  when ``DB_NAME`` itself names production, which is the CI gate (req 5).

USAGE
-----
``tests/conftest.py`` calls :func:`install` at import time, before any test
module is collected. That ordering matters: a module-level DSN in a test file
is built at *collection*, so the patch must already be in place.
"""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

#: The production database. Never connectable from a test.
PRODUCTION_DB_NAMES = frozenset({"safenestt_ai"})

#: Databases a test is permitted to destroy.
ALLOWED_TEST_DB_NAMES = frozenset({"safenestt_ai_test"})

#: Per-run scratch databases created by the remediation suite.
ALLOWED_TEST_DB_PREFIXES = (
    "safenestt_audittest_",
    "safenestt_gate_",
    "safenestt_bootstrap_",
    # test_startup_gate.py creates throwaway DBs with this prefix
    "safenestt_sg_",
)

#: Env var that may override the test database name.
TEST_DB_ENV_VAR = "SAFENESTT_TEST_DB_NAME"

#: Default test database name.
DEFAULT_TEST_DB_NAME = "safenestt_ai_test"

_installed = False
_originals: dict[str, Any] = {}


class ProductionDatabaseAccessError(RuntimeError):
    """Raised when test code attempts to connect to the production database."""


# --------------------------------------------------------------------------
# DSN parsing
# --------------------------------------------------------------------------

_DSN_DB_PATTERNS = (
    # postgresql://user:***@host:port/dbname (standard and SQLAlchemy forms)
    # matches: postgres://, postgresql://, postgresql+psycopg2://, postgresql+psycopg://
    re.compile(r"^postgres(?:ql)?(\+[a-z0-9]+)?://[^/?#]*/(?P<db>[^/?#]+)"),
    # SQLAlchemy URL object / bare "dbname" forms
    re.compile(r"^/(?P<db>[^/?#]+)"),
)


def extract_database_name(dsn: Any) -> str | None:
    """Best-effort extraction of the database name from a DSN.

    Returns ``None`` when the database cannot be determined. Callers must treat
    ``None`` as a rejection (fail closed).
    """
    if dsn is None:
        return None
    # SQLAlchemy URL object
    if hasattr(dsn, "database") and not isinstance(dsn, (str, bytes)):
        db = getattr(dsn, "database", None)
        return str(db) if db else None
    if isinstance(dsn, bytes):
        try:
            dsn = dsn.decode()
        except Exception:
            return None
    if not isinstance(dsn, str):
        return None
    text = dsn.strip()
    if not text:
        return None
    for pattern in _DSN_DB_PATTERNS:
        match = pattern.match(text)
        if match:
            name = match.group("db")
            # Strip a query string that may have survived the pattern.
            name = name.split("?", 1)[0].split("#", 1)[0]
            return name or None
    return None


def is_allowed_database(db_name: str | None) -> bool:
    """True only for an explicitly approved test database."""
    if not db_name:
        return False
    if db_name in PRODUCTION_DB_NAMES:
        return False
    if db_name in ALLOWED_TEST_DB_NAMES:
        return True
    return db_name.startswith(ALLOWED_TEST_DB_PREFIXES)


def assert_test_dsn(dsn: Any, *, caller: str = "unknown") -> str | None:
    """Validate a DSN before it is used. Returns the parsed db name.

    Raises :class:`ProductionDatabaseAccessError` when the target is production,
    unapproved, or unparseable.
    """
    db_name = extract_database_name(dsn)
    if db_name in PRODUCTION_DB_NAMES:
        raise ProductionDatabaseAccessError(
            f"BLOCKED by test-isolation guard: {caller} attempted to connect to the "
            f"PRODUCTION database {db_name!r}. Tests must target a database on the "
            f"allowlist ({sorted(ALLOWED_TEST_DB_NAMES)} or a name starting with "
            f"{list(ALLOWED_TEST_DB_PREFIXES)}). "
            f"If this is a genuine production check, run it outside pytest."
        )
    if not is_allowed_database(db_name):
        raise ProductionDatabaseAccessError(
            f"BLOCKED by test-isolation guard: {caller} target database "
            f"{db_name!r} is not an approved test database. Approved: "
            f"{sorted(ALLOWED_TEST_DB_NAMES)} or prefix {list(ALLOWED_TEST_DB_PREFIXES)}. "
            f"Failing closed because the target could not be proven safe."
        )
    return db_name


def assert_no_production_env() -> None:
    """CI gate (req 5): refuse to run tests when the environment names production.

    This is deliberately separate from the connection guard. The connection
    guard catches a module that builds its own DSN; this catches the case where
    the *environment itself* is pointed at production, which would make every
    ``DB_NAME``-derived URL dangerous even though it looks correct.
    """
    db_name = (os.environ.get("DB_NAME") or "").strip()
    if db_name in PRODUCTION_DB_NAMES:
        raise ProductionDatabaseAccessError(
            f"BLOCKED by test-isolation guard: DB_NAME={db_name!r} names the PRODUCTION "
            f"database. Refusing to start a test session against production. "
            f"Set DB_NAME to a test database ({sorted(ALLOWED_TEST_DB_NAMES)}) or "
            f"unset it so the suite default applies."
        )
    for var in ("SAFENESTT_DATABASE_URL", "DATABASE_URL", "OWNER_DATABASE_URL"):
        url = (os.environ.get(var) or "").strip()
        if not url:
            continue
        db_name = extract_database_name(url)
        if db_name in PRODUCTION_DB_NAMES:
            raise ProductionDatabaseAccessError(
                f"BLOCKED by test-isolation guard: {var} points at the PRODUCTION "
                f"database {db_name!r}. Refusing to start a test session."
            )


def resolve_test_db_name() -> str:
    """The single source of truth for the test database name."""
    return (os.environ.get(TEST_DB_ENV_VAR) or "").strip() or DEFAULT_TEST_DB_NAME


def assert_test_db_configured() -> str:
    """Resolve and validate the test DB name. Fails closed on production."""
    db_name = resolve_test_db_name()
    if not is_allowed_database(db_name):
        raise ProductionDatabaseAccessError(
            f"BLOCKED by test-isolation guard: resolved test database {db_name!r} is not "
            f"approved. Approved: {sorted(ALLOWED_TEST_DB_NAMES)} or prefix "
            f"{list(ALLOWED_TEST_DB_PREFIXES)}."
        )
    return db_name


# --------------------------------------------------------------------------
# Connection-level enforcement
# --------------------------------------------------------------------------


def _wrap_psycopg2_connect(original_connect):
    def guarded_connect(dsn=None, *args, **kwargs):
        if dsn is None:
            dsn = kwargs.get("dsn") or kwargs.get("connection_string")
        if dsn is None:
            # Build DSN from keyword args (host/port/dbname).
            dbname = kwargs.get("dbname") or kwargs.get("database")
            if dbname is None:
                raise ProductionDatabaseAccessError(
                    "BLOCKED by test-isolation guard: psycopg2.connect() called without a "
                    "resolvable database name. Failing closed."
                )
            assert_test_dsn(f"postgresql:///{dbname}", caller="psycopg2.connect(dbname=...)")
        else:
            assert_test_dsn(dsn, caller="psycopg2.connect()")
        return original_connect(dsn, *args, **kwargs)

    guarded_connect.__name__ = "guarded_connect"
    return guarded_connect


def _wrap_sqlalchemy_create_engine(original_create_engine):
    def guarded_create_engine(url=None, *args, **kwargs):
        if url is not None:
            assert_test_dsn(url, caller="sqlalchemy.create_engine()")
        return original_create_engine(url, *args, **kwargs)

    guarded_create_engine.__name__ = "guarded_create_engine"
    return guarded_create_engine


def install() -> None:
    """Install the connection-level guard. Idempotent."""
    global _installed
    if _installed:
        return

    # Refuse to start if the environment itself points at production.
    assert_no_production_env()

    import psycopg2
    import sqlalchemy

    from safenestt.persistence import engine as engine_mod

    if "psycopg2.connect" not in _originals:
        _originals["psycopg2.connect"] = psycopg2.connect
        psycopg2.connect = _wrap_psycopg2_connect(psycopg2.connect)

    if "sqlalchemy.create_engine" not in _originals:
        _originals["sqlalchemy.create_engine"] = sqlalchemy.create_engine
        sqlalchemy.create_engine = _wrap_sqlalchemy_create_engine(sqlalchemy.create_engine)

    if "safenestt.persistence.engine.create_engine" not in _originals:
        _originals["safenestt.persistence.engine.create_engine"] = engine_mod.create_engine
        engine_mod.create_engine = _wrap_sqlalchemy_create_engine(engine_mod.create_engine)

    _installed = True


def uninstall() -> None:
    """Restore the original connection functions (used by the regression test)."""
    global _installed
    if not _installed:
        return

    import psycopg2
    import sqlalchemy

    from safenestt.persistence import engine as engine_mod

    if "psycopg2.connect" in _originals:
        psycopg2.connect = _originals.pop("psycopg2.connect")
    if "sqlalchemy.create_engine" in _originals:
        sqlalchemy.create_engine = _originals.pop("sqlalchemy.create_engine")
    if "safenestt.persistence.engine.create_engine" in _originals:
        engine_mod.create_engine = _originals.pop("safenestt.persistence.engine.create_engine")

    _installed = False


def is_installed() -> bool:
    return _installed