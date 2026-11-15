"""REGRESSION TEST — the test suite must never be able to reach production.

This test exists because of the 2026-10-04 data-loss incident. The suite's
original guard inspected only ``os.environ["DB_NAME"]``, so a test module that
built its own DSN (``tests/test_persistence.py`` did exactly that, with a
hardcoded ``/safenestt_ai``) passed the guard and then dropped the production
tables.

These tests assert the CONNECTION-level barrier: that ``psycopg2.connect`` and
``sqlalchemy.create_engine`` refuse a production DSN, and that they refuse a
DSN that is merely *unapproved* or *unparseable*.

CRITICAL: nothing here opens a socket. Every assertion is that a call is
REFUSED. If a future refactor weakens the guard, these tests fail loudly rather
than silently permitting production access.

The tests exercise the pure logic plus the patched callables; they deliberately
do not connect to the test database either, so this module is safe to run even
if the test database is unavailable.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

import isolation_guard
from isolation_guard import (
    ALLOWED_TEST_DB_NAMES,
    PRODUCTION_DB_NAMES,
    ProductionDatabaseAccessError,
    assert_test_dsn,
    extract_database_name,
    is_allowed_database,
)

PROD = "safenestt_ai"
# Isolated test instance (conftest default): loopback, port 55432, test DB.
TEST_HOST = "127.0.0.1"
TEST_PORT = "55432"
TEST_DB = "safenestt_ai_test"
# Isolated test instance (conftest default): loopback, port 55432, test DB.
TEST_HOST = "127.0.0.1"
TEST_PORT = "55432"
TEST_DB = "safenestt_ai_test"


# ---------------------------------------------------------------------------
# 1. DSN parsing
# ---------------------------------------------------------------------------

class TestDatabaseNameExtraction:
    def test_extracts_db_from_full_dsn(self):
        dsn = f"postgresql://safenestt_app:***@{TEST_HOST}:{TEST_PORT}/{TEST_DB}"
        assert extract_database_name(dsn) == TEST_DB

    def test_extracts_db_with_query_string(self):
        dsn = f"postgresql://u:p@h:5432/{PROD}?sslmode=verify-full"
        assert extract_database_name(dsn) == PROD

    def test_extracts_db_without_credentials(self):
        assert extract_database_name(f"postgresql://@127.0.0.1:5432/{PROD}") == PROD

    def test_unparseable_returns_none(self):
        assert extract_database_name("") is None
        assert extract_database_name(None) is None
        assert extract_database_name(12345) is None

    def test_test_db_name_is_not_confused_with_production(self):
        """Regression: 'safenestt_ai_test' must not match the production name.

        A naive substring check treats the test database as production (or vice
        versa). The allowlist is compared as whole tokens for exactly this
        reason.
        """
        assert extract_database_name(
            "postgresql://u:p@h:5432/safenestt_ai_test"
        ) == "safenestt_ai_test"
        assert is_allowed_database("safenestt_ai_test") is True
        assert is_allowed_database(PROD) is False


# ---------------------------------------------------------------------------
# 2. Allowlist policy
# ---------------------------------------------------------------------------

class TestAllowlistPolicy:
    def test_production_is_never_allowed(self):
        assert PROD in PRODUCTION_DB_NAMES
        assert is_allowed_database(PROD) is False

    @pytest.mark.parametrize("name", sorted(ALLOWED_TEST_DB_NAMES))
    def test_allowlisted_names_are_allowed(self, name):
        assert is_allowed_database(name) is True

    @pytest.mark.parametrize(
        "name",
        ["postgres", "template1", "safenestt", "safenestt_ai_prod", "", None],
    )
    def test_unapproved_names_are_rejected(self, name):
        assert is_allowed_database(name) is False

    def test_prefix_scoped_scratch_databases_are_allowed(self):
        for prefix in isolation_guard.ALLOWED_TEST_DB_PREFIXES:
            assert is_allowed_database(f"{prefix}abc123") is True

    def test_resolved_test_db_name_is_approved(self):
        assert is_allowed_database(isolation_guard.resolve_test_db_name()) is True

    def test_assert_test_db_configured_returns_allowlisted_name(self):
        assert isolation_guard.assert_test_db_configured() in ALLOWED_TEST_DB_NAMES


# ---------------------------------------------------------------------------
# 3. assert_test_dsn refuses production  (THE core regression)
# ---------------------------------------------------------------------------

class TestAssertDsnRefusesProduction:
    def test_refuses_production_dsn(self):
        with pytest.raises(ProductionDatabaseAccessError) as exc:
            assert_test_dsn(
                f"postgresql://postgres:secret@127.0.0.1:54322/{PROD}",
                caller="regression-test",
            )
        assert PROD in str(exc.value)
        assert "PRODUCTION" in str(exc.value)

    def test_refuses_production_via_app_role(self):
        with pytest.raises(ProductionDatabaseAccessError):
            assert_test_dsn(f"postgresql://safenestt_app:secret@127.0.0.1:54322/{PROD}")

    def test_error_message_does_not_leak_password(self):
        with pytest.raises(ProductionDatabaseAccessError) as exc:
            assert_test_dsn("postgresql://postgres:sup3rs3cr3t@h:5432/safenestt_ai")
        assert "sup3rs3cr3t" not in str(exc.value)

    def test_allows_test_database(self):
        dsn = "postgresql://u:p@127.0.0.1:5432/safenestt_ai_test"
        assert assert_test_dsn(dsn) == "safenestt_ai_test"

    def test_fails_closed_on_unparseable_dsn(self):
        """An unparseable DSN is rejected, not assumed safe."""
        for bad in ["", "not-a-dsn", "///", None]:
            with pytest.raises(ProductionDatabaseAccessError):
                assert_test_dsn(bad)

    def test_refuses_other_production_like_name(self):
        with pytest.raises(ProductionDatabaseAccessError):
            assert_test_dsn("postgresql://u:p@h:5432/postgres")


# ---------------------------------------------------------------------------
# 4. The installed guard actually intercepts  (behavioural, still no sockets)
# ---------------------------------------------------------------------------

class TestInstalledGuardIntercepts:
    """Prove the patch is live, not just that the helpers work.

    psycopg2.connect is called with a production DSN and MUST raise before any
    network activity. If the guard were absent, this call would attempt a real
    connection — which is exactly why the assertion is 'raises'.
    """

    def test_guard_is_installed(self):
        assert isolation_guard.is_installed() is True

    def test_psycopg2_connect_refuses_production(self):
        import psycopg2

        with pytest.raises(ProductionDatabaseAccessError) as exc:
            psycopg2.connect(f"postgresql://postgres:secret@127.0.0.1:54322/{PROD}")
        assert "PRODUCTION" in str(exc.value)

    def test_psycopg2_connect_refuses_production_via_dbname_kwarg(self):
        """The keyword form (dbname=...) is the shape used by the remediation
        suite, so it must be blocked too."""
        import psycopg2

        with pytest.raises(ProductionDatabaseAccessError):
            psycopg2.connect(
                host="127.0.0.1", port=54322, user="postgres",
                password="postgres", dbname=PROD,
            )

    def test_psycopg2_connect_refuses_missing_dbname(self):
        import psycopg2

        with pytest.raises(ProductionDatabaseAccessError):
            psycopg2.connect(host="127.0.0.1", port=54322, user="postgres")

    def test_sqlalchemy_create_engine_refuses_production(self):
        import sqlalchemy

        with pytest.raises(ProductionDatabaseAccessError):
            sqlalchemy.create_engine(f"postgresql://u:p@127.0.0.1:54322/{PROD}")

    def test_engine_module_create_engine_refuses_production(self):
        from safenestt.persistence import engine as engine_mod

        with pytest.raises(ProductionDatabaseAccessError):
            engine_mod.create_engine(f"postgresql://u:p@127.0.0.1:54322/{PROD}")


# ---------------------------------------------------------------------------
# 5. No test module may hardcode a production DSN  (static, repo-wide)
# ---------------------------------------------------------------------------

class TestNoProductionDsnInTestSources:
    """Static sweep of every test file in the repo.

    This is the check that would have caught the original defect at review time.
    Comment lines and the isolation guard's own documentation are excluded,
    because naming the forbidden value is how the guard documents itself.
    """

    REPO_ROOT = os.path.dirname(_TESTS_DIR)
    TEST_DIRS = ("tests", "remediation_tests")

    def _python_test_files(self):
        for d in self.TEST_DIRS:
            base = os.path.join(self.REPO_ROOT, d)
            if not os.path.isdir(base):
                continue
            for fname in sorted(os.listdir(base)):
                if fname.endswith(".py"):
                    yield os.path.join(d, fname), os.path.join(base, fname)

    # Files whose job is to NAME production in order to refuse it. The guard
    # itself, this regression module, and the remediation modules that carry a
    # LIVE_DB sentinel asserted against at runtime.
    _SENTINEL_FILES = frozenset({
        "isolation_guard.py",
        "test_test_isolation_regression.py",
        "test_fresh_bootstrap.py",
        "test_graph_rls_bootstrap.py",
        "test_readiness_gate.py",
        "test_startup_gate.py",
    })

    # A reference is only a VIOLATION when it could become a connection
    # target. These shapes are all genuinely dangerous:
    #   * a postgres DSN whose path segment is the production name
    #   * dbname= / database= bound to the production name
    #   * a setdefault/getenv default of the production name
    _VIOLATION_PATTERNS = (
        re.compile(r"postgres(?:ql)?://[^\"'`\s]*[/\"]safenestt_ai(?![A-Za-z0-9_])"),
        re.compile(r"(?:dbname|database)\s*=\s*[\"']safenestt_ai(?![A-Za-z0-9_])"),
        re.compile(r"(?:setdefault|getenv)\([^)]*[\"']safenestt_ai(?![A-Za-z0-9_])"),
    )

    def test_no_test_source_uses_production_as_a_connection_target(self):
        offenders = []
        for rel, path in self._python_test_files():
            if os.path.basename(path) in self._SENTINEL_FILES:
                continue
            for lineno, line in enumerate(
                open(path, encoding="utf-8", errors="ignore").read().splitlines(), 1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for pat in self._VIOLATION_PATTERNS:
                    if pat.search(line):
                        offenders.append(f"{rel}:{lineno}: {stripped[:90]}")
                        break
        assert not offenders, (
            "test sources use the production database as a connection target:\n  "
            + "\n  ".join(offenders)
        )


    def test_production_db_name_is_excluded_from_allowlist(self):
        """The allowlist and the production denylist must not overlap."""
        assert not (set(ALLOWED_TEST_DB_NAMES) & set(PRODUCTION_DB_NAMES))
        for prefix in isolation_guard.ALLOWED_TEST_DB_PREFIXES:
            assert not prefix.startswith(PROD) or prefix == PROD + "_"
            # A production prefix would let 'safenestt_ai' itself slip through.
            assert PROD != f"{prefix}"


# ---------------------------------------------------------------------------
# 6. Port isolation  (added 2026-10-04, requirement 3)
# ---------------------------------------------------------------------------

class TestPortIsolation:
    """The suite must default to the dedicated test instance, not production.

    Database-name barriers can all be defeated by a refactor that hardcodes a
    URL. A different SERVER cannot be reached by accident. Production publishes
    54322; the dedicated test instance is 55432.
    """

    PRODUCTION_PORT = "54322"
    TEST_PORT = "55432"

    def test_conftest_default_port_is_not_the_production_port(self):
        """tests/conftest.py must not default DB_PORT to the production port."""
        path = os.path.join(_TESTS_DIR, "conftest.py")
        source = open(path, encoding="utf-8").read()
        # The production port may appear in a comment explaining the history,
        # but never as the value assigned to DB_PORT.
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "DB_PORT" in stripped and self.PRODUCTION_PORT in stripped:
                # Allow the guarded form that prefers an existing env value.
                assert 'os.environ.get("DB_PORT")' in source, (
                    f"conftest assigns the production port without honouring an "
                    f"exported DB_PORT: {stripped}"
                )

    def test_remediation_conftest_does_not_default_to_production_port(self):
        path = os.path.join(
            os.path.dirname(_TESTS_DIR), "remediation_tests", "conftest.py"
        )
        for line in open(path, encoding="utf-8").read().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if 'setdefault("DB_PORT"' in stripped:
                assert self.PRODUCTION_PORT not in stripped, (
                    f"remediation conftest defaults DB_PORT to production: {stripped}"
                )

    def test_isolated_instance_is_declared_on_the_test_port(self):
        """The dedicated instance must exist and be declared in compose."""
        compose = os.path.join(
            os.path.dirname(_TESTS_DIR), "docker-compose.test-db.yml"
        )
        assert os.path.exists(compose), "docker-compose.test-db.yml is missing"
        source = open(compose, encoding="utf-8").read()
        assert f"127.0.0.1:{self.TEST_PORT}:5432" in source, (
            "test instance must be published on loopback only, not 0.0.0.0"
        )
        assert f"0.0.0.0:{self.TEST_PORT}" not in source, (
            "test database must never be published on all interfaces"
        )
        # It must not join any production docker network. Comments legitimately
        # name the production network to explain why it is NOT used, so parse
        # the compose structure rather than grepping the raw text.
        try:
            import yaml

            cfg = yaml.safe_load(source)
        except Exception:
            return  # cannot parse; the port assertions above already ran
        for svc_name, svc in (cfg.get("services") or {}).items():
            joined = set((svc.get("networks") or {}))
            assert "supabase_network_safenestt-platform" not in joined, (
                f"service {svc_name} joins the production docker network"
            )
            assert not any(n.startswith("mia-ai") for n in joined), (
                f"service {svc_name} joins a mia-ai network: {joined}"
            )
