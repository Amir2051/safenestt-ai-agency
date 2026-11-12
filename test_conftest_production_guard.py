"""Focused tests for the tests/conftest.py production safety guard.

These are the ONLY tests that must be run while the production database is
under incident review. They import nothing from conftest (importing it would
create an engine and connect); they load the guard source and exercise the
decision logic in isolation. No database, no network, no pytest session that
triggers the destructive fixture.

Run:  python3 -m pytest test_conftest_production_guard.py -q
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

CONFTEST = Path("/home/ronzoro/safenestt-ai/tests/conftest.py")
SRC = CONFTEST.read_text()


# ---------------------------------------------------------------- load guard
def _load_guard():
    """Extract the guard's pure decision logic without importing conftest."""
    tree = ast.parse(SRC)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "assert_safe_test_database")
    const_names = {"_ALLOWED_TEST_DB_NAMES", "_PRODUCTION_DB_NAMES", "_ALLOWED_TEST_DB_PREFIXES"}
    mod = ast.Module(body=[fn] + [n for n in tree.body
                                 if isinstance(n, ast.Assign)
                                 and getattr(n.targets[0], "id", "") in const_names],
                     type_ignores=[])
    import os as _real_os
    ns: dict = {"RuntimeError": RuntimeError, "os": _real_os}
    exec(compile(ast.fix_missing_locations(mod), str(CONFTEST), "exec"), ns)
    return ns["assert_safe_test_database"], ns, None


GUARD, CONSTS, _ = _load_guard()


# ------------------------------------------------------------------ A. allowed
def test_a_allows_dedicated_test_database():
    assert GUARD("safenestt_ai_test") == "safenestt_ai_test"


def test_a2_allows_audittest_throwaway():
    assert GUARD("safenestt_audittest_abc123") == "safenestt_audittest_abc123"


def test_a3_allows_via_environment(monkeypatch):
    import os
    monkeypatch.setitem(os.environ, "DB_NAME", "safenestt_ai_test")
    assert GUARD() == "safenestt_ai_test"


# ------------------------------------------------------------------ B. refuse
def test_b_refuses_production_database():
    with pytest.raises(RuntimeError) as e:
        GUARD("safenestt_ai")
    assert "REFUSING DESTRUCTIVE TEST FIXTURE" in str(e.value)
    assert "production database identity" in str(e.value)


def test_b2_refuses_production_via_environment(monkeypatch):
    import os
    monkeypatch.setitem(os.environ, "DB_NAME", "safenestt_ai")
    with pytest.raises(RuntimeError):
        GUARD()


# ------------------------------------------------------------------ C. unknown
@pytest.mark.parametrize("name", [
    "postgres", "safenestt_ai_prod", "safenestt_ai2", "Safenestt_AI_Test", "", "mia_ai",
])
def test_c_refuses_unapproved_database(name):
    with pytest.raises(RuntimeError):
        GUARD(name)


def test_c2_refuses_when_db_name_unset(monkeypatch):
    import os
    monkeypatch.delitem(os.environ, "DB_NAME", raising=False)
    with pytest.raises(RuntimeError) as e:
        GUARD()
    assert "cannot determine target database" in str(e.value)


# ------------------------------------------------------------------ D. ordering
def _fixture_body() -> str:
    tree = ast.parse(SRC)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_clean_test_db")
    # get_source_segment omits decorators; slice the raw source instead so the
    # ordering assertions see the complete function including its docstring.
    lines = SRC.splitlines()
    return "\n".join(lines[fn.lineno - 1 : fn.body[-1].end_lineno])


def test_d_guard_runs_before_owner_engine_and_truncate():
    body = _fixture_body()
    guard_at = body.index("assert_safe_test_database()")
    engine_at = body.index("get_owner_engine()")
    truncate_at = body.index("TRUNCATE TABLE")  # the statement, not a comment
    assert guard_at < engine_at, "guard must precede get_owner_engine()"
    assert guard_at < truncate_at, "guard must precede TRUNCATE"


def test_d2_conftest_no_longer_forces_production_db_name():
    assert 'os.environ["DB_NAME"] = "safenestt_ai"' not in SRC
    assert "SAFENESTT_TEST_DB_NAME" in SRC


def test_d3_destructive_fixture_still_present():
    """Requirement 8: the fixture must remain for legitimate isolated test DBs."""
    body = _fixture_body()
    assert "TRUNCATE TABLE" in body
    assert "Base.metadata.sorted_tables" in body


# ------------------------------------------------------------------ robustness
def test_guard_is_fail_closed_on_prefix_typo():
    """A near-miss prefix must not be accepted."""
    with pytest.raises(RuntimeError):
        GUARD("safenestt_audittest")


def test_production_name_present_in_denylist():
    assert "safenestt_ai" in CONSTS["_PRODUCTION_DB_NAMES"]
    assert "safenestt_ai" not in CONSTS["_ALLOWED_TEST_DB_NAMES"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "--no-header"]))
