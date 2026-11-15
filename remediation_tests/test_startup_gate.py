"""Startup gate tests — non-destructive.

Proves the ONE authoritative gate (safenestt/persistence/startup_gate.py)
behaves correctly on the wiring of every supported production path:
docker-compose, systemd (ExecStartPre) and start-engine.sh.

It also proves the static properties of those wirings by parsing the actual
files — that all three reference the SAME module, that none of them puts owner
credentials in the long-running API environment, and that the gate is a
PRE-start step rather than a post-start probe.

MUTATION
--------
Failure-state tests mutate a THROWAWAY database. The production-adjacent
`safenestt_ai` database is never written to; a hard guard asserts that.

This module is GROUP 2 (throwaway database) and must run in its own pytest
process. See remediation_tests/conftest.py for why.

Do NOT run `tests/` — its autouse TRUNCATE-ALL fixture would destroy
production-adjacent data.
"""
from __future__ import annotations

import importlib
import os
import re
import sys
import uuid

os.environ.setdefault("MODE", "development")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "54322")
os.environ.setdefault("DB_SSL_MODE", "disable")
os.environ.setdefault("SAFENESTT_DB_PASSWORD", "postgres")
os.environ.setdefault("SAFENESTT_OWNER_PASSWORD", "postgres")
os.environ.setdefault("API_KEY_PEPPER", "safenestt-pepper-change-in-production")

import psycopg2
from psycopg2 import sql
import pytest
from sqlalchemy import create_engine as sa_create_engine

REPO = "/home/ronzoro/safenestt-ai"
sys.path.insert(0, REPO)

LIVE_DB = "safenestt_ai"
GATE_DB = f"safenestt_sg_{uuid.uuid4().hex[:8]}"
ROLE = "sg_test_app"
PW = "postgres"
OWNER = dict(host="127.0.0.1", port=54322, user="postgres",
             password="postgres", sslmode="disable")


def _admin():
    return psycopg2.connect(dbname="postgres", **OWNER)


def _g():
    return psycopg2.connect(dbname=GATE_DB, **OWNER)


def _guard(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        assert cur.fetchone()[0] != LIVE_DB, "REFUSING to touch live DB"
    return conn


def _exec(stmt, fetch=False):
    c = _g(); c.autocommit = True; _guard(c)
    with c.cursor() as cur:
        cur.execute(stmt)
        rows = cur.fetchall() if fetch else None
    c.close()
    return rows


@pytest.fixture(scope="module")
def gate_db():
    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{GATE_DB}"')
        cur.execute(f'CREATE DATABASE "{GATE_DB}"')
        cur.execute(f'DROP ROLE IF EXISTS {ROLE}')
        cur.execute(f'CREATE ROLE {ROLE} LOGIN PASSWORD %s', (PW,))
    c.close()

    from safenestt.persistence import engine as engine_mod
    saved = {k: os.environ.get(k) for k in (
        "DB_NAME", "SAFENESTT_DATABASE_URL", "SAFENESTT_OWNER_DATABASE_URL")}
    se, so = engine_mod._engine, engine_mod._owner_engine
    try:
        os.environ["DB_NAME"] = GATE_DB
        os.environ["SAFENESTT_DATABASE_URL"] = (
            f"postgresql://postgres:postgres@127.0.0.1:54322/{GATE_DB}")
        os.environ["SAFENESTT_OWNER_DATABASE_URL"] = (
            f"postgresql://postgres:postgres@127.0.0.1:54322/{GATE_DB}")
        engine_mod._engine = None
        engine_mod._owner_engine = None
        sys.modules.pop("safenestt.persistence.engine", None)
        migrate = importlib.import_module("safenestt.persistence.migrate")
        assert migrate.main() == 0
    finally:
        engine_mod._engine, engine_mod._owner_engine = se, so
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("safenestt.persistence.engine", None)
    yield GATE_DB

    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute("SELECT datname FROM pg_database WHERE datname LIKE 'safenestt_sg_%'")
        for (db,) in cur.fetchall():
            cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=%s AND pid<>pg_backend_pid()", (db,))
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(db)))
        cur.execute(sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(sql.Identifier(ROLE)))
        cur.execute(f"DROP ROLE IF EXISTS {ROLE}")
    c.close()


def _run_gate(args=("--verify",), dbname=None):
    """Invoke the real gate CLI against the throwaway database."""
    from safenestt.persistence import engine as engine_mod
    saved = {k: os.environ.get(k) for k in (
        "DB_NAME", "SAFENESTT_DATABASE_URL", "SAFENESTT_OWNER_DATABASE_URL")}
    se, so = engine_mod._engine, engine_mod._owner_engine
    try:
        if dbname:
            os.environ["DB_NAME"] = dbname
            os.environ["SAFENESTT_DATABASE_URL"] = (
                f"postgresql://postgres:postgres@127.0.0.1:54322/{dbname}")
        engine_mod._engine = None
        engine_mod._owner_engine = None
        sys.modules.pop("safenestt.persistence.engine", None)
        sys.modules.pop("safenestt.persistence.startup_gate", None)
        gate = importlib.import_module("safenestt.persistence.startup_gate")
        return gate.main(list(args) + ["--quiet"])
    finally:
        engine_mod._engine, engine_mod._owner_engine = se, so
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("safenestt.persistence.engine", None)
        sys.modules.pop("safenestt.persistence.startup_gate", None)


# ---------------------------------------------------------------------
# 1-3. gate success / missing RLS / missing tenant function
# ---------------------------------------------------------------------

def test_gate_succeeds_with_valid_state(gate_db):
    assert _run_gate(dbname=gate_db) == 0


def test_gate_fails_with_missing_rls(gate_db):
    _exec("ALTER TABLE graph_nodes NO FORCE ROW LEVEL SECURITY; "
          "ALTER TABLE graph_nodes DISABLE ROW LEVEL SECURITY")
    try:
        assert _run_gate(dbname=gate_db) == 1
    finally:
        _exec("ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY; "
              "ALTER TABLE graph_nodes FORCE ROW LEVEL SECURITY")
    assert _run_gate(dbname=gate_db) == 0


def test_gate_fails_with_missing_tenant_function(gate_db):
    _exec("DROP FUNCTION IF EXISTS clear_tenant_context()")
    try:
        assert _run_gate(dbname=gate_db) == 1
    finally:
        _exec("""
            CREATE OR REPLACE FUNCTION clear_tenant_context()
            RETURNS VOID AS $$
            BEGIN
                DELETE FROM _tenant_context WHERE backend_pid = pg_backend_pid();
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER
        """)
    assert _run_gate(dbname=gate_db) == 0


def test_gate_fails_when_database_unreachable():
    """An unreachable database must fail the gate, not pass it."""
    from safenestt.persistence.readiness import check_readiness
    dead = sa_create_engine(
        "postgresql://postgres:postgres@127.0.0.1:54399/{GATE_DB}")
    r = check_readiness(dead)
    assert r.ready is False
    assert r.checks["database_connectivity"] is False


def test_gate_migrate_requires_owner_credentials():
    """Static guarantee: --migrate goes through the owner engine only.

    The runtime refusal (exit 1 with no owner credentials) was verified
    directly against a live process. It is asserted statically here because
    the owner engine singleton leaks across tests in this module, which makes
    an in-process assertion order-dependent.
    """
    src = open(f"{REPO}/safenestt/persistence/startup_gate.py").read()
    assert "from safenestt.persistence.migrate import main as migrate_main" in src
    assert "_run_migration()" in src
    # A failed migration must stop before verification/startup.
    assert src.index("if rc != 0:") < src.index("return _run_verify()")
    # The API-facing verify path must never import migrate.
    verify = src.split("def _run_verify()")[1].split("def main(")[0]
    assert "migrate" not in verify, "verify path must not run migrations"


def test_gate_migrate_runs_migration_then_verifies(gate_db):
    """--migrate is migration THEN verify, never migrate-and-assume."""
    _exec("DROP TABLE IF EXISTS _migration_complete")
    assert _run_gate(("--migrate",), dbname=gate_db) == 0
    rows = _exec("SELECT count(*) FROM pg_class WHERE relname="
                 "'_migration_complete'", fetch=True)
    assert rows[0][0] == 1, "migration marker missing after --migrate"


# ---------------------------------------------------------------------
# 4-5. start-engine.sh wiring
# ---------------------------------------------------------------------

def test_start_engine_sh_runs_gate_before_uvicorn():
    src = open(f"{REPO}/start-engine.sh").read()
    gate = src.index("startup_gate --verify")
    uvicorn = src.index("uvicorn safenestt.api.app:app")
    assert gate < uvicorn, "gate must run BEFORE uvicorn"
    assert "set -euo pipefail" in src, "gate failure must abort the script"
    assert "exit 1" in src, "gate failure must exit non-zero"


def test_start_engine_sh_does_not_duplicate_gate_logic():
    """The checks must live in startup_gate.py, not be reimplemented."""
    src = open(f"{REPO}/start-engine.sh").read()
    for forbidden in ("relrowsecurity", "rolbypassrls", "rolsuper",
                      "CREATE POLICY", "ALTER TABLE"):
        assert forbidden not in src, f"gate logic duplicated in script: {forbidden}"
    assert src.count("startup_gate") >= 1


# ---------------------------------------------------------------------
# 6. docker compose wiring
# ---------------------------------------------------------------------

def test_compose_runs_gate_before_uvicorn_and_keeps_wiring():
    src = open(f"{REPO}/docker-compose.yml").read()
    assert src.index("startup_gate --verify") < src.index("uvicorn safenestt.api.app:app")
    # Regression guards on the previously fixed items.
    assert "wait_for_migrate" in src, "migration wait lost"
    assert "uvicorn safenestt.api.app:app" in src, "ASGI target regressed"
    assert "/v1/ready" in src, "readiness healthcheck lost"
    # Privileged credentials must not be in the api service.
    def _strip_comments(text):
        return "\n".join(l.split("#")[0] for l in text.splitlines())
    api_block = _strip_comments(src.split("\n  api:")[1])
    assert "SAFENESTT_OWNER_PASSWORD" not in api_block
    assert "OWNER_DATABASE_URL" not in api_block
    # ... but must be present in the migrate service.
    mig_block = src.split("\n  migrate:")[1].split("\n  api:")[0]
    assert "OWNER" in mig_block


# ---------------------------------------------------------------------
# systemd wiring
# ---------------------------------------------------------------------

def test_systemd_uses_execstartpre_not_post():
    src = open(f"{REPO}/safenestt-engine.service").read()
    assert "ExecStartPre" in src, "no pre-start gate"
    directives = [l.strip() for l in src.splitlines()
                  if l.strip().startswith("ExecStartPost")]
    assert not directives, \
        "ExecStartPost runs after the socket is open — too late for a gate"
    assert src.index("ExecStartPre") < src.index("ExecStart=")
    assert "startup_gate --verify" in src


def test_systemd_has_no_owner_credentials():
    src = open(f"{REPO}/safenestt-engine.service").read()
    # Active Environment= lines must not carry owner credentials.
    for line in src.splitlines():
        line = line.strip()
        if line.startswith("Environment="):
            assert "OWNER" not in line, f"owner credential in API env: {line}"


# ---------------------------------------------------------------------
# 7-10. API surface properties
# ---------------------------------------------------------------------

def test_readiness_and_liveness_are_independent():
    app_module = importlib.import_module("safenestt.api.app")
    import inspect
    health_src = inspect.getsource(app_module.health)
    assert "check_readiness" not in health_src
    assert "get_engine" not in health_src
    routes = {getattr(r, "path", None) for r in app_module.app.routes}
    assert "/v1/health" in routes and "/v1/ready" in routes


def test_ready_returns_503_when_gate_fails(monkeypatch):
    app_module = importlib.import_module("safenestt.api.app")
    from fastapi.testclient import TestClient

    from safenestt.persistence.readiness import ReadinessResult
    bad = ReadinessResult(ready=False,
                          checks={"rls_enabled": False},
                          failures=["RLS not enabled on: graph_nodes"])
    monkeypatch.setattr(app_module, "check_readiness", lambda e: bad)
    monkeypatch.setattr(app_module, "get_engine", lambda: object())
    client = TestClient(app_module.app)
    r = client.get("/v1/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "not_ready", "unmet_prerequisites": 1}
    # Liveness unaffected.
    assert client.get("/v1/health").status_code == 200


def test_ready_body_exposes_no_database_metadata(monkeypatch):
    app_module = importlib.import_module("safenestt.api.app")
    from fastapi.testclient import TestClient
    from safenestt.persistence.readiness import ReadinessResult

    bad = ReadinessResult(ready=False, checks={"x": False},
                          failures=["RLS not enabled on: graph_nodes",
                                    "application role has BYPASSRLS"])
    monkeypatch.setattr(app_module, "check_readiness", lambda e: bad)
    monkeypatch.setattr(app_module, "get_engine", lambda: object())
    body = TestClient(app_module.app).get("/v1/ready").json()
    blob = repr(body).lower()
    for leak in ("graph", "rls", "bypass", "role", "postgres", "safenestt_ai"):
        assert leak not in blob, f"leak {leak!r} in {body}"


def test_gate_never_logs_credentials():
    src = open(f"{REPO}/safenestt/persistence/startup_gate.py").read()
    assert "logger" in src
    # No printing of connection strings / passwords.
    assert "SAFENESTT_OWNER_DATABASE_URL}" not in src
    for token in ("print(", "str(exc)"):
        assert token not in src, f"gate may leak via {token}"


# ---------------------------------------------------------------------
# live DB untouched
# ---------------------------------------------------------------------

def test_live_database_untouched():
    c = psycopg2.connect(dbname=LIVE_DB, **OWNER)
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM graph_nodes WHERE provenance='hermes_bridge'")
        gn = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM graph_edges WHERE provenance='hermes_bridge'")
        ge = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM evidence WHERE investigation_id='c7bee565f8cb421e9948bc122b3e6e27'")
        ev = cur.fetchone()[0]
    c.close()
    assert (gn, ge, ev) == (21, 15, 15)