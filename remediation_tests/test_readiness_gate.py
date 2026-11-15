"""Readiness gate tests — non-destructive.

Proves the gate PASSES on a healthy database and FAILS for each specific
security regression, and that liveness stays independent of readiness.

ISOLATION
---------
These tests MUTATE a throwaway database (they disable RLS, drop policies,
flip role attributes and then restore them). The production-adjacent
`safenestt_ai` database is never written to; a hard guard asserts that at
every entry point.

This module belongs to GROUP 2 (throwaway database). It must run in its own
pytest process alongside the other throwaway-database modules — see the note
in remediation_tests/conftest.py. Do NOT merge it with the live-database
modules.

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
from sqlalchemy import create_engine as sa_create_engine, text

LIVE_DB = "safenestt_ai"
GATE_DB = f"safenestt_gate_{uuid.uuid4().hex[:8]}"
GATE_ROLE = "gate_test_app"
GATE_PW = "postgres"

OWNER = dict(host="127.0.0.1", port=54322, user="postgres",
             password="postgres", sslmode="disable")


def _admin():
    return psycopg2.connect(dbname="postgres", **OWNER)


def _gate():
    return psycopg2.connect(dbname=GATE_DB, **OWNER)


def _guard(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        name = cur.fetchone()[0]
    assert name != LIVE_DB, f"REFUSING TO RUN against {LIVE_DB}"
    return name


def _engine():
    return sa_create_engine(
        f"postgresql://postgres:postgres@127.0.0.1:54322/{GATE_DB}")


def _check():
    from safenestt.persistence.readiness import check_readiness
    return check_readiness(_engine(), app_role=GATE_ROLE)


@pytest.fixture(scope="module")
def healthy_db():
    """Throwaway database bootstrapped to a fully healthy security state."""
    c = _admin(); c.autocommit = True
    with c.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{GATE_DB}"')
        cur.execute(f'CREATE DATABASE "{GATE_DB}"')
        cur.execute(f'DROP ROLE IF EXISTS {GATE_ROLE}')
        cur.execute(f'CREATE ROLE {GATE_ROLE} LOGIN PASSWORD %s', (GATE_PW,))
    c.close()

    # Bootstrap through the real owner path.
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
        assert migrate.main() == 0, "bootstrap failed"
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
        cur.execute("SELECT datname FROM pg_database WHERE datname LIKE 'safenestt_gate_%'")
        for (db,) in cur.fetchall():
            cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=%s AND pid<>pg_backend_pid()", (db,))
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
                sql.Identifier(db)))
        cur.execute(sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(
            sql.Identifier(GATE_ROLE)))
        cur.execute(f'DROP ROLE IF EXISTS {GATE_ROLE}')
    c.close()


def _exec(sqltext, fetch=False):
    c = _gate(); c.autocommit = True; _guard(c)
    with c.cursor() as cur:
        cur.execute(sqltext)
        rows = cur.fetchall() if fetch else None
    c.close()
    return rows


# ---------------------------------------------------------------------
# 1. healthy -> PASS
# ---------------------------------------------------------------------

def test_healthy_database_is_ready(healthy_db):
    r = _check()
    assert r.ready is True, f"unexpected failures: {r.failures}"
    assert all(r.checks.values()), r.checks
    assert r.public_body() == {"status": "ready", "unmet_prerequisites": 0}


def test_public_body_leaks_no_database_metadata(healthy_db):
    body = _check().public_body()
    assert set(body) == {"status", "unmet_prerequisites"}
    blob = repr(body).lower()
    for leak in ("safenestt", "postgres", "graph_", "rls", "pg_", "role"):
        assert leak not in blob, f"public body leaks {leak!r}: {body}"


# ---------------------------------------------------------------------
# 2-8. failure states (each mutates then restores)
# ---------------------------------------------------------------------

def test_missing_tenant_function_fails(healthy_db):
    """Dropping a tenant function must fail the gate — then restore it.

    RESTORATION IS ESSENTIAL: without it every later test in this module
    fails, because the gate correctly keeps reporting tenant_functions=False.
    """
    _exec("DROP FUNCTION IF EXISTS clear_tenant_context()")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["tenant_functions"] is False
        assert any("clear_tenant_context" in f for f in r.failures)
    finally:
        _exec("""
            CREATE OR REPLACE FUNCTION clear_tenant_context()
            RETURNS VOID AS $$
            BEGIN
                DELETE FROM _tenant_context WHERE backend_pid = pg_backend_pid();
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER
        """)
    assert _check().ready is True, "restore failed — later tests would cascade"


def test_rls_disabled_on_required_table_fails(healthy_db):
    _exec("ALTER TABLE graph_nodes NO FORCE ROW LEVEL SECURITY; "
          "ALTER TABLE graph_nodes DISABLE ROW LEVEL SECURITY")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["rls_enabled"] is False
    finally:
        _exec("ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY; "
              "ALTER TABLE graph_nodes FORCE ROW LEVEL SECURITY")
    assert _check().ready is True


def test_force_rls_disabled_fails(healthy_db):
    _exec("ALTER TABLE graph_edges NO FORCE ROW LEVEL SECURITY")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["force_rls_enabled"] is False
    finally:
        _exec("ALTER TABLE graph_edges FORCE ROW LEVEL SECURITY")
    assert _check().ready is True


def test_missing_tenant_policy_fails(healthy_db):
    _exec("DROP POLICY IF EXISTS graph_nodes_tenant_isolation ON graph_nodes")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["tenant_policies"] is False
    finally:
        _exec("""CREATE POLICY graph_nodes_tenant_isolation ON graph_nodes
                 FOR ALL
                 USING (investigation_id IN (
                     SELECT investigation_id FROM investigations
                     WHERE tenant_id = get_current_tenant()))
                 WITH CHECK (investigation_id IN (
                     SELECT investigation_id FROM investigations
                     WHERE tenant_id = get_current_tenant()))""")
    assert _check().ready is True


def test_app_role_bypassrls_fails(healthy_db):
    _exec(f"ALTER ROLE {GATE_ROLE} BYPASSRLS")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["app_role_not_bypassrls"] is False
    finally:
        _exec(f"ALTER ROLE {GATE_ROLE} NOBYPASSRLS")
    assert _check().ready is True


def test_app_role_superuser_fails(healthy_db, monkeypatch):
    """A superuser app role must fail the gate.

    `postgres` on this server is NOT a superuser (rolsuper=false), so it
    cannot grant SUPERUSER to another role. We therefore point the gate at a
    role that genuinely has it, proving the check fires, and assert the live
    app role is NOT one of them.
    """
    from safenestt.persistence.readiness import check_readiness
    rows = _exec("SELECT rolname FROM pg_roles WHERE rolsuper", fetch=True)
    assert rows, "server has no superuser to test against"
    super_role = rows[0][0]
    r = check_readiness(_engine(), app_role=super_role)
    assert r.ready is False
    assert r.checks["app_role_not_superuser"] is False

    # And the healthy role must still pass.
    assert check_readiness(_engine(), app_role=GATE_ROLE).ready is True


def test_missing_table_fails(healthy_db):
    _exec("ALTER TABLE graph_edges RENAME TO graph_edges_hidden")
    try:
        r = _check()
        assert r.ready is False
        assert r.checks["required_tables"] is False
    finally:
        _exec("ALTER TABLE graph_edges_hidden RENAME TO graph_edges")
    assert _check().ready is True


# ---------------------------------------------------------------------
# 8. database unavailable
# ---------------------------------------------------------------------

def test_database_unavailable_fails_closed():
    from safenestt.persistence.readiness import check_readiness
    # Port with nothing listening -> connection refused.
    dead = sa_create_engine(
        "postgresql://postgres:postgres@127.0.0.1:54399/{GATE_DB}")
    r = check_readiness(dead)
    assert r.ready is False
    assert r.checks["database_connectivity"] is False
    assert r.public_body()["status"] == "not_ready"


# ---------------------------------------------------------------------
# 9. liveness independent from readiness
# ---------------------------------------------------------------------

def test_liveness_does_not_consult_database():
    """/v1/health must not depend on the database; /v1/ready must."""
    import inspect
    app_module = importlib.import_module("safenestt.api.app")
    src = inspect.getsource(app_module.health)
    assert "check_readiness" not in src
    assert "get_engine" not in src, "liveness must not touch the database"
    routes = {getattr(r, "path", None) for r in app_module.app.routes}
    assert "/v1/ready" in routes, "readiness endpoint not registered"


def test_ready_endpoint_returns_503_when_not_ready(monkeypatch):
    """The HTTP surface must withhold traffic."""
    import importlib as _il
    app_module = _il.import_module("safenestt.api.app")
    from fastapi.testclient import TestClient

    class _Dead:
        def connect(self):
            raise RuntimeError("database down")

    dead = type("E", (), {"connect": lambda self: (_ for _ in ()).throw(
        RuntimeError("database down"))})()
    monkeypatch.setattr(app_module, "get_engine", lambda: dead)
    client = TestClient(app_module.app)
    r = client.get("/v1/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "not_ready"
    # Liveness must still be OK.
    assert client.get("/v1/health").status_code == 200


# ---------------------------------------------------------------------
# 10. migration -> readiness eventually PASS
# ---------------------------------------------------------------------

def test_migration_creates_marker_then_ready(healthy_db):
    """After migrate.main(), the marker exists AND readiness passes."""
    _exec("DROP TABLE IF EXISTS _migration_complete")
    assert _exec("SELECT count(*) FROM pg_class WHERE relname="
                 "'_migration_complete'", fetch=True)[0][0] == 0

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

    # Marker present -> wait_for_migrate would succeed.
    rows = _exec("SELECT count(*) FROM pg_class WHERE relname="
                 "'_migration_complete'", fetch=True)
    assert rows[0][0] == 1, "migrate.main() did not create the marker"
    assert _check().ready is True

    # wait_for_migrate binds create_engine at ITS import time, so both modules
    # must be dropped and re-imported or it keeps the cached engine for the
    # wrong database.
    os.environ["DB_NAME"] = GATE_DB
    sys.modules.pop("safenestt.persistence.engine", None)
    sys.modules.pop("safenestt.persistence.wait_for_migrate", None)
    try:
        from safenestt.persistence.wait_for_migrate import wait_for_migration
        assert wait_for_migration(timeout=5) is True
    finally:
        os.environ["DB_NAME"] = LIVE_DB
        sys.modules.pop("safenestt.persistence.engine", None)
        sys.modules.pop("safenestt.persistence.wait_for_migrate", None)

    assert _check().ready is True


# ---------------------------------------------------------------------
# live database must be untouched
# ---------------------------------------------------------------------

def test_live_database_untouched():
    c = psycopg2.connect(dbname=LIVE_DB, **OWNER)
    with c.cursor() as cur:
        cur.execute("""SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class WHERE relname IN ('graph_nodes','graph_edges')""")
        rows = cur.fetchall()
        cur.execute("SELECT count(*) FROM graph_nodes WHERE provenance='hermes_bridge'")
        gn = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM graph_edges WHERE provenance='hermes_bridge'")
        ge = cur.fetchone()[0]
    c.close()
    assert len(rows) == 2
    for _n, en, fo in rows:
        assert en and fo
    assert gn == 21 and ge == 15, "engine graph data changed"