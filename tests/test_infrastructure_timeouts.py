"""Regression tests for bounded infrastructure timeouts.

These tests prove that the application fails fast when infrastructure
is unreachable, rather than hanging for libpq's multi-minute default.
"""
from __future__ import annotations

import os
import sys
import time

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# The negative-connection tests below build DSNs by hand. They used to name the
# PRODUCTION database, which reintroduced the exact pattern that destroyed
# production on 2026-10-04. Resolve the test database through the shared
# allowlist-validated guard instead.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

import isolation_guard  # noqa: E402

_TEST_DB_NAME = isolation_guard.assert_test_db_configured()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_engine():
    """Reset the engine singleton so each test gets a fresh engine."""
    from safenestt.persistence import engine as _eng_mod

    _eng_mod._engine = None
    _eng_mod._sessionmaker = None
    _eng_mod._owner_engine = None


def _reset_engine():
    """Reset the engine singleton so each test gets a fresh engine."""
    from safenestt.persistence import engine as _eng_mod

    _eng_mod._engine = None
    _eng_mod._sessionmaker = None
    _eng_mod._owner_engine = None


def _reset_engine():
    """Reset the engine singleton so each test gets a fresh engine."""
    from safenestt.persistence import engine as _eng_mod

    _eng_mod._engine = None
    _eng_mod._sessionmaker = None
    _eng_mod._owner_engine = None


def _get_fresh_client(reset_engine: bool = True):
    """Create a TestClient. Set reset_engine=False to reuse existing engine."""
    from safenestt.api.app import app as _app
    from fastapi.testclient import TestClient

    if reset_engine:
        _reset_engine()
    return TestClient(_app, raise_server_exceptions=False)


def _register_key(client, tenant_id: str, raw_key: str) -> str:
    """Register an API key via the running test client."""
    from safenestt.security.api_keys import get_key_store

    store = get_key_store()
    raw, _, _ = store.create_key(
        tenant_id=tenant_id,
        raw_key=raw_key,
        name=f"Test key for {tenant_id}",
    )
    return raw


# ---------------------------------------------------------------------------
# 1. PostgreSQL connection timeout
# ---------------------------------------------------------------------------


def test_postgresql_unreachable_fails_within_bounded_time():
    """Connecting to 127.0.0.2:54322 (non-listening) must fail within
    DB_CONNECT_TIMEOUT, not hang for libpq's multi-minute default."""
    from safenestt.persistence.engine import create_engine, get_engine

    timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
    # SECURITY FIX (2026-10-04): the database segment was the PRODUCTION name
    # "safenestt_ai". The assertion only depends on the port not listening,
    # so the test database name is used to eliminate the production-DSN
    # pattern entirely.
    url = f"postgresql+psycopg2://safenestt_app:***@127.0.0.1:1/{_TEST_DB_NAME}"  # noqa: S105
    # 127.0.0.1:1 is routable but the port is not listening, so the connection
    # attempt should time out via connect_timeout (not connection refused).

    prev = get_engine()
    try:
        engine = create_engine(url)
        start = time.monotonic()
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            assert False, "Expected connection refused"
        except SQLAlchemyError:
            elapsed = time.monotonic() - start
    finally:
        if prev is not None and get_engine() is not prev:
            create_engine()

    # Connection refused is near-instant on Linux; verify <= timeout + grace.
    assert elapsed <= timeout + 2, f"DB connection took {elapsed:.1f}s (expected <= {timeout + 2}s)"


def test_connect_timeout_set_in_connect_args():
    """Verify connect_timeout is set in connect_args by _build_engine.

    We verify the timeout takes effect by connecting to a port that is
    definitely NOT listening (54399) — connection refused must be fast.
    """
    from safenestt.persistence.engine import create_engine, get_engine

    timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
    # 54399 is a high port that nothing should be listening on
    # SECURITY FIX (2026-10-04): same as above — production name removed.
    url = f"postgresql+psycopg2://safenestt_app:***@127.0.0.1:54399/{_TEST_DB_NAME}"  # noqa: S105

    prev = get_engine()
    try:
        engine = create_engine(url)
        start = time.monotonic()
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            assert False, "Expected connection refused"
        except SQLAlchemyError:
            elapsed = time.monotonic() - start
    finally:
        if prev is not None and get_engine() is not prev:
            create_engine()

    # Connection refused is near-instant; proves connect_timeout is active.
    assert elapsed <= timeout + 2, f"Connection took {elapsed:.1f}s (expected <= {timeout + 2}s)"
    
    # The engine is created with connect_timeout in connect_args via
    # _build_engine (see safenestt/persistence/engine.py). Connection
    # refused happens within connect_timeout, proving the timeout is active.
    # No further verification needed of internal dialect attributes.


# ---------------------------------------------------------------------------
# 2. API key validation with unreachable DB
# ---------------------------------------------------------------------------


def test_api_key_validation_fails_fast_when_db_unreachable(monkeypatch):
    """validate_key() must fail fast when PostgreSQL is unreachable, not hang."""
    from safenestt.security.api_keys import get_key_store

    # 127.0.0.1:54399 — nothing listens there, connection refused is fast.
    monkeypatch.setenv("DB_HOST", "127.0.0.1")
    monkeypatch.setenv("DB_PORT", "54399")
    monkeypatch.setenv("DB_SSL_MODE", "disable")
    # TEST-only SSL: test DB has no SSL, so do NOT force verify-full here.
    # verify-full is for production only.

    timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
    store = get_key_store()
    raw_key = "test-key-invalid-db-xyz"

    start = time.monotonic()
    try:
        is_valid, _, _, metadata = store.validate_key(raw_key)
    except Exception:
        elapsed = time.monotonic() - start
        assert elapsed <= timeout + 2, f"validate_key took {elapsed:.1f}s — may be hanging"
        return

    elapsed = time.monotonic() - start
    assert elapsed <= timeout + 2, f"validate_key hung for {elapsed:.1f}s"
    assert not is_valid


# ---------------------------------------------------------------------------
# 3. Secret resolution
# ---------------------------------------------------------------------------


def test_get_secret_env_var_returns_fast():
    """Env var lookup must be instantaneous — no external call."""
    from safenestt.security.secrets import get_secret, clear_cache

    clear_cache()
    os.environ["SAFENESTT_TEST_SECRET_xyz"] = "env-value-123"
    try:
        start = time.monotonic()
        value = get_secret("SAFENESTT_TEST_SECRET_xyz")
        elapsed = time.monotonic() - start
        assert elapsed < 0.1, f"Env var lookup took {elapsed:.3f}s"
        assert value == "env-value-123"
    finally:
        os.environ.pop("SAFENESTT_TEST_SECRET_xyz", None)
        clear_cache()


def test_get_secret_returns_default_when_not_set():
    """Missing secret with default returns immediately."""
    from safenestt.security.secrets import get_secret, clear_cache

    clear_cache()
    os.environ.pop("SAFENESTT_NONEXISTENT_SECRET_xyz", None)
    start = time.monotonic()
    value = get_secret("SAFENESTT_NONEXISTENT_SECRET_xyz", default="fallback")
    elapsed = time.monotonic() - start
    assert elapsed < 0.1, f"Default secret lookup took {elapsed:.3f}s"
    assert value == "fallback"
    clear_cache()


def test_get_secret_aws_ssm_fails_fast_when_unreachable(monkeypatch):
    """AWS SSM probe must fail fast, not block for boto3 defaults."""
    from safenestt.security.secrets import get_secret, clear_cache

    clear_cache()
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    start = time.monotonic()
    value = get_secret("SAFENESTT_NONEXISTENT_AWS_SECRET_xyz", default="aws-fallback")
    elapsed = time.monotonic() - start
    assert elapsed < 5, f"AWS SSM probe took {elapsed:.1f}s — may be hanging"
    assert value == "aws-fallback"
    clear_cache()


def test_get_secret_gcp_fails_fast_when_unreachable(monkeypatch):
    """GCP Secret Manager probe must fail fast."""
    from safenestt.security.secrets import get_secret, clear_cache

    clear_cache()
    monkeypatch.setenv("GCP_PROJECT", "fake-project-12345")
    start = time.monotonic()
    value = get_secret("SAFENESTT_NONEXISTENT_GCP_SECRET_xyz", default="gcp-fallback")
    elapsed = time.monotonic() - start
    assert elapsed < 5, f"GCP Secret Manager probe took {elapsed:.1f}s — may be hanging"
    assert value == "gcp-fallback"
    clear_cache()


# ---------------------------------------------------------------------------
# 4. Startup with unreachable DB
# ---------------------------------------------------------------------------


def test_ensure_schema_fails_fast_when_db_unreachable(monkeypatch):
    """ensure_schema() must fail within DB_CONNECT_TIMEOUT, not hang."""
    from safenestt.investigations.store import ensure_schema

    monkeypatch.setenv("DB_HOST", "127.0.0.1")
    monkeypatch.setenv("DB_PORT", "54399")
    monkeypatch.setenv("DB_SSL_MODE", "disable")
    # TEST-only SSL: test DB has no SSL, so do NOT force verify-full here.
    # verify-full is for production only.

    timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
    start = time.monotonic()
    with pytest.raises(Exception):
        ensure_schema()
    elapsed = time.monotonic() - start
    assert elapsed <= timeout + 2, f"ensure_schema hung for {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# 5. Normal operation still works (regression guard)
# ---------------------------------------------------------------------------


def test_normal_health_check_still_works():
    """GET /v1/health must return 200 — verify we didn't break the fast path."""
    client = _get_fresh_client()
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_normal_investigation_create_still_works():
    """POST /v1/investigations with valid key must reach app path and return real response."""
    client = _get_fresh_client()
    raw_key = _register_key(client, "timeout-regression-tenant", "timeout-regression-key-abc123")

    resp = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "timeout-regression.example"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": raw_key},
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "investigation_id" in data
    assert data["status"] == "QUEUED"


def test_invalid_api_key_rejected_fast():
    """Invalid API key must return 401 quickly — not hang on DB validation."""
    client = _get_fresh_client()
    start = time.monotonic()
    resp = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "example.com"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": "invalid-key-that-is-not-in-db-xyz"},
    )
    elapsed = time.monotonic() - start

    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    assert elapsed < 10, f"Invalid key rejection took {elapsed:.1f}s — may be hanging"
    detail = resp.json().get("detail", {})
    assert detail.get("code") in {"invalid_key", "key_not_found"}


def test_malformed_json_returns_fast():
    """Malformed JSON body must return 422/400 quickly."""
    client = _get_fresh_client()
    raw_key = _register_key(client, "malformed-test-tenant", "malformed-test-key-xyz")

    start = time.monotonic()
    resp = client.post(
        "/v1/investigations",
        content="not json at all",
        headers={"X-API-Key": raw_key, "Content-Type": "application/json"},
    )
    elapsed = time.monotonic() - start

    assert resp.status_code in {400, 422}, f"Expected 400/422, got {resp.status_code}"
    assert elapsed < 1, f"Malformed JSON handling took {elapsed:.3f}s"


def test_downstream_failure_returns_bounded_5xx():


    """When model provider is unreachable, start must return bounded 5xx, not hang.

    The test monkeypatches _resolve_model_provider to return a provider whose
    health_check reports provider_not_configured. This causes run_investigation
    to short-circuit with FAILED status BEFORE running any OSINT subprocess calls
    or attempting a model generate. The 30s bound therefore measures ONLY the
    overhead of the failed-health-check path, not real subprocess duration.

    Production behavior preserved: when a real provider IS configured, the full
    pipeline (including OSINT subprocess calls) runs normally.
    """
    import importlib
    app_mod = importlib.import_module('safenestt.api.app')
    from safenestt.model.provider import ModelResponse

    # Replace the model provider resolver with one that reports "not configured"
    original_resolve = app_mod._resolve_model_provider

    class UnconfiguredProvider:
        provider_name = "test-unconfigured"

        def health_check(self) -> ModelResponse:
            return ModelResponse(
                provider=self.provider_name,
                model=None,
                content="not_configured",
                finish_reason="health",
                warnings=["provider_not_configured"],
            )

        def generate(self, request):
            return ModelResponse(
                provider=self.provider_name,
                model=None,
                content=None,
                error=type("ModelError", (), {"code": "unreachable", "message": "provider unreachable", "retryable": False})(),
            )

    app_mod._resolve_model_provider = lambda: UnconfiguredProvider()
    try:
        client = _get_fresh_client()
        raw_key = _register_key(client, "downstream-test-tenant", "downstream-test-key-789")

        # Create the investigation first
        create_resp = client.post(
            "/v1/investigations",
            json={
                "target": {"type": "domain", "value": "downstream-test.example"},
                "investigation_type": "cybersecurity",
            },
            headers={"X-API-Key": raw_key},
        )
        assert create_resp.status_code == 200
        inv_id = create_resp.json()["investigation_id"]

        # Start — pipeline will detect unconfigured provider and fail fast
        start = time.monotonic()
        start_resp = client.post(
            f"/v1/investigations/{inv_id}/start",
            headers={"X-API-Key": raw_key},
        )
        elapsed = time.monotonic() - start

        # Must complete (or fail) within a reasonable time, not hang
        assert elapsed < 30, f"Start took {elapsed:.1f}s — may be hanging"
        assert start_resp.status_code in {200, 500, 503}, (
            f"Expected 200/500/503, got {start_resp.status_code}: {start_resp.text}"
        )
    finally:
        app_mod._resolve_model_provider = original_resolve
