"""HTTPS redirect middleware — real HTTP-to-HTTPS redirect coverage.

The `enforce_https` middleware (api/app.py) redirects HTTP -> HTTPS in
production (MODE=production, 308 status). This test proves the redirect
fires on a real HTTP request rather than only on paper.

MODE=production is activated for this test only; the module-level
`_validate_production_security()` check uses a patched
`is_encryption_enabled` so the suite cannot fail before a key exists.
"""
from unittest import mock

import os
import pytest
from fastapi.testclient import TestClient

from safenestt.api.app import app


@pytest.fixture
def client_prod(monkeypatch):
    monkeypatch.setenv("MODE", "production")
    # Production mode would hard-fail at import without an encryption key;
    # patch it closed so this test can exercise the redirect middleware only.
    with mock.patch("safenestt.api.app.is_encryption_enabled", return_value=True):
        # Do NOT follow redirects: the middleware returns a 308 and we must
        # assert on the redirect itself, not on the https endpoint it lands on.
        yield TestClient(app, base_url="http://localhost", follow_redirects=False)


def test_https_redirect_prod_mode(client_prod):
    """HTTP request in production must be redirected to HTTPS (308)."""
    resp = client_prod.get("/v1/health", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 308
    assert resp.headers["location"] == "https://localhost/v1/health"
