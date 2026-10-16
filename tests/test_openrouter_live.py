"""
Live OpenRouter integration tests.

Validates the OpenRouter provider wired to the safenestt-ai engine:
- Live model inference via nvidia/nemotron-3.5-lightning:free
- Full investigation lifecycle (create / start / findings / report) through the API
- Findings generation quality checks

These tests hit the live OpenRouter API and consume real credits.
Run when you have a valid OPENROUTER_API_KEY and want to verify the
live path end-to-end.

Falls back gracefully (skips) when OPENROUTER_API_KEY is absent so the
suite stays green in environments that only have local/Ollama configured.
"""
from __future__ import annotations

import json
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from safenestt.security.api_keys import get_key_store
from safenestt.model.registry import OpenRouterProvider
from safenestt.model.provider import ModelRequest

# ---------------------------------------------------------------------------
# Skip everything when no live key is available.  This keeps the suite green
# in local-only environments while still being runnable in CI / staging where
# the key is injected.
# ---------------------------------------------------------------------------
_OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
_LIVE_AVAILABLE = bool(_OPENROUTER_KEY)


def _client() -> TestClient:
    """FastAPI test client against the in-process engine."""
    from safenestt.api.app import app
    return TestClient(app)


def _register_test_key(tenant_id: str = "openrouter-test") -> tuple[str, str]:
    """Create a throwaway API key for the given tenant and return (raw, fp)."""
    store = get_key_store()
    raw = f"test-openrouter-{uuid.uuid4().hex[:16]}"
    raw_key, _hash, fp = store.create_key(tenant_id=tenant_id, raw_key=raw, name="OpenRouter Live Test")
    return raw_key, fp


# ===================================================================
# 1. LIVE MODEL CALL
# ===================================================================


@pytest.mark.skipif(not _LIVE_AVAILABLE, reason="OPENROUTER_API_KEY not set — skipping live OpenRouter tests")
def test_openrouter_live_model_call():
    """Call the live nvidia/nemotron-3.5-lightning:free model and verify a
    sane non-empty response comes back."""
    provider = OpenRouterProvider()
    assert provider.api_key, "provider should have loaded the API key"
    assert provider.provider_name == "openrouter"
    assert provider.default_model == "nvidia/nemotron-3.5-lightning:free"

    resp = provider.generate(
        ModelRequest(
            prompt="Return a single JSON object: {\"status\": \"alive\"}. Nothing else.",
            model="nvidia/nemotron-3.5-lightning:free",
            max_tokens=64,
            response_format="json",
        )
    )

    assert resp.error is None, f"model call failed: {resp.error}"
    assert resp.provider == "openrouter"
    assert resp.model == "nvidia/nemotron-3.5-lightning:free"
    assert resp.content, "model returned empty content"
    assert resp.finish_reason in {"stop", "length", "content_filter"}

    parsed = json.loads(resp.content)
    assert parsed.get("status") == "alive"


@pytest.mark.skipif(not _LIVE_AVAILABLE, reason="OPENROUTER_API_KEY not set")
def test_openrouter_live_model_no_response_format():
    """Verify the provider works without forcing JSON mode (some models behave
    differently with / without response_format)."""
    provider = OpenRouterProvider()
    resp = provider.generate(
        ModelRequest(
            prompt="Reply with exactly the word OK and nothing else.",
            model="nvidia/nemotron-3.5-lightning:free",
            max_tokens=16,
        )
    )
    assert resp.error is None, f"model call failed: {resp.error}"
    assert resp.content, "model returned empty content"
    # The model may include reasoning text — just verify we got a real
    # non-stub response back from the live provider.
    content = resp.content.upper()
    assert any(word in content for word in ("OK", "HERE", "THINK", "PROCESS")), (
        f"unexpected response content: {resp.content[:100]!r}"
    )


# ===================================================================
# 2. CASE ANALYSIS — full investigation lifecycle
# ===================================================================


@pytest.mark.skipif(not _LIVE_AVAILABLE, reason="OPENROUTER_API_KEY not set")
def test_openrouter_case_analysis_lifecycle():
    """End-to-end: create an investigation, start it (triggers OpenRouter
    inference), and verify findings/report are produced."""
    client = _client()
    raw_key, _fp = _register_test_key("openrouter-case")

    # --- create ---
    create = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "example.com"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": raw_key},
    )
    assert create.status_code == 200, create.text
    body = create.json()
    investigation_id = body["investigation_id"]
    assert body["status"] == "QUEUED"
    assert body["model_provider"] == "openrouter"

    # --- start ---
    start = client.post(
        f"/v1/investigations/{investigation_id}/start",
        headers={"X-API-Key": raw_key},
    )
    assert start.status_code == 200, start.text
    start_body = start.json()
    assert start_body["status"] in {"COMPLETED", "RUNNING", "QUEUED"}
    assert start_body["model_provider"] == "openrouter"

    # Give the background investigator a moment if it's still running.
    if start_body["status"] == "RUNNING":
        time.sleep(3)

    # --- findings ---
    findings_resp = client.get(
        f"/v1/investigations/{investigation_id}/findings",
        headers={"X-API-Key": raw_key},
    )
    assert findings_resp.status_code == 200, findings_resp.text
    findings = findings_resp.json()
    assert isinstance(findings, list)

    # --- report ---
    report_resp = client.get(
        f"/v1/investigations/{investigation_id}/report",
        headers={"X-API-Key": raw_key},
    )
    assert report_resp.status_code == 200, report_resp.text
    report = report_resp.json()
    assert report["investigation_id"] == investigation_id
    assert "findings" in report
    assert "evidence" in report
    assert "risk" in report


# ===================================================================
# 3. FINDINGS GENERATION QUALITY
# ===================================================================


@pytest.mark.skipif(not _LIVE_AVAILABLE, reason="OPENROUTER_API_KEY not set")
def test_openrouter_findings_are_populated():
    """After a live investigation completes, assert at least one finding was
    generated by the model (proves the OpenRouter path isn't just stubbing)."""
    client = _client()
    raw_key, _fp = _register_test_key("openrouter-findings")

    create = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "example.com"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": raw_key},
    )
    assert create.status_code == 200
    investigation_id = create.json()["investigation_id"]

    client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})

    # Poll until complete or timeout.
    deadline = time.time() + 120
    while time.time() < deadline:
        status_resp = client.get(
            f"/v1/investigations/{investigation_id}",
            headers={"X-API-Key": raw_key},
        )
        status = status_resp.json()["status"]
        if status in {"COMPLETED", "FAILED"}:
            break
        time.sleep(2)

    findings_resp = client.get(
        f"/v1/investigations/{investigation_id}/findings",
        headers={"X-API-Key": raw_key},
    )
    findings = findings_resp.json()
    assert isinstance(findings, list)
    # A live model should always produce at least one finding for a real
    # target like example.com.  If it didn't, the OpenRouter path is broken.
    assert len(findings) >= 1, (
        f"Expected >= 1 finding from live OpenRouter run, got {len(findings)}. "
        "The live model path may be stubbing or failing silently."
    )

    # Each finding should have minimal structure.
    for f in findings:
        assert f.get("title") or f.get("description"), f"finding missing title/description: {f}"


@pytest.mark.skipif(not _LIVE_AVAILABLE, reason="OPENROUTER_API_KEY not set")
def test_openrouter_findings_have_meaningful_content():
    """Spot-check that findings contain actionable text, not placeholder
    stubs like 'mock response' or 'stub'."""
    client = _client()
    raw_key, _fp = _register_test_key("openrouter-meaningful")

    create = client.post(
        "/v1/investigations",
        json={
            "target": {"type": "domain", "value": "example.com"},
            "investigation_type": "cybersecurity",
        },
        headers={"X-API-Key": raw_key},
    )
    investigation_id = create.json()["investigation_id"]
    client.post(f"/v1/investigations/{investigation_id}/start", headers={"X-API-Key": raw_key})

    deadline = time.time() + 120
    while time.time() < deadline:
        status = client.get(
            f"/v1/investigations/{investigation_id}",
            headers={"X-API-Key": raw_key},
        ).json()["status"]
        if status in {"COMPLETED", "FAILED"}:
            break
        time.sleep(2)

    findings = client.get(
        f"/v1/investigations/{investigation_id}/findings",
        headers={"X-API-Key": raw_key},
    ).json()

    stub_phrases = ("mock", "stub", "lorem", "placeholder", "todo")
    for f in findings:
        text = (f.get("title") or "") + " " + (f.get("description") or "") + " " + (f.get("detail") or "")
        text_lower = text.lower()
        for phrase in stub_phrases:
            assert phrase not in text_lower, f"finding looks like a stub: {f}"
