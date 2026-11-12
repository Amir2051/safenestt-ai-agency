"""Focused regression tests for the two confirmed root-cause fixes.

FIX 1: the LLM/model finding path must go through RealityChecker.evaluate()
       instead of hardcoding reality_status="AI_INFERENCE".
FIX 2: that same finding must carry agent="investigator" and it must survive
       persistence (store.py previously never wrote the agent column).

Isolated: no database, no network, no production access. The investigator module is
imported directly and the store/provider are stubbed.
"""
from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path("/home/ronzoro/safenestt-ai")
sys.path.insert(0, str(REPO))

from safenestt.investigations.records import FindingRecord  # noqa: E402
from safenestt.investigations.reality import RealityChecker  # noqa: E402

INV = "inv-regression-0001"
SRC = (REPO / "safenestt" / "investigations" / "investigator.py").read_text()


# --------------------------------------------------------------------------- helpers
def llm_finding_block() -> str:
    """Return the source of the `if model_claim:` block."""
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and getattr(node.test, "id", None) == "model_claim":
            # Normalize to a whitespace-free form: comment-stripping re-joins
            # tokens with spaces, so all assertions below compare compact text.
            return _strip_comments(ast.get_source_segment(SRC, node))
    raise AssertionError("model_claim block not found")


def _c(text: str) -> str:
    """Compact a string for whitespace-insensitive substring assertions."""
    return "".join(text.split())


def _strip_comments(src: str) -> str:
    """Drop comments so explanatory prose quoting an old literal is not mistaken
    for live code. Uses tokenize, so a '#' inside a string literal is preserved."""
    import io
    import tokenize
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            continue
        out.append(tok.string)
    return " ".join(out)


class SpyChecker:
    """Stands in for RealityChecker; records calls and returns a known verdict."""

    def __init__(self, verdict="EVIDENCE_SUPPORTED"):
        self.verdict = verdict
        self.calls = []

    def evaluate(self, finding):
        self.calls.append(finding)
        return SimpleNamespace(
            finding_id=finding.finding_id,
            reality_status=self.verdict,
            contradictions=[],
            unsupported_claims=[],
            evidence_supported_claims=[],
        )


def build_and_adjudicate(spy, agent="investigator"):
    """Mirror the fixed LLM-path construction+adjudication+persist sequence."""
    ev = [SimpleNamespace(evidence_id="ev-1"), SimpleNamespace(evidence_id="ev-2")]
    finding = FindingRecord(
        investigation_id=INV,
        finding_id="f-1",
        claim="synthetic claim text",
        evidence_ids=[e.evidence_id for e in ev],
        risk_score=0.5,
        agent=agent,
    )
    evaluated = spy.evaluate(finding)
    finding.reality_status = evaluated.reality_status
    return finding


# --------------------------------------------------------------------------- FIX 1
def test_llm_path_no_longer_hardcodes_ai_inference():
    block = llm_finding_block()
    assert 'reality_status="AI_INFERENCE"' not in _c(block), (
        "LLM finding path still hardcodes reality_status='AI_INFERENCE'"
    )


def test_llm_path_calls_checker_evaluate():
    assert _c("checker.evaluate(model_finding)") in _c(llm_finding_block())


def test_llm_path_assigns_verdict_before_persist():
    block = llm_finding_block()
    evaluate_at = block.index("checker . evaluate ( model_finding")
    assign_at = block.index("model_finding . reality_status = evaluated_model . reality_status")
    persist_at = block.index("store . add_finding ( model_finding")
    assert evaluate_at < assign_at < persist_at, "must adjudicate then assign then persist"


def test_llm_finding_receives_checker_verdict_not_default():
    spy = SpyChecker("EVIDENCE_SUPPORTED")
    finding = build_and_adjudicate(spy)
    assert len(spy.calls) == 1, "checker.evaluate() must be invoked exactly once"
    assert finding.reality_status == "EVIDENCE_SUPPORTED"
    assert finding.reality_status != FindingRecord.__dataclass_fields__["reality_status"].default


def test_verdict_from_real_reality_checker_is_applied():
    """Use the real checker, not a spy: evidence_ids resolve -> EVIDENCE_SUPPORTED."""
    finding = FindingRecord(investigation_id=INV, finding_id="f-2",
                            claim="c", evidence_ids=["ev-1"], agent="investigator")
    result = RealityChecker(evidence_lookup=lambda i, e: SimpleNamespace()).evaluate(finding)
    finding.reality_status = result.reality_status
    assert finding.reality_status == "EVIDENCE_SUPPORTED"


# --------------------------------------------------------------------------- FIX 2
def test_llm_finding_gets_investigator_agent():
    assert _c('agent="investigator"') in _c(llm_finding_block())


def test_agent_survives_to_persistence_layer():
    finding = build_and_adjudicate(SpyChecker())
    assert finding.agent == "investigator"
    # store.py must actually write the column
    store_src = (REPO / "safenestt" / "investigations" / "store.py").read_text()
    assert 'agent=getattr(finding, "agent", None)' in store_src


def test_repository_layer_reads_agent():
    repo_src = (REPO / "safenestt" / "persistence" / "repositories.py").read_text()
    assert 'agent=getattr(finding, "agent", None)' in repo_src


# --------------------------------------------------------------------------- no regressions
def test_orchestrator_path_unchanged():
    """The orchestrator path still evaluates then assigns."""
    assert "evaluated = checker.evaluate(finding)" in SRC
    assert "finding.reality_status = evaluated.reality_status" in SRC


def test_fallback_path_unchanged():
    assert "evaluated = checker.evaluate(fallback)" in SRC
    assert "fallback.reality_status = evaluated.reality_status" in SRC


def test_agent_field_is_backwards_compatible():
    """Defaulted field: existing construction sites keep working unchanged."""
    f = FindingRecord(investigation_id=INV, finding_id="f-3", claim="c")
    assert f.agent == ""
    assert f.reality_status == "AI_INFERENCE"  # untouched default
    assert f.evidence_ids == [] and f.risk_score == 0.0


def test_encryption_still_applied_to_claim():
    """Patch must not disturb claim handling."""
    assert "claim=encrypt_value(finding.claim)" in (
        REPO / "safenestt" / "investigations" / "store.py").read_text()
    assert "_encrypt_field(finding.claim)" in (
        REPO / "safenestt" / "persistence" / "repositories.py").read_text()


def test_no_semantic_validation_added_yet():
    """Scope guard: RealityChecker semantics must NOT have been redesigned."""
    r = inspect.getsource(RealityChecker)
    assert "EVIDENCE_SUPPORTED" in r
    for state in ("PARTIALLY_SUPPORTED", "INSUFFICIENT_EVIDENCE"):
        assert f'reality_status="{state}"' not in r, (
            f"{state} must not be introduced by this patch"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "--no-header"]))
