"""Tests for the investigation intelligence layer.

These tests verify the deterministic intelligence components:
- InvestigationPlanner: lane selection from indicators
- EvidenceCorrelator: finding↔evidence lineage
- EntityGraphBuilder: relationship graph construction
- EvidenceInferenceClassifier: evidence-vs-inference classification
- RiskAssessor: deterministic risk scoring
- build_dossier_intelligence: full composition
"""

from __future__ import annotations

from safenestt.investigations.intelligence import (
    EvidenceCorrelator,
    EvidenceInferenceClassifier,
    EntityGraphBuilder,
    InvestigationPlanner,
    RiskAssessor,
    build_dossier_intelligence,
)


def test_planner_selects_base_lanes():
    """Planner always includes osint and threat_intel as base lanes."""
    plan = InvestigationPlanner().plan("example.com")
    assert "osint" in plan.lanes
    assert "threat_intel" in plan.lanes
    assert len(plan.stages) == 8
    assert "EVIDENCE_CORRELATION" in plan.stages
    assert "ENTITY_GRAPH" in plan.stages
    assert "REALITY_CHECK" in plan.stages


def test_planner_selects_specialized_lanes():
    """Planner adds crypto lane for wallet indicators, identity lane for PII."""
    plan = InvestigationPlanner().plan("example.com", {"domain": "example.com", "wallet_address": "0xabc"})
    assert "crypto" in plan.lanes
    assert "identity" not in plan.lanes

    plan2 = InvestigationPlanner().plan("example.com", {"email": "test@example.com", "phone": "+1234"})
    assert "identity" in plan2.lanes
    assert "crypto" not in plan2.lanes

    plan3 = InvestigationPlanner().plan("example.com", {"wallet_address": "0xabc", "email": "test@example.com"})
    assert "crypto" in plan3.lanes
    assert "identity" in plan3.lanes


def test_planner_filters_empty_indicators():
    """Empty/None values in indicators are filtered out."""
    plan = InvestigationPlanner().plan("example.com", {"wallet_address": "", "email": None})
    assert plan.lanes == ["osint", "threat_intel"]


def test_correlation_links_findings_to_evidence():
    """EvidenceCorrelator builds explicit finding↔evidence links."""
    result = EvidenceCorrelator().correlate(
        [{"finding_id": "f1", "evidence_ids": ["e1"]}],
        [{"evidence_id": "e1", "source": "shodan", "confidence": 0.8}],
    )
    assert len(result["links"]) == 1
    assert result["links"][0]["relationship"] == "supports"
    assert result["links"][0]["source"] == "shodan"
    assert result["finding_count"] == 1
    assert result["evidence_count"] == 1


def test_correlation_handles_missing_evidence():
    """EvidenceCorrelator skips evidence IDs that don't exist in the evidence list."""
    result = EvidenceCorrelator().correlate(
        [{"finding_id": "f1", "evidence_ids": ["e1", "e2"]}],
        [{"evidence_id": "e1", "source": "dns", "confidence": 0.9}],
    )
    assert len(result["links"]) == 1
    assert result["links"][0]["evidence_id"] == "e1"
    assert result["evidence_count"] == 1


def test_correlation_handles_empty_findings():
    """EvidenceCorrelator returns empty result for empty findings."""
    result = EvidenceCorrelator().correlate([], [{"evidence_id": "e1"}])
    assert result["links"] == []
    assert result["finding_count"] == 0


def test_classifier_respects_existing_reality_status():
    """EvidenceInferenceClassifier returns the existing reality_status if it's a known class."""
    classifier = EvidenceInferenceClassifier()
    assert classifier.classify({"reality_status": "VERIFIED_EVIDENCE", "evidence_ids": ["e1"]}, []) == "VERIFIED_EVIDENCE"
    assert classifier.classify({"reality_status": "AI_INFERENCE", "evidence_ids": ["e1"]}, []) == "AI_INFERENCE"
    assert classifier.classify({"reality_status": "UNVERIFIED_CLAIM", "evidence_ids": []}, []) == "UNVERIFIED_CLAIM"
    assert classifier.classify({"reality_status": "CORRELATED_EVIDENCE", "evidence_ids": ["e1"]}, []) == "CORRELATED_EVIDENCE"


def test_classifier_classifies_by_evidence_presence():
    """Findings without evidence are AI_INFERENCE; with evidence are VERIFIED or CORRELATED."""
    classifier = EvidenceInferenceClassifier()
    # No evidence_ids → inference
    assert classifier.classify({"evidence_ids": []}, []) == "AI_INFERENCE"
    # One matching evidence → verified
    assert classifier.classify({"evidence_ids": ["e1"]}, [{"evidence_id": "e1", "source": "dns"}]) == "VERIFIED_EVIDENCE"
    # Multiple matching evidences → correlated
    assert classifier.classify({"evidence_ids": ["e1", "e2"]}, [{"evidence_id": "e1"}, {"evidence_id": "e2"}]) == "CORRELATED_EVIDENCE"
    # evidence_ids referencing non-existent evidence → inference
    assert classifier.classify({"evidence_ids": ["e_missing"]}, []) == "AI_INFERENCE"


def test_graph_contains_target_finding_and_evidence():
    """EntityGraphBuilder creates nodes for target, findings, and evidence."""
    graph = EntityGraphBuilder().build(
        "example.com",
        [{"finding_id": "f1", "claim": "suspicious", "evidence_ids": ["e1"], "risk_score": 0.8}],
        [{"evidence_id": "e1", "source": "dns", "source_type": "tool", "confidence": 0.9}],
    )
    node_types = {n["type"] for n in graph["nodes"]}
    assert node_types == {"target", "finding", "evidence"}
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2  # target→evidence + finding→evidence
    assert any(e["relationship"] == "supported_by" for e in graph["edges"])


def test_graph_handles_findings_without_evidence():
    """EntityGraphBuilder includes findings even if they have no evidence links."""
    graph = EntityGraphBuilder().build(
        "example.com",
        [{"finding_id": "f1", "claim": "no evidence", "evidence_ids": []}],
        [],
    )
    node_types = {n["type"] for n in graph["nodes"]}
    assert node_types == {"target", "finding"}
    assert len(graph["edges"]) == 0


def test_risk_is_deterministic():
    """RiskAssessor produces a deterministic score from findings and evidence."""
    risk = RiskAssessor().assess(
        [{"finding_id": "f1", "confidence": 0.8, "evidence_ids": ["e1", "e2"]}],
        [{"evidence_id": "e1"}, {"evidence_id": "e2"}],
    )
    assert risk["score"] == 76.0
    assert risk["level"] == "HIGH"
    assert risk["method"] == "deterministic_evidence_weighted_v1"
    assert risk["finding_count"] == 1
    assert risk["evidence_count"] == 2


def test_risk_with_no_findings():
    """RiskAssessor returns zero score when there are no findings."""
    risk = RiskAssessor().assess([], [{"evidence_id": "e1"}])
    assert risk["score"] == 0.0
    assert risk["level"] == "LOW"
    assert risk["finding_count"] == 0


def test_risk_empty_coverage():
    """RiskAssessor handles empty evidence list gracefully."""
    risk = RiskAssessor().assess(
        [{"finding_id": "f1", "confidence": 0.5, "evidence_ids": []}],
        [],
    )
    # confidence=0.5, coverage=0/3=0, score=(0.7*0.5 + 0.3*0)*100 = 35.0
    assert risk["score"] == 35.0
    assert risk["level"] == "MEDIUM"


def test_dossier_intelligence_contains_lineage_and_graph():
    """build_dossier_intelligence composes full intelligence payload."""
    result = build_dossier_intelligence(
        "example.com",
        [{"finding_id": "f1", "claim": "suspicious", "evidence_ids": ["e1"], "risk_score": 0.7}],
        [{"evidence_id": "e1", "source": "dns", "observed_at": "2026-09-26T00:00:00Z", "confidence": 0.9}],
        {"domain": "example.com"},
    )
    assert result["plan"]["target"] == "example.com"
    assert result["findings"][0]["evidence_class"] == "VERIFIED_EVIDENCE"
    assert result["findings"][0]["provenance"]["sources"] == ["dns"]
    assert result["findings"][0]["provenance"]["timestamps"] == ["2026-09-26T00:00:00Z"]
    assert result["entity_graph"]["nodes"]
    assert result["entity_graph"]["edges"]
    assert result["risk_assessment"]["method"] == "deterministic_evidence_weighted_v1"
    assert "dossier" in result
    assert result["dossier"]["target"] == "example.com"
    assert result["generated_at"] is not None


def test_dossier_intelligence_inference_classification():
    """build_dossier_intelligence classifies findings without evidence as AI_INFERENCE."""
    result = build_dossier_intelligence(
        "example.com",
        [{"finding_id": "f1", "claim": "AI generated", "evidence_ids": []}],
        [],
    )
    assert result["findings"][0]["evidence_class"] == "AI_INFERENCE"
    assert result["findings"][0]["provenance"]["sources"] == []
    assert result["findings"][0]["provenance"]["evidence_ids"] == []


def test_dossier_intelligence_correlation_summary():
    """build_dossier_intelligence produces correlation summary."""
    result = build_dossier_intelligence(
        "example.com",
        [
            {"finding_id": "f1", "claim": "finding 1", "evidence_ids": ["e1"]},
            {"finding_id": "f2", "claim": "finding 2", "evidence_ids": ["e2"]},
            {"finding_id": "f3", "claim": "finding 3", "evidence_ids": ["e1", "e2"]},
        ],
        [
            {"evidence_id": "e1", "source": "dns", "confidence": 0.8},
            {"evidence_id": "e2", "source": "shodan", "confidence": 0.6},
        ],
    )
    assert result["correlation"]["finding_count"] == 3
    assert result["correlation"]["evidence_count"] == 2
    assert len(result["correlation"]["links"]) == 4  # f1→e1, f2→e2, f3→e1, f3→e2
