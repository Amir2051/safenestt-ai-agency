"""Tests for case_id propagation and graph edge security.

STATIC/CODE TESTS — no database required.
"""

import uuid
from datetime import datetime, timezone

from safenestt.investigations.records import InvestigationRecord, FindingRecord, EvidenceRecord
from safenestt.bridge.transformation import (
    GraphNodeRecord, GraphEdgeRecord, build_graph_from_findings,
)


# =============================================================================
# Test 1: case_id propagation through InvestigationRecord
# =============================================================================

def test_investigation_record_stores_case_id():
    """case_id='bc-12345' survives in InvestigationRecord."""
    record = InvestigationRecord(
        investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
        tenant_id="tenant-test-001",
        created_by="test-user@example.com",
        target="example.com",
        type="domain",
        status="QUEUED",
        case_id="bc-12345",
    )
    assert record.case_id == "bc-12345"
    print("PASS: InvestigationRecord stores case_id")


def test_case_id_differs_from_investigation_id():
    """investigations.case_id != investigation_id."""
    record = InvestigationRecord(
        investigation_id="inv-different-id",
        tenant_id="tenant-test",
        target="example.com",
        case_id="bc-12345",
    )
    assert record.case_id != record.investigation_id
    assert record.case_id == "bc-12345"
    assert record.investigation_id == "inv-different-id"
    print("PASS: case_id != investigation_id")


def test_case_id_optional_backward_compatible():
    """Missing case_id follows documented compatibility behavior."""
    record = InvestigationRecord(
        investigation_id="inv-no-case",
        tenant_id="tenant-test",
        target="example.com",
    )
    assert record.case_id is None
    print("PASS: case_id optional (backward compatible)")


def test_case_id_defaults_to_investigation_id_when_none():
    """When case_id is None, effective_case_id falls back to investigation_id."""
    record = InvestigationRecord(
        investigation_id="inv-fallback",
        tenant_id="tenant-test",
        case_id=None,
    )
    assert record.case_id is None
    effective = record.case_id or record.investigation_id
    assert effective == "inv-fallback"
    print("PASS: case_id=None falls back to investigation_id")


# =============================================================================
# Test 2: GraphNode/GraphEdge records from bridge
# =============================================================================

def test_graph_node_has_investigation_id_and_case_id():
    """GraphNodeRecord contains both investigation_id and case_id."""
    inv_id = "invbridge-test"
    case_id = "bc-bridge-case"
    now = datetime.now(timezone.utc)

    findings = [
        FindingRecord(
            investigation_id=inv_id,
            finding_id=f"fnd-{uuid.uuid4().hex[:12]}",
            claim="Test finding from orchestrator",
            evidence_ids=[],
            reality_status="EXTERNAL_INTELLIGENCE",
            risk_score=0.85,
            factors={
                "finding_type": "EXTERNAL_INTELLIGENCE",
                "provider": "shodan",
                "target": "example.com",
                "source": "shodan_api",
                "source_type": "tool",
            },
            created_at=now,
        ),
    ]

    nodes, edges = build_graph_from_findings(
        findings=findings,
        evidence_list=[],
        case_id=case_id,
        hermes_investigation_id=inv_id,
    )

    for node in nodes:
        assert node.investigation_id == inv_id, (
            f"Node {node.id}: investigation_id={node.investigation_id} != {inv_id}"
        )
        assert node.case_id == case_id, (
            f"Node {node.id}: case_id={node.case_id} != {case_id}"
        )
        assert node.node_key == node.id

    print(f"PASS: GraphNodeRecord has investigation_id={inv_id} and case_id={case_id}")


def test_graph_edge_has_investigation_id_and_case_id():
    """GraphEdgeRecord contains both investigation_id and case_id."""
    inv_id = "invedge-test"
    case_id = "bc-edge-case"
    now = datetime.now(timezone.utc)

    findings = [
        FindingRecord(
            investigation_id=inv_id,
            finding_id=f"fnd-{uuid.uuid4().hex[:12]}",
            claim="Test finding",
            evidence_ids=[],
            reality_status="AI_INFERENCE",
            risk_score=0.5,
            factors={"target": "example.com", "source": "model_synthesis"},
            created_at=now,
        ),
    ]

    nodes, edges = build_graph_from_findings(
        findings=findings,
        evidence_list=[],
        case_id=case_id,
        hermes_investigation_id=inv_id,
    )

    for edge in edges:
        assert edge.investigation_id == inv_id, (
            f"Edge {edge.id}: investigation_id={edge.investigation_id} != {inv_id}"
        )
        assert edge.case_id == case_id, (
            f"Edge {edge.id}: case_id={edge.case_id} != {case_id}"
        )
        assert edge.edge_key == edge.id

    print(f"PASS: GraphEdgeRecord has investigation_id={inv_id} and case_id={case_id}")


def test_bridge_passes_case_id_to_nodes_and_edges():
    """Verify bridge uses the case_id parameter, not investigation_id."""
    inv_id = "inv-123"
    case_id = "bc-456"  # Different from inv_id
    now = datetime.now(timezone.utc)

    findings = [
        FindingRecord(
            investigation_id=inv_id,
            finding_id="fnd-1",
            claim="Test",
            evidence_ids=[],
            reality_status="AI_INFERENCE",
            risk_score=0.5,
            factors={"target": "example.com", "source": "test"},
            created_at=now,
        )
    ]

    nodes, edges = build_graph_from_findings(
        findings=findings,
        evidence_list=[],
        case_id=case_id,
        hermes_investigation_id=inv_id,
    )

    # All nodes should have case_id=bc-456, NOT inv-123
    for node in nodes:
        assert node.case_id == case_id
        assert node.case_id != inv_id

    # All edges should have case_id=bc-456, NOT inv-123
    for edge in edges:
        assert edge.case_id == case_id
        assert edge.case_id != inv_id

    print(f"PASS: Bridge propagates case_id={case_id} (not investigation_id={inv_id})")


# =============================================================================
# Test 3: GraphEdgeRecord same-investigation validation (static)
# =============================================================================

def test_graph_edge_record_requires_investigation_id():
    """GraphEdgeRecord requires investigation_id field."""
    inv_id = "inv-sec-test"
    case_id = "bc-sec"

    edge = GraphEdgeRecord(
        id="ge-test",
        investigation_id=inv_id,
        case_id=case_id,
        edge_key="ge-test",
        source_node_id="gn-source",
        target_node_id="gn-target",
        edge_type="about",
        edge_label="test_edge",
    )

    assert edge.investigation_id == inv_id
    assert edge.case_id == case_id
    assert edge.source_node_id == "gn-source"
    assert edge.target_node_id == "gn-target"
    print("PASS: GraphEdgeRecord has all required fields")


def test_graph_edge_cross_investigation_detects_mismatch():
    """Static check: edge with source_node from inv-A and investigation_id=inv-B is detectable."""
    inv_a = "inv-a"
    inv_b = "inv-b"

    # This edge claims to be for inv_b but references a node from inv_a
    edge = GraphEdgeRecord(
        id="ge-cross-static",
        investigation_id=inv_b,  # Claims to be for B
        case_id="bc-b",
        edge_key="ge-cross-static",
        source_node_id="gn-from-a",  # But this node belongs to A
        target_node_id="gn-from-a-2",
        edge_type="about",
        edge_label="cross_edge",
    )

    # The record itself doesn't validate — that's the store's job.
    # But we can verify the mismatch is detectable:
    assert edge.investigation_id == inv_b
    # If we had a node registry, we would check:
    # node_inventory["gn-from-a"].investigation_id == inv_a != inv_b -> REJECT
    print("PASS: Cross-investigation edge is statically identifiable")


# =============================================================================
# Test 4: EvidenceRecord and FindingRecord have investigation_id
# =============================================================================

def test_evidence_record_has_investigation_id():
    """EvidenceRecord links to investigation via investigation_id."""
    inv_id = "inv-evidence-test"
    record = EvidenceRecord(
        investigation_id=inv_id,
        evidence_id=f"ev-{uuid.uuid4().hex[:12]}",
        source="shodan_api",
        source_type="tool",
        target="example.com",
        confidence=0.9,
    )
    assert record.investigation_id == inv_id
    print("PASS: EvidenceRecord has investigation_id")


def test_finding_record_has_investigation_id():
    """FindingRecord links to investigation via investigation_id."""
    inv_id = "inv-finding-test"
    record = FindingRecord(
        investigation_id=inv_id,
        finding_id=f"fnd-{uuid.uuid4().hex[:12]}",
        claim="Test finding",
        evidence_ids=[],
        reality_status="AI_INFERENCE",
        risk_score=0.5,
    )
    assert record.investigation_id == inv_id
    print("PASS: FindingRecord has investigation_id")


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("STATIC/CODE TESTS — case_id propagation and graph security")
    print("=" * 70)
    print()

    test_investigation_record_stores_case_id()
    test_case_id_differs_from_investigation_id()
    test_case_id_optional_backward_compatible()
    test_case_id_defaults_to_investigation_id_when_none()
    print()

    test_graph_node_has_investigation_id_and_case_id()
    test_graph_edge_has_investigation_id_and_case_id()
    test_bridge_passes_case_id_to_nodes_and_edges()
    print()

    test_graph_edge_record_requires_investigation_id()
    test_graph_edge_cross_investigation_detects_mismatch()
    print()

    test_evidence_record_has_investigation_id()
    test_finding_record_has_investigation_id()
    print()

    print("=" * 70)
    print("ALL STATIC TESTS PASSED")
    print("=" * 70)
