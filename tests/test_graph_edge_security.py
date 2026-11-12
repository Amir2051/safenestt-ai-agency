"""LIVE DATABASE TESTS — Graph edge security with real PostgreSQL.

Uses the same database setup as test_persistence.py (conftest.py fresh_db fixture).
"""

import hashlib
import uuid

import pytest

from safenestt.investigations.records import InvestigationRecord, FindingRecord, EvidenceRecord
from safenestt.bridge.transformation import GraphNodeRecord, GraphEdgeRecord, build_graph_from_findings
from safenestt.investigations.store import PersistentInvestigationStore


def _fp(tenant_id: str) -> str:
    return hashlib.sha256(f"test-key-for-{tenant_id}".encode()).hexdigest()


@pytest.fixture(scope="function")
def graph_store(database_session):
    """Create a store with test tenant context, matching the seeded api_keys."""
    tenant_id = "test-tenant-graph-sec"
    return PersistentInvestigationStore(
        tenant_id=tenant_id,
        key_fingerprint=_fp(tenant_id),
    )


@pytest.fixture(scope="function")
def fresh_investigation(graph_store):
    """Create a fresh investigation for testing."""
    inv_id = f"inv-graph-test-{uuid.uuid4().hex[:12]}"
    record = InvestigationRecord(
        investigation_id=inv_id,
        tenant_id="test-tenant-graph-sec",
        created_by="test@example.com",
        target="example.com",
        type="domain",
        status="QUEUED",
        case_id="bc-graph-test-case",
    )
    graph_store.create_investigation(record)
    return inv_id


@pytest.fixture(scope="function")
def two_investigations(graph_store):
    """Create two separate investigations with their own nodes."""
    inv_a = f"inv-a-{uuid.uuid4().hex[:12]}"
    inv_b = f"inv-b-{uuid.uuid4().hex[:12]}"

    ra = InvestigationRecord(
        investigation_id=inv_a,
        tenant_id="test-tenant-graph-sec",
        created_by="test@example.com",
        target="example-a.com",
        type="domain",
        status="QUEUED",
        case_id="bc-a",
    )
    rb = InvestigationRecord(
        investigation_id=inv_b,
        tenant_id="test-tenant-graph-sec",
        created_by="test@example.com",
        target="example-b.com",
        type="domain",
        status="QUEUED",
        case_id="bc-b",
    )
    graph_store.create_investigation(ra)
    graph_store.create_investigation(rb)

    node_a1 = GraphNodeRecord(
        id=f"gn-a1-{inv_a}",
        investigation_id=inv_a,
        case_id="bc-a",
        node_key=f"gn-a1-{inv_a}",
        node_type="finding",
        label="Node A1",
    )
    node_a2 = GraphNodeRecord(
        id=f"gn-a2-{inv_a}",
        investigation_id=inv_a,
        case_id="bc-a",
        node_key=f"gn-a2-{inv_a}",
        node_type="evidence",
        label="Node A2",
    )
    node_b1 = GraphNodeRecord(
        id=f"gn-b1-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        node_key=f"gn-b1-{inv_b}",
        node_type="finding",
        label="Node B1",
    )
    node_b2 = GraphNodeRecord(
        id=f"gn-b2-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        node_key=f"gn-b2-{inv_b}",
        node_type="evidence",
        label="Node B2",
    )

    graph_store.add_graph_node(node_a1)
    graph_store.add_graph_node(node_a2)
    graph_store.add_graph_node(node_b1)
    graph_store.add_graph_node(node_b2)

    return {
        "inv_a": inv_a,
        "inv_b": inv_b,
        "node_a1": node_a1,
        "node_a2": node_a2,
        "node_b1": node_b1,
        "node_b2": node_b2,
    }


# =============================================================================
# A. Valid same-investigation edge -> PASS
# =============================================================================

def test_valid_same_investigation_edge(graph_store, two_investigations):
    inv_a = two_investigations["inv_a"]

    edge_a = GraphEdgeRecord(
        id=f"ge-valid-{inv_a}",
        investigation_id=inv_a,
        case_id="bc-a",
        edge_key=f"ge-valid-{inv_a}",
        source_node_id=two_investigations["node_a1"].id,
        target_node_id=two_investigations["node_a2"].id,
        edge_type="supported_by",
        edge_label="finding_supports_evidence",
    )

    result = graph_store.add_graph_edge(edge_a)
    assert result is not None

    # Verify the investigation binding via the session-safe list path, not off
    # the returned ORM object (which detaches once the store session closes).
    edges = graph_store.list_graph_edges(inv_a)
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "supported_by"
    assert edges[0]["investigation_id"] == inv_a


# =============================================================================
# B. Source node from A + edge for B -> REJECT
# =============================================================================

def test_cross_investigation_source_rejected(graph_store, two_investigations):
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-cross-source-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-cross-source-{inv_b}",
        source_node_id=two_investigations["node_a1"].id,
        target_node_id=two_investigations["node_b2"].id,
        edge_type="supported_by",
        edge_label="cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        graph_store.add_graph_edge(cross_edge)

    edges_b = graph_store.list_graph_edges(inv_b)
    assert len(edges_b) == 0


# =============================================================================
# C. Target node from A + edge for B -> REJECT
# =============================================================================

def test_cross_investigation_target_rejected(graph_store, two_investigations):
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-cross-target-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-cross-target-{inv_b}",
        source_node_id=two_investigations["node_b1"].id,
        target_node_id=two_investigations["node_a2"].id,
        edge_type="supported_by",
        edge_label="cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        graph_store.add_graph_edge(cross_edge)

    edges_b = graph_store.list_graph_edges(inv_b)
    assert len(edges_b) == 0


# =============================================================================
# D. Both nodes from A + edge for B -> REJECT
# =============================================================================

def test_both_nodes_from_another_investigation_rejected(graph_store, two_investigations):
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-both-cross-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-both-cross-{inv_b}",
        source_node_id=two_investigations["node_a1"].id,
        target_node_id=two_investigations["node_a2"].id,
        edge_type="supported_by",
        edge_label="both_cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        graph_store.add_graph_edge(cross_edge)

    edges_b = graph_store.list_graph_edges(inv_b)
    assert len(edges_b) == 0
    edges_a = graph_store.list_graph_edges(inv_a)
    assert len(edges_a) == 0


# =============================================================================
# E. Nonexistent source -> REJECT
# =============================================================================

def test_nonexistent_source_rejected(graph_store, fresh_investigation):
    inv_id = fresh_investigation

    fake_edge = GraphEdgeRecord(
        id=f"ge-fake-source-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        edge_key=f"ge-fake-source-{inv_id}",
        source_node_id="gn-nonexistent-source",
        target_node_id="gn-nonexistent-target",
        edge_type="supported_by",
        edge_label="fake_edge",
    )

    with pytest.raises(ValueError, match="Source node not found"):
        graph_store.add_graph_edge(fake_edge)


# =============================================================================
# F. Nonexistent target -> REJECT
# =============================================================================

def test_nonexistent_target_rejected(graph_store, fresh_investigation):
    inv_id = fresh_investigation

    source_node = GraphNodeRecord(
        id=f"gn-real-source-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        node_key=f"gn-real-source-{inv_id}",
        node_type="finding",
        label="Real source",
    )
    graph_store.add_graph_node(source_node)

    fake_edge = GraphEdgeRecord(
        id=f"ge-fake-target-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        edge_key=f"ge-fake-target-{inv_id}",
        source_node_id=source_node.id,
        target_node_id="gn-nonexistent-target",
        edge_type="supported_by",
        edge_label="fake_target_edge",
    )

    with pytest.raises(ValueError, match="Target node not found"):
        graph_store.add_graph_edge(fake_edge)


# =============================================================================
# G. Graph nodes linked to correct investigation
# =============================================================================

def test_graph_nodes_linked_to_investigation(graph_store, fresh_investigation):
    inv_id = fresh_investigation

    node = GraphNodeRecord(
        id=f"gn-test-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        node_key=f"gn-test-{inv_id}",
        node_type="finding",
        label="Test node",
    )
    graph_store.add_graph_node(node)

    nodes = graph_store.list_graph_nodes(inv_id)
    assert len(nodes) == 1
    assert nodes[0]["investigation_id"] == inv_id
    assert nodes[0]["case_id"] == "bc-test"
    assert nodes[0]["node_type"] == "finding"

    other_nodes = graph_store.list_graph_nodes("nonexistent-investigation")
    assert len(other_nodes) == 0


# =============================================================================
# H. Graph edges preserve case_id
# =============================================================================

def test_graph_edges_preserve_case_id(graph_store, two_investigations):
    inv_a = two_investigations["inv_a"]

    edge = GraphEdgeRecord(
        id=f"ge-caseid-{inv_a}",
        investigation_id=inv_a,
        case_id="bc-a",
        edge_key=f"ge-caseid-{inv_a}",
        source_node_id=two_investigations["node_a1"].id,
        target_node_id=two_investigations["node_a2"].id,
        edge_type="about",
        edge_label="test",
    )
    graph_store.add_graph_edge(edge)

    edges = graph_store.list_graph_edges(inv_a)
    assert len(edges) >= 1
    our_edge = next((e for e in edges if e["edge_key"] == f"ge-caseid-{inv_a}"), None)
    assert our_edge is not None
    assert our_edge["case_id"] == "bc-a"
