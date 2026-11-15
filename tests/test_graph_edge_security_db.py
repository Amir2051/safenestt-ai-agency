"""LIVE DATABASE TESTS — Graph edge security with real PostgreSQL.

Separated from static tests because these require a running database.
"""

import hashlib
import os
import pytest
import psycopg2
import uuid
from datetime import datetime, timezone

from safenestt.investigations.records import InvestigationRecord, FindingRecord, EvidenceRecord
from safenestt.bridge.transformation import GraphNodeRecord, GraphEdgeRecord, build_graph_from_findings
from safenestt.investigations.store import PersistentInvestigationStore
from safenestt.persistence.engine import session_scope, create_engine
from safenestt.persistence.models import Base, GraphNodeModel, GraphEdgeModel

# Isolated test database (dedicated instance, never production).
_TEST_HOST = os.getenv("DB_HOST", "127.0.0.1")
_TEST_PORT = os.getenv("DB_PORT", "55432")
_TEST_DB = os.getenv("DB_NAME", "safenestt_ai_test")
_OWNER_PASS = os.getenv("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only")
_APP_PASS = os.getenv("SAFENESTT_DB_PASSWORD", "safenestt_test_local_only")
_OWNER_URL = f"postgresql://safenestt_owner_test:{_OWNER_PASS}@{_TEST_HOST}:{_TEST_PORT}/{_TEST_DB}"
_APP_URL = f"postgresql://safenestt_app:{_APP_PASS}@{_TEST_HOST}:{_TEST_PORT}/{_TEST_DB}"


def _seed_api_keys(owner_url: str, tenants: list[tuple[str, str]]) -> None:
    """Seed api_keys (deterministic SHA-256 fingerprints), mimicking test_persistence.py.

    These rows are what establish_tenant_context() verifies in SQL; the app role
    inserts directly (api_keys currently has no RLS policy), so the remaining
    work here is the owner-role schema bootstrap that the graph-edge tables
    require.
    """
    owner_engine = create_engine(owner_url)
    try:
        conn = psycopg2.connect(owner_url)
        conn.autocommit = True
        cur = conn.cursor()
        for tenant_id, raw_key in tenants:
            fp = hashlib.sha256(raw_key.encode()).hexdigest()
            cur.execute(
                "INSERT INTO api_keys (key_hash, key_fingerprint, tenant_id, active, revoked, scopes, created_at, use_count) "
                "VALUES (%s, %s, %s, TRUE, FALSE, '[]'::json, NOW(), 0)",
                (hashlib.sha256(raw_key.encode()).hexdigest(), fp, tenant_id),
            )
        cur.close()
        conn.close()
    finally:
        owner_engine.dispose()


@pytest.fixture(scope="function")
def graph_db():
    """Bootstrap the test DB and seed api_keys for the graph-edge tenant.

    NOTE: this function is intentionally idempotent and narrow. It drops then
    recreates the tables the graph-edge store actually touches (graph_nodes,
    graph_edges plus the audit/keys/investigations tables it writes) via the
    OWNER role, and seeds the api_keys rows that establish_tenant_context()
    verifies before any graph node/edge write. The graph-edge tenant's
    fingerprint must match the one the store() fixture passes, so the seed and
    store stay coupled here.
    """
    from safenestt.persistence.rls import apply_rls_policies

    # Drop then recreate the main tables via owner (graph nodes/edges are not
    # in Base.metadata, so we only need the tables the store actually uses,
    # plus the audit/keys tables the store may touch).
    conn = psycopg2.connect(_OWNER_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(
        "DROP TABLE IF EXISTS graph_edges, graph_nodes, audit_events, api_key_audit, api_keys, investigations, evidence, findings, agent_runs, reports, rate_limits, approvals CASCADE"
    )
    cur.close()
    conn.close()

    owner_engine = create_engine(_OWNER_URL)
    Base.metadata.create_all(owner_engine)
    apply_rls_policies(owner_engine)
    owner_engine.dispose()

    # Graph edges join to graph_nodes; nodes must exist before edges. The
    # graph-edge tests exercise cross-tenant rejection, so both tenants must
    # exist in the api_keys table. We seed one tenant for the entire scenario
    # (tenant_id="test-tenant-graph-sec", fingerprint derived from raw key) and
    # a second tenant for the cross-tenant assertions.
    tenants = [
        ("test-tenant-graph-sec", "test-key-for-test-tenant-graph-sec"),
        ("test-tenant-cross-1", "test-key-for-test-tenant-cross-1"),
    ]
    _seed_api_keys(_OWNER_URL, tenants)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def store(graph_db):
    """Create a store with a tenant context whose api_keys row actually exists.

    The tenant "test-tenant-graph-sec" is seeded in graph_db() with a
    deterministic SHA-256 key_fingerprint, and this store passes that exact
    fingerprint so establish_tenant_context() succeeds and the graph node/edge
    writes proceed instead of raising "Invalid API key or tenant mismatch".
    """
    import hashlib

    tenant_id = "test-tenant-graph-sec"
    raw_key = "test-key-for-test-tenant-graph-sec"
    key_fingerprint = hashlib.sha256(raw_key.encode()).hexdigest()
    return PersistentInvestigationStore(
        tenant_id=tenant_id,
        key_fingerprint=key_fingerprint,
    )


@pytest.fixture(scope="function")
def fresh_investigation(store):
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
    store.create_investigation(record)
    return inv_id


@pytest.fixture(scope="function")
def two_investigations(store):
    """Create two separate investigations with their own nodes."""
    inv_a = f"inv-a-{uuid.uuid4().hex[:12]}"
    inv_b = f"inv-b-{uuid.uuid4().hex[:12]}"

    # Create investigations
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
    store.create_investigation(ra)
    store.create_investigation(rb)

    # Create nodes for investigation A
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

    # Create nodes for investigation B
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

    # Persist all nodes
    store.add_graph_node(node_a1)
    store.add_graph_node(node_a2)
    store.add_graph_node(node_b1)
    store.add_graph_node(node_b2)

    return {
        "inv_a": inv_a,
        "inv_b": inv_b,
        "node_a1": node_a1,
        "node_a2": node_a2,
        "node_b1": node_b1,
        "node_b2": node_b2,
    }


# =============================================================================
# Test A: Valid same-investigation edge
# =============================================================================

def test_valid_same_investigation_edge(store, two_investigations):
    """A. valid same-investigation edge -> PASS."""
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

    result = store.add_graph_edge(edge_a)
    assert result is not None

    # Verify edge was persisted. Check the investigation binding via the
    # session-safe list path, not off the returned ORM object (which detaches
    # once the store session closes).
    edges = store.list_graph_edges(inv_a)
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "supported_by"
    assert edges[0]["investigation_id"] == inv_a


# =============================================================================
# Test B: Source node from A + edge for B -> REJECT
# =============================================================================

def test_cross_investigation_source_rejected(store, two_investigations):
    """B. source node from investigation A + edge for investigation B -> REJECT."""
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-cross-source-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-cross-source-{inv_b}",
        source_node_id=two_investigations["node_a1"].id,  # From A!
        target_node_id=two_investigations["node_b2"].id,    # From B
        edge_type="supported_by",
        edge_label="cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        store.add_graph_edge(cross_edge)

    # Verify no edge was created
    edges_b = store.list_graph_edges(inv_b)
    assert len(edges_b) == 0, f"Expected 0 edges in B, got {len(edges_b)}"


# =============================================================================
# Test C: Target node from A + edge for B -> REJECT
# =============================================================================

def test_cross_investigation_target_rejected(store, two_investigations):
    """C. target node from investigation A + edge for investigation B -> REJECT."""
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-cross-target-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-cross-target-{inv_b}",
        source_node_id=two_investigations["node_b1"].id,  # From B
        target_node_id=two_investigations["node_a2"].id,    # From A!
        edge_type="supported_by",
        edge_label="cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        store.add_graph_edge(cross_edge)

    edges_b = store.list_graph_edges(inv_b)
    assert len(edges_b) == 0


# =============================================================================
# Test D: Both nodes from A + edge for B -> REJECT
# =============================================================================

def test_both_nodes_from_another_investigation_rejected(store, two_investigations):
    """D. both nodes from investigation A + edge for investigation B -> REJECT."""
    inv_a = two_investigations["inv_a"]
    inv_b = two_investigations["inv_b"]

    cross_edge = GraphEdgeRecord(
        id=f"ge-both-cross-{inv_b}",
        investigation_id=inv_b,
        case_id="bc-b",
        edge_key=f"ge-both-cross-{inv_b}",
        source_node_id=two_investigations["node_a1"].id,  # From A
        target_node_id=two_investigations["node_a2"].id,    # From A
        edge_type="supported_by",
        edge_label="both_cross_investigation_edge",
    )

    with pytest.raises(ValueError, match="belongs to investigation"):
        store.add_graph_edge(cross_edge)

    edges_b = store.list_graph_edges(inv_b)
    assert len(edges_b) == 0
    edges_a = store.list_graph_edges(inv_a)
    assert len(edges_a) == 0  # No edge added to A either


# =============================================================================
# Test E: Nonexistent source -> REJECT
# =============================================================================

def test_nonexistent_source_rejected(store, fresh_investigation):
    """E. nonexistent source -> REJECT."""
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
        store.add_graph_edge(fake_edge)


# =============================================================================
# Test F: Nonexistent target -> REJECT
# =============================================================================

def test_nonexistent_target_rejected(store, fresh_investigation):
    """F. nonexistent target -> REJECT."""
    inv_id = fresh_investigation

    # First add a real source node
    source_node = GraphNodeRecord(
        id=f"gn-real-source-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        node_key=f"gn-real-source-{inv_id}",
        node_type="finding",
        label="Real source",
    )
    store.add_graph_node(source_node)

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
        store.add_graph_edge(fake_edge)


# =============================================================================
# Test G: Graph nodes linked to correct investigation
# =============================================================================

def test_graph_nodes_linked_to_investigation(store, fresh_investigation):
    """Verify graph nodes reference the correct investigation_id."""
    inv_id = fresh_investigation

    node = GraphNodeRecord(
        id=f"gn-test-{inv_id}",
        investigation_id=inv_id,
        case_id="bc-test",
        node_key=f"gn-test-{inv_id}",
        node_type="finding",
        label="Test node",
    )
    store.add_graph_node(node)

    # List nodes for this investigation
    nodes = store.list_graph_nodes(inv_id)
    assert len(nodes) == 1
    assert nodes[0]["investigation_id"] == inv_id
    assert nodes[0]["case_id"] == "bc-test"
    assert nodes[0]["node_type"] == "finding"

    # Verify node is NOT listed for other investigations
    other_nodes = store.list_graph_nodes("nonexistent-investigation")
    assert len(other_nodes) == 0


# =============================================================================
# Test H: Graph edges have correct case_id
# =============================================================================

def test_graph_edges_preserve_case_id(store, two_investigations):
    """Verify graph edges preserve the Base44 case_id."""
    inv_a = two_investigations["inv_a"]

    edge = GraphEdgeRecord(
        id=f"ge-caseid-{inv_a}",
        investigation_id=inv_a,
        case_id="bc-a",  # Base44 case ID
        edge_key=f"ge-caseid-{inv_a}",
        source_node_id=two_investigations["node_a1"].id,
        target_node_id=two_investigations["node_a2"].id,
        edge_type="about",
        edge_label="test",
    )
    store.add_graph_edge(edge)

    edges = store.list_graph_edges(inv_a)
    assert len(edges) >= 1
    # Find our edge
    our_edge = next((e for e in edges if e["edge_key"] == f"ge-caseid-{inv_a}"), None)
    assert our_edge is not None
    assert our_edge["case_id"] == "bc-a"
