"""
Phase 5 E2E Bridge Test.

Deterministic mocked test covering:

target → Hermes investigation → provider result → EvidenceRecord
→ FindingRecord → EntityGraphBuilder → Base44 transformation
→ CaseEvidenceItem → GraphNode → GraphEdge

Verifies:
- IDs remain linked
- evidence_ids are populated
- EXTERNAL_INTELLIGENCE remains intact
- provenance survives
- tenant/organization ID survives
- provider information survives
- graph relationships survive
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

import pytest

from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.bridge.transformation import (
    bridge_investigation,
    BridgeResult,
    CaseEvidenceItemData,
    GraphNodeRecord,
    GraphEdgeRecord,
    map_finding_type_to_category,
    map_confidence,
    map_provider_tool_call_to_tool_run_record,
    build_case_evidence_item_data,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)


def make_investigation(
    *,
    investigation_id: str = "inv-test-001",
    tenant_id: str = "org-acme",
    created_by: str = "agent-1",
    target: str = "example.com",
    type: str = "domain",
    status: str = "COMPLETED",
) -> InvestigationRecord:
    return InvestigationRecord(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        created_by=created_by,
        target=target,
        type=type,
        status=status,
        created_at=_now(),
        updated_at=_now(),
    )


def make_evidence(
    *,
    evidence_id: str,
    investigation_id: str = "inv-test-001",
    source: str = "shodan_api",
    source_type: str = "tool",
    target: str = "example.com",
    observed_at: datetime | None = None,
    data: dict | None = None,
    confidence: float = 0.9,
    tool_run_id: str = "run-1",
    provenance: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        source=source,
        source_type=source_type,
        target=target,
        observed_at=observed_at or _now(),
        data=data or {
            "provider": "Shodan",
            "title": f"Shodan scan of {target}",
            "description": f"Port scan results for {target}",
            "finding_type": "EXTERNAL_INTELLIGENCE",
            "source_timestamp": "2026-09-27T09:00:00Z",
            "evidence_refs": ["ref-1"],
            "entity_refs": ["entity-1"],
            "indicator_refs": ["indicator-1"],
            "provenance": {
                "case_id": "case-acme-001",
                "investigation_id": investigation_id,
                "organization_id": "org-acme",
                "agent_id": "agent-1",
                "agent_run_id": "run-1",
                "tool_id": "shodan",
                "task_id": "task-1",
                "collected_timestamp": "2026-09-27T10:00:00Z",
            },
            "metadata": {"ports": [80, 443], "services": ["http", "https"]},
        },
        confidence=confidence,
        tool_run_id=tool_run_id,
        provenance=provenance,
    )


def make_finding(
    *,
        finding_id: str,
        investigation_id: str = "inv-test-001",
        claim: str = "example.com has open ports",
        evidence_ids: list[str] | None = None,
        reality_status: str = "EXTERNAL_INTELLIGENCE",
        risk_score: float = 0.75,
        factors: dict | None = None,
        created_at: datetime | None = None,
) -> FindingRecord:
    return FindingRecord(
        investigation_id=investigation_id,
        finding_id=finding_id,
        claim=claim,
        evidence_ids=evidence_ids or [],
        reality_status=reality_status,
        risk_score=risk_score,
        factors=factors or {
            "provider": "Shodan",
            "source": "shodan_api",
            "source_type": "tool",
            "target": "example.com",
            "target_type": "domain",
            "indicator_type": "domain",
            "indicator": "example.com",
            "finding_type": "EXTERNAL_INTELLIGENCE",
            "confidence": 0.9,
            "collected_timestamp": "2026-09-27T10:00:00Z",
            "source_timestamp": "2026-09-27T09:00:00Z",
            "evidence_refs": ["ref-1"],
            "entity_refs": ["entity-1"],
            "indicator_refs": ["indicator-1"],
            "provenance": {
                "case_id": "case-acme-001",
                "investigation_id": investigation_id,
                "organization_id": "org-acme",
                "agent_id": "agent-1",
                "agent_run_id": "run-1",
                "tool_id": "shodan",
                "task_id": "task-1",
            },
        },
        created_at=created_at or _now(),
    )


def make_tool_call(
    *,
    tool_id: str = "shodan",
    task_id: str = "task-1",
    tool_status: str = "ALLOW",
    provider: str = "Shodan",
    source: str = "shodan_api",
    target: str = "example.com",
    confidence: float = 0.9,
    run_id: str = "run-1",
    data: dict | None = None,
    collected_at: str | None = None,
    started_at: str | None = None,
    latency_ms: int | None = None,
    capability: str = "host",
) -> dict:
    return {
        "tool_id": tool_id,
        "task_id": task_id,
        "tool_status": tool_status,
        "provider": provider,
        "source": source,
        "target": target,
        "confidence": confidence,
        "data": data or {"ports": [80, 443], "services": ["http", "https"]},
        "collected_at": collected_at or "2026-09-27T10:00:00Z",
        "run_id": run_id,
        "capability": capability,
        "started_at": started_at or "2026-09-27T09:58:00Z",
        "latency_ms": latency_ms or 1200,
    }


# ============================================================================
# Item 1: CaseEvidenceItem transformation
# ============================================================================


class TestCaseEvidenceItem:
    """Verify EvidenceRecord → CaseEvidenceItem mapping."""

    def test_evidence_map_preserves_ids(self):
        """Evidence IDs remain linked through the transformation."""
        ev = make_evidence(evidence_id="ev-abc-123")
        inv = make_investigation(investigation_id="inv-test-001")
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-abc-123"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        assert result.case_evidence_items, "Should produce at least one CaseEvidenceItem"
        item = result.case_evidence_items[0]

        # ID linkage: Base44 item id encodes Hermes evidence_id
        assert "ev-abc-123" in item["id"], f"Evidence id should be in Base44 item id: {item['id']}"
        assert item["_hermes_evidence_id"] == "ev-abc-123"
        assert item["_hermes_investigation_id"] == "inv-test-001"
        assert item["case_id"] == "case-acme-001"

    def test_evidence_map_preserves_provenance(self):
        """Provenance survives the transformation."""
        ev = make_evidence(
            evidence_id="ev-prov-001",
            data={
                "provenance": {
                    "case_id": "case-acme-001",
                    "investigation_id": "inv-test-001",
                    "organization_id": "org-acme",
                    "agent_id": "agent-1",
                    "agent_run_id": "run-1",
                    "tool_id": "shodan",
                    "task_id": "task-1",
                    "collected_timestamp": "2026-09-27T10:00:00Z",
                }
            },
        )
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-prov-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        item = result.case_evidence_items[0]
        data = item["data"]

        assert "provenance" in data, "Provenance should be in CaseEvidenceItem.data"
        prov = data["provenance"]
        assert prov["case_id"] == "case-acme-001"
        assert prov["investigation_id"] == "inv-test-001"
        assert prov["organization_id"] == "org-acme"
        assert prov["agent_id"] == "agent-1"

    def test_evidence_map_preserves_tenant_org(self):
        """Tenant/org ID survives."""
        inv = make_investigation(tenant_id="org-acme")
        ev = make_evidence(evidence_id="ev-org-001")
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-org-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        item = result.case_evidence_items[0]
        data = item["data"]

        # Provenance carries organization_id
        prov = data.get("provenance", {})
        assert prov.get("organization_id") == "org-acme", f"Org should survive: {prov}"
        # CaseEvidenceItem is scoped to case_id
        assert item["case_id"] == "case-acme-001"

    def test_evidence_map_preserves_provider_info(self):
        """Provider/source/target/confidence survive."""
        ev = make_evidence(
            evidence_id="ev-prov-002",
            source="shodan_api",
            confidence=0.9,
            data={
                "provider": "Shodan",
                "title": "Shodan scan of example.com",
                "source_timestamp": "2026-09-27T09:00:00Z",
            },
        )
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-prov-002"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        item = result.case_evidence_items[0]
        data = item["data"]

        assert data["provider"] == "Shodan"
        assert data["source"] == "shodan_api"
        assert data["target"] == "example.com"
        assert data["confidence"] == 0.9
        assert data["source_timestamp"] == "2026-09-27T09:00:00Z"

    def test_evidence_map_p_reserves_collected_timestamp(self):
        """collected_at survives."""
        ev = make_evidence(
            evidence_id="ev-time-001",
            observed_at=_now(),
            data={"collected_at": "2026-09-27T10:00:00Z"},
        )
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-time-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        data = result.case_evidence_items[0]["data"]

        assert data["collected_at"] == "2026-09-27T10:00:00Z"

    def test_evidence_map_preserves_evidence_refs(self):
        """evidence_refs / entity_refs / indicator_refs survive."""
        ev = make_evidence(
            evidence_id="ev-refs-001",
            data={
                "evidence_refs": ["ref-1", "ref-2"],
                "entity_refs": ["entity-1"],
                "indicator_refs": ["indicator-1", "indicator-2"],
            },
        )
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-refs-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        data = result.case_evidence_items[0]["data"]

        assert data["evidence_refs"] == ["ref-1", "ref-2"]
        assert data["entity_refs"] == ["entity-1"]
        assert data["indicator_refs"] == ["indicator-1", "indicator-2"]

    def test_case_evidence_item_category_is_external_intelligence(self):
        """EXTERNAL_INTELLIGENCE findings map to external_intelligence category."""
        ev = make_evidence(
            evidence_id="ev-ext-001",
            data={"finding_type": "EXTERNAL_INTELLIGENCE"},
        )
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-ext-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        item = result.case_evidence_items[0]

        assert item["category"] == "external_intelligence"
        assert item["relevance"] == "supporting"  # not primary (not VERIFIED_EVIDENCE)

    def test_case_evidence_item_category_verified_evidence_is_primary(self):
        """VERIFIED_EVIDENCE → category=evidence, relevance=primary."""
        ev = make_evidence(
            evidence_id="ev-verified-001",
            data={"finding_type": "VERIFIED_EVIDENCE"},
            confidence=1.0,
        )
        inv = make_investigation()
        finding = make_finding(
            finding_id="fnd-verified-001",
            evidence_ids=["ev-verified-001"],
            reality_status="VERIFIED_EVIDENCE",
        )

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        item = result.case_evidence_items[0]

        assert item["category"] == "evidence"
        assert item["relevance"] == "primary"

    def test_case_evidence_item_id_is_deterministic(self):
        """Same evidence_id + same investigation_id → same Base44 item id (dedup)."""
        ev = make_evidence(evidence_id="ev-dedup-001")
        inv = make_investigation(investigation_id="inv-dedup-001")
        finding = make_finding(finding_id="fnd-001", evidence_ids=["ev-dedup-001"])

        r1 = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        r2 = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        assert r1.case_evidence_items[0]["id"] == r2.case_evidence_items[0]["id"], \
            "Same inputs should produce same Base44 item id"

    def test_build_case_evidence_item_data_directly(self):
        """Direct call to build_case_evidence_item_data works."""
        ev = make_evidence(
            evidence_id="ev-direct-001",
            source="shodan_api",
            confidence=0.85,
            data={
                "provider": "Shodan",
                "title": "Scan result",
                "provenance": {"case_id": "case-1"},
                "evidence_refs": ["ref-1"],
            },
            tool_run_id="run-shodan-001",
        )
        ced = build_case_evidence_item_data(ev, provider_run_id="run-shodan-001")

        assert ced.source == "shodan_api"
        assert ced.provider == "Shodan"
        assert ced.confidence == 0.85
        assert ced.provider_run_id == "run-shodan-001"
        assert ced.evidence_refs == ["ref-1"]
        assert ced.provenance["case_id"] == "case-1"


# ============================================================================
# Item 2: GraphNode / GraphEdge transformation
# ============================================================================


class TestGraphTransformation:
    """Verify FindingRecord+EvidenceRecord → GraphNode/GraphEdge mapping."""

    def test_graph_nodes_are_created(self):
        """findings + evidence produce graph nodes."""
        ev = make_evidence(evidence_id="ev-graph-001")
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-graph-001", evidence_ids=["ev-graph-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        assert result.graph_nodes, "Should produce graph nodes"
        node_types = {n["node_type"] for n in result.graph_nodes}
        assert "finding" in node_types
        assert "evidence" in node_types
        assert "entity" in node_types

    def test_graph_edges_are_created(self):
        """findings + evidence produce graph edges."""
        ev = make_evidence(evidence_id="ev-edge-001")
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-edge-001", evidence_ids=["ev-edge-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        assert result.graph_edges, "Should produce graph edges"
        edge_types = {e["edge_type"] for e in result.graph_edges}
        assert "supported_by" in edge_types
        assert "about" in edge_types
        assert "supports" in edge_types

    def test_graph_node_label_is_capped_at_200(self):
        """Labels are capped at 200 chars (matching Base44 side)."""
        ev = make_evidence(evidence_id="ev-label-001")
        inv = make_investigation()
        long_claim = "A" * 300 + " has open ports"
        finding = make_finding(finding_id="fnd-label-001", claim=long_claim, evidence_ids=["ev-label-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        finding_node = [n for n in result.graph_nodes if n["node_type"] == "finding"][0]

        assert len(finding_node["label"]) <= 200
        assert finding_node["label"] == long_claim[:200]

    def test_graph_node_ids_are_deterministic(self):
        """Same inputs → same node ids."""
        ev = make_evidence(evidence_id="ev-gnid-001")
        inv = make_investigation(investigation_id="inv-gnid-001")
        finding = make_finding(finding_id="fnd-gnid-001", evidence_ids=["ev-gnid-001"])

        r1 = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")
        r2 = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        ids1 = {n["id"] for n in r1.graph_nodes}
        ids2 = {n["id"] for n in r2.graph_nodes}
        assert ids1 == ids2, "Same inputs should produce same node ids"

    def test_graph_edge_links_finding_to_evidence(self):
        """Finding→evidence edge carries correct IDs."""
        ev = make_evidence(evidence_id="ev-link-001")
        inv = make_investigation(investigation_id="inv-link-001")
        finding = make_finding(finding_id="fnd-link-001", evidence_ids=["ev-link-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        fe_edges = [e for e in result.graph_edges if e["edge_type"] == "supported_by"]
        assert fe_edges, "Should have finding→evidence edge"
        fe = fe_edges[0]
        assert fe["edge_data"]["finding_id"] == "fnd-link-001"
        assert fe["edge_data"]["evidence_id"] == "ev-link-001"

    def test_graph_edge_links_finding_to_entity(self):
        """Finding→entity edge exists when target is present."""
        ev = make_evidence(evidence_id="ev-ent-001")
        inv = make_investigation()
        finding = make_finding(
            finding_id="fnd-ent-001",
            evidence_ids=["ev-ent-001"],
            factors={"target": "example.com", "indicator_type": "domain"},
        )

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        fent_edges = [e for e in result.graph_edges if e["edge_type"] == "about"]
        assert fent_edges, "Should have finding→entity edge"
        assert fent_edges[0]["edge_data"]["entity_id"] == "example.com"

    def test_graph_edge_links_evidence_to_entity(self):
        """Evidence→entity edge exists for provider-backed evidence."""
        ev = make_evidence(evidence_id="ev-e2e-001")
        inv = make_investigation()
        finding = make_finding(finding_id="fnd-e2e-001", evidence_ids=["ev-e2e-001"])

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001")

        eent_edges = [e for e in result.graph_edges if e["edge_type"] == "supports"]
        assert eent_edges, "Should have evidence→entity edge"
        assert eent_edges[0]["edge_data"]["evidence_id"] == "ev-e2e-001"


# ============================================================================
# Item 3: ToolRunRecord mapping (Phase 5 Item B)
# ============================================================================


class TestToolRunRecordMapping:
    """Verify provider tool_call → ToolRunRecord mapping."""

    def test_tool_run_record_mapping(self):
        """Valid tool_call maps to ToolRunRecord dict."""
        tc = make_tool_call(
            tool_id="shodan",
            tool_status="ALLOW",
            run_id="run-1",
            provider="Shodan",
            target="example.com",
            capability="host",
            data={"ports": [80, 443]},
        )

        result = map_provider_tool_call_to_tool_run_record(tc, investigation_id="inv-001")

        assert result is not None
        assert result["tool_run_id"] == "run-1"        # Phase 5 Item A: actual run_id
        assert result["investigation_id"] == "inv-001"
        assert result["tool_id"] == "shodan"
        assert result["action"] == "host"
        assert result["status"] == "success"           # ALLOW → success
        assert result["payload"]["provider"] == "Shodan"
        assert result["payload"]["target"] == "example.com"
        assert result["redacted_metadata"]["tool_status"] == "ALLOW"
        assert result["redacted_metadata"]["latency_ms"] == 1200

    def test_tool_run_record_deny_maps_to_failed(self):
        """DENY → failed."""
        tc = make_tool_call(tool_status="DENY", run_id="run-deny-001")
        result = map_provider_tool_call_to_tool_run_record(tc, investigation_id="inv-001")
        assert result["status"] == "failed"

    def test_tool_run_record_blocked_maps_to_not_configured(self):
        """BLOCKED → not_configured."""
        tc = make_tool_call(tool_status="BLOCKED", run_id="run-blocked-001")
        result = map_provider_tool_call_to_tool_run_record(tc, investigation_id="inv-001")
        assert result["status"] == "not_configured"

    def test_tool_run_record_strips_credentials(self):
        """Credential-like values are stripped from output_data."""
        tc = make_tool_call(
            tool_status="ALLOW",
            run_id="run-cred-001",
            data={"api_key": "secret-key-123", "ports": [80], "token": "tok-abc"},
        )
        result = map_provider_tool_call_to_tool_run_record(tc, investigation_id="inv-001")
        output = result["result"]

        assert "api_key" not in output
        assert "token" not in output
        assert "ports" in output

    def test_tool_run_record_invalid_status_returns_none(self):
        """Unknown tool_status → None."""
        tc = {"tool_status": "UNKNOWN_STATUS", "run_id": "run-x"}
        result = map_provider_tool_call_to_tool_run_record(tc, investigation_id="inv-001")
        assert result is None


# ============================================================================
# Item 4: Full E2E bridge
# ============================================================================


class TestFullE2E:
    """End-to-end: target → Hermes investigation → provider result
    → EvidenceRecord → FindingRecord → Base44 transformation → CaseEvidenceItem, GraphNode, GraphEdge."""

    def test_e2e_full_flow(self):
        """Complete pipeline: investigation + findings + evidence + tool_calls → Base44 records."""
        inv = make_investigation(
            investigation_id="inv-e2e-001",
            tenant_id="org-acme",
            target="example.com",
            type="domain",
            status="COMPLETED",
        )

        tool_call = make_tool_call(
            tool_id="shodan",
            run_id="run-shodan-001",
            provider="Shodan",
            source="shodan_api",
            target="example.com",
            capability="host",
            data={"ports": [80, 443], "services": ["http", "https"]},
        )

        ev = make_evidence(
            evidence_id="ev-e2e-001",
            investigation_id="inv-e2e-001",
            source="shodan_api",
            source_type="tool",
            target="example.com",
            tool_run_id="run-shodan-001",   # Phase 5 Item A: real run_id
            data={
                "provider": "Shodan",
                "title": "Shodan scan of example.com",
                "description": "Open ports: 80, 443",
                "finding_type": "EXTERNAL_INTELLIGENCE",
                "source_timestamp": "2026-09-27T09:00:00Z",
                "evidence_refs": ["ref-shodan-001"],
                "entity_refs": ["entity-example-com"],
                "indicator_refs": ["indicator-example-com-domain"],
                "provenance": {
                    "case_id": "case-acme-001",
                    "investigation_id": "inv-e2e-001",
                    "organization_id": "org-acme",
                    "agent_id": "agent-1",
                    "agent_run_id": "run-shodan-001",
                    "tool_id": "shodan",
                    "task_id": "task-shodan-001",
                    "collected_timestamp": "2026-09-27T10:00:00Z",
                },
                "metadata": {"ports": [80, 443]},
            },
            confidence=0.9,
        )

        finding = make_finding(
            finding_id="fnd-e2e-001",
            investigation_id="inv-e2e-001",
            claim="example.com has open ports 80 and 443",
            evidence_ids=["ev-e2e-001"],
            reality_status="EXTERNAL_INTELLIGENCE",   # ← NOT downgraded
            risk_score=0.75,
            factors={
                "provider": "Shodan",
                "source": "shodan_api",
                "source_type": "tool",
                "target": "example.com",
                "target_type": "domain",
                "indicator_type": "domain",
                "indicator": "example.com",
                "finding_type": "EXTERNAL_INTELLIGENCE",
                "confidence": 0.9,
                "collected_timestamp": "2026-09-27T10:00:00Z",
                "source_timestamp": "2026-09-27T09:00:00Z",
                "evidence_refs": ["ref-shodan-001"],
                "entity_refs": ["entity-example-com"],
                "indicator_refs": ["indicator-example-com-domain"],
            },
        )

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001",
                                      provider_tool_calls=[tool_call])

        # --- CaseEvidenceItem ---
        assert len(result.case_evidence_items) == 1
        item = result.case_evidence_items[0]
        assert item["_hermes_evidence_id"] == "ev-e2e-001"
        assert item["_hermes_investigation_id"] == "inv-e2e-001"
        assert item["case_id"] == "case-acme-001"
        assert item["category"] == "external_intelligence"
        assert item["relevance"] == "supporting"
        assert item["data"]["provider"] == "Shodan"
        assert item["data"]["source"] == "shodan_api"
        assert item["data"]["target"] == "example.com"
        assert item["data"]["confidence"] == 0.9
        assert item["data"]["source_timestamp"] == "2026-09-27T09:00:00Z"
        assert item["data"]["collected_at"] == "2026-09-27T10:00:00Z"
        assert item["data"]["provenance"]["organization_id"] == "org-acme"
        assert item["data"]["provenance"]["agent_id"] == "agent-1"
        assert item["data"]["provider_run_id"] == "run-shodan-001"  # Phase 5 Item A

        # --- GraphNode ---
        assert len(result.graph_nodes) == 3  # finding + evidence + entity
        node_types = {n["node_type"] for n in result.graph_nodes}
        assert node_types == {"finding", "evidence", "entity"}

        finding_node = [n for n in result.graph_nodes if n["node_type"] == "finding"][0]
        assert finding_node["node_data"]["finding_type"] == "EXTERNAL_INTELLIGENCE"
        assert finding_node["node_data"]["provider"] == "Shodan"
        assert finding_node["node_data"]["evidence_ids"] == ["ev-e2e-001"]

        evidence_node = [n for n in result.graph_nodes if n["node_type"] == "evidence"][0]
        assert evidence_node["node_data"]["evidence_id"] == "ev-e2e-001"
        assert evidence_node["node_data"]["provider"] == "Shodan"
        assert evidence_node["node_data"]["source_type"] == "tool"
        assert evidence_node["node_data"]["confidence"] == 0.9

        entity_node = [n for n in result.graph_nodes if n["node_type"] == "entity"][0]
        assert entity_node["node_data"]["entity_id"] == "example.com"
        assert entity_node["node_data"]["entity_type"] == "domain"

        # --- GraphEdge ---
        assert len(result.graph_edges) == 3  # finding→evidence, finding→entity, evidence→entity
        edge_types = {e["edge_type"] for e in result.graph_edges}
        assert edge_types == {"supported_by", "about", "supports"}

        # --- ToolRunRecord ---
        assert len(result.tool_run_records) == 1
        tr = result.tool_run_records[0]
        assert tr["tool_run_id"] == "run-shodan-001"
        assert tr["status"] == "success"
        assert tr["tool_id"] == "shodan"
        assert tr["action"] == "host"

        # --- IDs linked end-to-end ---
        # evidence_id in CaseEvidenceItem.data matches GraphNode evidence node
        ev_node_id = f"gn-ev-inv-e2e-001-{'ev-e2e-001'[:12]}"
        assert any(n["id"] == ev_node_id and n["node_type"] == "evidence" for n in result.graph_nodes)

        # finding_id in GraphNode finding node
        fn_node_id = f"gn-fnd-inv-e2e-001-{'fnd-e2e-001'[:12]}"
        assert any(n["id"] == fn_node_id and n["node_type"] == "finding" for n in result.graph_nodes)

        # evidence_id in edge data matches evidence node id
        fe_edge = [e for e in result.graph_edges if e["edge_type"] == "supported_by"][0]
        assert fe_edge["edge_data"]["evidence_id"] == "ev-e2e-001"
        assert fe_edge["target_node_id"] == ev_node_id

    def test_e2e_excludes_unsupported_status_tool_calls(self):
        """Tool calls with status other than ALLOW/DENY/BLOCKED are excluded."""
        inv = make_investigation()
        ev = make_evidence(evidence_id="ev-xx-001")
        finding = make_finding(finding_id="fnd-xx-001", evidence_ids=["ev-xx-001"])
        tc = {"tool_status": "UNKNOWN", "run_id": "run-xx"}

        result = bridge_investigation(inv, [finding], [ev], case_id="case-acme-001",
                                      provider_tool_calls=[tc])
        assert result.tool_run_records == []

    def test_e2e_organization_isolation(self):
        """Different org → different case_id, data scoped to that case."""
        inv_a = make_investigation(investigation_id="inv-org-a", tenant_id="org-acme")
        inv_b = make_investigation(investigation_id="inv-org-b", tenant_id="org-xyz")
        ev_a = make_evidence(evidence_id="ev-org-a", investigation_id="inv-org-a")
        ev_b = make_evidence(evidence_id="ev-org-b", investigation_id="inv-org-b")
        f_a = make_finding(finding_id="fnd-a", investigation_id="inv-org-a", evidence_ids=["ev-org-a"])
        f_b = make_finding(finding_id="fnd-b", investigation_id="inv-org-b", evidence_ids=["ev-org-b"])

        r_a = bridge_investigation(inv_a, [f_a], [ev_a], case_id="case-acme-001")
        r_b = bridge_investigation(inv_b, [f_b], [ev_b], case_id="case-xyz-001")

        # Each result scoped to its own case
        assert all(item["case_id"] == "case-acme-001" for item in r_a.case_evidence_items)
        assert all(item["case_id"] == "case-xyz-001" for item in r_b.case_evidence_items)

        # IDs from different orgs don't collide
        ids_a = {item["_hermes_evidence_id"] for item in r_a.case_evidence_items}
        ids_b = {item["_hermes_evidence_id"] for item in r_b.case_evidence_items}
        assert ids_a == {"ev-org-a"}
        assert ids_b == {"ev-org-b"}

    def test_e2e_dedup_same_evidence_id(self):
        """Same evidence_id + investigation_id → only one CaseEvidenceItem (dedup marker)."""
        inv = make_investigation(investigation_id="inv-dedup-001")
        ev = make_evidence(evidence_id="ev-dedup-001", investigation_id="inv-dedup-001")
        finding1 = make_finding(finding_id="fnd-d1", investigation_id="inv-dedup-001", evidence_ids=["ev-dedup-001"])
        finding2 = make_finding(finding_id="fnd-d2", investigation_id="inv-dedup-001", evidence_ids=["ev-dedup-001"])

        # bridge_investigation creates one CaseEvidenceItem per evidence_id
        result = bridge_investigation(inv, [finding1, finding2], [ev], case_id="case-acme-001")

        # Should produce exactly 1 evidence item for this evidence_id
        ev_items = [item for item in result.case_evidence_items
                    if item["_hermes_evidence_id"] == "ev-dedup-001"]
        assert len(ev_items) == 1, f"Expected 1 deduped item, got {len(ev_items)}: {[i['id'] for i in ev_items]}"

    def test_e2e_multiple_evidence_ids(self):
        """Multiple evidence IDs → multiple CaseEvidenceItems."""
        inv = make_investigation()
        ev1 = make_evidence(evidence_id="ev-multi-1", investigation_id="inv-multi")
        ev2 = make_evidence(evidence_id="ev-multi-2", investigation_id="inv-multi")
        finding = make_finding(
            finding_id="fnd-multi",
            investigation_id="inv-multi",
            evidence_ids=["ev-multi-1", "ev-multi-2"],
        )

        result = bridge_investigation(inv, [finding], [ev1, ev2], case_id="case-acme-001")

        ev_items = [item for item in result.case_evidence_items
                    if item["_hermes_investigation_id"] == inv.investigation_id]
        assert len(ev_items) == 2
        assert {item["_hermes_evidence_id"] for item in ev_items} == {"ev-multi-1", "ev-multi-2"}

    def test_map_finding_type_to_category_coverage(self):
        """All finding types map correctly."""
        assert map_finding_type_to_category("EXTERNAL_INTELLIGENCE") == "external_intelligence"
        assert map_finding_type_to_category("VERIFIED_EVIDENCE") == "evidence"
        assert map_finding_type_to_category("AI_INFERENCE") == "ai_inference"
        assert map_finding_type_to_category("INVESTIGATOR_CONCLUSION") == "conclusion"
        assert map_finding_type_to_category("UNKNOWN_TYPE") == "supporting"

    def test_map_confidence_coverage(self):
        """Confidence bands are correct."""
        assert map_confidence(0.0) == "low"
        assert map_confidence(0.3) == "low"
        assert map_confidence(0.49) == "low"
        assert map_confidence(0.5) == "medium"
        assert map_confidence(0.749) == "medium"
        assert map_confidence(0.75) == "high"
        assert map_confidence(1.0) == "high"
        assert map_confidence(None) == "low"
