"""
SafeNestT Hermes → Base44 Bridge.

Maps Hermes InvestigationRecord/EvidenceRecord/FindingRecord into Base44
InvestigationCase/CaseEvidenceItem/GraphNode/GraphEdge for display in the
existing Base44 investigator workspace.

This is the Python-side transformation layer.  The same transformations are
mirrored in Base44 functions/hermesStart/entry.ts (TypeScript).  Both sides
share the same field-mapping contract so that Hermes investigation data appears
correctly in Base44 without a separate sync process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Re-exported for consumers that need the record types
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord

# ---------------------------------------------------------------------------
# Canonical mapping: Hermes record → Base44 entity
# ---------------------------------------------------------------------------

# The Base44 side already defines these in entry.ts; we mirror them here so
# Python-side tests can assert the mapping is correct without a live Base44 run.

BASE44_CATEGORY_MAP = {
    "EXTERNAL_INTELLIGENCE": "external_intelligence",
    "VERIFIED_EVIDENCE": "evidence",
    "AI_INFERENCE": "ai_inference",
    "INVESTIGATOR_CONCLUSION": "conclusion",
}


def map_finding_type_to_category(finding_type: str) -> str:
    """Hermes FindingRecord.reality_status / factors.finding_type → Base44 CaseEvidenceItem.category."""
    return BASE44_CATEGORY_MAP.get(finding_type, "supporting")


def map_confidence(confidence: float | None) -> str:
    """Hermes FindingRecord.risk_score/confidence → Base44 confidence band."""
    if confidence is None or confidence <= 0:
        return "low"
    if confidence < 0.5:
        return "low"
    if confidence < 0.75:
        return "medium"
    return "high"


# ---------------------------------------------------------------------------
# InvestigationCase mapping
# ---------------------------------------------------------------------------


@dataclass
class InvestigationCasePatch:
    """Fields to PATCH on an existing Base44 InvestigationCase after a Hermes investigation completes."""

    hermes_investigation_id: str | None = None
    hermes_status: str = "UNKNOWN"
    last_activity: str | None = None
    findings_count: int = 0
    evidence_count: int = 0
    hermes_report: str | None = None  # JSON-stringified, stored as text


def build_investigation_case_patch(
    hermes_inv: InvestigationRecord,
    *,
    findings: list[FindingRecord] | None = None,
    evidence: list[EvidenceRecord] | None = None,
) -> InvestigationCasePatch:
    """Build the InvestigationCase update payload for a completed Hermes investigation."""
    now = datetime.now(timezone.utc).isoformat()
    fcount = len(findings or [])
    ecount = len(evidence or [])
    return InvestigationCasePatch(
        hermes_investigation_id=hermes_inv.investigation_id,
        hermes_status=hermes_inv.status,
        last_activity=now,
        findings_count=fcount,
        evidence_count=ecount,
        hermes_report=None,  # report is stored separately via the report endpoint
    )


# ---------------------------------------------------------------------------
# CaseEvidenceItem mapping
# ---------------------------------------------------------------------------


@dataclass
class CaseEvidenceItemData:
    """Base44 CaseEvidenceItem.data payload built from a Hermes EvidenceRecord + FindingRecord."""

    title: str | None = None
    description: str | None = None
    source: str | None = None
    provider: str | None = None
    target: Any = None
    indicator: Any = None
    indicator_type: str | None = None
    confidence: float = 0.0
    evidence_confidence: float = 0.0
    collected_at: str | None = None
    source_timestamp: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    entity_refs: list[str] = field(default_factory=list)
    indicator_refs: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    provider_run_id: str | None = None
    source_type: str | None = None


def build_case_evidence_item_data(
    evidence: EvidenceRecord,
    finding: FindingRecord | None = None,
    *,
    provider_run_id: str | None = None,
) -> CaseEvidenceItemData:
    """Map a Hermes EvidenceRecord (+ optional FindingRecord) into Base44 CaseEvidenceItem.data.

    Preserves:
    - evidence_id (Hermes) → used to build the Base44 item id
    - source, provider, target, confidence
    - collected_at, source_timestamp, provenance
    - evidence_refs / entity_refs / indicator_refs from the evidence data dict
    - provider_run_id (Phase 5 Item A: actual provider run ID, not a random UUID)
    """
    data: dict[str, Any] = evidence.data or {}
    prov = data.get("provenance")
    if isinstance(prov, dict):
        provenance = prov
    elif isinstance(prov, str):
        provenance = {"raw": prov}
    else:
        provenance = {}

    return CaseEvidenceItemData(
        title=data.get("title") or evidence.source,
        description=data.get("description") or "",
        source=evidence.source,
        provider=data.get("provider") or (finding.factors.get("provider") if finding else None),
        target=evidence.target,
        indicator=data.get("indicator"),
        indicator_type=data.get("indicator_type") or (finding.factors.get("indicator_type") if finding else None),
        confidence=evidence.confidence,
        collected_at=evidence.observed_at.isoformat() if evidence.observed_at else None,
        source_timestamp=data.get("source_timestamp") or (finding.factors.get("source_timestamp") if finding else None),
        evidence_refs=data.get("evidence_refs") or [],
        entity_refs=data.get("entity_refs") or [],
        indicator_refs=data.get("indicator_refs") or [],
        provenance=provenance,
        metadata=data.get("metadata") or {},
        provider_run_id=provider_run_id or data.get("provider_run_id") or (finding.factors.get("provider_run_id") if finding else None),
        source_type=evidence.source_type,
    )


# ---------------------------------------------------------------------------
# GraphNode / GraphEdge mapping
# ---------------------------------------------------------------------------


@dataclass
class GraphNodeRecord:
    """A single Base44 GraphNode built from Hermes data."""

    id: str
    case_id: str
    node_type: str  # "entity" | "evidence" | "finding"
    label: str
    node_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdgeRecord:
    """A single Base44 GraphEdge built from Hermes data."""

    id: str
    case_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str  # "about" | "supports" | "supported_by"
    edge_label: str
    edge_data: dict[str, Any] = field(default_factory=dict)


def build_graph_from_findings(
    findings: list[FindingRecord],
    evidence_list: list[EvidenceRecord],
    *,
    case_id: str,
    hermes_investigation_id: str,
) -> tuple[list[GraphNodeRecord], list[GraphEdgeRecord]]:
    """Mirror the Base44 entry.ts persistEntityGraph() logic on the Python side.

    Produces GraphNode/GraphEdge records from Hermes FindingRecord + EvidenceRecord.
    Does NOT write to Base44 — returns the records for the caller (the TypeScript
    function) to create via base44.asServiceRole.entities.GraphNode/GraphEdge.
    """
    nodes: list[GraphNodeRecord] = []
    edges: list[GraphEdgeRecord] = []

    evidence_by_id = {e.evidence_id: e for e in evidence_list}

    for finding in findings:
        ftype = finding.reality_status
        target_str = finding.factors.get("target") or finding.factors.get("target_value") or ""
        evidence_ids = list(finding.evidence_ids or [])

        # --- Finding node ---
        finding_label = finding.claim[:200]
        finding_node_id = f"gn-fnd-{hermes_investigation_id}-{finding.finding_id[:12]}"

        # Determine source_type: mirror the TS logic
        if ftype == "EXTERNAL_INTELLIGENCE" and finding.factors.get("provider"):
            src_type = "external_intelligence"
        elif ftype == "VERIFIED_EVIDENCE":
            src_type = "evidence"
        else:
            src_type = "finding"

        nodes.append(GraphNodeRecord(
            id=finding_node_id,
            case_id=case_id,
            node_type="finding",
            label=finding_label,
            node_data={
                "finding_id": finding.finding_id,
                "finding_type": ftype,
                "category": map_finding_type_to_category(ftype),
                "confidence": finding.risk_score,
                "target": finding.factors.get("target"),
                "source": finding.factors.get("source") or "",
                "source_type": src_type,
                "provider": finding.factors.get("provider") or None,
                "evidence_ids": evidence_ids,
                "hermes_investigation_id": hermes_investigation_id,
                "created_at": finding.created_at.isoformat() if finding.created_at else datetime.now(timezone.utc).isoformat(),
            },
        ))

        # --- Evidence nodes (one per evidence_id) ---
        for ev_id in evidence_ids:
            ev = evidence_by_id.get(ev_id)
            if not ev:
                continue
            ev_node_id = f"gn-ev-{hermes_investigation_id}-{ev_id[:12]}"
            nodes.append(GraphNodeRecord(
                id=ev_node_id,
                case_id=case_id,
                node_type="evidence",
                label=ev.source[:200],
                node_data={
                    "evidence_id": ev_id,
                    "provider": ev.data.get("provider") or finding.factors.get("provider"),
                    "source": ev.source,
                    "source_type": ev.source_type,
                    "confidence": ev.confidence,
                    "source_timestamp": ev.data.get("source_timestamp") or None,
                    "collected_timestamp": ev.observed_at.isoformat() if ev.observed_at else None,
                    "metadata": ev.data,
                    "finding_type": ftype,
                    "hermes_investigation_id": hermes_investigation_id,
                },
            ))

        # --- Entity node (from finding target) ---
        if target_str:
            entity_node_id = f"gn-enty-{hermes_investigation_id}-{target_str[:12]}"
            nodes.append(GraphNodeRecord(
                id=entity_node_id,
                case_id=case_id,
                node_type="entity",
                label=target_str[:200],
                node_data={
                    "entity_id": target_str,
                    "entity_type": finding.factors.get("indicator_type") or "unknown",
                    "value": target_str,
                    "indicator": finding.factors.get("indicator") or None,
                    "indicator_type": finding.factors.get("indicator_type") or None,
                    "hermes_investigation_id": hermes_investigation_id,
                },
            ))

    # --- Edges ---
    evidence_by_id = {e.evidence_id: e for e in evidence_list}

    for finding in findings:
        ftype = finding.reality_status
        target_str = finding.factors.get("target") or finding.factors.get("target_value") or ""
        evidence_ids = list(finding.evidence_ids or [])
        finding_node_id = f"gn-fnd-{hermes_investigation_id}-{finding.finding_id[:12]}"

        # finding → evidence edges
        for ev_id in evidence_ids:
            ev_node_id = f"gn-ev-{hermes_investigation_id}-{ev_id[:12]}"
            edges.append(GraphEdgeRecord(
                id=f"ge-fe-{hermes_investigation_id}-{ev_id[:12]}",
                case_id=case_id,
                source_node_id=finding_node_id,
                target_node_id=ev_node_id,
                edge_type="supported_by",
                edge_label="finding_supports_evidence",
                edge_data={
                    "finding_id": finding.finding_id,
                    "evidence_id": ev_id,
                    "finding_type": ftype,
                    "hermes_investigation_id": hermes_investigation_id,
                },
            ))

        # finding → entity edge
        if target_str:
            entity_node_id = f"gn-enty-{hermes_investigation_id}-{target_str[:12]}"
            edges.append(GraphEdgeRecord(
                id=f"ge-fent-{hermes_investigation_id}-{target_str[:12]}",
                case_id=case_id,
                source_node_id=finding_node_id,
                target_node_id=entity_node_id,
                edge_type="about",
                edge_label="finding_related_to_entity",
                edge_data={
                    "finding_id": finding.finding_id,
                    "entity_id": target_str,
                    "finding_type": ftype,
                    "hermes_investigation_id": hermes_investigation_id,
                },
            ))

        # evidence → entity edges
        for ev_id in evidence_ids:
            ev_node_id = f"gn-ev-{hermes_investigation_id}-{ev_id[:12]}"
            if target_str:
                entity_node_id = f"gn-enty-{hermes_investigation_id}-{target_str[:12]}"
                edges.append(GraphEdgeRecord(
                    id=f"ge-eent-{hermes_investigation_id}-{target_str[:12]}-{ev_id[:8]}",
                    case_id=case_id,
                    source_node_id=ev_node_id,
                    target_node_id=entity_node_id,
                    edge_type="supports",
                    edge_label="evidence_supports_entity",
                    edge_data={
                        "evidence_id": ev_id,
                        "provider": (evidence_by_id.get(ev_id).data.get("provider") if evidence_by_id.get(ev_id) else None)
                                   or finding.factors.get("provider"),
                        "source": (evidence_by_id.get(ev_id).source if evidence_by_id.get(ev_id) else None)
                                  or finding.factors.get("source"),
                        "finding_type": ftype,
                        "hermes_investigation_id": hermes_investigation_id,
                    },
                ))

    return nodes, edges


# ---------------------------------------------------------------------------
# ToolRunRecord mapping (Phase 5 Item B)
# ---------------------------------------------------------------------------


def map_provider_tool_call_to_tool_run_record(
    tool_call: dict[str, Any],
    *,
    investigation_id: str,
) -> dict[str, Any] | None:
    """Map a Hermes provider tool_call dict to a ToolRunRecord-ready dict.

    Hermes provider tool_call shape (from orchestrator._provider_tool_calls):
        {
            "tool_id": "...",
            "task_id": "...",
            "tool_status": "ALLOW" | "DENY" | "BLOCKED",
            "provider": "...",
            "source": "...",
            "target": "...",
            "confidence": 0.0,
            "data": {...},
            "collected_at": "...",
            "run_id": "...",        # ← Phase 5 Item A: actual provider run ID
            "capability": "...",
            "started_at": "...",
            "latency_ms": ...,
        }

    Returns a dict matching ToolRunRecord fields, or None if the tool_call
    is not suitable (e.g. no run_id, status not mappable).
    """
    status_str = str(tool_call.get("tool_status", "")).upper()
    if status_str not in ("ALLOW", "DENY", "BLOCKED"):
        return None

    status_map = {
        "ALLOW": "success",
        "DENY": "failed",
        "BLOCKED": "not_configured",
    }

    tc = dict(tool_call)
    raw = tc.get("data") or tc.get("result") or {}
    if isinstance(raw, dict):
        # Strip credential-like values — we never log/print credentials
        safe_result: dict[str, Any] = {}
        for k, v in raw.items():
            key_lower = str(k).lower()
            if key_lower in ("api_key", "api_key_id", "token", "secret", "password", "credentials"):
                continue
            safe_result[k] = v
        tc["result"] = safe_result

    return {
        "tool_run_id": tc.get("run_id"),                        # ← Phase 5 Item A
        "investigation_id": investigation_id,
        "tool_id": tc.get("tool_id") or tc.get("provider", ""),
        "action": tc.get("capability") or tc.get("source", ""),
        "status": status_map[status_str],                        # ← top-level status
        "payload": {
            "provider": tc.get("provider"),
            "capability": tc.get("capability"),
            "target": tc.get("target"),
            "source": tc.get("source"),
        },
        "result": tc.get("result") or {},
        "executed_at": tc.get("started_at") or tc.get("collected_at") or None,
        "redacted_metadata": {
            "tool_status": status_str,
            "latency_ms": tc.get("latency_ms"),
        },
    }


# ---------------------------------------------------------------------------
# End-to-end bridge: Hermes investigation → Base44-ready payloads
# ---------------------------------------------------------------------------


@dataclass
class BridgeResult:
    """Output of a complete Hermes→Base44 bridge transformation."""

    case_id: str
    hermes_investigation_id: str
    investigation_case_patch: InvestigationCasePatch
    case_evidence_items: list[dict[str, Any]]  # each = {id, case_id, evidence_file_id, category, data, ...}
    graph_nodes: list[dict[str, Any]]           # each = {id, case_id, node_type, label, node_data, ...}
    graph_edges: list[dict[str, Any]]           # each = {id, case_id, source_node_id, target_node_id, ...}
    tool_run_records: list[dict[str, Any]]      # each = ToolRunRecord-ready dict


def bridge_investigation(
    hermes_inv: InvestigationRecord,
    findings: list[FindingRecord],
    evidence: list[EvidenceRecord],
    *,
    case_id: str,
    provider_tool_calls: list[dict[str, Any]] | None = None,
) -> BridgeResult:
    """Run the full Hermes→Base44 bridge transformation.

    Maps:
      InvestigationRecord  → InvestigationCase patch
      EvidenceRecord       → CaseEvidenceItem (with provider_run_id from tool_calls)
      FindingRecord + evidence → GraphNode/GraphEdge
      provider_tool_calls  → ToolRunRecord (Phase 5 Item B)

    All IDs are preserved from Hermes — no re-generation, no duplication.

    Tenant/org safety: the caller must already have verified that the Hermes
    investigation belongs to the Base44 case_id.  This function does not
    perform authorization — it only transforms data.
    """
    hermes_inv_id = hermes_inv.investigation_id

    # --- InvestigationCase patch ---
    case_patch = build_investigation_case_patch(hermes_inv, findings=findings, evidence=evidence)

    # --- CaseEvidenceItem records ---
    # For each evidence, attach the provider_run_id from the matching tool_call
    tool_call_by_run_id: dict[str, dict[str, Any]] = {}
    if provider_tool_calls:
        for tc in provider_tool_calls:
            rid = tc.get("run_id")
            if rid:
                tool_call_by_run_id[rid] = tc

    evidence_items: list[dict[str, Any]] = []
    for ev in evidence:
        # Find the tool_call that produced this evidence (via tool_run_id on EvidenceRecord)
        provider_run_id = ev.tool_run_id  # ← Phase 5 Item A: now set to actual run_id
        if not provider_run_id and ev.evidence_id in tool_call_by_run_id:
            provider_run_id = tool_call_by_run_id[ev.evidence_id].get("run_id")

        ced = build_case_evidence_item_data(ev, finding=None, provider_run_id=provider_run_id)

        # Find a matching finding (by evidence_ids) to enrich the data
        for f in findings:
            if ev.evidence_id in f.evidence_ids:
                # enrich with finding context
                fdata = f.data if hasattr(f, "data") else {}
                if isinstance(fdata, dict):
                    if not ced.provider and fdata.get("provider"):
                        ced.provider = fdata["provider"]
                    if not ced.source_timestamp and fdata.get("source_timestamp"):
                        ced.source_timestamp = fdata["source_timestamp"]
                    if not ced.provenance and fdata.get("provenance"):
                        ced.provenance = fdata["provenance"]
                break

        item_id = f"ev-{hermes_inv_id}-{ev.evidence_id[:12]}"
        evidence_items.append({
            "id": item_id,
            "case_id": case_id,
            "evidence_file_id": None,  # no file uploaded; evidence is data-only
            "category": map_finding_type_to_category(ev.data.get("finding_type", "EXTERNAL_INTELLIGENCE")
                                                      if isinstance(ev.data, dict) else "EXTERNAL_INTELLIGENCE"),
            "data": {
                "title": ced.title,
                "description": ced.description,
                "source": ced.source,
                "provider": ced.provider,
                "target": ced.target,
                "indicator": ced.indicator,
                "indicator_type": ced.indicator_type,
                "confidence": ced.confidence,
                "evidence_confidence": ced.evidence_confidence,
                "collected_at": ced.collected_at.replace("+00:00", "Z") if ced.collected_at else None,
                "source_timestamp": ced.source_timestamp,
                "evidence_refs": ced.evidence_refs,
                "entity_refs": ced.entity_refs,
                "indicator_refs": ced.indicator_refs,
                "provenance": ced.provenance,
                "metadata": ced.metadata,
                "provider_run_id": ced.provider_run_id,
                "source_type": ced.source_type,
                # Deduplication markers
                "_hermes_evidence_id": ev.evidence_id,
                "_hermes_investigation_id": hermes_inv_id,
            },
            "source": "extracted",
            "confidence": map_confidence(ev.confidence),
            "relevance": "primary" if ev.data.get("finding_type") == "VERIFIED_EVIDENCE" else "supporting",
            "analyst_note": f"{ev.data.get('finding_type', 'EXTERNAL_INTELLIGENCE')}: {ced.title or ev.source}".strip()[:500],
            "status": "confirmed",
            # Dedup markers
            "_hermes_evidence_id": ev.evidence_id,
            "_hermes_investigation_id": hermes_inv_id,
        })

    # --- Graph nodes and edges ---
    gn, ge = build_graph_from_findings(findings, evidence, case_id=case_id, hermes_investigation_id=hermes_inv_id)
    graph_nodes = [{
        "id": n.id,
        "case_id": n.case_id,
        "node_type": n.node_type,
        "label": n.label,
        "node_data": n.node_data,
        # Dedup
        "_hermes_investigation_id": hermes_inv_id,
    } for n in gn]
    graph_edges = [{
        "id": e.id,
        "case_id": e.case_id,
        "source_node_id": e.source_node_id,
        "target_node_id": e.target_node_id,
        "edge_type": e.edge_type,
        "edge_label": e.edge_label,
        "edge_data": e.edge_data,
        # Dedup
        "_hermes_investigation_id": hermes_inv_id,
    } for e in ge]

    # --- ToolRunRecord mapping (Phase 5 Item B) ---
    tool_run_records: list[dict[str, Any]] = []
    if provider_tool_calls:
        for tc in provider_tool_calls:
            mapped = map_provider_tool_call_to_tool_run_record(tc, investigation_id=hermes_inv_id)
            if mapped:
                tool_run_records.append(mapped)

    return BridgeResult(
        case_id=case_id,
        hermes_investigation_id=hermes_inv_id,
        investigation_case_patch=case_patch,
        case_evidence_items=evidence_items,
        graph_nodes=graph_nodes,
        graph_edges=graph_edges,
        tool_run_records=tool_run_records,
    )
