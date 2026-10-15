"""Derived investigation intelligence: planning, correlation, graph, provenance and risk.

This module is intentionally side-effect free. It does not change the Hermes/Base44 API
contract and can be applied to existing findings/evidence without a schema migration.

It provides deterministic intelligence layer on top of persisted findings and evidence:
- InvestigationPlanner: select lanes from indicators
- EvidenceCorrelator: explicit finding↔evidence lineage
- EntityGraphBuilder: relationship graph from evidence
- EvidenceInferenceClassifier: evidence-vs-inference distinction
- RiskAssessor: deterministic risk score
- build_dossier_intelligence: compose full intelligence payload
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Iterable


@dataclass(frozen=True)
class InvestigationPlan:
    target: str
    lanes: list[str]
    stages: list[str]
    rationale: dict[str, str]


@dataclass(frozen=True)
class EvidenceLink:
    finding_id: str
    evidence_id: str
    relationship: str
    source: str | None
    observed_at: str | None
    confidence: float


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0


class InvestigationPlanner:
    """Deterministically select investigation lanes from known indicators."""

    def plan(self, target: str, indicators: dict[str, Any] | None = None) -> InvestigationPlan:
        indicators = {k: v for k, v in (indicators or {}).items() if v not in (None, "", [], {})}
        lanes = ["osint", "threat_intel"]
        rationale = {
            "osint": "Collect public identity, domain, network and contextual signals.",
            "threat_intel": "Check indicators against threat-intelligence sources.",
        }
        specialized = []
        if any(k in indicators for k in ("wallet_address", "transaction_hash", "chain", "crypto")):
            specialized.append("crypto")
            rationale["crypto"] = "Blockchain indicators are present."
        if any(k in indicators for k in ("email", "phone", "username", "identity")):
            specialized.append("identity")
            rationale["identity"] = "Identity-linked indicators are present."
        if specialized:
            lanes.extend(specialized)
        return InvestigationPlan(
            target=target,
            lanes=lanes,
            stages=[
                "PLANNING",
                "MULTI_AGENT_COLLECTION",
                "EVIDENCE_CORRELATION",
                "ENTITY_GRAPH",
                "REALITY_CHECK",
                "RISK_ASSESSMENT",
                "FINDINGS",
                "DOSSIER",
            ],
            rationale=rationale,
        )


class EvidenceCorrelator:
    """Build explicit finding↔evidence lineage without modifying stored records."""

    def correlate(self, findings: Iterable[dict[str, Any]], evidence: Iterable[dict[str, Any]]) -> dict[str, Any]:
        evidence_by_id = {str(e.get("evidence_id")): e for e in evidence if e.get("evidence_id")}
        links: list[EvidenceLink] = []
        for finding in findings:
            fid = str(finding.get("finding_id") or "")
            if not fid:
                continue
            for eid in finding.get("evidence_ids") or []:
                ev = evidence_by_id.get(str(eid))
                if not ev:
                    continue
                links.append(EvidenceLink(
                    finding_id=fid,
                    evidence_id=str(eid),
                    relationship="supports",
                    source=ev.get("source"),
                    observed_at=_iso(ev.get("observed_at")),
                    confidence=float(ev.get("confidence") or 0.0),
                ))
        return {
            "links": [link.__dict__ for link in links],
            "finding_count": len({link.finding_id for link in links}),
            "evidence_count": len({link.evidence_id for link in links}),
        }


class EntityGraphBuilder:
    """Create a lightweight relationship graph from investigation evidence."""

    def build(self, target: str, findings: Iterable[dict[str, Any]], evidence: Iterable[dict[str, Any]]) -> dict[str, Any]:
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        target_id = _node_id("target", target)
        nodes[target_id] = GraphNode(target_id, "target", target)
        for ev in evidence:
            eid = str(ev.get("evidence_id") or "")
            if not eid:
                continue
            source = str(ev.get("source") or "unknown")
            ev_node = _node_id("evidence", eid)
            nodes[ev_node] = GraphNode(ev_node, "evidence", eid, {"source": source, "source_type": ev.get("source_type")})
            edges.append(GraphEdge(target_id, ev_node, "supported_by", [eid], float(ev.get("confidence") or 0.0)))
        for f in findings:
            fid = str(f.get("finding_id") or "")
            if not fid:
                continue
            f_node = _node_id("finding", fid)
            nodes[f_node] = GraphNode(f_node, "finding", str(f.get("claim") or fid), {"reality_status": f.get("reality_status"), "risk_score": f.get("risk_score", 0.0)})
            for eid in f.get("evidence_ids") or []:
                ev_node = _node_id("evidence", str(eid))
                if ev_node in nodes:
                    edges.append(GraphEdge(f_node, ev_node, "supported_by", [str(eid)], float(f.get("risk_score") or 0.0)))
        return {
            "nodes": [n.__dict__ for n in nodes.values()],
            "edges": [e.__dict__ for e in edges],
        }


class EvidenceInferenceClassifier:
    """Make the evidence-vs-inference distinction explicit and deterministic."""

    VERIFIED = "VERIFIED_EVIDENCE"
    INFERENCE = "AI_INFERENCE"
    CORRELATED = "CORRELATED_EVIDENCE"
    UNVERIFIED = "UNVERIFIED_CLAIM"

    def classify(self, finding: dict[str, Any], evidence: Iterable[dict[str, Any]]) -> str:
        status = str(finding.get("reality_status") or "").upper()
        if status in {self.VERIFIED, self.INFERENCE, self.UNVERIFIED, self.CORRELATED}:
            return status
        ids = {str(e.get("evidence_id")) for e in evidence if e.get("evidence_id")}
        refs = {str(x) for x in (finding.get("evidence_ids") or [])}
        if refs and refs.issubset(ids):
            return self.CORRELATED if len(refs) > 1 else self.VERIFIED
        return self.INFERENCE


class RiskAssessor:
    """Deterministic risk score based on evidence coverage and finding signals.

    This runs alongside the existing calculate_risk() from safenestt.investigations.risk.
    It provides an evidence-coverage-weighted score that complements the LLM-derived
    confidence scores from the primary risk engine.
    """

    def assess(self, findings: Iterable[dict[str, Any]], evidence: Iterable[dict[str, Any]]) -> dict[str, Any]:
        fs = list(findings)
        es = list(evidence)
        scores = []
        for f in fs:
            confidence = max(0.0, min(1.0, float(f.get("confidence", f.get("risk_score", 0.0)) or 0.0)))
            coverage = min(1.0, len(f.get("evidence_ids") or []) / 3.0)
            scores.append((0.7 * confidence + 0.3 * coverage) * 100)
        score = round(sum(scores) / len(scores), 2) if scores else 0.0
        level = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH" if score < 80 else "CRITICAL"
        return {
            "score": score,
            "level": level,
            "method": "deterministic_evidence_weighted_v1",
            "finding_count": len(fs),
            "evidence_count": len(es),
        }


def build_dossier_intelligence(
    target: str,
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    indicators: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose full intelligence payload from investigation findings and evidence.

    Returns a dict with:
    - plan: InvestigationPlan (lanes, stages, rationale)
    - findings: classified findings with provenance
    - correlation: finding↔evidence links
    - entity_graph: nodes and edges
    - risk_assessment: deterministic evidence-weighted score
    - dossier: complete structured report
    - generated_at: ISO timestamp
    """
    planner = InvestigationPlanner()
    plan = planner.plan(target, indicators)
    classifier = EvidenceInferenceClassifier()
    classified: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        item["evidence_class"] = classifier.classify(item, evidence)
        item["provenance"] = {
            "finding_id": item.get("finding_id"),
            "evidence_ids": list(item.get("evidence_ids") or []),
            "sources": [e.get("source") for e in evidence if e.get("evidence_id") in (item.get("evidence_ids") or [])],
            "timestamps": [_iso(e.get("observed_at")) for e in evidence if e.get("evidence_id") in (item.get("evidence_ids") or [])],
            "confidence": float(item.get("confidence", item.get("risk_score", 0.0)) or 0.0),
        }
        classified.append(item)
    correlation = EvidenceCorrelator().correlate(classified, evidence)
    graph = EntityGraphBuilder().build(target, classified, evidence)
    risk = RiskAssessor().assess(classified, evidence)
    return {
        "plan": plan.__dict__,
        "findings": classified,
        "correlation": correlation,
        "entity_graph": graph,
        "risk_assessment": risk,
        "dossier": {
            "target": target,
            "executive_summary": "Structured investigation results with explicit evidence lineage and risk assessment.",
            "findings": classified,
            "evidence": list(evidence),
            "risk": risk,
            "graph": graph,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{sha256(value.encode()).hexdigest()[:16]}"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)
