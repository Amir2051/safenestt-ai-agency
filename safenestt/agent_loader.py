from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from safenestt.registry import AgentRecord, AgentRegistry, AgentStatus, RiskLevel, agent_registry
from safenestt.security.permissions import PermissionManager

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

REFERENCE_ROOT = Path(os.environ.get("SAFENESTT_REFERENCE_ROOT", "reference/agency-agents"))

UPSTREAM_DIVISIONS = [
    "engineering",
    "security",
    "marketing",
    "sales",
    "product",
    "project-management",
    "specialized",
]

APPROVED_ROSTER = {
    "orchestrator": "AI Agency Orchestrator",
    "chief-of-staff": "Chief of Staff",
    "ai-engineer": "AI Engineer",
    "backend-engineer": "Backend Engineer",
    "frontend-engineer": "Frontend Engineer",
    "security-researcher": "Security Researcher",
    "osint-investigator": "OSINT Investigator",
    "fraud-investigator": "Fraud Investigator",
    "identity-graph-operator": "Identity Graph Operator",
    "product-manager": "Product Manager",
    "marketing-strategist": "Marketing Strategist",
    "sales-strategist": "Sales Strategist",
    "qa-reality-checker": "QA / Reality Checker",
}

ROSTER_SOURCE_MAP: dict[str, str | None] = {
    "orchestrator": "specialized/agents-orchestrator.md",
    "chief-of-staff": "specialized/specialized-chief-of-staff.md",
    "ai-engineer": "engineering/engineering-ai-engineer.md",
    "backend-engineer": "engineering/engineering-backend-architect.md",
    "frontend-engineer": "engineering/engineering-frontend-developer.md",
    "security-researcher": "security/security-appsec-engineer.md",
    "osint-investigator": None,
    "fraud-investigator": None,
    "identity-graph-operator": "specialized/identity-graph-operator.md",
    "product-manager": "product/product-manager.md",
    "marketing-strategist": None,
    "sales-strategist": None,
    "qa-reality-checker": "testing/testing-reality-checker.md",
}

PLACEHOLDER_DEFINITIONS: dict[str, dict[str, Any]] = {
    "osint-investigator": {
        "department": "security",
        "description": "Specialized open-source intelligence investigator for reconnaissance, source validation, and public-domain evidence collection.",
        "capabilities": ["osint", "investigation", "reconnaissance", "source-validation"],
        "knowledge_scopes": ["security", "investigation"],
        "memory_scope": "security",
    },
    "fraud-investigator": {
        "department": "security",
        "description": "Fraud pattern investigator focused on behavioral analysis, anomaly detection, and evidentiary documentation.",
        "capabilities": ["fraud-investigation", "anomaly-detection", "evidence-documentation"],
        "knowledge_scopes": ["security", "fraud-investigation"],
        "memory_scope": "security",
    },
    "marketing-strategist": {
        "department": "marketing",
        "description": "Marketing strategy lead for positioning, campaign design, and customer acquisition planning.",
        "capabilities": ["marketing", "strategy", "campaign-planning", "positioning"],
        "knowledge_scopes": ["marketing"],
        "memory_scope": "marketing",
    },
    "sales-strategist": {
        "department": "sales",
        "description": "Sales strategy lead for pipeline design, outreach strategy, and revenue execution.",
        "capabilities": ["sales", "strategy", "pipeline-planning", "outreach"],
        "knowledge_scopes": ["sales"],
        "memory_scope": "sales",
    },
}


def _parse_frontmatter(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if not text.startswith("---"):
        return data
    end = text.find("---", 3)
    if end == -1:
        return data
    block = text[3:end]
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def _source_path_for_approved(agent_id: str) -> Path | None:
    rel = ROSTER_SOURCE_MAP.get(agent_id)
    if rel is None:
        return None
    path = REFERENCE_ROOT / rel
    return path if path.exists() else None


def _placeholder_payload(name: str, agent_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "name": name,
        "department": None,
        "description": None,
        "capabilities": [],
        "model": None,
        "tools": [],
        "permissions": [],
        "risk_level": RiskLevel.LOW,
        "knowledge_scopes": [],
        "memory_scope": None,
        "supervisor": None,
        "handoff_targets": [],
        "status": AgentStatus.DRAFT,
        "source": None,
        "version": "0.1.0",
        "enabled": False,
    }
    overrides = PLACEHOLDER_DEFINITIONS.get(agent_id, {})
    for key, value in overrides.items():
        if key in payload:
            payload[key] = value
    return payload


def load_approved_roster(permission_manager: PermissionManager | None = None, registry: AgentRegistry | None = None) -> list[AgentRecord]:
    registry = registry or agent_registry
    loaded: list[AgentRecord] = []
    seen: set[str] = set()

    for agent_id, name in APPROVED_ROSTER.items():
        source_path = _source_path_for_approved(agent_id)
        record: AgentRecord | None = None

        if source_path is not None:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
            metadata = _parse_frontmatter(text)
            if "name" in metadata:
                category = metadata.get("category")
                record = AgentRecord(
                    agent_id=agent_id,
                    name=name,
                    department=category,
                    description=metadata.get("description"),
                    capabilities=[category] if category else [],
                    model=None,
                    tools=[],
                    permissions=[],
                    risk_level=RiskLevel.LOW,
                    knowledge_scopes=[],
                    memory_scope=None,
                    supervisor=None,
                    handoff_targets=[],
                    status=AgentStatus.DRAFT,
                    source=f"reference/{source_path.relative_to(REFERENCE_ROOT)}",
                    version="0.1.0",
                    enabled=False,
                )
            else:
                LOGGER.warning("Approved agent missing frontmatter name: %s", source_path)
        elif agent_id in PLACEHOLDER_DEFINITIONS:
            payload = _placeholder_payload(name, agent_id)
            record = AgentRecord(
                agent_id=payload["agent_id"],
                name=payload["name"],
                department=payload.get("department"),
                description=payload.get("description"),
                capabilities=payload.get("capabilities", []),
                model=payload.get("model"),
                tools=payload.get("tools", []),
                permissions=payload.get("permissions", []),
                risk_level=payload.get("risk_level", RiskLevel.LOW),
                knowledge_scopes=payload.get("knowledge_scopes", []),
                memory_scope=payload.get("memory_scope"),
                supervisor=payload.get("supervisor"),
                handoff_targets=payload.get("handoff_targets", []),
                status=payload.get("status", AgentStatus.DRAFT),
                source="safenestt-placeholder",
                version="0.1.0",
                enabled=False,
            )
            LOGGER.info("Loaded SafeNestT placeholder agent: %s", name)
        else:
            LOGGER.warning("Approved roster agent missing source/placeholder mapping: %s", name)

        if record is None:
            continue
        if record.agent_id in seen:
            continue
        seen.add(record.agent_id)
        registry.register(record)
        loaded.append(record)

    return loaded


def load_core_team(permission_manager: PermissionManager | None = None) -> list[AgentRecord]:
    return load_approved_roster(permission_manager=permission_manager)
