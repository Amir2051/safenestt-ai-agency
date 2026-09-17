from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any


@dataclass
class Provenance:
    case_id: str
    investigation_id: str | None = None
    organization_id: str | None = None
    created_by: str | None = None
    agent_id: str | None = None
    agent_run_id: str | None = None
    task_id: str | None = None
    tool_id: str | None = None
    provider: str | None = None
    source: str | None = None
    source_timestamp: str | None = None
    collected_timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    evidence_refs: list[str] = field(default_factory=list)
    entity_refs: list[str] = field(default_factory=list)
    indicator_refs: list[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    finding_type: str
    title: str
    description: str
    confidence: float = 0.0
    status: str = "open"
    requires_human_review: bool = True
    provenance: Provenance | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.finding_type not in {
            "VERIFIED_EVIDENCE",
            "EXTERNAL_INTELLIGENCE",
            "AI_INFERENCE",
            "INVESTIGATOR_CONCLUSION",
        }:
            raise ValueError(f"Unsupported finding_type: {self.finding_type}")


@dataclass
class AgentRun:
    run_id: str
    agent_id: str
    task_id: str | None = None
    status: str = "queued"
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    retry_count: int = 0
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Investigation:
    investigation_id: str
    case_id: str
    status: str = "queued"
    progress: int = 0
    current_stage: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
