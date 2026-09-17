from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCapability:
    tool_id: str
    name: str
    description: str
    provider: str
    actions: list[str] = field(default_factory=list)
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    rate_limit: dict[str, Any] = field(default_factory=lambda: {"scope": "agent", "limit": 10, "window_seconds": 60})
    timeout_seconds: float = 20.0
    retry_max: int = 2
    retry_backoff_seconds: float = 1.0
    auth_requirement: str = "env"
    cost: str | None = None
    error_behavior: str = "record_and_continue"
    provenance: bool = True


@dataclass
class ToolInput:
    capability: str
    payload: dict[str, Any]
    case_id: str | None = None
    investigation_id: str | None = None
    agent_id: str | None = None
    agent_run_id: str | None = None


@dataclass
class ToolOutput:
    tool_id: str
    action: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: int | None = None
    attempt: int = 1
