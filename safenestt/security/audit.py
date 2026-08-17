from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.registry import RiskLevel


@dataclass
class AuditEvent:
    event_id: str
    actor_type: str
    actor_id: str | None
    action: str
    decision: str
    risk_level: RiskLevel = RiskLevel.LOW
    resource_type: str | None = None
    resource_id: str | None = None
    detail: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


class AuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event

    def recent(self, limit: int = 100) -> list[AuditEvent]:
        return self.events[-limit:]


audit = AuditLogger()
