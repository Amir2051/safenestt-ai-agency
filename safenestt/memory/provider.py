from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from safenestt.registry import AgentRecord


@dataclass
class MemoryRecord:
    memory_id: str
    owner_type: str
    owner_id: str
    scope: str
    content: dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)


class MemoryProvider(ABC):
    @abstractmethod
    def add(self, record: MemoryRecord) -> MemoryRecord:
        raise NotImplementedError

    @abstractmethod
    def query(self, owner_id: str, scope: str, limit: int = 20) -> list[MemoryRecord]:
        raise NotImplementedError


class StubMemoryProvider(MemoryProvider):
    def __init__(self) -> None:
        self._records: list[MemoryRecord] = []

    def add(self, record: MemoryRecord) -> MemoryRecord:
        self._records.append(record)
        return record

    def query(self, owner_id: str, scope: str, limit: int = 20) -> list[MemoryRecord]:
        return [record for record in self._records if record.owner_id == owner_id and record.scope == scope][-limit:]


memory_provider = StubMemoryProvider()
