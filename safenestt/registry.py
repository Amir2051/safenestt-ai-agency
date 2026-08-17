from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEPRECATED = "deprecated"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AgentRecord:
    agent_id: str
    name: str
    department: str | None = None
    description: str | None = None
    capabilities: list[str] = field(default_factory=list)
    model: str | None = None
    tools: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    knowledge_scopes: list[str] = field(default_factory=list)
    memory_scope: str | None = None
    supervisor: str | None = None
    handoff_targets: list[str] = field(default_factory=list)
    status: AgentStatus = AgentStatus.DRAFT
    source: str | None = None
    version: str = "0.1.0"
    enabled: bool = False


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}

    def register(self, agent: AgentRecord) -> None:
        if agent.agent_id in self._agents:
            raise ValueError(f"agent_id already registered: {agent.agent_id}")
        self._agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._agents.get(agent_id)

    def list_by_department(self, department: str) -> list[AgentRecord]:
        return [agent for agent in self._agents.values() if agent.department == department]

    def enabled_agents(self) -> list[AgentRecord]:
        return [
            agent
            for agent in self._agents.values()
            if agent.enabled and agent.status == AgentStatus.ACTIVE
        ]

    def all(self) -> list[AgentRecord]:
        return list(self._agents.values())


agent_registry = AgentRegistry()
