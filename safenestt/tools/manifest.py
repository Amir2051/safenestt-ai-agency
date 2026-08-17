from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolManifest:
    tool_id: str
    name: str
    description: str
    provider: str
    actions: list[str] = field(default_factory=list)
    risk_level: str = "LOW"
    required_permissions: list[str] = field(default_factory=list)
    rate_limit: dict[str, Any] = field(default_factory=lambda: {"scope": "agent", "limit": 10, "window_seconds": 60})
    configuration_schema: dict[str, Any] = field(default_factory=dict)
    enabled: bool = False
    version: str = "0.1.0"


def default_tool_manifest(tool_id: str) -> ToolManifest:
    return ToolManifest(
        tool_id=tool_id,
        name=tool_id,
        description=f"Mock tool: {tool_id}",
        provider=tool_id,
        actions=[],
        enabled=False,
    )
