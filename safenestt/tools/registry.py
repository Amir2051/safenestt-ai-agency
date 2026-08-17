from __future__ import annotations

from typing import Any

from safenestt.tools.manifest import ToolManifest


class ToolRegistry:
    def __init__(self) -> None:
        self._manifests: dict[str, ToolManifest] = {}

    def register(self, manifest: ToolManifest) -> None:
        if manifest.tool_id in self._manifests:
            raise ValueError(f"tool already registered: {manifest.tool_id}")
        self._manifests[manifest.tool_id] = manifest

    def get(self, tool_id: str) -> ToolManifest | None:
        return self._manifests.get(tool_id)

    def all(self) -> list[ToolManifest]:
        return list(self._manifests.values())


tool_registry = ToolRegistry()
