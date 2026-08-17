from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from safenestt.security.redaction import redact


@dataclass
class MockWebSearchResult:
    query: str
    limit: int = 5

    def execute(self, agent, capability, payload):
        return self.to_tool_result()

    def to_tool_result(self) -> dict[str, Any]:
        return redact({
            "tool_id": "mock.web_search",
            "action": "search",
            "status": "success",
            "data": {"query": self.query, "results": [{"title": "result-1", "url": "https://example.com/1"}]},
            "metadata": {"limit": self.limit},
        })


@dataclass
class MockDocumentLookupResult:
    document_id: str

    def execute(self, agent, capability, payload):
        return self.to_tool_result()

    def to_tool_result(self) -> dict[str, Any]:
        return redact({
            "tool_id": "mock.document_lookup",
            "action": "lookup",
            "status": "success",
            "data": {"document_id": self.document_id, "title": "Mock Document"},
            "metadata": {"source": "mock"},
        })


@dataclass
class MockURLAnalysisResult:
    url: str

    def execute(self, agent, capability, payload):
        return self.to_tool_result()

    def to_tool_result(self) -> dict[str, Any]:
        return redact({
            "tool_id": "mock.url_analysis",
            "action": "analyze",
            "status": "success",
            "data": {"url": self.url, "risk": "low"},
            "metadata": {},
        })


@dataclass
class MockIdentityLookupResult:
    identifier: str

    def execute(self, agent, capability, payload):
        return self.to_tool_result()

    def to_tool_result(self) -> dict[str, Any]:
        return redact({
            "tool_id": "mock.identity_lookup",
            "action": "lookup",
            "status": "success",
            "data": {"identifier": self.identifier, "matches": 0},
            "metadata": {"mode": "mock"},
        })


class ProviderFailure(Exception):
    pass


class ProviderTimeout(Exception):
    pass


class MockFailureAdapter:
    def execute(self, agent, capability, payload):
        raise ProviderFailure("mock provider failure")


class MockTimeoutAdapter:
    def execute(self, agent, capability, payload):
        raise ProviderTimeout("mock provider timeout")


class MockMalformedAdapter:
    def execute(self, agent, capability, payload):
        return True


mock_provider_failure = MockFailureAdapter()
mock_provider_timeout = MockTimeoutAdapter()
mock_provider_malformed = MockMalformedAdapter()
