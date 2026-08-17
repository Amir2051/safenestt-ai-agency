from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelResponse:
    provider: str
    model: str
    content: str | None = None
    structured_data: dict[str, Any] | None = None
    usage: ModelUsage | None = None
    finish_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    error: ModelError | None = None


@dataclass
class ModelUsage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


@dataclass
class ModelError:
    code: str
    message: str
    retryable: bool = False


@dataclass
class ModelRequest:
    prompt: str
    model: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    response_format: str | None = None
    metadata: dict[str, Any] | None = None


class ModelProvider:
    provider_name: str = "base"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, default_model: str | None = None) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.default_model = default_model

    def health_check(self) -> ModelResponse:
        configured = bool(self.api_key or self.base_url)
        return ModelResponse(
            provider=self.provider_name,
            model=self.default_model or "unknown",
            content="configured" if configured else "not_configured",
            finish_reason="health",
            warnings=[] if configured else ["provider_not_configured"],
        )
