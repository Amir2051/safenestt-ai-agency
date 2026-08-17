from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from safenestt.model.provider import ModelError, ModelRequest, ModelResponse, ModelUsage
from safenestt.security.redaction import redact


class ModelProvider(ABC):
    provider_name: str = "base"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, default_model: str | None = None) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.default_model = default_model

    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        pass

    def health_check(self) -> ModelResponse:
        configured = bool(self.api_key or self.base_url)
        return ModelResponse(
            provider=self.provider_name,
            model=self.default_model or "unknown",
            content="configured" if configured else "not_configured",
            finish_reason="health",
            warnings=[] if configured else ["provider_not_configured"],
        )


@dataclass
class ModelProviderConfig:
    provider: str
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None


class ModelRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ModelProvider] = {}
        self._default_provider: str | None = None

    def register(self, provider: ModelProvider) -> None:
        if not getattr(provider, "provider_name", None):
            raise ValueError("provider_name is required")
        if provider.provider_name in self._providers:
            raise ValueError(f"provider {provider.provider_name} is already registered")
        self._providers[provider.provider_name] = provider

    def get(self, provider_name: str) -> ModelProvider | None:
        return self._providers.get(provider_name)

    def default(self) -> ModelProvider | None:
        if self._default_provider:
            return self._providers.get(self._default_provider)
        return next(iter(self._providers.values()), None)

    def set_default(self, provider_name: str) -> None:
        if provider_name not in self._providers:
            raise ValueError(f"provider {provider_name} is not registered")
        self._default_provider = provider_name


class MockModelProvider(ModelProvider):
    provider_name = "mock"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, default_model: str | None = None, provider_name: str | None = None) -> None:
        super().__init__(api_key=api_key, base_url=base_url, default_model=default_model or "mock-model")
        if provider_name:
            self.provider_name = provider_name
        self.responses: dict[str, dict[str, Any]] = {}

    def generate(self, request: ModelRequest) -> ModelResponse:
        model = request.model or self.default_model
        key = f"{model}:{request.prompt}"
        if key in self.responses:
            payload = self.responses[key]
            return self._response_from_payload(model, payload)

        return ModelResponse(
            provider=self.provider_name,
            model=model,
            content=f"mock response for: {request.prompt[:64]}",
            finish_reason="stop",
            usage=ModelUsage(prompt_tokens=4, completion_tokens=8, total_tokens=12),
        )

    def health_check(self) -> ModelResponse:
        return ModelResponse(
            provider=self.provider_name,
            model=self.default_model,
            content="configured",
            finish_reason="health",
        )

    def _response_from_payload(self, model: str, payload: dict[str, Any]) -> ModelResponse:
        return ModelResponse(
            provider=self.provider_name,
            model=model,
            content=payload.get("content"),
            structured_data=payload.get("structured_data"),
            usage=ModelUsage(**payload.get("usage", {})),
            finish_reason=payload.get("finish_reason"),
            warnings=payload.get("warnings", []),
            error=ModelError(**payload["error"]) if payload.get("error") else None,
        )


class OpenAICompatibleProvider(ModelProvider):
    provider_name = "openai"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key and not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing API key or base URL"),
            )
        return ModelResponse(
            provider=self.provider_name,
            model=request.model or self.default_model or "unknown",
            content="openai-compatible stub",
            finish_reason="stop",
            usage=ModelUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
        )


class AnthropicCompatibleProvider(ModelProvider):
    provider_name = "anthropic"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key and not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing API key or base URL"),
            )
        return ModelResponse(
            provider=self.provider_name,
            model=request.model or self.default_model or "unknown",
            content="anthropic-compatible stub",
            finish_reason="stop",
            usage=ModelUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
        )


class OllamaProvider(ModelProvider):
    provider_name = "ollama"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing Ollama base URL"),
            )
        return ModelResponse(
            provider=self.provider_name,
            model=request.model or self.default_model or "unknown",
            content="ollama stub",
            finish_reason="stop",
            usage=ModelUsage(prompt_tokens=1, completion_tokens=2, total_tokens=3),
        )


model_registry = ModelRegistry()
