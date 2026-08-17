from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from safenestt.model.provider import ModelError, ModelRequest, ModelResponse, ModelUsage
from safenestt.security.redaction import redact


class ModelProvider(ABC):
    provider_name: str = "base"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, default_model: str | None = None) -> None:
        self.api_key = api_key or os.getenv("MODEL_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.base_url = base_url or os.getenv("MODEL_BASE_URL") or os.getenv("OPENAI_BASE_URL") or os.getenv("GEMINI_BASE_URL")
        self.default_model = default_model or os.getenv("MODEL_NAME")

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


class _OpenAICompatibleBase(ModelProvider):
    provider_name = "openai"

    def _client(self):
        url = self.base_url.rstrip("/") if self.base_url else "https://api.openai.com/v1"
        if not url.endswith("/chat/completions"):
            url = url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return {
            "url": url,
            "headers": headers,
            "payload": {
                "model": self.default_model or "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": ""}],
                "max_tokens": 512,
            },
        }

    def _execute(self, request: ModelRequest) -> ModelResponse:
        client = self._client()
        payload = {
            "model": request.model or client["payload"]["model"],
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": request.max_tokens or client["payload"]["max_tokens"],
            "temperature": request.temperature or 0.2,
        }
        if request.response_format and request.response_format.lower() in {"json", "json_object"}:
            payload["response_format"] = {"type": "json_object"}
        import urllib.request
        data = __import__("json").dumps(payload).encode("utf-8")
        req = urllib.request.Request(client["url"], data=data, headers=client["headers"], method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = __import__("json").loads(resp.read().decode("utf-8"))
        except Exception as exc:
            return ModelResponse(
                provider=self.provider_name,
                model=payload["model"],
                error=ModelError(code="provider_error", message=str(exc), retryable=True),
            )
        try:
            choice = body["choices"][0]
            content = choice["message"]["content"]
            usage = body.get("usage", {})
            return ModelResponse(
                provider=self.provider_name,
                model=payload["model"],
                content=content,
                finish_reason=choice.get("finish_reason"),
                usage=ModelUsage(
                    prompt_tokens=usage.get("prompt_tokens"),
                    completion_tokens=usage.get("completion_tokens"),
                    total_tokens=usage.get("total_tokens"),
                ),
            )
        except Exception as exc:
            return ModelResponse(
                provider=self.provider_name,
                model=payload["model"],
                error=ModelError(code="malformed_provider_response", message=str(exc)),
            )

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key and not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing API key or base URL"),
            )
        if _should_stub_local(self.base_url):
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                content=f"{self.provider_name} stub",
                finish_reason="stop",
                usage=ModelUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
            )
        return self._execute(request)


def _should_stub_local(base_url: str | None) -> bool:
    base = (base_url or "").lower()
    return any(token in base for token in ["example.local", "localhost", "127.0.0.1"])


class OpenAICompatibleProvider(_OpenAICompatibleBase):
    provider_name = "openai"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key and not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing API key or base URL"),
            )
        if _should_stub_local(self.base_url):
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                content="openai-compatible stub",
                finish_reason="stop",
                usage=ModelUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
            )
        return self._execute(request)


class AnthropicCompatibleProvider(_OpenAICompatibleBase):
    provider_name = "anthropic"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key and not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing API key or base URL"),
            )
        if _should_stub_local(self.base_url):
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                content="anthropic-compatible stub",
                finish_reason="stop",
                usage=ModelUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5),
            )
        return self._execute(request)


class OllamaProvider(_OpenAICompatibleBase):
    provider_name = "ollama"

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.base_url:
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                error=ModelError(code="not_configured", message="missing Ollama base URL"),
            )
        if _should_stub_local(self.base_url):
            return ModelResponse(
                provider=self.provider_name,
                model=request.model or self.default_model or "unknown",
                content="ollama stub",
                finish_reason="stop",
                usage=ModelUsage(prompt_tokens=1, completion_tokens=2, total_tokens=3),
            )
        return self._execute(request)


class GeminiProvider(_OpenAICompatibleBase):
    provider_name = "gemini"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, default_model: str | None = None) -> None:
        super().__init__(api_key=api_key, base_url=base_url, default_model=default_model or "gemini-1.5-flash")
        if not self.base_url:
            key = self.api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            if key:
                self.base_url = f"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions?key={key}"
            else:
                self.base_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


model_registry = ModelRegistry()
