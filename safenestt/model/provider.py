from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelUsage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelError:
    code: str
    message: str
    detail: str | None = None
    raw: dict[str, Any] | None = None


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
class ModelRequest:
    prompt: str
    model: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    structured: bool = False
    metadata: dict[str, Any] | None = None


@dataclass
class ModelProviderConfig:
    provider: str
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
