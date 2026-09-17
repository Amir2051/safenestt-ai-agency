from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from safenestt.security.redaction import redact


class RateLimitScope(str):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    PROVIDER = "provider"
    ORGANIZATION = "organization"
    API_KEY = "api_key"  # NEW: per-API-key rate limiting


class RateLimitDecision(str):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    reset_at: datetime
    scope: str
    detail: str | None = None


class RateLimiter(ABC):
    @abstractmethod
    def check(self, scope: str, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        raise NotImplementedError


@dataclass
class InMemoryRateLimitEntry:
    tokens: int
    limit: int
    reset_at: datetime


class InMemoryRateLimiter(RateLimiter):
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], InMemoryRateLimitEntry] = {}

    def check(self, scope: str, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = datetime.utcnow()
        entry_key = (scope, key)
        entry = self._entries.get(entry_key)
        if entry is None or entry.reset_at <= now:
            entry = InMemoryRateLimitEntry(tokens=limit, limit=limit, reset_at=now + timedelta(seconds=window_seconds))
            self._entries[entry_key] = entry
        if entry.tokens <= 0:
            return RateLimitResult(allowed=False, remaining=0, limit=entry.limit, reset_at=entry.reset_at, scope=scope, detail="rate_limit_exceeded")
        entry.tokens -= 1
        return RateLimitResult(allowed=True, remaining=entry.tokens, limit=entry.limit, reset_at=entry.reset_at, scope=scope)


class RateLimitService:
    def __init__(self, limiter: RateLimiter | None = None) -> None:
        self.limiter = limiter or InMemoryRateLimiter()

    def enforce(self, scope: str, key: str, limit: int = 10, window_seconds: int = 60) -> RateLimitResult:
        return self.limiter.check(scope, key, limit, window_seconds)
