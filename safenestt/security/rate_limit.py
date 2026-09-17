from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from safenestt.security.redaction import redact


class RateLimitScope(str):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    PROVIDER = "provider"
    ORGANIZATION = "organization"
    API_KEY = "api_key"


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
    """Single-process rate limiter (for development/testing only)."""
    
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


class PostgreSQLRateLimiter(RateLimiter):
    """Multi-process rate limiter backed by PostgreSQL.
    
    Uses atomic UPDATE with RETURNING to safely decrement counters
    across multiple workers. The rate_limits table stores:
    - scope + key: unique identifier
    - tokens: remaining tokens in current window
    - window_start: when the current window began
    - window_seconds: duration of the window
    
    This design ensures that multiple workers observe the same counter
    and restarting a worker doesn't reset the limit.
    """
    
    def __init__(self) -> None:
        from safenestt.persistence.engine import get_engine, create_engine
        self._engine = get_engine() or create_engine()
    
    def check(self, scope: str, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        from sqlalchemy import text
        
        with self._engine.connect() as conn:
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=window_seconds)
            
            # Atomically get-or-create the counter row
            # Use INSERT ... ON CONFLICT for atomic initialization
            conn.execute(text("""
                INSERT INTO rate_limits (scope, key, tokens, window_start, window_seconds, reset_at)
                VALUES (:scope, :key, :limit, :now, :window_seconds, :reset_at)
                ON CONFLICT (scope, key) DO NOTHING
            """), {
                "scope": scope,
                "key": key,
                "limit": limit,
                "now": now,
                "window_seconds": window_seconds,
                "reset_at": now + timedelta(seconds=window_seconds)
            })
            
            # Check if window has expired and reset if needed
            conn.execute(text("""
                UPDATE rate_limits 
                SET tokens = :limit, 
                    window_start = :now,
                    reset_at = :reset_at
                WHERE scope = :scope 
                AND key = :key
                AND window_start < :window_start
            """), {
                "scope": scope,
                "key": key,
                "limit": limit,
                "now": now,
                "window_start": window_start,
                "reset_at": now + timedelta(seconds=window_seconds)
            })
            
            # Atomically decrement tokens if available
            result = conn.execute(text("""
                UPDATE rate_limits 
                SET tokens = tokens - 1
                WHERE scope = :scope 
                AND key = :key
                AND tokens > 0
                RETURNING tokens, reset_at
            """), {
                "scope": scope,
                "key": key
            }).fetchone()
            
            conn.commit()
            
            if result is None:
                # No tokens remaining — get the reset time
                reset_result = conn.execute(text("""
                    SELECT reset_at FROM rate_limits WHERE scope = :scope AND key = :key
                """), {"scope": scope, "key": key}).fetchone()
                
                reset_at = reset_result[0] if reset_result else now + timedelta(seconds=window_seconds)
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=limit,
                    reset_at=reset_at,
                    scope=scope,
                    detail="rate_limit_exceeded"
                )
            
            remaining, reset_at = result
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                limit=limit,
                reset_at=reset_at,
                scope=scope
            )


class RateLimitService:
    def __init__(self, limiter: RateLimiter | None = None) -> None:
        if limiter is None:
            # Use PostgreSQL-backed limiter by default
            try:
                limiter = PostgreSQLRateLimiter()
            except Exception:
                limiter = InMemoryRateLimiter()
        self.limiter = limiter

    def enforce(self, scope: str, key: str, limit: int = 10, window_seconds: int = 60) -> RateLimitResult:
        return self.limiter.check(scope, key, limit, window_seconds)
