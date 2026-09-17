"""Tests for shared rate limiting — ISSUE 3."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from safenestt.security.rate_limit import (
    RateLimitService, RateLimitScope,
    InMemoryRateLimiter, PostgreSQLRateLimiter
)


def test_postgresql_rate_limiter_basic():
    """PostgreSQL rate limiter allows requests within limit."""
    limiter = PostgreSQLRateLimiter()
    
    # First request should be allowed
    result = limiter.check(RateLimitScope.API_KEY, "test-key-1", limit=5, window_seconds=60)
    assert result.allowed
    assert result.remaining == 4
    assert result.limit == 5


def test_postgresql_rate_limiter_blocks_after_limit():
    """PostgreSQL rate limiter blocks after limit is reached."""
    limiter = PostgreSQLRateLimiter()
    key = "test-key-block"
    
    # Exhaust the limit
    for i in range(5):
        result = limiter.check(RateLimitScope.API_KEY, key, limit=5, window_seconds=60)
        assert result.allowed
        assert result.remaining == 4 - i
    
    # Next request should be blocked
    result = limiter.check(RateLimitScope.API_KEY, key, limit=5, window_seconds=60)
    assert not result.allowed
    assert result.remaining == 0
    assert result.detail == "rate_limit_exceeded"


def test_postgresql_rate_limiter_independent_keys():
    """Different keys have independent rate limits."""
    limiter = PostgreSQLRateLimiter()
    
    # Exhaust limit for key-1
    for _ in range(5):
        limiter.check(RateLimitScope.API_KEY, "key-1", limit=5, window_seconds=60)
    
    # key-1 should be blocked
    result = limiter.check(RateLimitScope.API_KEY, "key-1", limit=5, window_seconds=60)
    assert not result.allowed
    
    # key-2 should still work
    result = limiter.check(RateLimitScope.API_KEY, "key-2", limit=5, window_seconds=60)
    assert result.allowed


def test_postgresql_rate_limiter_window_reset():
    """Rate limit resets after window expires."""
    limiter = PostgreSQLRateLimiter()
    key = "test-key-reset"
    
    # Use a very short window
    for _ in range(3):
        limiter.check(RateLimitScope.API_KEY, key, limit=3, window_seconds=1)
    
    # Should be blocked
    result = limiter.check(RateLimitScope.API_KEY, key, limit=3, window_seconds=1)
    assert not result.allowed
    
    # Wait for window to expire
    import time
    time.sleep(1.5)
    
    # Should be allowed again
    result = limiter.check(RateLimitScope.API_KEY, key, limit=3, window_seconds=1)
    assert result.allowed


def test_postgresql_rate_limiter_shared_across_instances():
    """Multiple limiter instances share the same PostgreSQL counters."""
    limiter1 = PostgreSQLRateLimiter()
    limiter2 = PostgreSQLRateLimiter()
    key = "test-key-shared"
    
    # Use limiter1 to exhaust the limit
    for _ in range(5):
        limiter1.check(RateLimitScope.API_KEY, key, limit=5, window_seconds=60)
    
    # limiter2 should see the same counter and block
    result = limiter2.check(RateLimitScope.API_KEY, key, limit=5, window_seconds=60)
    assert not result.allowed


def test_in_memory_rate_limiter_fallback():
    """In-memory limiter works for single-process scenarios."""
    limiter = InMemoryRateLimiter()
    
    # First request should be allowed
    result = limiter.check(RateLimitScope.API_KEY, "test-key", limit=5, window_seconds=60)
    assert result.allowed
    assert result.remaining == 4
    
    # Exhaust the limit
    for _ in range(4):
        limiter.check(RateLimitScope.API_KEY, "test-key", limit=5, window_seconds=60)
    
    # Should be blocked
    result = limiter.check(RateLimitScope.API_KEY, "test-key", limit=5, window_seconds=60)
    assert not result.allowed


def test_rate_limit_service_uses_postgresql():
    """RateLimitService defaults to PostgreSQL-backed limiter."""
    service = RateLimitService()
    
    # Should use PostgreSQL limiter
    result = service.enforce(RateLimitScope.API_KEY, "test-service-key", limit=3, window_seconds=60)
    assert result.allowed
    assert result.remaining == 2
