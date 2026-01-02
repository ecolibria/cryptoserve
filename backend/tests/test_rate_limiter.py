"""Tests for rate limiting functionality."""

import asyncio
import pytest
import time
from unittest.mock import patch

from app.core.rate_limiter import (
    RateLimiter,
    RateLimitConfig,
    RateLimitType,
    RateLimitResult,
    InMemoryBackend,
    get_rate_limiter,
    set_rate_limiter,
)


class TestInMemoryBackend:
    """Tests for the in-memory rate limit backend."""

    @pytest.fixture
    def backend(self):
        return InMemoryBackend()

    @pytest.mark.asyncio
    async def test_first_request_allowed(self, backend):
        """First request should always be allowed."""
        result = await backend.check_and_consume(
            key="test",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is True
        assert result.remaining == 4  # Started with 5, consumed 1
        assert result.retry_after == 0

    @pytest.mark.asyncio
    async def test_burst_exhaustion(self, backend):
        """Should block after burst is exhausted."""
        # Consume all burst tokens
        for i in range(5):
            result = await backend.check_and_consume(
                key="test",
                limit=10,
                window_seconds=60,
                burst_size=5,
            )
            assert result.allowed is True
            assert result.remaining == 4 - i

        # Next request should be blocked
        result = await backend.check_and_consume(
            key="test",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after > 0

    @pytest.mark.asyncio
    async def test_token_refill(self, backend):
        """Tokens should refill over time."""
        # Exhaust all tokens
        for _ in range(5):
            await backend.check_and_consume(
                key="test",
                limit=60,  # 1 token per second
                window_seconds=60,
                burst_size=5,
            )

        # Should be blocked
        result = await backend.check_and_consume(
            key="test",
            limit=60,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is False

        # Wait for tokens to refill (1 second = 1 token)
        await asyncio.sleep(1.1)

        # Should be allowed again
        result = await backend.check_and_consume(
            key="test",
            limit=60,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_different_keys_independent(self, backend):
        """Different keys should have independent limits."""
        # Exhaust key1
        for _ in range(5):
            await backend.check_and_consume(
                key="key1",
                limit=10,
                window_seconds=60,
                burst_size=5,
            )

        # key1 should be blocked
        result1 = await backend.check_and_consume(
            key="key1",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result1.allowed is False

        # key2 should still work
        result2 = await backend.check_and_consume(
            key="key2",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result2.allowed is True

    @pytest.mark.asyncio
    async def test_reset(self, backend):
        """Reset should restore tokens."""
        # Exhaust tokens
        for _ in range(5):
            await backend.check_and_consume(
                key="test",
                limit=10,
                window_seconds=60,
                burst_size=5,
            )

        # Should be blocked
        result = await backend.check_and_consume(
            key="test",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is False

        # Reset
        await backend.reset("test")

        # Should be allowed again with full burst
        result = await backend.check_and_consume(
            key="test",
            limit=10,
            window_seconds=60,
            burst_size=5,
        )
        assert result.allowed is True
        assert result.remaining == 4


class TestRateLimiter:
    """Tests for the main RateLimiter class."""

    @pytest.fixture
    def limiter(self):
        return RateLimiter(
            backend=InMemoryBackend(),
            limits={
                RateLimitType.IP: RateLimitConfig(
                    requests_per_minute=10, burst_size=5
                ),
                RateLimitType.IDENTITY: RateLimitConfig(
                    requests_per_minute=20, burst_size=10
                ),
                RateLimitType.CONTEXT: RateLimitConfig(
                    requests_per_minute=30, burst_size=15
                ),
                RateLimitType.GLOBAL: RateLimitConfig(
                    requests_per_minute=1000, burst_size=100
                ),
            },
        )

    @pytest.mark.asyncio
    async def test_check_ip(self, limiter):
        """Should check IP rate limit."""
        result = await limiter.check_ip("192.168.1.1")
        assert result.allowed is True
        assert result.limit == 10

    @pytest.mark.asyncio
    async def test_check_identity(self, limiter):
        """Should check identity rate limit."""
        result = await limiter.check_identity("user-123")
        assert result.allowed is True
        assert result.limit == 20

    @pytest.mark.asyncio
    async def test_check_context(self, limiter):
        """Should check context rate limit."""
        result = await limiter.check_context("user-pii", "user-123")
        assert result.allowed is True
        assert result.limit == 30

    @pytest.mark.asyncio
    async def test_check_all_returns_most_restrictive(self, limiter):
        """check_all should return the most restrictive limit."""
        # Make IP limit almost exhausted
        for _ in range(4):
            await limiter.check_ip("192.168.1.1")

        result = await limiter.check_all(
            ip_address="192.168.1.1",
            identity_id="user-123",
            context_name="user-pii",
        )

        # Should return IP limit (most restrictive remaining)
        assert result.allowed is True
        assert result.remaining == 0  # IP has 0 remaining after check_all

    @pytest.mark.asyncio
    async def test_check_all_blocks_when_any_exceeded(self, limiter):
        """check_all should block if any limit is exceeded."""
        # Exhaust IP limit
        for _ in range(6):
            await limiter.check_ip("192.168.1.1")

        result = await limiter.check_all(
            ip_address="192.168.1.1",
            identity_id="user-123",
            context_name="user-pii",
        )

        assert result.allowed is False
        assert result.retry_after > 0

    @pytest.mark.asyncio
    async def test_custom_context_limit(self, limiter):
        """Should use custom context limits when set."""
        limiter.set_context_limit(
            "sensitive-data",
            RateLimitConfig(requests_per_minute=5, burst_size=2),
        )

        # Check default context
        default_result = await limiter.check_context("user-pii", "user-123")
        assert default_result.limit == 30

        # Check custom context
        custom_result = await limiter.check_context("sensitive-data", "user-123")
        assert custom_result.limit == 5

    @pytest.mark.asyncio
    async def test_disabled_limit(self, limiter):
        """Disabled limits should always allow."""
        limiter._limits[RateLimitType.IP] = RateLimitConfig(
            requests_per_minute=1, burst_size=1, enabled=False
        )

        # Should always be allowed even with tiny limit
        for _ in range(100):
            result = await limiter.check_ip("192.168.1.1")
            assert result.allowed is True


class TestRateLimitResult:
    """Tests for RateLimitResult headers."""

    def test_headers_when_allowed(self):
        """Should generate correct headers when allowed."""
        result = RateLimitResult(
            allowed=True,
            limit=100,
            remaining=50,
            reset_at=time.time() + 60,
            retry_after=0,
        )
        headers = result.headers
        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "50"
        assert headers["Retry-After"] == ""

    def test_headers_when_blocked(self):
        """Should generate correct headers when blocked."""
        reset_time = time.time() + 30
        result = RateLimitResult(
            allowed=False,
            limit=100,
            remaining=0,
            reset_at=reset_time,
            retry_after=30,
        )
        headers = result.headers
        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "0"
        assert headers["Retry-After"] == "30"

    def test_negative_remaining_clamped_to_zero(self):
        """Negative remaining should be clamped to 0 in headers."""
        result = RateLimitResult(
            allowed=False,
            limit=100,
            remaining=-5,
            reset_at=time.time() + 60,
            retry_after=10,
        )
        headers = result.headers
        assert headers["X-RateLimit-Remaining"] == "0"


class TestGlobalRateLimiter:
    """Tests for global rate limiter management."""

    def test_get_rate_limiter_creates_instance(self):
        """Should create a rate limiter instance."""
        # Reset global state
        set_rate_limiter(None)

        limiter = get_rate_limiter()
        assert limiter is not None
        assert isinstance(limiter, RateLimiter)

    def test_get_rate_limiter_returns_same_instance(self):
        """Should return the same instance on subsequent calls."""
        set_rate_limiter(None)

        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2

    def test_set_rate_limiter_overrides(self):
        """set_rate_limiter should override the global instance."""
        custom_limiter = RateLimiter()
        set_rate_limiter(custom_limiter)

        assert get_rate_limiter() is custom_limiter

        # Reset for other tests
        set_rate_limiter(None)
