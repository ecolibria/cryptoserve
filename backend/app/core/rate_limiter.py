"""Rate limiting for crypto operations.

Provides per-identity and per-context rate limiting with support for:
- In-memory storage (development/single instance)
- Redis storage (production/distributed)
- Token bucket algorithm with burst support
- Configurable limits per context
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.config import get_settings


class RateLimitExceeded(Exception):
    """Rate limit exceeded."""

    def __init__(
        self,
        message: str,
        limit: int,
        remaining: int,
        reset_at: float,
        retry_after: int,
    ):
        super().__init__(message)
        self.message = message
        self.limit = limit
        self.remaining = remaining
        self.reset_at = reset_at
        self.retry_after = retry_after


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: float  # Unix timestamp
    retry_after: int  # Seconds until retry allowed (0 if allowed)

    @property
    def headers(self) -> dict[str, str]:
        """Generate standard rate limit headers."""
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_at)),
            "Retry-After": str(self.retry_after) if not self.allowed else "",
        }


class RateLimitType(str, Enum):
    """Types of rate limits."""

    IP = "ip"  # Per IP address
    IDENTITY = "identity"  # Per authenticated identity
    CONTEXT = "context"  # Per encryption context
    GLOBAL = "global"  # Global rate limit


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""

    requests_per_minute: int = 100
    burst_size: int = 20  # Allow burst up to this many requests
    enabled: bool = True


# Default limits
DEFAULT_LIMITS = {
    RateLimitType.IP: RateLimitConfig(requests_per_minute=200, burst_size=50),
    RateLimitType.IDENTITY: RateLimitConfig(requests_per_minute=100, burst_size=20),
    RateLimitType.CONTEXT: RateLimitConfig(requests_per_minute=500, burst_size=100),
    RateLimitType.GLOBAL: RateLimitConfig(requests_per_minute=10000, burst_size=1000),
}


class RateLimitBackend(ABC):
    """Abstract backend for rate limit storage."""

    @abstractmethod
    async def check_and_consume(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        burst_size: int,
    ) -> RateLimitResult:
        """Check rate limit and consume one token if allowed.

        Uses token bucket algorithm:
        - Tokens are added at rate of limit/window_seconds
        - Maximum tokens is burst_size
        - Each request consumes one token

        Args:
            key: Unique identifier for the rate limit bucket
            limit: Maximum requests per window
            window_seconds: Time window in seconds
            burst_size: Maximum burst capacity

        Returns:
            RateLimitResult with status and headers
        """
        pass

    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        pass

    @abstractmethod
    async def get_usage(self, key: str) -> Optional[dict]:
        """Get current usage for a key."""
        pass


class InMemoryBackend(RateLimitBackend):
    """In-memory rate limit storage using token bucket algorithm.

    Suitable for development and single-instance deployments.
    """

    def __init__(self):
        self._buckets: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def check_and_consume(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        burst_size: int,
    ) -> RateLimitResult:
        async with self._lock:
            now = time.time()
            refill_rate = limit / window_seconds  # tokens per second

            if key not in self._buckets:
                # Initialize with full bucket
                self._buckets[key] = {
                    "tokens": float(burst_size),
                    "last_update": now,
                }

            bucket = self._buckets[key]

            # Refill tokens based on time elapsed
            elapsed = now - bucket["last_update"]
            bucket["tokens"] = min(
                burst_size, bucket["tokens"] + elapsed * refill_rate
            )
            bucket["last_update"] = now

            # Calculate reset time (when bucket will be full again)
            tokens_needed = burst_size - bucket["tokens"]
            reset_at = now + (tokens_needed / refill_rate) if tokens_needed > 0 else now

            if bucket["tokens"] >= 1:
                # Consume one token
                bucket["tokens"] -= 1
                return RateLimitResult(
                    allowed=True,
                    limit=limit,
                    remaining=int(bucket["tokens"]),
                    reset_at=reset_at,
                    retry_after=0,
                )
            else:
                # Not enough tokens
                retry_after = int((1 - bucket["tokens"]) / refill_rate) + 1
                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_at=now + retry_after,
                    retry_after=retry_after,
                )

    async def reset(self, key: str) -> None:
        async with self._lock:
            if key in self._buckets:
                del self._buckets[key]

    async def get_usage(self, key: str) -> Optional[dict]:
        async with self._lock:
            if key in self._buckets:
                bucket = self._buckets[key]
                return {
                    "tokens_remaining": bucket["tokens"],
                    "last_update": bucket["last_update"],
                }
            return None


class RedisBackend(RateLimitBackend):
    """Redis-based rate limit storage for distributed deployments.

    Uses Lua scripting for atomic token bucket operations.
    """

    # Lua script for atomic token bucket operation
    TOKEN_BUCKET_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window_seconds = tonumber(ARGV[2])
    local burst_size = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])
    local refill_rate = limit / window_seconds

    -- Get current bucket state
    local bucket = redis.call('HMGET', key, 'tokens', 'last_update')
    local tokens = tonumber(bucket[1]) or burst_size
    local last_update = tonumber(bucket[2]) or now

    -- Refill tokens
    local elapsed = now - last_update
    tokens = math.min(burst_size, tokens + elapsed * refill_rate)

    -- Calculate reset time
    local tokens_needed = burst_size - tokens
    local reset_at = now
    if tokens_needed > 0 then
        reset_at = now + (tokens_needed / refill_rate)
    end

    -- Try to consume a token
    if tokens >= 1 then
        tokens = tokens - 1
        redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        redis.call('EXPIRE', key, window_seconds * 2)
        return {1, math.floor(tokens), reset_at, 0}
    else
        local retry_after = math.ceil((1 - tokens) / refill_rate)
        redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        redis.call('EXPIRE', key, window_seconds * 2)
        return {0, 0, now + retry_after, retry_after}
    end
    """

    def __init__(self, redis_url: Optional[str] = None):
        settings = get_settings()
        self._redis_url = redis_url or settings.redis_url
        self._redis = None
        self._script_sha = None

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as redis

            self._redis = redis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            # Register the Lua script
            self._script_sha = await self._redis.script_load(self.TOKEN_BUCKET_SCRIPT)
        return self._redis

    async def check_and_consume(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        burst_size: int,
    ) -> RateLimitResult:
        redis = await self._get_redis()
        now = time.time()

        try:
            result = await redis.evalsha(
                self._script_sha,
                1,
                f"ratelimit:{key}",
                str(limit),
                str(window_seconds),
                str(burst_size),
                str(now),
            )
            allowed, remaining, reset_at, retry_after = result
            return RateLimitResult(
                allowed=bool(allowed),
                limit=limit,
                remaining=int(remaining),
                reset_at=float(reset_at),
                retry_after=int(retry_after),
            )
        except Exception:
            # On Redis error, fail open (allow request)
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit,
                reset_at=now + window_seconds,
                retry_after=0,
            )

    async def reset(self, key: str) -> None:
        redis = await self._get_redis()
        await redis.delete(f"ratelimit:{key}")

    async def get_usage(self, key: str) -> Optional[dict]:
        redis = await self._get_redis()
        bucket = await redis.hgetall(f"ratelimit:{key}")
        if bucket:
            return {
                "tokens_remaining": float(bucket.get("tokens", 0)),
                "last_update": float(bucket.get("last_update", 0)),
            }
        return None


class RateLimiter:
    """Main rate limiter class.

    Coordinates multiple rate limit types and backends.
    """

    def __init__(
        self,
        backend: Optional[RateLimitBackend] = None,
        limits: Optional[dict[RateLimitType, RateLimitConfig]] = None,
    ):
        self._backend = backend or InMemoryBackend()
        self._limits = limits or DEFAULT_LIMITS.copy()
        self._context_limits: dict[str, RateLimitConfig] = {}

    def set_context_limit(self, context_name: str, config: RateLimitConfig) -> None:
        """Set custom rate limit for a specific context."""
        self._context_limits[context_name] = config

    def get_context_limit(self, context_name: str) -> RateLimitConfig:
        """Get rate limit config for a context."""
        return self._context_limits.get(context_name, self._limits[RateLimitType.CONTEXT])

    async def check_ip(self, ip_address: str) -> RateLimitResult:
        """Check rate limit for an IP address."""
        config = self._limits[RateLimitType.IP]
        if not config.enabled:
            return RateLimitResult(
                allowed=True,
                limit=config.requests_per_minute,
                remaining=config.requests_per_minute,
                reset_at=time.time() + 60,
                retry_after=0,
            )

        return await self._backend.check_and_consume(
            key=f"ip:{ip_address}",
            limit=config.requests_per_minute,
            window_seconds=60,
            burst_size=config.burst_size,
        )

    async def check_identity(self, identity_id: str) -> RateLimitResult:
        """Check rate limit for an authenticated identity."""
        config = self._limits[RateLimitType.IDENTITY]
        if not config.enabled:
            return RateLimitResult(
                allowed=True,
                limit=config.requests_per_minute,
                remaining=config.requests_per_minute,
                reset_at=time.time() + 60,
                retry_after=0,
            )

        return await self._backend.check_and_consume(
            key=f"identity:{identity_id}",
            limit=config.requests_per_minute,
            window_seconds=60,
            burst_size=config.burst_size,
        )

    async def check_context(
        self, context_name: str, identity_id: str
    ) -> RateLimitResult:
        """Check rate limit for a specific context + identity combination."""
        config = self.get_context_limit(context_name)
        if not config.enabled:
            return RateLimitResult(
                allowed=True,
                limit=config.requests_per_minute,
                remaining=config.requests_per_minute,
                reset_at=time.time() + 60,
                retry_after=0,
            )

        return await self._backend.check_and_consume(
            key=f"context:{context_name}:{identity_id}",
            limit=config.requests_per_minute,
            window_seconds=60,
            burst_size=config.burst_size,
        )

    async def check_all(
        self,
        ip_address: str,
        identity_id: str,
        context_name: Optional[str] = None,
    ) -> RateLimitResult:
        """Check all applicable rate limits.

        Returns the most restrictive result.
        """
        results = [
            await self.check_ip(ip_address),
            await self.check_identity(identity_id),
        ]

        if context_name:
            results.append(await self.check_context(context_name, identity_id))

        # Find the most restrictive (lowest remaining or not allowed)
        not_allowed = [r for r in results if not r.allowed]
        if not_allowed:
            # Return the one with longest retry_after
            return max(not_allowed, key=lambda r: r.retry_after)

        # All allowed, return the one with lowest remaining
        return min(results, key=lambda r: r.remaining)

    async def reset_identity(self, identity_id: str) -> None:
        """Reset all rate limits for an identity."""
        await self._backend.reset(f"identity:{identity_id}")

    async def reset_ip(self, ip_address: str) -> None:
        """Reset rate limits for an IP."""
        await self._backend.reset(f"ip:{ip_address}")


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        # Use Redis if configured, otherwise in-memory
        settings = get_settings()
        if settings.redis_url:
            backend = RedisBackend(settings.redis_url)
        else:
            backend = InMemoryBackend()
        _rate_limiter = RateLimiter(backend=backend)
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the global rate limiter instance (for testing)."""
    global _rate_limiter
    _rate_limiter = limiter
