"""
Thread-safe key cache with TTL for CryptoServe SDK.

This module provides local caching of encryption keys to minimize
network round-trips and reduce latency from ~5-50ms to ~0.1-0.5ms.
"""

import threading
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
from collections import OrderedDict


@dataclass
class CachedKey:
    """A cached encryption key with metadata."""
    key: bytes
    key_id: str
    algorithm: str
    created_at: float
    expires_at: float
    version: int = 1

    def is_expired(self) -> bool:
        """Check if the key has expired."""
        return time.time() > self.expires_at

    def time_remaining(self) -> float:
        """Get remaining time in seconds before expiry."""
        return max(0, self.expires_at - time.time())


class KeyCache:
    """
    Thread-safe LRU cache for encryption keys.

    Features:
    - TTL-based expiration (configurable, default 5 minutes)
    - LRU eviction when max size exceeded
    - Thread-safe for concurrent access
    - Automatic cleanup of expired entries
    - Cache hit/miss statistics
    """

    def __init__(
        self,
        max_size: int = 100,
        default_ttl: float = 300.0,  # 5 minutes
        cleanup_interval: float = 60.0,  # 1 minute
    ):
        """
        Initialize the key cache.

        Args:
            max_size: Maximum number of keys to cache
            default_ttl: Default time-to-live in seconds
            cleanup_interval: How often to clean expired entries
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval

        self._cache: OrderedDict[str, CachedKey] = OrderedDict()
        self._lock = threading.RLock()

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

        # Last cleanup time
        self._last_cleanup = time.time()

    def _make_key(self, context: str, operation: str = "encrypt") -> str:
        """Generate cache key from context and operation."""
        return f"{context}:{operation}"

    def get(self, context: str, operation: str = "encrypt") -> Optional[CachedKey]:
        """
        Get a cached key if available and not expired.

        Args:
            context: The encryption context
            operation: The operation type (encrypt/decrypt)

        Returns:
            CachedKey if found and valid, None otherwise
        """
        cache_key = self._make_key(context, operation)

        with self._lock:
            # Run cleanup periodically
            self._maybe_cleanup()

            if cache_key not in self._cache:
                self._misses += 1
                return None

            cached = self._cache[cache_key]

            if cached.is_expired():
                del self._cache[cache_key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(cache_key)
            self._hits += 1
            return cached

    def put(
        self,
        context: str,
        key: bytes,
        key_id: str,
        algorithm: str = "AES-256-GCM",
        ttl: Optional[float] = None,
        operation: str = "encrypt",
        version: int = 1,
    ) -> None:
        """
        Store a key in the cache.

        Args:
            context: The encryption context
            key: The encryption key bytes
            key_id: Key identifier for tracking
            algorithm: Encryption algorithm
            ttl: Time-to-live in seconds (uses default if None)
            operation: The operation type (encrypt/decrypt)
            version: Key version for rotation tracking
        """
        cache_key = self._make_key(context, operation)
        ttl = ttl if ttl is not None else self.default_ttl
        now = time.time()

        cached = CachedKey(
            key=key,
            key_id=key_id,
            algorithm=algorithm,
            created_at=now,
            expires_at=now + ttl,
            version=version,
        )

        with self._lock:
            # If key exists, update it
            if cache_key in self._cache:
                self._cache[cache_key] = cached
                self._cache.move_to_end(cache_key)
            else:
                # Evict oldest if at capacity
                while len(self._cache) >= self.max_size:
                    oldest_key = next(iter(self._cache))
                    del self._cache[oldest_key]
                    self._evictions += 1

                self._cache[cache_key] = cached

    def invalidate(self, context: str, operation: Optional[str] = None) -> int:
        """
        Invalidate cached keys for a context.

        Args:
            context: The context to invalidate
            operation: Specific operation, or None for all

        Returns:
            Number of entries invalidated
        """
        count = 0
        with self._lock:
            if operation:
                cache_key = self._make_key(context, operation)
                if cache_key in self._cache:
                    del self._cache[cache_key]
                    count = 1
            else:
                # Invalidate all operations for this context
                to_remove = [k for k in self._cache if k.startswith(f"{context}:")]
                for k in to_remove:
                    del self._cache[k]
                    count += 1
        return count

    def invalidate_all(self) -> int:
        """Clear the entire cache."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def _maybe_cleanup(self) -> None:
        """Clean up expired entries if enough time has passed."""
        now = time.time()
        if now - self._last_cleanup < self.cleanup_interval:
            return

        self._last_cleanup = now

        # Find and remove expired entries
        expired = [k for k, v in self._cache.items() if v.is_expired()]
        for k in expired:
            del self._cache[k]

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "evictions": self._evictions,
                "contexts": list(set(k.split(":")[0] for k in self._cache)),
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


# Global cache instance for the SDK
_global_cache: Optional[KeyCache] = None
_cache_lock = threading.Lock()


def get_key_cache() -> KeyCache:
    """Get or create the global key cache."""
    global _global_cache
    if _global_cache is None:
        with _cache_lock:
            if _global_cache is None:
                _global_cache = KeyCache()
    return _global_cache


def configure_cache(
    max_size: int = 100,
    default_ttl: float = 300.0,
    cleanup_interval: float = 60.0,
) -> KeyCache:
    """
    Configure the global key cache.

    Args:
        max_size: Maximum number of keys to cache
        default_ttl: Default TTL in seconds
        cleanup_interval: Cleanup interval in seconds

    Returns:
        The configured cache instance
    """
    global _global_cache
    with _cache_lock:
        _global_cache = KeyCache(
            max_size=max_size,
            default_ttl=default_ttl,
            cleanup_interval=cleanup_interval,
        )
        return _global_cache
