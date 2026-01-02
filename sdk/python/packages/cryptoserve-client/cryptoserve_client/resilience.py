"""Resilience patterns for CryptoServe SDK.

Provides production-grade reliability features:
- Retry with exponential backoff and jitter
- Circuit breaker to prevent cascading failures
- Batch operations for bulk encryption/decryption
- Request timeout handling
"""

import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Generic, TypeVar

from .errors import CryptoServeError, ServerError, RateLimitError


# =============================================================================
# Retry with Exponential Backoff
# =============================================================================

@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    initial_delay: float = 0.5  # seconds
    max_delay: float = 30.0  # seconds
    multiplier: float = 2.0  # exponential factor
    jitter: float = 0.5  # random factor (0.5 = +/- 50%)
    retryable_errors: tuple = (ServerError, ConnectionError, TimeoutError)
    retry_on_rate_limit: bool = True


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay with exponential backoff and jitter."""
    delay = config.initial_delay * (config.multiplier ** attempt)
    delay = min(delay, config.max_delay)

    # Add jitter
    jitter_range = delay * config.jitter
    delay += random.uniform(-jitter_range, jitter_range)

    return max(0, delay)


def with_retry(config: RetryConfig | None = None):
    """Decorator to add retry logic to a function.

    Usage:
        @with_retry(RetryConfig(max_retries=3))
        def make_request():
            ...
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None

            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except RateLimitError as e:
                    if not config.retry_on_rate_limit or attempt >= config.max_retries:
                        raise

                    # Use Retry-After header if available
                    delay = e.retry_after if e.retry_after else calculate_delay(attempt, config)
                    time.sleep(delay)
                    last_error = e

                except config.retryable_errors as e:
                    if attempt >= config.max_retries:
                        raise

                    delay = calculate_delay(attempt, config)
                    time.sleep(delay)
                    last_error = e

            # This shouldn't happen, but just in case
            raise last_error or CryptoServeError("Retry failed without error")

        return wrapper
    return decorator


# =============================================================================
# Circuit Breaker
# =============================================================================

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 3  # Successes in half-open to close
    open_timeout: float = 30.0  # Seconds before trying half-open
    excluded_errors: tuple = ()  # Errors that don't count as failures


class CircuitBreaker:
    """Circuit breaker pattern implementation.

    Prevents cascading failures by failing fast when a service is unhealthy.

    Usage:
        cb = CircuitBreaker()

        try:
            result = cb.execute(lambda: make_request())
        except CircuitOpenError:
            # Service is unavailable, use fallback
            ...
    """

    def __init__(self, config: CircuitBreakerConfig | None = None, name: str = "default"):
        self.config = config or CircuitBreakerConfig()
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: datetime | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state (may transition from OPEN to HALF_OPEN)."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                # Check if timeout has elapsed
                if self._last_failure_time:
                    elapsed = (datetime.now(timezone.utc) - self._last_failure_time).total_seconds()
                    if elapsed >= self.config.open_timeout:
                        self._state = CircuitState.HALF_OPEN
                        self._success_count = 0

            return self._state

    def execute(self, func: Callable[[], Any]) -> Any:
        """Execute function with circuit breaker protection."""
        state = self.state

        if state == CircuitState.OPEN:
            raise CircuitOpenError(
                f"Circuit '{self.name}' is open. Service unavailable."
            )

        try:
            result = func()
            self._on_success()
            return result

        except self.config.excluded_errors:
            # These errors don't count against the circuit
            raise

        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self):
        """Record a successful call."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            else:
                self._failure_count = 0

    def _on_failure(self):
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.now(timezone.utc)

            if self._state == CircuitState.HALF_OPEN:
                # Immediate trip back to open
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.config.failure_threshold:
                self._state = CircuitState.OPEN

    def reset(self):
        """Manually reset the circuit to closed."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None


class CircuitOpenError(CryptoServeError):
    """Raised when circuit is open and rejecting requests."""
    pass


# =============================================================================
# Batch Operations
# =============================================================================

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class BatchItem(Generic[T, R]):
    """A single item in a batch operation."""
    data: T
    result: R | None = None
    error: Exception | None = None
    success: bool = False


@dataclass
class BatchResult(Generic[R]):
    """Result of a batch operation."""
    items: list[BatchItem]
    succeeded: int = 0
    failed: int = 0
    total: int = 0

    def __post_init__(self):
        self.succeeded = sum(1 for i in self.items if i.success)
        self.failed = sum(1 for i in self.items if not i.success)
        self.total = len(self.items)

    @property
    def all_succeeded(self) -> bool:
        return self.failed == 0

    def results(self) -> list[R | None]:
        """Get all results (successful ones only)."""
        return [i.result for i in self.items if i.success]

    def errors(self) -> list[tuple[int, Exception]]:
        """Get all errors with their indices."""
        return [(idx, i.error) for idx, i in enumerate(self.items) if i.error]


class BatchProcessor(Generic[T, R]):
    """Process items in batches for efficiency.

    Usage:
        processor = BatchProcessor(
            process_func=client.encrypt,
            batch_size=50,
        )
        results = processor.process(items)
    """

    def __init__(
        self,
        process_func: Callable[[T], R],
        batch_size: int = 50,
        stop_on_error: bool = False,
        retry_config: RetryConfig | None = None,
    ):
        self.process_func = process_func
        self.batch_size = batch_size
        self.stop_on_error = stop_on_error
        self.retry_config = retry_config

    def process(self, items: list[T]) -> BatchResult[R]:
        """Process all items, returning results."""
        batch_items = [BatchItem(data=item) for item in items]

        for batch_item in batch_items:
            try:
                if self.retry_config:
                    result = self._process_with_retry(batch_item.data)
                else:
                    result = self.process_func(batch_item.data)

                batch_item.result = result
                batch_item.success = True

            except Exception as e:
                batch_item.error = e
                batch_item.success = False

                if self.stop_on_error:
                    break

        return BatchResult(items=batch_items)

    def _process_with_retry(self, item: T) -> R:
        """Process with retry logic."""
        config = self.retry_config

        for attempt in range(config.max_retries + 1):
            try:
                return self.process_func(item)

            except config.retryable_errors as e:
                if attempt >= config.max_retries:
                    raise

                delay = calculate_delay(attempt, config)
                time.sleep(delay)

        raise CryptoServeError("Retry exhausted")


# =============================================================================
# Resilient Client Mixin
# =============================================================================

class ResilientMixin:
    """Mixin to add resilience features to a client.

    Adds retry, circuit breaker, and batching to any client class.
    """

    _circuit_breaker: CircuitBreaker | None = None
    _retry_config: RetryConfig | None = None

    def configure_resilience(
        self,
        retry_config: RetryConfig | None = None,
        circuit_config: CircuitBreakerConfig | None = None,
    ):
        """Configure resilience features.

        Args:
            retry_config: Retry configuration (None to disable)
            circuit_config: Circuit breaker configuration (None to disable)
        """
        self._retry_config = retry_config

        if circuit_config:
            self._circuit_breaker = CircuitBreaker(circuit_config)
        else:
            self._circuit_breaker = None

    def _resilient_request(self, func: Callable) -> Any:
        """Make a request with resilience features."""
        # Circuit breaker check
        if self._circuit_breaker:
            try:
                if self._retry_config:
                    return self._circuit_breaker.execute(
                        lambda: self._with_retry(func)
                    )
                else:
                    return self._circuit_breaker.execute(func)
            except CircuitOpenError:
                raise
        elif self._retry_config:
            return self._with_retry(func)
        else:
            return func()

    def _with_retry(self, func: Callable) -> Any:
        """Execute with retry logic."""
        config = self._retry_config
        last_error = None

        for attempt in range(config.max_retries + 1):
            try:
                return func()

            except RateLimitError as e:
                if not config.retry_on_rate_limit or attempt >= config.max_retries:
                    raise
                delay = e.retry_after if e.retry_after else calculate_delay(attempt, config)
                time.sleep(delay)
                last_error = e

            except config.retryable_errors as e:
                if attempt >= config.max_retries:
                    raise
                delay = calculate_delay(attempt, config)
                time.sleep(delay)
                last_error = e

        raise last_error or CryptoServeError("Retry failed")


# =============================================================================
# Convenience Functions
# =============================================================================

def create_production_config() -> tuple[RetryConfig, CircuitBreakerConfig]:
    """Create recommended production resilience configuration."""
    retry = RetryConfig(
        max_retries=3,
        initial_delay=0.5,
        max_delay=30.0,
        multiplier=2.0,
        jitter=0.3,
        retry_on_rate_limit=True,
    )

    circuit = CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=3,
        open_timeout=30.0,
    )

    return retry, circuit


def create_aggressive_retry_config() -> RetryConfig:
    """Create configuration for aggressive retries (batch jobs, etc.)."""
    return RetryConfig(
        max_retries=5,
        initial_delay=1.0,
        max_delay=60.0,
        multiplier=2.0,
        jitter=0.5,
        retry_on_rate_limit=True,
    )
