"""Prometheus Metrics for Crypto Operations.

Provides comprehensive metrics for monitoring cryptographic operations:
- Request counts and latencies
- Error rates by type
- Algorithm usage distribution
- Key management operations
- Resource utilization

Metrics follow Prometheus naming conventions and best practices.
"""

import time
from contextlib import contextmanager
from functools import wraps
from typing import Callable, Any

from prometheus_client import Counter, Histogram, Gauge, Info, REGISTRY


# ==================== Operation Counters ====================

CRYPTO_OPERATIONS_TOTAL = Counter(
    "crypto_operations_total",
    "Total number of cryptographic operations",
    ["operation", "algorithm", "status"],
)

CRYPTO_ERRORS_TOTAL = Counter(
    "crypto_errors_total",
    "Total number of cryptographic operation errors",
    ["operation", "error_type"],
)

KEY_OPERATIONS_TOTAL = Counter(
    "crypto_key_operations_total",
    "Total number of key management operations",
    ["operation", "key_type"],
)


# ==================== Latency Histograms ====================

# Buckets optimized for crypto operations (in seconds)
CRYPTO_LATENCY_BUCKETS = (
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
)

CRYPTO_OPERATION_LATENCY = Histogram(
    "crypto_operation_latency_seconds",
    "Latency of cryptographic operations in seconds",
    ["operation", "algorithm"],
    buckets=CRYPTO_LATENCY_BUCKETS,
)

PASSWORD_HASH_LATENCY = Histogram(
    "crypto_password_hash_latency_seconds",
    "Latency of password hashing operations",
    ["algorithm"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
)

SIGNATURE_LATENCY = Histogram(
    "crypto_signature_latency_seconds",
    "Latency of signature operations",
    ["operation", "algorithm"],
    buckets=CRYPTO_LATENCY_BUCKETS,
)

CERTIFICATE_LATENCY = Histogram(
    "crypto_certificate_latency_seconds",
    "Latency of certificate operations",
    ["operation"],
    buckets=CRYPTO_LATENCY_BUCKETS,
)


# ==================== Size Histograms ====================

DATA_SIZE_BYTES = Histogram(
    "crypto_data_size_bytes",
    "Size of data processed in bytes",
    ["operation"],
    buckets=(64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 10485760),
)

KEY_SIZE_BITS = Histogram(
    "crypto_key_size_bits",
    "Size of cryptographic keys in bits",
    ["key_type", "algorithm"],
    buckets=(128, 192, 256, 384, 512, 2048, 3072, 4096),
)


# ==================== Gauges ====================

ACTIVE_KEYS = Gauge(
    "crypto_active_keys",
    "Number of active cryptographic keys",
    ["key_type", "context"],
)

STREAMING_OPERATIONS = Gauge(
    "crypto_streaming_operations_active",
    "Number of active streaming encryption operations",
    ["operation"],
)

CONTEXTS_TOTAL = Gauge(
    "crypto_contexts_total",
    "Total number of encryption contexts",
)


# ==================== Info Metrics ====================

CRYPTO_ENGINE_INFO = Info(
    "crypto_engine",
    "Cryptographic engine information",
)


# ==================== Helper Classes ====================

class MetricsRecorder:
    """Helper for recording crypto operation metrics."""

    def __init__(self):
        self._initialized = False

    def initialize(self, version: str = "1.0.0", algorithms: list[str] | None = None):
        """Initialize metrics with engine info."""
        if self._initialized:
            return

        CRYPTO_ENGINE_INFO.info({
            "version": version,
            "supported_algorithms": ",".join(algorithms or []),
            "fips_mode": "false",
        })
        self._initialized = True

    @contextmanager
    def track_operation(
        self,
        operation: str,
        algorithm: str = "unknown",
        data_size: int | None = None,
    ):
        """Context manager to track an operation's metrics.

        Usage:
            with metrics.track_operation("encrypt", "aes-256-gcm", len(data)):
                encrypted = engine.encrypt(data)
        """
        start_time = time.perf_counter()
        status = "success"

        try:
            yield
        except Exception as e:
            status = "error"
            error_type = type(e).__name__
            CRYPTO_ERRORS_TOTAL.labels(operation=operation, error_type=error_type).inc()
            raise
        finally:
            duration = time.perf_counter() - start_time
            CRYPTO_OPERATIONS_TOTAL.labels(
                operation=operation,
                algorithm=algorithm,
                status=status,
            ).inc()
            CRYPTO_OPERATION_LATENCY.labels(
                operation=operation,
                algorithm=algorithm,
            ).observe(duration)

            if data_size is not None:
                DATA_SIZE_BYTES.labels(operation=operation).observe(data_size)

    @contextmanager
    def track_password_hash(self, algorithm: str):
        """Track password hashing operation."""
        start_time = time.perf_counter()
        status = "success"

        try:
            yield
        except Exception as e:
            status = "error"
            CRYPTO_ERRORS_TOTAL.labels(
                operation="password_hash",
                error_type=type(e).__name__,
            ).inc()
            raise
        finally:
            duration = time.perf_counter() - start_time
            PASSWORD_HASH_LATENCY.labels(algorithm=algorithm).observe(duration)
            CRYPTO_OPERATIONS_TOTAL.labels(
                operation="password_hash",
                algorithm=algorithm,
                status=status,
            ).inc()

    @contextmanager
    def track_signature(self, operation: str, algorithm: str):
        """Track signature operation."""
        start_time = time.perf_counter()
        status = "success"

        try:
            yield
        except Exception as e:
            status = "error"
            CRYPTO_ERRORS_TOTAL.labels(
                operation=f"signature_{operation}",
                error_type=type(e).__name__,
            ).inc()
            raise
        finally:
            duration = time.perf_counter() - start_time
            SIGNATURE_LATENCY.labels(
                operation=operation,
                algorithm=algorithm,
            ).observe(duration)
            CRYPTO_OPERATIONS_TOTAL.labels(
                operation=f"signature_{operation}",
                algorithm=algorithm,
                status=status,
            ).inc()

    @contextmanager
    def track_certificate(self, operation: str):
        """Track certificate operation."""
        start_time = time.perf_counter()
        status = "success"

        try:
            yield
        except Exception as e:
            status = "error"
            CRYPTO_ERRORS_TOTAL.labels(
                operation=f"certificate_{operation}",
                error_type=type(e).__name__,
            ).inc()
            raise
        finally:
            duration = time.perf_counter() - start_time
            CERTIFICATE_LATENCY.labels(operation=operation).observe(duration)
            CRYPTO_OPERATIONS_TOTAL.labels(
                operation=f"certificate_{operation}",
                algorithm="x509",
                status=status,
            ).inc()

    @contextmanager
    def track_streaming(self, operation: str):
        """Track streaming operation (increments/decrements active gauge)."""
        STREAMING_OPERATIONS.labels(operation=operation).inc()
        try:
            yield
        finally:
            STREAMING_OPERATIONS.labels(operation=operation).dec()

    def record_key_operation(self, operation: str, key_type: str):
        """Record a key management operation."""
        KEY_OPERATIONS_TOTAL.labels(
            operation=operation,
            key_type=key_type,
        ).inc()

    def record_key_size(self, key_type: str, algorithm: str, size_bits: int):
        """Record key size for analysis."""
        KEY_SIZE_BITS.labels(
            key_type=key_type,
            algorithm=algorithm,
        ).observe(size_bits)

    def set_active_keys(self, key_type: str, context: str, count: int):
        """Set the number of active keys."""
        ACTIVE_KEYS.labels(key_type=key_type, context=context).set(count)

    def set_contexts_total(self, count: int):
        """Set the total number of contexts."""
        CONTEXTS_TOTAL.set(count)


# ==================== Decorator ====================

def with_metrics(operation: str, algorithm_arg: str | int | None = None):
    """Decorator to automatically track operation metrics.

    Args:
        operation: Name of the operation
        algorithm_arg: Name or position of the algorithm argument

    Usage:
        @with_metrics("encrypt", algorithm_arg="algorithm")
        def encrypt(self, data: bytes, algorithm: str = "aes-256-gcm"):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine algorithm
            algorithm = "unknown"
            if algorithm_arg is not None:
                if isinstance(algorithm_arg, str) and algorithm_arg in kwargs:
                    algorithm = str(kwargs[algorithm_arg])
                elif isinstance(algorithm_arg, int) and len(args) > algorithm_arg:
                    algorithm = str(args[algorithm_arg])

            with metrics.track_operation(operation, algorithm):
                return func(*args, **kwargs)

        return wrapper
    return decorator


def with_async_metrics(operation: str, algorithm_arg: str | int | None = None):
    """Async version of with_metrics decorator."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            algorithm = "unknown"
            if algorithm_arg is not None:
                if isinstance(algorithm_arg, str) and algorithm_arg in kwargs:
                    algorithm = str(kwargs[algorithm_arg])
                elif isinstance(algorithm_arg, int) and len(args) > algorithm_arg:
                    algorithm = str(args[algorithm_arg])

            with metrics.track_operation(operation, algorithm):
                return await func(*args, **kwargs)

        return wrapper
    return decorator


# ==================== FastAPI Integration ====================

def get_metrics_endpoint():
    """Get FastAPI endpoint for Prometheus metrics scraping.

    Usage:
        from app.core.metrics import get_metrics_endpoint
        app.add_api_route("/metrics", get_metrics_endpoint())
    """
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response

    async def metrics_endpoint():
        return Response(
            content=generate_latest(REGISTRY),
            media_type=CONTENT_TYPE_LATEST,
        )

    return metrics_endpoint


def setup_metrics(app):
    """Set up metrics endpoint on FastAPI app.

    Usage:
        from app.core.metrics import setup_metrics
        setup_metrics(app)
    """
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi import Response

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        return Response(
            content=generate_latest(REGISTRY),
            media_type=CONTENT_TYPE_LATEST,
        )

    # Initialize engine info
    metrics.initialize(
        version="1.0.0",
        algorithms=[
            "aes-256-gcm",
            "chacha20-poly1305",
            "x25519",
            "ed25519",
            "ecdsa-p256",
            "rsa-oaep",
            "argon2id",
            "bcrypt",
            "scrypt",
        ],
    )


# Singleton instance
metrics = MetricsRecorder()
