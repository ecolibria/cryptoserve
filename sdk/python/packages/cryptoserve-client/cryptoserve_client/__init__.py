"""
CryptoServe Client - API client for CryptoServe server.

This package provides the network layer for communicating with
a CryptoServe server for key management and crypto operations.

Features:
- Automatic token refresh
- Retry with exponential backoff
- Circuit breaker for fault tolerance
- Batch operations for bulk processing
"""

from cryptoserve_client.client import CryptoClient
from cryptoserve_client.errors import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    ServerError,
    RateLimitError,
    TokenRefreshError,
)
from cryptoserve_client.resilience import (
    RetryConfig,
    CircuitBreakerConfig,
    CircuitBreaker,
    CircuitOpenError,
    BatchProcessor,
    BatchResult,
    create_production_config,
)

__version__ = "0.3.0"

__all__ = [
    # Client
    "CryptoClient",
    # Errors
    "CryptoServeError",
    "AuthenticationError",
    "AuthorizationError",
    "ContextNotFoundError",
    "ServerError",
    "RateLimitError",
    "TokenRefreshError",
    # Resilience
    "RetryConfig",
    "CircuitBreakerConfig",
    "CircuitBreaker",
    "CircuitOpenError",
    "BatchProcessor",
    "BatchResult",
    "create_production_config",
]

# Async client available if httpx is installed
try:
    from cryptoserve_client.async_client import AsyncCryptoClient
    __all__.append("AsyncCryptoClient")
except ImportError:
    pass
