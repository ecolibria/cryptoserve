"""
CryptoServe Client - API client for CryptoServe server.

This package provides the network layer for communicating with
a CryptoServe server for key management and crypto operations.
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

__version__ = "0.1.0"

__all__ = [
    "CryptoClient",
    "CryptoServeError",
    "AuthenticationError",
    "AuthorizationError",
    "ContextNotFoundError",
    "ServerError",
    "RateLimitError",
    "TokenRefreshError",
]

# Async client available if httpx is installed
try:
    from cryptoserve_client.async_client import AsyncCryptoClient
    __all__.append("AsyncCryptoClient")
except ImportError:
    pass
