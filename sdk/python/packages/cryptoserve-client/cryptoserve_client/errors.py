"""
Exception classes for CryptoServe Client.
"""


class CryptoServeError(Exception):
    """Base exception for CryptoServe errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class AuthenticationError(CryptoServeError):
    """Authentication failed - invalid or expired token."""
    pass


class AuthorizationError(CryptoServeError):
    """Not authorized for this operation or context."""
    pass


class ContextNotFoundError(CryptoServeError):
    """The specified context does not exist."""
    pass


class ServerError(CryptoServeError):
    """Server encountered an error."""
    pass


class RateLimitError(CryptoServeError):
    """Too many requests - rate limit exceeded."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class TokenRefreshError(CryptoServeError):
    """Failed to refresh the access token."""
    pass
