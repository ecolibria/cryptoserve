"""
Synchronous CryptoServe API client.
"""

import base64
from typing import Any

import requests

from cryptoserve_client.errors import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    ServerError,
    RateLimitError,
)


class CryptoClient:
    """
    Synchronous client for CryptoServe API.

    Handles communication with the CryptoServe server for encryption,
    decryption, and key management operations.

    Example:
        client = CryptoClient(
            server_url="https://api.cryptoserve.dev",
            token="your-identity-token",
        )
        ciphertext = client.encrypt(b"secret", context="user-pii")
    """

    def __init__(
        self,
        server_url: str,
        token: str,
        timeout: float = 30.0,
        user_agent: str | None = None,
    ):
        """
        Initialize the client.

        Args:
            server_url: Base URL of the CryptoServe server
            token: Identity token for authentication
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent or f"cryptoserve-client/{__import__('cryptoserve_client').__version__}",
        })

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """
        Encrypt data using server-managed keys.

        Args:
            plaintext: Data to encrypt
            context: Crypto context name

        Returns:
            Encrypted ciphertext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            ContextNotFoundError: If context doesn't exist
        """
        response = self._request(
            "POST",
            "/v1/crypto/encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "context": context,
            },
        )
        return base64.b64decode(response["ciphertext"])

    def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data using server-managed keys.

        Args:
            ciphertext: Encrypted data
            context: Crypto context name

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            CryptoServeError: If decryption fails
        """
        response = self._request(
            "POST",
            "/v1/crypto/decrypt",
            json={
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "context": context,
            },
        )
        return base64.b64decode(response["plaintext"])

    def get_identity_info(self) -> dict[str, Any]:
        """
        Get information about the current identity.

        Returns:
            Dict with identity details
        """
        return self._request("GET", f"/sdk/info/{self.token}")

    def health_check(self) -> dict[str, Any]:
        """
        Check server health.

        Returns:
            Dict with health status
        """
        response = self._session.get(
            f"{self.server_url}/health",
            timeout=self.timeout,
        )
        return response.json()

    def list_contexts(self) -> list[dict[str, Any]]:
        """
        List available contexts for this identity.

        Returns:
            List of context info dicts
        """
        info = self.get_identity_info()
        return info.get("allowed_contexts", [])

    def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Make an authenticated request to the API.

        Args:
            method: HTTP method
            path: API path
            **kwargs: Additional arguments for requests

        Returns:
            Response JSON

        Raises:
            CryptoServeError: On API errors
        """
        kwargs.setdefault("timeout", self.timeout)

        response = self._session.request(
            method,
            f"{self.server_url}{path}",
            **kwargs,
        )

        return self._handle_response(response, path)

    def _handle_response(
        self,
        response: requests.Response,
        path: str,
    ) -> dict[str, Any]:
        """
        Handle API response and raise appropriate exceptions.

        Args:
            response: HTTP response
            path: API path for error context

        Returns:
            Response JSON

        Raises:
            CryptoServeError: On API errors
        """
        if response.status_code == 200:
            return response.json()

        # Parse error detail
        try:
            detail = response.json().get("detail", "Unknown error")
        except Exception:
            detail = response.text or "Unknown error"

        status = response.status_code

        if status == 401:
            raise AuthenticationError(
                f"Invalid or expired token: {detail}",
                status_code=status,
            )
        elif status == 403:
            raise AuthorizationError(
                f"Not authorized: {detail}",
                status_code=status,
            )
        elif status == 404:
            if "context" in path.lower() or "context" in detail.lower():
                raise ContextNotFoundError(detail, status_code=status)
            raise CryptoServeError(f"Not found: {detail}", status_code=status)
        elif status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                f"Rate limit exceeded: {detail}",
                retry_after=int(retry_after) if retry_after else None,
            )
        elif status >= 500:
            raise ServerError(
                f"Server error ({status}): {detail}",
                status_code=status,
            )
        else:
            raise CryptoServeError(
                f"Request failed ({status}): {detail}",
                status_code=status,
            )

    def close(self):
        """Close the client session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
