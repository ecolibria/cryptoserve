"""
Asynchronous CryptoServe API client.

Requires httpx: pip install cryptoserve-client[async]
"""

import base64
from typing import Any

import httpx

from cryptoserve_client.errors import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    ServerError,
    RateLimitError,
)


class AsyncCryptoClient:
    """
    Asynchronous client for CryptoServe API.

    Use this for async applications (FastAPI, aiohttp, etc.)

    Example:
        async with AsyncCryptoClient(server_url, token) as client:
            ciphertext = await client.encrypt(b"secret", context="user-pii")
    """

    def __init__(
        self,
        server_url: str,
        token: str,
        timeout: float = 30.0,
        user_agent: str | None = None,
    ):
        """
        Initialize the async client.

        Args:
            server_url: Base URL of the CryptoServe server
            token: Identity token for authentication
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout

        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": user_agent or f"cryptoserve-client-async/{__import__('cryptoserve_client').__version__}",
            },
            timeout=timeout,
        )

    async def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """
        Encrypt data using server-managed keys.

        Args:
            plaintext: Data to encrypt
            context: Crypto context name

        Returns:
            Encrypted ciphertext
        """
        response = await self._request(
            "POST",
            "/v1/crypto/encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "context": context,
            },
        )
        return base64.b64decode(response["ciphertext"])

    async def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data using server-managed keys.

        Args:
            ciphertext: Encrypted data
            context: Crypto context name

        Returns:
            Decrypted plaintext
        """
        response = await self._request(
            "POST",
            "/v1/crypto/decrypt",
            json={
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "context": context,
            },
        )
        return base64.b64decode(response["plaintext"])

    async def get_identity_info(self) -> dict[str, Any]:
        """Get information about the current identity."""
        return await self._request("GET", f"/sdk/info/{self.token}")

    async def health_check(self) -> dict[str, Any]:
        """Check server health."""
        response = await self._client.get(f"{self.server_url}/health")
        return response.json()

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Make an authenticated request to the API."""
        response = await self._client.request(
            method,
            f"{self.server_url}{path}",
            **kwargs,
        )
        return self._handle_response(response, path)

    def _handle_response(
        self,
        response: httpx.Response,
        path: str,
    ) -> dict[str, Any]:
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 200:
            return response.json()

        try:
            detail = response.json().get("detail", "Unknown error")
        except Exception:
            detail = response.text or "Unknown error"

        status = response.status_code

        if status == 401:
            raise AuthenticationError(f"Invalid or expired token: {detail}", status)
        elif status == 403:
            raise AuthorizationError(f"Not authorized: {detail}", status)
        elif status == 404:
            if "context" in path.lower() or "context" in detail.lower():
                raise ContextNotFoundError(detail, status)
            raise CryptoServeError(f"Not found: {detail}", status)
        elif status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                f"Rate limit exceeded: {detail}",
                retry_after=int(retry_after) if retry_after else None,
            )
        elif status >= 500:
            raise ServerError(f"Server error ({status}): {detail}", status)
        else:
            raise CryptoServeError(f"Request failed ({status}): {detail}", status)

    async def close(self):
        """Close the client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
