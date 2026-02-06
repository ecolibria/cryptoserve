"""CryptoServe API client."""

import base64
import json
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import requests


class Usage(str, Enum):
    """
    Runtime usage hints for encryption operations.

    These hints tell CryptoServe HOW your data is being used, allowing
    intelligent algorithm selection that combines your context policy
    (WHAT the data is) with runtime usage (HOW it's being used).

    This is CryptoServe's key differentiator: admins define context policies
    once, and developers provide runtime hints without needing to understand
    cryptographic details. The platform automatically selects optimal algorithms.

    Example:
        # Store PII in database - use AT_REST
        crypto.encrypt(data, context="customer-pii", usage=Usage.AT_REST)

        # Send same PII over API - use IN_TRANSIT
        crypto.encrypt(data, context="customer-pii", usage=Usage.IN_TRANSIT)

        # Same context, different algorithms based on usage!
    """
    AT_REST = "at_rest"           # Database storage, file encryption (AES-256-GCM)
    IN_TRANSIT = "in_transit"     # Network transmission, API payloads (AES-256-GCM)
    IN_USE = "in_use"             # Memory encryption, active processing (AES-256-GCM-SIV)
    STREAMING = "streaming"       # Real-time data streams (ChaCha20-Poly1305)
    DISK = "disk"                 # Volume/disk encryption (XTS mode via context policy)


class CryptoServeError(Exception):
    """Base exception for CryptoServe errors."""
    pass


class AuthenticationError(CryptoServeError):
    """Authentication failed - invalid or expired token."""
    pass


class TokenRefreshError(CryptoServeError):
    """Failed to refresh the access token."""
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


class CryptoClient:
    """
    Client for CryptoServe API.

    This client handles communication with the CryptoServe server.
    In most cases, you should use the `crypto` class from the main
    module instead of this client directly.

    Supports automatic token refresh when a refresh token is provided.
    """

    # Refresh token if less than 5 minutes remaining
    REFRESH_THRESHOLD_SECONDS = 300

    def __init__(
        self,
        server_url: str,
        token: str,
        refresh_token: Optional[str] = None,
        auto_refresh: bool = True,
        timeout: float = 30.0,
    ):
        """
        Initialize the client.

        Args:
            server_url: Base URL of the CryptoServe server
            token: Access token for API calls
            refresh_token: Optional refresh token for auto-refresh
            auto_refresh: Enable automatic token refresh (default: True)
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self._access_token = token
        self._refresh_token = refresh_token
        self._auto_refresh = auto_refresh and refresh_token is not None
        self.timeout = timeout

        # Token expiry tracking
        self._token_expiry: Optional[datetime] = None
        self._parse_token_expiry(token)

        # Thread safety for token refresh
        self._refresh_lock = threading.Lock()

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "cryptoserve-sdk/1.0.0",
        })
        self._update_auth_header()

    def _update_auth_header(self):
        """Update the Authorization header with current token."""
        self.session.headers["Authorization"] = f"Bearer {self._access_token}"

    def _parse_token_expiry(self, token: str) -> None:
        """Parse token expiry from JWT payload (without verification)."""
        try:
            # JWT format: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode payload (base64url)
            payload = parts[1]
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            if "exp" in claims:
                self._token_expiry = datetime.fromtimestamp(
                    claims["exp"], tz=timezone.utc
                )
        except Exception:
            # If parsing fails, we'll rely on 401 responses to trigger refresh
            self._token_expiry = None

    def _should_refresh(self) -> bool:
        """Check if token needs refresh (expired or expiring soon)."""
        if not self._auto_refresh or not self._refresh_token:
            return False

        if self._token_expiry is None:
            return False

        now = datetime.now(timezone.utc)
        remaining = (self._token_expiry - now).total_seconds()
        return remaining < self.REFRESH_THRESHOLD_SECONDS

    def _do_refresh(self) -> None:
        """Exchange refresh token for new access token."""
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/auth/refresh",
                json={"refresh_token": self._refresh_token},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                self._access_token = data["access_token"]
                self._parse_token_expiry(self._access_token)
                self._update_auth_header()
            elif response.status_code == 401:
                # Refresh token is invalid/expired
                self._auto_refresh = False
                raise TokenRefreshError(
                    "Refresh token is invalid or expired. "
                    "Please update CRYPTOSERVE_REFRESH_TOKEN."
                )
            else:
                raise TokenRefreshError(
                    f"Token refresh failed ({response.status_code}): {response.text}"
                )
        except requests.RequestException as e:
            raise TokenRefreshError(f"Token refresh request failed: {e}")

    def _ensure_valid_token(self) -> None:
        """Refresh token if expired or expiring soon (thread-safe)."""
        if not self._should_refresh():
            return

        with self._refresh_lock:
            # Double-check after acquiring lock
            if self._should_refresh():
                self._do_refresh()

    def _try_refresh_and_retry(self) -> bool:
        """
        Attempt to refresh token after a 401 response.

        Returns:
            True if refresh succeeded and request should be retried.
            False if refresh is not available or failed.
        """
        if not self._auto_refresh or not self._refresh_token:
            return False

        try:
            with self._refresh_lock:
                self._do_refresh()
            return True
        except TokenRefreshError:
            return False

    def encrypt(
        self,
        plaintext: bytes,
        context: str,
        associated_data: Optional[bytes] = None,
        usage: Optional[Usage] = None,
    ) -> bytes:
        """
        Encrypt data.

        Args:
            plaintext: Data to encrypt
            context: Crypto context name
            associated_data: Optional authenticated but unencrypted data
            usage: Runtime usage hint (how this data is being used).
                   Combines with context policy to select optimal algorithm.
                   Options: Usage.AT_REST (database), Usage.IN_TRANSIT (network),
                   Usage.IN_USE (memory), Usage.STREAMING (real-time),
                   Usage.DISK (volume encryption).
                   If not specified, uses the context's default usage.

        Returns:
            Encrypted ciphertext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            ContextNotFoundError: If context doesn't exist
            ServerError: If server returns an error

        Example:
            # Store customer PII in database
            ciphertext = crypto.encrypt(
                data=customer_ssn.encode(),
                context="customer-pii",
                usage=Usage.AT_REST
            )

            # Send same PII over API (different algorithm selected)
            ciphertext = crypto.encrypt(
                data=customer_ssn.encode(),
                context="customer-pii",
                usage=Usage.IN_TRANSIT
            )
        """
        # Auto-refresh token if needed
        self._ensure_valid_token()

        payload = {
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
            "context": context,
        }
        if associated_data:
            payload["associated_data"] = base64.b64encode(associated_data).decode("ascii")
        if usage:
            payload["usage"] = usage.value if isinstance(usage, Usage) else usage

        response = self.session.post(
            f"{self.server_url}/v1/crypto/encrypt",
            json=payload,
            timeout=self.timeout,
        )

        # Handle 401 with retry after refresh
        if response.status_code == 401 and self._try_refresh_and_retry():
            response = self.session.post(
                f"{self.server_url}/v1/crypto/encrypt",
                json=payload,
                timeout=self.timeout,
            )

        self._handle_response(response, context)

        data = response.json()
        return base64.b64decode(data["ciphertext"])

    def decrypt(
        self,
        ciphertext: bytes,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data.

        Args:
            ciphertext: Encrypted data
            context: Crypto context name
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            CryptoServeError: If decryption fails
            ServerError: If server returns an error
        """
        # Auto-refresh token if needed
        self._ensure_valid_token()

        payload = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "context": context,
        }
        if associated_data:
            payload["associated_data"] = base64.b64encode(associated_data).decode("ascii")

        response = self.session.post(
            f"{self.server_url}/v1/crypto/decrypt",
            json=payload,
            timeout=self.timeout,
        )

        # Handle 401 with retry after refresh
        if response.status_code == 401 and self._try_refresh_and_retry():
            response = self.session.post(
                f"{self.server_url}/v1/crypto/decrypt",
                json=payload,
                timeout=self.timeout,
            )

        self._handle_response(response, context)

        data = response.json()
        return base64.b64decode(data["plaintext"])

    def _handle_response(self, response: requests.Response, context: str):
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 200:
            return

        try:
            detail = response.json().get("detail", "Unknown error")
        except Exception:
            detail = response.text or "Unknown error"

        if response.status_code == 401:
            raise AuthenticationError(
                f"Invalid or expired identity token: {detail}"
            )
        elif response.status_code == 403:
            raise AuthorizationError(
                f"Not authorized for context '{context}': {detail}"
            )
        elif response.status_code == 400:
            if "context" in detail.lower():
                raise ContextNotFoundError(detail)
            raise CryptoServeError(detail)
        else:
            raise ServerError(
                f"Server error ({response.status_code}): {detail}"
            )

    def hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """
        Compute a cryptographic hash locally.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha384, sha512, sha3-256, blake2b)

        Returns:
            Hash as hex string
        """
        import hashlib

        algorithm_map = {
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
            "sha3-256": hashlib.sha3_256,
            "blake2b": hashlib.blake2b,
        }

        if algorithm not in algorithm_map:
            raise CryptoServeError(
                f"Unsupported hash algorithm: {algorithm}. "
                f"Supported: {', '.join(algorithm_map.keys())}"
            )

        hasher = algorithm_map[algorithm]()
        hasher.update(data)
        return hasher.hexdigest()

    def mac(self, data: bytes, key: bytes, algorithm: str = "hmac-sha256") -> str:
        """
        Compute a Message Authentication Code locally.

        Args:
            data: Data to authenticate
            key: Secret key (should be 32 bytes for hmac-sha256)
            algorithm: MAC algorithm (hmac-sha256, hmac-sha512)

        Returns:
            MAC as hex string
        """
        import hashlib
        import hmac as hmac_module

        algorithm_map = {
            "hmac-sha256": hashlib.sha256,
            "hmac-sha512": hashlib.sha512,
        }

        if algorithm not in algorithm_map:
            raise CryptoServeError(
                f"Unsupported MAC algorithm: {algorithm}. "
                f"Supported: {', '.join(algorithm_map.keys())}"
            )

        digest = algorithm_map[algorithm]
        mac = hmac_module.new(key, data, digest)
        return mac.hexdigest()

    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Sign data using a key managed by the server.

        Args:
            data: Data to sign
            key_id: ID of the signing key

        Returns:
            Signature bytes
        """
        # Auto-refresh token if needed
        self._ensure_valid_token()

        response = self.session.post(
            f"{self.server_url}/v1/crypto/sign",
            json={
                "message": base64.b64encode(data).decode("ascii"),
                "key_id": key_id,
            },
            timeout=self.timeout,
        )

        # Handle 401 with retry after refresh
        if response.status_code == 401 and self._try_refresh_and_retry():
            response = self.session.post(
                f"{self.server_url}/v1/crypto/sign",
                json={
                    "message": base64.b64encode(data).decode("ascii"),
                    "key_id": key_id,
                },
                timeout=self.timeout,
            )

        self._handle_response(response, key_id)

        result = response.json()
        return base64.b64decode(result["signature"])

    def verify(
        self,
        data: bytes,
        signature: bytes,
        key_id: str,
        public_key: Optional[bytes] = None,
    ) -> bool:
        """
        Verify a signature.

        Args:
            data: Original data that was signed
            signature: Signature to verify
            key_id: ID of the signing key
            public_key: Optional public key bytes (if not using server key)

        Returns:
            True if signature is valid
        """
        # Auto-refresh token if needed
        self._ensure_valid_token()

        payload = {
            "message": base64.b64encode(data).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
            "key_id": key_id,
        }
        if public_key:
            payload["public_key"] = base64.b64encode(public_key).decode("ascii")

        response = self.session.post(
            f"{self.server_url}/v1/crypto/verify",
            json=payload,
            timeout=self.timeout,
        )

        # Handle 401 with retry after refresh
        if response.status_code == 401 and self._try_refresh_and_retry():
            response = self.session.post(
                f"{self.server_url}/v1/crypto/verify",
                json=payload,
                timeout=self.timeout,
            )

        if response.status_code == 200:
            return response.json().get("valid", False)

        # Handle specific errors
        self._handle_response(response, key_id)
        return False
