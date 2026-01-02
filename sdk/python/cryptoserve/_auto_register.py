"""
CryptoServe SDK with automatic application registration.

This module provides the CryptoServe class which handles automatic
application registration on first use, eliminating the need to
manually create applications in the dashboard.
"""

import requests
from typing import Optional

from cryptoserve._credentials import (
    load_app_credentials,
    save_app_credentials,
    update_app_tokens,
    get_session_cookie,
    get_server_url,
    get_api_url,
    is_logged_in,
)
from cryptoserve.client import (
    CryptoClient,
    CryptoServeError,
    AuthenticationError,
)


class CryptoServeNotLoggedInError(CryptoServeError):
    """User has not logged in via CLI."""
    pass


class CryptoServeRegistrationError(CryptoServeError):
    """Failed to register application."""
    pass


class CryptoServe:
    """
    CryptoServe SDK client with automatic application registration.

    This class provides a zero-friction developer experience:
    1. User runs `cryptoserve login` once (stores auth locally)
    2. Import and initialize CryptoServe with your app details
    3. App is automatically registered on first use

    Example:
        ```python
        from cryptoserve import CryptoServe

        # Initialize - app is auto-registered if needed
        crypto = CryptoServe(
            app_name="my-service",
            team="platform",
            environment="development"
        )

        # Use immediately
        encrypted = crypto.encrypt(b"sensitive data", context="user-pii")
        decrypted = crypto.decrypt(encrypted, context="user-pii")
        ```

    Args:
        app_name: Name of your application (e.g., "my-service")
        team: Team or department name (default: "default")
        environment: Environment name (default: "development")
        contexts: List of encryption contexts to request (default: ["default"])
        description: Optional application description
        server_url: Override server URL (uses saved URL from login by default)
        auto_register: Automatically register app if needed (default: True)
    """

    def __init__(
        self,
        app_name: str,
        team: str = "default",
        environment: str = "development",
        contexts: Optional[list[str]] = None,
        description: Optional[str] = None,
        server_url: Optional[str] = None,
        auto_register: bool = True,
    ):
        self.app_name = app_name
        self.team = team
        self.environment = environment
        self.contexts = contexts or ["default"]
        self.description = description
        # Base server URL for registration
        self.server_url = server_url or get_server_url()
        # API URL (with /api suffix) for CryptoClient
        self._api_url = get_api_url() if not server_url else server_url.rstrip("/") + "/api"
        self._client: Optional[CryptoClient] = None
        self._app_id: Optional[str] = None

        if auto_register:
            self._ensure_registered()

    def _ensure_registered(self) -> None:
        """Ensure the application is registered and we have valid credentials."""
        # First, try to load existing credentials
        creds = load_app_credentials(self.app_name, self.environment)

        if creds:
            # We have stored credentials - try to use them
            self._app_id = creds["app_id"]
            # Use API URL (with /api suffix) for CryptoClient
            stored_url = creds.get("server_url", self.server_url)
            api_url = stored_url.rstrip("/") + "/api" if not stored_url.endswith("/api") else stored_url
            self._client = CryptoClient(
                server_url=api_url,
                token=creds["access_token"],
                refresh_token=creds.get("refresh_token"),
                auto_refresh=True,
            )
            return

        # No stored credentials - need to register
        self._register_application()

    def _register_application(self) -> None:
        """Register the application with the server."""
        # Check if user is logged in
        session_cookie = get_session_cookie()
        if not session_cookie:
            raise CryptoServeNotLoggedInError(
                "Not logged in. Please run 'cryptoserve login' first.\n"
                "This is a one-time setup to link your machine to your account."
            )

        # Call the SDK register endpoint
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/applications/sdk/register",
                json={
                    "app_name": self.app_name,
                    "team": self.team,
                    "environment": self.environment,
                    "contexts": self.contexts,
                    "description": self.description,
                },
                cookies={"access_token": session_cookie},
                timeout=30,
            )

            if response.status_code == 401:
                raise CryptoServeNotLoggedInError(
                    "Session expired. Please run 'cryptoserve login' again."
                )

            if response.status_code == 400:
                error_detail = response.json().get("detail", "Registration failed")
                raise CryptoServeRegistrationError(error_detail)

            response.raise_for_status()
            data = response.json()

            # Save credentials locally
            save_app_credentials(
                app_name=self.app_name,
                environment=self.environment,
                app_id=data["app_id"],
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                contexts=data.get("contexts", self.contexts),
                server_url=self.server_url,
            )

            # Create the client (use API URL with /api suffix)
            self._app_id = data["app_id"]
            self._client = CryptoClient(
                server_url=self._api_url,
                token=data["access_token"],
                refresh_token=data["refresh_token"],
                auto_refresh=True,
            )

            # Log registration status
            if data.get("is_new"):
                print(f"[CryptoServe] Registered new app: {self.app_name} ({self.environment})")
            else:
                print(f"[CryptoServe] Connected to: {self.app_name} ({self.environment})")

        except requests.exceptions.ConnectionError:
            raise CryptoServeRegistrationError(
                f"Cannot connect to server at {self.server_url}. "
                "Make sure the server is running."
            )
        except requests.exceptions.RequestException as e:
            raise CryptoServeRegistrationError(f"Registration failed: {e}")

    @property
    def app_id(self) -> Optional[str]:
        """Get the application ID."""
        return self._app_id

    @property
    def client(self) -> CryptoClient:
        """Get the underlying CryptoClient."""
        if self._client is None:
            raise CryptoServeError("SDK not initialized. Call _ensure_registered() first.")
        return self._client

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """
        Encrypt data using a specific context.

        Args:
            plaintext: Data to encrypt
            context: Encryption context name (e.g., "user-pii", "payment-data")

        Returns:
            Encrypted ciphertext

        Example:
            ```python
            encrypted = crypto.encrypt(b"user@example.com", context="user-pii")
            ```
        """
        return self.client.encrypt(plaintext, context)

    def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data using a specific context.

        Args:
            ciphertext: Encrypted data
            context: Encryption context name (must match encryption context)

        Returns:
            Decrypted plaintext

        Example:
            ```python
            decrypted = crypto.decrypt(encrypted, context="user-pii")
            ```
        """
        return self.client.decrypt(ciphertext, context)

    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Sign data using a signing key.

        Args:
            data: Data to sign
            key_id: ID of the signing key

        Returns:
            Signature bytes

        Example:
            ```python
            signature = crypto.sign(b"document", key_id="my-key-id")
            ```
        """
        return self.client.sign(data, key_id)

    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        key_id: str | None = None,
        public_key: str | None = None
    ) -> bool:
        """
        Verify a signature.

        Args:
            data: Original data that was signed
            signature: Signature to verify
            key_id: ID of the signing key (if using server-managed keys)
            public_key: Public key PEM (if verifying external signature)

        Returns:
            True if signature is valid, False otherwise

        Example:
            ```python
            is_valid = crypto.verify_signature(b"document", signature, key_id="my-key-id")
            ```
        """
        return self.client.verify(data, signature, key_id, public_key)

    def hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """
        Compute a cryptographic hash.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha384, sha512, sha3-256, blake2b)

        Returns:
            Hash as hex string

        Example:
            ```python
            hash_hex = crypto.hash(b"hello world")
            ```
        """
        return self.client.hash(data, algorithm)

    def mac(self, data: bytes, key: bytes, algorithm: str = "hmac-sha256") -> str:
        """
        Compute a Message Authentication Code.

        Args:
            data: Data to authenticate
            key: Secret key
            algorithm: MAC algorithm (hmac-sha256, hmac-sha512)

        Returns:
            MAC as hex string

        Example:
            ```python
            mac_hex = crypto.mac(b"message", key)
            ```
        """
        return self.client.mac(data, key, algorithm)

    def health_check(self) -> bool:
        """
        Verify the SDK connection is working.

        Returns:
            True if connection is successful
        """
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/health",
                headers={"Authorization": f"Bearer {self.client._access_token}"},
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"CryptoServe(app_name='{self.app_name}', environment='{self.environment}')"
