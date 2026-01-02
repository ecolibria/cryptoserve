"""
CryptoServe SDK with automatic application registration.

This module provides the CryptoServe class which handles automatic
application registration on first use, eliminating the need to
manually create applications in the dashboard.

Performance Features:
- Local key caching (reduces latency from ~5-50ms to ~0.1-0.5ms)
- Client-side encryption when keys are cached
- Automatic cache invalidation on key rotation
"""

import requests
from typing import Optional, Dict, Any

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
from cryptoserve._cache import KeyCache, get_key_cache, configure_cache
from cryptoserve._local_crypto import (
    LocalCrypto,
    get_local_crypto,
    is_local_crypto_available,
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
        enable_cache: Enable local key caching for performance (default: True)
        cache_ttl: Cache TTL in seconds (default: 300 = 5 minutes)
        cache_size: Maximum cached keys (default: 100)
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
        enable_cache: bool = True,
        cache_ttl: float = 300.0,
        cache_size: int = 100,
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

        # Performance: local key caching
        self._enable_cache = enable_cache and is_local_crypto_available()
        self._cache: Optional[KeyCache] = None
        self._local_crypto: Optional[LocalCrypto] = None

        if self._enable_cache:
            self._cache = configure_cache(
                max_size=cache_size,
                default_ttl=cache_ttl,
            )
            self._local_crypto = get_local_crypto()

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

    def encrypt(
        self,
        plaintext: bytes,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypt data using a specific context.

        Performance: Uses local encryption with cached keys when available,
        reducing latency from ~5-50ms to ~0.1-0.5ms.

        Args:
            plaintext: Data to encrypt
            context: Encryption context name (e.g., "user-pii", "payment-data")
            associated_data: Optional authenticated data (not encrypted)

        Returns:
            Encrypted ciphertext

        Example:
            ```python
            encrypted = crypto.encrypt(b"user@example.com", context="user-pii")
            ```
        """
        # Try local encryption with cached key
        if self._enable_cache and self._cache and self._local_crypto:
            cached = self._cache.get(context, "encrypt")
            if cached:
                result = self._local_crypto.encrypt(
                    plaintext=plaintext,
                    key=cached.key,
                    key_id=cached.key_id,
                    context=context,
                    algorithm=cached.algorithm,
                    associated_data=associated_data,
                )
                if result.success and result.data:
                    return result.data

        # Fall back to server (also fetches key for caching)
        ciphertext = self.client.encrypt(plaintext, context, associated_data)

        # Try to cache the key for future operations
        self._cache_key_from_server(context, "encrypt")

        return ciphertext

    def decrypt(
        self,
        ciphertext: bytes,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data using a specific context.

        Performance: Uses local decryption with cached keys when available,
        reducing latency from ~5-50ms to ~0.1-0.5ms.

        Args:
            ciphertext: Encrypted data
            context: Encryption context name (must match encryption context)
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Example:
            ```python
            decrypted = crypto.decrypt(encrypted, context="user-pii")
            ```
        """
        # Try local decryption with cached key
        if self._enable_cache and self._cache and self._local_crypto:
            cached = self._cache.get(context, "decrypt")
            if cached:
                # Verify the cached key matches the ciphertext's key ID
                if self._local_crypto.can_decrypt_locally(ciphertext, cached.key_id):
                    result = self._local_crypto.decrypt(
                        ciphertext=ciphertext,
                        key=cached.key,
                        associated_data=associated_data,
                    )
                    if result.success and result.data:
                        return result.data

        # Fall back to server
        plaintext = self.client.decrypt(ciphertext, context, associated_data)

        # Try to cache the key for future operations
        self._cache_key_from_server(context, "decrypt")

        return plaintext

    def _cache_key_from_server(self, context: str, operation: str) -> None:
        """
        Fetch and cache key from server for local crypto operations.

        This is called after a successful server operation to enable
        future local operations.
        """
        if not self._enable_cache or not self._cache:
            return

        try:
            # Request key bundle from server
            response = requests.post(
                f"{self._api_url}/v1/crypto/key-bundle",
                headers={"Authorization": f"Bearer {self.client._access_token}"},
                json={"context": context},
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                import base64

                self._cache.put(
                    context=context,
                    key=base64.b64decode(data["key"]),
                    key_id=data["key_id"],
                    algorithm=data.get("algorithm", "AES-256-GCM"),
                    ttl=data.get("ttl", 300),
                    operation=operation,
                    version=data.get("version", 1),
                )
        except Exception:
            # Caching failure is non-fatal - server operations still work
            pass

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
                f"{self.server_url}/health",
                headers={"Authorization": f"Bearer {self.client._access_token}"},
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False

    # =========================================================================
    # String convenience methods
    # =========================================================================

    def encrypt_string(
        self,
        text: str,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> str:
        """
        Encrypt a string and return base64-encoded ciphertext.

        Args:
            text: String to encrypt
            context: Encryption context
            associated_data: Optional AAD

        Returns:
            Base64-encoded ciphertext
        """
        import base64
        ciphertext = self.encrypt(text.encode("utf-8"), context, associated_data)
        return base64.b64encode(ciphertext).decode("ascii")

    def decrypt_string(
        self,
        ciphertext: str,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> str:
        """
        Decrypt base64-encoded ciphertext to a string.

        Args:
            ciphertext: Base64-encoded ciphertext
            context: Encryption context
            associated_data: Optional AAD (must match encryption)

        Returns:
            Decrypted string
        """
        import base64
        plaintext = self.decrypt(base64.b64decode(ciphertext), context, associated_data)
        return plaintext.decode("utf-8")

    def encrypt_json(
        self,
        obj: Any,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> str:
        """
        Encrypt a JSON-serializable object.

        Args:
            obj: Object to serialize and encrypt
            context: Encryption context
            associated_data: Optional AAD

        Returns:
            Base64-encoded ciphertext
        """
        import json
        return self.encrypt_string(json.dumps(obj), context, associated_data)

    def decrypt_json(
        self,
        ciphertext: str,
        context: str,
        associated_data: Optional[bytes] = None,
    ) -> Any:
        """
        Decrypt ciphertext to a JSON object.

        Args:
            ciphertext: Base64-encoded ciphertext
            context: Encryption context
            associated_data: Optional AAD (must match encryption)

        Returns:
            Parsed JSON object
        """
        import json
        return json.loads(self.decrypt_string(ciphertext, context, associated_data))

    # =========================================================================
    # Cache management
    # =========================================================================

    def cache_stats(self) -> Dict[str, Any]:
        """
        Get cache performance statistics.

        Returns:
            Dict with cache stats including hit rate, size, etc.

        Example:
            ```python
            stats = crypto.cache_stats()
            print(f"Cache hit rate: {stats['hit_rate']:.1%}")
            ```
        """
        if not self._cache:
            return {
                "enabled": False,
                "reason": "Cache disabled or cryptography library not available",
            }

        stats = self._cache.stats()
        stats["enabled"] = True
        return stats

    def invalidate_cache(self, context: Optional[str] = None) -> int:
        """
        Invalidate cached keys.

        Args:
            context: Specific context to invalidate, or None for all

        Returns:
            Number of entries invalidated

        Example:
            ```python
            # Invalidate specific context (e.g., after key rotation)
            crypto.invalidate_cache("user-pii")

            # Invalidate all cached keys
            crypto.invalidate_cache()
            ```
        """
        if not self._cache:
            return 0

        if context:
            return self._cache.invalidate(context)
        else:
            return self._cache.invalidate_all()

    def configure_cache(
        self,
        ttl: Optional[float] = None,
        max_size: Optional[int] = None,
    ) -> None:
        """
        Reconfigure cache settings.

        Args:
            ttl: New TTL in seconds
            max_size: New maximum cache size
        """
        if not self._enable_cache:
            return

        self._cache = configure_cache(
            max_size=max_size or 100,
            default_ttl=ttl or 300.0,
        )

    def __repr__(self) -> str:
        cache_status = "enabled" if self._enable_cache else "disabled"
        return f"CryptoServe(app_name='{self.app_name}', environment='{self.environment}', cache={cache_status})"
