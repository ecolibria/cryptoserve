"""
CryptoServe API Client - Works Like Magic

Simple, intuitive cryptography for developers who don't want to think about it.
Every operation has sensible defaults - just call and go.

Features:
- Automatic token refresh
- Retry with exponential backoff
- Circuit breaker for fault tolerance
- Batch operations for bulk processing
"""

import base64
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, BinaryIO, Callable, Optional

import requests

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
    calculate_delay,
    create_production_config,
)


class CryptoClient:
    """
    CryptoServe client - cryptography that works like magic.

    Basic usage is simple:
        client = CryptoClient(server_url, token)
        encrypted = client.encrypt(b"secret data", "my-context")
        decrypted = client.decrypt(encrypted, "my-context")

    All operations have sensible defaults. Just call and go.

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
        user_agent: str | None = None,
        retry_config: RetryConfig | None = None,
        circuit_config: CircuitBreakerConfig | None = None,
        enable_resilience: bool = False,
    ):
        """
        Initialize the client.

        Args:
            server_url: CryptoServe server URL
            token: Access token for API calls
            refresh_token: Optional refresh token for auto-refresh
            auto_refresh: Enable automatic token refresh (default: True)
            timeout: Request timeout (default: 30s)
            user_agent: Optional custom user agent
            retry_config: Retry configuration (None to use defaults when enabled)
            circuit_config: Circuit breaker configuration (None to use defaults when enabled)
            enable_resilience: Enable retry and circuit breaker with production defaults
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

        # Resilience configuration
        if enable_resilience and not retry_config and not circuit_config:
            retry_config, circuit_config = create_production_config()

        self._retry_config = retry_config
        self._circuit_breaker = CircuitBreaker(circuit_config) if circuit_config else None

        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": user_agent or f"cryptoserve-client/{__import__('cryptoserve_client').__version__}",
        })
        self._update_auth_header()

    # Backward compatibility property
    @property
    def token(self) -> str:
        """Get the current access token."""
        return self._access_token

    def _update_auth_header(self):
        """Update the Authorization header with current token."""
        self._session.headers["Authorization"] = f"Bearer {self._access_token}"

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

    # ==========================================================================
    # Core Encryption - The "just works" experience
    # ==========================================================================

    def encrypt(self, plaintext: bytes, context: str, aad: bytes | None = None) -> bytes:
        """
        Encrypt data. That's it.

        The server handles algorithm selection, key management, and rotation.
        You just get back ciphertext.

        Args:
            plaintext: Data to encrypt
            context: Your crypto context name
            aad: Optional additional authenticated data

        Returns:
            Encrypted ciphertext (self-describing, includes all metadata)
        """
        payload = {
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
            "context": context,
        }
        if aad:
            payload["associated_data"] = base64.b64encode(aad).decode("ascii")

        response = self._request("POST", "/v1/crypto/encrypt", json=payload)
        return base64.b64decode(response["ciphertext"])

    def decrypt(self, ciphertext: bytes, context: str, aad: bytes | None = None) -> bytes:
        """
        Decrypt data. That's it.

        Args:
            ciphertext: Encrypted data (from encrypt())
            context: Your crypto context name
            aad: Additional authenticated data (if used during encryption)

        Returns:
            Decrypted plaintext
        """
        payload = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "context": context,
        }
        if aad:
            payload["associated_data"] = base64.b64encode(aad).decode("ascii")

        response = self._request("POST", "/v1/crypto/decrypt", json=payload)
        return base64.b64decode(response["plaintext"])

    # ==========================================================================
    # Signatures - Sign and verify anything
    # ==========================================================================

    def generate_signing_key(self, algorithm: str = "ed25519", key_id: str | None = None) -> dict:
        """
        Generate a signing key pair.

        Args:
            algorithm: "ed25519" (recommended), "ecdsa-p256", or "rsa"
            key_id: Optional key identifier

        Returns:
            {"key_id": "...", "public_key": "...", "algorithm": "..."}
        """
        return self._request("POST", "/v1/signatures/keys/generate", json={
            "algorithm": algorithm,
            "key_id": key_id,
        })

    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Sign data.

        Args:
            data: Data to sign
            key_id: Signing key ID (from generate_signing_key)

        Returns:
            Signature bytes
        """
        response = self._request("POST", "/v1/signatures/sign", json={
            "data": base64.b64encode(data).decode("ascii"),
            "key_id": key_id,
        })
        return base64.b64decode(response["signature"])

    def verify(self, data: bytes, signature: bytes, key_id: str | None = None, public_key: str | None = None) -> bool:
        """
        Verify a signature.

        Args:
            data: Signed data
            signature: Signature to verify
            key_id: Key ID (if using server-stored key)
            public_key: Public key (if verifying external signature)

        Returns:
            True if valid
        """
        payload = {
            "data": base64.b64encode(data).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        if key_id:
            payload["key_id"] = key_id
        if public_key:
            payload["public_key"] = public_key

        response = self._request("POST", "/v1/signatures/verify", json=payload)
        return response["valid"]

    # ==========================================================================
    # Hashing - Simple hash operations
    # ==========================================================================

    def hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """
        Hash data.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (default: sha256)
                Options: sha256, sha384, sha512, sha3-256, blake2b, blake3

        Returns:
            Hash as hex string
        """
        response = self._request("POST", "/v1/crypto/hash", json={
            "data": base64.b64encode(data).decode("ascii"),
            "algorithm": algorithm,
        })
        return response["hex"]

    def hash_verify(self, data: bytes, expected: str, algorithm: str = "sha256") -> bool:
        """
        Verify a hash (constant-time).

        Args:
            data: Data to verify
            expected: Expected hash (hex)
            algorithm: Hash algorithm

        Returns:
            True if hash matches
        """
        response = self._request("POST", "/v1/crypto/hash/verify", json={
            "data": base64.b64encode(data).decode("ascii"),
            "expected_digest": expected,
            "algorithm": algorithm,
        })
        return response["valid"]

    # ==========================================================================
    # Message Authentication - HMAC and KMAC
    # ==========================================================================

    def mac(self, data: bytes, key: bytes, algorithm: str = "hmac-sha256") -> str:
        """
        Compute message authentication code.

        Args:
            data: Data to authenticate
            key: MAC key
            algorithm: MAC algorithm (default: hmac-sha256)
                Options: hmac-sha256, hmac-sha512, kmac128, kmac256

        Returns:
            MAC as hex string
        """
        response = self._request("POST", "/v1/crypto/mac", json={
            "data": base64.b64encode(data).decode("ascii"),
            "key": base64.b64encode(key).decode("ascii"),
            "algorithm": algorithm,
        })
        return response["hex"]

    def mac_verify(self, data: bytes, key: bytes, expected: str, algorithm: str = "hmac-sha256") -> bool:
        """
        Verify a MAC (constant-time).

        Returns:
            True if MAC matches
        """
        response = self._request("POST", "/v1/crypto/mac/verify", json={
            "data": base64.b64encode(data).decode("ascii"),
            "key": base64.b64encode(key).decode("ascii"),
            "expected_tag": expected,
            "algorithm": algorithm,
        })
        return response["valid"]

    def generate_mac_key(self, algorithm: str = "hmac-sha256") -> bytes:
        """
        Generate a random MAC key.

        Returns:
            Random key bytes
        """
        response = self._request("POST", "/v1/crypto/mac/generate-key", json={
            "algorithm": algorithm,
        })
        return base64.b64decode(response["key"])

    # ==========================================================================
    # Password Hashing - Secure password storage
    # ==========================================================================

    def hash_password(self, password: str, algorithm: str = "argon2id") -> str:
        """
        Hash a password securely.

        Uses Argon2id by default (recommended).

        Args:
            password: Password to hash
            algorithm: "argon2id" (recommended), "bcrypt", "scrypt"

        Returns:
            Password hash string (store this in your database)
        """
        response = self._request("POST", "/v1/crypto/password/hash", json={
            "password": password,
            "algorithm": algorithm,
        })
        return response["hash"]

    def verify_password(self, password: str, hash_string: str) -> dict:
        """
        Verify a password against stored hash.

        Args:
            password: Password to check
            hash_string: Stored hash (from hash_password)

        Returns:
            {"valid": True/False, "needs_rehash": True/False}
        """
        response = self._request("POST", "/v1/crypto/password/verify", json={
            "password": password,
            "hash": hash_string,
        })
        return {"valid": response["valid"], "needs_rehash": response["needs_rehash"]}

    def check_password_strength(self, password: str) -> dict:
        """
        Check password strength.

        Returns:
            {"score": 0-100, "strength": "weak/fair/good/strong", "suggestions": [...]}
        """
        return self._request("POST", "/v1/crypto/password/strength", json={
            "password": password,
        })

    # ==========================================================================
    # JOSE - JWT, JWE, JWS, JWK
    # ==========================================================================

    def jws_sign(self, payload: bytes, key: bytes | dict, algorithm: str = "EdDSA") -> str:
        """
        Create a JSON Web Signature (JWS).

        Args:
            payload: Data to sign
            key: Signing key (bytes or JWK dict)
            algorithm: "EdDSA" (recommended), "ES256", "HS256"

        Returns:
            JWS compact serialization (header.payload.signature)
        """
        key_str = base64.b64encode(key).decode("ascii") if isinstance(key, bytes) else __import__("json").dumps(key)
        response = self._request("POST", "/v1/jose/sign", json={
            "payload": base64.b64encode(payload).decode("ascii"),
            "key": key_str,
            "algorithm": algorithm,
        })
        return response["jws"]

    def jws_verify(self, jws: str, key: bytes | dict) -> dict:
        """
        Verify a JSON Web Signature.

        Returns:
            {"valid": True/False, "payload": bytes}
        """
        key_str = base64.b64encode(key).decode("ascii") if isinstance(key, bytes) else __import__("json").dumps(key)
        response = self._request("POST", "/v1/jose/verify", json={
            "jws": jws,
            "key": key_str,
        })
        return {
            "valid": response["valid"],
            "payload": base64.b64decode(response["payload"]) if response["valid"] else None,
        }

    def jwe_encrypt(self, plaintext: bytes, key: bytes | dict, algorithm: str = "dir", encryption: str = "A256GCM") -> str:
        """
        Create a JSON Web Encryption (JWE).

        Args:
            plaintext: Data to encrypt
            key: Encryption key
            algorithm: Key management algorithm
            encryption: Content encryption algorithm

        Returns:
            JWE compact serialization
        """
        key_str = base64.b64encode(key).decode("ascii") if isinstance(key, bytes) else __import__("json").dumps(key)
        response = self._request("POST", "/v1/jose/encrypt", json={
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
            "key": key_str,
            "algorithm": algorithm,
            "encryption": encryption,
        })
        return response["jwe"]

    def jwe_decrypt(self, jwe: str, key: bytes | dict) -> bytes:
        """
        Decrypt a JSON Web Encryption (JWE).

        Returns:
            Decrypted plaintext
        """
        key_str = base64.b64encode(key).decode("ascii") if isinstance(key, bytes) else __import__("json").dumps(key)
        response = self._request("POST", "/v1/jose/decrypt", json={
            "jwe": jwe,
            "key": key_str,
        })
        return base64.b64decode(response["plaintext"])

    def generate_jwk(self, key_type: str = "OKP", curve: str = "Ed25519", use: str = "sig") -> dict:
        """
        Generate a JSON Web Key (JWK).

        Args:
            key_type: "EC", "OKP" (Ed25519/X25519), or "oct" (symmetric)
            curve: For EC/OKP keys: "P-256", "Ed25519", "X25519"
            use: "sig" (signing) or "enc" (encryption)

        Returns:
            {"private_jwk": {...}, "public_jwk": {...}}
        """
        return self._request("POST", "/v1/jose/jwk/generate", json={
            "key_type": key_type,
            "curve": curve,
            "use": use,
        })

    # ==========================================================================
    # Key Exchange - Derive shared secrets
    # ==========================================================================

    def generate_key_exchange_keys(self, algorithm: str = "x25519") -> dict:
        """
        Generate key exchange key pair.

        Args:
            algorithm: "x25519" (recommended), "ecdh-p256"

        Returns:
            {"private_key": bytes, "public_key": bytes}
        """
        response = self._request("POST", "/v1/crypto/key-exchange/generate", json={
            "algorithm": algorithm,
        })
        return {
            "private_key": base64.b64decode(response["private_key"]),
            "public_key": base64.b64decode(response["public_key"]),
        }

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes, algorithm: str = "x25519") -> bytes:
        """
        Derive shared secret using Diffie-Hellman.

        Args:
            private_key: Your private key
            peer_public_key: Other party's public key
            algorithm: "x25519" (recommended), "ecdh-p256"

        Returns:
            Shared secret (use for symmetric encryption)
        """
        response = self._request("POST", "/v1/crypto/key-exchange/derive", json={
            "private_key": base64.b64encode(private_key).decode("ascii"),
            "peer_public_key": base64.b64encode(peer_public_key).decode("ascii"),
            "algorithm": algorithm,
        })
        return base64.b64decode(response["shared_secret"])

    # ==========================================================================
    # Hybrid Encryption - Encrypt to a public key
    # ==========================================================================

    def hybrid_encrypt(self, plaintext: bytes, recipient_public_key: bytes, algorithm: str = "x25519-aes256gcm") -> bytes:
        """
        Encrypt to a public key (ECIES-style hybrid encryption).

        This is the easiest way to encrypt for a specific recipient:
        - Get their public key
        - Encrypt
        - They decrypt with their private key

        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's public key
            algorithm: "x25519-aes256gcm" (recommended)

        Returns:
            Ciphertext (includes ephemeral public key)
        """
        response = self._request("POST", "/v1/crypto/hybrid/encrypt", json={
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
            "recipient_public_key": base64.b64encode(recipient_public_key).decode("ascii"),
            "algorithm": algorithm,
        })
        return base64.b64decode(response["ciphertext"])

    def hybrid_decrypt(self, ciphertext: bytes, private_key: bytes, algorithm: str = "x25519-aes256gcm") -> bytes:
        """
        Decrypt hybrid-encrypted data.

        Args:
            ciphertext: Encrypted data (from hybrid_encrypt)
            private_key: Your private key

        Returns:
            Decrypted plaintext
        """
        response = self._request("POST", "/v1/crypto/hybrid/decrypt", json={
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "private_key": base64.b64encode(private_key).decode("ascii"),
            "algorithm": algorithm,
        })
        return base64.b64decode(response["plaintext"])

    # ==========================================================================
    # Secret Sharing - Split secrets among multiple parties
    # ==========================================================================

    def split_secret(self, secret: bytes, threshold: int, total_shares: int) -> list[dict]:
        """
        Split a secret using Shamir's Secret Sharing.

        Any `threshold` shares can reconstruct the secret.
        Fewer shares reveal nothing about the secret.

        Example: 3-of-5 split
            shares = client.split_secret(secret, threshold=3, total_shares=5)
            # Give one share to each of 5 custodians
            # Any 3 can reconstruct, 2 reveal nothing

        Args:
            secret: Secret to split
            threshold: Minimum shares needed
            total_shares: Total shares to generate

        Returns:
            List of shares [{"index": 1, "value": bytes}, ...]
        """
        response = self._request("POST", "/v1/secrets/shamir/split", json={
            "secret": base64.b64encode(secret).decode("ascii"),
            "threshold": threshold,
            "total_shares": total_shares,
        })
        return [
            {"index": s["index"], "value": base64.b64decode(s["value"])}
            for s in response["shares"]
        ]

    def combine_shares(self, shares: list[dict]) -> bytes:
        """
        Reconstruct a secret from shares.

        Args:
            shares: List of shares [{"index": 1, "value": bytes}, ...]

        Returns:
            Reconstructed secret
        """
        response = self._request("POST", "/v1/secrets/shamir/combine", json={
            "shares": [
                {"index": s["index"], "value": base64.b64encode(s["value"]).decode("ascii")}
                for s in shares
            ],
        })
        return base64.b64decode(response["secret"])

    # ==========================================================================
    # Leases - Time-limited secrets
    # ==========================================================================

    def create_lease(self, secret: bytes, ttl_seconds: int = 3600, renewable: bool = True) -> dict:
        """
        Create a time-limited lease for a secret.

        The secret automatically expires after TTL.
        Useful for temporary credentials, API keys, etc.

        Args:
            secret: Secret data
            ttl_seconds: Time to live (default: 1 hour)
            renewable: Allow lease renewal

        Returns:
            {"lease_id": "...", "expires_at": "...", "secret": bytes}
        """
        response = self._request("POST", "/v1/secrets/lease/create", json={
            "secret": base64.b64encode(secret).decode("ascii"),
            "ttl_seconds": ttl_seconds,
            "renewable": renewable,
        })
        return {
            "lease_id": response["lease_id"],
            "expires_at": response["expires_at"],
            "secret": base64.b64decode(response["secret"]),
        }

    def get_lease(self, lease_id: str) -> dict:
        """
        Get a secret by lease ID.

        Args:
            lease_id: Lease ID (from create_lease)

        Returns:
            {"lease_id": "...", "secret": bytes, "expires_at": "..."}
        """
        response = self._request("GET", f"/v1/secrets/lease/{lease_id}")
        return {
            "lease_id": response["lease_id"],
            "secret": base64.b64decode(response["secret"]),
            "expires_at": response["expires_at"],
        }

    def renew_lease(self, lease_id: str, increment_seconds: int = 3600) -> dict:
        """
        Renew a lease to extend its TTL.

        Returns:
            Updated lease info
        """
        response = self._request("POST", "/v1/secrets/lease/renew", json={
            "lease_id": lease_id,
            "increment_seconds": increment_seconds,
        })
        return {
            "lease_id": response["lease_id"],
            "expires_at": response["expires_at"],
        }

    def revoke_lease(self, lease_id: str) -> None:
        """
        Revoke a lease immediately.

        The secret becomes inaccessible.
        """
        self._request("POST", "/v1/secrets/lease/revoke", json={
            "lease_id": lease_id,
        })

    # ==========================================================================
    # Binary Scanning - Detect crypto in binaries
    # ==========================================================================

    def scan_binary(self, data: bytes) -> dict:
        """
        Scan binary data for cryptographic content.

        Detects hardcoded keys, S-boxes, weak algorithms, etc.

        Args:
            data: Binary data to scan

        Returns:
            {"findings": [...], "summary": {...}}
        """
        response = self._request("POST", "/v1/discovery/scan", json={
            "data": base64.b64encode(data).decode("ascii"),
        })
        return response

    def quick_scan(self, data: bytes) -> dict:
        """
        Quick check for cryptographic content.

        Returns:
            {"has_crypto": True/False, "risk_level": "...", "algorithms": [...]}
        """
        response = self._request("POST", "/v1/discovery/scan/quick", json={
            "data": base64.b64encode(data).decode("ascii"),
        })
        return response

    # ==========================================================================
    # Code Analysis - Detect crypto in source code (AST-based)
    # ==========================================================================

    def scan_code(self, code: str, language: str | None = None, filename: str | None = None) -> dict:
        """
        Scan source code for cryptographic usage.

        Uses AST analysis for accurate detection of:
        - Algorithm usage (encryption, hashing, signing, KDF)
        - Weak/broken algorithms
        - Quantum vulnerability assessment
        - Library detection

        Args:
            code: Source code to analyze
            language: Language hint (python, javascript, go, java)
            filename: Optional filename for language detection

        Returns:
            {
                "usages": [...],  # All crypto usages found
                "findings": [...],  # Security findings (weak algos, etc)
                "cbom": {...},  # Cryptographic Bill of Materials
            }
        """
        payload = {"code": code}
        if language:
            payload["language"] = language
        if filename:
            payload["filename"] = filename

        return self._request("POST", "/v1/code/scan", json=payload)

    def scan_code_quick(self, code: str, language: str | None = None) -> dict:
        """
        Quick analysis of source code for crypto.

        Fast check ideal for CI/CD pipelines.

        Returns:
            {
                "has_crypto": True/False,
                "algorithms": [...],
                "weak_algorithms": [...],
                "quantum_vulnerable": [...],
                "risk_level": "none/low/medium/high/critical",
                "recommendation": "..."
            }
        """
        payload = {"code": code}
        if language:
            payload["language"] = language

        return self._request("POST", "/v1/code/scan/quick", json=payload)

    def generate_cbom(self, code: str, language: str | None = None, filename: str | None = None) -> dict:
        """
        Generate Cryptographic Bill of Materials (CBOM).

        CBOM provides a complete inventory of crypto usage:
        - All algorithms in use
        - Libraries providing functionality
        - Quantum risk summary
        - Security findings summary

        Use for compliance, auditing, and quantum readiness.

        Returns:
            {
                "version": "1.0",
                "algorithms": [...],
                "libraries": [...],
                "quantum_summary": {...},
                "findings_summary": {...}
            }
        """
        payload = {"code": code}
        if language:
            payload["language"] = language
        if filename:
            payload["filename"] = filename

        return self._request("POST", "/v1/code/cbom", json=payload)

    def get_detectable_algorithms(self) -> dict:
        """
        Get list of all algorithms the scanner can detect.

        Returns dict mapping algorithm names to their properties:
        - category (encryption, hashing, signing, kdf, mac)
        - quantum_risk (none, low, high, critical)
        - is_weak (True/False)
        - weakness_reason (if weak)
        """
        return self._request("GET", "/v1/code/algorithms")

    def get_supported_languages(self) -> list:
        """
        Get list of languages supported for code analysis.

        Returns:
            [{"language": "python", "extensions": [".py"]}, ...]
        """
        return self._request("GET", "/v1/code/languages")

    # ==========================================================================
    # Certificates - PKI operations
    # ==========================================================================

    def generate_csr(
        self,
        common_name: str,
        organization: str | None = None,
        country: str | None = None,
        key_type: str = "ec",
        key_size: int = 256,
        san_domains: list[str] | None = None,
    ) -> dict:
        """
        Generate a Certificate Signing Request (CSR).

        Args:
            common_name: Certificate subject CN
            organization: Organization name
            country: Country code (2 letters)
            key_type: "ec" (recommended), "rsa", or "ed25519"
            key_size: 256/384/521 for EC, 2048-4096 for RSA
            san_domains: Subject Alternative Name domains

        Returns:
            {
                "csr_pem": "...",
                "private_key_pem": "...",  # KEEP SECRET!
                "public_key_pem": "...",
            }
        """
        return self._request("POST", "/v1/certificates/csr/generate", json={
            "subject": {
                "common_name": common_name,
                "organization": organization,
                "country": country,
            },
            "key_type": key_type,
            "key_size": key_size,
            "san_domains": san_domains,
        })

    def generate_self_signed_cert(
        self,
        common_name: str,
        organization: str | None = None,
        country: str | None = None,
        validity_days: int = 365,
        is_ca: bool = False,
        san_domains: list[str] | None = None,
    ) -> dict:
        """
        Generate a self-signed certificate.

        Useful for development, testing, or internal PKI root CAs.

        Returns:
            {"certificate_pem": "...", "private_key_pem": "..."}
        """
        return self._request("POST", "/v1/certificates/self-signed/generate", json={
            "subject": {
                "common_name": common_name,
                "organization": organization,
                "country": country,
            },
            "validity_days": validity_days,
            "is_ca": is_ca,
            "san_domains": san_domains,
        })

    def parse_certificate(self, certificate_pem: str) -> dict:
        """
        Parse a certificate and extract its information.

        Returns detailed info: subject, issuer, validity, key usage, SANs, etc.
        """
        return self._request("POST", "/v1/certificates/parse", json={
            "certificate": certificate_pem,
        })

    def verify_certificate(
        self,
        certificate_pem: str,
        issuer_certificate_pem: str | None = None,
        check_expiry: bool = True,
    ) -> dict:
        """
        Verify a certificate.

        Args:
            certificate_pem: Certificate to verify
            issuer_certificate_pem: Issuer cert (for signature verification)
            check_expiry: Whether to check expiration

        Returns:
            {"valid": True/False, "errors": [...], "warnings": [...]}
        """
        return self._request("POST", "/v1/certificates/verify", json={
            "certificate": certificate_pem,
            "issuer_certificate": issuer_certificate_pem,
            "check_expiry": check_expiry,
        })

    def verify_certificate_chain(self, certificates: list[str], check_expiry: bool = True) -> dict:
        """
        Verify a certificate chain.

        Args:
            certificates: List of PEM certs [leaf, intermediate(s), root]
            check_expiry: Whether to check expiration

        Returns:
            {"valid": True/False, "errors": [...], "chain_length": int}
        """
        return self._request("POST", "/v1/certificates/verify-chain", json={
            "certificates": certificates,
            "check_expiry": check_expiry,
        })

    # ==========================================================================
    # Dependency Scanning - Detect crypto in package files
    # ==========================================================================

    def scan_dependencies(self, content: str, filename: str | None = None) -> dict:
        """
        Scan a package file for cryptographic dependencies.

        Supports: package.json, requirements.txt, go.mod, Cargo.toml

        Args:
            content: File content
            filename: Filename for auto-detection

        Returns:
            {
                "dependencies": [...],  # Crypto deps found
                "crypto_packages": int,
                "quantum_vulnerable_count": int,
                "deprecated_count": int,
                "recommendations": [...]
            }
        """
        return self._request("POST", "/v1/dependencies/scan", json={
            "content": content,
            "filename": filename,
        })

    def scan_dependencies_quick(self, content: str, filename: str | None = None) -> dict:
        """
        Quick scan for crypto dependencies.

        Returns:
            {
                "has_crypto": True/False,
                "crypto_count": int,
                "quantum_vulnerable": True/False,
                "deprecated_present": True/False,
                "risk_level": "none/low/medium/high",
                "recommendation": "..."
            }
        """
        return self._request("POST", "/v1/dependencies/scan/quick", json={
            "content": content,
            "filename": filename,
        })

    def get_known_packages(self, package_type: str | None = None) -> dict:
        """
        Get list of known crypto packages.

        Args:
            package_type: Filter by type (npm, pypi, go, cargo)

        Returns dict of ecosystems to package lists.
        """
        params = {}
        if package_type:
            params["package_type"] = package_type
        return self._request("GET", "/v1/dependencies/known-packages", params=params)

    # ==========================================================================
    # Batch Operations - Process multiple items efficiently
    # ==========================================================================

    def encrypt_batch(
        self,
        items: list[tuple[bytes, str]],
        stop_on_error: bool = False,
    ) -> BatchResult[bytes]:
        """
        Encrypt multiple items in a batch.

        More efficient than individual calls for bulk operations.

        Args:
            items: List of (plaintext, context) tuples
            stop_on_error: Stop processing on first error

        Returns:
            BatchResult with encrypted data for each item

        Example:
            items = [
                (b"secret1", "user-pii"),
                (b"secret2", "user-pii"),
                (b"secret3", "payment-data"),
            ]
            result = client.encrypt_batch(items)
            if result.all_succeeded:
                ciphertexts = result.results()
        """
        def encrypt_item(item: tuple[bytes, str]) -> bytes:
            plaintext, context = item
            return self.encrypt(plaintext, context)

        processor = BatchProcessor(
            process_func=encrypt_item,
            retry_config=self._retry_config,
            stop_on_error=stop_on_error,
        )
        return processor.process(items)

    def decrypt_batch(
        self,
        items: list[tuple[bytes, str]],
        stop_on_error: bool = False,
    ) -> BatchResult[bytes]:
        """
        Decrypt multiple items in a batch.

        Args:
            items: List of (ciphertext, context) tuples
            stop_on_error: Stop processing on first error

        Returns:
            BatchResult with decrypted data for each item
        """
        def decrypt_item(item: tuple[bytes, str]) -> bytes:
            ciphertext, context = item
            return self.decrypt(ciphertext, context)

        processor = BatchProcessor(
            process_func=decrypt_item,
            retry_config=self._retry_config,
            stop_on_error=stop_on_error,
        )
        return processor.process(items)

    def hash_batch(
        self,
        items: list[bytes],
        algorithm: str = "sha256",
        stop_on_error: bool = False,
    ) -> BatchResult[str]:
        """
        Hash multiple items in a batch.

        Args:
            items: List of data to hash
            algorithm: Hash algorithm
            stop_on_error: Stop processing on first error

        Returns:
            BatchResult with hex hashes for each item
        """
        def hash_item(data: bytes) -> str:
            return self.hash(data, algorithm)

        processor = BatchProcessor(
            process_func=hash_item,
            retry_config=self._retry_config,
            stop_on_error=stop_on_error,
        )
        return processor.process(items)

    # ==========================================================================
    # Utilities
    # ==========================================================================

    def get_identity_info(self) -> dict:
        """Get information about your identity."""
        return self._request("GET", f"/sdk/info/{self.token}")

    def list_contexts(self) -> list[dict]:
        """List available crypto contexts."""
        info = self.get_identity_info()
        return info.get("allowed_contexts", [])

    def health_check(self) -> dict:
        """Check server health."""
        response = self._session.get(f"{self.server_url}/health", timeout=self.timeout)
        return response.json()

    # ==========================================================================
    # Internal
    # ==========================================================================

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make authenticated request with auto-refresh and resilience support."""
        # Auto-refresh token if needed
        self._ensure_valid_token()
        kwargs.setdefault("timeout", self.timeout)

        def make_request():
            response = self._session.request(method, f"{self.server_url}{path}", **kwargs)

            # Handle 401 with retry after refresh
            if response.status_code == 401 and self._try_refresh_and_retry():
                response = self._session.request(method, f"{self.server_url}{path}", **kwargs)

            return self._handle_response(response, path)

        # Apply resilience patterns
        if self._circuit_breaker:
            try:
                if self._retry_config:
                    return self._circuit_breaker.execute(
                        lambda: self._with_retry(make_request)
                    )
                else:
                    return self._circuit_breaker.execute(make_request)
            except CircuitOpenError:
                raise
        elif self._retry_config:
            return self._with_retry(make_request)
        else:
            return make_request()

    def _with_retry(self, func: Callable) -> Any:
        """Execute function with retry logic."""
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

    def _handle_response(self, response: requests.Response, path: str) -> dict:
        """Handle API response."""
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

    def close(self):
        """Close the client session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
