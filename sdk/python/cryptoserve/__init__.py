"""
CryptoServe SDK - Zero-config cryptographic operations with auto-registration.

NEW in v0.6.0 - Auto-registration (Recommended):
    from cryptoserve import CryptoServe

    # One-time setup: run `cryptoserve login` in terminal

    # Initialize - app is auto-registered on first use
    crypto = CryptoServe(
        app_name="my-service",
        team="platform",
        environment="development"
    )

    # Use immediately - no dashboard setup needed!
    encrypted = crypto.encrypt(b"sensitive data", context="user-pii")
    decrypted = crypto.decrypt(encrypted, context="user-pii")

Legacy Usage (still supported):
    from cryptoserve import crypto

    # Requires CRYPTOSERVE_TOKEN environment variable
    ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")
    plaintext = crypto.decrypt(ciphertext, context="user-pii")

    # String helpers
    encrypted = crypto.encrypt_string("my secret", context="user-pii")
    decrypted = crypto.decrypt_string(encrypted, context="user-pii")

    # Verify SDK is working
    result = crypto.verify()
    print(result.status)  # "healthy" or "error"

    # Enable mock mode for local testing (no server needed)
    crypto.enable_mock_mode()

Package Architecture:
    cryptoserve         - Full SDK (this package)
    cryptoserve-core    - Pure crypto primitives (no network)
    cryptoserve-client  - API client only
    cryptoserve-auto    - Auto-protect for third-party libraries
"""

# Re-export from sub-packages for convenience
from cryptoserve_client import CryptoClient
from cryptoserve_client.errors import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    TokenRefreshError,
)
from cryptoserve._identity import IDENTITY, AUTO_REFRESH_ENABLED, get_refresh_token

# New in 0.6.0: Auto-registration CryptoServe class
from cryptoserve._auto_register import (
    CryptoServe,
    CryptoServeNotLoggedInError,
    CryptoServeRegistrationError,
)

__version__ = "0.6.0"
__all__ = [
    # New in 0.6.0: Auto-registration SDK class
    "CryptoServe",
    "CryptoServeNotLoggedInError",
    "CryptoServeRegistrationError",
    # Legacy interface (still works)
    "crypto",
    "init",
    "InitResult",
    "get_init_status",
    "CryptoClient",
    "VerifyResult",
    "CryptoServeError",
    "AuthenticationError",
    "AuthorizationError",
    "ContextNotFoundError",
    "TokenRefreshError",
    "auto_protect",
    # CBOM and PQC recommendations
    "export_cbom",
    "get_pqc_recommendations",
    "CBOMResult",
    "PQCRecommendationResult",
]

# New in 0.4.0: crypto class now exposes hash, mac, sign, verify_signature,
# hash_password, verify_password, check_password_strength, split_secret,
# combine_shares, generate_signing_key, generate_mac_key


# Lazy import for auto_protect (optional dependency)
def auto_protect(**kwargs):
    """
    Enable auto-protection for third-party libraries.

    Requires: pip install cryptoserve[auto]

    Example:
        from cryptoserve import auto_protect
        auto_protect(encryption_key=key)
    """
    try:
        from cryptoserve_auto import protect
        return protect(**kwargs)
    except ImportError:
        raise ImportError(
            "cryptoserve-auto is not installed. "
            "Install with: pip install cryptoserve[auto]"
        )

# Create singleton client
_client = None
_mock_mode = False
_mock_storage: dict[str, bytes] = {}  # Context -> fake "encrypted" data mapping


class VerifyResult:
    """Result of SDK health verification."""

    def __init__(
        self,
        status: str,
        server_reachable: bool = False,
        token_valid: bool = False,
        encrypt_works: bool = False,
        decrypt_works: bool = False,
        latency_ms: float = 0,
        identity_name: str = "",
        allowed_contexts: list[str] = None,
        error: str = None,
    ):
        self.status = status  # "healthy", "degraded", "error"
        self.server_reachable = server_reachable
        self.token_valid = token_valid
        self.encrypt_works = encrypt_works
        self.decrypt_works = decrypt_works
        self.latency_ms = latency_ms
        self.identity_name = identity_name
        self.allowed_contexts = allowed_contexts or []
        self.error = error

    def __repr__(self):
        if self.status == "healthy":
            return f"VerifyResult(status='healthy', identity='{self.identity_name}', latency={self.latency_ms:.0f}ms)"
        return f"VerifyResult(status='{self.status}', error='{self.error}')"

    def __bool__(self):
        """Allow using result in boolean context: if crypto.verify(): ..."""
        return self.status == "healthy"


def _get_client() -> CryptoClient:
    """Get or create the singleton client."""
    global _client
    if _client is None:
        _client = CryptoClient(
            server_url=IDENTITY["server_url"],
            token=IDENTITY["token"],
            refresh_token=get_refresh_token(),
            auto_refresh=AUTO_REFRESH_ENABLED,
        )
    return _client


def _is_mock_mode() -> bool:
    """Check if mock mode is enabled."""
    return _mock_mode


class crypto:
    """
    Main interface for CryptoServe.

    This class provides a simple, zero-config interface for cryptographic
    operations. The SDK comes pre-configured with your identity, so you
    can use it immediately after installation.

    Usage:
        from cryptoserve import crypto

        # Encrypt bytes
        ciphertext = crypto.encrypt(b"data", context="user-pii")

        # Decrypt bytes
        plaintext = crypto.decrypt(ciphertext, context="user-pii")

        # Encrypt string (returns base64)
        encrypted = crypto.encrypt_string("secret", context="user-pii")

        # Decrypt base64 string
        decrypted = crypto.decrypt_string(encrypted, context="user-pii")
    """

    @classmethod
    def verify(cls) -> VerifyResult:
        """
        Verify the SDK is working correctly.

        Performs a comprehensive health check:
        1. Checks if server is reachable
        2. Validates identity token
        3. Tests encrypt/decrypt round-trip

        Returns:
            VerifyResult with status and diagnostic info

        Example:
            result = crypto.verify()
            if result:
                print(f"SDK healthy! Identity: {result.identity_name}")
            else:
                print(f"SDK error: {result.error}")
        """
        import time

        if _is_mock_mode():
            return VerifyResult(
                status="healthy",
                server_reachable=True,
                token_valid=True,
                encrypt_works=True,
                decrypt_works=True,
                latency_ms=0,
                identity_name=IDENTITY.get("name", "mock-identity"),
                allowed_contexts=IDENTITY.get("allowed_contexts", ["*"]),
                error=None,
            )

        start_time = time.time()

        # Step 1: Check server reachability
        try:
            import requests
            response = requests.get(
                f"{IDENTITY['server_url']}/health",
                timeout=5,
            )
            server_reachable = response.status_code == 200
        except Exception as e:
            return VerifyResult(
                status="error",
                server_reachable=False,
                error=f"Server unreachable: {str(e)}",
            )

        # Step 2: Validate token by fetching identity info
        try:
            response = requests.get(
                f"{IDENTITY['server_url']}/sdk/info/{IDENTITY['token']}",
                timeout=5,
            )
            if response.status_code != 200:
                return VerifyResult(
                    status="error",
                    server_reachable=True,
                    token_valid=False,
                    error="Invalid or expired token",
                )
            identity_info = response.json()
            token_valid = True
        except Exception as e:
            return VerifyResult(
                status="error",
                server_reachable=True,
                token_valid=False,
                error=f"Token validation failed: {str(e)}",
            )

        # Step 3: Test encrypt/decrypt round-trip
        test_data = b"cryptoserve-health-check"
        encrypt_works = False
        decrypt_works = False

        allowed_contexts = identity_info.get("allowed_contexts", [])
        if allowed_contexts:
            test_context = allowed_contexts[0]
            try:
                ciphertext = cls.encrypt(test_data, test_context)
                encrypt_works = True

                plaintext = cls.decrypt(ciphertext, test_context)
                decrypt_works = plaintext == test_data
            except Exception:
                # Encryption test failed, but server and token are working
                pass

        latency_ms = (time.time() - start_time) * 1000

        # Determine overall status
        if encrypt_works and decrypt_works:
            status = "healthy"
        elif token_valid and server_reachable:
            status = "degraded"  # Token works but crypto test failed
        else:
            status = "error"

        return VerifyResult(
            status=status,
            server_reachable=server_reachable,
            token_valid=token_valid,
            encrypt_works=encrypt_works,
            decrypt_works=decrypt_works,
            latency_ms=latency_ms,
            identity_name=identity_info.get("name", ""),
            allowed_contexts=allowed_contexts,
            error=None if status == "healthy" else "Crypto test failed",
        )

    @classmethod
    def enable_mock_mode(cls):
        """
        Enable mock mode for local development/testing.

        In mock mode:
        - No server connection required
        - Encryption uses local reversible encoding
        - All contexts are allowed
        - Perfect for unit tests and offline development

        Example:
            crypto.enable_mock_mode()
            encrypted = crypto.encrypt(b"test", context="any-context")
            decrypted = crypto.decrypt(encrypted, context="any-context")
            assert decrypted == b"test"
        """
        global _mock_mode
        _mock_mode = True

    @classmethod
    def disable_mock_mode(cls):
        """Disable mock mode and use real server."""
        global _mock_mode, _mock_storage
        _mock_mode = False
        _mock_storage.clear()

    @classmethod
    def is_mock_mode(cls) -> bool:
        """Check if mock mode is enabled."""
        return _is_mock_mode()

    @classmethod
    def encrypt(cls, plaintext: bytes | str, context: str) -> bytes:
        """
        Encrypt data.

        Args:
            plaintext: Data to encrypt (bytes or string)
            context: Crypto context (e.g., "user-pii", "payment-data")

        Returns:
            Encrypted ciphertext as bytes

        Raises:
            AuthenticationError: If identity token is invalid
            AuthorizationError: If not authorized for context
            ContextNotFoundError: If context doesn't exist
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        if _is_mock_mode():
            # Mock encryption: prefix with context and base64
            import base64
            mock_ciphertext = f"MOCK:{context}:".encode() + base64.b64encode(plaintext)
            return mock_ciphertext

        return _get_client().encrypt(plaintext, context)

    @classmethod
    def decrypt(cls, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data.

        Args:
            ciphertext: Encrypted data from crypto.encrypt()
            context: Crypto context used for encryption

        Returns:
            Decrypted plaintext as bytes

        Raises:
            AuthenticationError: If identity token is invalid
            AuthorizationError: If not authorized for context
            CryptoServeError: If decryption fails
        """
        if _is_mock_mode():
            # Mock decryption: reverse the mock encoding
            import base64

            if not ciphertext.startswith(b"MOCK:"):
                raise CryptoServeError("Invalid mock ciphertext format")

            # Parse MOCK:context:base64data
            parts = ciphertext.split(b":", 2)
            if len(parts) != 3:
                raise CryptoServeError("Invalid mock ciphertext format")

            stored_context = parts[1].decode()
            if stored_context != context:
                raise CryptoServeError(
                    f"Context mismatch: encrypted with '{stored_context}', "
                    f"decrypting with '{context}'"
                )

            return base64.b64decode(parts[2])

        return _get_client().decrypt(ciphertext, context)

    @classmethod
    def encrypt_string(cls, plaintext: str, context: str) -> str:
        """
        Encrypt a string and return base64-encoded ciphertext.

        Convenient for storing encrypted data in databases or JSON.

        Args:
            plaintext: String to encrypt
            context: Crypto context

        Returns:
            Base64-encoded ciphertext
        """
        import base64
        ciphertext = cls.encrypt(plaintext.encode("utf-8"), context)
        return base64.b64encode(ciphertext).decode("ascii")

    @classmethod
    def decrypt_string(cls, ciphertext_b64: str, context: str) -> str:
        """
        Decrypt a base64-encoded ciphertext to string.

        Args:
            ciphertext_b64: Base64-encoded ciphertext from encrypt_string()
            context: Crypto context used for encryption

        Returns:
            Decrypted plaintext as string
        """
        import base64
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cls.decrypt(ciphertext, context)
        return plaintext.decode("utf-8")

    @classmethod
    def get_identity(cls) -> dict:
        """
        Get current identity information.

        Returns:
            Dict with identity_id, name, team, environment, allowed_contexts
        """
        return {
            "identity_id": IDENTITY["identity_id"],
            "name": IDENTITY["name"],
            "team": IDENTITY["team"],
            "environment": IDENTITY["environment"],
            "allowed_contexts": IDENTITY["allowed_contexts"],
        }

    @classmethod
    def context_info(cls, context: str) -> dict:
        """
        Get detailed information about a crypto context.

        Args:
            context: Context name (e.g., "user-pii", "payment-data")

        Returns:
            Dict with algorithm, speed, overhead, quantum_resistant, compliance

        Example:
            info = crypto.context_info("user-pii")
            print(info["algorithm"])      # "AES-256-GCM"
            print(info["speed"])          # "fast"
            print(info["overhead_bytes"]) # 28
            print(info["quantum_safe"])   # False
        """
        if _is_mock_mode():
            return {
                "name": context,
                "algorithm": "AES-256-GCM",
                "speed": "fast",
                "overhead_bytes": 28,  # 12 nonce + 16 tag
                "quantum_safe": False,
                "compliance": ["SOC2"],
            }

        import requests
        response = requests.get(
            f"{IDENTITY['server_url']}/sdk/contexts/{context}",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            raise ContextNotFoundError(f"Context '{context}' not found")
        else:
            raise CryptoServeError(f"Failed to get context info: {response.text}")

    @classmethod
    def list_contexts(cls) -> list[dict]:
        """
        List all contexts available to this identity.

        Returns:
            List of context info dicts

        Example:
            for ctx in crypto.list_contexts():
                print(f"{ctx['name']}: {ctx['algorithm']}")
        """
        if _is_mock_mode():
            return [{"name": c, "algorithm": "AES-256-GCM"} for c in IDENTITY.get("allowed_contexts", ["*"])]

        import requests
        response = requests.get(
            f"{IDENTITY['server_url']}/sdk/contexts",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise CryptoServeError(f"Failed to list contexts: {response.text}")

    # =========================================================================
    # Advanced Cryptographic Operations
    # =========================================================================

    @classmethod
    def hash(cls, data: bytes | str, algorithm: str = "sha256") -> dict:
        """
        Compute a cryptographic hash.

        Args:
            data: Data to hash (bytes or string)
            algorithm: Hash algorithm (sha256, sha384, sha512, sha3-256,
                      sha3-512, blake2b, blake2s, blake3)

        Returns:
            Dict with digest (base64), hex, algorithm, length_bits

        Example:
            result = crypto.hash(b"hello world", algorithm="sha256")
            print(result["hex"])  # SHA-256 hash in hex
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if _is_mock_mode():
            import hashlib
            import base64
            h = hashlib.sha256(data)
            return {
                "digest": base64.b64encode(h.digest()).decode(),
                "hex": h.hexdigest(),
                "algorithm": algorithm,
                "length_bits": 256,
            }

        return _get_client().hash(data, algorithm)

    @classmethod
    def mac(cls, data: bytes | str, key: bytes, algorithm: str = "hmac-sha256") -> dict:
        """
        Compute a Message Authentication Code.

        Args:
            data: Data to authenticate (bytes or string)
            key: Secret key (bytes)
            algorithm: MAC algorithm (hmac-sha256, hmac-sha512, kmac128, kmac256)

        Returns:
            Dict with tag (base64), hex, algorithm, length_bits

        Example:
            key = crypto.generate_mac_key()
            result = crypto.mac(b"message", key, algorithm="hmac-sha256")
            print(result["hex"])
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if _is_mock_mode():
            import hmac
            import hashlib
            import base64
            h = hmac.new(key, data, hashlib.sha256)
            return {
                "tag": base64.b64encode(h.digest()).decode(),
                "hex": h.hexdigest(),
                "algorithm": algorithm,
                "length_bits": 256,
            }

        return _get_client().mac(data, key, algorithm)

    @classmethod
    def generate_mac_key(cls, algorithm: str = "hmac-sha256") -> bytes:
        """
        Generate a random key for MAC operations.

        Args:
            algorithm: MAC algorithm to generate key for

        Returns:
            Random key bytes (32 bytes for SHA-256 based MACs)
        """
        if _is_mock_mode():
            import os
            return os.urandom(32)

        return _get_client().generate_mac_key(algorithm)

    @classmethod
    def hash_password(cls, password: str, algorithm: str = "argon2id") -> str:
        """
        Hash a password securely.

        Args:
            password: Password to hash
            algorithm: Password hashing algorithm (argon2id, bcrypt, scrypt)

        Returns:
            Password hash in PHC format

        Example:
            hash = crypto.hash_password("my-secret-password")
            # Store hash in database
        """
        if _is_mock_mode():
            import base64
            import hashlib
            # Mock: use simple hash (NOT secure, only for testing)
            h = hashlib.sha256(password.encode()).hexdigest()[:32]
            return f"$mock$v=1${h}"

        result = _get_client().hash_password(password, algorithm)
        return result["hash"]

    @classmethod
    def verify_password(cls, password: str, hash: str) -> bool:
        """
        Verify a password against a hash.

        Args:
            password: Password to verify
            hash: Password hash from hash_password()

        Returns:
            True if password matches, False otherwise

        Example:
            if crypto.verify_password("user-input", stored_hash):
                print("Password correct!")
        """
        if _is_mock_mode():
            import hashlib
            h = hashlib.sha256(password.encode()).hexdigest()[:32]
            return hash == f"$mock$v=1${h}"

        result = _get_client().verify_password(password, hash)
        return result["valid"]

    @classmethod
    def check_password_strength(cls, password: str) -> dict:
        """
        Check password strength.

        Args:
            password: Password to analyze

        Returns:
            Dict with score (0-100), strength, entropy_bits, suggestions

        Example:
            result = crypto.check_password_strength("password123")
            print(f"Strength: {result['strength']}")  # "weak"
            print(result['suggestions'])  # ["Add special characters", ...]
        """
        if _is_mock_mode():
            score = min(len(password) * 8, 100)
            return {
                "score": score,
                "strength": "weak" if score < 40 else "fair" if score < 60 else "good" if score < 80 else "strong",
                "length": len(password),
                "entropy_bits": len(password) * 4,
                "suggestions": [] if score > 60 else ["Use a longer password"],
            }

        return _get_client().check_password_strength(password)

    @classmethod
    def split_secret(cls, secret: bytes | str, threshold: int, total_shares: int) -> list[dict]:
        """
        Split a secret using Shamir Secret Sharing.

        Any `threshold` shares can reconstruct the secret, but fewer
        shares reveal nothing about the original secret.

        Args:
            secret: Secret to split (bytes or string)
            threshold: Minimum shares needed to reconstruct (2-255)
            total_shares: Total shares to generate (2-255)

        Returns:
            List of shares, each with index and value

        Example:
            shares = crypto.split_secret(b"master-key", threshold=3, total_shares=5)
            # Distribute shares to 5 custodians
            # Any 3 can reconstruct the key
        """
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        if _is_mock_mode():
            import base64
            # Mock: just split the secret bytes (NOT real Shamir)
            return [
                {"index": i + 1, "value": base64.b64encode(secret).decode()}
                for i in range(total_shares)
            ]

        return _get_client().split_secret(secret, threshold, total_shares)

    @classmethod
    def combine_shares(cls, shares: list[dict]) -> bytes:
        """
        Reconstruct a secret from Shamir shares.

        Args:
            shares: List of shares from split_secret() (at least threshold)

        Returns:
            Reconstructed secret bytes

        Example:
            # Collect threshold shares from custodians
            collected_shares = [shares[0], shares[2], shares[4]]
            secret = crypto.combine_shares(collected_shares)
        """
        if _is_mock_mode():
            import base64
            # Mock: all shares have the same value
            return base64.b64decode(shares[0]["value"])

        return _get_client().combine_shares(shares)

    @classmethod
    def sign(cls, data: bytes | str, key_id: str) -> bytes:
        """
        Sign data with a signing key.

        Args:
            data: Data to sign (bytes or string)
            key_id: ID of the signing key

        Returns:
            Signature bytes

        Example:
            key = crypto.generate_signing_key()
            signature = crypto.sign(b"document", key["key_id"])
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if _is_mock_mode():
            import hashlib
            # Mock signature: hash of data + key_id
            return hashlib.sha256(data + key_id.encode()).digest()

        return _get_client().sign(data, key_id)

    @classmethod
    def verify_signature(cls, data: bytes | str, signature: bytes, key_id: str = None, public_key: str = None) -> bool:
        """
        Verify a signature.

        Args:
            data: Original signed data
            signature: Signature from sign()
            key_id: ID of signing key (if using server-managed keys)
            public_key: Public key PEM (if verifying external signature)

        Returns:
            True if signature is valid, False otherwise

        Example:
            is_valid = crypto.verify_signature(b"document", signature, key_id=key["key_id"])
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if _is_mock_mode():
            import hashlib
            expected = hashlib.sha256(data + (key_id or "").encode()).digest()
            return signature == expected

        return _get_client().verify(data, signature, key_id, public_key)

    @classmethod
    def generate_signing_key(cls, algorithm: str = "ed25519") -> dict:
        """
        Generate a new signing key pair.

        Args:
            algorithm: Signature algorithm (ed25519, ecdsa-p256)

        Returns:
            Dict with key_id, algorithm, public_key_jwk, public_key_pem

        Example:
            key = crypto.generate_signing_key()
            print(f"Key ID: {key['key_id']}")
            print(f"Public Key: {key['public_key_pem']}")
        """
        if _is_mock_mode():
            import uuid
            return {
                "key_id": str(uuid.uuid4()),
                "algorithm": algorithm,
                "public_key_jwk": {"kty": "OKP", "crv": "Ed25519"},
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----",
            }

        return _get_client().generate_signing_key(algorithm)


# =============================================================================
# SDK Initialization with Inventory & Secret Scanning
# =============================================================================

# Global state for initialization
_initialized = False
_init_config: dict = {}


class InitConfig:
    """Configuration for SDK initialization."""

    def __init__(
        self,
        scan_crypto: bool = True,
        report_to_platform: bool = True,
        block_on_violations: bool = False,
        async_reporting: bool = True,
    ):
        """
        Configure SDK initialization behavior.

        Args:
            scan_crypto: Detect crypto libraries from sys.modules (100% accurate)
            report_to_platform: Send inventory report to platform
            block_on_violations: Raise exception if policy violations found
            async_reporting: Report asynchronously (non-blocking)
        """
        self.scan_crypto = scan_crypto
        self.report_to_platform = report_to_platform
        self.block_on_violations = block_on_violations
        self.async_reporting = async_reporting


class InitResult:
    """Result of SDK initialization with crypto detection."""

    def __init__(
        self,
        success: bool,
        libraries: list[dict] | None = None,
        violations: list[dict] | None = None,
        warnings: list[dict] | None = None,
        action: str = "allow",
        error: str | None = None,
    ):
        self.success = success
        self.libraries = libraries or []
        self.violations = violations or []
        self.warnings = warnings or []
        self.action = action  # allow, warn, block
        self.error = error

    @property
    def algorithms(self) -> list[str]:
        """All algorithms available from detected libraries."""
        algos = []
        for lib in self.libraries:
            algos.extend(lib.get("algorithms", []))
        return list(set(algos))

    @property
    def quantum_vulnerable(self) -> list[dict]:
        """Libraries with quantum vulnerability."""
        return [lib for lib in self.libraries if lib.get("quantum_risk") in ["high", "critical"]]

    @property
    def deprecated(self) -> list[dict]:
        """Deprecated libraries that should be replaced."""
        return [lib for lib in self.libraries if lib.get("is_deprecated")]

    def __bool__(self):
        return self.success and self.action != "block"

    def __repr__(self):
        if self.success:
            return f"InitResult(libraries={len(self.libraries)}, algorithms={len(self.algorithms)}, action='{self.action}')"
        return f"InitResult(success=False, error='{self.error}')"


def init(
    scan_crypto: bool = True,
    report_to_platform: bool = True,
    block_on_violations: bool = False,
    async_reporting: bool = True,
) -> InitResult:
    """
    Initialize the CryptoServe SDK with crypto library detection.

    This function should be called once at application startup. It detects
    all cryptographic libraries loaded in the application with 100% accuracy
    by examining sys.modules at runtime.

    Args:
        scan_crypto: Detect imported crypto libraries from sys.modules.
            100% accurate - only reports what's actually loaded.
            Zero runtime overhead - runs once at startup.
            Default: True

        report_to_platform: Send inventory to platform for policy evaluation.
            Default: True

        block_on_violations: If True, raises CryptoServeError on policy violations.
            Useful for enforcing security policies in production.

        async_reporting: Send reports asynchronously (non-blocking).
            Default: True for minimal startup impact.

    Returns:
        InitResult with detected libraries and policy evaluation.

    Example:
        from cryptoserve import init

        # Detect crypto libraries at startup
        result = init()
        print(f"Detected {len(result.libraries)} crypto libraries")
        for lib in result.libraries:
            print(f"  - {lib['name']}: {lib['algorithms']}")

        # With policy enforcement
        result = init(block_on_violations=True)
        if not result:
            print(f"Blocked: {result.violations}")
            sys.exit(1)
    """
    global _initialized, _init_config

    if _initialized:
        # Already initialized, return cached result
        return InitResult(
            success=True,
            libraries=_init_config.get("libraries", []),
            violations=_init_config.get("violations", []),
            warnings=_init_config.get("warnings", []),
            action=_init_config.get("action", "allow"),
        )

    libraries = []
    violations = []
    warnings = []
    action = "allow"

    try:
        # Step 1: Detect crypto libraries from sys.modules (100% accurate)
        if scan_crypto:
            libraries = _scan_crypto_imports()

        # Step 2: Report to platform and get policy evaluation
        if report_to_platform and libraries:
            if async_reporting:
                import threading
                thread = threading.Thread(
                    target=_report_inventory_async,
                    args=(libraries,),
                    daemon=True,
                )
                thread.start()
                # Don't wait for response in async mode
            else:
                result = _report_inventory_sync(libraries)
                violations = result.get("violations", [])
                warnings = result.get("warnings", [])
                action = result.get("action", "allow")

        # Step 3: Check for blocking violations
        if block_on_violations and action == "block":
            raise CryptoServeError(
                f"SDK initialization blocked by policy: {len(violations)} violation(s) found",
                status_code=403,
            )

        _initialized = True
        _init_config = {
            "libraries": libraries,
            "violations": violations,
            "warnings": warnings,
            "action": action,
        }

        return InitResult(
            success=True,
            libraries=libraries,
            violations=violations,
            warnings=warnings,
            action=action,
        )

    except CryptoServeError:
        raise
    except Exception as e:
        return InitResult(success=False, error=str(e))


def _scan_crypto_imports() -> list[dict]:
    """
    Scan sys.modules for imported crypto libraries.

    This is designed to run once at startup with minimal overhead.
    Only examines already-loaded modules, no file I/O.
    """
    import sys

    # Known crypto library patterns
    CRYPTO_LIBRARIES = {
        "cryptography": {
            "category": "general",
            "algorithms": ["AES", "ChaCha20", "RSA", "ECDSA", "Ed25519", "SHA-256"],
            "quantum_risk": "high",
        },
        "pycryptodome": {
            "category": "general",
            "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5"],
            "quantum_risk": "high",
        },
        "Cryptodome": {
            "category": "general",
            "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5"],
            "quantum_risk": "high",
        },
        "nacl": {
            "category": "general",
            "algorithms": ["Curve25519", "Ed25519", "XSalsa20", "Poly1305"],
            "quantum_risk": "high",
        },
        "hashlib": {
            "category": "hashing",
            "algorithms": ["SHA-256", "SHA-512", "SHA-1", "MD5", "SHA3-256", "Blake2b"],
            "quantum_risk": "low",
        },
        "hmac": {
            "category": "mac",
            "algorithms": ["HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA1"],
            "quantum_risk": "low",
        },
        "secrets": {
            "category": "random",
            "algorithms": ["CSPRNG"],
            "quantum_risk": "none",
        },
        "bcrypt": {
            "category": "kdf",
            "algorithms": ["bcrypt"],
            "quantum_risk": "none",
        },
        "argon2": {
            "category": "kdf",
            "algorithms": ["Argon2id", "Argon2i", "Argon2d"],
            "quantum_risk": "none",
        },
        "passlib": {
            "category": "kdf",
            "algorithms": ["bcrypt", "Argon2", "PBKDF2", "scrypt"],
            "quantum_risk": "none",
        },
        "jwt": {
            "category": "token",
            "algorithms": ["HS256", "RS256", "ES256", "EdDSA"],
            "quantum_risk": "high",
        },
        "jose": {
            "category": "token",
            "algorithms": ["JWS", "JWE", "JWK"],
            "quantum_risk": "high",
        },
        "ssl": {
            "category": "tls",
            "algorithms": ["TLS", "RSA", "ECDHE", "AES-GCM"],
            "quantum_risk": "high",
        },
        "OpenSSL": {
            "category": "tls",
            "algorithms": ["TLS", "AES", "RSA", "ECDSA"],
            "quantum_risk": "high",
        },
        "oqs": {
            "category": "pqc",
            "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
            "quantum_risk": "none",
        },
        "liboqs": {
            "category": "pqc",
            "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
            "quantum_risk": "none",
        },
        # Deprecated
        "Crypto": {
            "category": "general",
            "algorithms": ["AES", "DES", "RSA"],
            "quantum_risk": "high",
            "is_deprecated": True,
            "deprecation_reason": "PyCrypto is unmaintained since 2013",
        },
    }

    detected = []
    seen = set()

    for module_name in list(sys.modules.keys()):
        for lib_pattern, lib_info in CRYPTO_LIBRARIES.items():
            if module_name == lib_pattern or module_name.startswith(f"{lib_pattern}."):
                if lib_pattern not in seen:
                    seen.add(lib_pattern)

                    # Get version
                    version = None
                    module = sys.modules.get(module_name)
                    if module:
                        version = getattr(module, "__version__", None)

                    detected.append({
                        "name": lib_pattern,
                        "version": version,
                        "category": lib_info["category"],
                        "algorithms": lib_info["algorithms"],
                        "quantum_risk": lib_info["quantum_risk"],
                        "is_deprecated": lib_info.get("is_deprecated", False),
                        "deprecation_reason": lib_info.get("deprecation_reason"),
                    })
                break

    return detected


def _report_inventory_sync(libraries: list[dict]) -> dict:
    """Report crypto inventory to platform synchronously."""
    import requests

    try:
        response = requests.post(
            f"{IDENTITY['server_url']}/api/v1/inventory/report",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            json={
                "identity_id": IDENTITY["identity_id"],
                "identity_name": IDENTITY["name"],
                "libraries": libraries,
                "algorithms": [],  # Derived from libraries on server
                "secrets": [],
                "scan_source": "import_scan",
            },
            timeout=10,
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"action": "allow", "violations": [], "warnings": []}

    except Exception:
        return {"action": "allow", "violations": [], "warnings": []}


def _report_inventory_async(libraries: list[dict]) -> None:
    """Report crypto inventory to platform asynchronously (fire and forget)."""
    try:
        _report_inventory_sync(libraries)
    except Exception:
        pass  # Silent failure for async reporting


def get_init_status() -> dict:
    """Get the current SDK initialization status."""
    return {
        "initialized": _initialized,
        "config": _init_config,
    }


# =============================================================================
# CBOM and PQC Recommendations
# =============================================================================


class CBOMResult:
    """Result of CBOM generation."""

    def __init__(
        self,
        cbom: dict,
        format: str = "json",
        quantum_readiness: dict | None = None,
    ):
        self.cbom = cbom
        self.format = format
        self.quantum_readiness = quantum_readiness or {}

    @property
    def score(self) -> float:
        """Quantum readiness score (0-100)."""
        return self.quantum_readiness.get("score", 0.0)

    @property
    def risk_level(self) -> str:
        """Quantum risk level: critical, high, medium, low, none."""
        return self.quantum_readiness.get("risk_level", "unknown")

    def to_json(self) -> str:
        """Export CBOM as JSON string."""
        import json
        return json.dumps(self.cbom, indent=2)

    def to_dict(self) -> dict:
        """Export CBOM as dictionary."""
        return {
            "cbom": self.cbom,
            "quantum_readiness": self.quantum_readiness,
        }

    def save(self, filepath: str) -> None:
        """Save CBOM to file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    def __repr__(self):
        components = len(self.cbom.get("components", []))
        return f"CBOMResult(components={components}, score={self.score:.0f}%, risk={self.risk_level})"


class PQCRecommendationResult:
    """Result of PQC migration recommendations."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def urgency(self) -> str:
        """Overall migration urgency: critical, high, medium, low, none."""
        return self._data.get("overall_urgency", "unknown")

    @property
    def score(self) -> float:
        """Quantum readiness score (0-100)."""
        return self._data.get("quantum_readiness_score", 0.0)

    @property
    def sndl_vulnerable(self) -> bool:
        """Whether vulnerable to Store Now, Decrypt Later attacks."""
        return self._data.get("sndl_assessment", {}).get("vulnerable", False)

    @property
    def key_findings(self) -> list[str]:
        """Key findings from the analysis."""
        return self._data.get("key_findings", [])

    @property
    def next_steps(self) -> list[str]:
        """Recommended next steps."""
        return self._data.get("next_steps", [])

    @property
    def kem_recommendations(self) -> list[dict]:
        """Key encapsulation mechanism recommendations."""
        return self._data.get("kem_recommendations", [])

    @property
    def signature_recommendations(self) -> list[dict]:
        """Digital signature algorithm recommendations."""
        return self._data.get("signature_recommendations", [])

    @property
    def migration_plan(self) -> list[dict]:
        """Ordered migration plan steps."""
        return self._data.get("migration_plan", [])

    def to_dict(self) -> dict:
        """Get the full recommendation data."""
        return self._data

    def __repr__(self):
        return f"PQCRecommendationResult(urgency={self.urgency}, score={self.score:.0f}%)"

    def __bool__(self):
        """True if recommendations exist."""
        return bool(self._data)


def export_cbom(
    format: str = "json",
    include_algorithms: bool = True,
) -> CBOMResult:
    """
    Generate and export a Cryptographic Bill of Materials (CBOM).

    Creates a comprehensive inventory of all cryptographic libraries and
    algorithms detected in the application. Supports multiple export formats
    for SBOM tooling integration.

    Args:
        format: Export format - "json", "cyclonedx", or "spdx"
        include_algorithms: Include algorithm details in CBOM

    Returns:
        CBOMResult with the generated CBOM and quantum readiness info

    Example:
        from cryptoserve import export_cbom

        # Generate CBOM
        result = export_cbom(format="cyclonedx")
        print(f"Quantum readiness: {result.score}%")

        # Save to file
        result.save("cbom-cyclonedx.json")

        # Access components
        for component in result.cbom["components"]:
            print(f"  {component['name']}: {component['quantum_risk']}")
    """
    if not _initialized:
        # Auto-initialize if not done
        init()

    libraries = _init_config.get("libraries", [])

    # Generate CBOM locally from detected libraries
    import os
    import datetime

    # Calculate quantum readiness metrics
    quantum_safe = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ["none", "low"])
    quantum_vulnerable = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ["high", "critical"])
    has_pqc = any("pqc" in lib.get("category", "").lower() or "post-quantum" in lib.get("category", "").lower() for lib in libraries)
    deprecated_count = sum(1 for lib in libraries if lib.get("is_deprecated", False))

    # Calculate score (0-100)
    total = quantum_safe + quantum_vulnerable
    if total == 0:
        score = 100.0  # No crypto = no risk
    else:
        score = (quantum_safe / total) * 100
        if has_pqc:
            score = min(100, score + 20)
        if deprecated_count > 0:
            score = max(0, score - (deprecated_count * 10))
    score = round(score, 1)

    # Determine risk level
    if score >= 80:
        risk_level = "low"
    elif score >= 50:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Collect all algorithms
    all_algorithms = []
    for lib in libraries:
        for algo in lib.get("algorithms", []):
            all_algorithms.append({
                "name": algo,
                "library": lib["name"],
                "category": lib.get("category", "unknown"),
            })

    # Build CBOM structure
    components = [
        {
            "bom_ref": f"crypto-lib-{lib['name']}",
            "type": "library",
            "name": lib["name"],
            "version": lib.get("version"),
            "category": lib.get("category", "unknown"),
            "quantum_risk": lib.get("quantum_risk", "unknown"),
            "is_deprecated": lib.get("is_deprecated", False),
            "algorithms": lib.get("algorithms", []),
        }
        for lib in libraries
    ]

    cbom = {
        "id": f"cbom_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "version": "1.0",
        "format": format,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "components": components,
        "algorithms": all_algorithms if include_algorithms else [],
        "summary": {
            "total_libraries": len(libraries),
            "quantum_safe": quantum_safe,
            "quantum_vulnerable": quantum_vulnerable,
            "deprecated": deprecated_count,
            "has_pqc": has_pqc,
        },
    }

    return CBOMResult(
        cbom=cbom,
        format=format,
        quantum_readiness={
            "score": score,
            "risk_level": risk_level,
            "has_pqc": has_pqc,
            "quantum_safe_count": quantum_safe,
            "quantum_vulnerable_count": quantum_vulnerable,
            "deprecated_count": deprecated_count,
        },
    )


def get_pqc_recommendations(
    data_profile: str | None = None,
) -> PQCRecommendationResult:
    """
    Get PQC (Post-Quantum Cryptography) migration recommendations.

    Analyzes the application's cryptographic inventory and provides
    actionable recommendations for migrating to quantum-safe algorithms.
    Includes SNDL (Store Now, Decrypt Later) risk assessment.

    Args:
        data_profile: Data sensitivity profile for risk calculation
            - "healthcare": 100 year protection (HIPAA)
            - "national_security": 75 year protection
            - "financial": 25 year protection (PCI-DSS)
            - "general": 10 year protection (default)
            - "short_lived": 1 year protection (session tokens)

    Returns:
        PQCRecommendationResult with migration guidance

    Example:
        from cryptoserve import get_pqc_recommendations

        # Get recommendations for financial data
        result = get_pqc_recommendations(data_profile="financial")

        print(f"Migration urgency: {result.urgency}")
        print(f"Quantum readiness: {result.score}%")

        if result.sndl_vulnerable:
            print("WARNING: Vulnerable to Store Now, Decrypt Later attacks!")

        print("Key findings:")
        for finding in result.key_findings:
            print(f"  - {finding}")

        print("Next steps:")
        for step in result.next_steps[:3]:
            print(f"  - {step}")

        # Get specific algorithm recommendations
        for rec in result.kem_recommendations:
            print(f"  Replace {rec['current_algorithm']} with {rec['recommended_algorithm']}")
    """
    if not _initialized:
        # Auto-initialize if not done
        init()

    libraries = _init_config.get("libraries", [])

    if _is_mock_mode():
        # Mock recommendations
        has_vulnerable = any(lib["quantum_risk"] in ["high", "critical"] for lib in libraries)
        return PQCRecommendationResult({
            "sndl_assessment": {
                "vulnerable": has_vulnerable,
                "protection_years_required": 10,
                "estimated_quantum_years": 15,
                "risk_window_years": -5 if not has_vulnerable else 5,
                "risk_level": "medium" if has_vulnerable else "low",
                "explanation": "Mock SNDL assessment",
            },
            "kem_recommendations": [
                {
                    "current_algorithm": "RSA",
                    "recommended_algorithm": "ML-KEM-768",
                    "fips_standard": "FIPS 203",
                    "security_level": "NIST Level 3",
                    "rationale": "RSA is vulnerable to Shor's algorithm",
                    "migration_complexity": "medium",
                }
            ] if has_vulnerable else [],
            "signature_recommendations": [],
            "migration_plan": [
                {
                    "priority": 1,
                    "phase": "immediate",
                    "action": "Inventory all asymmetric key usage",
                    "algorithms_affected": ["RSA", "ECDSA"],
                    "estimated_effort": "low",
                }
            ] if has_vulnerable else [],
            "overall_urgency": "medium" if has_vulnerable else "low",
            "quantum_readiness_score": 30.0 if has_vulnerable else 80.0,
            "key_findings": [
                f"Detected {len(libraries)} cryptographic libraries",
                "Quantum-vulnerable algorithms in use" if has_vulnerable else "No critical quantum vulnerabilities",
            ],
            "next_steps": [
                "Review algorithm recommendations",
                "Plan hybrid deployment strategy",
                "Train team on PQC concepts",
            ],
        })

    # Request recommendations from server
    import requests

    try:
        response = requests.post(
            f"{IDENTITY['server_url']}/api/v1/inventory/recommendations",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            json={
                "identity_id": IDENTITY["identity_id"],
                "libraries": libraries,
                "data_profile": data_profile,
            },
            timeout=30,
        )

        if response.status_code == 200:
            return PQCRecommendationResult(response.json())
        else:
            raise CryptoServeError(f"Failed to get recommendations: {response.text}")

    except requests.RequestException as e:
        raise CryptoServeError(f"Recommendations request failed: {str(e)}")
