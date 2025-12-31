"""
CryptoServe SDK - Zero-config cryptographic operations.

Usage:
    from cryptoserve import crypto

    # Encrypt data
    ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

    # Decrypt data
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
)
from cryptoserve._identity import IDENTITY

__version__ = "0.4.0"
__all__ = [
    "crypto",
    "CryptoClient",
    "VerifyResult",
    "CryptoServeError",
    "AuthenticationError",
    "AuthorizationError",
    "ContextNotFoundError",
    "auto_protect",
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
