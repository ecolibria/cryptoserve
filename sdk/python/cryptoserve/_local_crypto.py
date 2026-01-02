"""
Local cryptographic operations for the CryptoServe SDK.

This module provides high-performance local encryption/decryption
when keys are cached, reducing latency from ~5-50ms to ~0.1-0.5ms.

Supports:
- AES-256-GCM (default, FIPS compliant)
- AES-128-GCM (performance mode)
- ChaCha20-Poly1305 (software-optimized)
"""

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional, Tuple

# Use cryptography library for fast, secure implementations
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# Ciphertext format version
FORMAT_VERSION = 4  # Version 4 = SDK local crypto

# Nonce sizes
AES_GCM_NONCE_SIZE = 12
CHACHA_NONCE_SIZE = 12

# Key sizes
AES_256_KEY_SIZE = 32
AES_128_KEY_SIZE = 16
CHACHA_KEY_SIZE = 32


@dataclass
class LocalCryptoResult:
    """Result of a local crypto operation."""
    success: bool
    data: Optional[bytes] = None
    error: Optional[str] = None
    algorithm: Optional[str] = None
    latency_ms: float = 0.0
    cached: bool = True


class LocalCrypto:
    """
    High-performance local cryptographic operations.

    This class performs encryption/decryption locally using cached keys,
    dramatically reducing latency compared to network round-trips.
    """

    SUPPORTED_ALGORITHMS = {
        "AES-256-GCM": (AESGCM, AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE),
        "AES-128-GCM": (AESGCM, AES_128_KEY_SIZE, AES_GCM_NONCE_SIZE),
        "ChaCha20-Poly1305": (ChaCha20Poly1305, CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE),
    }

    def __init__(self):
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "cryptography library not available. "
                "Install with: pip install cryptography"
            )

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        key_id: str,
        context: str,
        algorithm: str = "AES-256-GCM",
        associated_data: Optional[bytes] = None,
    ) -> LocalCryptoResult:
        """
        Encrypt data locally using a cached key.

        Args:
            plaintext: Data to encrypt
            key: Encryption key
            key_id: Key identifier for the header
            context: Encryption context name
            algorithm: Encryption algorithm
            associated_data: Optional AAD

        Returns:
            LocalCryptoResult with encrypted data or error
        """
        start = time.perf_counter()

        try:
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                return LocalCryptoResult(
                    success=False,
                    error=f"Unsupported algorithm: {algorithm}",
                    latency_ms=(time.perf_counter() - start) * 1000,
                )

            cipher_class, expected_key_size, nonce_size = self.SUPPORTED_ALGORITHMS[algorithm]

            # Validate key size
            if len(key) != expected_key_size:
                return LocalCryptoResult(
                    success=False,
                    error=f"Invalid key size: expected {expected_key_size}, got {len(key)}",
                    latency_ms=(time.perf_counter() - start) * 1000,
                )

            # Generate random nonce
            nonce = os.urandom(nonce_size)

            # Create cipher and encrypt
            cipher = cipher_class(key)
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data)

            # Build self-describing ciphertext format
            header = {
                "v": FORMAT_VERSION,
                "ctx": context,
                "kid": key_id,
                "alg": algorithm,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "local": True,  # Marks as locally encrypted
            }

            if associated_data:
                header["aad_len"] = len(associated_data)

            header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
            header_len = len(header_bytes)

            # Format: [header_len:2][header][ciphertext]
            result = (
                header_len.to_bytes(2, "big") +
                header_bytes +
                ciphertext
            )

            latency = (time.perf_counter() - start) * 1000

            return LocalCryptoResult(
                success=True,
                data=result,
                algorithm=algorithm,
                latency_ms=latency,
                cached=True,
            )

        except Exception as e:
            return LocalCryptoResult(
                success=False,
                error=str(e),
                latency_ms=(time.perf_counter() - start) * 1000,
            )

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> LocalCryptoResult:
        """
        Decrypt data locally using a cached key.

        Args:
            ciphertext: Encrypted data (with header)
            key: Decryption key
            associated_data: Optional AAD (must match encryption)

        Returns:
            LocalCryptoResult with decrypted data or error
        """
        start = time.perf_counter()

        try:
            # Parse header
            header, raw_ciphertext = self._parse_ciphertext(ciphertext)

            algorithm = header.get("alg", "AES-256-GCM")

            if algorithm not in self.SUPPORTED_ALGORITHMS:
                return LocalCryptoResult(
                    success=False,
                    error=f"Unsupported algorithm: {algorithm}",
                    latency_ms=(time.perf_counter() - start) * 1000,
                )

            cipher_class, expected_key_size, _ = self.SUPPORTED_ALGORITHMS[algorithm]

            # Validate key size
            if len(key) != expected_key_size:
                return LocalCryptoResult(
                    success=False,
                    error=f"Invalid key size: expected {expected_key_size}, got {len(key)}",
                    latency_ms=(time.perf_counter() - start) * 1000,
                )

            # Get nonce from header
            nonce = base64.b64decode(header["nonce"])

            # Create cipher and decrypt
            cipher = cipher_class(key)
            plaintext = cipher.decrypt(nonce, raw_ciphertext, associated_data)

            latency = (time.perf_counter() - start) * 1000

            return LocalCryptoResult(
                success=True,
                data=plaintext,
                algorithm=algorithm,
                latency_ms=latency,
                cached=True,
            )

        except Exception as e:
            return LocalCryptoResult(
                success=False,
                error=str(e),
                latency_ms=(time.perf_counter() - start) * 1000,
            )

    def _parse_ciphertext(self, ciphertext: bytes) -> Tuple[dict, bytes]:
        """Parse header and raw ciphertext from formatted ciphertext."""
        if len(ciphertext) < 3:
            raise ValueError("Ciphertext too short")

        header_len = int.from_bytes(ciphertext[:2], "big")

        if len(ciphertext) < 2 + header_len:
            raise ValueError("Invalid ciphertext format")

        header_bytes = ciphertext[2:2 + header_len]
        raw_ciphertext = ciphertext[2 + header_len:]

        header = json.loads(header_bytes.decode("utf-8"))
        return header, raw_ciphertext

    def can_decrypt_locally(self, ciphertext: bytes, cached_key_id: str) -> bool:
        """
        Check if ciphertext can be decrypted locally with cached key.

        Args:
            ciphertext: The encrypted data
            cached_key_id: The key ID in our cache

        Returns:
            True if local decryption is possible
        """
        try:
            header, _ = self._parse_ciphertext(ciphertext)

            # Check if key ID matches
            if header.get("kid") != cached_key_id:
                return False

            # Check if algorithm is supported
            algorithm = header.get("alg", "AES-256-GCM")
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                return False

            return True

        except Exception:
            return False

    def get_key_id_from_ciphertext(self, ciphertext: bytes) -> Optional[str]:
        """Extract key ID from ciphertext header."""
        try:
            header, _ = self._parse_ciphertext(ciphertext)
            return header.get("kid")
        except Exception:
            return None

    def get_context_from_ciphertext(self, ciphertext: bytes) -> Optional[str]:
        """Extract context from ciphertext header."""
        try:
            header, _ = self._parse_ciphertext(ciphertext)
            return header.get("ctx")
        except Exception:
            return None


# Singleton instance
_local_crypto: Optional[LocalCrypto] = None


def get_local_crypto() -> LocalCrypto:
    """Get the local crypto instance."""
    global _local_crypto
    if _local_crypto is None:
        _local_crypto = LocalCrypto()
    return _local_crypto


def is_local_crypto_available() -> bool:
    """Check if local crypto is available."""
    return CRYPTO_AVAILABLE
