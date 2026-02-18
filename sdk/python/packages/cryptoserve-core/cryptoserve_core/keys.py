"""
Key derivation and management utilities.
"""
from __future__ import annotations

import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class CryptoKeyError(Exception):
    """Exception for key-related errors."""
    pass


class KeyDerivation:
    """
    Key generation and derivation utilities.

    Example:
        # Generate a random key
        key = KeyDerivation.generate_key(256)

        # Derive key from password
        key, salt = KeyDerivation.from_password("my-password", bits=256)

        # Derive multiple keys from master key
        enc_key, auth_key = KeyDerivation.derive_keys(master_key, count=2)
    """

    @staticmethod
    def generate_key(bits: int = 256) -> bytes:
        """
        Generate a cryptographically secure random key.

        Args:
            bits: Key size in bits (128, 192, or 256)

        Returns:
            Random key bytes
        """
        if bits not in (128, 192, 256):
            raise CryptoKeyError(f"Key size must be 128, 192, or 256 bits, got {bits}")
        return os.urandom(bits // 8)

    @staticmethod
    def from_password(
        password: str,
        salt: bytes | None = None,
        bits: int = 256,
        iterations: int = 600_000,
    ) -> Tuple[bytes, bytes]:
        """
        Derive a key from a password using PBKDF2.

        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            bits: Key size in bits
            iterations: PBKDF2 iterations (higher = slower but more secure)

        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(32)

        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=bits // 8,
        )
        return key, salt

    @staticmethod
    def derive_keys(
        master_key: bytes,
        count: int = 2,
        info: bytes = b"cryptoserve-key-derivation",
    ) -> list[bytes]:
        """
        Derive multiple keys from a master key using HKDF.

        Args:
            master_key: Master key material
            count: Number of keys to derive
            info: Context info for derivation

        Returns:
            List of derived keys
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * count,
            salt=None,
            info=info,
        )
        derived = hkdf.derive(master_key)
        return [derived[i * 32 : (i + 1) * 32] for i in range(count)]

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.

        Prevents timing attacks when comparing keys or tokens.

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise
        """
        import hmac
        return hmac.compare_digest(a, b)
