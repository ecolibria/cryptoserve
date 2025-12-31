"""Key Derivation Function Engine.

Provides comprehensive key derivation support:
- HKDF: HMAC-based Extract-and-Expand KDF (RFC 5869)
  - HKDF-SHA256, HKDF-SHA384, HKDF-SHA512
- KBKDF: Key-Based Key Derivation (NIST SP 800-108)
  - Counter Mode, Feedback Mode
- PBKDF2: Password-Based KDF (already in password_engine.py)
- Scrypt/Argon2: Memory-hard KDFs (already in password_engine.py)

Use Cases:
- HKDF: Deriving multiple keys from a single master key
- KBKDF: NIST-compliant key derivation for government/enterprise
- Extract-and-Expand: Converting non-uniform to uniform key material
"""

import os
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.kbkdf import (
    KBKDFHMAC,
    CounterLocation,
    Mode as KBKDFMode,
)


class KDFAlgorithm(str, Enum):
    """Supported KDF algorithms."""

    # HKDF family (RFC 5869)
    HKDF_SHA256 = "hkdf-sha256"
    HKDF_SHA384 = "hkdf-sha384"
    HKDF_SHA512 = "hkdf-sha512"

    # KBKDF family (NIST SP 800-108)
    KBKDF_HMAC_SHA256 = "kbkdf-hmac-sha256"
    KBKDF_HMAC_SHA384 = "kbkdf-hmac-sha384"
    KBKDF_HMAC_SHA512 = "kbkdf-hmac-sha512"


class KBKDFCounterLocation(str, Enum):
    """Counter location for KBKDF."""

    BEFORE_FIXED = "before_fixed"
    AFTER_FIXED = "after_fixed"
    # Note: MIDDLE_FIXED requires break_location parameter and is not commonly used


@dataclass
class DeriveResult:
    """Result of a key derivation operation."""

    derived_key: bytes
    algorithm: KDFAlgorithm
    key_length: int
    info_used: bytes
    salt_used: bytes | None


@dataclass
class MultiKeyResult:
    """Result of deriving multiple keys."""

    keys: list[bytes]
    algorithm: KDFAlgorithm
    key_lengths: list[int]
    labels: list[str]


class KDFError(Exception):
    """Key derivation error."""
    pass


class InvalidKeyMaterialError(KDFError):
    """Invalid input key material."""
    pass


class KDFEngine:
    """Comprehensive Key Derivation Function engine.

    Supports:
    - HKDF (RFC 5869): Best for deriving keys from high-entropy input
    - KBKDF (SP 800-108): NIST-compliant for federal requirements

    Usage:
        engine = KDFEngine()

        # HKDF - derive a single key
        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=b"encryption-key",
            salt=salt,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        # KBKDF - NIST SP 800-108 compliant
        result = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"session-key",
            context=b"session-context",
            algorithm=KDFAlgorithm.KBKDF_HMAC_SHA256,
        )

        # Derive multiple keys for encrypt-then-MAC
        keys = engine.derive_multiple_keys(
            master_key=key,
            key_specs=[
                ("encryption", 32),
                ("authentication", 32),
            ],
        )
    """

    # Hash algorithm mapping for HKDF
    HKDF_HASHES = {
        KDFAlgorithm.HKDF_SHA256: hashes.SHA256(),
        KDFAlgorithm.HKDF_SHA384: hashes.SHA384(),
        KDFAlgorithm.HKDF_SHA512: hashes.SHA512(),
    }

    # Hash algorithm mapping for KBKDF
    KBKDF_HASHES = {
        KDFAlgorithm.KBKDF_HMAC_SHA256: hashes.SHA256(),
        KDFAlgorithm.KBKDF_HMAC_SHA384: hashes.SHA384(),
        KDFAlgorithm.KBKDF_HMAC_SHA512: hashes.SHA512(),
    }

    # Counter location mapping
    COUNTER_LOCATIONS = {
        KBKDFCounterLocation.BEFORE_FIXED: CounterLocation.BeforeFixed,
        KBKDFCounterLocation.AFTER_FIXED: CounterLocation.AfterFixed,
    }

    def derive_hkdf(
        self,
        input_key_material: bytes,
        length: int,
        info: bytes = b"",
        salt: Optional[bytes] = None,
        algorithm: KDFAlgorithm = KDFAlgorithm.HKDF_SHA256,
    ) -> DeriveResult:
        """Derive a key using HKDF (RFC 5869).

        HKDF consists of two steps:
        1. Extract: Convert non-uniform input to uniform pseudorandom key
        2. Expand: Expand to desired length with context info

        Args:
            input_key_material: The source key material (high entropy)
            length: Desired output key length in bytes
            info: Application-specific context info (not secret)
            salt: Optional salt (random, not necessarily secret)
            algorithm: HKDF variant to use

        Returns:
            DeriveResult with derived key

        Raises:
            InvalidKeyMaterialError: If input is invalid
            KDFError: If derivation fails
        """
        if not input_key_material:
            raise InvalidKeyMaterialError("Input key material cannot be empty")

        if algorithm not in self.HKDF_HASHES:
            raise KDFError(f"Unsupported HKDF algorithm: {algorithm}")

        hash_algo = self.HKDF_HASHES[algorithm]

        hkdf = HKDF(
            algorithm=hash_algo,
            length=length,
            salt=salt,
            info=info,
        )

        derived_key = hkdf.derive(input_key_material)

        return DeriveResult(
            derived_key=derived_key,
            algorithm=algorithm,
            key_length=length,
            info_used=info,
            salt_used=salt,
        )

    def hkdf_expand(
        self,
        prk: bytes,
        length: int,
        info: bytes = b"",
        algorithm: KDFAlgorithm = KDFAlgorithm.HKDF_SHA256,
    ) -> DeriveResult:
        """Perform only the expand step of HKDF.

        Use when you already have a pseudorandom key (PRK) from
        a previous extract step or secure random generation.

        Args:
            prk: Pseudorandom key (uniform entropy)
            length: Desired output key length
            info: Application-specific context info
            algorithm: HKDF variant

        Returns:
            DeriveResult with derived key
        """
        if not prk:
            raise InvalidKeyMaterialError("PRK cannot be empty")

        if algorithm not in self.HKDF_HASHES:
            raise KDFError(f"Unsupported HKDF algorithm: {algorithm}")

        hash_algo = self.HKDF_HASHES[algorithm]

        hkdf_expand = HKDFExpand(
            algorithm=hash_algo,
            length=length,
            info=info,
        )

        derived_key = hkdf_expand.derive(prk)

        return DeriveResult(
            derived_key=derived_key,
            algorithm=algorithm,
            key_length=length,
            info_used=info,
            salt_used=None,
        )

    def derive_kbkdf(
        self,
        key: bytes,
        length: int,
        label: bytes,
        context: bytes,
        algorithm: KDFAlgorithm = KDFAlgorithm.KBKDF_HMAC_SHA256,
        counter_location: KBKDFCounterLocation = KBKDFCounterLocation.BEFORE_FIXED,
        rlen: int = 4,
    ) -> DeriveResult:
        """Derive a key using KBKDF (NIST SP 800-108).

        Key-Based Key Derivation Function using Counter Mode.
        Required for NIST/federal compliance.

        Args:
            key: The derivation key (master key)
            length: Desired output key length in bytes
            label: Identifies purpose of derived key
            context: Application context (e.g., session identifiers)
            algorithm: KBKDF variant to use
            counter_location: Where to place counter in input
            rlen: Counter length in bytes (1-4)

        Returns:
            DeriveResult with derived key

        Raises:
            InvalidKeyMaterialError: If key is invalid
            KDFError: If derivation fails
        """
        if not key:
            raise InvalidKeyMaterialError("Key cannot be empty")

        if algorithm not in self.KBKDF_HASHES:
            raise KDFError(f"Unsupported KBKDF algorithm: {algorithm}")

        hash_algo = self.KBKDF_HASHES[algorithm]
        location = self.COUNTER_LOCATIONS[counter_location]

        # KBKDF with Counter Mode
        kbkdf = KBKDFHMAC(
            algorithm=hash_algo,
            mode=KBKDFMode.CounterMode,
            length=length,
            rlen=rlen,
            llen=4,  # Length field size
            location=location,
            label=label,
            context=context,
            fixed=None,
        )

        derived_key = kbkdf.derive(key)

        # Combine label and context for info field
        info_combined = label + b"\x00" + context

        return DeriveResult(
            derived_key=derived_key,
            algorithm=algorithm,
            key_length=length,
            info_used=info_combined,
            salt_used=None,
        )

    def derive_multiple_keys(
        self,
        master_key: bytes,
        key_specs: list[tuple[str, int]],
        algorithm: KDFAlgorithm = KDFAlgorithm.HKDF_SHA256,
        salt: Optional[bytes] = None,
    ) -> MultiKeyResult:
        """Derive multiple keys from a single master key.

        Useful for encrypt-then-MAC where you need separate keys
        for encryption and authentication.

        Args:
            master_key: The source master key
            key_specs: List of (label, length) tuples
            algorithm: KDF algorithm to use
            salt: Optional salt for HKDF

        Returns:
            MultiKeyResult with all derived keys

        Example:
            keys = engine.derive_multiple_keys(
                master_key=key,
                key_specs=[
                    ("encryption", 32),
                    ("authentication", 32),
                    ("iv", 16),
                ],
            )
            enc_key = keys.keys[0]
            mac_key = keys.keys[1]
            iv = keys.keys[2]
        """
        if not master_key:
            raise InvalidKeyMaterialError("Master key cannot be empty")

        keys = []
        labels = []
        lengths = []

        for label, length in key_specs:
            info = f"key-derivation:{label}".encode("utf-8")

            if algorithm in self.HKDF_HASHES:
                result = self.derive_hkdf(
                    input_key_material=master_key,
                    length=length,
                    info=info,
                    salt=salt,
                    algorithm=algorithm,
                )
            elif algorithm in self.KBKDF_HASHES:
                result = self.derive_kbkdf(
                    key=master_key,
                    length=length,
                    label=label.encode("utf-8"),
                    context=b"multi-key-derivation",
                    algorithm=algorithm,
                )
            else:
                raise KDFError(f"Unsupported algorithm: {algorithm}")

            keys.append(result.derived_key)
            labels.append(label)
            lengths.append(length)

        return MultiKeyResult(
            keys=keys,
            algorithm=algorithm,
            key_lengths=lengths,
            labels=labels,
        )

    def derive_encryption_and_mac_keys(
        self,
        master_key: bytes,
        enc_key_length: int = 32,
        mac_key_length: int = 32,
        algorithm: KDFAlgorithm = KDFAlgorithm.HKDF_SHA256,
        salt: Optional[bytes] = None,
    ) -> tuple[bytes, bytes]:
        """Convenience method to derive separate encryption and MAC keys.

        This follows the best practice of using separate keys for
        encryption and authentication (encrypt-then-MAC).

        Args:
            master_key: Source master key
            enc_key_length: Encryption key length (default 32)
            mac_key_length: MAC key length (default 32)
            algorithm: KDF algorithm
            salt: Optional salt

        Returns:
            Tuple of (encryption_key, mac_key)
        """
        result = self.derive_multiple_keys(
            master_key=master_key,
            key_specs=[
                ("encryption", enc_key_length),
                ("authentication", mac_key_length),
            ],
            algorithm=algorithm,
            salt=salt,
        )

        return result.keys[0], result.keys[1]

    def derive_with_context(
        self,
        master_key: bytes,
        context_id: str,
        key_purpose: str,
        length: int = 32,
        algorithm: KDFAlgorithm = KDFAlgorithm.HKDF_SHA256,
    ) -> bytes:
        """Derive a key with structured context.

        Provides a simple interface for common use cases.

        Args:
            master_key: Source master key
            context_id: Unique context identifier (e.g., user ID)
            key_purpose: Purpose of the key (e.g., "file-encryption")
            length: Desired key length
            algorithm: KDF algorithm

        Returns:
            Derived key bytes
        """
        info = f"{context_id}:{key_purpose}".encode("utf-8")

        result = self.derive_hkdf(
            input_key_material=master_key,
            length=length,
            info=info,
            algorithm=algorithm,
        )

        return result.derived_key

    def generate_salt(self, length: int = 32) -> bytes:
        """Generate a random salt for key derivation.

        Args:
            length: Salt length in bytes

        Returns:
            Random salt bytes
        """
        return os.urandom(length)


# Singleton instance
kdf_engine = KDFEngine()
