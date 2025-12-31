"""Additional AEAD Modes Engine.

Provides OCB and EAX authenticated encryption modes using PyCryptodome.
These complement the standard GCM and CCM modes in the main crypto engine.

Security Properties:
- OCB: Single-pass AEAD, excellent performance, patent-free since 2021
- EAX: Two-pass AEAD, uses CTR + OMAC, provably secure

Both modes provide:
- Authenticated encryption with associated data
- Nonce-based encryption (nonce reuse catastrophic for OCB, safe for EAX)
- Tag-based authentication
"""

import os
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from Crypto.Cipher import AES


class AEADMode(str, Enum):
    """Supported AEAD modes."""

    OCB = "aes-ocb"  # Offset Codebook Mode - fastest, patent-free since 2021
    EAX = "aes-eax"  # EAX mode - CTR + OMAC, nonce-misuse resistant


@dataclass
class AEADResult:
    """Result of an AEAD operation."""

    ciphertext: bytes
    nonce: bytes
    tag: bytes
    algorithm: AEADMode
    key_size_bits: int
    aad_size: int


@dataclass
class DecryptResult:
    """Result of decryption."""

    plaintext: bytes
    algorithm: AEADMode
    verified: bool


class AEADModesError(Exception):
    """Base exception for AEAD modes errors."""
    pass


class AuthenticationError(AEADModesError):
    """Authentication tag verification failed."""
    pass


class InvalidKeyError(AEADModesError):
    """Invalid key size or format."""
    pass


class InvalidNonceError(AEADModesError):
    """Invalid nonce size or format."""
    pass


class AEADModesEngine:
    """Engine for OCB and EAX authenticated encryption modes.

    OCB (Offset Codebook Mode):
    - Single-pass AEAD with excellent performance
    - Nonce: 15 bytes recommended (1-15 bytes supported)
    - Tag: 16 bytes (full security)
    - Key sizes: 128, 192, 256 bits
    - CAUTION: Nonce reuse is catastrophic - reveals plaintext XOR

    EAX Mode:
    - Two-pass AEAD (CTR + OMAC)
    - Nonce: Any length (16 bytes recommended)
    - Tag: 16 bytes default
    - Key sizes: 128, 192, 256 bits
    - More resistant to nonce misuse than OCB

    Usage:
        engine = AEADModesEngine()

        # Encrypt with OCB
        result = engine.encrypt(
            plaintext=b"secret data",
            key=key_32_bytes,
            mode=AEADMode.OCB,
            associated_data=b"header",
        )

        # Decrypt
        plaintext = engine.decrypt(
            ciphertext=result.ciphertext,
            key=key_32_bytes,
            nonce=result.nonce,
            tag=result.tag,
            mode=AEADMode.OCB,
            associated_data=b"header",
        )
    """

    # Valid AES key sizes in bytes
    VALID_KEY_SIZES = {16, 24, 32}  # 128, 192, 256 bits

    # Default nonce sizes per mode
    DEFAULT_NONCE_SIZES = {
        AEADMode.OCB: 15,  # OCB: 1-15 bytes, 15 recommended
        AEADMode.EAX: 16,  # EAX: any length, 16 common
    }

    # OCB nonce constraints
    OCB_MIN_NONCE = 1
    OCB_MAX_NONCE = 15

    # Default tag size
    DEFAULT_TAG_SIZE = 16

    def __init__(self, default_mode: AEADMode = AEADMode.OCB):
        """Initialize the AEAD modes engine.

        Args:
            default_mode: Default AEAD mode to use
        """
        self.default_mode = default_mode

    def _validate_key(self, key: bytes) -> None:
        """Validate encryption key."""
        if not isinstance(key, bytes):
            raise InvalidKeyError("Key must be bytes")
        if len(key) not in self.VALID_KEY_SIZES:
            raise InvalidKeyError(
                f"Key must be 16, 24, or 32 bytes, got {len(key)}"
            )

    def _validate_nonce(self, nonce: bytes, mode: AEADMode) -> None:
        """Validate nonce for the given mode."""
        if not isinstance(nonce, bytes):
            raise InvalidNonceError("Nonce must be bytes")

        if mode == AEADMode.OCB:
            if not (self.OCB_MIN_NONCE <= len(nonce) <= self.OCB_MAX_NONCE):
                raise InvalidNonceError(
                    f"OCB nonce must be 1-15 bytes, got {len(nonce)}"
                )
        elif mode == AEADMode.EAX:
            if len(nonce) == 0:
                raise InvalidNonceError("EAX nonce cannot be empty")

    def _generate_nonce(self, mode: AEADMode) -> bytes:
        """Generate a random nonce for the given mode."""
        return os.urandom(self.DEFAULT_NONCE_SIZES[mode])

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        mode: Optional[AEADMode] = None,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
        tag_length: int = DEFAULT_TAG_SIZE,
    ) -> AEADResult:
        """Encrypt data using OCB or EAX mode.

        Args:
            plaintext: Data to encrypt
            key: Encryption key (16, 24, or 32 bytes)
            mode: AEAD mode (OCB or EAX)
            nonce: Optional nonce (random generated if not provided)
            associated_data: Optional AAD (authenticated but not encrypted)
            tag_length: Authentication tag length (default 16)

        Returns:
            AEADResult with ciphertext, nonce, tag, and metadata

        Raises:
            InvalidKeyError: If key size is invalid
            InvalidNonceError: If nonce size is invalid for mode
        """
        mode = mode or self.default_mode
        self._validate_key(key)

        if nonce is None:
            nonce = self._generate_nonce(mode)
        else:
            self._validate_nonce(nonce, mode)

        aad = associated_data or b""

        if mode == AEADMode.OCB:
            cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
            if aad:
                cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        elif mode == AEADMode.EAX:
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=tag_length)
            if aad:
                cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        else:
            raise AEADModesError(f"Unsupported mode: {mode}")

        return AEADResult(
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            algorithm=mode,
            key_size_bits=len(key) * 8,
            aad_size=len(aad),
        )

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        tag: bytes,
        mode: Optional[AEADMode] = None,
        associated_data: Optional[bytes] = None,
    ) -> DecryptResult:
        """Decrypt data using OCB or EAX mode.

        Args:
            ciphertext: Encrypted data
            key: Decryption key
            nonce: Nonce used during encryption
            tag: Authentication tag
            mode: AEAD mode (OCB or EAX)
            associated_data: Optional AAD (must match encryption)

        Returns:
            DecryptResult with plaintext

        Raises:
            AuthenticationError: If tag verification fails
            InvalidKeyError: If key size is invalid
            InvalidNonceError: If nonce size is invalid
        """
        mode = mode or self.default_mode
        self._validate_key(key)
        self._validate_nonce(nonce, mode)

        aad = associated_data or b""

        try:
            if mode == AEADMode.OCB:
                cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
                if aad:
                    cipher.update(aad)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            elif mode == AEADMode.EAX:
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=len(tag))
                if aad:
                    cipher.update(aad)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            else:
                raise AEADModesError(f"Unsupported mode: {mode}")

            return DecryptResult(
                plaintext=plaintext,
                algorithm=mode,
                verified=True,
            )

        except ValueError as e:
            raise AuthenticationError(f"Authentication failed: {e}") from e

    def encrypt_with_header(
        self,
        plaintext: bytes,
        key: bytes,
        mode: Optional[AEADMode] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypt with self-describing header.

        Format: [version:1][mode:1][nonce_len:1][tag_len:1][nonce][tag][ciphertext]

        Args:
            plaintext: Data to encrypt
            key: Encryption key
            mode: AEAD mode
            associated_data: Optional AAD

        Returns:
            Self-describing ciphertext with embedded header
        """
        mode = mode or self.default_mode
        result = self.encrypt(plaintext, key, mode, associated_data=associated_data)

        # Build header
        mode_byte = 0x01 if mode == AEADMode.OCB else 0x02
        header = struct.pack(
            "BBBB",
            0x01,  # Version
            mode_byte,
            len(result.nonce),
            len(result.tag),
        )

        return header + result.nonce + result.tag + result.ciphertext

    def decrypt_with_header(
        self,
        data: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> DecryptResult:
        """Decrypt self-describing ciphertext.

        Args:
            data: Ciphertext with header
            key: Decryption key
            associated_data: Optional AAD

        Returns:
            DecryptResult with plaintext
        """
        if len(data) < 4:
            raise AEADModesError("Data too short for header")

        version, mode_byte, nonce_len, tag_len = struct.unpack("BBBB", data[:4])

        if version != 0x01:
            raise AEADModesError(f"Unsupported version: {version}")

        mode = AEADMode.OCB if mode_byte == 0x01 else AEADMode.EAX

        header_end = 4
        nonce_end = header_end + nonce_len
        tag_end = nonce_end + tag_len

        if len(data) < tag_end:
            raise AEADModesError("Data too short for nonce and tag")

        nonce = data[header_end:nonce_end]
        tag = data[nonce_end:tag_end]
        ciphertext = data[tag_end:]

        return self.decrypt(
            ciphertext, key, nonce, tag, mode, associated_data
        )

    def get_recommended_mode(self, use_case: str) -> AEADMode:
        """Get recommended AEAD mode for a use case.

        Args:
            use_case: One of "performance", "safety", "general"

        Returns:
            Recommended AEADMode
        """
        recommendations = {
            "performance": AEADMode.OCB,  # Single-pass, fastest
            "safety": AEADMode.EAX,  # More resistant to nonce issues
            "general": AEADMode.OCB,  # Good balance
        }
        return recommendations.get(use_case, AEADMode.OCB)


# Singleton instance
aead_modes_engine = AEADModesEngine()
