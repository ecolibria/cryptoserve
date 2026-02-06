"""
Cipher implementations for CryptoServe Core.

Provides AES-256-GCM and ChaCha20-Poly1305 encryption.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class CipherError(Exception):
    """Base exception for cipher operations."""
    pass


class AESGCMCipher:
    """
    AES-256-GCM authenticated encryption.

    Industry standard, hardware-accelerated on modern CPUs.
    Recommended for most use cases.

    Example:
        cipher = AESGCMCipher(key)
        ciphertext, nonce = cipher.encrypt(b"secret")
        plaintext = cipher.decrypt(ciphertext, nonce)
    """

    NONCE_SIZE = 12  # 96 bits recommended for GCM
    TAG_SIZE = 16    # 128 bits
    KEY_SIZE = 32    # 256 bits

    def __init__(self, key: bytes):
        """
        Initialize cipher with key.

        Args:
            key: 32-byte (256-bit) encryption key

        Raises:
            CipherError: If key is invalid size
        """
        if len(key) != self.KEY_SIZE:
            raise CipherError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        self._cipher = AESGCM(key)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data with AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional authenticated but unencrypted data

        Returns:
            Tuple of (ciphertext_with_tag, nonce)
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypt AES-256-GCM ciphertext.

        Args:
            ciphertext: Encrypted data with authentication tag
            nonce: Nonce used during encryption
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            CipherError: If decryption or authentication fails
        """
        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise CipherError(f"Decryption failed: {e}") from e

    def close(self):
        """Explicitly clear key material. Use for deterministic cleanup."""
        self._cipher = None

    def __del__(self):
        """Best-effort key cleanup."""
        try:
            self._cipher = None
        except Exception:
            pass


class ChaCha20Cipher:
    """
    ChaCha20-Poly1305 authenticated encryption.

    Excellent software performance, especially on devices without
    AES hardware acceleration. Recommended for mobile and real-time.

    Example:
        cipher = ChaCha20Cipher(key)
        ciphertext, nonce = cipher.encrypt(b"secret")
        plaintext = cipher.decrypt(ciphertext, nonce)
    """

    NONCE_SIZE = 12  # 96 bits
    KEY_SIZE = 32    # 256 bits

    def __init__(self, key: bytes):
        """
        Initialize cipher with key.

        Args:
            key: 32-byte (256-bit) encryption key

        Raises:
            CipherError: If key is invalid size
        """
        if len(key) != self.KEY_SIZE:
            raise CipherError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        self._cipher = ChaCha20Poly1305(key)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data with ChaCha20-Poly1305.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional authenticated but unencrypted data

        Returns:
            Tuple of (ciphertext_with_tag, nonce)
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypt ChaCha20-Poly1305 ciphertext.

        Args:
            ciphertext: Encrypted data with authentication tag
            nonce: Nonce used during encryption
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            CipherError: If decryption or authentication fails
        """
        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise CipherError(f"Decryption failed: {e}") from e

    def close(self):
        """Explicitly clear key material. Use for deterministic cleanup."""
        self._cipher = None

    def __del__(self):
        """Best-effort key cleanup."""
        try:
            self._cipher = None
        except Exception:
            pass
