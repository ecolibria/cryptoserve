"""Secure memory handling utilities.

Provides functions for secure handling of sensitive data in memory:
- Secure zeroization of byte arrays
- Context managers for temporary key handling
- Memory-safe comparison

These utilities help protect against memory scraping attacks by
ensuring sensitive data is cleared from memory when no longer needed.
"""

import ctypes
import secrets
from contextlib import contextmanager
from typing import Generator


def secure_zero(data: bytearray) -> None:
    """Securely zero out a bytearray.

    Uses ctypes.memset to overwrite memory, which is less likely
    to be optimized away by the compiler compared to simple assignment.

    Args:
        data: The bytearray to zero. Must be a mutable bytearray, not bytes.

    Note:
        This function modifies the bytearray in-place.
        Python's garbage collector may still leave copies in memory.
        For maximum security, use the SecureBytes context manager.
    """
    if not isinstance(data, bytearray):
        raise TypeError("secure_zero requires a bytearray, not bytes")

    if len(data) == 0:
        return

    # Get the buffer address and overwrite with zeros
    buffer_type = ctypes.c_char * len(data)
    buffer = buffer_type.from_buffer(data)
    ctypes.memset(ctypes.addressof(buffer), 0, len(data))


def secure_random_overwrite(data: bytearray, passes: int = 3) -> None:
    """Overwrite a bytearray with random data multiple times, then zero.

    Provides defense-in-depth by overwriting with random data
    before final zeroization.

    Args:
        data: The bytearray to overwrite
        passes: Number of random overwrites before final zero
    """
    if not isinstance(data, bytearray):
        raise TypeError("secure_random_overwrite requires a bytearray")

    for _ in range(passes):
        random_data = secrets.token_bytes(len(data))
        for i in range(len(data)):
            data[i] = random_data[i]

    secure_zero(data)


class SecureBytes:
    """A bytearray wrapper that zeros memory on deletion.

    Use this for storing sensitive data like encryption keys.
    The data is automatically zeroed when the object is deleted
    or when exiting the context manager.

    Example:
        with SecureBytes(key_material) as secure_key:
            # Use secure_key.data for operations
            result = encrypt(secure_key.data, plaintext)
        # Key is zeroed here

        # Or without context manager:
        secure_key = SecureBytes(key_material)
        try:
            result = encrypt(secure_key.data, plaintext)
        finally:
            secure_key.clear()
    """

    def __init__(self, data: bytes | bytearray):
        """Initialize with sensitive data.

        Args:
            data: The sensitive data to protect. Will be copied to internal buffer.
        """
        self._data = bytearray(data)
        self._cleared = False

    @property
    def data(self) -> bytearray:
        """Access the underlying data."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return self._data

    def __bytes__(self) -> bytes:
        """Convert to bytes (creates a copy - use sparingly)."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._data)

    def __len__(self) -> int:
        """Return length of data."""
        return len(self._data)

    def clear(self) -> None:
        """Securely clear the data."""
        if not self._cleared:
            secure_zero(self._data)
            self._cleared = True

    def __enter__(self) -> "SecureBytes":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - clears data."""
        self.clear()

    def __del__(self) -> None:
        """Destructor - clears data."""
        self.clear()


@contextmanager
def temporary_key(key_bytes: bytes) -> Generator[bytearray, None, None]:
    """Context manager for temporary key usage.

    Yields a mutable bytearray copy of the key that is
    securely zeroed when the context exits.

    Args:
        key_bytes: The key material

    Yields:
        A bytearray containing the key

    Example:
        with temporary_key(derived_key) as key:
            ciphertext = encrypt(key, plaintext)
        # key is zeroed here
    """
    key_copy = bytearray(key_bytes)
    try:
        yield key_copy
    finally:
        secure_zero(key_copy)


def constant_time_compare(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    """Constant-time comparison of two byte sequences.

    This is a wrapper around hmac.compare_digest for clarity.
    Prevents timing attacks when comparing secrets.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if equal, False otherwise
    """
    import hmac
    return hmac.compare_digest(a, b)


def secure_random_bytes(n: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Wrapper around secrets.token_bytes for clarity.

    Args:
        n: Number of bytes to generate

    Returns:
        n random bytes
    """
    return secrets.token_bytes(n)
