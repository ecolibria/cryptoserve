"""
Ciphertext encoding utilities.

Provides standard format for encoding/decoding ciphertext with metadata.
"""

import base64
import struct
from typing import NamedTuple


class CiphertextBundle(NamedTuple):
    """Decoded ciphertext components."""
    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes


# Algorithm identifiers (1 byte each)
ALGORITHMS = {
    0x01: "AES-256-GCM",
    0x02: "ChaCha20-Poly1305",
    0x10: "KYBER-1024-AES-256-GCM",  # Future: post-quantum hybrid
}

ALGORITHM_IDS = {v: k for k, v in ALGORITHMS.items()}


def encode_ciphertext(
    algorithm: str,
    nonce: bytes,
    ciphertext: bytes,
    version: int = 1,
) -> bytes:
    """
    Encode ciphertext with metadata into a portable format.

    Format:
        [version: 1 byte][algorithm: 1 byte][nonce_len: 1 byte][nonce][ciphertext]

    Args:
        algorithm: Algorithm name (e.g., "AES-256-GCM")
        nonce: Encryption nonce/IV
        ciphertext: Encrypted data with auth tag
        version: Format version

    Returns:
        Encoded bytes ready for storage/transmission
    """
    if algorithm not in ALGORITHM_IDS:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    alg_id = ALGORITHM_IDS[algorithm]
    nonce_len = len(nonce)

    if nonce_len > 255:
        raise ValueError(f"Nonce too long: {nonce_len} bytes")

    header = struct.pack("BBB", version, alg_id, nonce_len)
    return header + nonce + ciphertext


def decode_ciphertext(encoded: bytes) -> CiphertextBundle:
    """
    Decode ciphertext from portable format.

    Args:
        encoded: Encoded ciphertext bytes

    Returns:
        CiphertextBundle with decoded components

    Raises:
        ValueError: If format is invalid
    """
    if len(encoded) < 3:
        raise ValueError("Encoded ciphertext too short")

    version, alg_id, nonce_len = struct.unpack("BBB", encoded[:3])

    if version != 1:
        raise ValueError(f"Unsupported format version: {version}")

    if alg_id not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm ID: {alg_id}")

    algorithm = ALGORITHMS[alg_id]

    if len(encoded) < 3 + nonce_len:
        raise ValueError("Encoded ciphertext truncated")

    nonce = encoded[3 : 3 + nonce_len]
    ciphertext = encoded[3 + nonce_len :]

    return CiphertextBundle(
        version=version,
        algorithm=algorithm,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def to_base64(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def from_base64(data: str) -> bytes:
    """Decode URL-safe base64 string to bytes."""
    return base64.urlsafe_b64decode(data.encode("ascii"))
