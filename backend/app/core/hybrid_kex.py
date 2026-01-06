"""Hybrid Key Exchange combining X25519 and ML-KEM.

This module implements hybrid key exchange per NIST recommendations for
the post-quantum transition period. The shared secret is derived from
both a classical X25519 exchange and a post-quantum ML-KEM encapsulation.

Security: If either algorithm remains secure, the combined scheme is secure.

Supported Modes:
- X25519 + ML-KEM-768: NIST Level 3 (recommended for most use cases)
- X25519 + ML-KEM-1024: NIST Level 5 (maximum security)

Usage:
    # Key generation (recipient)
    kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
    keypair = kex.generate_keypair()

    # Encapsulation (sender) - creates shared secret
    encap, shared_secret_sender = kex.encapsulate(
        keypair.x25519_public, keypair.mlkem_public
    )

    # Decapsulation (recipient) - recovers shared secret
    shared_secret_recipient = kex.decapsulate(encap, keypair)

    assert shared_secret_sender == shared_secret_recipient
"""

import json
import logging
import secrets
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.core.hybrid_crypto import is_pqc_available, get_mlkem, PQCError

logger = logging.getLogger(__name__)


class HybridKEXMode(str, Enum):
    """Supported hybrid key exchange modes."""

    X25519_MLKEM_768 = "X25519+ML-KEM-768"
    X25519_MLKEM_1024 = "X25519+ML-KEM-1024"


@dataclass
class HybridKEXKeyPair:
    """Hybrid key exchange key pair."""

    x25519_private: bytes
    x25519_public: bytes
    mlkem_private: bytes
    mlkem_public: bytes
    mode: HybridKEXMode
    key_id: str


@dataclass
class HybridKEXEncapsulation:
    """Result of hybrid key encapsulation."""

    x25519_public: bytes  # Ephemeral X25519 public key from sender
    mlkem_ciphertext: bytes  # ML-KEM ciphertext
    mode: HybridKEXMode


class HybridKeyExchange:
    """Hybrid key exchange combining X25519 and ML-KEM.

    This implements hybrid key exchange following NIST guidance for the
    post-quantum transition. The final shared secret is derived from
    both X25519 ECDH and ML-KEM using HKDF.

    Security Properties:
    - Forward secrecy: New ephemeral X25519 key per encapsulation
    - Hybrid security: Secure if either X25519 OR ML-KEM is secure
    - NIST compliant: Uses FIPS 203 ML-KEM

    Example:
        # Recipient generates key pair and shares public keys
        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()
        # Share keypair.x25519_public and keypair.mlkem_public with sender

        # Sender encapsulates (creates shared secret)
        encap, shared_secret_sender = kex.encapsulate(
            keypair.x25519_public, keypair.mlkem_public
        )
        # Send encap to recipient

        # Recipient decapsulates (recovers shared secret)
        shared_secret_recipient = kex.decapsulate(encap, keypair)

        # Both parties now have the same 32-byte shared secret
        assert shared_secret_sender == shared_secret_recipient
    """

    MLKEM_VARIANTS = {
        HybridKEXMode.X25519_MLKEM_768: "ML-KEM-768",
        HybridKEXMode.X25519_MLKEM_1024: "ML-KEM-1024",
    }

    def __init__(self, mode: HybridKEXMode = HybridKEXMode.X25519_MLKEM_768):
        if not is_pqc_available():
            raise PQCError("liboqs required for hybrid key exchange")
        self.mode = mode
        self._mlkem_variant = self.MLKEM_VARIANTS[mode]

    def generate_keypair(self) -> HybridKEXKeyPair:
        """Generate hybrid key pair (X25519 + ML-KEM).

        Returns:
            HybridKEXKeyPair containing both classical and PQC keys
        """
        # Generate X25519 key pair
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()

        x25519_private_bytes = x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        x25519_public_bytes = x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # Generate ML-KEM key pair
        kem = get_mlkem(self._mlkem_variant)
        mlkem_public = kem.generate_keypair()
        mlkem_private = kem.private_key

        key_id = secrets.token_hex(16)

        return HybridKEXKeyPair(
            x25519_private=x25519_private_bytes,
            x25519_public=x25519_public_bytes,
            mlkem_private=mlkem_private,
            mlkem_public=mlkem_public,
            mode=self.mode,
            key_id=key_id,
        )

    def encapsulate(
        self,
        recipient_x25519_public: bytes,
        recipient_mlkem_public: bytes,
    ) -> tuple[HybridKEXEncapsulation, bytes]:
        """Encapsulate to create shared secret.

        This performs:
        1. Ephemeral X25519 key generation and ECDH with recipient
        2. ML-KEM encapsulation with recipient's public key
        3. HKDF combination of both shared secrets

        Args:
            recipient_x25519_public: Recipient's X25519 public key (32 bytes)
            recipient_mlkem_public: Recipient's ML-KEM public key

        Returns:
            Tuple of (encapsulation_data, shared_secret)
            - encapsulation_data: Send to recipient for decapsulation
            - shared_secret: 32-byte key for symmetric encryption
        """
        # X25519 key exchange with ephemeral key
        ephemeral_x25519 = X25519PrivateKey.generate()
        ephemeral_x25519_public = ephemeral_x25519.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        recipient_x25519 = X25519PublicKey.from_public_bytes(recipient_x25519_public)
        x25519_shared = ephemeral_x25519.exchange(recipient_x25519)

        # ML-KEM encapsulation
        kem = get_mlkem(self._mlkem_variant)
        mlkem_ciphertext, mlkem_shared = kem.encap_secret(recipient_mlkem_public)

        # Combine shared secrets using HKDF
        combined = x25519_shared + mlkem_shared
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid-kex-v1",
            info=self.mode.value.encode(),
        ).derive(combined)

        encap = HybridKEXEncapsulation(
            x25519_public=ephemeral_x25519_public,
            mlkem_ciphertext=mlkem_ciphertext,
            mode=self.mode,
        )

        return encap, shared_secret

    def decapsulate(
        self,
        encapsulation: HybridKEXEncapsulation,
        keypair: HybridKEXKeyPair,
    ) -> bytes:
        """Decapsulate to recover shared secret.

        This performs:
        1. X25519 ECDH with sender's ephemeral public key
        2. ML-KEM decapsulation
        3. HKDF combination of both shared secrets

        Args:
            encapsulation: Encapsulation data from sender
            keypair: Recipient's hybrid key pair

        Returns:
            Shared secret (32 bytes)
        """
        if encapsulation.mode != keypair.mode:
            raise PQCError(f"Mode mismatch: {encapsulation.mode} vs {keypair.mode}")

        # X25519 key exchange
        x25519_private = X25519PrivateKey.from_private_bytes(keypair.x25519_private)
        sender_x25519_public = X25519PublicKey.from_public_bytes(encapsulation.x25519_public)
        x25519_shared = x25519_private.exchange(sender_x25519_public)

        # ML-KEM decapsulation
        kem = get_mlkem(self._mlkem_variant)
        kem.set_keypair(keypair.mlkem_public, keypair.mlkem_private)
        mlkem_shared = kem.decap_secret(encapsulation.mlkem_ciphertext)

        # Combine shared secrets using HKDF
        combined = x25519_shared + mlkem_shared
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid-kex-v1",
            info=encapsulation.mode.value.encode(),
        ).derive(combined)

        return shared_secret

    def serialize_encapsulation(self, encap: HybridKEXEncapsulation) -> bytes:
        """Serialize encapsulation for transmission.

        Format: header_len (2 bytes) + header_json + x25519_public + mlkem_ciphertext

        Args:
            encap: Encapsulation data to serialize

        Returns:
            Serialized bytes for transmission
        """
        header = {
            "mode": encap.mode.value,
            "x25519_len": len(encap.x25519_public),
            "mlkem_len": len(encap.mlkem_ciphertext),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(2, "big")

        return header_len + header_json + encap.x25519_public + encap.mlkem_ciphertext

    @staticmethod
    def deserialize_encapsulation(data: bytes) -> HybridKEXEncapsulation:
        """Deserialize encapsulation from bytes.

        Args:
            data: Serialized encapsulation bytes

        Returns:
            HybridKEXEncapsulation object
        """
        if len(data) < 2:
            raise ValueError("Invalid encapsulation data: too short")

        header_len = int.from_bytes(data[:2], "big")
        if len(data) < 2 + header_len:
            raise ValueError("Invalid encapsulation data: header truncated")

        header = json.loads(data[2 : 2 + header_len].decode())

        offset = 2 + header_len
        x25519_public = data[offset : offset + header["x25519_len"]]
        offset += header["x25519_len"]
        mlkem_ciphertext = data[offset : offset + header["mlkem_len"]]

        return HybridKEXEncapsulation(
            x25519_public=x25519_public,
            mlkem_ciphertext=mlkem_ciphertext,
            mode=HybridKEXMode(header["mode"]),
        )

    def serialize_keypair(self, keypair: HybridKEXKeyPair) -> dict:
        """Serialize keypair for storage.

        Args:
            keypair: Key pair to serialize

        Returns:
            Dictionary suitable for JSON serialization
        """
        import base64

        return {
            "mode": keypair.mode.value,
            "key_id": keypair.key_id,
            "x25519_private": base64.b64encode(keypair.x25519_private).decode(),
            "x25519_public": base64.b64encode(keypair.x25519_public).decode(),
            "mlkem_private": base64.b64encode(keypair.mlkem_private).decode(),
            "mlkem_public": base64.b64encode(keypair.mlkem_public).decode(),
        }

    @staticmethod
    def deserialize_keypair(data: dict) -> HybridKEXKeyPair:
        """Deserialize keypair from storage.

        Args:
            data: Serialized keypair dictionary

        Returns:
            HybridKEXKeyPair object
        """
        import base64

        return HybridKEXKeyPair(
            mode=HybridKEXMode(data["mode"]),
            key_id=data["key_id"],
            x25519_private=base64.b64decode(data["x25519_private"]),
            x25519_public=base64.b64decode(data["x25519_public"]),
            mlkem_private=base64.b64decode(data["mlkem_private"]),
            mlkem_public=base64.b64decode(data["mlkem_public"]),
        )


# Convenience functions


def hybrid_key_exchange(mode: HybridKEXMode = HybridKEXMode.X25519_MLKEM_768) -> HybridKeyExchange:
    """Create a hybrid key exchange instance.

    Args:
        mode: Key exchange mode (default: X25519+ML-KEM-768)

    Returns:
        HybridKeyExchange instance
    """
    return HybridKeyExchange(mode)


def get_hybrid_kex_info(mode: HybridKEXMode) -> dict:
    """Get information about a hybrid key exchange mode.

    Args:
        mode: Hybrid KEX mode

    Returns:
        Dictionary with mode details
    """
    info = {
        HybridKEXMode.X25519_MLKEM_768: {
            "name": "X25519 + ML-KEM-768",
            "classical_algorithm": "X25519 (Curve25519 ECDH)",
            "pqc_algorithm": "ML-KEM-768 (FIPS 203)",
            "classical_security_bits": 128,
            "quantum_security_bits": 192,
            "nist_pqc_level": 3,
            "x25519_public_key_bytes": 32,
            "mlkem_public_key_bytes": 1184,
            "mlkem_ciphertext_bytes": 1088,
            "shared_secret_bytes": 32,
            "recommended_for": ["general use", "TLS hybrid", "key agreement"],
        },
        HybridKEXMode.X25519_MLKEM_1024: {
            "name": "X25519 + ML-KEM-1024",
            "classical_algorithm": "X25519 (Curve25519 ECDH)",
            "pqc_algorithm": "ML-KEM-1024 (FIPS 203)",
            "classical_security_bits": 128,
            "quantum_security_bits": 256,
            "nist_pqc_level": 5,
            "x25519_public_key_bytes": 32,
            "mlkem_public_key_bytes": 1568,
            "mlkem_ciphertext_bytes": 1568,
            "shared_secret_bytes": 32,
            "recommended_for": ["maximum security", "long-term key agreement", "government"],
        },
    }
    return info.get(mode, {})
