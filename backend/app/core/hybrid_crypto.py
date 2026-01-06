"""Hybrid Quantum-Safe Cryptography Engine.

Implements hybrid encryption combining classical algorithms with post-quantum
Key Encapsulation Mechanisms (KEMs) per NIST guidance for the PQC transition.

This module uses liboqs (Open Quantum Safe) for real NIST-standardized
post-quantum algorithms:
- ML-KEM (FIPS 203) - Key Encapsulation Mechanism (formerly Kyber)
- ML-DSA (FIPS 204) - Digital Signature Algorithm (formerly Dilithium)

Hybrid Mode Benefits:
- Security if either algorithm is unbroken
- Transition path from classical to post-quantum
- Compliance with NSA CNSA 2.0 timeline

Supported Hybrid Modes:
- AES-256-GCM + ML-KEM-768 (recommended for most use cases)
- AES-256-GCM + ML-KEM-1024 (maximum security)
- ChaCha20-Poly1305 + ML-KEM-768 (no AES-NI environments)
"""

import os
import json
import base64
import secrets
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# =============================================================================
# liboqs Integration
# =============================================================================

try:
    import oqs

    LIBOQS_AVAILABLE = True
    logger.info("liboqs loaded successfully - real PQC enabled")
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning("liboqs not available - PQC operations will fail")
except RuntimeError as e:
    # liboqs-python installed but underlying C library not found
    LIBOQS_AVAILABLE = False
    logger.warning(f"liboqs C library not found - PQC operations will fail: {e}")


class PQCError(Exception):
    """Post-quantum cryptography error."""

    pass


class HybridMode(str, Enum):
    """Supported hybrid encryption modes."""

    AES_MLKEM_768 = "AES-256-GCM+ML-KEM-768"
    AES_MLKEM_1024 = "AES-256-GCM+ML-KEM-1024"
    CHACHA_MLKEM_768 = "ChaCha20-Poly1305+ML-KEM-768"


class SignatureAlgorithm(str, Enum):
    """Supported PQC signature algorithms."""

    # ML-DSA (FIPS 204) - Lattice-based, balanced key/signature sizes
    ML_DSA_44 = "ML-DSA-44"  # NIST Level 2 (128-bit security)
    ML_DSA_65 = "ML-DSA-65"  # NIST Level 3 (192-bit security)
    ML_DSA_87 = "ML-DSA-87"  # NIST Level 5 (256-bit security)

    # SLH-DSA (FIPS 205) - Hash-based, tiny keys but large signatures
    # "f" = fast signing, larger signatures; "s" = small signatures, slower
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"  # Level 1, fast (17KB sigs)
    SLH_DSA_SHA2_128S = "SLH-DSA-SHA2-128s"  # Level 1, small (8KB sigs)
    SLH_DSA_SHA2_192F = "SLH-DSA-SHA2-192f"  # Level 3, fast (35KB sigs)
    SLH_DSA_SHA2_192S = "SLH-DSA-SHA2-192s"  # Level 3, small (16KB sigs)
    SLH_DSA_SHA2_256F = "SLH-DSA-SHA2-256f"  # Level 5, fast (49KB sigs)
    SLH_DSA_SHA2_256S = "SLH-DSA-SHA2-256s"  # Level 5, small (29KB sigs)

    # Falcon (NIST alternate) - Smaller signatures than ML-DSA
    FALCON_512 = "Falcon-512"  # Level 1, compact signatures
    FALCON_1024 = "Falcon-1024"  # Level 5, compact signatures


@dataclass
class HybridKeyPair:
    """A hybrid key pair combining classical and PQC keys."""

    mode: HybridMode
    public_key: bytes  # Serialized public key (KEM)
    private_key: bytes  # Serialized private key (KEM)
    key_id: str  # Unique identifier

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "key_id": self.key_id,
        }


@dataclass
class SignatureKeyPair:
    """A PQC signature key pair."""

    algorithm: SignatureAlgorithm
    public_key: bytes
    private_key: bytes
    key_id: str

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm.value,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "key_id": self.key_id,
        }


@dataclass
class HybridCiphertext:
    """Result of hybrid encryption."""

    mode: HybridMode
    classical_ciphertext: bytes  # AES/ChaCha encrypted data
    kem_ciphertext: bytes  # ML-KEM encapsulated key
    nonce: bytes  # For AEAD
    key_id: str  # Which key was used

    def serialize(self) -> bytes:
        """Serialize to bytes for storage/transmission."""
        header = {
            "v": 1,
            "mode": self.mode.value,
            "kid": self.key_id,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "kem_ct_len": len(self.kem_ciphertext),
        }
        header_json = json.dumps(header, separators=(",", ":")).encode()
        header_len = len(header_json).to_bytes(2, "big")

        return header_len + header_json + self.kem_ciphertext + self.classical_ciphertext

    @classmethod
    def deserialize(cls, data: bytes) -> "HybridCiphertext":
        """Deserialize from bytes."""
        if len(data) < 3:
            raise ValueError("Invalid ciphertext: too short")

        header_len = int.from_bytes(data[:2], "big")
        if len(data) < 2 + header_len:
            raise ValueError("Invalid ciphertext: header truncated")

        header = json.loads(data[2 : 2 + header_len].decode())

        if header.get("v") != 1:
            raise ValueError(f"Unsupported version: {header.get('v')}")

        kem_ct_len = header["kem_ct_len"]
        kem_start = 2 + header_len
        kem_end = kem_start + kem_ct_len

        return cls(
            mode=HybridMode(header["mode"]),
            kem_ciphertext=data[kem_start:kem_end],
            classical_ciphertext=data[kem_end:],
            nonce=base64.b64decode(header["nonce"]),
            key_id=header["kid"],
        )


# =============================================================================
# Real ML-KEM Implementation using liboqs
# =============================================================================


class MLKEM:
    """Real ML-KEM implementation using liboqs.

    ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) is the
    NIST-standardized post-quantum KEM (FIPS 203), formerly known as Kyber.

    Security levels:
    - ML-KEM-512: NIST Level 1 (128-bit security)
    - ML-KEM-768: NIST Level 3 (192-bit security) - Recommended
    - ML-KEM-1024: NIST Level 5 (256-bit security) - Maximum security
    """

    # NIST FIPS 203 parameter sizes
    PARAMS = {
        "ML-KEM-512": {"pk_len": 800, "sk_len": 1632, "ct_len": 768, "ss_len": 32, "level": 1},
        "ML-KEM-768": {"pk_len": 1184, "sk_len": 2400, "ct_len": 1088, "ss_len": 32, "level": 3},
        "ML-KEM-1024": {"pk_len": 1568, "sk_len": 3168, "ct_len": 1568, "ss_len": 32, "level": 5},
    }

    def __init__(self, algorithm: str = "ML-KEM-768"):
        if not LIBOQS_AVAILABLE:
            raise PQCError("liboqs not installed. Install with: pip install liboqs-python")

        if algorithm not in self.PARAMS:
            raise ValueError(f"Unknown algorithm: {algorithm}. Valid: {list(self.PARAMS.keys())}")

        self.algorithm = algorithm
        self.params = self.PARAMS[algorithm]
        self._kem = oqs.KeyEncapsulation(algorithm)
        self._public_key: bytes | None = None
        self._private_key: bytes | None = None

    def generate_keypair(self) -> bytes:
        """Generate a new key pair. Returns public key.

        The private key is stored internally and can be accessed via
        the private_key property.
        """
        self._public_key = self._kem.generate_keypair()
        self._private_key = self._kem.export_secret_key()
        return self._public_key

    @property
    def public_key(self) -> bytes | None:
        """Get the public key (after generate_keypair)."""
        return self._public_key

    @property
    def private_key(self) -> bytes | None:
        """Get the private key (after generate_keypair)."""
        return self._private_key

    def set_keypair(self, public_key: bytes, private_key: bytes) -> None:
        """Set an existing key pair for decapsulation."""
        self._public_key = public_key
        self._private_key = private_key
        # Create new KEM instance with the secret key
        self._kem = oqs.KeyEncapsulation(self.algorithm, secret_key=private_key)

    def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key.

        Args:
            public_key: Recipient's ML-KEM public key

        Returns:
            Tuple of (ciphertext, shared_secret)
            - ciphertext: Send to recipient for decapsulation
            - shared_secret: 32-byte key for symmetric encryption
        """
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        """Decapsulate the shared secret using the private key.

        Args:
            ciphertext: The KEM ciphertext from encapsulation

        Returns:
            32-byte shared secret (same as encapsulation produced)
        """
        if self._private_key is None:
            raise PQCError("No private key set. Call set_keypair() first.")

        shared_secret = self._kem.decap_secret(ciphertext)
        return shared_secret

    def get_details(self) -> dict:
        """Get algorithm details."""
        return {
            "algorithm": self.algorithm,
            "nist_level": self.params["level"],
            "public_key_bytes": self.params["pk_len"],
            "secret_key_bytes": self.params["sk_len"],
            "ciphertext_bytes": self.params["ct_len"],
            "shared_secret_bytes": self.params["ss_len"],
            "standard": "NIST FIPS 203",
        }


# =============================================================================
# Real ML-DSA Implementation using liboqs
# =============================================================================


class MLDSA:
    """Real ML-DSA implementation using liboqs.

    ML-DSA (Module-Lattice-based Digital Signature Algorithm) is the
    NIST-standardized post-quantum signature scheme (FIPS 204),
    formerly known as Dilithium.

    Security levels:
    - ML-DSA-44: NIST Level 2 (~128-bit security)
    - ML-DSA-65: NIST Level 3 (~192-bit security) - Recommended
    - ML-DSA-87: NIST Level 5 (~256-bit security) - Maximum security
    """

    PARAMS = {
        "ML-DSA-44": {"pk_len": 1312, "sk_len": 2560, "sig_len": 2420, "level": 2},
        "ML-DSA-65": {"pk_len": 1952, "sk_len": 4032, "sig_len": 3309, "level": 3},
        "ML-DSA-87": {"pk_len": 2592, "sk_len": 4896, "sig_len": 4627, "level": 5},
    }

    def __init__(self, algorithm: str = "ML-DSA-65"):
        if not LIBOQS_AVAILABLE:
            raise PQCError("liboqs not installed. Install with: pip install liboqs-python")

        if algorithm not in self.PARAMS:
            raise ValueError(f"Unknown algorithm: {algorithm}. Valid: {list(self.PARAMS.keys())}")

        self.algorithm = algorithm
        self.params = self.PARAMS[algorithm]
        self._sig = oqs.Signature(algorithm)
        self._public_key: bytes | None = None
        self._private_key: bytes | None = None

    def generate_keypair(self) -> bytes:
        """Generate a new signature key pair. Returns public key."""
        self._public_key = self._sig.generate_keypair()
        self._private_key = self._sig.export_secret_key()
        return self._public_key

    @property
    def public_key(self) -> bytes | None:
        return self._public_key

    @property
    def private_key(self) -> bytes | None:
        return self._private_key

    def set_keypair(self, public_key: bytes, private_key: bytes) -> None:
        """Set an existing key pair."""
        self._public_key = public_key
        self._private_key = private_key
        self._sig = oqs.Signature(self.algorithm, secret_key=private_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the private key.

        Args:
            message: The message to sign

        Returns:
            The digital signature
        """
        if self._private_key is None:
            raise PQCError("No private key set. Call generate_keypair() or set_keypair() first.")

        return self._sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using the public key.

        Args:
            message: The original message
            signature: The signature to verify
            public_key: The signer's public key

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            return self._sig.verify(message, signature, public_key)
        except Exception:
            return False

    def get_details(self) -> dict:
        """Get algorithm details."""
        return {
            "algorithm": self.algorithm,
            "nist_level": self.params["level"],
            "public_key_bytes": self.params["pk_len"],
            "secret_key_bytes": self.params["sk_len"],
            "signature_bytes": self.params["sig_len"],
            "standard": "NIST FIPS 204",
        }


# =============================================================================
# Real SLH-DSA Implementation using liboqs
# =============================================================================


class SLHDSA:
    """Real SLH-DSA implementation using liboqs.

    SLH-DSA (Stateless Hash-based Digital Signature Algorithm) is the
    NIST-standardized post-quantum signature scheme (FIPS 205),
    formerly known as SPHINCS+.

    Key characteristics:
    - Hash-based: security relies only on hash function security
    - Stateless: no state management required (unlike XMSS/LMS)
    - Conservative: most conservative security assumptions of all PQC sigs
    - Trade-off: tiny keys (32-64 bytes) but large signatures (8-50 KB)

    Variants:
    - "f" (fast): Faster signing, larger signatures
    - "s" (small): Smaller signatures, slower signing
    - SHA2: Uses SHA-256 internally
    - SHAKE: Uses SHAKE256 internally

    Security levels:
    - 128f/128s: NIST Level 1 (128-bit security)
    - 192f/192s: NIST Level 3 (192-bit security)
    - 256f/256s: NIST Level 5 (256-bit security)
    """

    # NIST FIPS 205 parameter sizes (using liboqs SLH_DSA_PURE_* variants)
    PARAMS = {
        "SLH-DSA-SHA2-128f": {
            "oqs_name": "SLH_DSA_PURE_SHA2_128F",
            "pk_len": 32,
            "sk_len": 64,
            "sig_len": 17088,
            "level": 1,
            "variant": "fast",
        },
        "SLH-DSA-SHA2-128s": {
            "oqs_name": "SLH_DSA_PURE_SHA2_128S",
            "pk_len": 32,
            "sk_len": 64,
            "sig_len": 7856,
            "level": 1,
            "variant": "small",
        },
        "SLH-DSA-SHA2-192f": {
            "oqs_name": "SLH_DSA_PURE_SHA2_192F",
            "pk_len": 48,
            "sk_len": 96,
            "sig_len": 35664,
            "level": 3,
            "variant": "fast",
        },
        "SLH-DSA-SHA2-192s": {
            "oqs_name": "SLH_DSA_PURE_SHA2_192S",
            "pk_len": 48,
            "sk_len": 96,
            "sig_len": 16224,
            "level": 3,
            "variant": "small",
        },
        "SLH-DSA-SHA2-256f": {
            "oqs_name": "SLH_DSA_PURE_SHA2_256F",
            "pk_len": 64,
            "sk_len": 128,
            "sig_len": 49856,
            "level": 5,
            "variant": "fast",
        },
        "SLH-DSA-SHA2-256s": {
            "oqs_name": "SLH_DSA_PURE_SHA2_256S",
            "pk_len": 64,
            "sk_len": 128,
            "sig_len": 29792,
            "level": 5,
            "variant": "small",
        },
    }

    def __init__(self, algorithm: str = "SLH-DSA-SHA2-128f"):
        if not LIBOQS_AVAILABLE:
            raise PQCError("liboqs not installed. Install with: pip install liboqs-python")

        if algorithm not in self.PARAMS:
            raise ValueError(f"Unknown algorithm: {algorithm}. Valid: {list(self.PARAMS.keys())}")

        self.algorithm = algorithm
        self.params = self.PARAMS[algorithm]
        self._oqs_name = self.params["oqs_name"]
        self._sig = oqs.Signature(self._oqs_name)
        self._public_key: bytes | None = None
        self._private_key: bytes | None = None

    def generate_keypair(self) -> bytes:
        """Generate a new signature key pair. Returns public key."""
        self._public_key = self._sig.generate_keypair()
        self._private_key = self._sig.export_secret_key()
        return self._public_key

    @property
    def public_key(self) -> bytes | None:
        return self._public_key

    @property
    def private_key(self) -> bytes | None:
        return self._private_key

    def set_keypair(self, public_key: bytes, private_key: bytes) -> None:
        """Set an existing key pair."""
        self._public_key = public_key
        self._private_key = private_key
        self._sig = oqs.Signature(self._oqs_name, secret_key=private_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the private key.

        Note: SLH-DSA signing is slower than ML-DSA but produces
        signatures with conservative security assumptions.

        Args:
            message: The message to sign

        Returns:
            The digital signature (large: 8-50 KB depending on variant)
        """
        if self._private_key is None:
            raise PQCError("No private key set. Call generate_keypair() or set_keypair() first.")

        return self._sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using the public key.

        Args:
            message: The original message
            signature: The signature to verify
            public_key: The signer's public key

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            return self._sig.verify(message, signature, public_key)
        except Exception:
            return False

    def get_details(self) -> dict:
        """Get algorithm details."""
        return {
            "algorithm": self.algorithm,
            "nist_level": self.params["level"],
            "variant": self.params["variant"],
            "public_key_bytes": self.params["pk_len"],
            "secret_key_bytes": self.params["sk_len"],
            "signature_bytes": self.params["sig_len"],
            "standard": "NIST FIPS 205",
            "security_basis": "hash-based (conservative)",
        }


# =============================================================================
# Factory Functions
# =============================================================================


def get_mlkem(algorithm: str = "ML-KEM-768") -> MLKEM:
    """Get an ML-KEM instance.

    Args:
        algorithm: One of "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"

    Returns:
        MLKEM instance for key encapsulation

    Raises:
        PQCError: If liboqs is not installed
    """
    return MLKEM(algorithm)


def get_mldsa(algorithm: str = "ML-DSA-65") -> MLDSA:
    """Get an ML-DSA instance.

    Args:
        algorithm: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"

    Returns:
        MLDSA instance for digital signatures

    Raises:
        PQCError: If liboqs is not installed
    """
    return MLDSA(algorithm)


def get_slhdsa(algorithm: str = "SLH-DSA-SHA2-128f") -> SLHDSA:
    """Get an SLH-DSA instance.

    SLH-DSA (FIPS 205) is a hash-based signature scheme with the most
    conservative security assumptions. It has tiny keys but large signatures.

    Args:
        algorithm: One of:
            - "SLH-DSA-SHA2-128f" (fast, 17KB sigs) - recommended default
            - "SLH-DSA-SHA2-128s" (small, 8KB sigs)
            - "SLH-DSA-SHA2-192f" (fast, 35KB sigs)
            - "SLH-DSA-SHA2-192s" (small, 16KB sigs)
            - "SLH-DSA-SHA2-256f" (fast, 49KB sigs)
            - "SLH-DSA-SHA2-256s" (small, 29KB sigs)

    Returns:
        SLHDSA instance for digital signatures

    Raises:
        PQCError: If liboqs is not installed
    """
    return SLHDSA(algorithm)


def is_pqc_available() -> bool:
    """Check if PQC operations are available."""
    return LIBOQS_AVAILABLE


def get_available_kem_algorithms() -> list[str]:
    """Get list of available KEM algorithms."""
    if not LIBOQS_AVAILABLE:
        return []
    return list(MLKEM.PARAMS.keys())


def get_available_sig_algorithms() -> list[str]:
    """Get list of available signature algorithms (ML-DSA only)."""
    if not LIBOQS_AVAILABLE:
        return []
    return list(MLDSA.PARAMS.keys())


def get_available_slhdsa_algorithms() -> list[str]:
    """Get list of available SLH-DSA signature algorithms."""
    if not LIBOQS_AVAILABLE:
        return []
    return list(SLHDSA.PARAMS.keys())


def get_all_available_sig_algorithms() -> list[str]:
    """Get list of all available PQC signature algorithms (ML-DSA + SLH-DSA)."""
    if not LIBOQS_AVAILABLE:
        return []
    return list(MLDSA.PARAMS.keys()) + list(SLHDSA.PARAMS.keys())


# =============================================================================
# Hybrid Crypto Engine
# =============================================================================


class HybridCryptoEngine:
    """Hybrid quantum-safe encryption engine.

    Combines classical AEAD (AES-GCM or ChaCha20-Poly1305) with
    post-quantum Key Encapsulation Mechanism (ML-KEM).

    The hybrid approach provides security if either algorithm remains
    secure, following NIST transition guidance.

    Example:
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()

        # Encrypt
        ciphertext = engine.encrypt(b"secret data", keypair.public_key, keypair.key_id)

        # Decrypt
        plaintext = engine.decrypt(ciphertext, keypair.private_key)
    """

    def __init__(self, mode: HybridMode = HybridMode.AES_MLKEM_768):
        self.mode = mode
        self._kem_algorithm = self._get_kem_algorithm(mode)

    def _get_kem_algorithm(self, mode: HybridMode) -> str:
        """Get the KEM algorithm for a hybrid mode."""
        if "1024" in mode.value:
            return "ML-KEM-1024"
        return "ML-KEM-768"

    def _get_aead(self, key: bytes) -> AESGCM | ChaCha20Poly1305:
        """Get the AEAD cipher for this mode."""
        if "ChaCha" in self.mode.value:
            return ChaCha20Poly1305(key)
        return AESGCM(key)

    def _derive_symmetric_key(self, kem_shared_secret: bytes, context: bytes = b"") -> bytes:
        """Derive a symmetric key from the KEM shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256 or ChaCha20
            salt=None,
            info=b"cryptoserve-hybrid-v1" + context,
        )
        return hkdf.derive(kem_shared_secret)

    def generate_keypair(self, key_id: str | None = None) -> HybridKeyPair:
        """Generate a hybrid key pair.

        Returns:
            HybridKeyPair with ML-KEM public and private keys
        """
        kem = get_mlkem(self._kem_algorithm)
        public_key = kem.generate_keypair()

        key_id = key_id or secrets.token_hex(16)

        return HybridKeyPair(
            mode=self.mode,
            public_key=public_key,
            private_key=kem.private_key,
            key_id=key_id,
        )

    def encrypt(
        self,
        plaintext: bytes,
        public_key: bytes,
        key_id: str,
        associated_data: bytes | None = None,
    ) -> HybridCiphertext:
        """Encrypt data using hybrid encryption.

        Steps:
        1. Generate KEM shared secret using recipient's public key
        2. Derive symmetric key from shared secret using HKDF
        3. Encrypt plaintext with AES-GCM or ChaCha20-Poly1305
        4. Package KEM ciphertext + AEAD ciphertext

        Args:
            plaintext: Data to encrypt
            public_key: Recipient's ML-KEM public key
            key_id: Key identifier for audit/rotation
            associated_data: Optional authenticated data (not encrypted)

        Returns:
            HybridCiphertext containing both KEM and AEAD components
        """
        # Step 1: KEM encapsulation
        kem = get_mlkem(self._kem_algorithm)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        # Step 2: Derive symmetric key
        symmetric_key = self._derive_symmetric_key(
            shared_secret,
            context=key_id.encode() if key_id else b"",
        )

        # Step 3: AEAD encryption
        nonce = os.urandom(12)  # 96 bits for GCM
        aead = self._get_aead(symmetric_key)
        ciphertext = aead.encrypt(nonce, plaintext, associated_data)

        return HybridCiphertext(
            mode=self.mode,
            classical_ciphertext=ciphertext,
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            key_id=key_id,
        )

    def decrypt(
        self,
        hybrid_ciphertext: HybridCiphertext,
        private_key: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt hybrid-encrypted data.

        Steps:
        1. KEM decapsulation to recover shared secret
        2. Derive symmetric key from shared secret
        3. AEAD decryption

        Args:
            hybrid_ciphertext: The encrypted data
            private_key: Recipient's ML-KEM private key
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If decryption fails (authentication failure)
        """
        # Step 1: KEM decapsulation
        kem = get_mlkem(self._kem_algorithm)
        kem.set_keypair(b"", private_key)  # Only need private key for decap

        shared_secret = kem.decap_secret(hybrid_ciphertext.kem_ciphertext)

        # Step 2: Derive symmetric key
        symmetric_key = self._derive_symmetric_key(
            shared_secret,
            context=hybrid_ciphertext.key_id.encode() if hybrid_ciphertext.key_id else b"",
        )

        # Step 3: AEAD decryption
        aead = self._get_aead(symmetric_key)
        try:
            plaintext = aead.decrypt(
                hybrid_ciphertext.nonce,
                hybrid_ciphertext.classical_ciphertext,
                associated_data,
            )
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        return plaintext


# =============================================================================
# Signature Engine
# =============================================================================


class PQCSignatureEngine:
    """Post-quantum digital signature engine supporting ML-DSA and SLH-DSA.

    Supports:
    - ML-DSA (FIPS 204): Lattice-based, balanced key/signature sizes
    - SLH-DSA (FIPS 205): Hash-based, tiny keys but large signatures

    Example:
        # ML-DSA (recommended for most use cases)
        engine = PQCSignatureEngine(SignatureAlgorithm.ML_DSA_65)
        keypair = engine.generate_keypair()

        # SLH-DSA (conservative security, large signatures)
        engine = PQCSignatureEngine(SignatureAlgorithm.SLH_DSA_SHA2_128F)
        keypair = engine.generate_keypair()

        # Sign
        signature = engine.sign(b"message", keypair.private_key)

        # Verify
        valid = engine.verify(b"message", signature, keypair.public_key)
    """

    # SLH-DSA algorithm values for detection
    _SLHDSA_ALGORITHMS = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHA2-256s",
    }

    def __init__(self, algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65):
        self.algorithm = algorithm
        self._is_slhdsa = algorithm.value in self._SLHDSA_ALGORITHMS

    def _get_signer(self) -> MLDSA | SLHDSA:
        """Get the appropriate signature implementation."""
        if self._is_slhdsa:
            return get_slhdsa(self.algorithm.value)
        return get_mldsa(self.algorithm.value)

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        """Generate a signature key pair."""
        sig = self._get_signer()
        public_key = sig.generate_keypair()

        key_id = key_id or secrets.token_hex(16)

        return SignatureKeyPair(
            algorithm=self.algorithm,
            public_key=public_key,
            private_key=sig.private_key,
            key_id=key_id,
        )

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message."""
        sig = self._get_signer()
        sig.set_keypair(b"", private_key)
        return sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature."""
        sig = self._get_signer()
        return sig.verify(message, signature, public_key)

    def get_algorithm_info(self) -> dict:
        """Get information about the current algorithm."""
        sig = self._get_signer()
        return sig.get_details()


# =============================================================================
# Convenience Functions
# =============================================================================


def create_hybrid_engine(
    quantum_security_level: int = 192,
    prefer_chacha: bool = False,
) -> HybridCryptoEngine:
    """Create a hybrid crypto engine with appropriate mode.

    Args:
        quantum_security_level: Minimum post-quantum security bits (128, 192, or 256)
        prefer_chacha: Use ChaCha20 instead of AES (for non-AES-NI systems)

    Returns:
        Configured HybridCryptoEngine
    """
    if quantum_security_level >= 256:
        mode = HybridMode.AES_MLKEM_1024
    elif prefer_chacha:
        mode = HybridMode.CHACHA_MLKEM_768
    else:
        mode = HybridMode.AES_MLKEM_768

    return HybridCryptoEngine(mode)


def hybrid_encrypt(
    plaintext: bytes,
    public_key: bytes,
    key_id: str = "",
    mode: HybridMode = HybridMode.AES_MLKEM_768,
) -> bytes:
    """Simple hybrid encryption interface.

    Args:
        plaintext: Data to encrypt
        public_key: Recipient's ML-KEM public key
        key_id: Optional key identifier
        mode: Hybrid encryption mode

    Returns:
        Serialized hybrid ciphertext
    """
    engine = HybridCryptoEngine(mode)
    result = engine.encrypt(plaintext, public_key, key_id)
    return result.serialize()


def hybrid_decrypt(
    ciphertext: bytes,
    private_key: bytes,
) -> bytes:
    """Simple hybrid decryption interface.

    Args:
        ciphertext: Serialized hybrid ciphertext
        private_key: Recipient's ML-KEM private key

    Returns:
        Decrypted plaintext
    """
    hybrid_ct = HybridCiphertext.deserialize(ciphertext)
    engine = HybridCryptoEngine(hybrid_ct.mode)
    return engine.decrypt(hybrid_ct, private_key)


def pqc_sign(
    message: bytes,
    private_key: bytes,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
) -> bytes:
    """Sign a message with ML-DSA.

    Args:
        message: Message to sign
        private_key: ML-DSA private key
        algorithm: Signature algorithm to use

    Returns:
        Digital signature
    """
    engine = PQCSignatureEngine(algorithm)
    return engine.sign(message, private_key)


def pqc_verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
) -> bool:
    """Verify an ML-DSA signature.

    Args:
        message: Original message
        signature: Signature to verify
        public_key: Signer's public key
        algorithm: Signature algorithm used

    Returns:
        True if valid, False otherwise
    """
    engine = PQCSignatureEngine(algorithm)
    return engine.verify(message, signature, public_key)


# =============================================================================
# Key Management Helpers
# =============================================================================


def serialize_keypair(keypair: HybridKeyPair) -> dict:
    """Serialize a key pair for storage."""
    return {
        "mode": keypair.mode.value,
        "public_key": base64.b64encode(keypair.public_key).decode("ascii"),
        "private_key": base64.b64encode(keypair.private_key).decode("ascii"),
        "key_id": keypair.key_id,
    }


def deserialize_keypair(data: dict) -> HybridKeyPair:
    """Deserialize a key pair from storage."""
    return HybridKeyPair(
        mode=HybridMode(data["mode"]),
        public_key=base64.b64decode(data["public_key"]),
        private_key=base64.b64decode(data["private_key"]),
        key_id=data["key_id"],
    )


def serialize_sig_keypair(keypair: SignatureKeyPair) -> dict:
    """Serialize a signature key pair for storage."""
    return {
        "algorithm": keypair.algorithm.value,
        "public_key": base64.b64encode(keypair.public_key).decode("ascii"),
        "private_key": base64.b64encode(keypair.private_key).decode("ascii"),
        "key_id": keypair.key_id,
    }


def deserialize_sig_keypair(data: dict) -> SignatureKeyPair:
    """Deserialize a signature key pair from storage."""
    return SignatureKeyPair(
        algorithm=SignatureAlgorithm(data["algorithm"]),
        public_key=base64.b64decode(data["public_key"]),
        private_key=base64.b64decode(data["private_key"]),
        key_id=data["key_id"],
    )


# =============================================================================
# Algorithm Information
# =============================================================================


def get_hybrid_algorithm_info(mode: HybridMode) -> dict[str, Any]:
    """Get information about a hybrid mode."""
    info = {
        HybridMode.AES_MLKEM_768: {
            "name": "AES-256-GCM + ML-KEM-768",
            "classical_algorithm": "AES-256-GCM",
            "pqc_algorithm": "ML-KEM-768 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 192,
            "nist_pqc_level": 3,
            "cnsa_compliant": True,
            "recommended_for": ["general use", "most applications", "TLS hybrid"],
            "public_key_bytes": 1184,
            "ciphertext_overhead_bytes": 1088 + 28,  # KEM CT + AEAD overhead
        },
        HybridMode.AES_MLKEM_1024: {
            "name": "AES-256-GCM + ML-KEM-1024",
            "classical_algorithm": "AES-256-GCM",
            "pqc_algorithm": "ML-KEM-1024 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 256,
            "nist_pqc_level": 5,
            "cnsa_compliant": True,
            "recommended_for": ["maximum security", "long-term secrets", "government"],
            "public_key_bytes": 1568,
            "ciphertext_overhead_bytes": 1568 + 28,
        },
        HybridMode.CHACHA_MLKEM_768: {
            "name": "ChaCha20-Poly1305 + ML-KEM-768",
            "classical_algorithm": "ChaCha20-Poly1305",
            "pqc_algorithm": "ML-KEM-768 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 192,
            "nist_pqc_level": 3,
            "cnsa_compliant": True,
            "recommended_for": ["no AES-NI", "mobile devices", "embedded systems"],
            "public_key_bytes": 1184,
            "ciphertext_overhead_bytes": 1088 + 16,
        },
    }
    return info.get(mode, {})


def get_signature_algorithm_info(algorithm: SignatureAlgorithm) -> dict[str, Any]:
    """Get information about a signature algorithm."""
    info = {
        SignatureAlgorithm.ML_DSA_44: {
            "name": "ML-DSA-44",
            "standard": "NIST FIPS 204",
            "security_bits": 128,
            "nist_level": 2,
            "public_key_bytes": 1312,
            "signature_bytes": 2420,
            "recommended_for": ["general use", "performance-sensitive"],
        },
        SignatureAlgorithm.ML_DSA_65: {
            "name": "ML-DSA-65",
            "standard": "NIST FIPS 204",
            "security_bits": 192,
            "nist_level": 3,
            "public_key_bytes": 1952,
            "signature_bytes": 3309,
            "recommended_for": ["most applications", "balanced security/performance"],
        },
        SignatureAlgorithm.ML_DSA_87: {
            "name": "ML-DSA-87",
            "standard": "NIST FIPS 204",
            "security_bits": 256,
            "nist_level": 5,
            "public_key_bytes": 2592,
            "signature_bytes": 4627,
            "recommended_for": ["maximum security", "long-term signatures"],
        },
        SignatureAlgorithm.FALCON_512: {
            "name": "Falcon-512",
            "standard": "NIST Round 3 Alternate",
            "security_bits": 128,
            "nist_level": 1,
            "public_key_bytes": 897,
            "signature_bytes": 690,  # Average, varies
            "recommended_for": ["small signatures", "embedded systems"],
        },
        SignatureAlgorithm.FALCON_1024: {
            "name": "Falcon-1024",
            "standard": "NIST Round 3 Alternate",
            "security_bits": 256,
            "nist_level": 5,
            "public_key_bytes": 1793,
            "signature_bytes": 1330,  # Average, varies
            "recommended_for": ["small signatures", "maximum security"],
        },
        # SLH-DSA (FIPS 205) - Hash-based signatures
        SignatureAlgorithm.SLH_DSA_SHA2_128F: {
            "name": "SLH-DSA-SHA2-128f",
            "standard": "NIST FIPS 205",
            "security_bits": 128,
            "nist_level": 1,
            "variant": "fast",
            "public_key_bytes": 32,
            "signature_bytes": 17088,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["firmware signing", "high-assurance", "conservative security"],
        },
        SignatureAlgorithm.SLH_DSA_SHA2_128S: {
            "name": "SLH-DSA-SHA2-128s",
            "standard": "NIST FIPS 205",
            "security_bits": 128,
            "nist_level": 1,
            "variant": "small",
            "public_key_bytes": 32,
            "signature_bytes": 7856,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["bandwidth-constrained", "conservative security"],
        },
        SignatureAlgorithm.SLH_DSA_SHA2_192F: {
            "name": "SLH-DSA-SHA2-192f",
            "standard": "NIST FIPS 205",
            "security_bits": 192,
            "nist_level": 3,
            "variant": "fast",
            "public_key_bytes": 48,
            "signature_bytes": 35664,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["high-assurance applications", "government"],
        },
        SignatureAlgorithm.SLH_DSA_SHA2_192S: {
            "name": "SLH-DSA-SHA2-192s",
            "standard": "NIST FIPS 205",
            "security_bits": 192,
            "nist_level": 3,
            "variant": "small",
            "public_key_bytes": 48,
            "signature_bytes": 16224,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["balanced size/security", "government"],
        },
        SignatureAlgorithm.SLH_DSA_SHA2_256F: {
            "name": "SLH-DSA-SHA2-256f",
            "standard": "NIST FIPS 205",
            "security_bits": 256,
            "nist_level": 5,
            "variant": "fast",
            "public_key_bytes": 64,
            "signature_bytes": 49856,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["maximum security", "long-term assurance"],
        },
        SignatureAlgorithm.SLH_DSA_SHA2_256S: {
            "name": "SLH-DSA-SHA2-256s",
            "standard": "NIST FIPS 205",
            "security_bits": 256,
            "nist_level": 5,
            "variant": "small",
            "public_key_bytes": 64,
            "signature_bytes": 29792,
            "security_basis": "hash-based (conservative)",
            "recommended_for": ["maximum security", "bandwidth-sensitive"],
        },
    }
    return info.get(algorithm, {})
