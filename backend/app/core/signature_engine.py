"""Digital Signature Engine.

Provides signing and verification operations with multiple algorithms:
- Ed25519: Fast, secure, deterministic (recommended)
- Ed448: Higher security margin
- ECDSA-P256: NIST curve, TLS compatible
- ECDSA-P384: Higher security NIST curve

Future (PQC):
- ML-DSA-65: Post-quantum signatures (FIPS 204)
- SLH-DSA: Hash-based post-quantum

Key features:
- Deterministic signatures (no random nonce issues)
- Key pair generation with secure storage
- Multiple output formats (raw, DER, PEM)

Security Notes:
- Private keys are encrypted in memory using a session key
- For production use, integrate with HSM or secure key storage
- Session keys are regenerated on each engine instantiation
"""

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Identity
from app.core.secure_memory import SecureBytes


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""
    ED25519 = "Ed25519"
    ED448 = "Ed448"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    # Future PQC
    ML_DSA_65 = "ML-DSA-65"
    SLH_DSA_128F = "SLH-DSA-SHA2-128f"


class SignatureFormat(str, Enum):
    """Output format for signatures."""
    RAW = "raw"  # Raw bytes
    BASE64 = "base64"  # Base64 encoded
    DER = "der"  # DER encoded (for ECDSA)
    JWS = "jws"  # JSON Web Signature format


@dataclass
class SigningKeyPair:
    """A signing key pair with metadata."""
    key_id: str
    algorithm: SignatureAlgorithm
    private_key_pem: bytes  # Encrypted PEM
    public_key_pem: bytes
    public_key_jwk: dict
    created_at: datetime
    context: str


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    signature: bytes
    algorithm: SignatureAlgorithm
    key_id: str
    format: SignatureFormat


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    valid: bool
    algorithm: SignatureAlgorithm
    key_id: str
    message: str


class SignatureError(Exception):
    """Base signature exception."""
    pass


class KeyNotFoundError(SignatureError):
    """Signing key not found."""
    pass


class InvalidSignatureError(SignatureError):
    """Signature verification failed."""
    pass


class UnsupportedAlgorithmError(SignatureError):
    """Algorithm not supported."""
    pass


class SignatureEngine:
    """Handles digital signature operations."""

    # Algorithm metadata
    ALGORITHMS = {
        SignatureAlgorithm.ED25519: {
            "security_bits": 128,
            "signature_size": 64,
            "public_key_size": 32,
            "deterministic": True,
            "description": "Edwards-curve Digital Signature Algorithm (RFC 8032)",
        },
        SignatureAlgorithm.ECDSA_P256: {
            "security_bits": 128,
            "signature_size": 64,  # r + s, each 32 bytes
            "public_key_size": 65,  # Uncompressed point
            "deterministic": False,  # Unless using RFC 6979
            "description": "ECDSA with NIST P-256 curve (FIPS 186-4)",
        },
        SignatureAlgorithm.ECDSA_P384: {
            "security_bits": 192,
            "signature_size": 96,  # r + s, each 48 bytes
            "public_key_size": 97,
            "deterministic": False,
            "description": "ECDSA with NIST P-384 curve (FIPS 186-4)",
        },
    }

    def __init__(self):
        """Initialize signature engine with encrypted key storage.

        WARNING: This implementation stores encrypted private keys in memory.
        For production deployments, integrate with:
        - Hardware Security Module (HSM)
        - Cloud KMS (AWS KMS, GCP Cloud HSM, Azure Key Vault)
        - Secure enclave storage

        The session encryption key is generated fresh on each instantiation
        and is used to protect private keys at rest in memory.
        """
        # Generate session key for encrypting private keys in memory
        # This protects against memory scraping if the process is compromised
        self._session_key = os.urandom(32)  # AES-256 key
        self._cipher = AESGCM(self._session_key)

        # In-memory key cache with encrypted private keys
        self._keys: dict[str, SigningKeyPair] = {}

        logger.info(
            "SignatureEngine initialized with encrypted key storage. "
            "For production, use HSM integration."
        )

    def _encrypt_private_key(self, private_key_pem: bytes) -> bytes:
        """Encrypt private key for storage using session key.

        Args:
            private_key_pem: Unencrypted PEM-encoded private key

        Returns:
            Encrypted key blob: nonce (12 bytes) || ciphertext
        """
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, private_key_pem, None)
        return nonce + ciphertext

    def _decrypt_private_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt private key from storage.

        Args:
            encrypted_key: Encrypted key blob from _encrypt_private_key

        Returns:
            Decrypted PEM-encoded private key
        """
        nonce = encrypted_key[:12]
        ciphertext = encrypted_key[12:]
        return self._cipher.decrypt(nonce, ciphertext, None)

    def generate_key_pair(
        self,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
        context: str = "default",
    ) -> SigningKeyPair:
        """Generate a new signing key pair.

        Args:
            algorithm: Signature algorithm to use
            context: Context identifier for the key

        Returns:
            SigningKeyPair with public and private keys
        """
        import secrets

        key_id = f"sig_{context}_{secrets.token_hex(8)}"

        if algorithm == SignatureAlgorithm.ED25519:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Build JWK for public key
            public_raw = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            public_jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode(),
                "kid": key_id,
                "use": "sig",
                "alg": "EdDSA",
            }

        elif algorithm in [SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384]:
            curve = ec.SECP256R1() if algorithm == SignatureAlgorithm.ECDSA_P256 else ec.SECP384R1()
            private_key = ec.generate_private_key(curve)
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Build JWK
            public_numbers = public_key.public_numbers()
            key_size = 32 if algorithm == SignatureAlgorithm.ECDSA_P256 else 48

            public_jwk = {
                "kty": "EC",
                "crv": "P-256" if algorithm == SignatureAlgorithm.ECDSA_P256 else "P-384",
                "x": base64.urlsafe_b64encode(
                    public_numbers.x.to_bytes(key_size, "big")
                ).rstrip(b"=").decode(),
                "y": base64.urlsafe_b64encode(
                    public_numbers.y.to_bytes(key_size, "big")
                ).rstrip(b"=").decode(),
                "kid": key_id,
                "use": "sig",
                "alg": "ES256" if algorithm == SignatureAlgorithm.ECDSA_P256 else "ES384",
            }

        else:
            raise UnsupportedAlgorithmError(f"Algorithm {algorithm} not yet implemented")

        # Encrypt private key before storage
        encrypted_private_pem = self._encrypt_private_key(private_pem)

        key_pair = SigningKeyPair(
            key_id=key_id,
            algorithm=algorithm,
            private_key_pem=encrypted_private_pem,  # Stored encrypted
            public_key_pem=public_pem,
            public_key_jwk=public_jwk,
            created_at=datetime.now(timezone.utc),
            context=context,
        )

        # Cache the key (with encrypted private key)
        self._keys[key_id] = key_pair

        return key_pair

    def sign(
        self,
        message: bytes,
        key_id: str,
        output_format: SignatureFormat = SignatureFormat.RAW,
    ) -> SignatureResult:
        """Sign a message.

        Args:
            message: The message to sign
            key_id: ID of the signing key
            output_format: Desired signature format

        Returns:
            SignatureResult with signature bytes
        """
        key_pair = self._keys.get(key_id)
        if not key_pair:
            raise KeyNotFoundError(f"Signing key not found: {key_id}")

        # Decrypt private key from storage
        decrypted_pem = self._decrypt_private_key(key_pair.private_key_pem)

        if key_pair.algorithm == SignatureAlgorithm.ED25519:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                self._extract_raw_private_key(decrypted_pem, "ed25519")
            )
            signature = private_key.sign(message)

        elif key_pair.algorithm in [SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384]:
            private_key = serialization.load_pem_private_key(
                decrypted_pem, password=None  # Use decrypted PEM
            )
            # Use SHA-256 for P-256, SHA-384 for P-384
            hash_alg = hashes.SHA256() if key_pair.algorithm == SignatureAlgorithm.ECDSA_P256 else hashes.SHA384()
            signature_der = private_key.sign(message, ec.ECDSA(hash_alg))

            if output_format == SignatureFormat.DER:
                signature = signature_der
            else:
                # Convert DER to raw (r || s) format
                r, s = decode_dss_signature(signature_der)
                key_size = 32 if key_pair.algorithm == SignatureAlgorithm.ECDSA_P256 else 48
                signature = r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")

        else:
            raise UnsupportedAlgorithmError(f"Algorithm {key_pair.algorithm} not implemented")

        # Format output
        if output_format == SignatureFormat.BASE64:
            signature = base64.b64encode(signature)

        return SignatureResult(
            signature=signature,
            algorithm=key_pair.algorithm,
            key_id=key_id,
            format=output_format,
        )

    def verify(
        self,
        message: bytes,
        signature: bytes,
        key_id: str,
        signature_format: SignatureFormat = SignatureFormat.RAW,
    ) -> VerificationResult:
        """Verify a signature.

        Args:
            message: The original message
            signature: The signature to verify
            key_id: ID of the signing key (uses public key)
            signature_format: Format of the signature

        Returns:
            VerificationResult indicating validity
        """
        key_pair = self._keys.get(key_id)
        if not key_pair:
            raise KeyNotFoundError(f"Signing key not found: {key_id}")

        # Decode signature if needed
        if signature_format == SignatureFormat.BASE64:
            signature = base64.b64decode(signature)

        try:
            if key_pair.algorithm == SignatureAlgorithm.ED25519:
                public_key = serialization.load_pem_public_key(key_pair.public_key_pem)
                public_key.verify(signature, message)

            elif key_pair.algorithm in [SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384]:
                public_key = serialization.load_pem_public_key(key_pair.public_key_pem)
                hash_alg = hashes.SHA256() if key_pair.algorithm == SignatureAlgorithm.ECDSA_P256 else hashes.SHA384()

                if signature_format == SignatureFormat.DER:
                    signature_der = signature
                else:
                    # Convert raw (r || s) to DER
                    key_size = 32 if key_pair.algorithm == SignatureAlgorithm.ECDSA_P256 else 48
                    r = int.from_bytes(signature[:key_size], "big")
                    s = int.from_bytes(signature[key_size:], "big")
                    signature_der = encode_dss_signature(r, s)

                public_key.verify(signature_der, message, ec.ECDSA(hash_alg))

            else:
                raise UnsupportedAlgorithmError(f"Algorithm {key_pair.algorithm} not implemented")

            return VerificationResult(
                valid=True,
                algorithm=key_pair.algorithm,
                key_id=key_id,
                message="Signature is valid",
            )

        except InvalidSignature:
            return VerificationResult(
                valid=False,
                algorithm=key_pair.algorithm,
                key_id=key_id,
                message="Signature verification failed",
            )

    def get_public_key(self, key_id: str, format: str = "pem") -> bytes | dict:
        """Get the public key for a key pair.

        Args:
            key_id: ID of the key pair
            format: "pem", "jwk", or "raw"

        Returns:
            Public key in requested format
        """
        key_pair = self._keys.get(key_id)
        if not key_pair:
            raise KeyNotFoundError(f"Signing key not found: {key_id}")

        if format == "jwk":
            return key_pair.public_key_jwk
        elif format == "pem":
            return key_pair.public_key_pem
        elif format == "raw":
            public_key = serialization.load_pem_public_key(key_pair.public_key_pem)
            if key_pair.algorithm == SignatureAlgorithm.ED25519:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            else:
                # For EC keys, return uncompressed point
                return public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
        else:
            raise ValueError(f"Unknown format: {format}")

    def list_keys(self, context: str | None = None) -> list[dict]:
        """List all signing keys.

        Args:
            context: Optional filter by context

        Returns:
            List of key metadata (without private keys)
        """
        keys = []
        for key_id, key_pair in self._keys.items():
            if context and key_pair.context != context:
                continue
            keys.append({
                "key_id": key_id,
                "algorithm": key_pair.algorithm.value,
                "context": key_pair.context,
                "created_at": key_pair.created_at.isoformat(),
                "public_key_jwk": key_pair.public_key_jwk,
            })
        return keys

    def delete_key(self, key_id: str) -> bool:
        """Delete a signing key pair.

        Args:
            key_id: ID of the key to delete

        Returns:
            True if deleted, False if not found
        """
        if key_id in self._keys:
            # Securely clear private key
            key_pair = self._keys[key_id]
            if isinstance(key_pair.private_key_pem, bytearray):
                from app.core.secure_memory import secure_zero
                secure_zero(key_pair.private_key_pem)
            del self._keys[key_id]
            return True
        return False

    def _extract_raw_private_key(self, pem_data: bytes, key_type: str) -> bytes:
        """Extract raw private key bytes from PEM.

        Args:
            pem_data: PEM-encoded private key
            key_type: "ed25519" or "ec"

        Returns:
            Raw private key bytes
        """
        private_key = serialization.load_pem_private_key(pem_data, password=None)

        if key_type == "ed25519":
            return private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            # For EC, return the private number as bytes
            return private_key.private_numbers().private_value.to_bytes(
                (private_key.key_size + 7) // 8, "big"
            )

    def import_public_key(
        self,
        public_key_data: bytes | dict,
        key_id: str | None = None,
        format: str = "pem",
    ) -> str:
        """Import a public key for verification only.

        Args:
            public_key_data: Public key in PEM or JWK format
            key_id: Optional key ID (generated if not provided)
            format: "pem" or "jwk"

        Returns:
            Key ID
        """
        import secrets

        if key_id is None:
            key_id = f"sig_imported_{secrets.token_hex(8)}"

        if format == "jwk":
            jwk = public_key_data if isinstance(public_key_data, dict) else json.loads(public_key_data)
            algorithm, public_pem = self._jwk_to_pem(jwk)
            public_jwk = jwk
        else:
            public_pem = public_key_data if isinstance(public_key_data, bytes) else public_key_data.encode()
            public_key = serialization.load_pem_public_key(public_pem)

            # Determine algorithm from key type
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                algorithm = SignatureAlgorithm.ED25519
                public_raw = public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                public_jwk = {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode(),
                    "kid": key_id,
                    "use": "sig",
                }
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                if curve_name == "secp256r1":
                    algorithm = SignatureAlgorithm.ECDSA_P256
                    crv = "P-256"
                    key_size = 32
                elif curve_name == "secp384r1":
                    algorithm = SignatureAlgorithm.ECDSA_P384
                    crv = "P-384"
                    key_size = 48
                else:
                    raise UnsupportedAlgorithmError(f"Unsupported curve: {curve_name}")

                numbers = public_key.public_numbers()
                public_jwk = {
                    "kty": "EC",
                    "crv": crv,
                    "x": base64.urlsafe_b64encode(numbers.x.to_bytes(key_size, "big")).rstrip(b"=").decode(),
                    "y": base64.urlsafe_b64encode(numbers.y.to_bytes(key_size, "big")).rstrip(b"=").decode(),
                    "kid": key_id,
                    "use": "sig",
                }
            else:
                raise UnsupportedAlgorithmError(f"Unsupported key type: {type(public_key)}")

        # Store as key pair with no private key
        key_pair = SigningKeyPair(
            key_id=key_id,
            algorithm=algorithm,
            private_key_pem=b"",  # No private key for imported public keys
            public_key_pem=public_pem,
            public_key_jwk=public_jwk,
            created_at=datetime.now(timezone.utc),
            context="imported",
        )
        self._keys[key_id] = key_pair

        return key_id

    def _jwk_to_pem(self, jwk: dict) -> tuple[SignatureAlgorithm, bytes]:
        """Convert JWK to PEM format.

        Args:
            jwk: JWK dictionary

        Returns:
            Tuple of (algorithm, pem_bytes)
        """
        kty = jwk.get("kty")

        if kty == "OKP":
            crv = jwk.get("crv")
            if crv == "Ed25519":
                x = base64.urlsafe_b64decode(jwk["x"] + "==")
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(x)
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return SignatureAlgorithm.ED25519, pem
            else:
                raise UnsupportedAlgorithmError(f"Unsupported curve: {crv}")

        elif kty == "EC":
            crv = jwk.get("crv")
            x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
            y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")

            if crv == "P-256":
                curve = ec.SECP256R1()
                algorithm = SignatureAlgorithm.ECDSA_P256
            elif crv == "P-384":
                curve = ec.SECP384R1()
                algorithm = SignatureAlgorithm.ECDSA_P384
            else:
                raise UnsupportedAlgorithmError(f"Unsupported curve: {crv}")

            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
            public_key = public_numbers.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return algorithm, pem

        else:
            raise UnsupportedAlgorithmError(f"Unsupported key type: {kty}")


# Singleton instance
signature_engine = SignatureEngine()
