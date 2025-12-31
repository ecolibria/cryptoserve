"""Asymmetric Encryption Engine.

Provides public-key encryption with modern algorithms:
- X25519 + AES-GCM: Simple, fast, secure hybrid encryption
- ECIES: Elliptic Curve Integrated Encryption Scheme
- RSA-OAEP: RSA with Optimal Asymmetric Encryption Padding
- HPKE (RFC 9180): Hybrid Public Key Encryption (future)

Key encapsulation follows best practices:
- Ephemeral key per encryption
- Authenticated encryption for payload
- Key derivation with domain separation
"""

import base64
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AsymmetricAlgorithm(str, Enum):
    """Supported asymmetric encryption algorithms."""
    X25519_AESGCM = "x25519-aesgcm"  # Recommended
    X25519_CHACHA20 = "x25519-chacha20"  # Alternative
    ECIES_P256 = "ecies-p256"  # NIST curve
    ECIES_P384 = "ecies-p384"  # Higher security
    RSA_OAEP_SHA256 = "rsa-oaep-sha256"  # Legacy/interop
    RSA_OAEP_SHA384 = "rsa-oaep-sha384"


class KeyExchangeAlgorithm(str, Enum):
    """Supported key exchange algorithms."""
    X25519 = "x25519"  # Recommended: Modern, fast
    ECDH_P256 = "ecdh-p256"  # NIST P-256
    ECDH_P384 = "ecdh-p384"  # NIST P-384
    ECDH_P521 = "ecdh-p521"  # NIST P-521


@dataclass
class KeyPair:
    """Asymmetric key pair."""
    private_key: Any
    public_key: Any
    algorithm: AsymmetricAlgorithm
    key_id: str
    created_at: datetime


@dataclass
class EncryptResult:
    """Result of asymmetric encryption."""
    ciphertext: bytes
    ephemeral_public_key: bytes | None  # For X25519/ECIES
    algorithm: AsymmetricAlgorithm
    key_id: str | None


@dataclass
class DecryptResult:
    """Result of asymmetric decryption."""
    plaintext: bytes
    algorithm: AsymmetricAlgorithm


class AsymmetricError(Exception):
    """Asymmetric operation failed."""
    pass


class KeyNotFoundError(AsymmetricError):
    """Key not found."""
    pass


class DecryptionError(AsymmetricError):
    """Decryption failed."""
    pass


class UnsupportedAlgorithmError(AsymmetricError):
    """Algorithm not supported."""
    pass


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding_needed = 4 - len(data) % 4
    if padding_needed != 4:
        data += "=" * padding_needed
    return base64.urlsafe_b64decode(data)


class AsymmetricEngine:
    """Handles asymmetric encryption operations."""

    # Algorithm metadata
    ALGORITHMS = {
        AsymmetricAlgorithm.X25519_AESGCM: {
            "key_exchange": "X25519",
            "encryption": "AES-256-GCM",
            "security_bits": 128,
            "ephemeral_key_size": 32,
        },
        AsymmetricAlgorithm.X25519_CHACHA20: {
            "key_exchange": "X25519",
            "encryption": "ChaCha20-Poly1305",
            "security_bits": 128,
            "ephemeral_key_size": 32,
        },
        AsymmetricAlgorithm.ECIES_P256: {
            "key_exchange": "ECDH-P256",
            "encryption": "AES-256-GCM",
            "security_bits": 128,
            "ephemeral_key_size": 65,  # Uncompressed point
        },
        AsymmetricAlgorithm.ECIES_P384: {
            "key_exchange": "ECDH-P384",
            "encryption": "AES-256-GCM",
            "security_bits": 192,
            "ephemeral_key_size": 97,
        },
        AsymmetricAlgorithm.RSA_OAEP_SHA256: {
            "key_exchange": None,
            "encryption": "RSA-OAEP-SHA256",
            "security_bits": 112,  # For 2048-bit RSA
        },
        AsymmetricAlgorithm.RSA_OAEP_SHA384: {
            "key_exchange": None,
            "encryption": "RSA-OAEP-SHA384",
            "security_bits": 128,
        },
    }

    def __init__(self):
        self._keys: dict[str, KeyPair] = {}

    def generate_key_pair(
        self,
        algorithm: AsymmetricAlgorithm = AsymmetricAlgorithm.X25519_AESGCM,
        context: str = "default",
        rsa_key_size: int = 4096,
    ) -> KeyPair:
        """Generate a new key pair.

        Args:
            algorithm: Encryption algorithm
            context: Context identifier
            rsa_key_size: Key size for RSA (2048, 3072, 4096)

        Returns:
            KeyPair with public and private keys
        """
        import secrets
        key_id = f"asym_{context}_{secrets.token_hex(8)}"

        if algorithm in [AsymmetricAlgorithm.X25519_AESGCM, AsymmetricAlgorithm.X25519_CHACHA20]:
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()

        elif algorithm == AsymmetricAlgorithm.ECIES_P256:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()

        elif algorithm == AsymmetricAlgorithm.ECIES_P384:
            private_key = ec.generate_private_key(ec.SECP384R1())
            public_key = private_key.public_key()

        elif algorithm in [AsymmetricAlgorithm.RSA_OAEP_SHA256, AsymmetricAlgorithm.RSA_OAEP_SHA384]:
            if rsa_key_size < 2048:
                raise AsymmetricError("RSA key size must be at least 2048 bits")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=rsa_key_size,
            )
            public_key = private_key.public_key()

        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

        key_pair = KeyPair(
            private_key=private_key,
            public_key=public_key,
            algorithm=algorithm,
            key_id=key_id,
            created_at=datetime.now(timezone.utc),
        )

        self._keys[key_id] = key_pair
        return key_pair

    def encrypt(
        self,
        plaintext: bytes,
        public_key: Any | str,
        algorithm: AsymmetricAlgorithm = AsymmetricAlgorithm.X25519_AESGCM,
        key_id: str | None = None,
    ) -> EncryptResult:
        """Encrypt data with a public key.

        Args:
            plaintext: Data to encrypt
            public_key: Public key object or key_id
            algorithm: Encryption algorithm
            key_id: Key ID if using stored key

        Returns:
            EncryptResult with ciphertext
        """
        # Resolve public key
        if isinstance(public_key, str):
            key_id = public_key
            if key_id not in self._keys:
                raise KeyNotFoundError(f"Key not found: {key_id}")
            public_key = self._keys[key_id].public_key
            algorithm = self._keys[key_id].algorithm

        if algorithm in [AsymmetricAlgorithm.X25519_AESGCM, AsymmetricAlgorithm.X25519_CHACHA20]:
            return self._encrypt_x25519(plaintext, public_key, algorithm, key_id)

        elif algorithm in [AsymmetricAlgorithm.ECIES_P256, AsymmetricAlgorithm.ECIES_P384]:
            return self._encrypt_ecies(plaintext, public_key, algorithm, key_id)

        elif algorithm in [AsymmetricAlgorithm.RSA_OAEP_SHA256, AsymmetricAlgorithm.RSA_OAEP_SHA384]:
            return self._encrypt_rsa(plaintext, public_key, algorithm, key_id)

        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

    def decrypt(
        self,
        ciphertext: bytes,
        private_key: Any | str,
        ephemeral_public_key: bytes | None = None,
        algorithm: AsymmetricAlgorithm | None = None,
    ) -> DecryptResult:
        """Decrypt data with a private key.

        Args:
            ciphertext: Encrypted data
            private_key: Private key object or key_id
            ephemeral_public_key: Ephemeral public key (for X25519/ECIES)
            algorithm: Encryption algorithm (auto-detected if key_id used)

        Returns:
            DecryptResult with plaintext
        """
        # Resolve private key
        key_id = None
        if isinstance(private_key, str):
            key_id = private_key
            if key_id not in self._keys:
                raise KeyNotFoundError(f"Key not found: {key_id}")
            key_pair = self._keys[key_id]
            private_key = key_pair.private_key
            algorithm = key_pair.algorithm

        if algorithm is None:
            raise AsymmetricError("Algorithm must be specified")

        if algorithm in [AsymmetricAlgorithm.X25519_AESGCM, AsymmetricAlgorithm.X25519_CHACHA20]:
            return self._decrypt_x25519(ciphertext, private_key, ephemeral_public_key, algorithm)

        elif algorithm in [AsymmetricAlgorithm.ECIES_P256, AsymmetricAlgorithm.ECIES_P384]:
            return self._decrypt_ecies(ciphertext, private_key, ephemeral_public_key, algorithm)

        elif algorithm in [AsymmetricAlgorithm.RSA_OAEP_SHA256, AsymmetricAlgorithm.RSA_OAEP_SHA384]:
            return self._decrypt_rsa(ciphertext, private_key, algorithm)

        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

    # ==================== X25519 Encryption ====================

    def _encrypt_x25519(
        self,
        plaintext: bytes,
        public_key: X25519PublicKey,
        algorithm: AsymmetricAlgorithm,
        key_id: str | None,
    ) -> EncryptResult:
        """Encrypt with X25519 + AEAD."""
        # Generate ephemeral key pair
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # Perform key exchange
        shared_secret = ephemeral_private.exchange(public_key)

        # Derive encryption key
        enc_key = self._derive_key(shared_secret, b"x25519-encryption", 32)

        # Encrypt with AEAD
        nonce = os.urandom(12)

        if algorithm == AsymmetricAlgorithm.X25519_AESGCM:
            cipher = AESGCM(enc_key)
        else:  # ChaCha20
            cipher = ChaCha20Poly1305(enc_key)

        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Serialize ephemeral public key
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Package: ephemeral_public_key || nonce || ciphertext
        packed = ephemeral_bytes + nonce + ciphertext

        return EncryptResult(
            ciphertext=packed,
            ephemeral_public_key=ephemeral_bytes,
            algorithm=algorithm,
            key_id=key_id,
        )

    def _decrypt_x25519(
        self,
        packed_ciphertext: bytes,
        private_key: X25519PrivateKey,
        ephemeral_public_key: bytes | None,
        algorithm: AsymmetricAlgorithm,
    ) -> DecryptResult:
        """Decrypt with X25519 + AEAD."""
        try:
            # Parse packed format
            ephemeral_bytes = packed_ciphertext[:32]
            nonce = packed_ciphertext[32:44]
            ciphertext = packed_ciphertext[44:]

            # Reconstruct ephemeral public key
            ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_bytes)

            # Perform key exchange
            shared_secret = private_key.exchange(ephemeral_public)

            # Derive encryption key
            enc_key = self._derive_key(shared_secret, b"x25519-encryption", 32)

            # Decrypt
            if algorithm == AsymmetricAlgorithm.X25519_AESGCM:
                cipher = AESGCM(enc_key)
            else:
                cipher = ChaCha20Poly1305(enc_key)

            plaintext = cipher.decrypt(nonce, ciphertext, None)

            return DecryptResult(
                plaintext=plaintext,
                algorithm=algorithm,
            )

        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")

    # ==================== ECIES Encryption ====================

    def _encrypt_ecies(
        self,
        plaintext: bytes,
        public_key: ec.EllipticCurvePublicKey,
        algorithm: AsymmetricAlgorithm,
        key_id: str | None,
    ) -> EncryptResult:
        """Encrypt with ECIES (ECDH + AEAD)."""
        curve = public_key.curve

        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(curve)
        ephemeral_public = ephemeral_private.public_key()

        # Perform key exchange
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

        # Derive encryption key
        enc_key = self._derive_key(shared_secret, b"ecies-encryption", 32)

        # Encrypt with AES-GCM
        nonce = os.urandom(12)
        cipher = AESGCM(enc_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Serialize ephemeral public key (uncompressed point)
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Package: ephemeral_public_key || nonce || ciphertext
        key_size = 65 if algorithm == AsymmetricAlgorithm.ECIES_P256 else 97
        packed = ephemeral_bytes + nonce + ciphertext

        return EncryptResult(
            ciphertext=packed,
            ephemeral_public_key=ephemeral_bytes,
            algorithm=algorithm,
            key_id=key_id,
        )

    def _decrypt_ecies(
        self,
        packed_ciphertext: bytes,
        private_key: ec.EllipticCurvePrivateKey,
        ephemeral_public_key: bytes | None,
        algorithm: AsymmetricAlgorithm,
    ) -> DecryptResult:
        """Decrypt with ECIES."""
        try:
            # Determine key size
            key_size = 65 if algorithm == AsymmetricAlgorithm.ECIES_P256 else 97

            # Parse packed format
            ephemeral_bytes = packed_ciphertext[:key_size]
            nonce = packed_ciphertext[key_size:key_size + 12]
            ciphertext = packed_ciphertext[key_size + 12:]

            # Reconstruct ephemeral public key
            curve = private_key.curve
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                curve, ephemeral_bytes
            )

            # Perform key exchange
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

            # Derive encryption key
            enc_key = self._derive_key(shared_secret, b"ecies-encryption", 32)

            # Decrypt
            cipher = AESGCM(enc_key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            return DecryptResult(
                plaintext=plaintext,
                algorithm=algorithm,
            )

        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")

    # ==================== RSA-OAEP Encryption ====================

    def _encrypt_rsa(
        self,
        plaintext: bytes,
        public_key: rsa.RSAPublicKey,
        algorithm: AsymmetricAlgorithm,
        key_id: str | None,
    ) -> EncryptResult:
        """Encrypt with RSA-OAEP.

        For large messages, uses hybrid encryption:
        - Generate random AES key
        - Encrypt message with AES-GCM
        - Encrypt AES key with RSA-OAEP
        """
        # Determine hash algorithm
        if algorithm == AsymmetricAlgorithm.RSA_OAEP_SHA256:
            hash_alg = hashes.SHA256()
        else:
            hash_alg = hashes.SHA384()

        # Maximum bytes for RSA-OAEP
        key_size_bytes = public_key.key_size // 8
        max_plaintext = key_size_bytes - 2 * hash_alg.digest_size - 2

        if len(plaintext) <= max_plaintext:
            # Direct encryption
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_alg),
                    algorithm=hash_alg,
                    label=None,
                ),
            )
            # Prefix with 0x00 to indicate direct
            packed = b"\x00" + ciphertext
        else:
            # Hybrid encryption
            aes_key = os.urandom(32)
            nonce = os.urandom(12)

            # Encrypt message with AES-GCM
            cipher = AESGCM(aes_key)
            encrypted_message = cipher.encrypt(nonce, plaintext, None)

            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_alg),
                    algorithm=hash_alg,
                    label=None,
                ),
            )

            # Package: 0x01 || key_len (2 bytes) || encrypted_key || nonce || ciphertext
            key_len = len(encrypted_key).to_bytes(2, "big")
            packed = b"\x01" + key_len + encrypted_key + nonce + encrypted_message

        return EncryptResult(
            ciphertext=packed,
            ephemeral_public_key=None,
            algorithm=algorithm,
            key_id=key_id,
        )

    def _decrypt_rsa(
        self,
        packed_ciphertext: bytes,
        private_key: rsa.RSAPrivateKey,
        algorithm: AsymmetricAlgorithm,
    ) -> DecryptResult:
        """Decrypt with RSA-OAEP."""
        try:
            # Determine hash algorithm
            if algorithm == AsymmetricAlgorithm.RSA_OAEP_SHA256:
                hash_alg = hashes.SHA256()
            else:
                hash_alg = hashes.SHA384()

            mode = packed_ciphertext[0]

            if mode == 0x00:
                # Direct decryption
                ciphertext = packed_ciphertext[1:]
                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_alg),
                        algorithm=hash_alg,
                        label=None,
                    ),
                )
            elif mode == 0x01:
                # Hybrid decryption
                key_len = int.from_bytes(packed_ciphertext[1:3], "big")
                encrypted_key = packed_ciphertext[3:3 + key_len]
                nonce = packed_ciphertext[3 + key_len:3 + key_len + 12]
                encrypted_message = packed_ciphertext[3 + key_len + 12:]

                # Decrypt AES key
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_alg),
                        algorithm=hash_alg,
                        label=None,
                    ),
                )

                # Decrypt message
                cipher = AESGCM(aes_key)
                plaintext = cipher.decrypt(nonce, encrypted_message, None)
            else:
                raise DecryptionError(f"Unknown encryption mode: {mode}")

            return DecryptResult(
                plaintext=plaintext,
                algorithm=algorithm,
            )

        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")

    # ==================== Key Management ====================

    def get_public_key(
        self,
        key_id: str,
        format: str = "raw",
    ) -> bytes | dict:
        """Get public key for a key pair.

        Args:
            key_id: Key pair ID
            format: "raw", "pem", or "jwk"

        Returns:
            Public key in requested format
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_pair = self._keys[key_id]
        public_key = key_pair.public_key

        if format == "pem":
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        elif format == "raw":
            if isinstance(public_key, X25519PublicKey):
                return public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            else:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

        elif format == "jwk":
            return self._key_to_jwk(public_key, key_id)

        else:
            raise ValueError(f"Unknown format: {format}")

    def import_public_key(
        self,
        public_key_data: bytes | dict,
        algorithm: AsymmetricAlgorithm,
        key_id: str | None = None,
        format: str = "raw",
    ) -> str:
        """Import a public key for encryption.

        Args:
            public_key_data: Public key data
            algorithm: Encryption algorithm
            key_id: Optional key ID
            format: "raw", "pem", or "jwk"

        Returns:
            Key ID
        """
        import secrets

        if key_id is None:
            key_id = f"asym_imported_{secrets.token_hex(8)}"

        if format == "jwk":
            public_key = self._jwk_to_key(public_key_data)
        elif format == "pem":
            public_key = serialization.load_pem_public_key(public_key_data)
        elif format == "raw":
            if algorithm in [AsymmetricAlgorithm.X25519_AESGCM, AsymmetricAlgorithm.X25519_CHACHA20]:
                public_key = X25519PublicKey.from_public_bytes(public_key_data)
            elif algorithm == AsymmetricAlgorithm.ECIES_P256:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), public_key_data
                )
            elif algorithm == AsymmetricAlgorithm.ECIES_P384:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP384R1(), public_key_data
                )
            else:
                raise AsymmetricError(f"Raw format not supported for {algorithm}")
        else:
            raise ValueError(f"Unknown format: {format}")

        # Store as key pair without private key
        key_pair = KeyPair(
            private_key=None,
            public_key=public_key,
            algorithm=algorithm,
            key_id=key_id,
            created_at=datetime.now(timezone.utc),
        )
        self._keys[key_id] = key_pair

        return key_id

    def list_keys(self, context: str | None = None) -> list[dict]:
        """List all key pairs."""
        keys = []
        for key_id, key_pair in self._keys.items():
            if context and not key_id.startswith(f"asym_{context}_"):
                continue
            keys.append({
                "key_id": key_id,
                "algorithm": key_pair.algorithm.value,
                "has_private_key": key_pair.private_key is not None,
                "created_at": key_pair.created_at.isoformat(),
            })
        return keys

    def delete_key(self, key_id: str) -> bool:
        """Delete a key pair."""
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False

    # ==================== Helper Methods ====================

    def _derive_key(self, shared_secret: bytes, info: bytes, length: int) -> bytes:
        """Derive key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.derive(shared_secret)

    def _key_to_jwk(self, public_key: Any, kid: str) -> dict:
        """Convert public key to JWK."""
        if isinstance(public_key, X25519PublicKey):
            raw = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return {
                "kty": "OKP",
                "crv": "X25519",
                "x": _b64url_encode(raw),
                "kid": kid,
                "use": "enc",
            }

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            numbers = public_key.public_numbers()
            curve = public_key.curve

            if curve.name == "secp256r1":
                crv, size = "P-256", 32
            elif curve.name == "secp384r1":
                crv, size = "P-384", 48
            else:
                raise AsymmetricError(f"Unsupported curve: {curve.name}")

            return {
                "kty": "EC",
                "crv": crv,
                "x": _b64url_encode(numbers.x.to_bytes(size, "big")),
                "y": _b64url_encode(numbers.y.to_bytes(size, "big")),
                "kid": kid,
                "use": "enc",
            }

        elif isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            return {
                "kty": "RSA",
                "n": _b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": _b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                "kid": kid,
                "use": "enc",
            }

        else:
            raise AsymmetricError(f"Unsupported key type: {type(public_key)}")

    def _jwk_to_key(self, jwk: dict) -> Any:
        """Convert JWK to public key."""
        kty = jwk.get("kty")

        if kty == "OKP" and jwk.get("crv") == "X25519":
            x = _b64url_decode(jwk["x"])
            return X25519PublicKey.from_public_bytes(x)

        elif kty == "EC":
            crv = jwk.get("crv")
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")

            if crv == "P-256":
                curve = ec.SECP256R1()
            elif crv == "P-384":
                curve = ec.SECP384R1()
            else:
                raise AsymmetricError(f"Unsupported curve: {crv}")

            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()

        elif kty == "RSA":
            n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()

        else:
            raise AsymmetricError(f"Unsupported key type: {kty}")


# Singleton instance
asymmetric_engine = AsymmetricEngine()
