"""HPKE (Hybrid Public Key Encryption) Engine.

Implements RFC 9180 HPKE for modern hybrid encryption.

HPKE provides:
- Key encapsulation (KEM) for asymmetric key exchange
- Key derivation (KDF) for deriving encryption keys
- Authenticated encryption (AEAD) for message encryption

Supported Cipher Suites:
- DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
- DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305
- DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM
- DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM (recommended)
- DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305

Modes:
- Base: No authentication
- PSK: Pre-shared key authentication
- Auth: Sender authentication
- AuthPSK: Both sender auth and PSK

Standards:
- RFC 9180: Hybrid Public Key Encryption
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Check if pyhpke is available
try:
    from pyhpke import CipherSuite, KEMId, KDFId, AEADId
    HPKE_AVAILABLE = True
except ImportError:
    HPKE_AVAILABLE = False
    CipherSuite = None
    KEMId = None
    KDFId = None
    AEADId = None


class HPKECipherSuite(str, Enum):
    """Supported HPKE cipher suites."""
    # X25519-based (recommended for most use cases)
    X25519_SHA256_AES128GCM = "x25519-sha256-aes128gcm"
    X25519_SHA256_CHACHA20 = "x25519-sha256-chacha20poly1305"

    # P-256-based (NIST compliance)
    P256_SHA256_AES128GCM = "p256-sha256-aes128gcm"
    P256_SHA256_CHACHA20 = "p256-sha256-chacha20poly1305"

    # P-384-based (higher security)
    P384_SHA384_AES256GCM = "p384-sha384-aes256gcm"


class HPKEMode(str, Enum):
    """HPKE modes of operation."""
    BASE = "base"           # No sender authentication
    PSK = "psk"             # Pre-shared key authentication
    AUTH = "auth"           # Sender public key authentication
    AUTH_PSK = "auth_psk"   # Both sender auth and PSK


@dataclass
class HPKEKeyPair:
    """HPKE key pair."""
    private_key: bytes
    public_key: bytes
    suite: HPKECipherSuite


@dataclass
class HPKEEncryptedMessage:
    """HPKE encrypted message with encapsulated key."""
    enc: bytes              # Encapsulated key
    ciphertext: bytes       # Encrypted message
    suite: HPKECipherSuite
    mode: HPKEMode
    info: bytes = b""       # Optional context info
    aad: bytes = b""        # Additional authenticated data


class HPKEError(Exception):
    """HPKE operation error."""
    pass


class HPKEEngine:
    """HPKE encryption engine implementing RFC 9180.

    Provides hybrid public key encryption with modern algorithms
    for secure key exchange and authenticated encryption.
    """

    # Map cipher suite enum to pyhpke components
    _SUITE_MAP = {
        HPKECipherSuite.X25519_SHA256_AES128GCM: (
            "DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"
        ),
        HPKECipherSuite.X25519_SHA256_CHACHA20: (
            "DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "CHACHA20_POLY1305"
        ),
        HPKECipherSuite.P256_SHA256_AES128GCM: (
            "DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"
        ),
        HPKECipherSuite.P256_SHA256_CHACHA20: (
            "DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "CHACHA20_POLY1305"
        ),
        HPKECipherSuite.P384_SHA384_AES256GCM: (
            "DHKEM_P384_HKDF_SHA384", "HKDF_SHA384", "AES256_GCM"
        ),
    }

    def __init__(self):
        """Initialize HPKE engine."""
        if not HPKE_AVAILABLE:
            raise HPKEError(
                "HPKE requires pyhpke. Install with: pip install pyhpke"
            )

    def _get_cipher_suite(self, suite: HPKECipherSuite) -> "CipherSuite":
        """Get pyhpke CipherSuite from enum."""
        if suite not in self._SUITE_MAP:
            raise HPKEError(f"Unsupported cipher suite: {suite}")

        kem_name, kdf_name, aead_name = self._SUITE_MAP[suite]
        kem_id = getattr(KEMId, kem_name)
        kdf_id = getattr(KDFId, kdf_name)
        aead_id = getattr(AEADId, aead_name)

        return CipherSuite.new(kem_id, kdf_id, aead_id)

    def generate_keypair(
        self,
        suite: HPKECipherSuite = HPKECipherSuite.X25519_SHA256_AES128GCM,
    ) -> HPKEKeyPair:
        """Generate a new HPKE key pair.

        Args:
            suite: Cipher suite determining the key type

        Returns:
            HPKEKeyPair with private and public keys
        """
        import secrets

        cs = self._get_cipher_suite(suite)
        # pyhpke uses derive_key_pair with input key material
        ikm = secrets.token_bytes(32)
        key_pair = cs.kem.derive_key_pair(ikm)

        return HPKEKeyPair(
            private_key=key_pair.private_key.to_private_bytes(),
            public_key=key_pair.public_key.to_public_bytes(),
            suite=suite,
        )

    def encrypt(
        self,
        recipient_public_key: bytes,
        plaintext: bytes,
        suite: HPKECipherSuite = HPKECipherSuite.X25519_SHA256_AES128GCM,
        info: bytes = b"",
        aad: bytes = b"",
    ) -> HPKEEncryptedMessage:
        """Encrypt a message using HPKE (Base mode).

        Args:
            recipient_public_key: Recipient's public key
            plaintext: Message to encrypt
            suite: Cipher suite to use
            info: Optional context info for key derivation
            aad: Additional authenticated data

        Returns:
            HPKEEncryptedMessage containing enc and ciphertext
        """
        cs = self._get_cipher_suite(suite)

        # Load recipient's public key
        pk = cs.kem.deserialize_public_key(recipient_public_key)

        # Create sender context (Base mode)
        enc, sender = cs.create_sender_context(pk, info=info)

        # Encrypt with AAD
        ciphertext = sender.seal(plaintext, aad=aad)

        return HPKEEncryptedMessage(
            enc=enc,
            ciphertext=ciphertext,
            suite=suite,
            mode=HPKEMode.BASE,
            info=info,
            aad=aad,
        )

    def decrypt(
        self,
        recipient_private_key: bytes,
        encrypted_message: HPKEEncryptedMessage,
    ) -> bytes:
        """Decrypt an HPKE encrypted message (Base mode).

        Args:
            recipient_private_key: Recipient's private key
            encrypted_message: The encrypted message

        Returns:
            Decrypted plaintext
        """
        cs = self._get_cipher_suite(encrypted_message.suite)

        # Load recipient's private key
        sk = cs.kem.deserialize_private_key(recipient_private_key)

        # Create recipient context
        recipient = cs.create_recipient_context(
            encrypted_message.enc,
            sk,
            info=encrypted_message.info,
        )

        # Decrypt with AAD
        plaintext = recipient.open(
            encrypted_message.ciphertext,
            aad=encrypted_message.aad,
        )

        return plaintext

    def encrypt_with_auth(
        self,
        sender_private_key: bytes,
        recipient_public_key: bytes,
        plaintext: bytes,
        suite: HPKECipherSuite = HPKECipherSuite.X25519_SHA256_AES128GCM,
        info: bytes = b"",
        aad: bytes = b"",
    ) -> HPKEEncryptedMessage:
        """Encrypt with sender authentication (Auth mode).

        The sender's identity is cryptographically bound to the message,
        allowing the recipient to verify who encrypted it.

        Args:
            sender_private_key: Sender's private key for authentication
            recipient_public_key: Recipient's public key
            plaintext: Message to encrypt
            suite: Cipher suite to use
            info: Optional context info
            aad: Additional authenticated data

        Returns:
            HPKEEncryptedMessage
        """
        cs = self._get_cipher_suite(suite)

        # Load keys
        pk = cs.kem.deserialize_public_key(recipient_public_key)
        sk = cs.kem.deserialize_private_key(sender_private_key)

        # Create authenticated sender context
        enc, sender = cs.create_sender_context(pk, info=info, sks=sk)

        # Encrypt
        ciphertext = sender.seal(plaintext, aad=aad)

        return HPKEEncryptedMessage(
            enc=enc,
            ciphertext=ciphertext,
            suite=suite,
            mode=HPKEMode.AUTH,
            info=info,
            aad=aad,
        )

    def decrypt_with_auth(
        self,
        recipient_private_key: bytes,
        sender_public_key: bytes,
        encrypted_message: HPKEEncryptedMessage,
    ) -> bytes:
        """Decrypt with sender authentication verification (Auth mode).

        Args:
            recipient_private_key: Recipient's private key
            sender_public_key: Sender's public key for verification
            encrypted_message: The encrypted message

        Returns:
            Decrypted plaintext

        Raises:
            HPKEError: If authentication fails
        """
        cs = self._get_cipher_suite(encrypted_message.suite)

        # Load keys
        sk = cs.kem.deserialize_private_key(recipient_private_key)
        pks = cs.kem.deserialize_public_key(sender_public_key)

        # Create authenticated recipient context
        recipient = cs.create_recipient_context(
            encrypted_message.enc,
            sk,
            info=encrypted_message.info,
            pks=pks,
        )

        # Decrypt (will fail if sender auth doesn't match)
        plaintext = recipient.open(
            encrypted_message.ciphertext,
            aad=encrypted_message.aad,
        )

        return plaintext

    def encrypt_with_psk(
        self,
        recipient_public_key: bytes,
        plaintext: bytes,
        psk: bytes,
        psk_id: bytes,
        suite: HPKECipherSuite = HPKECipherSuite.X25519_SHA256_AES128GCM,
        info: bytes = b"",
        aad: bytes = b"",
    ) -> HPKEEncryptedMessage:
        """Encrypt with pre-shared key authentication (PSK mode).

        Combines asymmetric encryption with a shared secret for
        additional authentication.

        Args:
            recipient_public_key: Recipient's public key
            plaintext: Message to encrypt
            psk: Pre-shared key
            psk_id: Identifier for the PSK
            suite: Cipher suite to use
            info: Optional context info
            aad: Additional authenticated data

        Returns:
            HPKEEncryptedMessage
        """
        cs = self._get_cipher_suite(suite)

        # Load recipient's public key
        pk = cs.kem.deserialize_public_key(recipient_public_key)

        # Create PSK sender context
        enc, sender = cs.create_sender_context(
            pk, info=info, psk=psk, psk_id=psk_id
        )

        # Encrypt
        ciphertext = sender.seal(plaintext, aad=aad)

        return HPKEEncryptedMessage(
            enc=enc,
            ciphertext=ciphertext,
            suite=suite,
            mode=HPKEMode.PSK,
            info=info,
            aad=aad,
        )

    def decrypt_with_psk(
        self,
        recipient_private_key: bytes,
        encrypted_message: HPKEEncryptedMessage,
        psk: bytes,
        psk_id: bytes,
    ) -> bytes:
        """Decrypt with pre-shared key (PSK mode).

        Args:
            recipient_private_key: Recipient's private key
            encrypted_message: The encrypted message
            psk: Pre-shared key (must match sender's)
            psk_id: PSK identifier (must match sender's)

        Returns:
            Decrypted plaintext
        """
        cs = self._get_cipher_suite(encrypted_message.suite)

        # Load private key
        sk = cs.kem.deserialize_private_key(recipient_private_key)

        # Create PSK recipient context
        recipient = cs.create_recipient_context(
            encrypted_message.enc,
            sk,
            info=encrypted_message.info,
            psk=psk,
            psk_id=psk_id,
        )

        # Decrypt
        plaintext = recipient.open(
            encrypted_message.ciphertext,
            aad=encrypted_message.aad,
        )

        return plaintext

    def get_suite_info(self, suite: HPKECipherSuite) -> dict[str, Any]:
        """Get information about a cipher suite.

        Args:
            suite: The cipher suite

        Returns:
            Dictionary with suite details
        """
        info = {
            HPKECipherSuite.X25519_SHA256_AES128GCM: {
                "name": "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
                "kem": "X25519",
                "kdf": "HKDF-SHA256",
                "aead": "AES-128-GCM",
                "security_level": 128,
                "nist_approved": False,
                "recommended": True,
            },
            HPKECipherSuite.X25519_SHA256_CHACHA20: {
                "name": "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305",
                "kem": "X25519",
                "kdf": "HKDF-SHA256",
                "aead": "ChaCha20-Poly1305",
                "security_level": 128,
                "nist_approved": False,
                "recommended": True,
            },
            HPKECipherSuite.P256_SHA256_AES128GCM: {
                "name": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
                "kem": "P-256",
                "kdf": "HKDF-SHA256",
                "aead": "AES-128-GCM",
                "security_level": 128,
                "nist_approved": True,
                "recommended": True,
            },
            HPKECipherSuite.P256_SHA256_CHACHA20: {
                "name": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305",
                "kem": "P-256",
                "kdf": "HKDF-SHA256",
                "aead": "ChaCha20-Poly1305",
                "security_level": 128,
                "nist_approved": False,
                "recommended": False,
            },
            HPKECipherSuite.P384_SHA384_AES256GCM: {
                "name": "DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM",
                "kem": "P-384",
                "kdf": "HKDF-SHA384",
                "aead": "AES-256-GCM",
                "security_level": 192,
                "nist_approved": True,
                "recommended": False,
            },
        }
        return info.get(suite, {})

    def list_cipher_suites(self) -> list[dict[str, Any]]:
        """List all supported cipher suites.

        Returns:
            List of cipher suite information
        """
        return [
            {"suite": suite.value, **self.get_suite_info(suite)}
            for suite in HPKECipherSuite
        ]


# Singleton instance (created on first use to avoid import errors)
_hpke_engine: HPKEEngine | None = None


def get_hpke_engine() -> HPKEEngine:
    """Get the HPKE engine singleton.

    Returns:
        HPKEEngine instance

    Raises:
        HPKEError: If pyhpke is not available
    """
    global _hpke_engine
    if _hpke_engine is None:
        _hpke_engine = HPKEEngine()
    return _hpke_engine


def hpke_available() -> bool:
    """Check if HPKE is available.

    Returns:
        True if pyhpke is installed
    """
    return HPKE_AVAILABLE
