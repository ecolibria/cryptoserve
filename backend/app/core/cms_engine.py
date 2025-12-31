"""Cryptographic Message Syntax (CMS) Engine.

Implements PKCS#7/CMS (RFC 5652) message formats for interoperable
cryptographic operations.

Supported Content Types:
- SignedData: Digital signatures with certificate chains
- EnvelopedData: Public key encryption for multiple recipients
- EncryptedData: Symmetric encryption
- AuthenticatedData: MAC-based authentication

Use Cases:
- Secure email (S/MIME)
- Document signing
- Secure data exchange
- Certificate-based encryption

References:
- RFC 5652: Cryptographic Message Syntax (CMS)
- RFC 3565: AES-CBC Content Encryption Algorithm
- RFC 5084: AES-GCM and AES-CCM for CMS
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.x509 import Certificate, load_pem_x509_certificate


class CMSContentType(str, Enum):
    """CMS content types (OIDs simplified to names)."""

    DATA = "data"  # 1.2.840.113549.1.7.1
    SIGNED_DATA = "signed-data"  # 1.2.840.113549.1.7.2
    ENVELOPED_DATA = "enveloped-data"  # 1.2.840.113549.1.7.3
    ENCRYPTED_DATA = "encrypted-data"  # 1.2.840.113549.1.7.6
    AUTHENTICATED_DATA = "authenticated-data"  # 1.2.840.113549.1.9.16.1.2


class CMSEncryptionAlgorithm(str, Enum):
    """Supported CMS encryption algorithms."""

    AES_128_CBC = "aes-128-cbc"
    AES_256_CBC = "aes-256-cbc"
    AES_128_GCM = "aes-128-gcm"
    AES_256_GCM = "aes-256-gcm"


class CMSDigestAlgorithm(str, Enum):
    """Supported digest algorithms for CMS."""

    SHA256 = "sha-256"
    SHA384 = "sha-384"
    SHA512 = "sha-512"


class CMSError(Exception):
    """CMS operation failed."""

    pass


class CMSDecryptionError(CMSError):
    """CMS decryption failed."""

    pass


class CMSVerificationError(CMSError):
    """CMS signature verification failed."""

    pass


class CMSFormatError(CMSError):
    """CMS format parsing failed."""

    pass


@dataclass
class SignerInfo:
    """Information about a signer in SignedData."""

    certificate_pem: bytes
    digest_algorithm: CMSDigestAlgorithm
    signature: bytes
    signed_attributes: dict = field(default_factory=dict)
    signing_time: Optional[datetime] = None


@dataclass
class RecipientInfo:
    """Information about a recipient in EnvelopedData."""

    certificate_pem: bytes
    encrypted_key: bytes
    key_encryption_algorithm: str = "rsaes-oaep"


@dataclass
class SignedDataResult:
    """Result of creating SignedData."""

    content_type: CMSContentType = CMSContentType.SIGNED_DATA
    version: int = 1
    digest_algorithms: list[CMSDigestAlgorithm] = field(default_factory=list)
    encapsulated_content: bytes = b""
    signers: list[SignerInfo] = field(default_factory=list)
    certificates: list[bytes] = field(default_factory=list)
    serialized: bytes = b""


@dataclass
class EnvelopedDataResult:
    """Result of creating EnvelopedData."""

    content_type: CMSContentType = CMSContentType.ENVELOPED_DATA
    version: int = 0
    recipients: list[RecipientInfo] = field(default_factory=list)
    encryption_algorithm: CMSEncryptionAlgorithm = CMSEncryptionAlgorithm.AES_256_GCM
    encrypted_content: bytes = b""
    iv_or_nonce: bytes = b""
    auth_tag: Optional[bytes] = None
    serialized: bytes = b""


@dataclass
class EncryptedDataResult:
    """Result of creating EncryptedData."""

    content_type: CMSContentType = CMSContentType.ENCRYPTED_DATA
    version: int = 0
    encryption_algorithm: CMSEncryptionAlgorithm = CMSEncryptionAlgorithm.AES_256_GCM
    encrypted_content: bytes = b""
    iv_or_nonce: bytes = b""
    auth_tag: Optional[bytes] = None
    serialized: bytes = b""


@dataclass
class AuthenticatedDataResult:
    """Result of creating AuthenticatedData."""

    content_type: CMSContentType = CMSContentType.AUTHENTICATED_DATA
    version: int = 0
    recipients: list[RecipientInfo] = field(default_factory=list)
    mac_algorithm: str = "hmac-sha256"
    digest_algorithm: CMSDigestAlgorithm = CMSDigestAlgorithm.SHA256
    encapsulated_content: bytes = b""
    mac: bytes = b""
    serialized: bytes = b""


@dataclass
class DecryptionResult:
    """Result of decrypting CMS data."""

    plaintext: bytes
    content_type: CMSContentType
    encryption_algorithm: CMSEncryptionAlgorithm


@dataclass
class VerificationResult:
    """Result of verifying SignedData."""

    verified: bool
    content: bytes
    signers: list[SignerInfo]
    certificates: list[bytes]


class CMSEngine:
    """Cryptographic Message Syntax (CMS) operations.

    Provides PKCS#7/CMS message creation and processing for
    digital signatures and encryption.

    Usage:
        engine = CMSEngine()

        # Sign data
        signed = engine.create_signed_data(
            content=b"document",
            signer_key=private_key,
            signer_certificate=cert_pem,
        )

        # Encrypt for recipients
        enveloped = engine.create_enveloped_data(
            content=b"secret data",
            recipient_certificates=[cert1_pem, cert2_pem],
        )

        # Symmetric encryption
        encrypted = engine.create_encrypted_data(
            content=b"data",
            key=symmetric_key,
        )
    """

    # Hash algorithm mapping
    DIGEST_ALGORITHMS = {
        CMSDigestAlgorithm.SHA256: hashes.SHA256(),
        CMSDigestAlgorithm.SHA384: hashes.SHA384(),
        CMSDigestAlgorithm.SHA512: hashes.SHA512(),
    }

    # Key sizes for encryption algorithms
    KEY_SIZES = {
        CMSEncryptionAlgorithm.AES_128_CBC: 16,
        CMSEncryptionAlgorithm.AES_256_CBC: 32,
        CMSEncryptionAlgorithm.AES_128_GCM: 16,
        CMSEncryptionAlgorithm.AES_256_GCM: 32,
    }

    # Version numbers for different structures
    SIGNED_DATA_VERSION = 1
    ENVELOPED_DATA_VERSION = 0
    ENCRYPTED_DATA_VERSION = 0
    AUTHENTICATED_DATA_VERSION = 0

    def create_signed_data(
        self,
        content: bytes,
        signer_key: bytes,
        signer_certificate: bytes,
        digest_algorithm: CMSDigestAlgorithm = CMSDigestAlgorithm.SHA256,
        include_content: bool = True,
        detached: bool = False,
    ) -> SignedDataResult:
        """Create a SignedData structure.

        Args:
            content: Data to sign
            signer_key: PEM-encoded private key
            signer_certificate: PEM-encoded certificate
            digest_algorithm: Hash algorithm for signature
            include_content: Include content in result
            detached: Create detached signature (content not embedded)

        Returns:
            SignedDataResult with signature

        Raises:
            CMSError: If signing fails
        """
        if not content:
            raise CMSError("Content cannot be empty")

        # Load the private key
        try:
            private_key = serialization.load_pem_private_key(signer_key, password=None)
        except Exception as e:
            raise CMSError(f"Failed to load private key: {e}")

        # Load and validate certificate
        try:
            cert = load_pem_x509_certificate(signer_certificate)
        except Exception as e:
            raise CMSError(f"Failed to load certificate: {e}")

        # Create digest of content
        hash_algo = self.DIGEST_ALGORITHMS[digest_algorithm]
        digest = hashes.Hash(hash_algo.__class__())
        digest.update(content)
        content_digest = digest.finalize()

        # Create signed attributes
        signing_time = datetime.now(timezone.utc)
        signed_attributes = {
            "content-type": CMSContentType.DATA.value,
            "message-digest": content_digest.hex(),
            "signing-time": signing_time.isoformat(),
        }

        # Create signature
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                content,
                padding.PKCS1v15(),
                hash_algo.__class__(),
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                content,
                ec.ECDSA(hash_algo.__class__()),
            )
        else:
            raise CMSError(f"Unsupported key type: {type(private_key)}")

        # Create signer info
        signer_info = SignerInfo(
            certificate_pem=signer_certificate,
            digest_algorithm=digest_algorithm,
            signature=signature,
            signed_attributes=signed_attributes,
            signing_time=signing_time,
        )

        # Build result
        result = SignedDataResult(
            version=self.SIGNED_DATA_VERSION,
            digest_algorithms=[digest_algorithm],
            encapsulated_content=content if include_content and not detached else b"",
            signers=[signer_info],
            certificates=[signer_certificate],
        )

        # Serialize to our internal format
        result.serialized = self._serialize_signed_data(result)

        return result

    def verify_signed_data(
        self,
        signed_data: SignedDataResult | bytes,
        content: Optional[bytes] = None,
    ) -> VerificationResult:
        """Verify a SignedData structure.

        Args:
            signed_data: SignedData structure or serialized bytes
            content: Original content (required for detached signatures)

        Returns:
            VerificationResult with verification status

        Raises:
            CMSVerificationError: If verification fails
        """
        # Parse if bytes
        if isinstance(signed_data, bytes):
            signed_data = self._parse_signed_data(signed_data)

        # Get content
        data_to_verify = content if content else signed_data.encapsulated_content
        if not data_to_verify:
            raise CMSVerificationError("No content to verify")

        # Verify each signer
        verified_signers = []
        for signer in signed_data.signers:
            try:
                # Load certificate
                cert = load_pem_x509_certificate(signer.certificate_pem)
                public_key = cert.public_key()

                # Verify signature
                hash_algo = self.DIGEST_ALGORITHMS[signer.digest_algorithm]

                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signer.signature,
                        data_to_verify,
                        padding.PKCS1v15(),
                        hash_algo.__class__(),
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        signer.signature,
                        data_to_verify,
                        ec.ECDSA(hash_algo.__class__()),
                    )
                else:
                    raise CMSVerificationError(
                        f"Unsupported key type: {type(public_key)}"
                    )

                verified_signers.append(signer)
            except Exception as e:
                raise CMSVerificationError(f"Signature verification failed: {e}")

        return VerificationResult(
            verified=len(verified_signers) == len(signed_data.signers),
            content=data_to_verify,
            signers=verified_signers,
            certificates=signed_data.certificates,
        )

    def create_enveloped_data(
        self,
        content: bytes,
        recipient_certificates: list[bytes],
        encryption_algorithm: CMSEncryptionAlgorithm = CMSEncryptionAlgorithm.AES_256_GCM,
    ) -> EnvelopedDataResult:
        """Create an EnvelopedData structure.

        Encrypts content for multiple recipients using their public keys.

        Args:
            content: Data to encrypt
            recipient_certificates: List of PEM-encoded recipient certificates
            encryption_algorithm: Content encryption algorithm

        Returns:
            EnvelopedDataResult with encrypted content

        Raises:
            CMSError: If encryption fails
        """
        if not content:
            raise CMSError("Content cannot be empty")
        if not recipient_certificates:
            raise CMSError("At least one recipient certificate required")

        # Generate content encryption key (CEK)
        key_size = self.KEY_SIZES[encryption_algorithm]
        cek = os.urandom(key_size)

        # Encrypt content
        if encryption_algorithm in (
            CMSEncryptionAlgorithm.AES_128_GCM,
            CMSEncryptionAlgorithm.AES_256_GCM,
        ):
            nonce = os.urandom(12)
            aesgcm = AESGCM(cek)
            ciphertext = aesgcm.encrypt(nonce, content, None)
            # GCM appends tag to ciphertext
            encrypted_content = ciphertext[:-16]
            auth_tag = ciphertext[-16:]
            iv_or_nonce = nonce
        else:
            # CBC mode
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(cek), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # PKCS7 padding
            pad_len = 16 - (len(content) % 16)
            padded = content + bytes([pad_len] * pad_len)
            encrypted_content = encryptor.update(padded) + encryptor.finalize()
            iv_or_nonce = iv
            auth_tag = None

        # Encrypt CEK for each recipient
        recipients = []
        for cert_pem in recipient_certificates:
            try:
                cert = load_pem_x509_certificate(cert_pem)
                public_key = cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    encrypted_key = public_key.encrypt(
                        cek,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                else:
                    raise CMSError(
                        f"Unsupported key type for key encryption: {type(public_key)}"
                    )

                recipients.append(
                    RecipientInfo(
                        certificate_pem=cert_pem,
                        encrypted_key=encrypted_key,
                        key_encryption_algorithm="rsaes-oaep",
                    )
                )
            except Exception as e:
                raise CMSError(f"Failed to encrypt key for recipient: {e}")

        result = EnvelopedDataResult(
            version=self.ENVELOPED_DATA_VERSION,
            recipients=recipients,
            encryption_algorithm=encryption_algorithm,
            encrypted_content=encrypted_content,
            iv_or_nonce=iv_or_nonce,
            auth_tag=auth_tag,
        )

        result.serialized = self._serialize_enveloped_data(result)

        return result

    def decrypt_enveloped_data(
        self,
        enveloped_data: EnvelopedDataResult | bytes,
        recipient_key: bytes,
        recipient_certificate: bytes,
    ) -> DecryptionResult:
        """Decrypt an EnvelopedData structure.

        Args:
            enveloped_data: EnvelopedData structure or serialized bytes
            recipient_key: PEM-encoded private key
            recipient_certificate: PEM-encoded certificate (to find RecipientInfo)

        Returns:
            DecryptionResult with decrypted content

        Raises:
            CMSDecryptionError: If decryption fails
        """
        # Parse if bytes
        if isinstance(enveloped_data, bytes):
            enveloped_data = self._parse_enveloped_data(enveloped_data)

        # Load private key
        try:
            private_key = serialization.load_pem_private_key(
                recipient_key, password=None
            )
        except Exception as e:
            raise CMSDecryptionError(f"Failed to load private key: {e}")

        # Find matching recipient
        matching_recipient = None
        for recipient in enveloped_data.recipients:
            if recipient.certificate_pem == recipient_certificate:
                matching_recipient = recipient
                break

        if not matching_recipient:
            raise CMSDecryptionError("No matching recipient found")

        # Decrypt CEK
        try:
            if isinstance(private_key, rsa.RSAPrivateKey):
                cek = private_key.decrypt(
                    matching_recipient.encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            else:
                raise CMSDecryptionError(
                    f"Unsupported key type: {type(private_key)}"
                )
        except Exception as e:
            raise CMSDecryptionError(f"Failed to decrypt content encryption key: {e}")

        # Decrypt content
        algo = enveloped_data.encryption_algorithm
        try:
            if algo in (
                CMSEncryptionAlgorithm.AES_128_GCM,
                CMSEncryptionAlgorithm.AES_256_GCM,
            ):
                aesgcm = AESGCM(cek)
                # Append tag back to ciphertext for decryption
                ciphertext_with_tag = (
                    enveloped_data.encrypted_content + enveloped_data.auth_tag
                )
                plaintext = aesgcm.decrypt(
                    enveloped_data.iv_or_nonce,
                    ciphertext_with_tag,
                    None,
                )
            else:
                # CBC mode
                cipher = Cipher(
                    algorithms.AES(cek),
                    modes.CBC(enveloped_data.iv_or_nonce),
                )
                decryptor = cipher.decryptor()
                padded = (
                    decryptor.update(enveloped_data.encrypted_content)
                    + decryptor.finalize()
                )
                # Remove PKCS7 padding
                pad_len = padded[-1]
                plaintext = padded[:-pad_len]
        except Exception as e:
            raise CMSDecryptionError(f"Content decryption failed: {e}")

        return DecryptionResult(
            plaintext=plaintext,
            content_type=CMSContentType.ENVELOPED_DATA,
            encryption_algorithm=algo,
        )

    def create_encrypted_data(
        self,
        content: bytes,
        key: bytes,
        encryption_algorithm: CMSEncryptionAlgorithm = CMSEncryptionAlgorithm.AES_256_GCM,
    ) -> EncryptedDataResult:
        """Create an EncryptedData structure.

        Uses symmetric encryption (key must be pre-shared).

        Args:
            content: Data to encrypt
            key: Symmetric encryption key
            encryption_algorithm: Encryption algorithm

        Returns:
            EncryptedDataResult with encrypted content

        Raises:
            CMSError: If encryption fails
        """
        if not content:
            raise CMSError("Content cannot be empty")

        expected_key_size = self.KEY_SIZES[encryption_algorithm]
        if len(key) != expected_key_size:
            raise CMSError(
                f"Key must be {expected_key_size} bytes for {encryption_algorithm}"
            )

        # Encrypt content
        if encryption_algorithm in (
            CMSEncryptionAlgorithm.AES_128_GCM,
            CMSEncryptionAlgorithm.AES_256_GCM,
        ):
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, content, None)
            encrypted_content = ciphertext[:-16]
            auth_tag = ciphertext[-16:]
            iv_or_nonce = nonce
        else:
            # CBC mode
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # PKCS7 padding
            pad_len = 16 - (len(content) % 16)
            padded = content + bytes([pad_len] * pad_len)
            encrypted_content = encryptor.update(padded) + encryptor.finalize()
            iv_or_nonce = iv
            auth_tag = None

        result = EncryptedDataResult(
            version=self.ENCRYPTED_DATA_VERSION,
            encryption_algorithm=encryption_algorithm,
            encrypted_content=encrypted_content,
            iv_or_nonce=iv_or_nonce,
            auth_tag=auth_tag,
        )

        result.serialized = self._serialize_encrypted_data(result)

        return result

    def decrypt_encrypted_data(
        self,
        encrypted_data: EncryptedDataResult | bytes,
        key: bytes,
    ) -> DecryptionResult:
        """Decrypt an EncryptedData structure.

        Args:
            encrypted_data: EncryptedData structure or serialized bytes
            key: Symmetric decryption key

        Returns:
            DecryptionResult with decrypted content

        Raises:
            CMSDecryptionError: If decryption fails
        """
        # Parse if bytes
        if isinstance(encrypted_data, bytes):
            encrypted_data = self._parse_encrypted_data(encrypted_data)

        algo = encrypted_data.encryption_algorithm
        expected_key_size = self.KEY_SIZES[algo]
        if len(key) != expected_key_size:
            raise CMSDecryptionError(
                f"Key must be {expected_key_size} bytes for {algo}"
            )

        try:
            if algo in (
                CMSEncryptionAlgorithm.AES_128_GCM,
                CMSEncryptionAlgorithm.AES_256_GCM,
            ):
                aesgcm = AESGCM(key)
                ciphertext_with_tag = (
                    encrypted_data.encrypted_content + encrypted_data.auth_tag
                )
                plaintext = aesgcm.decrypt(
                    encrypted_data.iv_or_nonce,
                    ciphertext_with_tag,
                    None,
                )
            else:
                # CBC mode
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(encrypted_data.iv_or_nonce),
                )
                decryptor = cipher.decryptor()
                padded = (
                    decryptor.update(encrypted_data.encrypted_content)
                    + decryptor.finalize()
                )
                # Remove PKCS7 padding
                pad_len = padded[-1]
                plaintext = padded[:-pad_len]
        except Exception as e:
            raise CMSDecryptionError(f"Decryption failed: {e}")

        return DecryptionResult(
            plaintext=plaintext,
            content_type=CMSContentType.ENCRYPTED_DATA,
            encryption_algorithm=algo,
        )

    def create_authenticated_data(
        self,
        content: bytes,
        recipient_certificates: list[bytes],
        digest_algorithm: CMSDigestAlgorithm = CMSDigestAlgorithm.SHA256,
    ) -> AuthenticatedDataResult:
        """Create an AuthenticatedData structure.

        Provides MAC-based authentication without encryption.

        Args:
            content: Data to authenticate
            recipient_certificates: List of PEM-encoded recipient certificates
            digest_algorithm: Hash algorithm for MAC

        Returns:
            AuthenticatedDataResult with MAC

        Raises:
            CMSError: If operation fails
        """
        if not content:
            raise CMSError("Content cannot be empty")
        if not recipient_certificates:
            raise CMSError("At least one recipient certificate required")

        # Generate MAC key
        mac_key = os.urandom(32)

        # Compute MAC
        hash_algo = self.DIGEST_ALGORITHMS[digest_algorithm]
        h = HMAC(mac_key, hash_algo.__class__())
        h.update(content)
        mac_value = h.finalize()

        # Encrypt MAC key for each recipient
        recipients = []
        for cert_pem in recipient_certificates:
            try:
                cert = load_pem_x509_certificate(cert_pem)
                public_key = cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    encrypted_key = public_key.encrypt(
                        mac_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                else:
                    raise CMSError(
                        f"Unsupported key type for key encryption: {type(public_key)}"
                    )

                recipients.append(
                    RecipientInfo(
                        certificate_pem=cert_pem,
                        encrypted_key=encrypted_key,
                        key_encryption_algorithm="rsaes-oaep",
                    )
                )
            except Exception as e:
                raise CMSError(f"Failed to encrypt key for recipient: {e}")

        result = AuthenticatedDataResult(
            version=self.AUTHENTICATED_DATA_VERSION,
            recipients=recipients,
            mac_algorithm=f"hmac-{digest_algorithm.value}",
            digest_algorithm=digest_algorithm,
            encapsulated_content=content,
            mac=mac_value,
        )

        result.serialized = self._serialize_authenticated_data(result)

        return result

    def verify_authenticated_data(
        self,
        authenticated_data: AuthenticatedDataResult | bytes,
        recipient_key: bytes,
        recipient_certificate: bytes,
    ) -> VerificationResult:
        """Verify an AuthenticatedData structure.

        Args:
            authenticated_data: AuthenticatedData or serialized bytes
            recipient_key: PEM-encoded private key
            recipient_certificate: PEM-encoded certificate

        Returns:
            VerificationResult

        Raises:
            CMSVerificationError: If verification fails
        """
        # Parse if bytes
        if isinstance(authenticated_data, bytes):
            authenticated_data = self._parse_authenticated_data(authenticated_data)

        # Load private key
        try:
            private_key = serialization.load_pem_private_key(
                recipient_key, password=None
            )
        except Exception as e:
            raise CMSVerificationError(f"Failed to load private key: {e}")

        # Find matching recipient
        matching_recipient = None
        for recipient in authenticated_data.recipients:
            if recipient.certificate_pem == recipient_certificate:
                matching_recipient = recipient
                break

        if not matching_recipient:
            raise CMSVerificationError("No matching recipient found")

        # Decrypt MAC key
        try:
            if isinstance(private_key, rsa.RSAPrivateKey):
                mac_key = private_key.decrypt(
                    matching_recipient.encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            else:
                raise CMSVerificationError(
                    f"Unsupported key type: {type(private_key)}"
                )
        except Exception as e:
            raise CMSVerificationError(f"Failed to decrypt MAC key: {e}")

        # Verify MAC
        try:
            hash_algo = self.DIGEST_ALGORITHMS[authenticated_data.digest_algorithm]
            h = HMAC(mac_key, hash_algo.__class__())
            h.update(authenticated_data.encapsulated_content)
            h.verify(authenticated_data.mac)
        except Exception:
            raise CMSVerificationError("MAC verification failed")

        return VerificationResult(
            verified=True,
            content=authenticated_data.encapsulated_content,
            signers=[],
            certificates=[r.certificate_pem for r in authenticated_data.recipients],
        )

    # Serialization helpers (simplified binary format, not full ASN.1/DER)
    # These use a simple TLV (Type-Length-Value) format for demonstration
    # In production, use proper ASN.1/DER encoding

    def _serialize_signed_data(self, data: SignedDataResult) -> bytes:
        """Serialize SignedData to bytes."""
        parts = [
            b"SIGNED",  # Magic
            bytes([data.version]),
            self._encode_tlv(data.encapsulated_content),
        ]

        # Encode signers
        signer_data = b""
        for signer in data.signers:
            signer_data += self._encode_tlv(signer.certificate_pem)
            signer_data += self._encode_tlv(signer.digest_algorithm.value.encode())
            signer_data += self._encode_tlv(signer.signature)

        parts.append(self._encode_tlv(signer_data))

        # Encode certificates
        certs_data = b"".join(self._encode_tlv(c) for c in data.certificates)
        parts.append(self._encode_tlv(certs_data))

        return b"".join(parts)

    def _parse_signed_data(self, data: bytes) -> SignedDataResult:
        """Parse SignedData from bytes."""
        if not data.startswith(b"SIGNED"):
            raise CMSFormatError("Invalid SignedData format")

        pos = 6
        version = data[pos]
        pos += 1

        content, pos = self._decode_tlv(data, pos)

        signer_data, pos = self._decode_tlv(data, pos)
        signers = []
        signer_pos = 0
        while signer_pos < len(signer_data):
            cert_pem, signer_pos = self._decode_tlv(signer_data, signer_pos)
            algo_bytes, signer_pos = self._decode_tlv(signer_data, signer_pos)
            signature, signer_pos = self._decode_tlv(signer_data, signer_pos)

            signers.append(
                SignerInfo(
                    certificate_pem=cert_pem,
                    digest_algorithm=CMSDigestAlgorithm(algo_bytes.decode()),
                    signature=signature,
                )
            )

        certs_data, pos = self._decode_tlv(data, pos)
        certificates = []
        cert_pos = 0
        while cert_pos < len(certs_data):
            cert, cert_pos = self._decode_tlv(certs_data, cert_pos)
            certificates.append(cert)

        return SignedDataResult(
            version=version,
            encapsulated_content=content,
            signers=signers,
            certificates=certificates,
        )

    def _serialize_enveloped_data(self, data: EnvelopedDataResult) -> bytes:
        """Serialize EnvelopedData to bytes."""
        parts = [
            b"ENVELOPE",  # Magic
            bytes([data.version]),
            self._encode_tlv(data.encryption_algorithm.value.encode()),
            self._encode_tlv(data.iv_or_nonce),
            self._encode_tlv(data.encrypted_content),
            self._encode_tlv(data.auth_tag if data.auth_tag else b""),
        ]

        # Encode recipients
        recipients_data = b""
        for r in data.recipients:
            recipients_data += self._encode_tlv(r.certificate_pem)
            recipients_data += self._encode_tlv(r.encrypted_key)
            recipients_data += self._encode_tlv(r.key_encryption_algorithm.encode())

        parts.append(self._encode_tlv(recipients_data))

        return b"".join(parts)

    def _parse_enveloped_data(self, data: bytes) -> EnvelopedDataResult:
        """Parse EnvelopedData from bytes."""
        if not data.startswith(b"ENVELOPE"):
            raise CMSFormatError("Invalid EnvelopedData format")

        pos = 8
        version = data[pos]
        pos += 1

        algo_bytes, pos = self._decode_tlv(data, pos)
        iv_or_nonce, pos = self._decode_tlv(data, pos)
        encrypted_content, pos = self._decode_tlv(data, pos)
        auth_tag_bytes, pos = self._decode_tlv(data, pos)
        auth_tag = auth_tag_bytes if auth_tag_bytes else None

        recipients_data, pos = self._decode_tlv(data, pos)
        recipients = []
        r_pos = 0
        while r_pos < len(recipients_data):
            cert_pem, r_pos = self._decode_tlv(recipients_data, r_pos)
            enc_key, r_pos = self._decode_tlv(recipients_data, r_pos)
            key_algo, r_pos = self._decode_tlv(recipients_data, r_pos)

            recipients.append(
                RecipientInfo(
                    certificate_pem=cert_pem,
                    encrypted_key=enc_key,
                    key_encryption_algorithm=key_algo.decode(),
                )
            )

        return EnvelopedDataResult(
            version=version,
            encryption_algorithm=CMSEncryptionAlgorithm(algo_bytes.decode()),
            iv_or_nonce=iv_or_nonce,
            encrypted_content=encrypted_content,
            auth_tag=auth_tag,
            recipients=recipients,
        )

    def _serialize_encrypted_data(self, data: EncryptedDataResult) -> bytes:
        """Serialize EncryptedData to bytes."""
        return b"".join(
            [
                b"ENCRYPTED",  # Magic
                bytes([data.version]),
                self._encode_tlv(data.encryption_algorithm.value.encode()),
                self._encode_tlv(data.iv_or_nonce),
                self._encode_tlv(data.encrypted_content),
                self._encode_tlv(data.auth_tag if data.auth_tag else b""),
            ]
        )

    def _parse_encrypted_data(self, data: bytes) -> EncryptedDataResult:
        """Parse EncryptedData from bytes."""
        if not data.startswith(b"ENCRYPTED"):
            raise CMSFormatError("Invalid EncryptedData format")

        pos = 9
        version = data[pos]
        pos += 1

        algo_bytes, pos = self._decode_tlv(data, pos)
        iv_or_nonce, pos = self._decode_tlv(data, pos)
        encrypted_content, pos = self._decode_tlv(data, pos)
        auth_tag_bytes, pos = self._decode_tlv(data, pos)
        auth_tag = auth_tag_bytes if auth_tag_bytes else None

        return EncryptedDataResult(
            version=version,
            encryption_algorithm=CMSEncryptionAlgorithm(algo_bytes.decode()),
            iv_or_nonce=iv_or_nonce,
            encrypted_content=encrypted_content,
            auth_tag=auth_tag,
        )

    def _serialize_authenticated_data(self, data: AuthenticatedDataResult) -> bytes:
        """Serialize AuthenticatedData to bytes."""
        parts = [
            b"AUTHDATA",  # Magic
            bytes([data.version]),
            self._encode_tlv(data.mac_algorithm.encode()),
            self._encode_tlv(data.digest_algorithm.value.encode()),
            self._encode_tlv(data.encapsulated_content),
            self._encode_tlv(data.mac),
        ]

        # Encode recipients
        recipients_data = b""
        for r in data.recipients:
            recipients_data += self._encode_tlv(r.certificate_pem)
            recipients_data += self._encode_tlv(r.encrypted_key)
            recipients_data += self._encode_tlv(r.key_encryption_algorithm.encode())

        parts.append(self._encode_tlv(recipients_data))

        return b"".join(parts)

    def _parse_authenticated_data(self, data: bytes) -> AuthenticatedDataResult:
        """Parse AuthenticatedData from bytes."""
        if not data.startswith(b"AUTHDATA"):
            raise CMSFormatError("Invalid AuthenticatedData format")

        pos = 8
        version = data[pos]
        pos += 1

        mac_algo, pos = self._decode_tlv(data, pos)
        digest_algo_bytes, pos = self._decode_tlv(data, pos)
        content, pos = self._decode_tlv(data, pos)
        mac_value, pos = self._decode_tlv(data, pos)

        recipients_data, pos = self._decode_tlv(data, pos)
        recipients = []
        r_pos = 0
        while r_pos < len(recipients_data):
            cert_pem, r_pos = self._decode_tlv(recipients_data, r_pos)
            enc_key, r_pos = self._decode_tlv(recipients_data, r_pos)
            key_algo, r_pos = self._decode_tlv(recipients_data, r_pos)

            recipients.append(
                RecipientInfo(
                    certificate_pem=cert_pem,
                    encrypted_key=enc_key,
                    key_encryption_algorithm=key_algo.decode(),
                )
            )

        return AuthenticatedDataResult(
            version=version,
            mac_algorithm=mac_algo.decode(),
            digest_algorithm=CMSDigestAlgorithm(digest_algo_bytes.decode()),
            encapsulated_content=content,
            mac=mac_value,
            recipients=recipients,
        )

    def _encode_tlv(self, value: bytes) -> bytes:
        """Encode value with length prefix (4 bytes, big-endian)."""
        return len(value).to_bytes(4, "big") + value

    def _decode_tlv(self, data: bytes, pos: int) -> tuple[bytes, int]:
        """Decode TLV and return (value, new_position)."""
        if pos + 4 > len(data):
            raise CMSFormatError("Truncated TLV")
        length = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if pos + length > len(data):
            raise CMSFormatError("Truncated TLV value")
        value = data[pos : pos + length]
        return value, pos + length


# Singleton instance
cms_engine = CMSEngine()
