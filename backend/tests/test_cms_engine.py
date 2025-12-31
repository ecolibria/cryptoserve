"""Tests for CMS (Cryptographic Message Syntax) engine."""

import os
import pytest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from app.core.cms_engine import (
    cms_engine,
    CMSEngine,
    CMSContentType,
    CMSEncryptionAlgorithm,
    CMSDigestAlgorithm,
    CMSError,
    CMSDecryptionError,
    CMSVerificationError,
    CMSFormatError,
    SignedDataResult,
    EnvelopedDataResult,
    EncryptedDataResult,
    AuthenticatedDataResult,
)


def generate_rsa_key_and_cert():
    """Generate an RSA key pair and self-signed certificate."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Serialize
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_key_pem, cert_pem


def generate_ec_key_and_cert():
    """Generate an EC key pair and self-signed certificate."""
    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org EC"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ec.test.example.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_key_pem, cert_pem


@pytest.fixture
def engine():
    """Create a fresh CMS engine."""
    return CMSEngine()


@pytest.fixture
def rsa_credentials():
    """Generate RSA key and certificate."""
    return generate_rsa_key_and_cert()


@pytest.fixture
def ec_credentials():
    """Generate EC key and certificate."""
    return generate_ec_key_and_cert()


@pytest.fixture
def second_rsa_credentials():
    """Generate second RSA key and certificate for multi-recipient tests."""
    return generate_rsa_key_and_cert()


class TestSignedData:
    """Tests for SignedData creation and verification."""

    def test_sign_and_verify_rsa(self, engine, rsa_credentials):
        """Test signing and verifying with RSA."""
        private_key, cert = rsa_credentials
        content = b"Hello, signed world!"

        signed = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        assert signed.content_type == CMSContentType.SIGNED_DATA
        assert signed.version == 1
        assert len(signed.signers) == 1
        assert signed.encapsulated_content == content

        # Verify
        result = engine.verify_signed_data(signed)

        assert result.verified is True
        assert result.content == content
        assert len(result.signers) == 1

    def test_sign_and_verify_ec(self, engine, ec_credentials):
        """Test signing and verifying with EC."""
        private_key, cert = ec_credentials
        content = b"EC signed content"

        signed = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        result = engine.verify_signed_data(signed)

        assert result.verified is True
        assert result.content == content

    def test_sign_with_different_digest_algorithms(self, engine, rsa_credentials):
        """Test signing with different digest algorithms."""
        private_key, cert = rsa_credentials
        content = b"Test content"

        for algo in CMSDigestAlgorithm:
            signed = engine.create_signed_data(
                content=content,
                signer_key=private_key,
                signer_certificate=cert,
                digest_algorithm=algo,
            )

            assert algo in signed.digest_algorithms
            result = engine.verify_signed_data(signed)
            assert result.verified is True

    def test_detached_signature(self, engine, rsa_credentials):
        """Test creating detached signature."""
        private_key, cert = rsa_credentials
        content = b"Content for detached signature"

        signed = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
            detached=True,
        )

        assert signed.encapsulated_content == b""

        # Verify with external content
        result = engine.verify_signed_data(signed, content=content)

        assert result.verified is True
        assert result.content == content

    def test_verify_with_serialized(self, engine, rsa_credentials):
        """Test verifying from serialized bytes."""
        private_key, cert = rsa_credentials
        content = b"Serialization test"

        signed = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        # Verify from serialized
        result = engine.verify_signed_data(signed.serialized)

        assert result.verified is True
        assert result.content == content

    def test_sign_empty_content_fails(self, engine, rsa_credentials):
        """Test that signing empty content fails."""
        private_key, cert = rsa_credentials

        with pytest.raises(CMSError, match="empty"):
            engine.create_signed_data(
                content=b"",
                signer_key=private_key,
                signer_certificate=cert,
            )

    def test_sign_with_invalid_key_fails(self, engine, rsa_credentials):
        """Test that signing with invalid key fails."""
        _, cert = rsa_credentials

        with pytest.raises(CMSError, match="private key"):
            engine.create_signed_data(
                content=b"test",
                signer_key=b"not a key",
                signer_certificate=cert,
            )


class TestEnvelopedData:
    """Tests for EnvelopedData (public key encryption)."""

    def test_encrypt_decrypt_single_recipient(self, engine, rsa_credentials):
        """Test encrypting for a single recipient."""
        private_key, cert = rsa_credentials
        content = b"Secret message"

        enveloped = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert],
        )

        assert enveloped.content_type == CMSContentType.ENVELOPED_DATA
        assert len(enveloped.recipients) == 1
        assert enveloped.encrypted_content != content

        # Decrypt
        result = engine.decrypt_enveloped_data(
            enveloped,
            recipient_key=private_key,
            recipient_certificate=cert,
        )

        assert result.plaintext == content

    def test_encrypt_decrypt_multiple_recipients(
        self, engine, rsa_credentials, second_rsa_credentials
    ):
        """Test encrypting for multiple recipients."""
        key1, cert1 = rsa_credentials
        key2, cert2 = second_rsa_credentials
        content = b"Multi-recipient secret"

        enveloped = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert1, cert2],
        )

        assert len(enveloped.recipients) == 2

        # Both recipients can decrypt
        result1 = engine.decrypt_enveloped_data(
            enveloped,
            recipient_key=key1,
            recipient_certificate=cert1,
        )
        assert result1.plaintext == content

        result2 = engine.decrypt_enveloped_data(
            enveloped,
            recipient_key=key2,
            recipient_certificate=cert2,
        )
        assert result2.plaintext == content

    def test_encrypt_with_aes_cbc(self, engine, rsa_credentials):
        """Test encrypting with AES-CBC."""
        private_key, cert = rsa_credentials
        content = b"CBC encrypted content"

        for algo in [
            CMSEncryptionAlgorithm.AES_128_CBC,
            CMSEncryptionAlgorithm.AES_256_CBC,
        ]:
            enveloped = engine.create_enveloped_data(
                content=content,
                recipient_certificates=[cert],
                encryption_algorithm=algo,
            )

            assert enveloped.encryption_algorithm == algo
            assert enveloped.auth_tag is None  # CBC has no auth tag

            result = engine.decrypt_enveloped_data(
                enveloped,
                recipient_key=private_key,
                recipient_certificate=cert,
            )
            assert result.plaintext == content

    def test_encrypt_with_aes_gcm(self, engine, rsa_credentials):
        """Test encrypting with AES-GCM."""
        private_key, cert = rsa_credentials
        content = b"GCM encrypted content"

        for algo in [
            CMSEncryptionAlgorithm.AES_128_GCM,
            CMSEncryptionAlgorithm.AES_256_GCM,
        ]:
            enveloped = engine.create_enveloped_data(
                content=content,
                recipient_certificates=[cert],
                encryption_algorithm=algo,
            )

            assert enveloped.encryption_algorithm == algo
            assert enveloped.auth_tag is not None  # GCM has auth tag

            result = engine.decrypt_enveloped_data(
                enveloped,
                recipient_key=private_key,
                recipient_certificate=cert,
            )
            assert result.plaintext == content

    def test_decrypt_with_serialized(self, engine, rsa_credentials):
        """Test decrypting from serialized bytes."""
        private_key, cert = rsa_credentials
        content = b"Serialized envelope"

        enveloped = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert],
        )

        result = engine.decrypt_enveloped_data(
            enveloped.serialized,
            recipient_key=private_key,
            recipient_certificate=cert,
        )

        assert result.plaintext == content

    def test_decrypt_wrong_recipient_fails(
        self, engine, rsa_credentials, second_rsa_credentials
    ):
        """Test that decryption with wrong recipient fails."""
        _, cert1 = rsa_credentials
        key2, cert2 = second_rsa_credentials
        content = b"Wrong recipient test"

        enveloped = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert1],  # Only cert1 is a recipient
        )

        with pytest.raises(CMSDecryptionError, match="No matching recipient"):
            engine.decrypt_enveloped_data(
                enveloped,
                recipient_key=key2,
                recipient_certificate=cert2,
            )

    def test_encrypt_empty_content_fails(self, engine, rsa_credentials):
        """Test that encrypting empty content fails."""
        _, cert = rsa_credentials

        with pytest.raises(CMSError, match="empty"):
            engine.create_enveloped_data(
                content=b"",
                recipient_certificates=[cert],
            )

    def test_encrypt_no_recipients_fails(self, engine):
        """Test that encrypting without recipients fails."""
        with pytest.raises(CMSError, match="recipient"):
            engine.create_enveloped_data(
                content=b"test",
                recipient_certificates=[],
            )


class TestEncryptedData:
    """Tests for EncryptedData (symmetric encryption)."""

    def test_encrypt_decrypt_aes_gcm(self, engine):
        """Test symmetric encryption with AES-GCM."""
        content = b"Symmetric secret"
        key = os.urandom(32)

        encrypted = engine.create_encrypted_data(
            content=content,
            key=key,
            encryption_algorithm=CMSEncryptionAlgorithm.AES_256_GCM,
        )

        assert encrypted.content_type == CMSContentType.ENCRYPTED_DATA
        assert encrypted.encrypted_content != content
        assert encrypted.auth_tag is not None

        result = engine.decrypt_encrypted_data(encrypted, key=key)

        assert result.plaintext == content

    def test_encrypt_decrypt_aes_cbc(self, engine):
        """Test symmetric encryption with AES-CBC."""
        content = b"CBC symmetric content"
        key = os.urandom(32)

        encrypted = engine.create_encrypted_data(
            content=content,
            key=key,
            encryption_algorithm=CMSEncryptionAlgorithm.AES_256_CBC,
        )

        assert encrypted.auth_tag is None

        result = engine.decrypt_encrypted_data(encrypted, key=key)

        assert result.plaintext == content

    def test_different_key_sizes(self, engine):
        """Test encryption with different key sizes."""
        content = b"Key size test"

        # AES-128
        key_128 = os.urandom(16)
        encrypted = engine.create_encrypted_data(
            content=content,
            key=key_128,
            encryption_algorithm=CMSEncryptionAlgorithm.AES_128_GCM,
        )
        result = engine.decrypt_encrypted_data(encrypted, key=key_128)
        assert result.plaintext == content

        # AES-256
        key_256 = os.urandom(32)
        encrypted = engine.create_encrypted_data(
            content=content,
            key=key_256,
            encryption_algorithm=CMSEncryptionAlgorithm.AES_256_GCM,
        )
        result = engine.decrypt_encrypted_data(encrypted, key=key_256)
        assert result.plaintext == content

    def test_decrypt_with_serialized(self, engine):
        """Test decrypting from serialized bytes."""
        content = b"Serialized encrypted"
        key = os.urandom(32)

        encrypted = engine.create_encrypted_data(content=content, key=key)

        result = engine.decrypt_encrypted_data(encrypted.serialized, key=key)

        assert result.plaintext == content

    def test_wrong_key_size_fails(self, engine):
        """Test that wrong key size fails."""
        with pytest.raises(CMSError, match="bytes"):
            engine.create_encrypted_data(
                content=b"test",
                key=os.urandom(24),  # Wrong size
                encryption_algorithm=CMSEncryptionAlgorithm.AES_256_GCM,
            )

    def test_wrong_decryption_key_fails(self, engine):
        """Test that decryption with wrong key fails."""
        content = b"Wrong key test"
        key = os.urandom(32)
        wrong_key = os.urandom(32)

        encrypted = engine.create_encrypted_data(content=content, key=key)

        with pytest.raises(CMSDecryptionError):
            engine.decrypt_encrypted_data(encrypted, key=wrong_key)

    def test_encrypt_empty_content_fails(self, engine):
        """Test that encrypting empty content fails."""
        with pytest.raises(CMSError, match="empty"):
            engine.create_encrypted_data(
                content=b"",
                key=os.urandom(32),
            )


class TestAuthenticatedData:
    """Tests for AuthenticatedData (MAC-based authentication)."""

    def test_create_and_verify(self, engine, rsa_credentials):
        """Test creating and verifying authenticated data."""
        private_key, cert = rsa_credentials
        content = b"Authenticated content"

        authenticated = engine.create_authenticated_data(
            content=content,
            recipient_certificates=[cert],
        )

        assert authenticated.content_type == CMSContentType.AUTHENTICATED_DATA
        assert authenticated.encapsulated_content == content
        assert len(authenticated.mac) > 0

        result = engine.verify_authenticated_data(
            authenticated,
            recipient_key=private_key,
            recipient_certificate=cert,
        )

        assert result.verified is True
        assert result.content == content

    def test_different_digest_algorithms(self, engine, rsa_credentials):
        """Test with different digest algorithms."""
        private_key, cert = rsa_credentials
        content = b"Digest test"

        for algo in CMSDigestAlgorithm:
            authenticated = engine.create_authenticated_data(
                content=content,
                recipient_certificates=[cert],
                digest_algorithm=algo,
            )

            assert authenticated.digest_algorithm == algo

            result = engine.verify_authenticated_data(
                authenticated,
                recipient_key=private_key,
                recipient_certificate=cert,
            )
            assert result.verified is True

    def test_multiple_recipients(
        self, engine, rsa_credentials, second_rsa_credentials
    ):
        """Test with multiple recipients."""
        key1, cert1 = rsa_credentials
        key2, cert2 = second_rsa_credentials
        content = b"Multi-auth content"

        authenticated = engine.create_authenticated_data(
            content=content,
            recipient_certificates=[cert1, cert2],
        )

        assert len(authenticated.recipients) == 2

        # Both can verify
        result1 = engine.verify_authenticated_data(
            authenticated,
            recipient_key=key1,
            recipient_certificate=cert1,
        )
        assert result1.verified is True

        result2 = engine.verify_authenticated_data(
            authenticated,
            recipient_key=key2,
            recipient_certificate=cert2,
        )
        assert result2.verified is True

    def test_verify_with_serialized(self, engine, rsa_credentials):
        """Test verifying from serialized bytes."""
        private_key, cert = rsa_credentials
        content = b"Serialized auth"

        authenticated = engine.create_authenticated_data(
            content=content,
            recipient_certificates=[cert],
        )

        result = engine.verify_authenticated_data(
            authenticated.serialized,
            recipient_key=private_key,
            recipient_certificate=cert,
        )

        assert result.verified is True

    def test_wrong_recipient_fails(
        self, engine, rsa_credentials, second_rsa_credentials
    ):
        """Test that verification with wrong recipient fails."""
        _, cert1 = rsa_credentials
        key2, cert2 = second_rsa_credentials
        content = b"Wrong auth recipient"

        authenticated = engine.create_authenticated_data(
            content=content,
            recipient_certificates=[cert1],
        )

        with pytest.raises(CMSVerificationError, match="No matching recipient"):
            engine.verify_authenticated_data(
                authenticated,
                recipient_key=key2,
                recipient_certificate=cert2,
            )

    def test_empty_content_fails(self, engine, rsa_credentials):
        """Test that empty content fails."""
        _, cert = rsa_credentials

        with pytest.raises(CMSError, match="empty"):
            engine.create_authenticated_data(
                content=b"",
                recipient_certificates=[cert],
            )


class TestSerialization:
    """Tests for serialization and parsing."""

    def test_signed_data_roundtrip(self, engine, rsa_credentials):
        """Test SignedData serialization roundtrip."""
        private_key, cert = rsa_credentials
        content = b"Roundtrip signed"

        original = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        # Parse serialized
        parsed = engine._parse_signed_data(original.serialized)

        assert parsed.version == original.version
        assert parsed.encapsulated_content == content
        assert len(parsed.signers) == len(original.signers)

    def test_enveloped_data_roundtrip(self, engine, rsa_credentials):
        """Test EnvelopedData serialization roundtrip."""
        private_key, cert = rsa_credentials
        content = b"Roundtrip enveloped"

        original = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert],
        )

        # Parse serialized
        parsed = engine._parse_enveloped_data(original.serialized)

        assert parsed.version == original.version
        assert parsed.encryption_algorithm == original.encryption_algorithm
        assert len(parsed.recipients) == len(original.recipients)

        # Can still decrypt
        result = engine.decrypt_enveloped_data(
            parsed,
            recipient_key=private_key,
            recipient_certificate=cert,
        )
        assert result.plaintext == content

    def test_encrypted_data_roundtrip(self, engine):
        """Test EncryptedData serialization roundtrip."""
        content = b"Roundtrip encrypted"
        key = os.urandom(32)

        original = engine.create_encrypted_data(content=content, key=key)

        # Parse serialized
        parsed = engine._parse_encrypted_data(original.serialized)

        assert parsed.version == original.version
        assert parsed.encryption_algorithm == original.encryption_algorithm

        # Can still decrypt
        result = engine.decrypt_encrypted_data(parsed, key=key)
        assert result.plaintext == content

    def test_authenticated_data_roundtrip(self, engine, rsa_credentials):
        """Test AuthenticatedData serialization roundtrip."""
        private_key, cert = rsa_credentials
        content = b"Roundtrip authenticated"

        original = engine.create_authenticated_data(
            content=content,
            recipient_certificates=[cert],
        )

        # Parse serialized
        parsed = engine._parse_authenticated_data(original.serialized)

        assert parsed.version == original.version
        assert parsed.mac == original.mac
        assert parsed.encapsulated_content == content

        # Can still verify
        result = engine.verify_authenticated_data(
            parsed,
            recipient_key=private_key,
            recipient_certificate=cert,
        )
        assert result.verified is True

    def test_invalid_format_fails(self, engine):
        """Test that invalid formats are rejected."""
        with pytest.raises(CMSFormatError):
            engine._parse_signed_data(b"INVALID")

        with pytest.raises(CMSFormatError):
            engine._parse_enveloped_data(b"INVALID")

        with pytest.raises(CMSFormatError):
            engine._parse_encrypted_data(b"INVALID")

        with pytest.raises(CMSFormatError):
            engine._parse_authenticated_data(b"INVALID")


class TestLargeContent:
    """Tests for handling large content."""

    def test_large_signed_data(self, engine, rsa_credentials):
        """Test signing large content."""
        private_key, cert = rsa_credentials
        content = os.urandom(100 * 1024)  # 100KB

        signed = engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        result = engine.verify_signed_data(signed)

        assert result.verified is True
        assert result.content == content

    def test_large_encrypted_data(self, engine):
        """Test encrypting large content."""
        content = os.urandom(100 * 1024)  # 100KB
        key = os.urandom(32)

        encrypted = engine.create_encrypted_data(content=content, key=key)
        result = engine.decrypt_encrypted_data(encrypted, key=key)

        assert result.plaintext == content

    def test_large_enveloped_data(self, engine, rsa_credentials):
        """Test enveloping large content."""
        private_key, cert = rsa_credentials
        content = os.urandom(100 * 1024)  # 100KB

        enveloped = engine.create_enveloped_data(
            content=content,
            recipient_certificates=[cert],
        )

        result = engine.decrypt_enveloped_data(
            enveloped,
            recipient_key=private_key,
            recipient_certificate=cert,
        )

        assert result.plaintext == content


class TestSingletonInstance:
    """Tests for singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert cms_engine is not None
        assert isinstance(cms_engine, CMSEngine)

    def test_singleton_works(self, rsa_credentials):
        """Test that singleton can perform operations."""
        private_key, cert = rsa_credentials
        content = b"Singleton test"

        signed = cms_engine.create_signed_data(
            content=content,
            signer_key=private_key,
            signer_certificate=cert,
        )

        result = cms_engine.verify_signed_data(signed)

        assert result.verified is True
