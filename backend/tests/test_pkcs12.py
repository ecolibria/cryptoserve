"""Tests for PKCS#12 import/export functionality."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from app.core.key_export import (
    KeyExportEngine,
    KeyType,
    PKCS12ExportResult,
    PKCS12ImportResult,
    PKCS12ExportError,
    PKCS12ImportError,
)


@pytest.fixture
def engine():
    """Create KeyExportEngine instance."""
    return KeyExportEngine()


@pytest.fixture
def ec_key():
    """Generate EC P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def rsa_key():
    """Generate RSA 2048-bit private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture
def ed25519_key():
    """Generate Ed25519 private key."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def ec_p384_key():
    """Generate EC P-384 private key."""
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture
def ec_p521_key():
    """Generate EC P-521 private key."""
    return ec.generate_private_key(ec.SECP521R1())


def create_self_signed_cert(private_key, subject_name="Test Cert"):
    """Create a self-signed certificate for testing."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    # Add basic constraints for CA cert
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    # Sign with appropriate algorithm
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm = None  # Ed25519 uses built-in algorithm
    else:
        algorithm = hashes.SHA256()

    return builder.sign(private_key, algorithm)


def create_ca_cert(private_key, subject_name="Test CA"):
    """Create a CA certificate for testing."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm = None
    else:
        algorithm = hashes.SHA256()

    return builder.sign(private_key, algorithm)


class TestPKCS12Export:
    """Tests for PKCS#12 export functionality."""

    def test_export_ec_key_with_password(self, engine, ec_key):
        """Test exporting EC key with password protection."""
        cert = create_self_signed_cert(ec_key)
        result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password="test-password-123",
            friendly_name="Test EC Key",
        )

        assert isinstance(result, PKCS12ExportResult)
        assert len(result.pkcs12_data) > 0
        assert result.key_type == KeyType.EC_P256
        assert result.includes_chain is False
        assert "CN=Test Cert" in result.certificate_subject
        assert len(result.certificate_fingerprint) == 64  # SHA-256 hex

    def test_export_rsa_key_with_password(self, engine, rsa_key):
        """Test exporting RSA key with password protection."""
        cert = create_self_signed_cert(rsa_key)
        result = engine.export_to_pkcs12(
            private_key=rsa_key,
            certificate=cert,
            password="rsa-test-password",
        )

        assert result.key_type == KeyType.RSA_2048
        assert len(result.pkcs12_data) > 0
        assert result.includes_chain is False

    def test_export_ed25519_key_with_password(self, engine, ed25519_key):
        """Test exporting Ed25519 key with password protection."""
        cert = create_self_signed_cert(ed25519_key)
        result = engine.export_to_pkcs12(
            private_key=ed25519_key,
            certificate=cert,
            password="ed25519-password",
        )

        assert result.key_type == KeyType.ED25519
        assert len(result.pkcs12_data) > 0

    def test_export_ec_p384_key(self, engine, ec_p384_key):
        """Test exporting EC P-384 key."""
        cert = create_self_signed_cert(ec_p384_key)
        result = engine.export_to_pkcs12(
            private_key=ec_p384_key,
            certificate=cert,
            password="p384-password",
        )

        assert result.key_type == KeyType.EC_P384

    def test_export_ec_p521_key(self, engine, ec_p521_key):
        """Test exporting EC P-521 key."""
        cert = create_self_signed_cert(ec_p521_key)
        result = engine.export_to_pkcs12(
            private_key=ec_p521_key,
            certificate=cert,
            password="p521-password",
        )

        assert result.key_type == KeyType.EC_P521

    def test_export_without_password(self, engine, ec_key):
        """Test exporting without password (no encryption)."""
        cert = create_self_signed_cert(ec_key)
        result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=None,
        )

        assert len(result.pkcs12_data) > 0

    def test_export_with_ca_chain(self, engine, ec_key):
        """Test exporting with CA certificate chain."""
        cert = create_self_signed_cert(ec_key)

        # Create a CA cert for the chain
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_cert = create_ca_cert(ca_key)

        result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password="chain-password",
            ca_certs=[ca_cert],
        )

        assert result.includes_chain is True

    def test_export_with_pem_certificate(self, engine, ec_key):
        """Test exporting with PEM-encoded certificate bytes."""
        cert = create_self_signed_cert(ec_key)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert_pem,
            password="pem-password",
        )

        assert len(result.pkcs12_data) > 0

    def test_export_with_der_certificate(self, engine, ec_key):
        """Test exporting with DER-encoded certificate bytes."""
        cert = create_self_signed_cert(ec_key)
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert_der,
            password="der-password",
        )

        assert len(result.pkcs12_data) > 0

    def test_export_key_cert_mismatch_fails(self, engine, ec_key):
        """Test that mismatched key and certificate fails."""
        other_key = ec.generate_private_key(ec.SECP256R1())
        cert = create_self_signed_cert(other_key)  # Different key

        with pytest.raises(PKCS12ExportError, match="does not match"):
            engine.export_to_pkcs12(
                private_key=ec_key,
                certificate=cert,
                password="password",
            )

    def test_export_invalid_certificate_fails(self, engine, ec_key):
        """Test that invalid certificate bytes fail."""
        with pytest.raises(PKCS12ExportError, match="Failed to parse certificate"):
            engine.export_to_pkcs12(
                private_key=ec_key,
                certificate=b"not a certificate",
                password="password",
            )


class TestPKCS12Import:
    """Tests for PKCS#12 import functionality."""

    def test_import_ec_key(self, engine, ec_key):
        """Test importing EC key from PKCS#12."""
        cert = create_self_signed_cert(ec_key)
        password = "import-test-password"

        # Export first
        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
        )

        # Import back
        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert isinstance(import_result, PKCS12ImportResult)
        assert import_result.key_type == KeyType.EC_P256
        assert import_result.certificate is not None
        assert len(import_result.additional_certs) == 0
        assert len(import_result.certificate_fingerprint) == 64

    def test_import_rsa_key(self, engine, rsa_key):
        """Test importing RSA key from PKCS#12."""
        cert = create_self_signed_cert(rsa_key)
        password = "rsa-import-password"

        export_result = engine.export_to_pkcs12(
            private_key=rsa_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert import_result.key_type == KeyType.RSA_2048

    def test_import_ed25519_key(self, engine, ed25519_key):
        """Test importing Ed25519 key from PKCS#12."""
        cert = create_self_signed_cert(ed25519_key)
        password = "ed25519-import-password"

        export_result = engine.export_to_pkcs12(
            private_key=ed25519_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert import_result.key_type == KeyType.ED25519

    def test_import_with_ca_chain(self, engine, ec_key):
        """Test importing with CA certificate chain."""
        cert = create_self_signed_cert(ec_key)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_cert = create_ca_cert(ca_key)
        password = "chain-import-password"

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
            ca_certs=[ca_cert],
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert len(import_result.additional_certs) == 1

    def test_import_wrong_password_fails(self, engine, ec_key):
        """Test that wrong password fails import."""
        cert = create_self_signed_cert(ec_key)

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password="correct-password",
        )

        with pytest.raises(PKCS12ImportError, match="wrong password or corrupted"):
            engine.import_from_pkcs12(
                pkcs12_data=export_result.pkcs12_data,
                password="wrong-password",
            )

    def test_import_corrupted_data_fails(self, engine):
        """Test that corrupted PKCS#12 data fails."""
        with pytest.raises(PKCS12ImportError):
            engine.import_from_pkcs12(
                pkcs12_data=b"corrupted pkcs12 data",
                password="password",
            )

    def test_import_without_password_when_encrypted_fails(self, engine, ec_key):
        """Test that importing encrypted PKCS#12 without password fails."""
        cert = create_self_signed_cert(ec_key)

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password="encryption-password",
        )

        with pytest.raises(PKCS12ImportError):
            engine.import_from_pkcs12(
                pkcs12_data=export_result.pkcs12_data,
                password=None,
            )


class TestPKCS12Roundtrip:
    """Tests for PKCS#12 export/import roundtrip."""

    def test_roundtrip_ec_key_preserves_data(self, engine, ec_key):
        """Test that EC key data is preserved through roundtrip."""
        cert = create_self_signed_cert(ec_key)
        password = "roundtrip-password"

        # Export
        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
        )

        # Import
        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        # Verify private key is the same by comparing public keys
        original_pub = ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        imported_pub = import_result.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert original_pub == imported_pub

        # Verify certificate fingerprints match
        assert export_result.certificate_fingerprint == import_result.certificate_fingerprint

    def test_roundtrip_rsa_key_preserves_data(self, engine, rsa_key):
        """Test that RSA key data is preserved through roundtrip."""
        cert = create_self_signed_cert(rsa_key)
        password = "rsa-roundtrip"

        export_result = engine.export_to_pkcs12(
            private_key=rsa_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        # Verify public keys match
        original_pub = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        imported_pub = import_result.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert original_pub == imported_pub

    def test_roundtrip_ed25519_key_preserves_data(self, engine, ed25519_key):
        """Test that Ed25519 key data is preserved through roundtrip."""
        cert = create_self_signed_cert(ed25519_key)
        password = "ed25519-roundtrip"

        export_result = engine.export_to_pkcs12(
            private_key=ed25519_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        # Verify public keys match
        original_pub = ed25519_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        imported_pub = import_result.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert original_pub == imported_pub

    def test_roundtrip_with_unicode_password(self, engine, ec_key):
        """Test roundtrip with unicode password."""
        cert = create_self_signed_cert(ec_key)
        password = "测试密码🔐"

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert import_result.private_key is not None

    def test_roundtrip_with_special_chars_password(self, engine, ec_key):
        """Test roundtrip with special characters in password."""
        cert = create_self_signed_cert(ec_key)
        password = "p@$$w0rd!#$%^&*()"

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert import_result.private_key is not None

    def test_roundtrip_with_long_password(self, engine, ec_key):
        """Test roundtrip with very long password."""
        cert = create_self_signed_cert(ec_key)
        password = "a" * 1000

        export_result = engine.export_to_pkcs12(
            private_key=ec_key,
            certificate=cert,
            password=password,
        )

        import_result = engine.import_from_pkcs12(
            pkcs12_data=export_result.pkcs12_data,
            password=password,
        )

        assert import_result.private_key is not None


class TestKeyValidation:
    """Tests for key-certificate validation."""

    def test_validate_key_cert_pair_matching(self, engine, ec_key):
        """Test validation passes for matching key and cert."""
        cert = create_self_signed_cert(ec_key)
        assert engine._validate_key_cert_pair(ec_key, cert) is True

    def test_validate_key_cert_pair_mismatched(self, engine, ec_key):
        """Test validation fails for mismatched key and cert."""
        other_key = ec.generate_private_key(ec.SECP256R1())
        cert = create_self_signed_cert(other_key)
        assert engine._validate_key_cert_pair(ec_key, cert) is False

    def test_validate_rsa_key_cert_pair(self, engine, rsa_key):
        """Test validation for RSA key and cert."""
        cert = create_self_signed_cert(rsa_key)
        assert engine._validate_key_cert_pair(rsa_key, cert) is True

    def test_validate_ed25519_key_cert_pair(self, engine, ed25519_key):
        """Test validation for Ed25519 key and cert."""
        cert = create_self_signed_cert(ed25519_key)
        assert engine._validate_key_cert_pair(ed25519_key, cert) is True
