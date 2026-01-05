"""Tests for SCT (Signed Certificate Timestamp) validation."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.core.sct_validator import (
    SCTParser,
    SCTValidator,
    SCT,
    SCTVersion,
    HashAlgorithm,
    SignatureAlgorithm,
    CTLogInfo,
    SCT_EXTENSION_OID,
    sct_validator,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def validator():
    """Create a fresh SCT validator for testing."""
    return SCTValidator()


@pytest.fixture
def sample_sct_data():
    """Create sample SCT data for parsing tests.

    SCT format:
    - version: 1 byte (0 for v1)
    - log_id: 32 bytes
    - timestamp: 8 bytes (ms since epoch)
    - extensions: 2-byte length + data
    - signature: hash_alg(1) + sig_alg(1) + 2-byte length + signature
    """
    # Create a minimal valid SCT
    version = b'\x00'  # v1
    log_id = b'\x01' * 32  # 32 byte log ID
    timestamp = (1704067200000).to_bytes(8, 'big')  # 2024-01-01 00:00:00 UTC in ms
    extensions_length = b'\x00\x00'  # 0 bytes of extensions
    extensions = b''
    hash_alg = b'\x04'  # SHA256
    sig_alg = b'\x03'  # ECDSA
    signature = b'\x30\x46' + b'\x02\x21' + b'\x00' + b'\xaa' * 32 + b'\x02\x21' + b'\x00' + b'\xbb' * 32
    sig_length = len(signature).to_bytes(2, 'big')

    return (
        version + log_id + timestamp + extensions_length + extensions +
        hash_alg + sig_alg + sig_length + signature
    )


@pytest.fixture
def sample_sct_list(sample_sct_data):
    """Create a sample SCT list with length prefix."""
    # Single SCT with length prefix
    sct_with_length = len(sample_sct_data).to_bytes(2, 'big') + sample_sct_data
    # List with total length prefix
    return len(sct_with_length).to_bytes(2, 'big') + sct_with_length


@pytest.fixture
def self_signed_cert():
    """Create a self-signed certificate for testing (no SCTs)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    # Generate key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create certificate
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
        .sign(private_key, hashes.SHA256())
    )

    return cert


# =============================================================================
# SCT Parser Tests
# =============================================================================


class TestSCTParser:
    """Tests for SCT parsing."""

    def test_parse_sct_valid(self, sample_sct_data):
        """Test parsing a valid SCT."""
        sct = SCTParser.parse_sct(sample_sct_data)

        assert sct is not None
        assert sct.version == SCTVersion.V1
        assert len(sct.log_id) == 32
        assert sct.log_id == b'\x01' * 32
        assert sct.timestamp.year == 2024
        assert sct.hash_algorithm == HashAlgorithm.SHA256
        assert sct.signature_algorithm == SignatureAlgorithm.ECDSA
        assert len(sct.signature) > 0

    def test_parse_sct_too_short(self):
        """Test parsing fails for data that's too short."""
        sct = SCTParser.parse_sct(b'\x00' * 10)
        assert sct is None

    def test_parse_sct_empty(self):
        """Test parsing fails for empty data."""
        sct = SCTParser.parse_sct(b'')
        assert sct is None

    def test_parse_sct_list(self, sample_sct_list):
        """Test parsing an SCT list."""
        scts = SCTParser.parse_sct_list(sample_sct_list)

        assert len(scts) == 1
        assert scts[0].version == SCTVersion.V1

    def test_parse_sct_list_empty(self):
        """Test parsing empty SCT list."""
        scts = SCTParser.parse_sct_list(b'\x00\x00')  # Length 0
        assert len(scts) == 0

    def test_parse_sct_list_too_short(self):
        """Test parsing fails gracefully for short data."""
        scts = SCTParser.parse_sct_list(b'\x00')  # Only 1 byte
        assert len(scts) == 0


# =============================================================================
# SCT Validator Tests
# =============================================================================


class TestSCTValidator:
    """Tests for SCT validation."""

    def test_validator_initialization(self, validator):
        """Test validator initializes with known logs."""
        assert validator.known_logs is not None
        assert len(validator.known_logs) >= 0  # May have defaults

    def test_extract_scts_from_cert_no_scts(self, validator, self_signed_cert):
        """Test extracting SCTs from cert without SCTs."""
        scts = validator.extract_scts_from_certificate(self_signed_cert)
        assert len(scts) == 0

    def test_validate_certificate_scts_no_scts(self, validator, self_signed_cert):
        """Test validating cert with no SCTs."""
        result = validator.validate_certificate_scts(self_signed_cert, min_scts=2)

        assert result["total_scts"] == 0
        assert result["valid_scts"] == 0
        assert result["meets_minimum"] is False
        assert result["minimum_required"] == 2

    def test_get_required_scts_short_lifetime(self, validator):
        """Test required SCTs for short-lived cert."""
        # Create cert with 90-day lifetime
        private_key = ec.generate_private_key(ec.SECP256R1())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
            .sign(private_key, hashes.SHA256())
        )

        required = validator.get_required_scts(cert)
        assert required == 2

    def test_get_required_scts_long_lifetime(self, validator):
        """Test required SCTs for long-lived cert."""
        # Create cert with 1-year lifetime
        private_key = ec.generate_private_key(ec.SECP256R1())

        subject = issuer = x509.Name([
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
            .sign(private_key, hashes.SHA256())
        )

        required = validator.get_required_scts(cert)
        assert required == 3

    def test_validate_sct_unknown_log(self, validator, self_signed_cert, sample_sct_data):
        """Test validating SCT from unknown log."""
        sct = SCTParser.parse_sct(sample_sct_data)
        result = validator.validate_sct(sct, self_signed_cert)

        # Unknown logs are treated as valid but flagged
        assert result.valid is True
        assert result.log_name == "Unknown CT Log"
        assert "unknown log" in result.error.lower()

    def test_validate_sct_future_timestamp(self, validator, self_signed_cert):
        """Test validating SCT with future timestamp."""
        # Create SCT with future timestamp
        future_timestamp = datetime.now(timezone.utc) + timedelta(days=1)
        sct = SCT(
            version=SCTVersion.V1,
            log_id=b'\x01' * 32,
            timestamp=future_timestamp,
            extensions=b'',
            hash_algorithm=HashAlgorithm.SHA256,
            signature_algorithm=SignatureAlgorithm.ECDSA,
            signature=b'\x00' * 64,
        )

        result = validator.validate_sct(sct, self_signed_cert)

        assert result.valid is False
        assert "future" in result.error.lower()


# =============================================================================
# SCT Data Structure Tests
# =============================================================================


class TestSCTDataStructures:
    """Tests for SCT-related data structures."""

    def test_sct_log_id_hex(self):
        """Test SCT log_id_hex property."""
        sct = SCT(
            version=SCTVersion.V1,
            log_id=bytes.fromhex('a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10'),
            timestamp=datetime.now(timezone.utc),
            extensions=b'',
            hash_algorithm=HashAlgorithm.SHA256,
            signature_algorithm=SignatureAlgorithm.ECDSA,
            signature=b'\x00' * 64,
        )

        assert sct.log_id_hex == 'a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10'

    def test_sct_timestamp_ms(self):
        """Test SCT timestamp_ms property."""
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        sct = SCT(
            version=SCTVersion.V1,
            log_id=b'\x01' * 32,
            timestamp=ts,
            extensions=b'',
            hash_algorithm=HashAlgorithm.SHA256,
            signature_algorithm=SignatureAlgorithm.ECDSA,
            signature=b'\x00' * 64,
        )

        assert sct.timestamp_ms == 1704067200000

    def test_ct_log_info(self):
        """Test CTLogInfo data structure."""
        log = CTLogInfo(
            log_id="test_id",
            name="Test Log",
            url="https://ct.test.com/",
            public_key=b'\x00' * 64,
            operator="Test Operator",
            status="active",
        )

        assert log.log_id == "test_id"
        assert log.name == "Test Log"
        assert log.operator == "Test Operator"


# =============================================================================
# PEM/DER Certificate Tests
# =============================================================================


class TestCertificateLoading:
    """Tests for certificate loading functions."""

    def test_extract_scts_from_pem(self, validator, self_signed_cert):
        """Test extracting SCTs from PEM certificate."""
        from cryptography.hazmat.primitives import serialization

        pem_data = self_signed_cert.public_bytes(serialization.Encoding.PEM)
        scts = validator.extract_scts_from_pem(pem_data)

        # Self-signed cert has no SCTs
        assert len(scts) == 0

    def test_extract_scts_from_der(self, validator, self_signed_cert):
        """Test extracting SCTs from DER certificate."""
        from cryptography.hazmat.primitives import serialization

        der_data = self_signed_cert.public_bytes(serialization.Encoding.DER)
        scts = validator.extract_scts_from_der(der_data)

        # Self-signed cert has no SCTs
        assert len(scts) == 0

    def test_extract_scts_from_invalid_pem(self, validator):
        """Test extracting SCTs from invalid PEM."""
        scts = validator.extract_scts_from_pem(b"not a certificate")
        assert len(scts) == 0

    def test_extract_scts_from_invalid_der(self, validator):
        """Test extracting SCTs from invalid DER."""
        scts = validator.extract_scts_from_der(b"\x00\x01\x02\x03")
        assert len(scts) == 0


# =============================================================================
# Singleton Tests
# =============================================================================


class TestSCTValidatorSingleton:
    """Tests for singleton validator instance."""

    def test_singleton_exists(self):
        """Test that singleton validator exists."""
        assert sct_validator is not None

    def test_singleton_is_validator(self):
        """Test that singleton is SCTValidator instance."""
        assert isinstance(sct_validator, SCTValidator)


# =============================================================================
# Integration Tests
# =============================================================================


class TestSCTValidatorIntegration:
    """Integration tests for SCT validation."""

    def test_full_validation_flow(self, validator, self_signed_cert):
        """Test complete validation workflow."""
        # 1. Extract SCTs
        scts = validator.extract_scts_from_certificate(self_signed_cert)

        # 2. Validate (should report no SCTs)
        result = validator.validate_certificate_scts(self_signed_cert, min_scts=2)

        # 3. Verify results
        assert result["certificate_subject"] is not None
        assert "test.example.com" in result["certificate_subject"]
        assert result["total_scts"] == 0
        assert result["meets_minimum"] is False

    def test_validation_with_custom_log_list(self):
        """Test validation with custom CT log list."""
        custom_logs = {
            "abc123": CTLogInfo(
                log_id="abc123",
                name="Custom Test Log",
                url="https://ct.custom.test/",
                public_key=b'\x00' * 64,
                operator="Custom Operator",
            ),
        }

        validator = SCTValidator(known_logs=custom_logs)
        assert len(validator.known_logs) == 1
        assert "abc123" in validator.known_logs
