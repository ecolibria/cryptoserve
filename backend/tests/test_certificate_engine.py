"""Tests for the certificate management engine."""

import hashlib
from pathlib import Path

import pytest
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.core.certificate_engine import (
    CertificateEngine,
    CertificateType,
    SubjectInfo,
    KeyUsage,
    CertificateError,
    CSRError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh certificate engine for each test."""
    return CertificateEngine()


@pytest.fixture
def basic_subject():
    """Create a basic subject for testing."""
    return SubjectInfo(
        common_name="test.example.com",
        organization="Test Organization",
        country="US",
    )


class TestCSRGeneration:
    """Tests for CSR generation."""

    def test_generate_csr_ec_p256(self, fresh_engine, basic_subject):
        """Test CSR generation with EC P-256."""
        result = fresh_engine.generate_csr(
            subject=basic_subject,
            key_type=CertificateType.EC,
            key_size=256,
        )

        assert result.key_type == CertificateType.EC
        assert result.key_size == 256
        assert result.subject == basic_subject
        assert b"-----BEGIN CERTIFICATE REQUEST-----" in result.csr_pem
        assert b"-----BEGIN PRIVATE KEY-----" in result.private_key_pem
        assert len(result.csr_der) > 0

    def test_generate_csr_ec_p384(self, fresh_engine, basic_subject):
        """Test CSR generation with EC P-384."""
        result = fresh_engine.generate_csr(
            subject=basic_subject,
            key_type=CertificateType.EC,
            key_size=384,
        )

        assert result.key_size == 384

    def test_generate_csr_rsa_2048(self, fresh_engine, basic_subject):
        """Test CSR generation with RSA 2048."""
        result = fresh_engine.generate_csr(
            subject=basic_subject,
            key_type=CertificateType.RSA,
            key_size=2048,
        )

        assert result.key_type == CertificateType.RSA
        assert result.key_size == 2048

    def test_generate_csr_ed25519(self, fresh_engine, basic_subject):
        """Test CSR generation with Ed25519."""
        result = fresh_engine.generate_csr(
            subject=basic_subject,
            key_type=CertificateType.ED25519,
        )

        assert result.key_type == CertificateType.ED25519
        assert result.key_size is None

    def test_generate_csr_with_san(self, fresh_engine, basic_subject):
        """Test CSR generation with SANs."""
        result = fresh_engine.generate_csr(
            subject=basic_subject,
            san_domains=["www.example.com", "api.example.com"],
            san_ips=["192.168.1.1"],
            san_emails=["admin@example.com"],
        )

        # Parse and verify SANs are present
        csr_info = fresh_engine.parse_csr(result.csr_pem)
        assert "DNS:www.example.com" in csr_info["san"]
        assert "DNS:api.example.com" in csr_info["san"]
        assert "IP:192.168.1.1" in csr_info["san"]
        assert "email:admin@example.com" in csr_info["san"]

    def test_generate_csr_full_subject(self, fresh_engine):
        """Test CSR with full subject details."""
        subject = SubjectInfo(
            common_name="secure.example.com",
            organization="Acme Corp",
            organizational_unit="Security Team",
            country="US",
            state="California",
            locality="San Francisco",
            email="security@example.com",
        )

        result = fresh_engine.generate_csr(subject=subject)

        csr_info = fresh_engine.parse_csr(result.csr_pem)
        assert csr_info["subject"]["common_name"] == "secure.example.com"
        assert csr_info["subject"]["organization"] == "Acme Corp"

    def test_csr_is_valid(self, fresh_engine, basic_subject):
        """Test that generated CSR has valid signature."""
        result = fresh_engine.generate_csr(subject=basic_subject)
        csr_info = fresh_engine.parse_csr(result.csr_pem)

        assert csr_info["is_valid"]

    def test_rsa_key_size_validation(self, fresh_engine, basic_subject):
        """Test RSA key size validation."""
        with pytest.raises(CSRError):
            fresh_engine.generate_csr(
                subject=basic_subject,
                key_type=CertificateType.RSA,
                key_size=1024,  # Too small
            )


class TestSelfSignedCertificate:
    """Tests for self-signed certificate generation."""

    def test_generate_self_signed_ec(self, fresh_engine, basic_subject):
        """Test self-signed certificate generation with EC."""
        cert_pem, key_pem = fresh_engine.generate_self_signed(
            subject=basic_subject,
            key_type=CertificateType.EC,
            key_size=256,
            validity_days=365,
        )

        assert b"-----BEGIN CERTIFICATE-----" in cert_pem
        assert b"-----BEGIN PRIVATE KEY-----" in key_pem

        # Parse and verify
        info = fresh_engine.parse_certificate(cert_pem)
        assert info.subject.common_name == basic_subject.common_name
        assert info.key_type == CertificateType.EC
        assert not info.is_ca

    def test_generate_self_signed_ca(self, fresh_engine, basic_subject):
        """Test self-signed CA certificate."""
        cert_pem, _ = fresh_engine.generate_self_signed(
            subject=basic_subject,
            is_ca=True,
            validity_days=3650,
        )

        info = fresh_engine.parse_certificate(cert_pem)
        assert info.is_ca
        assert KeyUsage.KEY_CERT_SIGN in info.key_usage
        assert KeyUsage.CRL_SIGN in info.key_usage

    def test_generate_self_signed_with_san(self, fresh_engine, basic_subject):
        """Test self-signed certificate with SANs."""
        cert_pem, _ = fresh_engine.generate_self_signed(
            subject=basic_subject,
            san_domains=["www.example.com"],
            san_ips=["127.0.0.1"],
        )

        info = fresh_engine.parse_certificate(cert_pem)
        assert "DNS:www.example.com" in info.san
        assert "IP:127.0.0.1" in info.san

    def test_certificate_validity_period(self, fresh_engine, basic_subject):
        """Test certificate validity period."""
        cert_pem, _ = fresh_engine.generate_self_signed(
            subject=basic_subject,
            validity_days=30,
        )

        info = fresh_engine.parse_certificate(cert_pem)
        now = datetime.now(timezone.utc)

        assert info.not_before <= now
        assert info.not_after > now
        # Should be approximately 30 days
        diff = (info.not_after - info.not_before).days
        assert 29 <= diff <= 31


class TestCertificateParsing:
    """Tests for certificate parsing."""

    def test_parse_certificate_pem(self, fresh_engine, basic_subject):
        """Test parsing PEM certificate."""
        cert_pem, _ = fresh_engine.generate_self_signed(subject=basic_subject)
        info = fresh_engine.parse_certificate(cert_pem)

        assert info.subject.common_name == basic_subject.common_name
        assert info.issuer.common_name == basic_subject.common_name  # Self-signed
        assert len(info.fingerprint_sha256) == 64  # SHA256 hex
        assert len(info.fingerprint_sha1) == 40  # SHA1 hex
        assert info.serial_number > 0

    def test_parse_certificate_der(self, fresh_engine, basic_subject):
        """Test parsing DER certificate."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert_pem, _ = fresh_engine.generate_self_signed(subject=basic_subject)

        # Convert to DER
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        info = fresh_engine.parse_certificate(cert_der)
        assert info.subject.common_name == basic_subject.common_name

    def test_parse_certificate_key_usage(self, fresh_engine, basic_subject):
        """Test parsing key usage extensions."""
        cert_pem, _ = fresh_engine.generate_self_signed(subject=basic_subject)
        info = fresh_engine.parse_certificate(cert_pem)

        assert KeyUsage.DIGITAL_SIGNATURE in info.key_usage
        assert KeyUsage.KEY_ENCIPHERMENT in info.key_usage

    def test_parse_certificate_string_input(self, fresh_engine, basic_subject):
        """Test parsing certificate from string."""
        cert_pem, _ = fresh_engine.generate_self_signed(subject=basic_subject)
        cert_str = cert_pem.decode("utf-8")

        info = fresh_engine.parse_certificate(cert_str)
        assert info.subject.common_name == basic_subject.common_name


class TestCertificateValidation:
    """Tests for certificate validation."""

    def test_verify_valid_certificate(self, fresh_engine, basic_subject):
        """Test verifying a valid certificate."""
        cert_pem, _ = fresh_engine.generate_self_signed(subject=basic_subject)

        result = fresh_engine.verify_certificate(cert_pem)

        assert result.valid
        assert len(result.errors) == 0

    def test_verify_expired_certificate(self, fresh_engine, basic_subject):
        """Test verifying an expired certificate."""
        # Generate a certificate with negative validity (effectively expired)
        # We'll create one that was valid in the past
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        # Create certificate valid from 60 days ago to 30 days ago
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.test")]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=60))
            .not_valid_after(now - timedelta(days=30))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        result = fresh_engine.verify_certificate(cert_pem)

        assert not result.valid
        assert any("expired" in e.lower() for e in result.errors)

    def test_verify_not_yet_valid_certificate(self, fresh_engine, basic_subject):
        """Test verifying a not-yet-valid certificate."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        # Create certificate valid from 30 days in the future
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future.test")]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=30))
            .not_valid_after(now + timedelta(days=60))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        result = fresh_engine.verify_certificate(cert_pem)

        assert not result.valid
        assert any("not yet valid" in e.lower() for e in result.errors)

    def test_verify_expiring_soon_warning(self, fresh_engine, basic_subject):
        """Test warning for soon-to-expire certificate."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        # Create certificate expiring in 15 days
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expiring.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expiring.test")]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=15))
            .not_valid_after(now + timedelta(days=15))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        result = fresh_engine.verify_certificate(cert_pem)

        assert result.valid  # Still valid
        assert any("expires soon" in w.lower() for w in result.warnings)


class TestChainValidation:
    """Tests for certificate chain validation."""

    def test_verify_simple_chain(self, fresh_engine):
        """Test verifying a simple two-cert chain."""
        # Generate CA
        ca_subject = SubjectInfo(common_name="Test CA", organization="Test")
        ca_cert_pem, ca_key_pem = fresh_engine.generate_self_signed(
            subject=ca_subject,
            is_ca=True,
            validity_days=3650,
        )

        # Generate leaf signed by CA
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)

        result = fresh_engine.verify_chain([leaf_pem, ca_cert_pem])

        assert result.valid
        assert result.chain_length == 2
        assert result.root_subject.common_name == "Test CA"

    def test_verify_chain_wrong_order(self, fresh_engine):
        """Test chain validation with wrong certificate order."""
        ca_subject = SubjectInfo(common_name="Test CA")
        ca_cert_pem, ca_key_pem = fresh_engine.generate_self_signed(
            subject=ca_subject,
            is_ca=True,
        )

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)

        # Wrong order: CA first, leaf second
        result = fresh_engine.verify_chain([ca_cert_pem, leaf_pem])

        assert not result.valid
        assert any("issuer" in e.lower() or "signature" in e.lower() for e in result.errors)

    def test_verify_empty_chain(self, fresh_engine):
        """Test chain validation with empty chain."""
        result = fresh_engine.verify_chain([])

        assert not result.valid
        assert any("empty" in e.lower() for e in result.errors)


class TestCSRParsing:
    """Tests for CSR parsing."""

    def test_parse_csr(self, fresh_engine, basic_subject):
        """Test parsing a CSR."""
        csr_result = fresh_engine.generate_csr(
            subject=basic_subject,
            san_domains=["www.example.com"],
        )

        csr_info = fresh_engine.parse_csr(csr_result.csr_pem)

        assert csr_info["subject"]["common_name"] == basic_subject.common_name
        assert csr_info["subject"]["organization"] == basic_subject.organization
        assert csr_info["is_valid"]
        assert "DNS:www.example.com" in csr_info["san"]

    def test_parse_csr_der(self, fresh_engine, basic_subject):
        """Test parsing DER-encoded CSR."""
        csr_result = fresh_engine.generate_csr(subject=basic_subject)
        csr_info = fresh_engine.parse_csr(csr_result.csr_der)

        assert csr_info["subject"]["common_name"] == basic_subject.common_name


class TestEdgeCases:
    """Tests for edge cases."""

    def test_invalid_certificate_data(self, fresh_engine):
        """Test parsing invalid certificate data."""
        with pytest.raises(CertificateError):
            fresh_engine.parse_certificate(b"not a certificate")

    def test_invalid_csr_data(self, fresh_engine):
        """Test parsing invalid CSR data."""
        with pytest.raises(CSRError):
            fresh_engine.parse_csr(b"not a csr")

    def test_unsupported_ec_key_size(self, fresh_engine, basic_subject):
        """Test unsupported EC key size."""
        with pytest.raises(CSRError):
            fresh_engine.generate_csr(
                subject=basic_subject,
                key_type=CertificateType.EC,
                key_size=128,  # Not supported
            )


# ---------------------------------------------------------------------------
# Listed keys: the eight compromised eMudhra intermediate keys and the removed
# root, emSign ECC Root CA - G3. The fixtures are public certificates committed
# under testdata/trust-keys; its README says where each came from. Expected
# values are recomputed here from those certificates.
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]
TRUST_FIXTURES = REPO / "testdata" / "trust-keys"

LEAF_OV_G3C = "leaves/crtsh-29977124910/cert.pem"  # issued under the EM OV TLS CA - G3C key
LEAF_EV_G3B = "leaves/crtsh-30010072947/cert.pem"  # issued under the EM EV TLS CA - G3B key
OV_G3C = "listed/cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f/cert.pem"
EV_G3B = "listed/e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838/cert.pem"
DV_G3C = "listed/0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19/cert.pem"
ANCHORED = "anchored/crtsh-14658191778/cert.pem"  # its signature verifies under the removed root's key
REMOVED_ROOT = "root/emsign-ecc-root-ca-g3.pem"
CONTROL_ROOT = "control/emsign-root-ca-g1.pem"
LISTED = sorted(p.relative_to(TRUST_FIXTURES).as_posix() for p in (TRUST_FIXTURES / "listed").glob("*/cert.pem"))

TLS_FIX = (
    "Replace the chain with one issued by a CA none of whose keys is listed, "
    "and remove this certificate from any bundle or pin set you ship."
)
CODE_SIGNING_FIX = (
    "Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; "
    "a verifier that checks revocation can reject signatures under this key."
)
ROOT_FIX = (
    "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle "
    "you ship; Chrome's removal date for all devices is 2026-10-27."
)
RULE_4 = (
    "Chain anchors on emSign ECC Root CA - G3 (the last certificate's signature verifies under that "
    "root's key), which Mozilla removed from its root store on 2026-10-20. " + ROOT_FIX
)
ANCHOR_WARNING = (
    "Chain anchor not checked: no issuer certificate was supplied. "
    "Verify again with the issuer certificate or the full chain."
)


def rule_1(cert_name, spki, fix):
    return (
        f"{cert_name} uses a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449, "
        f"SPKI SHA-256 {spki}). {fix}"
    )


def rule_2(cert_name, issuer_spki, fix):
    return (
        f"{cert_name} is signed by a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449, "
        f"issuer SPKI SHA-256 {issuer_spki}); its issuer is revoked. {fix}"
    )


def rule_3(cert_name):
    return (
        f"{cert_name} is emSign ECC Root CA - G3, which Mozilla removed from its root store on 2026-10-20. "
        f"{ROOT_FIX}"
    )


def trust_pem(rel):
    return (TRUST_FIXTURES / rel).read_bytes()


def spki_sha256(rel):
    cert = x509.load_pem_x509_certificate(trust_pem(rel))
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def fix_for(rel):
    """The Fix for a listed certificate, chosen by the use its extended key usage states."""
    cert = x509.load_pem_x509_certificate(trust_pem(rel))
    usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    return CODE_SIGNING_FIX if x509.oid.ExtendedKeyUsageOID.CODE_SIGNING in usages else TLS_FIX


def issued_by_test_ca():
    """An ordinary leaf and the CA that issued it, both made here with fresh keys."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return leaf.public_bytes(pem), ca.public_bytes(pem)


class TestListedKeys:
    """A certificate that is, or is signed by, a listed key is not valid, on every surface that reads `errors`."""

    def test_fixtures_hold_the_removed_root_the_advisory_names(self):
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_pem_x509_certificate(trust_pem(REMOVED_ROOT))
        assert cert.fingerprint(hashes.SHA256()).hex() == (
            "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
        )
        assert spki_sha256(REMOVED_ROOT) == "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"
        assert len(LISTED) == 16
        assert len({spki_sha256(rel) for rel in LISTED}) == 8

    @pytest.mark.parametrize("listed", LISTED)
    def test_chain_holding_a_listed_intermediate_is_invalid_with_the_rule_1_error(self, fresh_engine, listed):
        result = fresh_engine.verify_chain([trust_pem(listed)], check_expiry=False)

        assert result.valid is False
        assert result.errors == [rule_1("Leaf certificate", spki_sha256(listed), fix_for(listed))]

    def test_leaf_and_its_listed_intermediate_report_both_certificates(self, fresh_engine):
        result = fresh_engine.verify_chain([trust_pem(LEAF_OV_G3C), trust_pem(OV_G3C)], check_expiry=False)

        assert result.valid is False
        assert result.errors == [
            rule_2("Leaf certificate", spki_sha256(OV_G3C), TLS_FIX),
            rule_1("Certificate 1", spki_sha256(OV_G3C), TLS_FIX),
        ]

    @pytest.mark.parametrize("leaf,issuer", [(LEAF_OV_G3C, OV_G3C), (LEAF_EV_G3B, EV_G3B)])
    def test_leaf_issued_under_a_tls_intermediate_returns_the_rule_2_error(self, fresh_engine, leaf, issuer):
        result = fresh_engine.verify_certificate(trust_pem(leaf), check_expiry=False)

        assert result.valid is False
        assert result.errors == [rule_2("Leaf certificate", spki_sha256(issuer), TLS_FIX)]
        assert result.warnings == [ANCHOR_WARNING]

    def test_leaf_verified_with_its_listed_issuer_reports_both(self, fresh_engine):
        result = fresh_engine.verify_certificate(
            trust_pem(LEAF_OV_G3C), issuer_cert_data=trust_pem(OV_G3C), check_expiry=False
        )

        assert result.valid is False
        assert result.errors == [
            rule_2("Leaf certificate", spki_sha256(OV_G3C), TLS_FIX),
            rule_1("Certificate 1", spki_sha256(OV_G3C), TLS_FIX),
        ]
        assert ANCHOR_WARNING not in result.warnings

    def test_chain_ending_at_the_removed_root_returns_the_rule_3_error(self, fresh_engine):
        chain = [trust_pem(DV_G3C), trust_pem(ANCHORED), trust_pem(REMOVED_ROOT)]
        result = fresh_engine.verify_chain(chain, check_expiry=False)

        assert result.valid is False
        assert result.errors == [
            rule_1("Leaf certificate", spki_sha256(DV_G3C), TLS_FIX),
            rule_3("Certificate 2"),
        ]

    def test_same_chain_without_the_root_returns_the_rule_4_error(self, fresh_engine):
        chain = [trust_pem(DV_G3C), trust_pem(ANCHORED)]
        result = fresh_engine.verify_chain(chain, check_expiry=False)

        assert result.valid is False
        assert result.errors == [
            rule_1("Leaf certificate", spki_sha256(DV_G3C), TLS_FIX),
            RULE_4,
        ]

    def test_removed_root_alone_is_reported_once(self, fresh_engine):
        result = fresh_engine.verify_certificate(trust_pem(REMOVED_ROOT), check_expiry=False)

        assert result.valid is False
        assert result.errors == [rule_3("Leaf certificate")]
        assert ANCHOR_WARNING not in result.warnings

    def test_issuer_anchored_on_the_removed_root_returns_the_rule_4_error(self, fresh_engine):
        result = fresh_engine.verify_certificate(
            trust_pem(DV_G3C), issuer_cert_data=trust_pem(ANCHORED), check_expiry=False
        )

        assert result.valid is False
        assert result.errors == [
            rule_1("Leaf certificate", spki_sha256(DV_G3C), TLS_FIX),
            RULE_4,
        ]

    def test_leaf_verified_without_its_issuer_returns_the_anchor_warning(self, fresh_engine):
        leaf_pem, ca_pem = issued_by_test_ca()

        alone = fresh_engine.verify_certificate(leaf_pem)
        assert alone.valid is True
        assert alone.errors == []
        assert alone.warnings == [ANCHOR_WARNING]

        with_issuer = fresh_engine.verify_certificate(leaf_pem, issuer_cert_data=ca_pem)
        assert with_issuer.valid is True
        assert ANCHOR_WARNING not in with_issuer.warnings

    def test_another_root_of_the_same_ca_is_not_flagged(self, fresh_engine):
        result = fresh_engine.verify_certificate(trust_pem(CONTROL_ROOT), check_expiry=False)

        assert result.valid is True
        assert result.errors == []
        assert result.warnings == []

    def test_a_name_alone_raises_nothing(self, fresh_engine):
        """A fresh key under the removed root's exact subject name is not the removed root."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        name = x509.load_pem_x509_certificate(trust_pem(REMOVED_ROOT)).subject
        key = ec.generate_private_key(ec.SECP384R1())
        now = datetime.now(timezone.utc)
        lookalike = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA384())
        )

        result = fresh_engine.verify_chain([lookalike.public_bytes(serialization.Encoding.PEM)])

        assert result.valid is True
        assert result.errors == []

    def test_engine_and_cli_carry_byte_equal_key_tables(self):
        engine_copy = REPO / "backend" / "app" / "core" / "trust_keys.json"
        cli_copy = REPO / "sdk" / "javascript" / "lib" / "trust-keys.json"

        assert engine_copy.read_bytes() == cli_copy.read_bytes()
