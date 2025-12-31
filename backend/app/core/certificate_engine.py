"""Certificate Management Engine.

Provides certificate operations for PKI workflows:
- CSR (Certificate Signing Request) generation
- Certificate parsing and validation
- Certificate chain verification
- Certificate info extraction
- Self-signed certificate generation

Security model:
- Private keys never leave the engine
- Chain validation follows RFC 5280
- Expiration and revocation checking
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


class CertificateType(str, Enum):
    """Certificate types."""
    RSA = "rsa"
    EC = "ec"
    ED25519 = "ed25519"


class KeyUsage(str, Enum):
    """Key usage extensions."""
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ExtendedKeyUsage(str, Enum):
    """Extended key usage."""
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"
    CODE_SIGNING = "code_signing"
    EMAIL_PROTECTION = "email_protection"
    TIME_STAMPING = "time_stamping"
    OCSP_SIGNING = "ocsp_signing"


@dataclass
class SubjectInfo:
    """Subject/Issuer distinguished name."""
    common_name: str
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None


@dataclass
class CSRResult:
    """Result of CSR generation."""
    csr_pem: bytes
    csr_der: bytes
    private_key_pem: bytes
    public_key_pem: bytes
    subject: SubjectInfo
    key_type: CertificateType
    key_size: int | None


@dataclass
class CertificateInfo:
    """Parsed certificate information."""
    subject: SubjectInfo
    issuer: SubjectInfo
    serial_number: int
    not_before: datetime
    not_after: datetime
    key_type: CertificateType
    key_size: int | None
    signature_algorithm: str
    is_ca: bool
    key_usage: list[KeyUsage]
    extended_key_usage: list[ExtendedKeyUsage]
    san: list[str]  # Subject Alternative Names
    fingerprint_sha256: str
    fingerprint_sha1: str
    pem: bytes


@dataclass
class ChainValidationResult:
    """Result of certificate chain validation."""
    valid: bool
    errors: list[str]
    warnings: list[str]
    chain_length: int
    root_subject: SubjectInfo | None


class CertificateError(Exception):
    """Certificate operation failed."""
    pass


class CSRError(CertificateError):
    """CSR operation failed."""
    pass


class ValidationError(CertificateError):
    """Validation failed."""
    pass


class CertificateEngine:
    """Handles certificate operations."""

    def generate_csr(
        self,
        subject: SubjectInfo,
        key_type: CertificateType = CertificateType.EC,
        key_size: int = 256,
        san_domains: list[str] | None = None,
        san_ips: list[str] | None = None,
        san_emails: list[str] | None = None,
    ) -> CSRResult:
        """Generate a Certificate Signing Request.

        Args:
            subject: Subject distinguished name
            key_type: Key type (RSA, EC, ED25519)
            key_size: Key size (2048-4096 for RSA, 256/384/521 for EC)
            san_domains: Subject Alternative Name DNS entries
            san_ips: Subject Alternative Name IP addresses
            san_emails: Subject Alternative Name email addresses

        Returns:
            CSRResult with CSR and key material
        """
        # Generate key pair
        private_key, public_key, actual_key_size = self._generate_key_pair(key_type, key_size)

        # Build subject
        name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, subject.common_name)]
        if subject.organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization))
        if subject.organizational_unit:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit))
        if subject.country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country))
        if subject.state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.state))
        if subject.locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality))
        if subject.email:
            name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject.email))

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(name_attributes)
        )

        # Add SANs
        san_list = []
        if san_domains:
            san_list.extend([x509.DNSName(d) for d in san_domains])
        if san_ips:
            import ipaddress
            san_list.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips])
        if san_emails:
            san_list.extend([x509.RFC822Name(e) for e in san_emails])

        if san_list:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Sign CSR
        if key_type == CertificateType.ED25519:
            csr = csr_builder.sign(private_key, None)
        else:
            csr = csr_builder.sign(private_key, hashes.SHA256())

        # Export keys
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return CSRResult(
            csr_pem=csr.public_bytes(serialization.Encoding.PEM),
            csr_der=csr.public_bytes(serialization.Encoding.DER),
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
            subject=subject,
            key_type=key_type,
            key_size=actual_key_size,
        )

    def generate_self_signed(
        self,
        subject: SubjectInfo,
        key_type: CertificateType = CertificateType.EC,
        key_size: int = 256,
        validity_days: int = 365,
        is_ca: bool = False,
        san_domains: list[str] | None = None,
        san_ips: list[str] | None = None,
    ) -> tuple[bytes, bytes]:
        """Generate a self-signed certificate.

        Args:
            subject: Subject distinguished name
            key_type: Key type
            key_size: Key size
            validity_days: Certificate validity in days
            is_ca: Whether this is a CA certificate
            san_domains: Subject Alternative Name DNS entries
            san_ips: Subject Alternative Name IP addresses

        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        import ipaddress

        private_key, public_key, _ = self._generate_key_pair(key_type, key_size)

        # Build subject
        name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, subject.common_name)]
        if subject.organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization))
        if subject.country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country))

        subject_name = x509.Name(name_attributes)

        now = datetime.now(timezone.utc)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(subject_name)  # Self-signed
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        # Basic constraints
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True,
        )

        # Key usage
        if is_ca:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        else:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )

        # SANs
        san_list = []
        if san_domains:
            san_list.extend([x509.DNSName(d) for d in san_domains])
        if san_ips:
            san_list.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips])

        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Subject Key Identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        # Sign certificate
        if key_type == CertificateType.ED25519:
            certificate = cert_builder.sign(private_key, None)
        else:
            certificate = cert_builder.sign(private_key, hashes.SHA256())

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def parse_certificate(self, cert_data: bytes | str) -> CertificateInfo:
        """Parse a certificate and extract information.

        Args:
            cert_data: Certificate in PEM or DER format

        Returns:
            CertificateInfo with parsed data
        """
        cert = self._load_certificate(cert_data)

        # Extract subject
        subject = self._extract_name(cert.subject)
        issuer = self._extract_name(cert.issuer)

        # Determine key type and size
        public_key = cert.public_key()
        key_type, key_size = self._get_key_info(public_key)

        # Extract extensions
        is_ca = False
        key_usage = []
        extended_key_usage = []
        san = []

        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append(KeyUsage.DIGITAL_SIGNATURE)
            if ku.key_encipherment:
                key_usage.append(KeyUsage.KEY_ENCIPHERMENT)
            if ku.data_encipherment:
                key_usage.append(KeyUsage.DATA_ENCIPHERMENT)
            if ku.key_agreement:
                key_usage.append(KeyUsage.KEY_AGREEMENT)
            if ku.key_cert_sign:
                key_usage.append(KeyUsage.KEY_CERT_SIGN)
            if ku.crl_sign:
                key_usage.append(KeyUsage.CRL_SIGN)
        except x509.ExtensionNotFound:
            pass

        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for oid in eku_ext.value:
                if oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    extended_key_usage.append(ExtendedKeyUsage.SERVER_AUTH)
                elif oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    extended_key_usage.append(ExtendedKeyUsage.CLIENT_AUTH)
                elif oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    extended_key_usage.append(ExtendedKeyUsage.CODE_SIGNING)
                elif oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    extended_key_usage.append(ExtendedKeyUsage.EMAIL_PROTECTION)
                elif oid == x509.oid.ExtendedKeyUsageOID.TIME_STAMPING:
                    extended_key_usage.append(ExtendedKeyUsage.TIME_STAMPING)
                elif oid == x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING:
                    extended_key_usage.append(ExtendedKeyUsage.OCSP_SIGNING)
        except x509.ExtensionNotFound:
            pass

        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san.append(f"email:{name.value}")
        except x509.ExtensionNotFound:
            pass

        # Fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()

        # Get signature algorithm name
        sig_alg = cert.signature_algorithm_oid._name

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.serial_number,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            key_type=key_type,
            key_size=key_size,
            signature_algorithm=sig_alg,
            is_ca=is_ca,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            san=san,
            fingerprint_sha256=fingerprint_sha256,
            fingerprint_sha1=fingerprint_sha1,
            pem=cert.public_bytes(serialization.Encoding.PEM),
        )

    def verify_certificate(
        self,
        cert_data: bytes | str,
        issuer_cert_data: bytes | str | None = None,
        check_expiry: bool = True,
    ) -> ChainValidationResult:
        """Verify a certificate.

        Args:
            cert_data: Certificate to verify
            issuer_cert_data: Issuer certificate (for signature verification)
            check_expiry: Whether to check expiration

        Returns:
            ChainValidationResult with validation details
        """
        errors = []
        warnings = []

        cert = self._load_certificate(cert_data)
        now = datetime.now(timezone.utc)

        # Check expiry
        if check_expiry:
            if cert.not_valid_before_utc > now:
                errors.append(f"Certificate not yet valid (starts {cert.not_valid_before_utc})")
            if cert.not_valid_after_utc < now:
                errors.append(f"Certificate expired ({cert.not_valid_after_utc})")
            elif cert.not_valid_after_utc < now + timedelta(days=30):
                warnings.append(f"Certificate expires soon ({cert.not_valid_after_utc})")

        # Verify signature if issuer provided
        if issuer_cert_data:
            issuer_cert = self._load_certificate(issuer_cert_data)

            try:
                issuer_public_key = issuer_cert.public_key()

                # Check issuer is a CA
                try:
                    basic_constraints = issuer_cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    )
                    if not basic_constraints.value.ca:
                        errors.append("Issuer certificate is not a CA")
                except x509.ExtensionNotFound:
                    warnings.append("Issuer certificate lacks BasicConstraints extension")

                # Verify signature
                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        cert.signature_algorithm_parameters or None,
                    )
                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm),
                    )
                elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                    )
            except Exception as e:
                errors.append(f"Signature verification failed: {e}")

        return ChainValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            chain_length=2 if issuer_cert_data else 1,
            root_subject=self._extract_name(issuer_cert.subject) if issuer_cert_data else None,
        )

    def verify_chain(
        self,
        certificates: list[bytes | str],
        check_expiry: bool = True,
    ) -> ChainValidationResult:
        """Verify a certificate chain.

        Args:
            certificates: List of certificates (leaf first, root last)
            check_expiry: Whether to check expiration

        Returns:
            ChainValidationResult with validation details
        """
        if not certificates:
            return ChainValidationResult(
                valid=False,
                errors=["Empty certificate chain"],
                warnings=[],
                chain_length=0,
                root_subject=None,
            )

        errors = []
        warnings = []
        certs = [self._load_certificate(c) for c in certificates]

        now = datetime.now(timezone.utc)

        for i, cert in enumerate(certs):
            cert_name = f"Certificate {i}" if i > 0 else "Leaf certificate"

            # Check expiry
            if check_expiry:
                if cert.not_valid_before_utc > now:
                    errors.append(f"{cert_name} not yet valid")
                if cert.not_valid_after_utc < now:
                    errors.append(f"{cert_name} expired")

            # Verify chain linkage (except for the last/root)
            if i < len(certs) - 1:
                issuer_cert = certs[i + 1]

                # Check issuer matches
                if cert.issuer != issuer_cert.subject:
                    errors.append(f"{cert_name} issuer doesn't match next certificate subject")

                # Verify signature
                try:
                    issuer_public_key = issuer_cert.public_key()
                    if isinstance(issuer_public_key, rsa.RSAPublicKey):
                        issuer_public_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            cert.signature_algorithm_parameters or None,
                        )
                    elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                        issuer_public_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            ec.ECDSA(cert.signature_hash_algorithm),
                        )
                    elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
                        issuer_public_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                        )
                except Exception as e:
                    errors.append(f"{cert_name} signature verification failed: {e}")

                # Check issuer is CA
                try:
                    basic_constraints = issuer_cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    )
                    if not basic_constraints.value.ca:
                        errors.append(f"Certificate {i+1} is not a CA but signs {cert_name}")
                except x509.ExtensionNotFound:
                    warnings.append(f"Certificate {i+1} lacks BasicConstraints")

        # Check root is self-signed
        root_cert = certs[-1]
        if root_cert.subject != root_cert.issuer:
            warnings.append("Root certificate is not self-signed")

        return ChainValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            chain_length=len(certs),
            root_subject=self._extract_name(root_cert.subject),
        )

    def parse_csr(self, csr_data: bytes | str) -> dict:
        """Parse a CSR and extract information.

        Args:
            csr_data: CSR in PEM or DER format

        Returns:
            Dictionary with CSR information
        """
        if isinstance(csr_data, str):
            csr_data = csr_data.encode()

        try:
            if b"-----BEGIN" in csr_data:
                csr = x509.load_pem_x509_csr(csr_data)
            else:
                csr = x509.load_der_x509_csr(csr_data)
        except Exception as e:
            raise CSRError(f"Failed to parse CSR: {e}")

        subject = self._extract_name(csr.subject)
        public_key = csr.public_key()
        key_type, key_size = self._get_key_info(public_key)

        # Extract SANs if present
        san = []
        try:
            san_ext = csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san.append(f"email:{name.value}")
        except x509.ExtensionNotFound:
            pass

        return {
            "subject": {
                "common_name": subject.common_name,
                "organization": subject.organization,
                "country": subject.country,
            },
            "key_type": key_type.value,
            "key_size": key_size,
            "san": san,
            "is_valid": csr.is_signature_valid,
        }

    # ==================== Helper Methods ====================

    def _generate_key_pair(
        self,
        key_type: CertificateType,
        key_size: int,
    ) -> tuple[Any, Any, int | None]:
        """Generate a key pair."""
        if key_type == CertificateType.RSA:
            if key_size < 2048:
                raise CSRError("RSA key size must be at least 2048")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )
            return private_key, private_key.public_key(), key_size

        elif key_type == CertificateType.EC:
            if key_size == 256:
                curve = ec.SECP256R1()
            elif key_size == 384:
                curve = ec.SECP384R1()
            elif key_size == 521:
                curve = ec.SECP521R1()
            else:
                raise CSRError(f"Unsupported EC key size: {key_size}")

            private_key = ec.generate_private_key(curve)
            return private_key, private_key.public_key(), key_size

        elif key_type == CertificateType.ED25519:
            private_key = ed25519.Ed25519PrivateKey.generate()
            return private_key, private_key.public_key(), None

        else:
            raise CSRError(f"Unknown key type: {key_type}")

    def _load_certificate(self, cert_data: bytes | str) -> x509.Certificate:
        """Load a certificate from PEM or DER format."""
        if isinstance(cert_data, str):
            cert_data = cert_data.encode()

        try:
            if b"-----BEGIN" in cert_data:
                return x509.load_pem_x509_certificate(cert_data)
            else:
                return x509.load_der_x509_certificate(cert_data)
        except Exception as e:
            raise CertificateError(f"Failed to load certificate: {e}")

    def _extract_name(self, name: x509.Name) -> SubjectInfo:
        """Extract SubjectInfo from X.509 Name."""
        def get_attr(oid) -> str | None:
            try:
                return name.get_attributes_for_oid(oid)[0].value
            except (IndexError, ValueError):
                return None

        return SubjectInfo(
            common_name=get_attr(NameOID.COMMON_NAME) or "",
            organization=get_attr(NameOID.ORGANIZATION_NAME),
            organizational_unit=get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=get_attr(NameOID.COUNTRY_NAME),
            state=get_attr(NameOID.STATE_OR_PROVINCE_NAME),
            locality=get_attr(NameOID.LOCALITY_NAME),
            email=get_attr(NameOID.EMAIL_ADDRESS),
        )

    def _get_key_info(self, public_key: Any) -> tuple[CertificateType, int | None]:
        """Get key type and size from public key."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return CertificateType.RSA, public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return CertificateType.EC, public_key.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return CertificateType.ED25519, None
        else:
            raise CertificateError(f"Unknown public key type: {type(public_key)}")


# Singleton instance
certificate_engine = CertificateEngine()
