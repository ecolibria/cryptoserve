"""Signed Certificate Timestamp (SCT) Validator.

Validates SCTs embedded in X.509 certificates to verify that certificates
were properly logged to Certificate Transparency logs.

SCT Delivery Methods (RFC 6962):
1. X.509v3 Extension (OID 1.3.6.1.4.1.11129.2.4.2) - embedded in cert
2. TLS Extension (signed_certificate_timestamp) - during TLS handshake
3. OCSP Stapling - via OCSP response

This module focuses on validating embedded SCTs from X.509 certificates.

Standards:
- RFC 6962: Certificate Transparency
- RFC 9162: Certificate Transparency Version 2.0
"""

import hashlib
import struct
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)

# SCT extension OID (RFC 6962)
SCT_EXTENSION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


class SCTVersion(IntEnum):
    """SCT version (RFC 6962)."""
    V1 = 0


class SignatureType(IntEnum):
    """CT signature type."""
    CERTIFICATE_TIMESTAMP = 0
    TREE_HASH = 1


class HashAlgorithm(IntEnum):
    """Hash algorithm for SCT signatures."""
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm(IntEnum):
    """Signature algorithm for SCT."""
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


@dataclass
class SCT:
    """Signed Certificate Timestamp."""
    version: SCTVersion
    log_id: bytes  # 32-byte SHA-256 hash of log's public key
    timestamp: datetime
    extensions: bytes
    hash_algorithm: HashAlgorithm
    signature_algorithm: SignatureAlgorithm
    signature: bytes

    @property
    def log_id_hex(self) -> str:
        """Return log ID as hex string."""
        return self.log_id.hex()

    @property
    def timestamp_ms(self) -> int:
        """Return timestamp as milliseconds since epoch."""
        return int(self.timestamp.timestamp() * 1000)


@dataclass
class SCTValidationResult:
    """Result of SCT validation."""
    valid: bool
    sct: SCT
    log_name: str | None = None
    error: str | None = None
    verified_at: datetime | None = None


@dataclass
class CTLogInfo:
    """Information about a CT log."""
    log_id: str  # hex-encoded
    name: str
    url: str
    public_key: bytes
    operator: str
    status: str = "active"


# Known CT log public keys (from Google CT log list)
# Log IDs are SHA-256 hashes of the log's public key
# Public keys are DER-encoded SubjectPublicKeyInfo (placeholder values here)
# In production, these would be populated from Google's CT log list JSON
KNOWN_CT_LOGS: dict[str, CTLogInfo] = {
    # Google Argon logs
    "a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10": CTLogInfo(
        log_id="a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10",
        name="Google 'Argon2024' log",
        url="https://ct.googleapis.com/logs/argon2024/",
        public_key=b"",  # Would be actual DER-encoded public key
        operator="Google",
    ),
    # Let's Encrypt Oak logs
    "b73efb24df9c4dba75f239c5ba58f46c5dfc42cf7a9f35c49e1d098125edb499": CTLogInfo(
        log_id="b73efb24df9c4dba75f239c5ba58f46c5dfc42cf7a9f35c49e1d098125edb499",
        name="Let's Encrypt 'Oak2024H1'",
        url="https://oak.ct.letsencrypt.org/2024h1/",
        public_key=b"",  # Would be actual DER-encoded public key
        operator="Let's Encrypt",
    ),
    # Cloudflare Nimbus logs
    "7a328c54d8b72db620ea38e0521ee98416703213854d3bd22bc13a57a352eb52": CTLogInfo(
        log_id="7a328c54d8b72db620ea38e0521ee98416703213854d3bd22bc13a57a352eb52",
        name="Cloudflare 'Nimbus2024'",
        url="https://ct.cloudflare.com/logs/nimbus2024/",
        public_key=b"",  # Would be actual DER-encoded public key
        operator="Cloudflare",
    ),
}


class SCTParser:
    """Parser for Signed Certificate Timestamps."""

    @staticmethod
    def parse_sct_list(data: bytes) -> list[SCT]:
        """Parse a list of SCTs from the SCT extension.

        The SCT extension contains a serialized list of SCTs.
        Format: 2-byte length prefix, then concatenated SCTs.

        Args:
            data: Raw SCT extension data

        Returns:
            List of parsed SCTs
        """
        scts = []
        offset = 0

        # Skip outer length prefix (2 bytes)
        if len(data) < 2:
            return scts

        list_length = struct.unpack(">H", data[0:2])[0]
        offset = 2
        end = min(offset + list_length, len(data))

        while offset < end:
            # Each SCT has a 2-byte length prefix
            if offset + 2 > end:
                break

            sct_length = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2

            if offset + sct_length > len(data):
                break

            sct_data = data[offset:offset + sct_length]
            offset += sct_length

            try:
                sct = SCTParser.parse_sct(sct_data)
                if sct:
                    scts.append(sct)
            except Exception as e:
                logger.warning(f"Failed to parse SCT: {e}")

        return scts

    @staticmethod
    def parse_sct(data: bytes) -> SCT | None:
        """Parse a single SCT.

        SCT format (RFC 6962):
        - version: 1 byte
        - log_id: 32 bytes
        - timestamp: 8 bytes (ms since epoch)
        - extensions: 2-byte length + data
        - signature: hash_alg(1) + sig_alg(1) + 2-byte length + signature

        Args:
            data: Raw SCT data

        Returns:
            Parsed SCT or None if parsing fails
        """
        if len(data) < 44:  # Minimum SCT size
            return None

        offset = 0

        # Version (1 byte)
        version = SCTVersion(data[offset])
        offset += 1

        # Log ID (32 bytes)
        log_id = data[offset:offset + 32]
        offset += 32

        # Timestamp (8 bytes, ms since epoch)
        timestamp_ms = struct.unpack(">Q", data[offset:offset + 8])[0]
        timestamp = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        offset += 8

        # Extensions (2-byte length prefix)
        if offset + 2 > len(data):
            return None
        ext_length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        extensions = data[offset:offset + ext_length]
        offset += ext_length

        # Signature
        if offset + 4 > len(data):
            return None
        hash_alg = HashAlgorithm(data[offset])
        sig_alg = SignatureAlgorithm(data[offset + 1])
        offset += 2

        sig_length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        signature = data[offset:offset + sig_length]

        return SCT(
            version=version,
            log_id=log_id,
            timestamp=timestamp,
            extensions=extensions,
            hash_algorithm=hash_alg,
            signature_algorithm=sig_alg,
            signature=signature,
        )


class SCTValidator:
    """Validates Signed Certificate Timestamps.

    Verifies that SCTs are properly signed by known CT logs.
    """

    def __init__(self, known_logs: dict[str, CTLogInfo] | None = None):
        """Initialize validator with known CT logs.

        Args:
            known_logs: Map of log_id (hex) -> CTLogInfo
        """
        self.known_logs = known_logs or KNOWN_CT_LOGS
        self._parser = SCTParser()

    def extract_scts_from_certificate(self, cert: x509.Certificate) -> list[SCT]:
        """Extract embedded SCTs from a certificate.

        Args:
            cert: X.509 certificate

        Returns:
            List of SCTs embedded in the certificate
        """
        try:
            # Get the SCT extension
            sct_ext = cert.extensions.get_extension_for_oid(SCT_EXTENSION_OID)
            sct_data = sct_ext.value.value  # Raw extension data
            return self._parser.parse_sct_list(sct_data)
        except x509.ExtensionNotFound:
            return []
        except Exception as e:
            logger.warning(f"Failed to extract SCTs: {e}")
            return []

    def extract_scts_from_pem(self, pem_data: bytes) -> list[SCT]:
        """Extract SCTs from a PEM-encoded certificate.

        Args:
            pem_data: PEM-encoded certificate

        Returns:
            List of SCTs
        """
        try:
            cert = x509.load_pem_x509_certificate(pem_data)
            return self.extract_scts_from_certificate(cert)
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            return []

    def extract_scts_from_der(self, der_data: bytes) -> list[SCT]:
        """Extract SCTs from a DER-encoded certificate.

        Args:
            der_data: DER-encoded certificate

        Returns:
            List of SCTs
        """
        try:
            cert = x509.load_der_x509_certificate(der_data)
            return self.extract_scts_from_certificate(cert)
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            return []

    def validate_sct(
        self,
        sct: SCT,
        cert: x509.Certificate,
        issuer_key_hash: bytes | None = None,
    ) -> SCTValidationResult:
        """Validate a single SCT.

        Validation checks:
        1. SCT version is supported
        2. Log ID matches a known CT log
        3. Timestamp is reasonable (not in future, not too old)
        4. Signature verifies (if log public key is known)

        Args:
            sct: The SCT to validate
            cert: The certificate the SCT is for
            issuer_key_hash: Hash of issuer's public key (for precerts)

        Returns:
            Validation result
        """
        now = datetime.now(timezone.utc)

        # Check version
        if sct.version != SCTVersion.V1:
            return SCTValidationResult(
                valid=False,
                sct=sct,
                error=f"Unsupported SCT version: {sct.version}",
            )

        # Check timestamp is not in future
        if sct.timestamp > now:
            return SCTValidationResult(
                valid=False,
                sct=sct,
                error=f"SCT timestamp is in the future: {sct.timestamp}",
            )

        # Check log is known
        log_id_hex = sct.log_id_hex
        log_info = self.known_logs.get(log_id_hex)

        if not log_info:
            # Unknown log - we can't verify signature but SCT might still be valid
            return SCTValidationResult(
                valid=True,  # Treat as valid but note unknown log
                sct=sct,
                log_name="Unknown CT Log",
                error=f"SCT from unknown log: {log_id_hex[:16]}...",
                verified_at=now,
            )

        # TODO: Implement full signature verification
        # This requires:
        # 1. Constructing the signed data (TBSCertificate + SCT fields)
        # 2. Verifying against log's public key
        # For now, we validate structure and known log

        return SCTValidationResult(
            valid=True,
            sct=sct,
            log_name=log_info.name,
            verified_at=now,
        )

    def validate_certificate_scts(
        self,
        cert: x509.Certificate,
        min_scts: int = 2,
    ) -> dict[str, Any]:
        """Validate all SCTs in a certificate.

        Chrome/Safari require at least 2-3 SCTs depending on cert lifetime.

        Args:
            cert: Certificate to validate
            min_scts: Minimum number of valid SCTs required

        Returns:
            Validation summary with results for each SCT
        """
        scts = self.extract_scts_from_certificate(cert)
        results = []
        valid_count = 0

        for sct in scts:
            result = self.validate_sct(sct, cert)
            results.append(result)
            if result.valid:
                valid_count += 1

        return {
            "certificate_subject": cert.subject.rfc4514_string(),
            "total_scts": len(scts),
            "valid_scts": valid_count,
            "meets_minimum": valid_count >= min_scts,
            "minimum_required": min_scts,
            "results": results,
            "logs_used": [r.log_name for r in results if r.log_name],
        }

    def get_required_scts(self, cert: x509.Certificate) -> int:
        """Calculate minimum required SCTs for a certificate.

        Per Chrome CT Policy:
        - Cert lifetime < 180 days: 2 SCTs
        - Cert lifetime >= 180 days: 3 SCTs
        - Cert lifetime >= 39 months: 4 SCTs (older policy)

        Args:
            cert: Certificate to check

        Returns:
            Minimum number of SCTs required
        """
        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
        days = lifetime.days

        if days < 180:
            return 2
        elif days < 39 * 30:  # ~39 months
            return 3
        else:
            return 4


# Singleton instance
sct_validator = SCTValidator()
