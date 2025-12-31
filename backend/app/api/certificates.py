"""Certificate Management API routes.

Provides PKI operations: CSR generation, self-signed certs, certificate parsing and validation.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field

from app.models import Identity
from app.core.certificate_engine import (
    CertificateEngine,
    CertificateError,
    CSRError,
    ValidationError,
    SubjectInfo,
    CertificateType,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/v1/certificates", tags=["certificates"])

# Singleton engine
certificate_engine = CertificateEngine()


# ============================================================================
# Request/Response Models
# ============================================================================

class SubjectInfoRequest(BaseModel):
    """Certificate subject information."""
    common_name: str = Field(..., description="Common Name (CN)")
    organization: str | None = Field(default=None, description="Organization (O)")
    organizational_unit: str | None = Field(default=None, description="Organizational Unit (OU)")
    country: str | None = Field(default=None, description="Country code (C)")
    state: str | None = Field(default=None, description="State/Province (ST)")
    locality: str | None = Field(default=None, description="City/Locality (L)")
    email: str | None = Field(default=None, description="Email address")


class CSRRequest(BaseModel):
    """CSR generation request."""
    subject: SubjectInfoRequest
    key_type: str = Field(default="ec", description="Key type: ec (recommended), rsa, ed25519")
    key_size: int = Field(default=256, description="Key size: 256/384/521 for EC, 2048-4096 for RSA")
    san_domains: list[str] | None = Field(default=None, description="Subject Alternative Name domains")
    san_ips: list[str] | None = Field(default=None, description="Subject Alternative Name IPs")
    san_emails: list[str] | None = Field(default=None, description="Subject Alternative Name emails")


class CSRResponse(BaseModel):
    """CSR generation response."""
    csr_pem: str = Field(..., description="CSR in PEM format")
    private_key_pem: str = Field(..., description="Private key in PEM format (keep secret!)")
    public_key_pem: str = Field(..., description="Public key in PEM format")
    key_type: str
    key_size: int | None


class SelfSignedRequest(BaseModel):
    """Self-signed certificate request."""
    subject: SubjectInfoRequest
    key_type: str = Field(default="ec", description="Key type: ec, rsa, ed25519")
    key_size: int = Field(default=256, description="Key size")
    validity_days: int = Field(default=365, description="Certificate validity in days")
    is_ca: bool = Field(default=False, description="Create as CA certificate")
    san_domains: list[str] | None = Field(default=None, description="SAN domains")
    san_ips: list[str] | None = Field(default=None, description="SAN IPs")


class SelfSignedResponse(BaseModel):
    """Self-signed certificate response."""
    certificate_pem: str
    private_key_pem: str


class ParseCertificateRequest(BaseModel):
    """Certificate parsing request."""
    certificate: str = Field(..., description="Certificate in PEM or base64-encoded DER format")


class SubjectInfoResponse(BaseModel):
    """Subject/Issuer info response."""
    common_name: str
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None


class CertificateInfoResponse(BaseModel):
    """Parsed certificate information."""
    subject: SubjectInfoResponse
    issuer: SubjectInfoResponse
    serial_number: str
    not_before: str
    not_after: str
    key_type: str
    key_size: int | None
    signature_algorithm: str
    is_ca: bool
    key_usage: list[str]
    extended_key_usage: list[str]
    san: list[str]
    fingerprint_sha256: str
    fingerprint_sha1: str
    days_until_expiry: int


class VerifyCertificateRequest(BaseModel):
    """Certificate verification request."""
    certificate: str = Field(..., description="Certificate to verify (PEM)")
    issuer_certificate: str | None = Field(default=None, description="Issuer certificate (PEM)")
    check_expiry: bool = Field(default=True, description="Check expiration dates")


class VerifyChainRequest(BaseModel):
    """Certificate chain verification request."""
    certificates: list[str] = Field(..., description="Certificates (leaf first, root last)")
    check_expiry: bool = Field(default=True)


class ValidationResultResponse(BaseModel):
    """Validation result."""
    valid: bool
    errors: list[str]
    warnings: list[str]
    chain_length: int


class ParseCSRRequest(BaseModel):
    """CSR parsing request."""
    csr: str = Field(..., description="CSR in PEM format")


# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/csr/generate", response_model=CSRResponse)
async def generate_csr(
    data: CSRRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a Certificate Signing Request (CSR).

    Creates a CSR with a new key pair. Send the CSR to a Certificate Authority
    to obtain a signed certificate.

    Key recommendations:
    - EC with P-256 (key_size=256) for most use cases
    - RSA 2048 or 4096 for legacy compatibility
    - Ed25519 for modern high-security applications
    """
    try:
        key_type = CertificateType(data.key_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid key type: {data.key_type}. Use: ec, rsa, ed25519",
        )

    subject = SubjectInfo(
        common_name=data.subject.common_name,
        organization=data.subject.organization,
        organizational_unit=data.subject.organizational_unit,
        country=data.subject.country,
        state=data.subject.state,
        locality=data.subject.locality,
        email=data.subject.email,
    )

    try:
        result = certificate_engine.generate_csr(
            subject=subject,
            key_type=key_type,
            key_size=data.key_size,
            san_domains=data.san_domains,
            san_ips=data.san_ips,
            san_emails=data.san_emails,
        )
    except CSRError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return CSRResponse(
        csr_pem=result.csr_pem.decode("utf-8"),
        private_key_pem=result.private_key_pem.decode("utf-8"),
        public_key_pem=result.public_key_pem.decode("utf-8"),
        key_type=result.key_type.value,
        key_size=result.key_size,
    )


@router.post("/self-signed/generate", response_model=SelfSignedResponse)
async def generate_self_signed(
    data: SelfSignedRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a self-signed certificate.

    Useful for:
    - Development/testing environments
    - Internal PKI root CA certificates
    - Quick prototyping

    For production, use a proper CA-signed certificate.
    """
    try:
        key_type = CertificateType(data.key_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid key type: {data.key_type}",
        )

    subject = SubjectInfo(
        common_name=data.subject.common_name,
        organization=data.subject.organization,
        organizational_unit=data.subject.organizational_unit,
        country=data.subject.country,
        state=data.subject.state,
        locality=data.subject.locality,
        email=data.subject.email,
    )

    try:
        cert_pem, key_pem = certificate_engine.generate_self_signed(
            subject=subject,
            key_type=key_type,
            key_size=data.key_size,
            validity_days=data.validity_days,
            is_ca=data.is_ca,
            san_domains=data.san_domains,
            san_ips=data.san_ips,
        )
    except CertificateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return SelfSignedResponse(
        certificate_pem=cert_pem.decode("utf-8"),
        private_key_pem=key_pem.decode("utf-8"),
    )


@router.post("/parse", response_model=CertificateInfoResponse)
async def parse_certificate(
    data: ParseCertificateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Parse a certificate and extract its information.

    Accepts certificates in PEM format.
    Returns detailed information about the certificate including:
    - Subject and issuer details
    - Validity period
    - Key usage and extensions
    - Fingerprints
    """
    try:
        info = certificate_engine.parse_certificate(data.certificate)
    except CertificateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    days_until_expiry = (info.not_after - now).days

    return CertificateInfoResponse(
        subject=SubjectInfoResponse(
            common_name=info.subject.common_name,
            organization=info.subject.organization,
            organizational_unit=info.subject.organizational_unit,
            country=info.subject.country,
            state=info.subject.state,
            locality=info.subject.locality,
            email=info.subject.email,
        ),
        issuer=SubjectInfoResponse(
            common_name=info.issuer.common_name,
            organization=info.issuer.organization,
            organizational_unit=info.issuer.organizational_unit,
            country=info.issuer.country,
            state=info.issuer.state,
            locality=info.issuer.locality,
            email=info.issuer.email,
        ),
        serial_number=str(info.serial_number),
        not_before=info.not_before.isoformat(),
        not_after=info.not_after.isoformat(),
        key_type=info.key_type.value,
        key_size=info.key_size,
        signature_algorithm=info.signature_algorithm,
        is_ca=info.is_ca,
        key_usage=[ku.value for ku in info.key_usage],
        extended_key_usage=[eku.value for eku in info.extended_key_usage],
        san=info.san,
        fingerprint_sha256=info.fingerprint_sha256,
        fingerprint_sha1=info.fingerprint_sha1,
        days_until_expiry=days_until_expiry,
    )


@router.post("/verify", response_model=ValidationResultResponse)
async def verify_certificate(
    data: VerifyCertificateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a certificate.

    Checks:
    - Expiration dates
    - Signature (if issuer certificate provided)
    - CA constraints

    Returns validation result with any errors or warnings.
    """
    try:
        result = certificate_engine.verify_certificate(
            cert_data=data.certificate,
            issuer_cert_data=data.issuer_certificate,
            check_expiry=data.check_expiry,
        )
    except CertificateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ValidationResultResponse(
        valid=result.valid,
        errors=result.errors,
        warnings=result.warnings,
        chain_length=result.chain_length,
    )


@router.post("/verify-chain", response_model=ValidationResultResponse)
async def verify_certificate_chain(
    data: VerifyChainRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a certificate chain.

    Validates the entire chain from leaf to root:
    - Each certificate's signature verified by the next
    - Expiration dates checked
    - CA constraints verified

    Certificates should be in order: [leaf, intermediate(s), root]
    """
    if len(data.certificates) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Chain must have at least 2 certificates",
        )

    try:
        result = certificate_engine.verify_chain(
            certificates=data.certificates,
            check_expiry=data.check_expiry,
        )
    except CertificateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ValidationResultResponse(
        valid=result.valid,
        errors=result.errors,
        warnings=result.warnings,
        chain_length=result.chain_length,
    )


@router.post("/csr/parse")
async def parse_csr(
    data: ParseCSRRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Parse a Certificate Signing Request.

    Returns information about the CSR including subject, key type, and SANs.
    """
    try:
        info = certificate_engine.parse_csr(data.csr)
    except CSRError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return info


@router.post("/upload/parse")
async def parse_uploaded_certificate(
    file: UploadFile = File(...),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Parse an uploaded certificate file.

    Accepts PEM or DER format certificate files.
    """
    if not identity:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    content = await file.read()

    if len(content) > 100 * 1024:  # 100KB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large (max 100KB)",
        )

    try:
        # Try as text first
        try:
            cert_data = content.decode("utf-8")
        except UnicodeDecodeError:
            # Binary DER format
            cert_data = content

        info = certificate_engine.parse_certificate(cert_data)
    except CertificateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    days_until_expiry = (info.not_after - now).days

    return {
        "filename": file.filename,
        "subject": {
            "common_name": info.subject.common_name,
            "organization": info.subject.organization,
            "country": info.subject.country,
        },
        "issuer": {
            "common_name": info.issuer.common_name,
            "organization": info.issuer.organization,
        },
        "not_before": info.not_before.isoformat(),
        "not_after": info.not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "is_expired": days_until_expiry < 0,
        "key_type": info.key_type.value,
        "key_size": info.key_size,
        "is_ca": info.is_ca,
        "san": info.san,
        "fingerprint_sha256": info.fingerprint_sha256,
    }
