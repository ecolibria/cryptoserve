"""Certificate Transparency Monitoring API routes.

Provides endpoints for monitoring CT logs to detect unauthorized
certificate issuance for your domains.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.api.crypto import get_sdk_identity
from app.core.ct_monitoring import (
    ct_monitor,
    CTMonitor,
    CTLogEntry,
    CTAlert,
    CTAlertSeverity,
    CTAlertType,
    CTMonitoringResult,
    DomainConfig,
)
from app.core.sct_validator import (
    sct_validator,
    SCTValidator,
    SCT,
    SCTValidationResult,
)


router = APIRouter(prefix="/api/v1/ct", tags=["certificate-transparency"])


# =============================================================================
# Helper Functions
# =============================================================================


def normalize_domain(domain: str) -> str:
    """Normalize a domain by stripping URL components.

    Handles inputs like:
    - "https://www.example.com" -> "example.com"
    - "http://example.com/path" -> "example.com"
    - "www.example.com" -> "example.com"
    - "example.com" -> "example.com"
    """
    # Strip whitespace
    domain = domain.strip()

    # Remove protocol
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]

    # Remove path and query string
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]

    # Remove port if present
    domain = domain.split(":")[0]

    # Optionally remove www. prefix (keep it for now since certs may differ)
    # if domain.startswith("www."):
    #     domain = domain[4:]

    return domain.lower()


# =============================================================================
# Request/Response Models
# =============================================================================


class DomainConfigRequest(BaseModel):
    """Domain monitoring configuration."""
    domain: str = Field(..., description="Domain to monitor (e.g., example.com)")
    includeSubdomains: bool = Field(default=True, description="Include subdomains")
    expectedIssuers: list[str] = Field(
        default_factory=list,
        description="Expected CA issuers (alerts if cert from other CA)",
    )
    alertOnWildcard: bool = Field(default=True, description="Alert on wildcard certs")
    expiryWarningDays: int = Field(default=30, description="Days before expiry to warn")


class CTCertificateResponse(BaseModel):
    """Certificate entry from CT logs."""
    id: int
    issuerName: str
    commonName: str
    domains: list[str]
    notBefore: datetime
    notAfter: datetime
    serialNumber: str
    fingerprint: str
    isExpired: bool
    daysUntilExpiry: int
    isWildcard: bool
    entryTimestamp: datetime | None = None


class CTAlertResponse(BaseModel):
    """Alert from CT monitoring."""
    alertType: str
    severity: str
    domain: str
    message: str
    certificateId: int | None = None
    details: dict = Field(default_factory=dict)
    createdAt: datetime


class MonitoringResultResponse(BaseModel):
    """Result of monitoring a domain."""
    domain: str
    totalCerts: int
    activeCerts: int
    expiredCerts: int
    alertCount: int
    criticalAlerts: int
    highAlerts: int
    issuers: dict[str, int]
    scannedAt: datetime


class ScanDomainResponse(BaseModel):
    """Full scan results for a domain."""
    summary: MonitoringResultResponse
    certificates: list[CTCertificateResponse]
    alerts: list[CTAlertResponse]


class BulkScanRequest(BaseModel):
    """Request to scan multiple domains."""
    domains: list[DomainConfigRequest]


class BulkScanResponse(BaseModel):
    """Response from bulk domain scan."""
    results: list[MonitoringResultResponse]
    totalDomains: int
    totalCerts: int
    totalAlerts: int
    criticalAlerts: int


class RecentCertsResponse(BaseModel):
    """Recent certificates for a domain."""
    domain: str
    days: int
    certificates: list[CTCertificateResponse]
    count: int


# =============================================================================
# Helper Functions
# =============================================================================


def _cert_to_response(cert: CTLogEntry) -> CTCertificateResponse:
    """Convert CTLogEntry to API response."""
    return CTCertificateResponse(
        id=cert.id,
        issuerName=cert.issuer_name,
        commonName=cert.common_name,
        domains=cert.domains,
        notBefore=cert.not_before,
        notAfter=cert.not_after,
        serialNumber=cert.serial_number,
        fingerprint=cert.sha256_fingerprint,
        isExpired=cert.is_expired,
        daysUntilExpiry=cert.days_until_expiry,
        isWildcard=cert.is_wildcard,
        entryTimestamp=cert.entry_timestamp,
    )


def _alert_to_response(alert: CTAlert) -> CTAlertResponse:
    """Convert CTAlert to API response."""
    return CTAlertResponse(
        alertType=alert.alert_type.value,
        severity=alert.severity.value,
        domain=alert.domain,
        message=alert.message,
        certificateId=alert.certificate.id if alert.certificate else None,
        details=alert.details,
        createdAt=alert.created_at,
    )


def _result_to_summary(result: CTMonitoringResult) -> MonitoringResultResponse:
    """Convert CTMonitoringResult to summary response."""
    critical = sum(1 for a in result.alerts if a.severity == CTAlertSeverity.CRITICAL)
    high = sum(1 for a in result.alerts if a.severity == CTAlertSeverity.HIGH)

    return MonitoringResultResponse(
        domain=result.domain,
        totalCerts=result.total_certs,
        activeCerts=result.active_certs,
        expiredCerts=result.expired_certs,
        alertCount=len(result.alerts),
        criticalAlerts=critical,
        highAlerts=high,
        issuers=result.issuers,
        scannedAt=result.scanned_at,
    )


def _config_from_request(req: DomainConfigRequest) -> DomainConfig:
    """Convert API request to DomainConfig."""
    return DomainConfig(
        domain=req.domain,
        include_subdomains=req.includeSubdomains,
        expected_issuers=req.expectedIssuers,
        alert_on_wildcard=req.alertOnWildcard,
        expiry_warning_days=req.expiryWarningDays,
    )


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/scan/{domain}", response_model=ScanDomainResponse)
async def scan_domain(
    domain: str,
    include_subdomains: bool = Query(default=True, description="Include subdomains"),
    include_expired: bool = Query(default=False, description="Include expired certs in results"),
    expected_issuers: list[str] = Query(default=[], description="Expected CA issuers"),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Scan CT logs for certificates issued to a domain.

    Queries public CT log aggregators to find all certificates
    ever issued for the specified domain. Returns certificates
    and any security alerts.

    By default, only active (non-expired) certificates are returned
    in the results, but summary stats include all certificates.

    This is useful for:
    - Detecting unauthorized certificate issuance
    - Finding rogue or misissued certificates
    - Auditing your CA relationships
    - Monitoring certificate expiration

    The domain parameter accepts full URLs (e.g., "https://www.example.com")
    which will be automatically normalized to just the domain.
    """
    # Normalize domain (strip https://, paths, etc.)
    domain = normalize_domain(domain)

    if not domain or "." not in domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain format. Please provide a valid domain like 'example.com'",
        )

    config = DomainConfig(
        domain=domain,
        include_subdomains=include_subdomains,
        expected_issuers=expected_issuers,
    )

    try:
        result = await ct_monitor.monitor_domain(config)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query CT logs: {str(e)}",
        )

    # Filter certificates for response (stats still include all)
    certs_to_return = result.certificates
    if not include_expired:
        certs_to_return = [c for c in result.certificates if not c.is_expired]

    return ScanDomainResponse(
        summary=_result_to_summary(result),
        certificates=[_cert_to_response(c) for c in certs_to_return],
        alerts=[_alert_to_response(a) for a in result.alerts],
    )


@router.post("/scan/bulk", response_model=BulkScanResponse)
async def scan_domains_bulk(
    request: BulkScanRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Scan CT logs for multiple domains.

    Efficiently scans multiple domains in parallel.
    Returns summary results for each domain.
    """
    if len(request.domains) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 10 domains per bulk scan",
        )

    configs = [_config_from_request(d) for d in request.domains]

    try:
        results = await ct_monitor.monitor_domains(configs)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query CT logs: {str(e)}",
        )

    summaries = [_result_to_summary(r) for r in results]
    total_certs = sum(r.total_certs for r in results)
    total_alerts = sum(len(r.alerts) for r in results)
    critical_alerts = sum(
        1 for r in results
        for a in r.alerts
        if a.severity == CTAlertSeverity.CRITICAL
    )

    return BulkScanResponse(
        results=summaries,
        totalDomains=len(results),
        totalCerts=total_certs,
        totalAlerts=total_alerts,
        criticalAlerts=critical_alerts,
    )


@router.get("/recent/{domain}", response_model=RecentCertsResponse)
async def get_recent_certificates(
    domain: str,
    days: int = Query(default=7, ge=1, le=90, description="Days to look back"),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Get recently issued certificates for a domain.

    Finds certificates issued within the last N days.
    Useful for detecting new or unexpected issuances.
    """
    # Normalize domain (strip https://, paths, etc.)
    domain = normalize_domain(domain)

    if not domain or "." not in domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain format",
        )

    try:
        certs = await ct_monitor.find_recent_certificates(domain, days)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query CT logs: {str(e)}",
        )

    return RecentCertsResponse(
        domain=domain,
        days=days,
        certificates=[_cert_to_response(c) for c in certs],
        count=len(certs),
    )


@router.get("/certificate/{cert_id}")
async def get_certificate_details(
    cert_id: int,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Get detailed information about a specific certificate.

    Returns the full certificate data from CT logs including
    the complete certificate chain if available.
    """
    try:
        details = await ct_monitor.get_certificate_details(cert_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to get certificate details: {str(e)}",
        )

    if not details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate not found: {cert_id}",
        )

    return details


@router.get("/issuers/{domain}")
async def get_certificate_issuers(
    domain: str,
    include_subdomains: bool = Query(default=True),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Get all CAs that have issued certificates for a domain.

    Returns a breakdown of certificate authorities that have
    issued certificates for your domain. Useful for auditing
    your CA relationships and detecting unauthorized issuers.
    """
    # Normalize domain (strip https://, paths, etc.)
    domain = normalize_domain(domain)

    if not domain or "." not in domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain format",
        )

    try:
        certs = await ct_monitor.search_certificates(
            domain,
            include_subdomains=include_subdomains,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query CT logs: {str(e)}",
        )

    # Count by issuer
    issuers: dict[str, dict] = {}
    for cert in certs:
        issuer = cert.issuer_name
        if issuer not in issuers:
            issuers[issuer] = {
                "name": issuer,
                "count": 0,
                "activeCerts": 0,
                "expiredCerts": 0,
                "wildcards": 0,
            }

        issuers[issuer]["count"] += 1
        if cert.is_expired:
            issuers[issuer]["expiredCerts"] += 1
        else:
            issuers[issuer]["activeCerts"] += 1
        if cert.is_wildcard:
            issuers[issuer]["wildcards"] += 1

    # Sort by count
    sorted_issuers = sorted(
        issuers.values(),
        key=lambda x: x["count"],
        reverse=True,
    )

    return {
        "domain": domain,
        "totalIssuers": len(issuers),
        "totalCertificates": len(certs),
        "issuers": sorted_issuers,
    }


@router.get("/search")
async def search_certificates(
    q: str = Query(..., min_length=3, description="Domain to search"),
    exclude_expired: bool = Query(default=False, description="Exclude expired certs"),
    limit: int = Query(default=100, ge=1, le=1000, description="Max results"),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Search CT logs for certificates matching a query.

    Free-form search of CT logs. Use this for investigating
    suspicious domains or finding related certificates.
    """
    try:
        certs = await ct_monitor.search_certificates(
            domain=q,
            include_subdomains=True,
            exclude_expired=exclude_expired,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query CT logs: {str(e)}",
        )

    # Limit results
    limited_certs = certs[:limit]

    return {
        "query": q,
        "totalResults": len(certs),
        "returnedResults": len(limited_certs),
        "certificates": [_cert_to_response(c) for c in limited_certs],
    }


# =============================================================================
# SCT Validation Models
# =============================================================================


class SCTResponse(BaseModel):
    """Signed Certificate Timestamp response."""
    logId: str
    logName: str | None
    timestamp: datetime
    valid: bool
    error: str | None = None


class SCTValidationResponse(BaseModel):
    """SCT validation result for a certificate."""
    certificateSubject: str
    totalScts: int
    validScts: int
    meetsMinimum: bool
    minimumRequired: int
    scts: list[SCTResponse]
    logsUsed: list[str]


class ValidateSCTRequest(BaseModel):
    """Request to validate SCTs in a certificate."""
    certificate: str = Field(..., description="PEM-encoded certificate")
    minScts: int = Field(default=2, ge=1, le=5, description="Minimum SCTs required")


# =============================================================================
# SCT Validation Endpoints
# =============================================================================


@router.post("/sct/validate", response_model=SCTValidationResponse)
async def validate_certificate_scts(
    request: ValidateSCTRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Validate Signed Certificate Timestamps (SCTs) in a certificate.

    SCTs prove that a certificate was logged to Certificate Transparency
    logs before being issued. Chrome, Safari, and other browsers require
    certificates to have valid SCTs.

    This endpoint:
    1. Extracts embedded SCTs from the certificate
    2. Validates each SCT against known CT logs
    3. Checks if the certificate meets browser requirements

    Browser Requirements (Chrome CT Policy):
    - Certificates with lifetime < 180 days: 2 SCTs required
    - Certificates with lifetime >= 180 days: 3 SCTs required

    Input:
    - PEM-encoded X.509 certificate

    Returns:
    - List of SCTs found and their validation status
    - Whether the certificate meets minimum SCT requirements
    """
    try:
        cert_pem = request.certificate.encode()

        # Load certificate
        from cryptography import x509
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid PEM certificate: {str(e)}",
            )

        # Calculate required SCTs based on cert lifetime
        required_scts = sct_validator.get_required_scts(cert)
        min_scts = max(request.minScts, required_scts)

        # Validate SCTs
        result = sct_validator.validate_certificate_scts(cert, min_scts)

        # Convert to response
        sct_responses = []
        for sct_result in result["results"]:
            sct_responses.append(SCTResponse(
                logId=sct_result.sct.log_id_hex,
                logName=sct_result.log_name,
                timestamp=sct_result.sct.timestamp,
                valid=sct_result.valid,
                error=sct_result.error,
            ))

        return SCTValidationResponse(
            certificateSubject=result["certificate_subject"],
            totalScts=result["total_scts"],
            validScts=result["valid_scts"],
            meetsMinimum=result["meets_minimum"],
            minimumRequired=result["minimum_required"],
            scts=sct_responses,
            logsUsed=result["logs_used"],
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SCT validation failed: {str(e)}",
        )


@router.get("/sct/info")
async def get_sct_info(
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Get information about known CT logs.

    Returns the list of CT logs that are recognized for SCT validation.
    This is useful for understanding which logs are trusted and their status.
    """
    logs = []
    for log_id, log_info in sct_validator.known_logs.items():
        logs.append({
            "logId": log_id,
            "name": log_info.name,
            "url": log_info.url,
            "operator": log_info.operator,
            "status": log_info.status,
        })

    return {
        "knownLogs": logs,
        "totalLogs": len(logs),
        "browserRequirements": {
            "chrome": {
                "lifetime_under_180_days": 2,
                "lifetime_180_days_plus": 3,
            },
            "safari": {
                "minimum": 2,
            },
        },
    }
