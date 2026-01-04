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
from app.models import User
from app.auth.jwt import get_current_user
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


router = APIRouter(prefix="/api/v1/ct", tags=["certificate-transparency"])


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
    user: Annotated[User, Depends(get_current_user)] = None,
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
    """
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
    user: Annotated[User, Depends(get_current_user)],
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
    user: Annotated[User, Depends(get_current_user)] = None,
):
    """Get recently issued certificates for a domain.

    Finds certificates issued within the last N days.
    Useful for detecting new or unexpected issuances.
    """
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
    user: Annotated[User, Depends(get_current_user)] = None,
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
    user: Annotated[User, Depends(get_current_user)] = None,
):
    """Get all CAs that have issued certificates for a domain.

    Returns a breakdown of certificate authorities that have
    issued certificates for your domain. Useful for auditing
    your CA relationships and detecting unauthorized issuers.
    """
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
    user: Annotated[User, Depends(get_current_user)] = None,
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
