"""Security Dashboard API.

Provides endpoints for aggregating security scan data from:
- Code analysis (crypto usage patterns)
- Dependency scanning (vulnerable libraries)
- Certificate monitoring (expiration tracking)

This dashboard complements the compliance dashboard by focusing on
proactive security scanning rather than operational compliance.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import (
    User,
    SecurityScan,
    SecurityFinding,
    CertificateInventory,
    ScanType,
    SeverityLevel,
)

router = APIRouter(prefix="/api/admin/security-dashboard", tags=["security-dashboard"])


# =============================================================================
# Response Models
# =============================================================================

class ScanSummary(BaseModel):
    """Summary of a security scan."""
    scan_id: str
    scan_type: str
    target_name: str
    scanned_at: datetime
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    quantum_vulnerable_count: int


class DashboardStats(BaseModel):
    """Overall security dashboard statistics."""
    # Scan counts
    total_scans_30d: int
    code_scans_30d: int
    dependency_scans_30d: int
    certificate_scans_30d: int

    # Finding counts
    total_findings_30d: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

    # Quantum risk
    quantum_vulnerable_total: int
    quantum_safe_total: int

    # Trends
    findings_trend: str  # "improving", "stable", "worsening"
    scan_frequency: str  # "daily", "weekly", "infrequent"

    # Certificates
    expiring_soon: int  # Within 30 days
    expired: int


class FindingSummary(BaseModel):
    """Summary of a security finding."""
    id: int
    severity: str
    title: str
    scan_type: str
    algorithm: str | None
    quantum_risk: str | None
    file_path: str | None
    recommendation: str | None
    scanned_at: datetime


class CertificateSummary(BaseModel):
    """Summary of a tracked certificate."""
    id: int
    common_name: str
    issuer_cn: str | None
    not_after: datetime
    days_until_expiry: int
    key_type: str
    key_size: int | None
    is_expired: bool
    is_weak_key: bool
    quantum_vulnerable: bool


class ScanTrendPoint(BaseModel):
    """Data point for scan trends."""
    date: str
    code_scans: int
    dependency_scans: int
    certificate_scans: int
    findings: int


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get overall security dashboard statistics.

    Returns aggregated metrics from all security scans including:
    - Scan counts by type
    - Finding counts by severity
    - Quantum vulnerability status
    - Certificate expiration status
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Count scans by type
    result = await db.execute(
        select(
            SecurityScan.scan_type,
            func.count(SecurityScan.id)
        ).where(
            SecurityScan.scanned_at >= thirty_days_ago
        ).group_by(SecurityScan.scan_type)
    )
    scan_counts = {r[0].value: r[1] for r in result.fetchall()}

    code_scans = scan_counts.get("code", 0)
    dependency_scans = scan_counts.get("dependency", 0)
    certificate_scans = scan_counts.get("certificate", 0)
    total_scans = code_scans + dependency_scans + certificate_scans

    # Count findings by severity
    result = await db.execute(
        select(
            SecurityFinding.severity,
            func.count(SecurityFinding.id)
        ).join(SecurityScan).where(
            SecurityScan.scanned_at >= thirty_days_ago
        ).group_by(SecurityFinding.severity)
    )
    severity_counts = {r[0].value: r[1] for r in result.fetchall()}

    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)
    total_findings = critical + high + medium + low

    # Quantum vulnerability counts
    result = await db.execute(
        select(
            func.sum(SecurityScan.quantum_vulnerable_count),
            func.sum(SecurityScan.quantum_safe_count)
        ).where(SecurityScan.scanned_at >= thirty_days_ago)
    )
    row = result.fetchone()
    quantum_vulnerable = row[0] or 0 if row else 0
    quantum_safe = row[1] or 0 if row else 0

    # Calculate trend (compare last 15 days to previous 15 days)
    fifteen_days_ago = datetime.now(timezone.utc) - timedelta(days=15)

    result = await db.execute(
        select(func.count(SecurityFinding.id)).join(SecurityScan).where(
            SecurityScan.scanned_at >= fifteen_days_ago
        )
    )
    recent_findings = result.scalar() or 0

    result = await db.execute(
        select(func.count(SecurityFinding.id)).join(SecurityScan).where(
            and_(
                SecurityScan.scanned_at >= thirty_days_ago,
                SecurityScan.scanned_at < fifteen_days_ago,
            )
        )
    )
    older_findings = result.scalar() or 0

    if recent_findings < older_findings * 0.8:
        findings_trend = "improving"
    elif recent_findings > older_findings * 1.2:
        findings_trend = "worsening"
    else:
        findings_trend = "stable"

    # Scan frequency
    if total_scans >= 25:
        scan_frequency = "daily"
    elif total_scans >= 4:
        scan_frequency = "weekly"
    else:
        scan_frequency = "infrequent"

    # Certificate status
    now = datetime.now(timezone.utc)
    thirty_days_future = now + timedelta(days=30)

    result = await db.execute(
        select(func.count(CertificateInventory.id)).where(
            and_(
                CertificateInventory.not_after > now,
                CertificateInventory.not_after <= thirty_days_future,
            )
        )
    )
    expiring_soon = result.scalar() or 0

    result = await db.execute(
        select(func.count(CertificateInventory.id)).where(
            CertificateInventory.not_after <= now
        )
    )
    expired = result.scalar() or 0

    return DashboardStats(
        total_scans_30d=total_scans,
        code_scans_30d=code_scans,
        dependency_scans_30d=dependency_scans,
        certificate_scans_30d=certificate_scans,
        total_findings_30d=total_findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        quantum_vulnerable_total=quantum_vulnerable,
        quantum_safe_total=quantum_safe,
        findings_trend=findings_trend,
        scan_frequency=scan_frequency,
        expiring_soon=expiring_soon,
        expired=expired,
    )


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    scan_type: ScanType | None = None,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=100),
):
    """List recent security scans.

    Returns a list of security scans with summary information.
    Optionally filter by scan type (code, dependency, certificate).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = select(SecurityScan).where(
        SecurityScan.scanned_at >= cutoff
    )

    if scan_type:
        query = query.where(SecurityScan.scan_type == scan_type)

    query = query.order_by(desc(SecurityScan.scanned_at)).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()

    return [
        ScanSummary(
            scan_id=scan.scan_id,
            scan_type=scan.scan_type.value,
            target_name=scan.target_name,
            scanned_at=scan.scanned_at,
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            quantum_vulnerable_count=scan.quantum_vulnerable_count,
        )
        for scan in scans
    ]


@router.get("/findings", response_model=list[FindingSummary])
async def list_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    severity: SeverityLevel | None = None,
    scan_type: ScanType | None = None,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=200),
):
    """List security findings.

    Returns a list of individual security findings.
    Optionally filter by severity or scan type.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = (
        select(SecurityFinding, SecurityScan)
        .join(SecurityScan)
        .where(SecurityScan.scanned_at >= cutoff)
    )

    if severity:
        query = query.where(SecurityFinding.severity == severity)

    if scan_type:
        query = query.where(SecurityScan.scan_type == scan_type)

    query = query.order_by(
        desc(SecurityFinding.severity),
        desc(SecurityScan.scanned_at)
    ).limit(limit)

    result = await db.execute(query)
    rows = result.fetchall()

    return [
        FindingSummary(
            id=finding.id,
            severity=finding.severity.value,
            title=finding.title,
            scan_type=scan.scan_type.value,
            algorithm=finding.algorithm,
            quantum_risk=finding.quantum_risk,
            file_path=finding.file_path,
            recommendation=finding.recommendation,
            scanned_at=scan.scanned_at,
        )
        for finding, scan in rows
    ]


@router.get("/certificates", response_model=list[CertificateSummary])
async def list_certificates(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    expiring_only: bool = False,
    include_expired: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
):
    """List tracked certificates.

    Returns certificates in the inventory with expiration status.
    Use expiring_only=true to show only certificates expiring within 30 days.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    now = datetime.now(timezone.utc)
    thirty_days_future = now + timedelta(days=30)

    query = select(CertificateInventory)

    if expiring_only:
        query = query.where(
            and_(
                CertificateInventory.not_after > now,
                CertificateInventory.not_after <= thirty_days_future,
            )
        )
    elif not include_expired:
        query = query.where(CertificateInventory.not_after > now)

    query = query.order_by(CertificateInventory.not_after).limit(limit)

    result = await db.execute(query)
    certs = result.scalars().all()

    return [
        CertificateSummary(
            id=cert.id,
            common_name=cert.common_name,
            issuer_cn=cert.issuer_cn,
            not_after=cert.not_after,
            days_until_expiry=cert.days_until_expiry,
            key_type=cert.key_type,
            key_size=cert.key_size,
            is_expired=cert.is_expired,
            is_weak_key=cert.is_weak_key,
            quantum_vulnerable=cert.quantum_vulnerable,
        )
        for cert in certs
    ]


@router.get("/trends", response_model=list[ScanTrendPoint])
async def get_scan_trends(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=7, le=90),
):
    """Get scan and finding trends over time.

    Returns daily counts of scans and findings for trend visualization.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Get scans by date and type
    result = await db.execute(
        select(
            func.date(SecurityScan.scanned_at).label("date"),
            SecurityScan.scan_type,
            func.count(SecurityScan.id).label("count")
        ).where(
            SecurityScan.scanned_at >= cutoff
        ).group_by(
            func.date(SecurityScan.scanned_at),
            SecurityScan.scan_type
        ).order_by(func.date(SecurityScan.scanned_at))
    )

    scan_data: dict[str, dict[str, int]] = {}
    for row in result.fetchall():
        date_str = str(row[0])
        scan_type = row[1].value if row[1] else "unknown"
        count = row[2]

        if date_str not in scan_data:
            scan_data[date_str] = {"code": 0, "dependency": 0, "certificate": 0, "findings": 0}

        if scan_type in scan_data[date_str]:
            scan_data[date_str][scan_type] = count

    # Get findings by date
    result = await db.execute(
        select(
            func.date(SecurityScan.scanned_at).label("date"),
            func.count(SecurityFinding.id).label("count")
        ).join(SecurityScan).where(
            SecurityScan.scanned_at >= cutoff
        ).group_by(
            func.date(SecurityScan.scanned_at)
        ).order_by(func.date(SecurityScan.scanned_at))
    )

    for row in result.fetchall():
        date_str = str(row[0])
        if date_str in scan_data:
            scan_data[date_str]["findings"] = row[1]

    # Convert to list and fill missing dates
    trends = []
    current = cutoff.date()
    end = datetime.now(timezone.utc).date()

    while current <= end:
        date_str = str(current)
        data = scan_data.get(date_str, {"code": 0, "dependency": 0, "certificate": 0, "findings": 0})
        trends.append(ScanTrendPoint(
            date=date_str,
            code_scans=data["code"],
            dependency_scans=data["dependency"],
            certificate_scans=data["certificate"],
            findings=data["findings"],
        ))
        current += timedelta(days=1)

    return trends
