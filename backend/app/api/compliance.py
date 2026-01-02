"""Compliance Reporting API.

Provides endpoints for compliance status, framework adherence,
and regulatory reporting for enterprise audits.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, AuditLog, Context, Key, PQCKey, Tenant
from app.core.fips import get_fips_status, FIPSMode
from app.core.key_ceremony import key_ceremony_service, CeremonyState
from app.config import get_settings

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


# =============================================================================
# Response Models
# =============================================================================

class FrameworkStatus(BaseModel):
    """Status for a specific compliance framework."""
    framework: str
    enabled: bool
    contexts_count: int
    compliant: bool
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AlgorithmCompliance(BaseModel):
    """Algorithm compliance status."""
    fips_mode: str
    fips_compliant: bool
    quantum_safe_available: bool
    quantum_safe_contexts: int
    deprecated_algorithms_in_use: list[str] = Field(default_factory=list)
    approved_algorithms: list[str]


class KeyManagementStatus(BaseModel):
    """Key management compliance status."""
    kms_backend: str
    hsm_backed: bool
    key_ceremony_enabled: bool
    ceremony_state: str | None
    total_keys: int
    pqc_keys: int
    keys_needing_rotation: int


class AuditStatus(BaseModel):
    """Audit logging status."""
    enabled: bool
    total_events_30d: int
    operations_by_type: dict[str, int]
    policy_violations_30d: int
    failed_operations_30d: int


class TenantCompliance(BaseModel):
    """Per-tenant compliance summary."""
    tenant_id: str
    tenant_name: str
    contexts: int
    keys: int
    frameworks: list[str]
    compliant: bool


class ComplianceReport(BaseModel):
    """Full compliance status report."""
    generated_at: datetime
    overall_status: str  # "compliant", "warnings", "non_compliant"
    overall_score: int  # 0-100

    # Framework compliance
    frameworks: list[FrameworkStatus]

    # Technical compliance
    algorithms: AlgorithmCompliance
    key_management: KeyManagementStatus
    audit: AuditStatus

    # Multi-tenant
    tenants: list[TenantCompliance]

    # Summary
    critical_issues: list[str]
    warnings: list[str]
    recommendations: list[str]


class ComplianceExport(BaseModel):
    """Exportable compliance report for auditors."""
    report: ComplianceReport
    export_format: str
    generated_by: str
    signature: str | None = None


# =============================================================================
# Helper Functions
# =============================================================================

async def get_framework_status(
    db: AsyncSession,
    framework: str,
    tenant_id: str | None = None,
) -> FrameworkStatus:
    """Get compliance status for a specific framework."""

    # Count contexts using this framework
    query = select(func.count(Context.id)).where(
        Context.compliance_tags.contains([framework])
    )
    if tenant_id:
        query = query.where(Context.tenant_id == tenant_id)

    result = await db.execute(query)
    context_count = result.scalar() or 0

    issues = []
    recommendations = []
    compliant = True

    # Framework-specific checks
    if framework == "HIPAA":
        # Check for PHI contexts with proper encryption
        if context_count == 0:
            issues.append("No HIPAA-tagged contexts configured")
            compliant = False
        recommendations.append("Ensure all PHI data uses health-data context")

    elif framework == "PCI-DSS":
        # Check for payment data contexts
        if context_count == 0:
            issues.append("No PCI-DSS-tagged contexts configured")
            compliant = False
        recommendations.append("Ensure all cardholder data uses payment-data context")

    elif framework == "GDPR":
        # Check for PII contexts
        if context_count == 0:
            issues.append("No GDPR-tagged contexts configured")
            compliant = False
        recommendations.append("Ensure data subject rights can be exercised (deletion, export)")

    elif framework == "SOC2":
        # Check audit logging
        settings = get_settings()
        if not settings.database_url:
            issues.append("Database not configured for audit persistence")
            compliant = False

    return FrameworkStatus(
        framework=framework,
        enabled=context_count > 0,
        contexts_count=context_count,
        compliant=compliant,
        issues=issues,
        recommendations=recommendations,
    )


async def get_algorithm_compliance(db: AsyncSession) -> AlgorithmCompliance:
    """Get algorithm compliance status."""
    from app.core.fips import get_fips_approved_algorithms

    fips_status = get_fips_status()

    # Count quantum-safe contexts
    result = await db.execute(
        select(func.count(Context.id)).where(
            Context.algorithm.ilike("%ML-KEM%") |
            Context.algorithm.ilike("%Kyber%") |
            Context.algorithm.ilike("%Dilithium%")
        )
    )
    quantum_safe_count = result.scalar() or 0

    # Check for deprecated algorithms in recent audit logs
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    result = await db.execute(
        select(AuditLog.algorithm).where(
            and_(
                AuditLog.timestamp >= thirty_days_ago,
                AuditLog.algorithm.isnot(None),
            )
        ).distinct()
    )
    used_algorithms = [r[0] for r in result.fetchall() if r[0]]

    # Check for deprecated
    deprecated = []
    deprecated_patterns = ["DES", "3DES", "RC4", "MD5", "SHA1"]
    for alg in used_algorithms:
        for dep in deprecated_patterns:
            if dep.lower() in alg.lower():
                deprecated.append(alg)
                break

    return AlgorithmCompliance(
        fips_mode=fips_status.mode.value,
        fips_compliant=fips_status.compliant,
        quantum_safe_available=True,  # liboqs is installed
        quantum_safe_contexts=quantum_safe_count,
        deprecated_algorithms_in_use=deprecated,
        approved_algorithms=get_fips_approved_algorithms(),
    )


async def get_key_management_status(db: AsyncSession) -> KeyManagementStatus:
    """Get key management compliance status."""
    import os

    settings = get_settings()

    # Count keys
    result = await db.execute(select(func.count(Key.id)))
    total_keys = result.scalar() or 0

    result = await db.execute(select(func.count(PQCKey.id)))
    pqc_keys = result.scalar() or 0

    # Check for keys needing rotation (older than 90 days)
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    result = await db.execute(
        select(func.count(Key.id)).where(Key.created_at < ninety_days_ago)
    )
    needs_rotation = result.scalar() or 0

    # KMS backend
    kms_backend = os.environ.get("KMS_BACKEND", "local")

    # Ceremony status
    ceremony_state = None
    if settings.key_ceremony_enabled:
        ceremony_state = key_ceremony_service.state.value

    return KeyManagementStatus(
        kms_backend=kms_backend,
        hsm_backed=kms_backend in ("aws_kms", "gcp_kms", "azure_keyvault"),
        key_ceremony_enabled=settings.key_ceremony_enabled,
        ceremony_state=ceremony_state,
        total_keys=total_keys,
        pqc_keys=pqc_keys,
        keys_needing_rotation=needs_rotation,
    )


async def get_audit_status(db: AsyncSession) -> AuditStatus:
    """Get audit logging status."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Total events
    result = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= thirty_days_ago)
    )
    total_events = result.scalar() or 0

    # Operations by type
    result = await db.execute(
        select(AuditLog.operation, func.count(AuditLog.id)).where(
            AuditLog.timestamp >= thirty_days_ago
        ).group_by(AuditLog.operation)
    )
    ops_by_type = {r[0]: r[1] for r in result.fetchall()}

    # Policy violations
    result = await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= thirty_days_ago,
                AuditLog.policy_violation == True,
            )
        )
    )
    violations = result.scalar() or 0

    # Failed operations
    result = await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= thirty_days_ago,
                AuditLog.success == False,
            )
        )
    )
    failed = result.scalar() or 0

    return AuditStatus(
        enabled=True,
        total_events_30d=total_events,
        operations_by_type=ops_by_type,
        policy_violations_30d=violations,
        failed_operations_30d=failed,
    )


async def get_tenant_compliance(
    db: AsyncSession,
    tenant: Tenant,
) -> TenantCompliance:
    """Get compliance status for a specific tenant."""

    # Count contexts
    result = await db.execute(
        select(func.count(Context.id)).where(Context.tenant_id == tenant.id)
    )
    context_count = result.scalar() or 0

    # Count keys
    result = await db.execute(
        select(func.count(Key.id)).where(Key.tenant_id == tenant.id)
    )
    key_count = result.scalar() or 0

    # Get frameworks in use
    result = await db.execute(
        select(Context.compliance_tags).where(
            and_(
                Context.tenant_id == tenant.id,
                Context.compliance_tags.isnot(None),
            )
        )
    )
    all_tags = []
    for row in result.fetchall():
        if row[0]:
            all_tags.extend(row[0])
    frameworks = list(set(all_tags))

    return TenantCompliance(
        tenant_id=str(tenant.id),
        tenant_name=tenant.name,
        contexts=context_count,
        keys=key_count,
        frameworks=frameworks,
        compliant=True,  # Would need more detailed checks
    )


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/status", response_model=ComplianceReport)
async def get_compliance_status(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get comprehensive compliance status report.

    Returns compliance status across all frameworks, algorithms,
    key management, and audit logging.

    Requires admin access.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for compliance reports",
        )

    # Gather all compliance data
    frameworks = []
    for fw in ["GDPR", "HIPAA", "PCI-DSS", "SOC2", "NIST", "FedRAMP"]:
        fw_status = await get_framework_status(db, fw)
        frameworks.append(fw_status)

    algorithms = await get_algorithm_compliance(db)
    key_mgmt = await get_key_management_status(db)
    audit = await get_audit_status(db)

    # Get tenant compliance
    result = await db.execute(select(Tenant))
    tenants = result.scalars().all()
    tenant_compliance = []
    for tenant in tenants:
        tc = await get_tenant_compliance(db, tenant)
        tenant_compliance.append(tc)

    # Calculate overall status
    critical_issues = []
    warnings = []
    recommendations = []

    # Check FIPS compliance
    if algorithms.fips_mode == "enabled" and not algorithms.fips_compliant:
        critical_issues.append("FIPS mode enabled but system is not FIPS compliant")

    # Check for deprecated algorithms
    if algorithms.deprecated_algorithms_in_use:
        critical_issues.append(
            f"Deprecated algorithms in use: {', '.join(algorithms.deprecated_algorithms_in_use)}"
        )

    # Check key rotation
    if key_mgmt.keys_needing_rotation > 0:
        warnings.append(
            f"{key_mgmt.keys_needing_rotation} keys are older than 90 days and should be rotated"
        )

    # Check HSM backing
    if not key_mgmt.hsm_backed:
        warnings.append("Keys are not HSM-backed - consider using cloud KMS in production")

    # Check key ceremony
    if key_mgmt.key_ceremony_enabled:
        if key_mgmt.ceremony_state == "sealed":
            critical_issues.append("Key ceremony is sealed - service crypto operations are unavailable")
        elif key_mgmt.ceremony_state == "uninitialized":
            warnings.append("Key ceremony enabled but not initialized")

    # Check policy violations
    if audit.policy_violations_30d > 0:
        warnings.append(f"{audit.policy_violations_30d} policy violations in last 30 days")

    # Framework issues
    for fw in frameworks:
        critical_issues.extend(fw.issues)
        recommendations.extend(fw.recommendations)

    # Recommendations
    if algorithms.quantum_safe_contexts == 0:
        recommendations.append("Consider enabling quantum-safe algorithms for long-term secrets")

    if not key_mgmt.key_ceremony_enabled:
        recommendations.append("Consider enabling key ceremony for enterprise key protection")

    # Calculate score
    score = 100
    score -= len(critical_issues) * 20
    score -= len(warnings) * 5
    score = max(0, min(100, score))

    if critical_issues:
        overall_status = "non_compliant"
    elif warnings:
        overall_status = "warnings"
    else:
        overall_status = "compliant"

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc),
        overall_status=overall_status,
        overall_score=score,
        frameworks=frameworks,
        algorithms=algorithms,
        key_management=key_mgmt,
        audit=audit,
        tenants=tenant_compliance,
        critical_issues=critical_issues,
        warnings=warnings,
        recommendations=recommendations,
    )


@router.get("/frameworks/{framework}")
async def get_framework_compliance(
    framework: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get detailed compliance status for a specific framework.

    Supported frameworks: GDPR, HIPAA, PCI-DSS, SOC2, NIST, FedRAMP
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    valid_frameworks = ["GDPR", "HIPAA", "PCI-DSS", "SOC2", "NIST", "FedRAMP"]
    framework = framework.upper()

    if framework not in valid_frameworks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown framework. Valid options: {', '.join(valid_frameworks)}",
        )

    status_result = await get_framework_status(db, framework)

    # Get contexts for this framework
    result = await db.execute(
        select(Context).where(Context.compliance_tags.contains([framework]))
    )
    contexts = result.scalars().all()

    return {
        "framework": framework,
        "status": status_result,
        "contexts": [
            {
                "name": c.name,
                "algorithm": c.algorithm,
                "data_examples": c.data_examples,
            }
            for c in contexts
        ],
    }


@router.get("/algorithms")
async def get_algorithm_status(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get algorithm compliance status.

    Returns FIPS status, quantum-safe availability, and algorithm usage.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    algorithms = await get_algorithm_compliance(db)
    fips_status = get_fips_status()

    return {
        "algorithms": algorithms,
        "fips_details": {
            "mode": fips_status.mode.value,
            "openssl_version": fips_status.openssl_version,
            "openssl_fips_available": fips_status.openssl_fips_available,
            "compliant": fips_status.compliant,
            "message": fips_status.message,
        },
    }


@router.get("/export")
async def export_compliance_report(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    format: str = Query(default="json", description="Export format: json, csv"),
):
    """Export compliance report for auditors.

    Generates a timestamped compliance report suitable for
    external audit documentation.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    # Get full report
    report = await get_compliance_status(current_user, db)

    return ComplianceExport(
        report=report,
        export_format=format,
        generated_by=current_user.email or current_user.github_username or "admin",
        signature=None,  # Could add HMAC signature for integrity
    )


@router.get("/audit-summary")
async def get_audit_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
):
    """Get audit log summary for compliance reporting.

    Returns aggregated audit data for the specified time period.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Operations by day
    result = await db.execute(
        select(
            func.date(AuditLog.timestamp).label("date"),
            func.count(AuditLog.id).label("count"),
        ).where(
            AuditLog.timestamp >= cutoff
        ).group_by(
            func.date(AuditLog.timestamp)
        ).order_by(
            func.date(AuditLog.timestamp)
        )
    )
    daily_ops = [{"date": str(r[0]), "count": r[1]} for r in result.fetchall()]

    # Algorithm usage
    result = await db.execute(
        select(
            AuditLog.cipher,
            AuditLog.mode,
            AuditLog.key_bits,
            func.count(AuditLog.id).label("count"),
        ).where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.cipher.isnot(None),
            )
        ).group_by(
            AuditLog.cipher, AuditLog.mode, AuditLog.key_bits
        ).order_by(
            func.count(AuditLog.id).desc()
        )
    )
    algorithm_usage = [
        {
            "cipher": r[0],
            "mode": r[1],
            "key_bits": r[2],
            "count": r[3],
        }
        for r in result.fetchall()
    ]

    # Top contexts
    result = await db.execute(
        select(
            AuditLog.context,
            func.count(AuditLog.id).label("count"),
        ).where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.context.isnot(None),
            )
        ).group_by(
            AuditLog.context
        ).order_by(
            func.count(AuditLog.id).desc()
        ).limit(10)
    )
    top_contexts = [{"context": r[0], "count": r[1]} for r in result.fetchall()]

    return {
        "period_days": days,
        "cutoff_date": cutoff.isoformat(),
        "daily_operations": daily_ops,
        "algorithm_usage": algorithm_usage,
        "top_contexts": top_contexts,
    }
