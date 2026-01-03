"""Compliance Reporting API.

Provides endpoints for compliance status, framework adherence,
and regulatory reporting for enterprise audits.

Community Edition Features:
- Overall compliance status dashboard
- Single framework status view
- Basic data inventory (counts only)
- Simple risk score (aggregate only)
- JSON/CSV export

Premium Features (Enterprise License):
- Multi-framework compliance reports with detailed requirements
- Auditor-ready evidence packages with tamper-evident signing
- Per-context risk scoring with detailed breakdown
- Crypto-shredding for data retention compliance
- Real-time compliance alerting
- Historical trend analysis
- PDF report generation with executive summaries
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated
from enum import Enum

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
# Data Inventory Models (Community - Limited)
# =============================================================================

class DataClassification(str, Enum):
    """Data classification levels."""
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"


class DataInventoryItem(BaseModel):
    """Summary of a data type in the inventory (Community Edition)."""
    context_name: str
    data_classification: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    algorithm: str
    quantum_safe: bool = False
    operations_30d: int = 0


class DataInventorySummary(BaseModel):
    """Data inventory summary (Community Edition - limited details)."""
    total_contexts: int
    total_data_types: int
    pii_count: int
    phi_count: int
    pci_count: int
    quantum_safe_count: int
    items: list[DataInventoryItem]
    generated_at: datetime

    # Premium upsell
    premium_features_available: list[str] = Field(
        default_factory=lambda: [
            "Full data lineage tracking",
            "Detailed field-level inventory",
            "Data residency mapping",
            "Retention policy management",
            "Crypto-shredding automation",
        ]
    )


# =============================================================================
# Risk Score Models (Community - Aggregate Only)
# =============================================================================

class RiskLevel(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskScoreSummary(BaseModel):
    """Simplified risk score (Community Edition - aggregate only)."""
    overall_score: int = Field(ge=0, le=100, description="Overall risk 0-100 (lower is better)")
    risk_level: RiskLevel
    high_risk_contexts: int = Field(description="Number of contexts with high risk")
    key_findings: list[str] = Field(default_factory=list, description="Top 3 risk findings")
    assessed_at: datetime

    # Premium upsell
    premium_features_available: list[str] = Field(
        default_factory=lambda: [
            "Per-context risk breakdown",
            "Risk component analysis (algorithm, key age, access patterns)",
            "Historical risk trending",
            "Risk remediation recommendations",
            "Compliance impact scoring",
        ]
    )


# =============================================================================
# Premium Feature Indicators
# =============================================================================

class PremiumFeature(BaseModel):
    """A premium feature not available in Community Edition."""
    name: str
    description: str
    category: str


PREMIUM_FEATURES = [
    PremiumFeature(
        name="Evidence Packages",
        description="Generate auditor-ready evidence packages with tamper-evident signatures",
        category="audit",
    ),
    PremiumFeature(
        name="Crypto-Shredding",
        description="Securely destroy encryption keys to make data permanently unrecoverable",
        category="retention",
    ),
    PremiumFeature(
        name="Detailed Risk Scoring",
        description="Per-context risk analysis with component breakdown and recommendations",
        category="risk",
    ),
    PremiumFeature(
        name="Compliance Alerting",
        description="Real-time alerts for compliance violations and policy breaches",
        category="monitoring",
    ),
    PremiumFeature(
        name="PDF Reports",
        description="Executive-ready compliance reports with visualizations",
        category="reporting",
    ),
    PremiumFeature(
        name="Historical Trends",
        description="Track compliance posture over time with trending analysis",
        category="analytics",
    ),
]


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
    query = select(func.count(Context.name)).where(
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
        select(func.count(Context.name)).where(
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

    # Flatten the approved algorithms dict into a list
    approved_algs_dict = get_fips_approved_algorithms()
    approved_algs_list = []
    for category_algs in approved_algs_dict.values():
        if isinstance(category_algs, list):
            approved_algs_list.extend(category_algs)

    return AlgorithmCompliance(
        fips_mode=fips_status.mode.value,
        fips_compliant=fips_status.compliant,
        quantum_safe_available=True,  # liboqs is installed
        quantum_safe_contexts=quantum_safe_count,
        deprecated_algorithms_in_use=deprecated,
        approved_algorithms=approved_algs_list,
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
        select(func.count(Context.name)).where(Context.tenant_id == tenant.id)
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


# =============================================================================
# Data Inventory Endpoints (Community - Limited)
# =============================================================================

@router.get("/data-inventory", response_model=DataInventorySummary)
async def get_data_inventory(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get data inventory summary (Community Edition).

    Returns a summary of data types protected by CryptoServe,
    including classifications, frameworks, and algorithms.

    Note: Detailed field-level inventory, data lineage, and
    crypto-shredding features require Enterprise license.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for data inventory",
        )

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Get all contexts with their configurations
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    items = []
    pii_count = 0
    phi_count = 0
    pci_count = 0
    quantum_safe_count = 0

    for ctx in contexts:
        # Determine data classifications
        classifications = []
        if getattr(ctx, 'pii', False) or (ctx.data_examples and any('pii' in str(e).lower() for e in ctx.data_examples)):
            classifications.append("pii")
            pii_count += 1
        if getattr(ctx, 'phi', False) or (ctx.compliance_tags and 'HIPAA' in ctx.compliance_tags):
            classifications.append("phi")
            phi_count += 1
        if getattr(ctx, 'pci', False) or (ctx.compliance_tags and 'PCI-DSS' in ctx.compliance_tags):
            classifications.append("pci")
            pci_count += 1

        # Check quantum safety
        quantum_safe = False
        if ctx.algorithm:
            quantum_patterns = ['ML-KEM', 'Kyber', 'Dilithium', 'SPHINCS', 'hybrid']
            quantum_safe = any(p.lower() in ctx.algorithm.lower() for p in quantum_patterns)
            if quantum_safe:
                quantum_safe_count += 1

        # Get operation count for this context
        op_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.context == ctx.name,
                    AuditLog.timestamp >= thirty_days_ago,
                )
            )
        )
        ops_count = op_result.scalar() or 0

        items.append(DataInventoryItem(
            context_name=ctx.name,
            data_classification=classifications,
            frameworks=ctx.compliance_tags or [],
            algorithm=ctx.algorithm or "AES-256-GCM",
            quantum_safe=quantum_safe,
            operations_30d=ops_count,
        ))

    return DataInventorySummary(
        total_contexts=len(contexts),
        total_data_types=len(items),
        pii_count=pii_count,
        phi_count=phi_count,
        pci_count=pci_count,
        quantum_safe_count=quantum_safe_count,
        items=items,
        generated_at=datetime.now(timezone.utc),
    )


# =============================================================================
# Risk Score Endpoints (Community - Aggregate Only)
# =============================================================================

@router.get("/risk-score", response_model=RiskScoreSummary)
async def get_risk_score(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get aggregate risk score (Community Edition).

    Returns an overall risk assessment based on algorithm usage,
    key management practices, and compliance posture.

    Note: Per-context risk breakdown, component analysis, and
    remediation recommendations require Enterprise license.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for risk scoring",
        )

    score = 0  # Start at 0 (best), add points for risks
    findings = []
    high_risk_count = 0

    # Check key rotation status
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    result = await db.execute(
        select(func.count(Key.id)).where(Key.created_at < ninety_days_ago)
    )
    old_keys = result.scalar() or 0
    if old_keys > 0:
        score += min(20, old_keys * 2)
        findings.append(f"{old_keys} keys older than 90 days need rotation")

    # Check for deprecated algorithms
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

    deprecated_patterns = ["DES", "3DES", "RC4", "MD5", "SHA1"]
    deprecated_in_use = []
    for alg in used_algorithms:
        for dep in deprecated_patterns:
            if dep.lower() in alg.lower():
                deprecated_in_use.append(alg)
                break

    if deprecated_in_use:
        score += 30
        findings.append(f"Deprecated algorithms in use: {', '.join(deprecated_in_use[:3])}")

    # Check policy violations
    result = await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= thirty_days_ago,
                AuditLog.policy_violation == True,
            )
        )
    )
    violations = result.scalar() or 0
    if violations > 0:
        score += min(25, violations)
        findings.append(f"{violations} policy violations in last 30 days")

    # Check contexts without quantum-safe algorithms
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    non_quantum_sensitive = 0
    for ctx in contexts:
        # Check if context has sensitive data requiring long-term protection
        is_sensitive = (
            (ctx.compliance_tags and any(f in ctx.compliance_tags for f in ['HIPAA', 'PCI-DSS', 'GDPR'])) or
            getattr(ctx, 'pii', False) or
            getattr(ctx, 'phi', False)
        )
        # Check if not quantum-safe
        is_quantum_safe = ctx.algorithm and any(
            p.lower() in ctx.algorithm.lower()
            for p in ['ML-KEM', 'Kyber', 'hybrid']
        )

        if is_sensitive and not is_quantum_safe:
            non_quantum_sensitive += 1
            high_risk_count += 1

    if non_quantum_sensitive > 0:
        score += min(15, non_quantum_sensitive * 3)
        findings.append(f"{non_quantum_sensitive} sensitive contexts lack quantum-safe encryption")

    # Check HSM backing
    import os
    kms_backend = os.environ.get("KMS_BACKEND", "local")
    if kms_backend == "local":
        score += 10
        findings.append("Keys not backed by HSM - consider cloud KMS for production")

    # Cap score at 100
    score = min(100, score)

    # Determine risk level
    if score >= 50:
        risk_level = RiskLevel.CRITICAL
    elif score >= 30:
        risk_level = RiskLevel.HIGH
    elif score >= 15:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return RiskScoreSummary(
        overall_score=score,
        risk_level=risk_level,
        high_risk_contexts=high_risk_count,
        key_findings=findings[:3],  # Top 3 findings only in Community
        assessed_at=datetime.now(timezone.utc),
    )


# =============================================================================
# Premium Feature Discovery
# =============================================================================

@router.get("/premium-features")
async def get_premium_features(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Discover premium compliance features available with Enterprise license.

    Returns a list of advanced compliance features that provide:
    - Auditor-ready evidence packages
    - Crypto-shredding for data retention
    - Per-context risk analysis
    - Real-time compliance alerting
    - And more...
    """
    return {
        "edition": "community",
        "premium_features": PREMIUM_FEATURES,
        "upgrade_info": {
            "contact": "sales@cryptoserve.io",
            "documentation": "https://docs.cryptoserve.io/enterprise",
            "features_comparison": "https://cryptoserve.io/pricing",
        },
    }


@router.post("/evidence-package")
async def create_evidence_package(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Generate an auditor-ready evidence package.

    ⚠️ PREMIUM FEATURE - Requires Enterprise License

    Evidence packages include:
    - Encryption key inventory with rotation history
    - Algorithm compliance documentation
    - Audit log excerpts with integrity verification
    - Policy configuration snapshots
    - Tamper-evident digital signature
    """
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": "premium_feature_required",
            "feature": "Evidence Packages",
            "message": "Generating auditor-ready evidence packages requires an Enterprise license.",
            "upgrade_url": "https://cryptoserve.io/enterprise",
            "contact": "sales@cryptoserve.io",
        },
    )


@router.post("/crypto-shred")
async def crypto_shred(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Perform crypto-shredding to destroy data irrecoverably.

    ⚠️ PREMIUM FEATURE - Requires Enterprise License

    Crypto-shredding permanently destroys encryption keys,
    making all associated data permanently unrecoverable.
    This is required for GDPR Article 17 (Right to Erasure)
    and other data retention compliance.
    """
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": "premium_feature_required",
            "feature": "Crypto-Shredding",
            "message": "Crypto-shredding for compliance requires an Enterprise license.",
            "upgrade_url": "https://cryptoserve.io/enterprise",
            "contact": "sales@cryptoserve.io",
        },
    )


@router.get("/risk-score/{context_name}")
async def get_context_risk_score(
    context_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get detailed risk score for a specific context.

    ⚠️ PREMIUM FEATURE - Requires Enterprise License

    Per-context risk scoring provides:
    - Component-level risk breakdown (algorithm, key age, access patterns)
    - Specific remediation recommendations
    - Compliance impact analysis
    - Historical risk trending
    """
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": "premium_feature_required",
            "feature": "Detailed Risk Scoring",
            "message": f"Per-context risk analysis for '{context_name}' requires an Enterprise license.",
            "alternative": "Use GET /api/compliance/risk-score for aggregate risk score (free)",
            "upgrade_url": "https://cryptoserve.io/enterprise",
        },
    )


@router.get("/alerts")
async def get_compliance_alerts(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get real-time compliance alerts.

    ⚠️ PREMIUM FEATURE - Requires Enterprise License

    Compliance alerting provides:
    - Real-time notifications for policy violations
    - Key rotation reminders
    - Algorithm deprecation warnings
    - Configurable alert policies with webhooks
    """
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": "premium_feature_required",
            "feature": "Compliance Alerting",
            "message": "Real-time compliance alerting requires an Enterprise license.",
            "upgrade_url": "https://cryptoserve.io/enterprise",
        },
    )


@router.get("/trends")
async def get_compliance_trends(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get historical compliance trends.

    ⚠️ PREMIUM FEATURE - Requires Enterprise License

    Historical trending provides:
    - Compliance score over time
    - Risk trajectory analysis
    - Key rotation compliance history
    - Algorithm migration progress
    """
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": "premium_feature_required",
            "feature": "Historical Trends",
            "message": "Historical compliance trending requires an Enterprise license.",
            "upgrade_url": "https://cryptoserve.io/enterprise",
        },
    )
