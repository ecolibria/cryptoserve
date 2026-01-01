"""User Dashboard API routes.

Provides crypto security metrics for the user dashboard:
- Quantum readiness overview
- Algorithm usage statistics
- Security posture summary
- Recent scan results
- Promotion readiness metrics
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, Identity, AuditLog, CryptoInventoryReport
from app.models.application import Application, ApplicationStatus
from app.database import get_db
from app.auth.jwt import get_dashboard_or_sdk_user
from app.core.promotion import (
    check_promotion_readiness,
    get_context_tier,
    TIER_REQUIREMENTS,
    ContextTier,
)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


# ============================================================================
# Response Models
# ============================================================================


class AlgorithmUsage(BaseModel):
    """Algorithm usage statistics."""
    algorithm: str
    count: int
    category: str  # symmetric, asymmetric, hash, kdf
    quantum_safe: bool


class SecurityPosture(BaseModel):
    """Security posture summary."""
    overall_score: float = Field(..., description="0-100 score")
    quantum_readiness: float = Field(..., description="0-100 score")
    deprecated_usage: int = Field(..., description="Count of deprecated algo usages")
    weak_algorithms: int = Field(..., description="Count of weak algo usages")
    recommendations: list[str]


class RecentActivity(BaseModel):
    """Recent crypto activity."""
    total_operations_24h: int
    successful_24h: int
    failed_24h: int
    most_used_context: str | None
    most_used_algorithm: str | None


class AppPromotionStatus(BaseModel):
    """Promotion status for a single application."""
    app_id: str
    app_name: str
    environment: str
    is_ready: bool
    ready_count: int
    total_count: int
    blocking_contexts: list[str]
    estimated_ready_at: datetime | None = None
    requires_approval: bool = False


class PromotionMetrics(BaseModel):
    """Overall promotion metrics for dashboard."""
    apps_ready_for_promotion: int = Field(..., description="Apps ready to promote to production")
    apps_blocking: int = Field(..., description="Apps with blocking contexts")
    total_dev_apps: int = Field(..., description="Total apps in development/staging")
    tier_distribution: dict[str, int] = Field(default_factory=dict, description="Context count by tier")
    app_statuses: list[AppPromotionStatus] = Field(default_factory=list, description="Per-app promotion status")


class DashboardMetrics(BaseModel):
    """Complete dashboard metrics response."""
    security_posture: SecurityPosture
    recent_activity: RecentActivity
    algorithm_distribution: list[AlgorithmUsage]
    quantum_vulnerable_count: int
    pqc_ready_count: int
    active_identities: int
    total_contexts: int
    last_scan_date: str | None
    warnings: list[str]
    promotion_metrics: PromotionMetrics | None = None


# Algorithm categorization
ALGORITHM_INFO = {
    # Symmetric - quantum safe
    "aes-256-gcm": {"category": "symmetric", "quantum_safe": True},
    "aes-128-gcm": {"category": "symmetric", "quantum_safe": True},
    "chacha20-poly1305": {"category": "symmetric", "quantum_safe": True},
    # Symmetric - weak/deprecated
    "des": {"category": "symmetric", "quantum_safe": False, "deprecated": True},
    "3des": {"category": "symmetric", "quantum_safe": False, "deprecated": True},
    "rc4": {"category": "symmetric", "quantum_safe": False, "deprecated": True},
    # Asymmetric - quantum vulnerable
    "rsa": {"category": "asymmetric", "quantum_safe": False},
    "rsa-2048": {"category": "asymmetric", "quantum_safe": False},
    "rsa-4096": {"category": "asymmetric", "quantum_safe": False},
    "ecdsa": {"category": "asymmetric", "quantum_safe": False},
    "ecdh": {"category": "asymmetric", "quantum_safe": False},
    "ed25519": {"category": "asymmetric", "quantum_safe": False},
    "x25519": {"category": "asymmetric", "quantum_safe": False},
    # Asymmetric - PQC (quantum safe)
    "kyber": {"category": "asymmetric", "quantum_safe": True},
    "ml-kem": {"category": "asymmetric", "quantum_safe": True},
    "dilithium": {"category": "asymmetric", "quantum_safe": True},
    "ml-dsa": {"category": "asymmetric", "quantum_safe": True},
    "sphincs": {"category": "asymmetric", "quantum_safe": True},
    "slh-dsa": {"category": "asymmetric", "quantum_safe": True},
    # Hash - quantum safe
    "sha256": {"category": "hash", "quantum_safe": True},
    "sha384": {"category": "hash", "quantum_safe": True},
    "sha512": {"category": "hash", "quantum_safe": True},
    "sha3": {"category": "hash", "quantum_safe": True},
    "blake2": {"category": "hash", "quantum_safe": True},
    "blake3": {"category": "hash", "quantum_safe": True},
    # Hash - weak/deprecated
    "md5": {"category": "hash", "quantum_safe": False, "deprecated": True},
    "sha1": {"category": "hash", "quantum_safe": False, "deprecated": True},
    # KDFs - quantum safe
    "argon2": {"category": "kdf", "quantum_safe": True},
    "bcrypt": {"category": "kdf", "quantum_safe": True},
    "scrypt": {"category": "kdf", "quantum_safe": True},
    "pbkdf2": {"category": "kdf", "quantum_safe": True},
}

DEPRECATED_ALGORITHMS = {"des", "3des", "rc4", "md5", "sha1"}
WEAK_ALGORITHMS = DEPRECATED_ALGORITHMS | {"rsa-1024"}
QUANTUM_VULNERABLE = {"rsa", "rsa-2048", "rsa-4096", "ecdsa", "ecdh", "ed25519", "x25519", "dsa"}


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get comprehensive dashboard metrics for the current user.

    Returns security posture, recent activity, and algorithm usage statistics.
    """
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)

    # Get user's identities
    identity_result = await db.execute(
        select(Identity).where(Identity.user_id == user.id)
    )
    identities = list(identity_result.scalars().all())
    identity_ids = [i.id for i in identities]
    active_identities = len([i for i in identities if i.status == "active"])

    # Get all contexts from identities
    all_contexts = set()
    for identity in identities:
        all_contexts.update(identity.allowed_contexts or [])

    # Get recent activity (last 24h)
    if identity_ids:
        audit_result = await db.execute(
            select(AuditLog).where(
                AuditLog.identity_id.in_(identity_ids),
                AuditLog.timestamp >= day_ago,
            )
        )
        recent_logs = list(audit_result.scalars().all())
    else:
        recent_logs = []

    total_ops_24h = len(recent_logs)
    successful_24h = len([l for l in recent_logs if l.status == "success"])
    failed_24h = total_ops_24h - successful_24h

    # Most used context and algorithm
    context_counts: dict[str, int] = {}
    algo_counts: dict[str, int] = {}

    for log in recent_logs:
        if log.context:
            context_counts[log.context] = context_counts.get(log.context, 0) + 1
        if log.algorithm:
            algo = log.algorithm.lower()
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

    most_used_context = max(context_counts.keys(), key=lambda k: context_counts[k]) if context_counts else None
    most_used_algorithm = max(algo_counts.keys(), key=lambda k: algo_counts[k]) if algo_counts else None

    # Algorithm distribution
    algorithm_distribution = []
    quantum_vulnerable_count = 0
    pqc_ready_count = 0
    deprecated_count = 0
    weak_count = 0

    for algo, count in algo_counts.items():
        info = ALGORITHM_INFO.get(algo, {"category": "unknown", "quantum_safe": False})
        algorithm_distribution.append(AlgorithmUsage(
            algorithm=algo,
            count=count,
            category=info["category"],
            quantum_safe=info["quantum_safe"],
        ))

        if algo in QUANTUM_VULNERABLE:
            quantum_vulnerable_count += count
        if info["quantum_safe"] and info["category"] == "asymmetric":
            pqc_ready_count += count
        if algo in DEPRECATED_ALGORITHMS:
            deprecated_count += count
        if algo in WEAK_ALGORITHMS:
            weak_count += count

    # Sort by count descending
    algorithm_distribution.sort(key=lambda x: x.count, reverse=True)

    # Get last scan date from inventory reports
    last_scan_date = None
    if identity_ids:
        report_result = await db.execute(
            select(CryptoInventoryReport.created_at)
            .where(CryptoInventoryReport.identity_id.in_(identity_ids))
            .order_by(CryptoInventoryReport.created_at.desc())
            .limit(1)
        )
        row = report_result.first()
        if row:
            last_scan_date = row[0].isoformat()

    # Calculate scores
    total_asymmetric = quantum_vulnerable_count + pqc_ready_count
    if total_asymmetric > 0:
        quantum_readiness = (pqc_ready_count / total_asymmetric) * 100
    else:
        quantum_readiness = 100.0  # No asymmetric = no quantum risk

    # Overall score (weighted)
    # - 40% quantum readiness
    # - 30% no deprecated algorithms
    # - 30% no weak algorithms
    deprecated_penalty = min(deprecated_count * 5, 30)  # Max 30 points off
    weak_penalty = min(weak_count * 10, 30)  # Max 30 points off
    overall_score = max(0, (quantum_readiness * 0.4) + (30 - deprecated_penalty) + (30 - weak_penalty))

    # Generate recommendations
    recommendations = []
    if quantum_vulnerable_count > 0:
        recommendations.append(f"Migrate {quantum_vulnerable_count} quantum-vulnerable operations to PQC algorithms")
    if deprecated_count > 0:
        recommendations.append(f"Replace {deprecated_count} deprecated algorithm usages (MD5, SHA1, DES)")
    if weak_count > 0 and deprecated_count == 0:
        recommendations.append(f"Upgrade {weak_count} weak algorithm usages to stronger alternatives")
    if not recommendations:
        recommendations.append("Crypto posture is healthy - continue monitoring")

    # Generate warnings
    warnings = []
    if deprecated_count > 0:
        warnings.append(f"{deprecated_count} operations using deprecated algorithms")
    if quantum_vulnerable_count > pqc_ready_count and total_asymmetric > 0:
        warnings.append("Majority of asymmetric operations are quantum-vulnerable")
    if failed_24h > successful_24h and total_ops_24h > 10:
        warnings.append("High failure rate in last 24 hours")

    # Calculate promotion metrics
    promotion_metrics = None
    try:
        # Get applications from the Application model (not Identity alias)
        app_result = await db.execute(
            select(Application)
            .where(Application.user_id == user.id)
            .where(Application.status == ApplicationStatus.ACTIVE.value)
        )
        apps = list(app_result.scalars().all())

        # Filter non-production apps
        dev_apps = [a for a in apps if a.environment.lower() != "production"]

        if dev_apps:
            app_statuses = []
            apps_ready = 0
            apps_blocking = 0
            tier_distribution: dict[str, int] = {
                "tier_1": 0,
                "tier_2": 0,
                "tier_3": 0,
            }

            for app in dev_apps:
                # Check promotion readiness
                readiness = await check_promotion_readiness(db, app, "production")

                # Update tier distribution
                for ctx in app.allowed_contexts or []:
                    tier = get_context_tier(ctx)
                    tier_distribution[tier.value] = tier_distribution.get(tier.value, 0) + 1

                if readiness.is_ready:
                    apps_ready += 1
                else:
                    apps_blocking += 1

                app_statuses.append(AppPromotionStatus(
                    app_id=app.id,
                    app_name=app.name,
                    environment=app.environment,
                    is_ready=readiness.is_ready,
                    ready_count=readiness.ready_count,
                    total_count=readiness.total_count,
                    blocking_contexts=readiness.blocking_contexts,
                    estimated_ready_at=readiness.estimated_ready_at,
                    requires_approval=readiness.requires_approval,
                ))

            promotion_metrics = PromotionMetrics(
                apps_ready_for_promotion=apps_ready,
                apps_blocking=apps_blocking,
                total_dev_apps=len(dev_apps),
                tier_distribution=tier_distribution,
                app_statuses=app_statuses,
            )
    except Exception:
        # Don't fail dashboard if promotion metrics fail
        pass

    return DashboardMetrics(
        security_posture=SecurityPosture(
            overall_score=round(overall_score, 1),
            quantum_readiness=round(quantum_readiness, 1),
            deprecated_usage=deprecated_count,
            weak_algorithms=weak_count,
            recommendations=recommendations,
        ),
        recent_activity=RecentActivity(
            total_operations_24h=total_ops_24h,
            successful_24h=successful_24h,
            failed_24h=failed_24h,
            most_used_context=most_used_context,
            most_used_algorithm=most_used_algorithm,
        ),
        algorithm_distribution=algorithm_distribution[:10],  # Top 10
        quantum_vulnerable_count=quantum_vulnerable_count,
        pqc_ready_count=pqc_ready_count,
        active_identities=active_identities,
        total_contexts=len(all_contexts),
        last_scan_date=last_scan_date,
        warnings=warnings,
        promotion_metrics=promotion_metrics,
    )
