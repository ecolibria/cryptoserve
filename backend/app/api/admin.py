"""Admin API routes for enterprise dashboard."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, desc, and_, or_, text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Identity, IdentityStatus, Context, AuditLog, Key, Policy, OrganizationSettings
from app.models.crypto_inventory import CryptoInventoryReport, CryptoLibraryUsage, EnforcementAction
from app.schemas.context import (
    ContextConfig,
    DataIdentity,
    RegulatoryMapping,
    ThreatModel,
    AccessPatterns,
    RetentionPolicy,
    Sensitivity,
    DataCategory,
    Adversary,
    AccessFrequency,
)
from app.core.algorithm_resolver import resolve_algorithm

router = APIRouter(prefix="/api/admin", tags=["admin"])


# --- Pydantic Schemas ---

class AdminDashboardStats(BaseModel):
    """Aggregate statistics for admin dashboard."""
    total_users: int
    new_users_today: int
    total_identities: int
    active_identities: int
    expiring_soon: int  # Within 7 days
    total_operations: int
    operations_today: int
    operations_yesterday: int
    successful_operations: int
    failed_operations: int
    avg_latency_ms: float
    total_data_bytes: int
    contexts_count: int


class UserSummary(BaseModel):
    """User summary for admin listing."""
    id: str
    github_username: str
    email: Optional[str]
    avatar_url: Optional[str]
    created_at: datetime
    last_login_at: Optional[datetime]
    is_admin: bool
    identity_count: int
    operation_count: int


class IdentitySummary(BaseModel):
    """Identity summary for admin listing."""
    id: str
    name: str
    team: str
    environment: str
    type: str
    status: str
    allowed_contexts: list[str]
    created_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime]
    user_id: str
    user_name: str
    operation_count: int


class ContextStats(BaseModel):
    """Context with usage statistics."""
    name: str
    display_name: str
    description: str
    algorithm: str
    compliance_tags: list[str]
    data_examples: list[str]
    created_at: datetime
    operation_count: int
    identity_count: int
    last_key_rotation: Optional[datetime]
    key_version: int


class TrendDataPoint(BaseModel):
    """Single data point for trend charts."""
    date: str
    encrypt_count: int
    decrypt_count: int
    success_count: int
    failed_count: int


class TeamUsage(BaseModel):
    """Team usage statistics."""
    team: str
    operation_count: int
    identity_count: int


class HealthStatus(BaseModel):
    """System health status."""
    database: str
    encryption_service: str
    expiring_identities: int
    failed_operations_last_hour: int
    avg_latency_last_hour: float


class RiskScoreResponse(BaseModel):
    """Crypto risk score response."""
    score: int  # 0-100, higher is better
    grade: str  # A, B, C, D, F
    trend: str  # improving, stable, declining
    factors: list[dict]  # Individual risk factors
    premium_required: bool  # True to see detailed breakdown


class QuantumReadinessResponse(BaseModel):
    """Quantum readiness assessment."""
    readiness_percent: int  # 0-100
    classical_contexts: int
    quantum_ready_contexts: int
    hybrid_contexts: int
    migration_status: str  # not_started, in_progress, complete
    estimated_completion: Optional[str]  # Date estimate
    premium_required: bool  # True for migration tools


class ComplianceFramework(BaseModel):
    """Compliance framework status."""
    name: str
    status: str  # compliant, partial, non_compliant, not_applicable
    coverage_percent: int
    issues: int
    last_audit: Optional[datetime]


class ComplianceStatusResponse(BaseModel):
    """Overall compliance status."""
    frameworks: list[ComplianceFramework]
    overall_score: int
    export_available: bool  # Always False for OSS (premium feature)
    premium_required: bool


# --- Auth Dependency ---

async def require_admin(
    user: Annotated[User, Depends(get_current_user)]
) -> User:
    """Verify user has admin privileges."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# --- Admin Dashboard ---

@router.get("/dashboard", response_model=AdminDashboardStats)
async def get_admin_dashboard(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get aggregate statistics for admin dashboard."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_from_now = now + timedelta(days=7)

    # User stats
    total_users = await db.scalar(select(func.count(User.id)))
    new_users_today = await db.scalar(
        select(func.count(User.id)).where(User.created_at >= today_start)
    )

    # Identity stats
    total_identities = await db.scalar(select(func.count(Identity.id)))
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now
            )
        )
    )
    expiring_soon = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now,
                Identity.expires_at <= week_from_now
            )
        )
    )

    # Operations stats
    total_operations = await db.scalar(select(func.count(AuditLog.id)))
    operations_today = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= today_start)
    )
    operations_yesterday = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= yesterday_start,
                AuditLog.timestamp < today_start
            )
        )
    )
    successful_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == True)
    )
    failed_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == False)
    )

    # Average latency
    avg_latency = await db.scalar(
        select(func.avg(AuditLog.latency_ms)).where(AuditLog.latency_ms.isnot(None))
    )

    # Total data processed
    total_input = await db.scalar(
        select(func.sum(AuditLog.input_size_bytes)).where(AuditLog.input_size_bytes.isnot(None))
    ) or 0
    total_output = await db.scalar(
        select(func.sum(AuditLog.output_size_bytes)).where(AuditLog.output_size_bytes.isnot(None))
    ) or 0

    # Context count
    contexts_count = await db.scalar(select(func.count(Context.name)))

    return AdminDashboardStats(
        total_users=total_users or 0,
        new_users_today=new_users_today or 0,
        total_identities=total_identities or 0,
        active_identities=active_identities or 0,
        expiring_soon=expiring_soon or 0,
        total_operations=total_operations or 0,
        operations_today=operations_today or 0,
        operations_yesterday=operations_yesterday or 0,
        successful_operations=successful_operations or 0,
        failed_operations=failed_operations or 0,
        avg_latency_ms=round(avg_latency or 0, 2),
        total_data_bytes=total_input + total_output,
        contexts_count=contexts_count or 0,
    )


# --- User Management ---

@router.get("/users", response_model=list[UserSummary])
async def list_all_users(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: Optional[str] = Query(None, description="Search by username or email"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all users with statistics."""
    query = select(User).order_by(desc(User.created_at))

    if search:
        query = query.where(
            or_(
                User.github_username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%")
            )
        )

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    users = result.scalars().all()

    summaries = []
    for user in users:
        # Count identities
        identity_count = await db.scalar(
            select(func.count(Identity.id)).where(Identity.user_id == user.id)
        )
        # Count operations
        identity_ids_result = await db.execute(
            select(Identity.id).where(Identity.user_id == user.id)
        )
        identity_ids = [r[0] for r in identity_ids_result.fetchall()]

        operation_count = 0
        if identity_ids:
            operation_count = await db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.identity_id.in_(identity_ids)
                )
            ) or 0

        summaries.append(UserSummary(
            id=user.id,
            github_username=user.github_username,
            email=user.email,
            avatar_url=user.avatar_url,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            is_admin=user.is_admin,
            identity_count=identity_count or 0,
            operation_count=operation_count,
        ))

    return summaries


@router.get("/users/{user_id}")
async def get_user_details(
    user_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get detailed user information."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Get user's identities
    identities_result = await db.execute(
        select(Identity).where(Identity.user_id == user_id).order_by(desc(Identity.created_at))
    )
    identities = identities_result.scalars().all()

    return {
        "user": {
            "id": user.id,
            "github_username": user.github_username,
            "email": user.email,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "is_admin": user.is_admin,
        },
        "identities": [
            {
                "id": i.id,
                "name": i.name,
                "team": i.team,
                "environment": i.environment,
                "type": i.type.value,
                "status": i.status.value,
                "allowed_contexts": i.allowed_contexts,
                "created_at": i.created_at.isoformat(),
                "expires_at": i.expires_at.isoformat(),
            }
            for i in identities
        ],
    }


# --- Identity Management ---

@router.get("/identities", response_model=list[IdentitySummary])
async def list_all_identities(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: Optional[str] = Query(None, description="Search by name, team, or ID"),
    status_filter: Optional[str] = Query(None, alias="status"),
    team: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all identities across all users."""
    query = select(Identity, User).join(User).order_by(desc(Identity.created_at))

    if search:
        query = query.where(
            or_(
                Identity.name.ilike(f"%{search}%"),
                Identity.team.ilike(f"%{search}%"),
                Identity.id.ilike(f"%{search}%")
            )
        )

    if status_filter:
        try:
            status_enum = IdentityStatus(status_filter)
            query = query.where(Identity.status == status_enum)
        except ValueError:
            pass

    if team:
        query = query.where(Identity.team == team)

    if environment:
        query = query.where(Identity.environment == environment)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    rows = result.fetchall()

    summaries = []
    for identity, user in rows:
        # Count operations for this identity
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.identity_id == identity.id)
        ) or 0

        summaries.append(IdentitySummary(
            id=identity.id,
            name=identity.name,
            team=identity.team,
            environment=identity.environment,
            type=identity.type.value,
            status=identity.status.value,
            allowed_contexts=identity.allowed_contexts,
            created_at=identity.created_at,
            expires_at=identity.expires_at,
            last_used_at=identity.last_used_at,
            user_id=user.id,
            user_name=user.github_username,
            operation_count=operation_count,
        ))

    return summaries


@router.delete("/identities/{identity_id}")
async def admin_revoke_identity(
    identity_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Admin revoke an identity."""
    result = await db.execute(select(Identity).where(Identity.id == identity_id))
    identity = result.scalar_one_or_none()

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity not found",
        )

    identity.status = IdentityStatus.REVOKED
    await db.commit()

    return {"message": f"Identity {identity_id} revoked"}


# --- Global Audit ---

@router.get("/audit/global")
async def get_global_audit_logs(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    identity_id: Optional[str] = Query(None),
    context: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    success: Optional[bool] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Get global audit logs with filtering."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if identity_id:
        query = query.where(AuditLog.identity_id == identity_id)
    if context:
        query = query.where(AuditLog.context == context)
    if operation:
        query = query.where(AuditLog.operation == operation)
    if success is not None:
        query = query.where(AuditLog.success == success)
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "operation": log.operation,
            "context": log.context,
            "success": log.success,
            "error_message": log.error_message,
            "identity_id": log.identity_id,
            "identity_name": log.identity_name,
            "team": log.team,
            "input_size_bytes": log.input_size_bytes,
            "output_size_bytes": log.output_size_bytes,
            "latency_ms": log.latency_ms,
            "ip_address": log.ip_address,
        }
        for log in logs
    ]


@router.get("/audit/export")
async def export_audit_logs(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("csv", regex="^(csv|json)$"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
):
    """Export audit logs as CSV or JSON."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)

    query = query.limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "operation", "context", "success", "error_message",
            "identity_id", "identity_name", "team", "input_size_bytes",
            "output_size_bytes", "latency_ms", "ip_address"
        ])
        for log in logs:
            writer.writerow([
                log.timestamp.isoformat(),
                log.operation,
                log.context,
                log.success,
                log.error_message or "",
                log.identity_id,
                log.identity_name or "",
                log.team or "",
                log.input_size_bytes or "",
                log.output_size_bytes or "",
                log.latency_ms or "",
                log.ip_address or "",
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
        )
    else:
        import json
        data = [
            {
                "timestamp": log.timestamp.isoformat(),
                "operation": log.operation,
                "context": log.context,
                "success": log.success,
                "error_message": log.error_message,
                "identity_id": log.identity_id,
                "identity_name": log.identity_name,
                "team": log.team,
                "input_size_bytes": log.input_size_bytes,
                "output_size_bytes": log.output_size_bytes,
                "latency_ms": log.latency_ms,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_logs.json"}
        )


# --- Context Management ---

@router.get("/contexts", response_model=list[ContextStats])
async def get_contexts_with_stats(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get all contexts with usage statistics."""
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    stats = []
    for ctx in contexts:
        # Count operations
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.context == ctx.name)
        ) or 0

        # Count identities that have access
        # Use JSON containment check for TEXT column storing JSON arrays
        identity_count = await db.scalar(
            select(func.count(Identity.id)).where(
                text("allowed_contexts::jsonb ? :context_name").bindparams(context_name=ctx.name)
            )
        ) or 0

        # Get latest key info
        key_result = await db.execute(
            select(Key).where(Key.context == ctx.name).order_by(desc(Key.version)).limit(1)
        )
        latest_key = key_result.scalar_one_or_none()

        stats.append(ContextStats(
            name=ctx.name,
            display_name=ctx.display_name,
            description=ctx.description,
            algorithm=ctx.algorithm,
            compliance_tags=ctx.compliance_tags or [],
            data_examples=ctx.data_examples or [],
            created_at=ctx.created_at,
            operation_count=operation_count,
            identity_count=identity_count,
            last_key_rotation=latest_key.created_at if latest_key else None,
            key_version=latest_key.version if latest_key else 0,
        ))

    return stats


class KeyRotationResponse(BaseModel):
    """Response from key rotation."""
    message: str
    context: str
    old_version: int
    new_version: int
    key_id: str
    rotated_at: datetime


@router.post("/contexts/{context_name}/rotate-key", response_model=KeyRotationResponse)
async def rotate_context_key(
    context_name: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger key rotation for a context.

    Creates a new key version for the specified context. The old key
    is marked as rotated but retained for decrypting existing data.

    Returns:
        Key rotation details including old and new version numbers.
    """
    # Verify context exists
    result = await db.execute(select(Context).where(Context.name == context_name))
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Context not found",
        )

    # Get current key version before rotation
    key_result = await db.execute(
        select(Key).where(Key.context == context_name).order_by(desc(Key.version)).limit(1)
    )
    current_key = key_result.scalar_one_or_none()
    old_version = current_key.version if current_key else 0

    # Rotate the key
    from app.core.key_manager import key_manager
    _, new_key_id = await key_manager.rotate_key(db, context_name)

    # Get the new key record for version info
    new_key_result = await db.execute(
        select(Key).where(Key.id == new_key_id)
    )
    new_key_record = new_key_result.scalar_one()

    return KeyRotationResponse(
        message=f"Key rotated for context {context_name}",
        context=context_name,
        old_version=old_version,
        new_version=new_key_record.version,
        key_id=new_key_id,
        rotated_at=new_key_record.created_at,
    )


# --- Key Usage Tracking ---

class KeyUsageStats(BaseModel):
    """Usage statistics for a key."""
    key_id: str
    context: str
    version: int
    status: str
    created_at: datetime
    encrypt_count: int
    decrypt_count: int
    total_operations: int
    total_bytes_processed: int
    last_used: Optional[datetime]


class ContextKeyHistory(BaseModel):
    """Key history for a context."""
    context: str
    active_key_version: int
    total_keys: int
    keys: list[KeyUsageStats]


@router.get("/keys/{context_name}/usage", response_model=ContextKeyHistory)
async def get_key_usage(
    context_name: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get key usage statistics for a context.

    Shows usage metrics for all key versions including:
    - Operation counts (encrypt/decrypt)
    - Total data processed
    - Last used timestamp
    """
    # Verify context exists
    result = await db.execute(select(Context).where(Context.name == context_name))
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Context not found",
        )

    # Get all keys for this context
    keys_result = await db.execute(
        select(Key).where(Key.context == context_name).order_by(desc(Key.version))
    )
    keys = keys_result.scalars().all()

    key_stats = []
    active_version = 0

    for key in keys:
        # Count operations by this key (using key_id from audit logs)
        # Note: Audit logs track identity, not key directly
        # For accurate per-key tracking, we'd need to store key_id in audit logs
        # For now, estimate based on time windows

        # Get operations for this context
        encrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.context == context_name,
                    AuditLog.operation == "encrypt"
                )
            )
        ) or 0

        decrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.context == context_name,
                    AuditLog.operation == "decrypt"
                )
            )
        ) or 0

        # Total bytes
        total_bytes = await db.scalar(
            select(func.sum(AuditLog.input_size_bytes)).where(
                and_(
                    AuditLog.context == context_name,
                    AuditLog.input_size_bytes.isnot(None)
                )
            )
        ) or 0

        # Last used
        last_used_result = await db.execute(
            select(AuditLog.timestamp).where(AuditLog.context == context_name)
            .order_by(desc(AuditLog.timestamp)).limit(1)
        )
        last_used = last_used_result.scalar_one_or_none()

        if key.status.value == "active":
            active_version = key.version

        key_stats.append(KeyUsageStats(
            key_id=key.id,
            context=key.context,
            version=key.version,
            status=key.status.value,
            created_at=key.created_at,
            encrypt_count=encrypt_count // max(len(keys), 1),  # Distribute across versions
            decrypt_count=decrypt_count // max(len(keys), 1),
            total_operations=(encrypt_count + decrypt_count) // max(len(keys), 1),
            total_bytes_processed=total_bytes // max(len(keys), 1),
            last_used=last_used,
        ))

    return ContextKeyHistory(
        context=context_name,
        active_key_version=active_version,
        total_keys=len(keys),
        keys=key_stats,
    )


# --- Cryptographic Bill of Materials (CBOM) ---

class AlgorithmInventory(BaseModel):
    """Algorithm usage in the system."""
    algorithm: str
    family: str
    mode: str
    key_bits: int
    context_count: int
    contexts: list[str]
    quantum_resistant: bool
    deprecated: bool
    standards: list[str]


class CBOMSummary(BaseModel):
    """Cryptographic Bill of Materials summary."""
    generated_at: datetime
    total_contexts: int
    total_algorithms: int
    quantum_ready_percent: int
    algorithms: list[AlgorithmInventory]
    by_family: dict[str, int]
    by_mode: dict[str, int]
    by_security_level: dict[str, int]
    recommendations: list[str]


@router.get("/cbom", response_model=CBOMSummary)
async def get_cryptographic_bill_of_materials(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Generate Cryptographic Bill of Materials (CBOM).

    Provides a complete inventory of cryptographic algorithms in use,
    including security classifications and migration recommendations.
    """
    from app.core.algorithm_resolver import ALGORITHMS

    # Get all contexts
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    # Analyze algorithms in use
    algo_usage: dict[str, list[str]] = {}  # algorithm -> context names
    for ctx in contexts:
        algo = ctx.algorithm
        if algo not in algo_usage:
            algo_usage[algo] = []
        algo_usage[algo].append(ctx.name)

    # Build algorithm inventory
    algorithms = []
    by_family: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    by_security: dict[str, int] = {"128-bit": 0, "192-bit": 0, "256-bit": 0, "512-bit": 0}

    deprecated_algos = {"DES", "3DES", "RC4", "MD5", "SHA-1", "RSA-1024", "RSA-2048"}
    pqc_algos = {"ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS"}

    quantum_ready = 0
    deprecated_count = 0

    for algo, ctx_list in algo_usage.items():
        # Get algorithm properties from registry
        props = ALGORITHMS.get(algo, {})

        family = props.get("family", "Unknown")
        mode = props.get("mode")
        mode_str = mode.value if hasattr(mode, "value") else str(mode) if mode else "unknown"
        key_bits = props.get("key_bits", 256)
        standards = props.get("standards", [])

        # Determine if quantum resistant
        is_quantum = props.get("quantum_resistant", False) or any(p in algo for p in pqc_algos)
        if is_quantum:
            quantum_ready += len(ctx_list)

        # Determine if deprecated
        is_deprecated = any(d in algo for d in deprecated_algos) or props.get("legacy", False)
        if is_deprecated:
            deprecated_count += len(ctx_list)

        algorithms.append(AlgorithmInventory(
            algorithm=algo,
            family=family,
            mode=mode_str,
            key_bits=key_bits,
            context_count=len(ctx_list),
            contexts=ctx_list,
            quantum_resistant=is_quantum,
            deprecated=is_deprecated,
            standards=standards,
        ))

        # Aggregate by family
        by_family[family] = by_family.get(family, 0) + len(ctx_list)

        # Aggregate by mode
        by_mode[mode_str] = by_mode.get(mode_str, 0) + len(ctx_list)

        # Aggregate by security level
        if key_bits <= 128:
            by_security["128-bit"] += len(ctx_list)
        elif key_bits <= 192:
            by_security["192-bit"] += len(ctx_list)
        elif key_bits <= 256:
            by_security["256-bit"] += len(ctx_list)
        else:
            by_security["512-bit"] += len(ctx_list)

    # Generate recommendations
    recommendations = []

    if deprecated_count > 0:
        recommendations.append(
            f"CRITICAL: {deprecated_count} context(s) use deprecated algorithms. Migrate immediately."
        )

    total = len(contexts)
    quantum_percent = int((quantum_ready / total * 100)) if total > 0 else 0

    if quantum_percent < 25:
        recommendations.append(
            "Consider migrating high-value contexts to post-quantum algorithms."
        )

    if by_mode.get("cbc", 0) > 0:
        recommendations.append(
            f"INFO: {by_mode.get('cbc', 0)} context(s) use CBC mode. Consider GCM for authenticated encryption."
        )

    if by_security.get("128-bit", 0) > 0 and any(
        ctx.config.get("data_identity", {}).get("sensitivity") in ["critical", "high"]
        for ctx in contexts
    ):
        recommendations.append(
            "Consider upgrading 128-bit keys to 256-bit for high-sensitivity data."
        )

    # Sort by context count
    algorithms.sort(key=lambda a: a.context_count, reverse=True)

    return CBOMSummary(
        generated_at=datetime.now(timezone.utc),
        total_contexts=total,
        total_algorithms=len(algo_usage),
        quantum_ready_percent=quantum_percent,
        algorithms=algorithms,
        by_family=by_family,
        by_mode=by_mode,
        by_security_level=by_security,
        recommendations=recommendations,
    )


# --- Analytics ---

@router.get("/analytics/trends", response_model=list[TrendDataPoint])
async def get_operation_trends(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365),
):
    """Get operation trends over time."""
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days)

    trends = []
    current_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    while current_date <= now:
        next_date = current_date + timedelta(days=1)

        # Get counts for this day
        encrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.operation == "encrypt"
                )
            )
        ) or 0

        decrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.operation == "decrypt"
                )
            )
        ) or 0

        success_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.success == True
                )
            )
        ) or 0

        failed_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.success == False
                )
            )
        ) or 0

        trends.append(TrendDataPoint(
            date=current_date.strftime("%Y-%m-%d"),
            encrypt_count=encrypt_count,
            decrypt_count=decrypt_count,
            success_count=success_count,
            failed_count=failed_count,
        ))

        current_date = next_date

    return trends


@router.get("/analytics/teams", response_model=list[TeamUsage])
async def get_team_usage(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50),
):
    """Get usage statistics by team."""
    # Get teams from identities
    teams_result = await db.execute(
        select(Identity.team, func.count(Identity.id).label("identity_count"))
        .group_by(Identity.team)
        .order_by(desc("identity_count"))
        .limit(limit)
    )
    teams = teams_result.fetchall()

    usage = []
    for team_name, identity_count in teams:
        # Get operation count for this team
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.team == team_name)
        ) or 0

        usage.append(TeamUsage(
            team=team_name,
            operation_count=operation_count,
            identity_count=identity_count,
        ))

    return usage


# --- Health ---

@router.get("/health", response_model=HealthStatus)
async def get_system_health(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get system health status."""
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    week_from_now = now + timedelta(days=7)

    # Check database
    try:
        await db.execute(select(func.count(User.id)))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    # Expiring identities
    expiring = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now,
                Identity.expires_at <= week_from_now
            )
        )
    ) or 0

    # Failed operations last hour
    failed_last_hour = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= hour_ago,
                AuditLog.success == False
            )
        )
    ) or 0

    # Average latency last hour
    avg_latency = await db.scalar(
        select(func.avg(AuditLog.latency_ms)).where(
            and_(
                AuditLog.timestamp >= hour_ago,
                AuditLog.latency_ms.isnot(None)
            )
        )
    ) or 0

    return HealthStatus(
        database=db_status,
        encryption_service="healthy",  # Could add actual check
        expiring_identities=expiring,
        failed_operations_last_hour=failed_last_hour,
        avg_latency_last_hour=round(avg_latency, 2),
    )


# --- Premium Feature Previews (OSS shows value, gates details) ---

@router.get("/risk-score", response_model=RiskScoreResponse)
async def get_risk_score(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get crypto risk score for the organization.

    OSS: Shows overall score and grade
    Premium: Shows detailed breakdown by factor
    """
    # Calculate risk factors based on actual data
    now = datetime.now(timezone.utc)

    # Factor 1: Algorithm strength (check for deprecated algorithms)
    contexts_result = await db.execute(select(Context))
    contexts = contexts_result.scalars().all()

    deprecated_algos = {"DES", "3DES", "RC4", "MD5", "SHA-1", "RSA-1024"}
    weak_count = sum(1 for c in contexts if any(d in c.algorithm for d in deprecated_algos))
    total_contexts = len(contexts)
    algo_score = max(0, 100 - (weak_count * 20)) if total_contexts > 0 else 100

    # Factor 2: Key rotation frequency
    thirty_days_ago = now - timedelta(days=30)
    recent_rotations = await db.scalar(
        select(func.count(Key.id)).where(Key.created_at >= thirty_days_ago)
    ) or 0
    rotation_score = min(100, recent_rotations * 25)  # 4 rotations = 100

    # Factor 3: Identity hygiene (expired/revoked cleanup)
    total_identities = await db.scalar(select(func.count(Identity.id))) or 0
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now
            )
        )
    ) or 0
    identity_score = (active_identities / total_identities * 100) if total_identities > 0 else 100

    # Factor 4: Operation success rate
    total_ops = await db.scalar(select(func.count(AuditLog.id))) or 0
    successful_ops = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == True)
    ) or 0
    success_rate = (successful_ops / total_ops * 100) if total_ops > 0 else 100

    # Factor 5: Quantum readiness (contexts using PQC)
    pqc_algos = {"ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS"}
    quantum_ready = sum(1 for c in contexts if any(p in c.algorithm for p in pqc_algos))
    quantum_score = (quantum_ready / total_contexts * 100) if total_contexts > 0 else 0

    # Calculate overall score (weighted average)
    overall_score = int(
        algo_score * 0.30 +
        rotation_score * 0.15 +
        identity_score * 0.20 +
        success_rate * 0.20 +
        quantum_score * 0.15
    )

    # Determine grade
    if overall_score >= 90:
        grade = "A"
    elif overall_score >= 80:
        grade = "B"
    elif overall_score >= 70:
        grade = "C"
    elif overall_score >= 60:
        grade = "D"
    else:
        grade = "F"

    # Determine trend (compare to 7 days ago - simplified)
    week_ago = now - timedelta(days=7)
    old_failed = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp < week_ago,
                AuditLog.success == False
            )
        )
    ) or 0
    recent_failed = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= week_ago,
                AuditLog.success == False
            )
        )
    ) or 0

    if recent_failed < old_failed:
        trend = "improving"
    elif recent_failed > old_failed:
        trend = "declining"
    else:
        trend = "stable"

    # Factors - OSS shows names only, premium shows details
    factors = [
        {"name": "Algorithm Strength", "category": "crypto"},
        {"name": "Key Rotation", "category": "keys"},
        {"name": "Identity Hygiene", "category": "access"},
        {"name": "Operation Success", "category": "ops"},
        {"name": "Quantum Readiness", "category": "quantum"},
    ]

    return RiskScoreResponse(
        score=overall_score,
        grade=grade,
        trend=trend,
        factors=factors,
        premium_required=True,  # Detailed scores require premium
    )


@router.get("/quantum-readiness", response_model=QuantumReadinessResponse)
async def get_quantum_readiness(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get quantum readiness assessment.

    OSS: Shows readiness percentage and counts
    Premium: Access to migration tools and detailed planning
    """
    # Get all contexts
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    # Categorize by quantum readiness
    pqc_algos = {"ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS", "BIKE", "HQC"}
    hybrid_algos = {"AES-256-GCM+ML-KEM", "ChaCha20-Poly1305+ML-KEM", "Hybrid"}

    classical_contexts = 0
    quantum_ready_contexts = 0
    hybrid_contexts = 0

    for ctx in contexts:
        algo = ctx.algorithm
        if any(h in algo for h in hybrid_algos):
            hybrid_contexts += 1
        elif any(p in algo for p in pqc_algos):
            quantum_ready_contexts += 1
        else:
            classical_contexts += 1

    total = len(contexts)

    # Calculate readiness percentage
    # Hybrid and quantum-ready both count as "ready"
    ready_count = quantum_ready_contexts + hybrid_contexts
    readiness_percent = int((ready_count / total * 100)) if total > 0 else 0

    # Determine migration status
    if readiness_percent == 0:
        migration_status = "not_started"
        estimated_completion = None
    elif readiness_percent >= 100:
        migration_status = "complete"
        estimated_completion = None
    else:
        migration_status = "in_progress"
        # Estimate completion based on remaining contexts
        remaining = classical_contexts
        estimated_completion = (datetime.now(timezone.utc) + timedelta(days=remaining * 30)).strftime("%Y-%m-%d")

    return QuantumReadinessResponse(
        readiness_percent=readiness_percent,
        classical_contexts=classical_contexts,
        quantum_ready_contexts=quantum_ready_contexts,
        hybrid_contexts=hybrid_contexts,
        migration_status=migration_status,
        estimated_completion=estimated_completion,
        premium_required=True,  # Migration tools require premium
    )


@router.get("/compliance-status", response_model=ComplianceStatusResponse)
async def get_compliance_status(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get compliance status across frameworks.

    OSS: Shows framework status and coverage
    Premium: Export compliance reports, detailed remediation
    """
    # Get all contexts with their compliance tags
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    # Analyze compliance by framework
    framework_requirements = {
        "SOC2": {"encryption": True, "audit_logging": True, "key_rotation": True, "access_control": True},
        "HIPAA": {"encryption": True, "audit_logging": True, "phi_protection": True},
        "PCI-DSS": {"encryption": True, "key_management": True, "strong_crypto": True},
        "GDPR": {"encryption": True, "data_minimization": True, "right_to_erasure": True},
    }

    # Check what we have
    has_encryption = len(contexts) > 0  # Any contexts means encryption is used
    has_audit = await db.scalar(select(func.count(AuditLog.id))) > 0
    has_key_rotation = await db.scalar(
        select(func.count(Key.id)).where(
            Key.created_at >= datetime.now(timezone.utc) - timedelta(days=90)
        )
    ) > 0

    # Check for specific context types
    context_tags = set()
    for ctx in contexts:
        context_tags.update(ctx.compliance_tags or [])

    frameworks = []

    # SOC2
    soc2_met = sum([has_encryption, has_audit, has_key_rotation, len(contexts) > 0])
    soc2_total = 4
    soc2_coverage = int(soc2_met / soc2_total * 100)
    frameworks.append(ComplianceFramework(
        name="SOC2",
        status="compliant" if soc2_coverage >= 80 else "partial" if soc2_coverage >= 50 else "non_compliant",
        coverage_percent=soc2_coverage,
        issues=soc2_total - soc2_met,
        last_audit=None,
    ))

    # HIPAA
    has_phi = "HIPAA" in context_tags or any("health" in (ctx.name or "").lower() for ctx in contexts)
    hipaa_met = sum([has_encryption, has_audit, has_phi])
    hipaa_total = 3
    hipaa_coverage = int(hipaa_met / hipaa_total * 100)
    frameworks.append(ComplianceFramework(
        name="HIPAA",
        status="compliant" if hipaa_coverage >= 80 else "partial" if hipaa_coverage >= 50 else "non_compliant",
        coverage_percent=hipaa_coverage,
        issues=hipaa_total - hipaa_met,
        last_audit=None,
    ))

    # PCI-DSS
    strong_crypto = all(
        "AES-256" in ctx.algorithm or "AES-128" in ctx.algorithm or "ChaCha20" in ctx.algorithm
        for ctx in contexts
    ) if contexts else False
    pci_met = sum([has_encryption, has_key_rotation, strong_crypto])
    pci_total = 3
    pci_coverage = int(pci_met / pci_total * 100)
    frameworks.append(ComplianceFramework(
        name="PCI-DSS",
        status="compliant" if pci_coverage >= 80 else "partial" if pci_coverage >= 50 else "non_compliant",
        coverage_percent=pci_coverage,
        issues=pci_total - pci_met,
        last_audit=None,
    ))

    # GDPR
    has_gdpr = "GDPR" in context_tags or any("pii" in (ctx.name or "").lower() for ctx in contexts)
    gdpr_met = sum([has_encryption, has_gdpr, has_audit])
    gdpr_total = 3
    gdpr_coverage = int(gdpr_met / gdpr_total * 100)
    frameworks.append(ComplianceFramework(
        name="GDPR",
        status="compliant" if gdpr_coverage >= 80 else "partial" if gdpr_coverage >= 50 else "non_compliant",
        coverage_percent=gdpr_coverage,
        issues=gdpr_total - gdpr_met,
        last_audit=None,
    ))

    # Calculate overall score
    overall_score = int(sum(f.coverage_percent for f in frameworks) / len(frameworks))

    return ComplianceStatusResponse(
        frameworks=frameworks,
        overall_score=overall_score,
        export_available=False,  # Always false for OSS
        premium_required=True,
    )


# --- Policy Wizard ---

class WizardPublishRequest(BaseModel):
    """Request to publish a policy from the wizard."""
    data_type: str  # pii, financial, health, auth, business, internal
    compliance: list[str]  # gdpr, ccpa, hipaa, pci-dss, sox, soc2, none
    threat_level: str  # standard, elevated, maximum
    access_pattern: str  # high-throughput, balanced, batch, rare
    policy_name: str  # Human-readable name
    context_name: str  # ID for developers


class WizardPublishResponse(BaseModel):
    """Response from wizard publish."""
    success: bool
    context_name: str
    policy_name: str
    algorithm: str
    message: str


# Data type to DataCategory mapping
DATA_TYPE_MAPPING = {
    "pii": DataCategory.PERSONAL_IDENTIFIER,
    "financial": DataCategory.FINANCIAL,
    "health": DataCategory.HEALTH,
    "auth": DataCategory.AUTHENTICATION,
    "business": DataCategory.BUSINESS_CONFIDENTIAL,
    "internal": DataCategory.GENERAL,
}

# Threat level to adversaries and protection years
THREAT_LEVEL_MAPPING = {
    "standard": {
        "adversaries": [Adversary.OPPORTUNISTIC],
        "protection_years": 5,
    },
    "elevated": {
        "adversaries": [Adversary.ORGANIZED_CRIME, Adversary.INSIDER],
        "protection_years": 10,
    },
    "maximum": {
        "adversaries": [Adversary.NATION_STATE, Adversary.QUANTUM],
        "protection_years": 30,
    },
}

# Access pattern to frequency and latency
ACCESS_PATTERN_MAPPING = {
    "high-throughput": {
        "frequency": AccessFrequency.HIGH,
        "latency_ms": 10,
        "ops_per_second": 10000,
    },
    "balanced": {
        "frequency": AccessFrequency.MEDIUM,
        "latency_ms": 50,
        "ops_per_second": 1000,
    },
    "batch": {
        "frequency": AccessFrequency.LOW,
        "latency_ms": 500,
        "ops_per_second": 100,
        "batch_operations": True,
    },
    "rare": {
        "frequency": AccessFrequency.RARE,
        "latency_ms": 1000,
        "ops_per_second": 10,
    },
}

# Compliance framework to retention requirements
COMPLIANCE_RETENTION = {
    "gdpr": {"maximum_days": 2555, "deletion_method": "crypto_shred"},
    "ccpa": {"maximum_days": 2555, "deletion_method": "crypto_shred"},
    "hipaa": {"minimum_days": 2555, "maximum_days": 3650},
    "pci-dss": {"minimum_days": 365, "maximum_days": 2555},
    "sox": {"minimum_days": 2555, "maximum_days": 3650},
    "soc2": {"minimum_days": 365, "maximum_days": 730},
}


def build_context_config_from_wizard(data: WizardPublishRequest) -> ContextConfig:
    """Build a full ContextConfig from wizard inputs."""
    # Data identity
    category = DATA_TYPE_MAPPING.get(data.data_type, DataCategory.GENERAL)
    sensitivity = Sensitivity.CRITICAL if data.data_type in ["pii", "financial", "health"] else (
        Sensitivity.HIGH if data.data_type in ["auth", "business"] else Sensitivity.MEDIUM
    )

    # Determine PII/PHI/PCI flags
    pii = data.data_type == "pii"
    phi = data.data_type == "health"
    pci = data.data_type == "financial"
    notification_required = pii or phi or pci

    data_identity = DataIdentity(
        category=category,
        sensitivity=sensitivity,
        pii=pii,
        phi=phi,
        pci=pci,
        notification_required=notification_required,
        examples=[],  # Could be populated based on data_type
    )

    # Regulatory mapping
    frameworks = [f.upper() for f in data.compliance if f != "none"]

    # Build retention from strictest compliance requirement
    retention_config = {}
    for framework in data.compliance:
        if framework in COMPLIANCE_RETENTION:
            reqs = COMPLIANCE_RETENTION[framework]
            if "minimum_days" in reqs:
                retention_config["minimum_days"] = max(
                    retention_config.get("minimum_days", 0),
                    reqs["minimum_days"]
                )
            if "maximum_days" in reqs:
                retention_config["maximum_days"] = min(
                    retention_config.get("maximum_days", 99999),
                    reqs["maximum_days"]
                )
            if "deletion_method" in reqs:
                retention_config["deletion_method"] = reqs["deletion_method"]

    retention = RetentionPolicy(**retention_config) if retention_config else None

    regulatory = RegulatoryMapping(
        frameworks=frameworks,
        retention=retention,
    )

    # Threat model
    threat_config = THREAT_LEVEL_MAPPING.get(data.threat_level, THREAT_LEVEL_MAPPING["standard"])
    threat_model = ThreatModel(
        adversaries=threat_config["adversaries"],
        protection_lifetime_years=threat_config["protection_years"],
    )

    # Access patterns
    access_config = ACCESS_PATTERN_MAPPING.get(data.access_pattern, ACCESS_PATTERN_MAPPING["balanced"])
    access_patterns = AccessPatterns(
        frequency=access_config["frequency"],
        latency_requirement_ms=access_config["latency_ms"],
        operations_per_second=access_config.get("ops_per_second"),
        batch_operations=access_config.get("batch_operations", False),
    )

    return ContextConfig(
        data_identity=data_identity,
        regulatory=regulatory,
        threat_model=threat_model,
        access_patterns=access_patterns,
    )


@router.post("/wizard/publish", response_model=WizardPublishResponse)
async def publish_wizard_policy(
    data: WizardPublishRequest,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Publish a policy from the admin wizard.

    This endpoint:
    1. Builds a full context configuration from wizard inputs
    2. Runs the algorithm resolver to determine optimal encryption
    3. Creates the context in the database
    4. Creates a linked policy
    5. Returns success with details

    Developers will immediately see the new context in their dashboard.
    """
    # Check if context already exists
    existing_context = await db.execute(
        select(Context).where(Context.name == data.context_name)
    )
    if existing_context.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Context '{data.context_name}' already exists",
        )

    # Build context config from wizard inputs
    config = build_context_config_from_wizard(data)

    # Run algorithm resolver
    derived = resolve_algorithm(config)

    # Get compliance tags
    compliance_tags = [f.upper() for f in data.compliance if f != "none"]

    # Create the context
    context = Context(
        name=data.context_name,
        display_name=data.policy_name,
        description=f"{data.policy_name} - Created via policy wizard",
        config=config.model_dump(),
        derived=derived.model_dump(),
        algorithm=derived.resolved_algorithm,
        data_examples=[],  # Could be populated based on data_type
        compliance_tags=compliance_tags,
    )
    db.add(context)

    # Create the policy
    policy_rule = f"context.name == \"{data.context_name}\""
    policy = Policy(
        name=f"{data.context_name}-policy",
        description=f"Auto-generated policy for {data.policy_name}",
        rule=policy_rule,
        severity="block",
        message=f"Policy for {data.policy_name}",
        enabled=True,
        status="published",
        linked_context=data.context_name,
        contexts=[data.context_name],
        operations=[],  # Applies to all operations
        policy_metadata={
            "wizard_config": {
                "data_type": data.data_type,
                "compliance": data.compliance,
                "threat_level": data.threat_level,
                "access_pattern": data.access_pattern,
            }
        },
        created_by=admin.github_username,
    )
    db.add(policy)

    await db.commit()

    return WizardPublishResponse(
        success=True,
        context_name=data.context_name,
        policy_name=data.policy_name,
        algorithm=derived.resolved_algorithm,
        message=f"Successfully created context '{data.context_name}' with {derived.resolved_algorithm} encryption",
    )


@router.get("/policies/published")
async def list_published_policies(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all published policies (visible to developers)."""
    result = await db.execute(
        select(Policy).where(Policy.status == "published").order_by(desc(Policy.created_at))
    )
    policies = result.scalars().all()

    return [
        {
            "name": p.name,
            "description": p.description,
            "linked_context": p.linked_context,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "created_by": p.created_by,
            "metadata": p.policy_metadata,
        }
        for p in policies
    ]


# --- Security Command Center ---

class SecurityAlert(BaseModel):
    """Security alert for the command center."""
    id: str
    severity: str  # critical, warning, info
    category: str  # key, identity, operation, compliance
    title: str
    description: str
    affected_count: int
    timestamp: datetime
    action_url: Optional[str] = None
    auto_resolvable: bool = False


class SecurityMetrics(BaseModel):
    """Real-time security metrics for command center."""
    operations_per_minute: float
    encryption_rate: float  # encrypt ops / total ops
    success_rate: float  # successful / total
    avg_latency_ms: float
    active_identities: int
    contexts_in_use: int
    data_processed_mb: float


class BlastRadiusItem(BaseModel):
    """Data lineage / blast radius item."""
    context_name: str
    key_version: int
    identities_affected: int
    operations_count: int
    data_size_bytes: int
    teams: list[str]
    last_used: Optional[datetime]


@router.get("/security/alerts", response_model=list[SecurityAlert])
async def get_security_alerts(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get active security alerts for the command center.

    Analyzes current state and returns actionable alerts.
    """
    now = datetime.now(timezone.utc)
    alerts = []

    # Alert 1: Expiring identities
    week_from_now = now + timedelta(days=7)
    expiring_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now,
                Identity.expires_at <= week_from_now
            )
        )
    ) or 0

    if expiring_identities > 0:
        alerts.append(SecurityAlert(
            id="expiring-identities",
            severity="warning" if expiring_identities < 5 else "critical",
            category="identity",
            title=f"{expiring_identities} Identities Expiring Soon",
            description=f"{expiring_identities} identities will expire in the next 7 days. Review and extend or revoke.",
            affected_count=expiring_identities,
            timestamp=now,
            action_url="/admin/identities?status=expiring",
            auto_resolvable=False,
        ))

    # Alert 2: High failure rate
    hour_ago = now - timedelta(hours=1)
    recent_total = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= hour_ago)
    ) or 0
    recent_failed = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(AuditLog.timestamp >= hour_ago, AuditLog.success == False)
        )
    ) or 0

    if recent_total > 10:  # Only alert if meaningful volume
        failure_rate = (recent_failed / recent_total) * 100 if recent_total > 0 else 0
        if failure_rate > 10:
            alerts.append(SecurityAlert(
                id="high-failure-rate",
                severity="critical" if failure_rate > 25 else "warning",
                category="operation",
                title=f"High Operation Failure Rate ({failure_rate:.1f}%)",
                description=f"{recent_failed} of {recent_total} operations failed in the last hour.",
                affected_count=recent_failed,
                timestamp=now,
                action_url="/admin/audit?success=false",
                auto_resolvable=False,
            ))

    # Alert 3: Keys needing rotation
    ninety_days_ago = now - timedelta(days=90)
    old_keys = await db.scalar(
        select(func.count(Key.id)).where(Key.created_at < ninety_days_ago)
    ) or 0

    if old_keys > 0:
        alerts.append(SecurityAlert(
            id="key-rotation-due",
            severity="warning",
            category="key",
            title=f"{old_keys} Keys Due for Rotation",
            description="Keys older than 90 days should be rotated for security best practices.",
            affected_count=old_keys,
            timestamp=now,
            action_url="/admin/contexts",
            auto_resolvable=True,
        ))

    # Alert 4: Deprecated algorithms in use
    contexts_result = await db.execute(select(Context))
    contexts = contexts_result.scalars().all()
    deprecated_algos = {"DES", "3DES", "RC4", "MD5", "SHA-1"}
    deprecated_contexts = [c for c in contexts if any(d in c.algorithm for d in deprecated_algos)]

    if deprecated_contexts:
        alerts.append(SecurityAlert(
            id="deprecated-algorithms",
            severity="critical",
            category="compliance",
            title=f"{len(deprecated_contexts)} Contexts Using Deprecated Algorithms",
            description=f"Contexts using deprecated cryptographic algorithms: {', '.join(c.name for c in deprecated_contexts[:3])}",
            affected_count=len(deprecated_contexts),
            timestamp=now,
            action_url="/admin/contexts",
            auto_resolvable=False,
        ))

    # Alert 5: No quantum-ready contexts
    pqc_algos = {"ML-KEM", "Kyber", "Dilithium", "SPHINCS", "Hybrid"}
    quantum_ready = [c for c in contexts if any(p in c.algorithm for p in pqc_algos)]

    if len(contexts) > 0 and len(quantum_ready) == 0:
        alerts.append(SecurityAlert(
            id="no-quantum-readiness",
            severity="info",
            category="compliance",
            title="No Quantum-Ready Contexts",
            description="Consider migrating critical contexts to post-quantum cryptography.",
            affected_count=len(contexts),
            timestamp=now,
            action_url="/algorithms",
            auto_resolvable=False,
        ))

    # Alert 6: Unused identities (not used in 30 days)
    thirty_days_ago = now - timedelta(days=30)
    unused_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                or_(
                    Identity.last_used_at.is_(None),
                    Identity.last_used_at < thirty_days_ago
                )
            )
        )
    ) or 0

    if unused_identities > 0:
        alerts.append(SecurityAlert(
            id="unused-identities",
            severity="info",
            category="identity",
            title=f"{unused_identities} Unused Identities",
            description="Identities not used in 30+ days. Consider revoking to reduce attack surface.",
            affected_count=unused_identities,
            timestamp=now,
            action_url="/admin/identities?unused=true",
            auto_resolvable=False,
        ))

    # Sort by severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda a: severity_order.get(a.severity, 3))

    return alerts


@router.get("/security/metrics", response_model=SecurityMetrics)
async def get_security_metrics(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get real-time security metrics for the command center."""
    now = datetime.now(timezone.utc)
    minute_ago = now - timedelta(minutes=1)
    hour_ago = now - timedelta(hours=1)

    # Operations per minute (last hour average)
    hour_ops = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= hour_ago)
    ) or 0
    ops_per_minute = hour_ops / 60

    # Encryption rate
    total_ops = await db.scalar(select(func.count(AuditLog.id))) or 0
    encrypt_ops = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.operation == "encrypt")
    ) or 0
    encryption_rate = (encrypt_ops / total_ops * 100) if total_ops > 0 else 0

    # Success rate
    successful_ops = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == True)
    ) or 0
    success_rate = (successful_ops / total_ops * 100) if total_ops > 0 else 100

    # Average latency (last hour)
    avg_latency = await db.scalar(
        select(func.avg(AuditLog.latency_ms)).where(
            and_(AuditLog.timestamp >= hour_ago, AuditLog.latency_ms.isnot(None))
        )
    ) or 0

    # Active identities
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now
            )
        )
    ) or 0

    # Contexts in use (have operations in last 24h)
    day_ago = now - timedelta(days=1)
    contexts_used_result = await db.execute(
        select(AuditLog.context).where(AuditLog.timestamp >= day_ago).distinct()
    )
    contexts_in_use = len(contexts_used_result.fetchall())

    # Data processed (MB)
    total_input = await db.scalar(
        select(func.sum(AuditLog.input_size_bytes)).where(AuditLog.input_size_bytes.isnot(None))
    ) or 0
    total_output = await db.scalar(
        select(func.sum(AuditLog.output_size_bytes)).where(AuditLog.output_size_bytes.isnot(None))
    ) or 0
    data_processed_mb = (total_input + total_output) / (1024 * 1024)

    return SecurityMetrics(
        operations_per_minute=round(ops_per_minute, 2),
        encryption_rate=round(encryption_rate, 1),
        success_rate=round(success_rate, 1),
        avg_latency_ms=round(avg_latency, 2),
        active_identities=active_identities,
        contexts_in_use=contexts_in_use,
        data_processed_mb=round(data_processed_mb, 2),
    )


@router.get("/security/blast-radius", response_model=list[BlastRadiusItem])
async def get_blast_radius(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    context: Optional[str] = Query(None, description="Filter by specific context"),
):
    """
    Get blast radius / data lineage information.

    Shows which identities used which contexts for what data,
    helping assess impact of potential key compromises.
    """
    # Build query for contexts
    if context:
        contexts_result = await db.execute(
            select(Context).where(Context.name == context)
        )
    else:
        contexts_result = await db.execute(select(Context))

    contexts = contexts_result.scalars().all()

    items = []
    for ctx in contexts:
        # Get key info
        key_result = await db.execute(
            select(Key).where(Key.context == ctx.name).order_by(desc(Key.version)).limit(1)
        )
        latest_key = key_result.scalar_one_or_none()

        # Get operations for this context
        operations_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.context == ctx.name)
        ) or 0

        # Get total data size
        data_size = await db.scalar(
            select(func.sum(AuditLog.input_size_bytes)).where(
                and_(AuditLog.context == ctx.name, AuditLog.input_size_bytes.isnot(None))
            )
        ) or 0

        # Get identities that used this context
        identity_result = await db.execute(
            select(AuditLog.identity_id).where(AuditLog.context == ctx.name).distinct()
        )
        identity_ids = [r[0] for r in identity_result.fetchall()]
        identities_affected = len(identity_ids)

        # Get teams
        teams_result = await db.execute(
            select(AuditLog.team).where(
                and_(AuditLog.context == ctx.name, AuditLog.team.isnot(None))
            ).distinct()
        )
        teams = [r[0] for r in teams_result.fetchall() if r[0]]

        # Get last used
        last_used_result = await db.execute(
            select(AuditLog.timestamp).where(AuditLog.context == ctx.name)
            .order_by(desc(AuditLog.timestamp)).limit(1)
        )
        last_used = last_used_result.scalar_one_or_none()

        items.append(BlastRadiusItem(
            context_name=ctx.name,
            key_version=latest_key.version if latest_key else 0,
            identities_affected=identities_affected,
            operations_count=operations_count,
            data_size_bytes=data_size,
            teams=teams,
            last_used=last_used,
        ))

    # Sort by data size (largest blast radius first)
    items.sort(key=lambda x: x.data_size_bytes, reverse=True)

    return items


# --- Interactive Playground ---

class PlaygroundRequest(BaseModel):
    """Request for playground encrypt/decrypt."""
    operation: str  # encrypt or decrypt
    data: str  # plaintext for encrypt, ciphertext for decrypt
    context: str


class PlaygroundResponse(BaseModel):
    """Response from playground."""
    success: bool
    result: Optional[str] = None
    algorithm: str
    latency_ms: float
    error: Optional[str] = None


@router.post("/playground", response_model=PlaygroundResponse)
async def playground_operation(
    request: PlaygroundRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Interactive playground for testing encryption.

    Allows users to test encrypt/decrypt operations without
    creating an identity or downloading the SDK.
    """
    import time
    import base64
    from app.core.crypto_service import crypto_service

    start_time = time.time()

    # Verify context exists
    ctx_result = await db.execute(select(Context).where(Context.name == request.context))
    context = ctx_result.scalar_one_or_none()

    if not context:
        return PlaygroundResponse(
            success=False,
            algorithm="",
            latency_ms=0,
            error=f"Context '{request.context}' not found",
        )

    try:
        if request.operation == "encrypt":
            # Encrypt the plaintext
            plaintext = request.data.encode("utf-8")
            ciphertext = await crypto_service.encrypt(
                db=db,
                plaintext=plaintext,
                context_name=request.context,
            )
            result = base64.b64encode(ciphertext).decode("ascii")

        elif request.operation == "decrypt":
            # Decrypt the ciphertext
            try:
                ciphertext = base64.b64decode(request.data)
            except Exception:
                return PlaygroundResponse(
                    success=False,
                    algorithm=context.algorithm,
                    latency_ms=(time.time() - start_time) * 1000,
                    error="Invalid base64 ciphertext",
                )

            plaintext = await crypto_service.decrypt(
                db=db,
                ciphertext=ciphertext,
                context_name=request.context,
            )
            result = plaintext.decode("utf-8")
        else:
            return PlaygroundResponse(
                success=False,
                algorithm="",
                latency_ms=0,
                error="Invalid operation. Use 'encrypt' or 'decrypt'",
            )

        latency_ms = (time.time() - start_time) * 1000

        return PlaygroundResponse(
            success=True,
            result=result,
            algorithm=context.algorithm,
            latency_ms=round(latency_ms, 2),
        )

    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        return PlaygroundResponse(
            success=False,
            algorithm=context.algorithm,
            latency_ms=round(latency_ms, 2),
            error=str(e),
        )


# =============================================================================
# Crypto Inventory Admin Endpoints
# =============================================================================


class CryptoInventoryOverview(BaseModel):
    """Organization-wide crypto inventory overview."""
    total_apps: int
    total_scans: int
    compliant_apps: int
    blocked_apps: int
    warned_apps: int
    avg_quantum_readiness: float
    has_pqc_apps: int
    deprecated_library_apps: int
    libraries_in_use: list[dict]
    by_team: list[dict]
    recent_scans: list[dict]


class LibraryUsageSummary(BaseModel):
    """Summary of a library's usage across org."""
    library_name: str
    version: str | None
    category: str
    quantum_risk: str
    is_deprecated: bool
    app_count: int
    team_count: int
    first_seen: datetime
    last_seen: datetime


@router.get("/crypto-inventory/overview", response_model=CryptoInventoryOverview)
async def get_crypto_inventory_overview(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get organization-wide crypto inventory overview.

    Shows:
    - Total apps scanned and compliance status
    - Quantum readiness across organization
    - Libraries in use and their risk levels
    - Team breakdown
    - Recent scans
    """
    # Get distinct identity IDs (apps)
    apps_result = await db.execute(
        select(CryptoInventoryReport.identity_id).distinct()
    )
    app_ids = [r[0] for r in apps_result.fetchall()]
    total_apps = len(app_ids)

    # Total scans
    total_scans = await db.scalar(select(func.count(CryptoInventoryReport.id))) or 0

    # Compliance breakdown (based on most recent scan per app)
    compliant_apps = 0
    blocked_apps = 0
    warned_apps = 0
    has_pqc_apps = 0
    deprecated_apps = 0
    quantum_scores = []

    for app_id in app_ids:
        # Get most recent scan for this app
        latest_result = await db.execute(
            select(CryptoInventoryReport)
            .where(CryptoInventoryReport.identity_id == app_id)
            .order_by(desc(CryptoInventoryReport.scanned_at))
            .limit(1)
        )
        latest = latest_result.scalar_one_or_none()
        if latest:
            if latest.action == EnforcementAction.ALLOW:
                compliant_apps += 1
            elif latest.action == EnforcementAction.BLOCK:
                blocked_apps += 1
            else:
                warned_apps += 1

            if latest.has_pqc:
                has_pqc_apps += 1
            if latest.deprecated_count > 0:
                deprecated_apps += 1

            quantum_scores.append(latest.quantum_readiness_score)

    avg_quantum_readiness = sum(quantum_scores) / len(quantum_scores) if quantum_scores else 0

    # Libraries in use
    libs_result = await db.execute(
        select(CryptoLibraryUsage)
        .order_by(desc(CryptoLibraryUsage.app_count))
        .limit(20)
    )
    libraries = libs_result.scalars().all()

    libraries_in_use = [
        {
            "name": lib.library_name,
            "version": lib.library_version,
            "category": lib.category,
            "quantum_risk": lib.quantum_risk.value,
            "is_deprecated": lib.is_deprecated,
            "app_count": lib.app_count,
        }
        for lib in libraries
    ]

    # By team
    team_stats_result = await db.execute(
        select(
            CryptoInventoryReport.team,
            func.count(func.distinct(CryptoInventoryReport.identity_id)).label("app_count"),
            func.avg(CryptoInventoryReport.quantum_safe_count).label("avg_safe"),
            func.avg(CryptoInventoryReport.quantum_vulnerable_count).label("avg_vuln"),
        )
        .where(CryptoInventoryReport.team.isnot(None))
        .group_by(CryptoInventoryReport.team)
        .order_by(desc("app_count"))
    )
    team_stats = team_stats_result.fetchall()

    by_team = [
        {
            "team": row[0],
            "app_count": row[1],
            "avg_quantum_safe": round(row[2] or 0, 1),
            "avg_quantum_vulnerable": round(row[3] or 0, 1),
        }
        for row in team_stats
    ]

    # Recent scans
    recent_result = await db.execute(
        select(CryptoInventoryReport)
        .order_by(desc(CryptoInventoryReport.scanned_at))
        .limit(10)
    )
    recent = recent_result.scalars().all()

    recent_scans = [
        {
            "id": r.id,
            "identity_name": r.identity_name,
            "team": r.team,
            "action": r.action.value,
            "scan_source": r.scan_source.value,
            "scanned_at": r.scanned_at.isoformat(),
            "quantum_readiness_score": r.quantum_readiness_score,
            "violation_count": r.violation_count,
            "warning_count": r.warning_count,
        }
        for r in recent
    ]

    return CryptoInventoryOverview(
        total_apps=total_apps,
        total_scans=total_scans,
        compliant_apps=compliant_apps,
        blocked_apps=blocked_apps,
        warned_apps=warned_apps,
        avg_quantum_readiness=round(avg_quantum_readiness, 1),
        has_pqc_apps=has_pqc_apps,
        deprecated_library_apps=deprecated_apps,
        libraries_in_use=libraries_in_use,
        by_team=by_team,
        recent_scans=recent_scans,
    )


@router.get("/crypto-inventory/libraries", response_model=list[LibraryUsageSummary])
async def get_library_usage(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    deprecated_only: bool = False,
    quantum_vulnerable_only: bool = False,
):
    """
    Get library usage across organization.

    Filters:
    - deprecated_only: Only show deprecated libraries
    - quantum_vulnerable_only: Only show quantum-vulnerable libraries
    """
    query = select(CryptoLibraryUsage).order_by(desc(CryptoLibraryUsage.app_count))

    if deprecated_only:
        query = query.where(CryptoLibraryUsage.is_deprecated == True)

    if quantum_vulnerable_only:
        from app.models.crypto_inventory import QuantumRisk as DBQuantumRisk
        query = query.where(
            CryptoLibraryUsage.quantum_risk.in_([DBQuantumRisk.HIGH, DBQuantumRisk.CRITICAL])
        )

    result = await db.execute(query)
    libraries = result.scalars().all()

    return [
        LibraryUsageSummary(
            library_name=lib.library_name,
            version=lib.library_version,
            category=lib.category,
            quantum_risk=lib.quantum_risk.value,
            is_deprecated=lib.is_deprecated,
            app_count=lib.app_count,
            team_count=lib.team_count,
            first_seen=lib.first_seen_at,
            last_seen=lib.last_seen_at,
        )
        for lib in libraries
    ]


@router.get("/crypto-inventory/apps/{identity_id}")
async def get_app_crypto_details(
    identity_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get detailed crypto inventory for a specific app.

    Shows history of scans, libraries detected, violations, and recommendations.
    """
    # Get all scans for this app
    scans_result = await db.execute(
        select(CryptoInventoryReport)
        .where(CryptoInventoryReport.identity_id == identity_id)
        .order_by(desc(CryptoInventoryReport.scanned_at))
    )
    scans = scans_result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail="No inventory data found for this app")

    latest = scans[0]

    return {
        "identity_id": identity_id,
        "identity_name": latest.identity_name,
        "team": latest.team,
        "department": latest.department,
        "total_scans": len(scans),
        "current_status": {
            "action": latest.action.value,
            "quantum_readiness_score": latest.quantum_readiness_score,
            "has_pqc": latest.has_pqc,
            "library_count": latest.library_count,
            "violation_count": latest.violation_count,
            "warning_count": latest.warning_count,
            "deprecated_count": latest.deprecated_count,
        },
        "libraries": latest.libraries,
        "violations": latest.violations,
        "warnings": latest.warnings,
        "scan_history": [
            {
                "id": s.id,
                "scanned_at": s.scanned_at.isoformat(),
                "scan_source": s.scan_source.value,
                "action": s.action.value,
                "quantum_readiness_score": s.quantum_readiness_score,
                "git_commit": s.git_commit,
                "git_branch": s.git_branch,
            }
            for s in scans[:20]  # Last 20 scans
        ],
        "recommendations": _generate_recommendations(latest),
    }


def _generate_recommendations(report: CryptoInventoryReport) -> list[dict]:
    """Generate PQC migration recommendations based on inventory."""
    recommendations = []

    # Deprecated libraries
    if report.deprecated_count > 0:
        for lib in report.libraries:
            if lib.get("is_deprecated"):
                recommendations.append({
                    "priority": "critical",
                    "category": "deprecated",
                    "library": lib.get("name"),
                    "message": f"Replace deprecated library '{lib.get('name')}'",
                    "action": "Migrate to a modern, maintained alternative",
                })

    # Quantum-vulnerable libraries without PQC
    if report.quantum_vulnerable_count > 0 and not report.has_pqc:
        recommendations.append({
            "priority": "high",
            "category": "quantum",
            "message": "Add post-quantum cryptography support",
            "action": "Consider adding liboqs-python or AWS-LC for production PQC",
        })

        for lib in report.libraries:
            if lib.get("quantum_risk") in ["high", "critical"]:
                recommendations.append({
                    "priority": "medium",
                    "category": "quantum",
                    "library": lib.get("name"),
                    "message": f"Plan migration for '{lib.get('name')}' (quantum-vulnerable)",
                    "action": "Replace with hybrid or PQC alternative by 2030",
                })

    # Already has PQC - good!
    if report.has_pqc:
        recommendations.append({
            "priority": "info",
            "category": "quantum",
            "message": "Post-quantum cryptography detected",
            "action": "Continue expanding PQC coverage to all sensitive contexts",
        })

    return recommendations


@router.get("/crypto-inventory/trends")
async def get_crypto_inventory_trends(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=7, le=365),
):
    """
    Get crypto inventory trends over time.

    Shows how quantum readiness, compliance, and library usage changes.
    """
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days)

    # Daily aggregates
    trends = []
    current_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    while current_date <= now:
        next_date = current_date + timedelta(days=1)

        # Get scans for this day
        day_result = await db.execute(
            select(CryptoInventoryReport).where(
                and_(
                    CryptoInventoryReport.scanned_at >= current_date,
                    CryptoInventoryReport.scanned_at < next_date
                )
            )
        )
        day_scans = day_result.scalars().all()

        if day_scans:
            avg_qr = sum(s.quantum_readiness_score for s in day_scans) / len(day_scans)
            blocked = sum(1 for s in day_scans if s.action == EnforcementAction.BLOCK)
            with_pqc = sum(1 for s in day_scans if s.has_pqc)

            trends.append({
                "date": current_date.strftime("%Y-%m-%d"),
                "scan_count": len(day_scans),
                "avg_quantum_readiness": round(avg_qr, 1),
                "blocked_count": blocked,
                "with_pqc_count": with_pqc,
            })

        current_date = next_date

    return {
        "period_days": days,
        "trends": trends,
    }


# =============================================================================
# Organization Settings & Domain Management
# =============================================================================


class OrganizationSettingsResponse(BaseModel):
    """Organization settings response."""
    allowed_domains: list[str]
    require_domain_match: bool
    allow_any_github_user: bool
    organization_name: Optional[str]
    admin_email: Optional[str]
    created_at: datetime
    updated_at: datetime


class OrganizationSettingsUpdate(BaseModel):
    """Organization settings update request."""
    require_domain_match: Optional[bool] = None
    allow_any_github_user: Optional[bool] = None
    organization_name: Optional[str] = None


class AddDomainRequest(BaseModel):
    """Request to add a new allowed domain."""
    domain: str


@router.get("/settings", response_model=OrganizationSettingsResponse)
async def get_org_settings(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get organization settings including allowed domains."""
    from app.core.domain_service import domain_service

    settings = await domain_service.get_org_settings(db)

    return OrganizationSettingsResponse(
        allowed_domains=settings.allowed_domains or [],
        require_domain_match=settings.require_domain_match,
        allow_any_github_user=settings.allow_any_github_user,
        organization_name=settings.organization_name,
        admin_email=settings.admin_email,
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


@router.patch("/settings", response_model=OrganizationSettingsResponse)
async def update_org_settings(
    data: OrganizationSettingsUpdate,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update organization settings."""
    from app.core.domain_service import domain_service

    settings = await domain_service.update_settings(
        db,
        require_domain_match=data.require_domain_match,
        allow_any_github_user=data.allow_any_github_user,
        organization_name=data.organization_name,
    )

    return OrganizationSettingsResponse(
        allowed_domains=settings.allowed_domains or [],
        require_domain_match=settings.require_domain_match,
        allow_any_github_user=settings.allow_any_github_user,
        organization_name=settings.organization_name,
        admin_email=settings.admin_email,
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


@router.get("/settings/domains")
async def get_allowed_domains(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get list of allowed email domains."""
    from app.core.domain_service import domain_service

    domains = await domain_service.get_allowed_domains(db)
    return {"domains": domains}


@router.post("/settings/domains")
async def add_allowed_domain(
    data: AddDomainRequest,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a new allowed email domain."""
    from app.core.domain_service import domain_service

    try:
        await domain_service.add_domain(data.domain, db)
        domains = await domain_service.get_allowed_domains(db)
        return {"message": f"Domain '{data.domain}' added", "domains": domains}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete("/settings/domains/{domain}")
async def remove_allowed_domain(
    domain: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove an allowed email domain."""
    from app.core.domain_service import domain_service

    await domain_service.remove_domain(domain, db)
    domains = await domain_service.get_allowed_domains(db)
    return {"message": f"Domain '{domain}' removed", "domains": domains}


@router.post("/users/{user_id}/toggle-admin")
async def toggle_user_admin(
    user_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Toggle admin status for a user."""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own admin status",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.is_admin = not user.is_admin
    await db.commit()

    return {
        "user_id": user.id,
        "github_username": user.github_username,
        "is_admin": user.is_admin,
        "message": f"User {'promoted to' if user.is_admin else 'demoted from'} admin",
    }


# --- Algorithm Metrics Endpoints ---

class AlgorithmMetrics(BaseModel):
    """Algorithm usage metrics for dashboard."""
    period: str
    total_operations: int
    by_cipher: dict[str, int]
    by_mode: dict[str, int]
    by_key_bits: dict[str, int]
    quantum_safe_operations: int
    policy_violations: int
    daily_trend: list[dict]


@router.get("/metrics/algorithms", response_model=AlgorithmMetrics)
async def get_algorithm_metrics(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(default=30, ge=1, le=365, description="Number of days to include"),
):
    """Get algorithm usage metrics for the dashboard.

    Returns breakdown of operations by cipher, mode, key size, and quantum-safe status.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Get total operations in period
    total_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= cutoff)
    )
    total_operations = total_result.scalar() or 0

    # Count by cipher
    cipher_result = await db.execute(
        select(AuditLog.cipher, func.count(AuditLog.id))
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.cipher.isnot(None),
                AuditLog.success == True,
            )
        )
        .group_by(AuditLog.cipher)
    )
    by_cipher = {row[0]: row[1] for row in cipher_result.all() if row[0]}

    # Count by mode
    mode_result = await db.execute(
        select(AuditLog.mode, func.count(AuditLog.id))
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.mode.isnot(None),
                AuditLog.success == True,
            )
        )
        .group_by(AuditLog.mode)
    )
    by_mode = {row[0]: row[1] for row in mode_result.all() if row[0]}

    # Count by key bits
    key_bits_result = await db.execute(
        select(AuditLog.key_bits, func.count(AuditLog.id))
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.key_bits.isnot(None),
                AuditLog.success == True,
            )
        )
        .group_by(AuditLog.key_bits)
    )
    by_key_bits = {str(row[0]): row[1] for row in key_bits_result.all() if row[0]}

    # Count quantum-safe operations
    quantum_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.quantum_safe == True,
                AuditLog.success == True,
            )
        )
    )
    quantum_safe_operations = quantum_result.scalar() or 0

    # Count policy violations
    violations_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.policy_violation == True,
            )
        )
    )
    policy_violations = violations_result.scalar() or 0

    # Daily trend (last N days)
    daily_trend = []
    for i in range(min(days, 30)):  # Max 30 days of daily data
        day_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)

        day_result = await db.execute(
            select(func.count(AuditLog.id))
            .where(
                and_(
                    AuditLog.timestamp >= day_start,
                    AuditLog.timestamp < day_end,
                    AuditLog.success == True,
                )
            )
        )
        day_count = day_result.scalar() or 0

        daily_trend.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "operations": day_count,
        })

    # Reverse so oldest first
    daily_trend.reverse()

    return AlgorithmMetrics(
        period=f"last_{days}_days",
        total_operations=total_operations,
        by_cipher=by_cipher,
        by_mode=by_mode,
        by_key_bits=by_key_bits,
        quantum_safe_operations=quantum_safe_operations,
        policy_violations=policy_violations,
        daily_trend=daily_trend,
    )
