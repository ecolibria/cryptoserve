"""Promotion service for application environment promotion.

Handles the promotion workflow from development to production:
- Trust thresholds validation
- Context sensitivity tiers
- Expedited approval requests
- Promotion readiness checks
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application import Application
from app.models.audit import AuditLog


class ContextTier(str, Enum):
    """Context sensitivity tiers with different requirements."""
    TIER_1 = "tier_1"  # Low: session-tokens, cache-data
    TIER_2 = "tier_2"  # Medium: user-pii, api-keys
    TIER_3 = "tier_3"  # High: pci, health-data, secrets


class ExpediteePriority(str, Enum):
    """Priority levels for expedited approval requests."""
    CRITICAL = "critical"  # Production down, security incident
    HIGH = "high"  # Customer-impacting, need today
    NORMAL = "normal"  # Business need, flexible timing


# Context to tier mapping
CONTEXT_TIERS = {
    # Tier 1 - Low sensitivity
    "session-tokens": ContextTier.TIER_1,
    "cache-data": ContextTier.TIER_1,
    "temp-data": ContextTier.TIER_1,
    "analytics": ContextTier.TIER_1,
    # Tier 2 - Medium sensitivity
    "user-pii": ContextTier.TIER_2,
    "api-keys": ContextTier.TIER_2,
    "internal-data": ContextTier.TIER_2,
    "customer-data": ContextTier.TIER_2,
    # Tier 3 - High sensitivity
    "pci": ContextTier.TIER_3,
    "payment-data": ContextTier.TIER_3,
    "health-data": ContextTier.TIER_3,
    "phi": ContextTier.TIER_3,
    "secrets": ContextTier.TIER_3,
    "encryption-keys": ContextTier.TIER_3,
}


# Tier requirements
TIER_REQUIREMENTS = {
    ContextTier.TIER_1: {
        "min_operations": 10,
        "min_hours_in_dev": 1,
        "min_unique_days": 1,
        "requires_approval": False,
    },
    ContextTier.TIER_2: {
        "min_operations": 50,
        "min_hours_in_dev": 24,
        "min_unique_days": 2,
        "requires_approval": False,
    },
    ContextTier.TIER_3: {
        "min_operations": 100,
        "min_hours_in_dev": 48,
        "min_unique_days": 3,
        "requires_approval": True,
    },
}


class ContextReadiness(BaseModel):
    """Readiness status for a single context."""
    context: str
    tier: str
    tier_display: str

    # Requirements
    required_operations: int
    required_hours: int
    required_days: int
    requires_approval: bool

    # Current status
    current_operations: int
    current_hours: float
    current_unique_days: int

    # Calculated
    operations_met: bool
    hours_met: bool
    days_met: bool
    is_ready: bool

    # If not ready, when will it be?
    estimated_ready_at: Optional[datetime] = None
    blocking_reason: Optional[str] = None


class PromotionReadiness(BaseModel):
    """Overall promotion readiness for an application."""
    app_id: str
    app_name: str
    current_environment: str
    target_environment: str = "production"

    # Overall status
    is_ready: bool
    requires_approval: bool

    # Per-context readiness
    contexts: list[ContextReadiness]

    # Summary
    ready_count: int
    total_count: int
    blocking_contexts: list[str]

    # Estimated completion
    estimated_ready_at: Optional[datetime] = None

    # Developer trust score
    developer_trust_score: float = 1.0


class ExpeditedRequest(BaseModel):
    """Request for expedited promotion approval."""
    request_id: str = Field(default_factory=lambda: f"EXP-{datetime.now().strftime('%Y')}-{uuid4().hex[:4].upper()}")
    app_id: str
    app_name: str
    priority: ExpediteePriority
    justification: str
    contexts: list[str]
    thresholds_bypassed: list[str]
    requester_email: str
    requester_trust_score: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Approval tracking
    status: str = "pending"  # pending, approved, rejected
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    follow_up_required: bool = False
    follow_up_date: Optional[datetime] = None


def get_context_tier(context: str) -> ContextTier:
    """Get the tier for a context, defaulting to Tier 2."""
    return CONTEXT_TIERS.get(context, ContextTier.TIER_2)


def get_tier_display(tier: ContextTier) -> str:
    """Get human-readable tier name."""
    return {
        ContextTier.TIER_1: "Tier 1 (Low)",
        ContextTier.TIER_2: "Tier 2 (Medium)",
        ContextTier.TIER_3: "Tier 3 (High)",
    }[tier]


async def get_context_stats(
    db: AsyncSession,
    app_id: str,
    context: str,
) -> tuple[int, float, int]:
    """Get operation stats for a context.

    Returns:
        Tuple of (operation_count, hours_in_dev, unique_days)
    """
    # Get operation count for this context
    # Note: AuditLog uses identity_id (legacy name) for application_id
    count_result = await db.execute(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.identity_id == app_id)
        .where(AuditLog.context == context)
        .where(AuditLog.success == True)
    )
    operation_count = count_result.scalar() or 0

    # Get first operation timestamp
    first_op_result = await db.execute(
        select(func.min(AuditLog.timestamp))
        .select_from(AuditLog)
        .where(AuditLog.identity_id == app_id)
        .where(AuditLog.context == context)
    )
    first_op = first_op_result.scalar()

    if first_op:
        now = datetime.now(timezone.utc)
        if first_op.tzinfo is None:
            first_op = first_op.replace(tzinfo=timezone.utc)
        hours_in_dev = (now - first_op).total_seconds() / 3600
    else:
        hours_in_dev = 0.0

    # Get unique days with operations
    unique_days_result = await db.execute(
        select(func.count(func.distinct(func.date(AuditLog.timestamp))))
        .select_from(AuditLog)
        .where(AuditLog.identity_id == app_id)
        .where(AuditLog.context == context)
    )
    unique_days = unique_days_result.scalar() or 0

    return operation_count, hours_in_dev, unique_days


async def check_context_readiness(
    db: AsyncSession,
    app_id: str,
    context: str,
) -> ContextReadiness:
    """Check if a context is ready for promotion."""
    tier = get_context_tier(context)
    requirements = TIER_REQUIREMENTS[tier]

    # Get current stats
    operations, hours, days = await get_context_stats(db, app_id, context)

    # Check requirements
    operations_met = operations >= requirements["min_operations"]
    hours_met = hours >= requirements["min_hours_in_dev"]
    days_met = days >= requirements["min_unique_days"]

    is_ready = operations_met and hours_met and days_met

    # Calculate estimated ready time if not ready
    estimated_ready_at = None
    blocking_reason = None

    if not is_ready:
        blocking_reasons = []
        max_wait_hours = 0

        if not operations_met:
            needed = requirements["min_operations"] - operations
            blocking_reasons.append(f"Need {needed} more operations")
            # Assume average 10 ops/hour based on current rate
            if operations > 0 and hours > 0:
                ops_per_hour = operations / hours
                hours_needed = needed / ops_per_hour if ops_per_hour > 0 else 24
            else:
                hours_needed = 24  # Default estimate
            max_wait_hours = max(max_wait_hours, hours_needed)

        if not hours_met:
            needed = requirements["min_hours_in_dev"] - hours
            blocking_reasons.append(f"Need {needed:.0f} more hours in dev")
            max_wait_hours = max(max_wait_hours, needed)

        if not days_met:
            needed = requirements["min_unique_days"] - days
            blocking_reasons.append(f"Need {needed} more unique days")
            max_wait_hours = max(max_wait_hours, needed * 24)

        blocking_reason = "; ".join(blocking_reasons)
        estimated_ready_at = datetime.now(timezone.utc) + timedelta(hours=max_wait_hours)

    return ContextReadiness(
        context=context,
        tier=tier.value,
        tier_display=get_tier_display(tier),
        required_operations=requirements["min_operations"],
        required_hours=requirements["min_hours_in_dev"],
        required_days=requirements["min_unique_days"],
        requires_approval=requirements["requires_approval"],
        current_operations=operations,
        current_hours=hours,
        current_unique_days=days,
        operations_met=operations_met,
        hours_met=hours_met,
        days_met=days_met,
        is_ready=is_ready,
        estimated_ready_at=estimated_ready_at,
        blocking_reason=blocking_reason,
    )


async def check_promotion_readiness(
    db: AsyncSession,
    application: Application,
    target_environment: str = "production",
) -> PromotionReadiness:
    """Check if an application is ready for promotion."""
    contexts = application.allowed_contexts or []

    if not contexts:
        return PromotionReadiness(
            app_id=application.id,
            app_name=application.name,
            current_environment=application.environment,
            target_environment=target_environment,
            is_ready=False,
            requires_approval=False,
            contexts=[],
            ready_count=0,
            total_count=0,
            blocking_contexts=[],
            estimated_ready_at=None,
        )

    # Check each context
    context_readiness = []
    for context in contexts:
        readiness = await check_context_readiness(db, application.id, context)
        context_readiness.append(readiness)

    # Summarize
    ready_count = sum(1 for c in context_readiness if c.is_ready)
    total_count = len(context_readiness)
    blocking_contexts = [c.context for c in context_readiness if not c.is_ready]
    requires_approval = any(c.requires_approval for c in context_readiness)
    is_ready = all(c.is_ready for c in context_readiness)

    # Get latest estimated ready time
    estimated_ready_at = None
    if not is_ready:
        estimates = [c.estimated_ready_at for c in context_readiness if c.estimated_ready_at]
        if estimates:
            estimated_ready_at = max(estimates)

    return PromotionReadiness(
        app_id=application.id,
        app_name=application.name,
        current_environment=application.environment,
        target_environment=target_environment,
        is_ready=is_ready,
        requires_approval=requires_approval,
        contexts=context_readiness,
        ready_count=ready_count,
        total_count=total_count,
        blocking_contexts=blocking_contexts,
        estimated_ready_at=estimated_ready_at,
    )


async def create_expedited_request(
    db: AsyncSession,
    application: Application,
    priority: ExpediteePriority,
    justification: str,
    requester_email: str,
) -> ExpeditedRequest:
    """Create an expedited promotion request."""
    readiness = await check_promotion_readiness(db, application)

    # Gather bypassed thresholds
    thresholds_bypassed = []
    for ctx in readiness.contexts:
        if not ctx.is_ready:
            if not ctx.operations_met:
                thresholds_bypassed.append(
                    f"{ctx.context}: {ctx.current_operations}/{ctx.required_operations} ops"
                )
            if not ctx.hours_met:
                thresholds_bypassed.append(
                    f"{ctx.context}: {ctx.current_hours:.0f}/{ctx.required_hours}h in dev"
                )
            if not ctx.days_met:
                thresholds_bypassed.append(
                    f"{ctx.context}: {ctx.current_unique_days}/{ctx.required_days} days"
                )

    request = ExpeditedRequest(
        app_id=application.id,
        app_name=application.name,
        priority=priority,
        justification=justification,
        contexts=application.allowed_contexts or [],
        thresholds_bypassed=thresholds_bypassed,
        requester_email=requester_email,
        requester_trust_score=1.0,  # TODO: Calculate from user history
    )

    # TODO: Store in database, send notifications
    # For now, just return the request

    return request
