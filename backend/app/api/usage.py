"""Usage statistics API routes.

Provides endpoints for viewing API usage metrics and error summaries.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Context, AuditLog
from app.schemas.usage import (
    ContextUsageStats,
    ErrorSummary,
    DailyUsageStats,
    UsagePeriod,
    UsageStatsResponse,
)

router = APIRouter(prefix="/api/v1", tags=["usage"])


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/usage/stats", response_model=UsageStatsResponse)
async def get_usage_stats(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    start_date: datetime | None = Query(
        default=None,
        description="Start of period (defaults to 30 days ago)"
    ),
    end_date: datetime | None = Query(
        default=None,
        description="End of period (defaults to now)"
    ),
    context_ids: list[str] | None = Query(
        default=None,
        description="Filter by specific contexts"
    ),
):
    """Get usage statistics for the current user's tenant.

    Returns:
    - Total API calls in the period
    - Breakdown by context (encrypt, decrypt, sign, verify)
    - Error summary
    - Daily usage breakdown
    """
    now = datetime.now(timezone.utc)

    # Default to last 30 days
    if end_date is None:
        end_date = now
    if start_date is None:
        start_date = now - timedelta(days=30)

    # Base query conditions
    base_conditions = [
        AuditLog.tenant_id == user.tenant_id,
        AuditLog.timestamp >= start_date,
        AuditLog.timestamp <= end_date,
    ]

    if context_ids:
        base_conditions.append(AuditLog.context.in_(context_ids))

    # Get total calls
    total_result = await db.execute(
        select(func.count(AuditLog.id)).where(and_(*base_conditions))
    )
    total_calls = total_result.scalar() or 0

    # Get breakdown by context
    context_stats_query = select(
        AuditLog.context,
        func.sum(case((AuditLog.operation == "encrypt", 1), else_=0)).label("encrypt_calls"),
        func.sum(case((AuditLog.operation == "decrypt", 1), else_=0)).label("decrypt_calls"),
        func.sum(case((AuditLog.operation == "sign", 1), else_=0)).label("sign_calls"),
        func.sum(case((AuditLog.operation == "verify", 1), else_=0)).label("verify_calls"),
    ).where(
        and_(*base_conditions)
    ).group_by(AuditLog.context)

    context_stats_result = await db.execute(context_stats_query)
    context_rows = context_stats_result.all()

    # Get context display names
    context_names = {}
    if context_rows:
        context_ids_list = [row[0] for row in context_rows]
        contexts_result = await db.execute(
            select(Context.name, Context.display_name).where(
                Context.name.in_(context_ids_list),
                Context.tenant_id == user.tenant_id
            )
        )
        context_names = {row[0]: row[1] for row in contexts_result.all()}

    by_context = []
    for row in context_rows:
        context_id = row[0]
        by_context.append(ContextUsageStats(
            context_id=context_id,
            context_name=context_names.get(context_id, context_id),
            encrypt_calls=row[1] or 0,
            decrypt_calls=row[2] or 0,
            sign_calls=row[3] or 0,
            verify_calls=row[4] or 0,
        ))

    # Get error summary
    error_conditions = base_conditions + [AuditLog.success == False]  # noqa: E712
    error_query = select(
        AuditLog.context,
        AuditLog.error_message,
        func.count(AuditLog.id).label("count"),
        func.max(AuditLog.timestamp).label("last_occurred"),
    ).where(
        and_(*error_conditions)
    ).group_by(
        AuditLog.context,
        AuditLog.error_message
    ).order_by(
        func.count(AuditLog.id).desc()
    ).limit(20)

    error_result = await db.execute(error_query)
    error_rows = error_result.all()

    errors = []
    for row in error_rows:
        # Categorize error type from error message
        error_msg = row[1] or "UNKNOWN_ERROR"
        error_type = categorize_error(error_msg)

        errors.append(ErrorSummary(
            context_name=row[0],
            error_type=error_type,
            count=row[2],
            last_occurred=row[3],
        ))

    # Get daily breakdown
    # Use date truncation for grouping
    daily_query = select(
        func.date(AuditLog.timestamp).label("date"),
        func.count(AuditLog.id).label("total_calls"),
    ).where(
        and_(*base_conditions)
    ).group_by(
        func.date(AuditLog.timestamp)
    ).order_by(
        func.date(AuditLog.timestamp)
    )

    daily_result = await db.execute(daily_query)
    daily_rows = daily_result.all()

    daily_breakdown = []
    for row in daily_rows:
        date_str = row[0].isoformat() if hasattr(row[0], 'isoformat') else str(row[0])
        daily_breakdown.append(DailyUsageStats(
            date=date_str,
            total_calls=row[1],
        ))

    return UsageStatsResponse(
        org_id=user.tenant_id,
        period=UsagePeriod(start=start_date, end=end_date),
        total_calls=total_calls,
        by_context=by_context,
        errors=errors,
        daily_breakdown=daily_breakdown,
    )


def categorize_error(error_message: str) -> str:
    """Categorize an error message into a standard error type."""
    error_lower = error_message.lower()

    if "decrypt" in error_lower:
        return "DECRYPTION_FAILED"
    elif "encrypt" in error_lower:
        return "ENCRYPTION_FAILED"
    elif "context" in error_lower and ("not found" in error_lower or "invalid" in error_lower):
        return "CONTEXT_NOT_FOUND"
    elif "key" in error_lower:
        return "KEY_ERROR"
    elif "auth" in error_lower or "permission" in error_lower or "forbidden" in error_lower:
        return "AUTHORIZATION_FAILED"
    elif "timeout" in error_lower:
        return "TIMEOUT"
    elif "rate" in error_lower or "limit" in error_lower:
        return "RATE_LIMITED"
    elif "validation" in error_lower or "invalid" in error_lower:
        return "VALIDATION_ERROR"
    else:
        return "UNKNOWN_ERROR"


@router.get("/usage/contexts/{context_name}", response_model=ContextUsageStats)
async def get_context_usage(
    context_name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
):
    """Get usage statistics for a specific context."""
    now = datetime.now(timezone.utc)

    if end_date is None:
        end_date = now
    if start_date is None:
        start_date = now - timedelta(days=30)

    # Verify context exists
    context_result = await db.execute(
        select(Context).where(
            Context.name == context_name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = context_result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=404,
            detail=f"Context not found: {context_name}"
        )

    # Get stats for this context
    stats_query = select(
        func.sum(case((AuditLog.operation == "encrypt", 1), else_=0)).label("encrypt_calls"),
        func.sum(case((AuditLog.operation == "decrypt", 1), else_=0)).label("decrypt_calls"),
        func.sum(case((AuditLog.operation == "sign", 1), else_=0)).label("sign_calls"),
        func.sum(case((AuditLog.operation == "verify", 1), else_=0)).label("verify_calls"),
    ).where(
        AuditLog.tenant_id == user.tenant_id,
        AuditLog.context == context_name,
        AuditLog.timestamp >= start_date,
        AuditLog.timestamp <= end_date,
    )

    result = await db.execute(stats_query)
    row = result.one()

    return ContextUsageStats(
        context_id=context_name,
        context_name=context.display_name,
        encrypt_calls=row[0] or 0,
        decrypt_calls=row[1] or 0,
        sign_calls=row[2] or 0,
        verify_calls=row[3] or 0,
    )
