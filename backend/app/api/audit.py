"""Audit log API routes."""

from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.crypto import get_sdk_identity
from app.models import Identity, AuditLog

router = APIRouter(prefix="/api/audit", tags=["audit"])


class AuditLogResponse(BaseModel):
    """Audit log response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    operation: str
    context: str
    success: bool
    error_message: str | None
    identity_id: str
    identity_name: str | None
    team: str | None
    input_size_bytes: int | None
    output_size_bytes: int | None
    latency_ms: int | None


class AuditStats(BaseModel):
    """Audit statistics."""
    total_operations: int
    successful_operations: int
    failed_operations: int
    operations_by_context: dict[str, int]
    operations_by_identity: dict[str, int]


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
    identity_id: str | None = Query(None),
    context: str | None = Query(None),
    success: bool | None = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    """List audit logs for the current user's identities."""
    # Get user's identity IDs (use the identity's user_id to find all identities)
    identity_result = await db.execute(
        select(Identity.id).where(Identity.user_id == identity.user_id)
    )
    user_identity_ids = [row[0] for row in identity_result.fetchall()]

    if not user_identity_ids:
        return []

    # Build query
    query = select(AuditLog).where(
        AuditLog.identity_id.in_(user_identity_ids)
    )

    if identity_id:
        if identity_id not in user_identity_ids:
            return []
        query = query.where(AuditLog.identity_id == identity_id)

    if context:
        query = query.where(AuditLog.context == context)

    if success is not None:
        query = query.where(AuditLog.success == success)

    query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    logs = result.scalars().all()

    return logs


@router.get("/stats", response_model=AuditStats)
async def get_audit_stats(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get audit statistics for the current user."""
    # Get user's identity IDs (use the identity's user_id to find all identities)
    identity_result = await db.execute(
        select(Identity.id).where(Identity.user_id == identity.user_id)
    )
    user_identity_ids = [row[0] for row in identity_result.fetchall()]

    if not user_identity_ids:
        return AuditStats(
            total_operations=0,
            successful_operations=0,
            failed_operations=0,
            operations_by_context={},
            operations_by_identity={},
        )

    # Get all logs for user's identities
    result = await db.execute(
        select(AuditLog).where(AuditLog.identity_id.in_(user_identity_ids))
    )
    logs = result.scalars().all()

    # Calculate stats
    total = len(logs)
    successful = sum(1 for log in logs if log.success)
    failed = total - successful

    by_context: dict[str, int] = {}
    by_identity: dict[str, int] = {}

    for log in logs:
        by_context[log.context] = by_context.get(log.context, 0) + 1
        by_identity[log.identity_id] = by_identity.get(log.identity_id, 0) + 1

    return AuditStats(
        total_operations=total,
        successful_operations=successful,
        failed_operations=failed,
        operations_by_context=by_context,
        operations_by_identity=by_identity,
    )
