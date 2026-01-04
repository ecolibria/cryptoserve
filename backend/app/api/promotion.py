"""Promotion API routes.

Provides endpoints for application promotion workflow:
- Check promotion readiness
- Request promotion
- Request expedited approval
- Check promotion status
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User
from app.models.application import Application, ApplicationStatus
from app.core.promotion import (
    PromotionReadiness,
    ExpeditedRequest,
    ExpediteePriority,
    check_promotion_readiness,
    create_expedited_request,
    ContextReadiness,
)

router = APIRouter(prefix="/api/v1/applications", tags=["promotion"])


# ============================================================================
# Request/Response Models
# ============================================================================


class PromotionRequest(BaseModel):
    """Request to promote an application."""
    target_environment: str = Field("production", description="Target environment")


class ExpeditedPromotionRequest(BaseModel):
    """Request for expedited promotion approval."""
    priority: ExpediteePriority = Field(..., description="Priority level")
    justification: str = Field(..., min_length=10, max_length=1000, description="Justification for expedited approval")


class PromotionResponse(BaseModel):
    """Response for promotion readiness check."""
    app_id: str
    app_name: str
    current_environment: str
    target_environment: str
    is_ready: bool
    requires_approval: bool
    ready_count: int
    total_count: int
    blocking_contexts: list[str]
    estimated_ready_at: datetime | None
    contexts: list[ContextReadiness]
    message: str


class ExpeditedResponse(BaseModel):
    """Response for expedited promotion request."""
    request_id: str
    app_id: str
    app_name: str
    priority: str
    status: str
    thresholds_bypassed: list[str]
    message: str
    next_steps: list[str]


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/{app_id}/promotion", response_model=PromotionResponse)
async def check_app_promotion_readiness(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    target: str = "production",
):
    """Check if an application is ready for promotion."""
    # Get application
    result = await db.execute(
        select(Application)
        .where(Application.id == app_id)
        .where(Application.user_id == user.id)
    )
    application = result.scalar_one_or_none()

    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application not found: {app_id}",
        )

    if application.status != ApplicationStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot promote inactive application",
        )

    if application.environment.lower() == target.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application is already in {target} environment",
        )

    # Check readiness with user trust score
    readiness = await check_promotion_readiness(
        db, application, target,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )

    # Generate message
    if readiness.is_ready:
        if readiness.requires_approval:
            message = "Ready for promotion. Admin approval required for Tier 3 contexts."
        else:
            message = "Ready for promotion! All thresholds met."
    else:
        if readiness.estimated_ready_at:
            eta = readiness.estimated_ready_at.strftime("%a, %b %d at %I:%M %p")
            message = f"Not yet ready. Estimated ready: {eta}"
        else:
            message = "Not yet ready. Continue development to meet thresholds."

    return PromotionResponse(
        app_id=readiness.app_id,
        app_name=readiness.app_name,
        current_environment=readiness.current_environment,
        target_environment=readiness.target_environment,
        is_ready=readiness.is_ready,
        requires_approval=readiness.requires_approval,
        ready_count=readiness.ready_count,
        total_count=readiness.total_count,
        blocking_contexts=readiness.blocking_contexts,
        estimated_ready_at=readiness.estimated_ready_at,
        contexts=readiness.contexts,
        message=message,
    )


@router.post("/{app_id}/promotion", response_model=PromotionResponse)
async def request_promotion(
    app_id: str,
    data: PromotionRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Request promotion of an application."""
    # Get application
    result = await db.execute(
        select(Application)
        .where(Application.id == app_id)
        .where(Application.user_id == user.id)
    )
    application = result.scalar_one_or_none()

    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application not found: {app_id}",
        )

    # Check readiness with user trust score
    readiness = await check_promotion_readiness(
        db, application, data.target_environment,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )

    if not readiness.is_ready:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application not ready for promotion. Blocking contexts: {', '.join(readiness.blocking_contexts)}",
        )

    if readiness.requires_approval:
        # Submit for admin approval - create expedited request with NORMAL priority
        from app.core.promotion import ExpediteePriority as CoreExpediteePriority
        approval_request = await create_expedited_request(
            db=db,
            application=application,
            priority=CoreExpediteePriority.NORMAL,
            justification=f"Automatic approval request for promotion to {data.target_environment}",
            requester_email=user.email,
            requester_user_id=user.id,
            tenant_id=user.tenant_id,
        )
        message = f"Promotion request submitted (#{approval_request.request_id}). Awaiting admin approval for Tier 3 contexts."
    else:
        # Auto-approve and promote
        application.environment = data.target_environment
        await db.commit()
        message = f"Application promoted to {data.target_environment}!"

    return PromotionResponse(
        app_id=readiness.app_id,
        app_name=readiness.app_name,
        current_environment=application.environment,
        target_environment=data.target_environment,
        is_ready=True,
        requires_approval=readiness.requires_approval,
        ready_count=readiness.ready_count,
        total_count=readiness.total_count,
        blocking_contexts=[],
        estimated_ready_at=None,
        contexts=readiness.contexts,
        message=message,
    )


@router.post("/{app_id}/promotion/expedite", response_model=ExpeditedResponse)
async def request_expedited_promotion(
    app_id: str,
    data: ExpeditedPromotionRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Request expedited promotion approval (bypasses thresholds)."""
    # Get application
    result = await db.execute(
        select(Application)
        .where(Application.id == app_id)
        .where(Application.user_id == user.id)
    )
    application = result.scalar_one_or_none()

    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application not found: {app_id}",
        )

    if application.status != ApplicationStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot promote inactive application",
        )

    # Create expedited request (now persisted to database with calculated trust score)
    request = await create_expedited_request(
        db=db,
        application=application,
        priority=data.priority,
        justification=data.justification,
        requester_email=user.email,
        requester_user_id=user.id,
        tenant_id=user.tenant_id,
    )

    # Generate response based on priority
    next_steps = []
    if data.priority == ExpediteePriority.CRITICAL:
        message = "Critical expedited request submitted. On-call admin notified via PagerDuty."
        next_steps = [
            "On-call admin has been paged",
            "Expected response time: 15 minutes",
            f"Track request: {request.request_id}",
        ]
    elif data.priority == ExpediteePriority.HIGH:
        message = "High-priority expedited request submitted. Security team notified."
        next_steps = [
            "Security team notified via Slack",
            "Expected response time: 2 hours",
            f"Track request: {request.request_id}",
        ]
    else:
        message = "Expedited request submitted. Pending admin review."
        next_steps = [
            "Request queued for review",
            "Expected response time: 24 hours",
            f"Track request: {request.request_id}",
        ]

    return ExpeditedResponse(
        request_id=request.request_id,
        app_id=request.app_id,
        app_name=request.app_name,
        priority=request.priority.value,
        status=request.status,
        thresholds_bypassed=request.thresholds_bypassed,
        message=message,
        next_steps=next_steps,
    )
