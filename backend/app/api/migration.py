"""Algorithm Migration API.

Provides endpoints for analyzing algorithm usage and executing migrations
with intelligent recommendations and risk assessments.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.crypto import get_sdk_identity
from app.models import Identity, Context, MigrationHistory
from app.core.migration_advisor import (
    MigrationAdvisor,
    MigrationAssessment,
    MigrationPlan,
    MigrationPreview,
    Recommendation,
)
from app.core.crypto_registry import crypto_registry


router = APIRouter(prefix="/api/migration", tags=["migration"])


# Request schemas
class MigrateContextRequest(BaseModel):
    """Request to migrate a single context."""
    contextName: str
    newAlgorithm: str


class BulkMigrateRequest(BaseModel):
    """Request to migrate all contexts using a specific algorithm."""
    fromAlgorithm: str
    toAlgorithm: str


class SimulateRequest(BaseModel):
    """Request to simulate a migration."""
    contextName: str
    newAlgorithm: str


# Response schemas
class MigrationResult(BaseModel):
    """Result of a migration operation."""
    success: bool
    contextName: str
    previousAlgorithm: str
    newAlgorithm: str
    message: str


class BulkMigrationResult(BaseModel):
    """Result of a bulk migration operation."""
    success: bool
    migratedCount: int
    failedCount: int
    results: list[MigrationResult]


class MigrationHistoryEntry(BaseModel):
    """Entry in migration history."""
    contextName: str
    previousAlgorithm: str
    newAlgorithm: str
    migratedAt: datetime
    migratedBy: str
    success: bool


@router.get("/assessment", response_model=MigrationAssessment)
async def get_assessment(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get full migration assessment for the current tenant.

    Returns a comprehensive analysis including:
    - Overall risk score and level
    - Prioritized recommendations
    - Quantum readiness percentage
    - Categories of affected contexts
    """
    advisor = MigrationAdvisor(db)
    assessment = await advisor.analyze_tenant(str(identity.tenant_id))
    return assessment


@router.get("/recommendations", response_model=list[Recommendation])
async def get_recommendations(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get prioritized list of migration recommendations.

    Returns only contexts that need migration, sorted by risk score.
    """
    advisor = MigrationAdvisor(db)
    assessment = await advisor.analyze_tenant(str(identity.tenant_id))
    return assessment.recommendations


@router.get("/plan/{context_name}", response_model=MigrationPlan)
async def get_migration_plan(
    context_name: str,
    target_algorithm: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get detailed migration plan for a specific context.

    Args:
        context_name: Name of the context to migrate
        target_algorithm: Algorithm to migrate to

    Returns step-by-step plan with warnings and rollback steps.
    """
    # Get context
    result = await db.execute(
        select(Context).where(
            Context.tenant_id == identity.tenant_id,
            Context.name == context_name,
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context '{context_name}' not found",
        )

    advisor = MigrationAdvisor(db)
    plan = await advisor.generate_migration_plan(context, target_algorithm)
    return plan


@router.post("/simulate", response_model=MigrationPreview)
async def simulate_migration(
    request: SimulateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Simulate a migration to preview impact.

    This is a dry-run that shows what would change without
    actually executing the migration.
    """
    # Get context
    result = await db.execute(
        select(Context).where(
            Context.tenant_id == identity.tenant_id,
            Context.name == request.contextName,
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context '{request.contextName}' not found",
        )

    advisor = MigrationAdvisor(db)
    preview = await advisor.preview_migration(context, request.newAlgorithm)
    return preview


@router.post("/execute", response_model=MigrationResult)
async def execute_migration(
    request: MigrateContextRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Execute a migration for a single context.

    This updates the context's algorithm and triggers key rotation if needed.
    """
    # Get context
    result = await db.execute(
        select(Context).where(
            Context.tenant_id == identity.tenant_id,
            Context.name == request.contextName,
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context '{request.contextName}' not found",
        )

    # Validate new algorithm
    new_algo = crypto_registry.get(request.newAlgorithm)
    if not new_algo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Algorithm '{request.newAlgorithm}' not found in registry",
        )

    # Preview to check if we can proceed
    advisor = MigrationAdvisor(db)
    preview = await advisor.preview_migration(context, request.newAlgorithm)

    if not preview.canProceed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot proceed with migration: {', '.join(preview.warnings)}",
        )

    # Execute migration
    previous_algorithm = context.algorithm
    context.algorithm = request.newAlgorithm
    context.updated_at = datetime.now(timezone.utc)

    # Update derived if using 5-layer config
    if context.derived:
        context.derived["resolved_algorithm"] = request.newAlgorithm

    # Log the migration
    history = MigrationHistory(
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
        action="algorithm_migration",
        context_name=context.name,
        previous_algorithm=previous_algorithm or "unknown",
        new_algorithm=request.newAlgorithm,
        success=True,
    )
    db.add(history)

    await db.commit()

    return MigrationResult(
        success=True,
        contextName=context.name,
        previousAlgorithm=previous_algorithm or "unknown",
        newAlgorithm=request.newAlgorithm,
        message=f"Successfully migrated '{context.name}' to {request.newAlgorithm}",
    )


@router.post("/execute-bulk", response_model=BulkMigrationResult)
async def execute_bulk_migration(
    request: BulkMigrateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Execute migration for all contexts using a specific algorithm.

    Migrates all contexts using fromAlgorithm to toAlgorithm.
    Returns detailed results for each context.
    """
    # Validate target algorithm
    new_algo = crypto_registry.get(request.toAlgorithm)
    if not new_algo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Algorithm '{request.toAlgorithm}' not found in registry",
        )

    # Get all contexts using the source algorithm
    result = await db.execute(
        select(Context).where(
            Context.tenant_id == identity.tenant_id,
            Context.algorithm == request.fromAlgorithm,
        )
    )
    contexts = result.scalars().all()

    if not contexts:
        return BulkMigrationResult(
            success=True,
            migratedCount=0,
            failedCount=0,
            results=[],
        )

    results = []
    migrated = 0
    failed = 0

    for context in contexts:
        try:
            previous = context.algorithm
            context.algorithm = request.toAlgorithm
            context.updated_at = datetime.now(timezone.utc)

            if context.derived:
                context.derived["resolved_algorithm"] = request.toAlgorithm

            results.append(MigrationResult(
                success=True,
                contextName=context.name,
                previousAlgorithm=previous or "unknown",
                newAlgorithm=request.toAlgorithm,
                message=f"Migrated successfully",
            ))
            migrated += 1
        except Exception as e:
            results.append(MigrationResult(
                success=False,
                contextName=context.name,
                previousAlgorithm=context.algorithm or "unknown",
                newAlgorithm=request.toAlgorithm,
                message=str(e),
            ))
            failed += 1

    # Log bulk migration
    history = MigrationHistory(
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
        action="bulk_algorithm_migration",
        context_name=None,  # Bulk migration
        previous_algorithm=request.fromAlgorithm,
        new_algorithm=request.toAlgorithm,
        success=failed == 0,
        details={
            "migrated_count": migrated,
            "failed_count": failed,
        },
    )
    db.add(history)

    await db.commit()

    return BulkMigrationResult(
        success=failed == 0,
        migratedCount=migrated,
        failedCount=failed,
        results=results,
    )


@router.get("/history", response_model=list[MigrationHistoryEntry])
async def get_migration_history(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
):
    """Get migration history for the current tenant.

    Returns past migrations sorted by date (most recent first).
    """
    result = await db.execute(
        select(MigrationHistory)
        .where(MigrationHistory.tenant_id == identity.tenant_id)
        .order_by(MigrationHistory.migrated_at.desc())
        .limit(limit)
    )
    records = result.scalars().all()

    history = []
    for record in records:
        # Handle both single and bulk migrations
        if record.action == "algorithm_migration":
            history.append(MigrationHistoryEntry(
                contextName=record.context_name or "unknown",
                previousAlgorithm=record.previous_algorithm,
                newAlgorithm=record.new_algorithm,
                migratedAt=record.migrated_at,
                migratedBy=str(record.user_id),
                success=record.success,
            ))
        else:
            # Bulk migration - create entry for the operation
            details = record.details or {}
            history.append(MigrationHistoryEntry(
                contextName=f"Bulk: {details.get('migrated_count', 0)} contexts",
                previousAlgorithm=record.previous_algorithm,
                newAlgorithm=record.new_algorithm,
                migratedAt=record.migrated_at,
                migratedBy=str(record.user_id),
                success=record.success,
            ))

    return history
