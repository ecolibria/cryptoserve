"""Context API routes.

Supports both legacy simple contexts and the new 5-layer context model.
"""

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Context
from app.schemas.context import (
    ContextConfig,
    ContextCreate as ContextCreateSchema,
    DerivedRequirements,
    AlgorithmPolicy,
    PolicyEnforcement,
)
from app.core.algorithm_resolver import resolve_algorithm

router = APIRouter(prefix="/api/contexts", tags=["contexts"])


# =============================================================================
# Response Schemas
# =============================================================================

class ContextResponse(BaseModel):
    """Context response schema with full 5-layer config."""
    name: str
    display_name: str
    description: str
    config: ContextConfig | None = None
    derived: DerivedRequirements | None = None

    # Legacy fields for backward compatibility
    data_examples: list[str] | None = None
    compliance_tags: list[str] | None = None
    algorithm: str

    # Algorithm policy enforcement
    algorithm_policy: AlgorithmPolicy | None = None
    policy_enforcement: PolicyEnforcement = PolicyEnforcement.NONE

    created_at: datetime
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class ContextListResponse(BaseModel):
    """Simplified context for list views."""
    name: str
    display_name: str
    description: str
    algorithm: str
    sensitivity: str
    quantum_resistant: bool
    compliance_tags: list[str] | None = None

    class Config:
        from_attributes = True


# =============================================================================
# Legacy Create Schema (backward compatible)
# =============================================================================

class ContextCreateLegacy(BaseModel):
    """Legacy context creation schema for backward compatibility."""
    name: str
    display_name: str
    description: str
    data_examples: list[str] | None = None
    compliance_tags: list[str] | None = None
    algorithm: str = "AES-256-GCM"


class ContextUpdateSchema(BaseModel):
    """Schema for updating an existing context."""
    name: str
    display_name: str
    description: str
    config: ContextConfig
    algorithm_policy: AlgorithmPolicy | None = None
    policy_enforcement: PolicyEnforcement | None = None


# =============================================================================
# Helper Functions
# =============================================================================

def context_to_response(ctx: Context) -> dict[str, Any]:
    """Convert Context model to response dict with computed derived requirements."""
    # Parse config if present
    config = None
    derived = None

    if ctx.config:
        try:
            config = ContextConfig.model_validate(ctx.config)
            # Compute derived requirements from config
            derived = resolve_algorithm(config)
        except Exception:
            # Fall back to cached derived if config parsing fails
            if ctx.derived:
                derived = DerivedRequirements.model_validate(ctx.derived)

    # Parse algorithm policy if present
    algorithm_policy = None
    if ctx.algorithm_policy:
        try:
            algorithm_policy = AlgorithmPolicy.model_validate(ctx.algorithm_policy)
        except Exception:
            pass

    # Build response
    response = {
        "name": ctx.name,
        "display_name": ctx.display_name,
        "description": ctx.description,
        "config": config,
        "derived": derived,
        "data_examples": ctx.data_examples,
        "compliance_tags": ctx.compliance_tags,
        "algorithm": ctx.algorithm,
        "algorithm_policy": algorithm_policy,
        "policy_enforcement": ctx.policy_enforcement or "none",
        "created_at": ctx.created_at,
        "updated_at": ctx.updated_at,
    }

    # Add computed properties for list view
    if derived:
        response["sensitivity"] = config.data_identity.sensitivity.value if config else "medium"
        response["quantum_resistant"] = derived.quantum_resistant
    else:
        response["sensitivity"] = ctx.sensitivity
        response["quantum_resistant"] = ctx.quantum_resistant

    return response


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("", response_model=list[ContextListResponse])
async def list_contexts(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all available contexts for the user's tenant."""
    result = await db.execute(
        select(Context)
        .where(Context.tenant_id == user.tenant_id)
        .order_by(Context.name)
    )
    contexts = result.scalars().all()
    return [context_to_response(ctx) for ctx in contexts]


@router.get("/{name}", response_model=ContextResponse)
async def get_context(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific context with full 5-layer configuration."""
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    return context_to_response(context)


@router.post("", response_model=ContextResponse, status_code=status.HTTP_201_CREATED)
async def create_context(
    data: ContextCreateSchema,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new context with 5-layer configuration.

    The algorithm is automatically resolved based on the configuration.
    """
    # Check if context already exists for this tenant
    result = await db.execute(
        select(Context).where(
            Context.name == data.name,
            Context.tenant_id == user.tenant_id
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Context already exists: {data.name}",
        )

    # Resolve algorithm from config
    derived = resolve_algorithm(data.config)

    # Extract legacy fields from config for backward compatibility
    compliance_tags = data.config.regulatory.frameworks if data.config.regulatory else []
    data_examples = data.config.data_identity.examples if data.config.data_identity else []

    context = Context(
        tenant_id=user.tenant_id,
        name=data.name,
        display_name=data.display_name,
        description=data.description,
        config=data.config.model_dump(),
        derived=derived.model_dump(),
        algorithm=derived.resolved_algorithm,
        compliance_tags=compliance_tags,
        data_examples=data_examples,
    )

    db.add(context)
    await db.commit()
    await db.refresh(context)

    return context_to_response(context)


@router.post("/legacy", response_model=ContextResponse, status_code=status.HTTP_201_CREATED)
async def create_context_legacy(
    data: ContextCreateLegacy,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a context using legacy simple schema (backward compatible)."""
    # Check if context already exists for this tenant
    result = await db.execute(
        select(Context).where(
            Context.name == data.name,
            Context.tenant_id == user.tenant_id
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Context already exists: {data.name}",
        )

    context = Context(
        tenant_id=user.tenant_id,
        name=data.name,
        display_name=data.display_name,
        description=data.description,
        data_examples=data.data_examples,
        compliance_tags=data.compliance_tags,
        algorithm=data.algorithm,
    )

    db.add(context)
    await db.commit()
    await db.refresh(context)

    return context_to_response(context)


@router.put("/{name}", response_model=ContextResponse)
async def update_context(
    name: str,
    data: ContextUpdateSchema,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an existing context's configuration."""
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    # Re-resolve algorithm from updated config
    derived = resolve_algorithm(data.config)

    # Update fields
    context.display_name = data.display_name
    context.description = data.description
    context.config = data.config.model_dump()
    context.derived = derived.model_dump()
    context.algorithm = derived.resolved_algorithm
    context.compliance_tags = data.config.regulatory.frameworks if data.config.regulatory else []
    context.data_examples = data.config.data_identity.examples if data.config.data_identity else []
    context.updated_at = datetime.now(timezone.utc)

    # Update algorithm policy fields
    if data.algorithm_policy is not None:
        context.algorithm_policy = data.algorithm_policy.model_dump()
    else:
        context.algorithm_policy = None

    if data.policy_enforcement is not None:
        context.policy_enforcement = data.policy_enforcement.value

    await db.commit()
    await db.refresh(context)

    return context_to_response(context)


@router.get("/{name}/resolve", response_model=DerivedRequirements)
async def resolve_context_algorithm(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the derived requirements for a context.

    Returns the algorithm resolution with full rationale.
    """
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    if not context.config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Context {name} has no 5-layer configuration",
        )

    config = ContextConfig.model_validate(context.config)
    return resolve_algorithm(config)
