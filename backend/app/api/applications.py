"""Application API routes.

Provides endpoints for managing SDK applications:
- Create application (generates Ed25519 keypair + tokens)
- List applications
- Get application details
- Update application
- Delete/revoke application
- Token management (rotate, revoke)
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User
from app.models.application import Application, ApplicationStatus
from app.core.application_manager import application_manager
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1/applications", tags=["applications"])


# ============================================================================
# Request/Response Models
# ============================================================================


class ApplicationCreate(BaseModel):
    """Application creation schema."""
    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    team: str = Field(..., min_length=1, max_length=64)
    environment: str = Field("development", max_length=32)
    allowed_contexts: list[str] = Field(default_factory=list)
    expires_in_days: int = Field(90, ge=1, le=365)


class ApplicationUpdate(BaseModel):
    """Application update schema."""
    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    allowed_contexts: list[str] | None = None


class ApplicationResponse(BaseModel):
    """Application response schema."""
    id: str
    name: str
    description: str | None
    team: str
    environment: str
    allowed_contexts: list[str]
    status: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    key_created_at: datetime
    has_refresh_token: bool
    refresh_token_expires_at: datetime | None

    class Config:
        from_attributes = True


class ApplicationCreateResponse(BaseModel):
    """Response when creating a new application."""
    application: ApplicationResponse
    access_token: str
    refresh_token: str
    setup_instructions: dict


class TokenInfo(BaseModel):
    """Token information response."""
    access_token_algorithm: str = "Ed25519"
    access_token_lifetime_seconds: int = 3600
    refresh_token_active: bool
    refresh_token_expires_at: datetime | None
    refresh_token_rotated_at: datetime | None
    last_used_at: datetime | None


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    """Token refresh response."""
    access_token: str
    expires_at: datetime


class TokenRotateResponse(BaseModel):
    """Token rotation response."""
    refresh_token: str
    expires_at: datetime
    message: str


# ============================================================================
# Helper Functions
# ============================================================================


def application_to_response(app: Application) -> ApplicationResponse:
    """Convert Application model to response."""
    return ApplicationResponse(
        id=app.id,
        name=app.name,
        description=app.description,
        team=app.team,
        environment=app.environment,
        allowed_contexts=app.allowed_contexts or [],
        status=app.status if isinstance(app.status, str) else app.status.value,
        created_at=app.created_at,
        expires_at=app.expires_at,
        last_used_at=app.last_used_at,
        key_created_at=app.key_created_at,
        has_refresh_token=app.refresh_token_hash is not None,
        refresh_token_expires_at=app.refresh_token_expires_at,
    )


# ============================================================================
# Helper Functions
# ============================================================================

# Context-specific example data for code generation
CONTEXT_EXAMPLES = {
    "user-pii": {
        "data": 'b"user@example.com"',
        "comment": "Encrypt user PII",
        "var": "encrypted_email",
    },
    "payment-data": {
        "data": 'b"4111-1111-1111-1111"',
        "comment": "Encrypt payment card",
        "var": "encrypted_card",
    },
    "health-data": {
        "data": 'b"Patient diagnosis: ..."',
        "comment": "Encrypt health record",
        "var": "encrypted_record",
    },
    "session-tokens": {
        "data": 'b"session_abc123..."',
        "comment": "Encrypt session token",
        "var": "encrypted_token",
    },
    "secrets": {
        "data": 'b"api_key_xyz..."',
        "comment": "Encrypt secret",
        "var": "encrypted_secret",
    },
}


def _generate_code_examples(contexts: list[str]) -> str:
    """Generate code examples based on selected contexts."""
    lines = ["from cryptoserve import crypto", ""]

    for ctx in contexts:
        example = CONTEXT_EXAMPLES.get(ctx, {
            "data": 'b"sensitive data"',
            "comment": f"Encrypt data for {ctx}",
            "var": "encrypted",
        })

        lines.append(f"# {example['comment']}")
        lines.append(f"{example['var']} = crypto.encrypt(")
        lines.append(f'    {example["data"]},')
        lines.append(f'    context="{ctx}"')
        lines.append(")")
        lines.append("")

    # Add decrypt example for first context
    if contexts:
        first_ctx = contexts[0]
        first_example = CONTEXT_EXAMPLES.get(first_ctx, {"var": "encrypted"})
        lines.append("# Decrypt when needed")
        lines.append(f'plaintext = crypto.decrypt({first_example["var"]}, context="{first_ctx}")')

    return "\n".join(lines)


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("", response_model=list[ApplicationResponse])
async def list_applications(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all applications for the current user."""
    result = await db.execute(
        select(Application)
        .where(Application.user_id == user.id)
        .order_by(Application.created_at.desc())
    )
    applications = result.scalars().all()
    return [application_to_response(app) for app in applications]


@router.post("", response_model=ApplicationCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_application(
    data: ApplicationCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new application with Ed25519 keypair and tokens."""
    application, access_token, refresh_token = await application_manager.create_application(
        db=db,
        user=user,
        name=data.name,
        description=data.description,
        team=data.team,
        environment=data.environment,
        allowed_contexts=data.allowed_contexts,
        expires_in_days=data.expires_in_days,
    )

    # Generate context-aware code examples
    code_examples = _generate_code_examples(data.allowed_contexts)

    setup_instructions = {
        "step1": {
            "title": "Set your token",
            "command": f'export CRYPTOSERVE_TOKEN="{access_token[:50]}..."',
            "note": "Store the full token securely",
        },
        "step2": {
            "title": "Install SDK",
            "command": "pip install -e ./sdk/python  # Local development",
        },
        "step3": {
            "title": "Use in your code",
            "code": code_examples,
        },
    }

    return ApplicationCreateResponse(
        application=application_to_response(application),
        access_token=access_token,
        refresh_token=refresh_token,
        setup_instructions=setup_instructions,
    )


@router.get("/{app_id}", response_model=ApplicationResponse)
async def get_application(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific application."""
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

    return application_to_response(application)


@router.patch("/{app_id}", response_model=ApplicationResponse)
async def update_application(
    app_id: str,
    data: ApplicationUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an application."""
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

    updated = await application_manager.update_application(
        db=db,
        application=application,
        name=data.name,
        description=data.description,
        allowed_contexts=data.allowed_contexts,
    )

    return application_to_response(updated)


@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_application(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete (revoke) an application."""
    success = await application_manager.revoke_application(db, app_id, user)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application not found: {app_id}",
        )


# ============================================================================
# Token Management Endpoints
# ============================================================================


@router.get("/{app_id}/tokens", response_model=TokenInfo)
async def get_token_info(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get token information for an application."""
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

    return TokenInfo(
        refresh_token_active=application.has_valid_refresh_token,
        refresh_token_expires_at=application.refresh_token_expires_at,
        refresh_token_rotated_at=application.refresh_token_rotated_at,
        last_used_at=application.last_used_at,
    )


@router.post("/{app_id}/tokens/rotate", response_model=TokenRotateResponse)
async def rotate_tokens(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Rotate refresh token for an application.

    The old refresh token will be immediately invalidated.
    You'll need to update CRYPTOSERVE_TOKEN in your application.
    """
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
            detail="Cannot rotate tokens for inactive application",
        )

    new_refresh_token = await application_manager.rotate_refresh_token(db, application)

    return TokenRotateResponse(
        refresh_token=new_refresh_token,
        expires_at=application.refresh_token_expires_at,
        message="Token rotated successfully. Update CRYPTOSERVE_TOKEN in your application.",
    )


@router.post("/{app_id}/tokens/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_tokens(
    app_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Revoke all tokens for an application.

    This immediately invalidates all access and refresh tokens.
    The application will need new tokens to continue operating.
    """
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

    await application_manager.revoke_tokens(db, application)
