"""Authentication API routes.

Provides token refresh and verification endpoints for SDK clients:
- Refresh access token using refresh token
- Verify access token (for debugging)
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.application_manager import application_manager

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ============================================================================
# Request/Response Models
# ============================================================================


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    """Token refresh response."""
    access_token: str
    expires_at: datetime
    token_type: str = "bearer"


class TokenVerifyRequest(BaseModel):
    """Token verification request."""
    access_token: str


class TokenVerifyResponse(BaseModel):
    """Token verification response."""
    valid: bool
    app_id: str | None = None
    app_name: str | None = None
    team: str | None = None
    environment: str | None = None
    contexts: list[str] | None = None
    expires_at: datetime | None = None
    error: str | None = None


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
    data: TokenRefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Exchange refresh token for new access token.

    This endpoint allows SDK clients to obtain a new short-lived access token
    using their long-lived refresh token. The access token expires in 1 hour.

    The SDK should call this endpoint automatically when the access token
    is about to expire (within 5 minutes of expiry).
    """
    result = await application_manager.refresh_access_token(
        db=db,
        refresh_token=data.refresh_token,
    )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    access_token, expires_at = result

    return TokenRefreshResponse(
        access_token=access_token,
        expires_at=expires_at,
    )


@router.post("/verify", response_model=TokenVerifyResponse)
async def verify_token(
    data: TokenVerifyRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify an access token and return its claims.

    This endpoint is primarily for debugging and testing. It verifies the
    Ed25519 signature and returns the token claims if valid.

    Note: The SDK verifies tokens locally using the cached public key,
    so this endpoint is not needed for normal operation.
    """
    from app.core.token_manager import token_manager

    # First decode without verification to get app_id
    payload = token_manager.decode_token_unverified(data.access_token)
    if not payload:
        return TokenVerifyResponse(
            valid=False,
            error="Invalid token format",
        )

    # Get application
    application = await application_manager.get_application_by_access_token(
        db=db,
        access_token=data.access_token,
    )

    if not application:
        return TokenVerifyResponse(
            valid=False,
            error="Token verification failed or application not found",
        )

    # Decode expiry
    from datetime import timezone
    exp = payload.get("exp")
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None

    return TokenVerifyResponse(
        valid=True,
        app_id=payload.get("sub"),
        app_name=payload.get("name"),
        team=payload.get("team"),
        environment=payload.get("env"),
        contexts=payload.get("contexts"),
        expires_at=expires_at,
    )
