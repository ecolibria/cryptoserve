"""Authentication API routes.

Provides token refresh, verification, and revocation endpoints:
- Refresh access token using refresh token
- Verify access token (for debugging)
- Revoke access token (logout / token invalidation)
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.application_manager import application_manager
from app.auth.jwt import (
    get_current_user,
    verify_token as jwt_verify_token,
    revoke_token_db,
)
from app.models import User
from app.core.slowapi_limiter import limiter

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


class TokenRevokeRequest(BaseModel):
    """Token revocation request."""

    token: str | None = None


class TokenRevokeResponse(BaseModel):
    """Token revocation response."""

    revoked: bool


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/refresh", response_model=TokenRefreshResponse)
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
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
@limiter.limit("30/minute")
async def verify_token(
    request: Request,
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


@router.post("/revoke", response_model=TokenRevokeResponse)
@limiter.limit("10/minute")
async def revoke_token_endpoint(
    request: Request,
    data: TokenRevokeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Revoke a JWT access token.

    If a token is provided in the request body, that token is revoked.
    Otherwise, the caller's current token (from header or cookie) is revoked.

    Requires authentication.
    """
    token_to_revoke = data.token
    if not token_to_revoke:
        # Revoke the current token from header or cookie
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token_to_revoke = auth_header[7:]
        else:
            token_to_revoke = request.cookies.get("access_token")

    if not token_to_revoke:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token provided and no current token found",
        )

    payload = jwt_verify_token(token_to_revoke)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )

    # Verify the token belongs to the authenticated user
    token_user_id = payload.get("sub")
    if token_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot revoke tokens belonging to other users",
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token does not contain a jti claim",
        )

    # Persist revocation to database (survives restarts)
    from datetime import datetime, timezone

    exp = payload.get("exp")
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc)
    await revoke_token_db(db, jti, expires_at)
    return TokenRevokeResponse(revoked=True)
