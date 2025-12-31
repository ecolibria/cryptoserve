"""JWT token handling for user sessions."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User

settings = get_settings()
security = HTTPBearer(auto_error=False)


def create_access_token(user_id: str, github_username: str) -> str:
    """Create JWT access token for user session."""
    expires = datetime.now(timezone.utc) + timedelta(days=settings.jwt_expiration_days)
    payload = {
        "sub": user_id,
        "username": github_username,
        "exp": expires,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_token(token: str) -> dict | None:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Get current authenticated user from JWT token."""
    token = None

    # Try Authorization header first
    if credentials:
        token = credentials.credentials

    # Fall back to cookie
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


async def get_current_user_optional(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User | None:
    """Get current user if authenticated, None otherwise."""
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


async def get_dashboard_or_sdk_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Get current user from either JWT cookie (dashboard) or SDK Bearer token.

    This allows developer tools to be used from both:
    1. The web dashboard (JWT cookie auth)
    2. SDK clients (Bearer token with identity API key)
    """
    from app.models import Identity

    token = None

    # Try Authorization header first (SDK client)
    if credentials:
        token = credentials.credentials

        # Check if this is an SDK identity token (not a JWT)
        # SDK tokens are UUIDs without dots (JWT has 3 dot-separated parts)
        if token and "." not in token:
            # This looks like an SDK identity token, try to find the identity
            result = await db.execute(
                select(Identity).where(Identity.api_key == token)
            )
            identity = result.scalar_one_or_none()
            if identity:
                # Get the user who owns this identity
                user_result = await db.execute(
                    select(User).where(User.id == identity.user_id)
                )
                user = user_result.scalar_one_or_none()
                if user:
                    return user

    # Try cookie-based JWT auth (dashboard)
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Try JWT verification
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user
