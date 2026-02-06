"""JWT token handling for user sessions."""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User
from app.models.revoked_token import RevokedToken

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer(auto_error=False)

# In-memory cache for fast revocation checks (populated from DB on startup)
# This avoids a DB query on every authenticated request while still being persistent
_revoked_tokens_cache: set[str] = set()


async def revoke_token_db(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    """Persist a revoked token to the database and update the cache."""
    record = RevokedToken(jti=jti, expires_at=expires_at)
    db.add(record)
    await db.commit()
    _revoked_tokens_cache.add(jti)


def revoke_token(jti: str) -> None:
    """Add a token's jti to the in-memory revocation cache.

    For backward compatibility. Prefer revoke_token_db() for persistence.
    """
    _revoked_tokens_cache.add(jti)


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked by its jti."""
    return jti in _revoked_tokens_cache


async def load_revoked_tokens(db: AsyncSession) -> None:
    """Load non-expired revoked tokens from the database into the cache.

    Call this at application startup to restore revocation state.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(select(RevokedToken.jti).where(RevokedToken.expires_at > now))
    jtis = result.scalars().all()
    _revoked_tokens_cache.update(jtis)
    logger.info(f"Loaded {len(jtis)} revoked tokens from database")


async def cleanup_expired_tokens(db: AsyncSession) -> int:
    """Remove expired revoked tokens from the database.

    Returns the number of tokens cleaned up.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(delete(RevokedToken).where(RevokedToken.expires_at <= now))
    await db.commit()
    count = result.rowcount
    if count:
        logger.info(f"Cleaned up {count} expired revoked tokens")
    return count


def create_access_token(user_id: str, github_username: str) -> str:
    """Create JWT access token for user session."""
    expires = datetime.now(timezone.utc) + timedelta(days=settings.jwt_expiration_days)
    payload = {
        "sub": user_id,
        "username": github_username,
        "exp": expires,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_token(token: str) -> dict | None:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
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

    # Check if the token has been revoked
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
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
    token = None

    # Try Authorization header first (SDK client)
    if credentials:
        token = credentials.credentials

        # Check if this is an SDK identity token (not a JWT)
        # SDK tokens are UUIDs without dots (JWT has 3 dot-separated parts)
        if token and "." not in token:
            # This looks like an SDK identity token
            from app.core.identity_manager import identity_manager

            identity = await identity_manager.get_identity_by_token(db, token)
            if identity:
                # Get the user who owns this identity
                user_result = await db.execute(select(User).where(User.id == identity.user_id))
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

    # Check if the token has been revoked
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
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
