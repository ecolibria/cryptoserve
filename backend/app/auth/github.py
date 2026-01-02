"""GitHub OAuth authentication."""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, status, Depends, Response, Request, Cookie
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User
from app.auth.jwt import create_access_token

# Rate limiting (optional - graceful fallback if not installed)
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)

    def rate_limit(limit_string):
        """Rate limit decorator."""
        return limiter.limit(limit_string)
except ImportError:
    limiter = None

    def rate_limit(limit_string):
        """No-op decorator when rate limiting is not available."""
        def decorator(func):
            return func
        return decorator

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth state token expiration (5 minutes)
OAUTH_STATE_EXPIRATION = 300


def generate_oauth_state() -> str:
    """Generate a signed OAuth state parameter for CSRF protection."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    data = f"{timestamp}:{nonce}"
    signature = hmac.new(
        settings.oauth_state_secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    return f"{data}:{signature}"


def verify_oauth_state(state: str) -> bool:
    """Verify the OAuth state parameter."""
    try:
        parts = state.split(":")
        if len(parts) != 3:
            return False
        timestamp, nonce, signature = parts

        # Check expiration
        if int(time.time()) - int(timestamp) > OAUTH_STATE_EXPIRATION:
            return False

        # Verify signature
        data = f"{timestamp}:{nonce}"
        expected_signature = hmac.new(
            settings.oauth_state_secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, TypeError):
        return False

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@router.get("/dev-login")
@rate_limit("5/minute")
async def dev_login(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cli_callback: str | None = None,
):
    """Development mode login - bypasses OAuth for testing.

    Args:
        cli_callback: Optional callback URL for CLI login flow.
                     If provided, redirects to this URL after auth with session info.
    """
    if not settings.dev_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev login only available in dev mode",
        )

    # Validate CLI callback URL if provided (must be localhost)
    if cli_callback:
        from urllib.parse import urlparse
        parsed = urlparse(cli_callback)
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CLI callback must be localhost",
            )

    # Ensure default tenant exists and get it
    from app.core.tenant import get_or_create_default_tenant
    default_tenant = await get_or_create_default_tenant(db)

    # Find or create dev user
    dev_github_id = 1
    result = await db.execute(select(User).where(User.github_id == dev_github_id))
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            tenant_id=default_tenant.id,
            github_id=dev_github_id,
            github_username="devuser",
            email="dev@localhost",
            avatar_url=None,
            last_login_at=datetime.now(timezone.utc),
            is_admin=True,  # Dev user is admin in dev mode
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        user.last_login_at = datetime.now(timezone.utc)
        # Ensure dev user always has admin in dev mode
        if not user.is_admin:
            user.is_admin = True
        await db.commit()

    # Create JWT token
    jwt_token = create_access_token(user.id, user.github_username)

    # Check if this is a CLI login
    if cli_callback:
        # CLI login flow - redirect to local callback with session info
        from urllib.parse import urlencode
        callback_params = urlencode({
            "session": jwt_token,
            "user": user.github_username,
        })
        callback_url = f"{cli_callback}?{callback_params}"

        return RedirectResponse(
            url=callback_url,
            status_code=status.HTTP_302_FOUND,
        )

    # Standard web login flow - redirect to frontend with token in cookie
    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
        domain=settings.cookie_domain,
    )
    return response


@router.get("/status")
async def auth_status():
    """Check auth configuration status."""
    return {
        "devMode": settings.dev_mode,
        "githubConfigured": bool(settings.github_client_id),
    }


@router.get("/github")
@rate_limit("10/minute")
async def github_login(request: Request, cli_callback: str | None = None):
    """Redirect to GitHub OAuth authorization with CSRF protection.

    Args:
        cli_callback: Optional callback URL for CLI login flow.
                     If provided, redirects to this URL after auth with session info.
    """
    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth not configured",
        )

    # Validate CLI callback URL if provided (must be localhost)
    if cli_callback:
        from urllib.parse import urlparse
        parsed = urlparse(cli_callback)
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CLI callback must be localhost",
            )

    # Generate CSRF state token
    state = generate_oauth_state()

    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": f"{settings.backend_url}/auth/github/callback",
        "scope": "read:user user:email",
        "state": state,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())

    # Store state in cookie for verification
    response = RedirectResponse(f"{GITHUB_AUTHORIZE_URL}?{query}")
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=OAUTH_STATE_EXPIRATION,
    )

    # Store CLI callback URL if provided
    if cli_callback:
        response.set_cookie(
            key="cli_callback",
            value=cli_callback,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            max_age=OAUTH_STATE_EXPIRATION,
        )

    return response


@router.get("/github/callback")
@rate_limit("10/minute")
async def github_callback(
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub OAuth callback with CSRF and domain validation."""
    from app.core.domain_service import domain_service

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code",
        )

    # Verify CSRF state parameter
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state or not verify_oauth_state(state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )

        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange code for token",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No access token in response",
            )

        # Get user info
        user_response = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )

        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get user info",
            )

        github_user = user_response.json()

        # Get ALL verified emails from GitHub
        emails_response = await client.get(
            GITHUB_EMAILS_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )

        verified_emails = []
        primary_email = None
        email_verified = False

        if emails_response.status_code == 200:
            emails = emails_response.json()
            # Collect all verified emails
            verified_emails = [
                e["email"] for e in emails
                if e.get("verified", False)
            ]
            # Find primary email
            primary_email_obj = next(
                (e for e in emails if e.get("primary")),
                None
            )
            if primary_email_obj:
                primary_email = primary_email_obj.get("email")
                email_verified = primary_email_obj.get("verified", False)

        # Fall back to user profile email if no verified emails found
        if not verified_emails and github_user.get("email"):
            verified_emails = [github_user["email"]]
            primary_email = github_user["email"]

    # Check domain authorization
    allowed_email = None
    for email in verified_emails:
        if await domain_service.is_domain_allowed(email, db):
            allowed_email = email
            break

    # If no verified email matches allowed domains, check if domain restriction applies
    if not allowed_email:
        org_settings = await domain_service.get_org_settings(db)
        if org_settings.require_domain_match and not org_settings.allow_any_github_user:
            # Get allowed domains for error message
            allowed_domains = await domain_service.get_allowed_domains(db)
            if allowed_domains:
                # Redirect to frontend with error
                cli_callback = request.cookies.get("cli_callback")
                if cli_callback:
                    # CLI login - return error to CLI
                    from urllib.parse import urlencode
                    callback_params = urlencode({
                        "error": "domain_not_allowed",
                        "message": "Your email domain is not authorized",
                    })
                    response = RedirectResponse(
                        url=f"{cli_callback}?{callback_params}",
                        status_code=status.HTTP_302_FOUND,
                    )
                    response.delete_cookie("cli_callback")
                    response.delete_cookie("oauth_state")
                    return response

                # Web login - redirect to frontend with error
                response = RedirectResponse(
                    url=f"{settings.frontend_url}/?error=domain_not_allowed",
                    status_code=status.HTTP_302_FOUND,
                )
                response.delete_cookie("oauth_state")
                return response

    # Use allowed email if found, otherwise use primary email
    email = allowed_email or primary_email
    email_domain = domain_service.extract_domain(email) if email else None

    # Ensure default tenant exists and get it
    from app.core.tenant import get_or_create_default_tenant
    default_tenant = await get_or_create_default_tenant(db)

    # Find or create user
    github_id = github_user["id"]
    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()

    # Determine if user should be admin
    should_be_admin = await domain_service.should_be_admin(email, db)

    if user:
        # Update existing user
        user.github_username = github_user["login"]
        user.email = email
        user.email_verified = email_verified
        user.email_domain = email_domain
        user.avatar_url = github_user.get("avatar_url")
        user.last_login_at = datetime.now(timezone.utc)
        # Don't demote existing admins, but promote if needed
        if should_be_admin and not user.is_admin:
            user.is_admin = True
    else:
        # Create new user with default tenant
        user = User(
            tenant_id=default_tenant.id,
            github_id=github_id,
            github_username=github_user["login"],
            email=email,
            email_verified=email_verified,
            email_domain=email_domain,
            avatar_url=github_user.get("avatar_url"),
            last_login_at=datetime.now(timezone.utc),
            is_admin=should_be_admin,
        )
        db.add(user)

    await db.commit()
    await db.refresh(user)

    # Create JWT token
    jwt_token = create_access_token(user.id, user.github_username)

    # Check if this is a CLI login (callback URL stored in cookie)
    cli_callback = request.cookies.get("cli_callback")

    if cli_callback:
        # CLI login flow - redirect to local callback with session info
        from urllib.parse import urlencode, urlparse
        parsed = urlparse(cli_callback)

        # Validate again for safety
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid CLI callback",
            )

        # Build callback URL with session token and user info
        callback_params = urlencode({
            "session": jwt_token,
            "user": user.github_username,
        })
        callback_url = f"{cli_callback}?{callback_params}"

        response = RedirectResponse(
            url=callback_url,
            status_code=status.HTTP_302_FOUND,
        )
        # Clear the CLI callback cookie
        response.delete_cookie("cli_callback")
        response.delete_cookie("oauth_state")
        return response

    # Standard web login flow - redirect to frontend with token in cookie
    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
        domain=settings.cookie_domain,
    )
    # Clear the OAuth state cookie
    response.delete_cookie("oauth_state")
    return response


@router.post("/logout")
async def logout(response: Response):
    """Log out by clearing the session cookie."""
    response.delete_cookie("access_token")
    return {"message": "Logged out"}


@router.get("/me")
async def get_me(user: User = Depends(get_db)):
    """Get current user info."""
    from app.auth.jwt import get_current_user
    # This is a placeholder - actual implementation uses dependency
    pass


# Export router
github_oauth_router = router
