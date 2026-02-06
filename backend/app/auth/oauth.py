"""Unified OAuth Router.

Provides multi-provider OAuth authentication using the provider abstraction.
Supports GitHub, Google, Azure AD, Okta, and generic OIDC.
"""

import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User, UserInvitation
from app.auth.jwt import create_access_token
from app.auth.providers import get_provider
from app.auth.providers.registry import list_providers
from app.core.slowapi_limiter import limiter

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth state token expiration (5 minutes)
OAUTH_STATE_EXPIRATION = 300


def generate_oauth_state(provider: str) -> str:
    """Generate a signed OAuth state parameter for CSRF protection.

    Includes the provider name to prevent cross-provider attacks.
    """
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    data = f"{provider}:{timestamp}:{nonce}"
    signature = hmac.new(settings.oauth_state_secret.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}:{signature}"


def verify_oauth_state(state: str) -> tuple[bool, str | None]:
    """Verify the OAuth state parameter.

    Returns:
        Tuple of (is_valid, provider_name)
    """
    try:
        parts = state.split(":")
        if len(parts) != 4:
            return False, None
        provider, timestamp, nonce, signature = parts

        # Check expiration
        if int(time.time()) - int(timestamp) > OAUTH_STATE_EXPIRATION:
            return False, None

        # Verify signature
        data = f"{provider}:{timestamp}:{nonce}"
        expected_signature = hmac.new(settings.oauth_state_secret.encode(), data.encode(), hashlib.sha256).hexdigest()[
            :16
        ]

        if not hmac.compare_digest(signature, expected_signature):
            return False, None

        return True, provider
    except (ValueError, TypeError):
        return False, None


@router.get("/providers")
async def get_available_providers():
    """List available OAuth providers.

    Returns the list of configured and enabled OAuth providers
    that users can use to authenticate.
    """
    providers = list_providers()
    return {
        "providers": providers,
        "dev_mode": settings.dev_mode,
    }


@router.get("/status")
async def auth_status():
    """Check auth configuration status."""
    providers = list_providers()
    return {
        "dev_mode": settings.dev_mode,
        "providers_configured": len(providers),
        "providers": [p["name"] for p in providers],
    }


@router.get("/login/{provider}")
@limiter.limit("10/minute")
async def oauth_login(
    provider: str,
    request: Request,
    cli_callback: str | None = None,
):
    """Initiate OAuth login with specified provider.

    Args:
        provider: OAuth provider name (github, google, azure_ad, okta, oidc)
        cli_callback: Optional callback URL for CLI login flow
    """
    oauth_provider = get_provider(provider)
    if not oauth_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown or unconfigured provider: {provider}. "
            f"Available: {[p['name'] for p in list_providers()]}",
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

    # Generate CSRF state token (includes provider name)
    state = generate_oauth_state(provider)

    # Build redirect URI
    redirect_uri = f"{settings.backend_url}/auth/callback/{provider}"

    # Get authorization URL from provider
    auth_url = await oauth_provider.get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
    )

    # Create redirect response with state cookie
    response = RedirectResponse(auth_url)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=OAUTH_STATE_EXPIRATION,
    )

    # Store CLI callback URL if provided
    if cli_callback:
        response.set_cookie(
            key="cli_callback",
            value=cli_callback,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=OAUTH_STATE_EXPIRATION,
        )

    return response


@router.get("/callback/{provider}")
@limiter.limit("10/minute")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle OAuth callback from provider.

    This is the redirect target after user authorizes with the provider.
    """
    from app.core.domain_service import domain_service
    from app.core.onboarding_service import onboarding_service
    from app.core.tenant import get_or_create_default_tenant

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code",
        )

    # Verify CSRF state parameter
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter",
        )

    is_valid, state_provider = verify_oauth_state(state)
    if not is_valid or state_provider != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # Get provider
    oauth_provider = get_provider(provider)
    if not oauth_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}",
        )

    # Exchange code for tokens
    redirect_uri = f"{settings.backend_url}/auth/callback/{provider}"
    try:
        token_data = await oauth_provider.exchange_code(code, redirect_uri)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    access_token = token_data.get("access_token")
    id_token = token_data.get("id_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No access token in response",
        )

    # Get user info from provider
    try:
        user_info = await oauth_provider.get_user_info(access_token, id_token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Use primary email
    email = user_info.email
    email_domain = domain_service.extract_domain(email) if email else None

    # Check auto-provisioning for new users
    # (existing users are handled below)
    should_provision, provision_role, provision_source = await onboarding_service.check_auto_provisioning(
        db=db,
        email=email,
        github_orgs=user_info.groups,  # GitHub orgs come through groups
    )

    # Get or create default tenant
    default_tenant = await get_or_create_default_tenant(db)

    # Create a unique provider-specific ID (e.g., "github:12345")
    # This allows users to have accounts from multiple providers

    # Find user by provider ID (check github_id for backwards compatibility with GitHub)
    user = None
    if provider == "github":
        # Check legacy github_id field for existing GitHub users
        result = await db.execute(select(User).where(User.github_id == int(user_info.provider_id)))
        user = result.scalar_one_or_none()

    # If not found and we have email, try to find by email (account linking)
    if not user and email:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

    if user:
        # Update existing user
        user.github_username = user_info.username
        user.email = email
        user.email_verified = user_info.email_verified
        user.email_domain = email_domain
        user.avatar_url = user_info.avatar_url
        user.last_login_at = datetime.now(timezone.utc)

        # For GitHub, ensure github_id is set
        if provider == "github" and not user.github_id:
            user.github_id = int(user_info.provider_id)

        # Don't demote existing admins, but promote if first user
        if provision_source == "first_user" and not user.is_admin:
            user.is_admin = True
            user.role = "admin"
    else:
        # New user - check if they should be provisioned
        if not should_provision:
            cli_callback = request.cookies.get("cli_callback")
            if cli_callback:
                from urllib.parse import urlencode

                callback_params = urlencode(
                    {
                        "error": "not_authorized",
                        "message": "You are not authorized to access this system. Contact an administrator for an invitation.",
                    }
                )
                response = RedirectResponse(
                    url=f"{cli_callback}?{callback_params}",
                    status_code=status.HTTP_302_FOUND,
                )
                response.delete_cookie("cli_callback")
                response.delete_cookie("oauth_state")
                return response

            response = RedirectResponse(
                url=f"{settings.frontend_url}/?error=not_authorized",
                status_code=status.HTTP_302_FOUND,
            )
            response.delete_cookie("oauth_state")
            return response

        # Create new user with provisioning info
        github_id = int(user_info.provider_id) if provider == "github" else 0
        is_admin = provision_source == "first_user" or provision_role in ["admin", "owner"]
        user = User(
            tenant_id=default_tenant.id,
            github_id=github_id,
            github_username=user_info.username,
            email=email,
            email_verified=user_info.email_verified,
            email_domain=email_domain,
            avatar_url=user_info.avatar_url,
            last_login_at=datetime.now(timezone.utc),
            is_admin=is_admin,
            role=provision_role,
            provisioning_source=provision_source,
        )
        db.add(user)

        # If provisioned via invitation, accept it
        if provision_source == "invitation" and email:
            from app.models.invitation import InvitationStatus

            invitation_result = await db.execute(
                select(UserInvitation).where(
                    UserInvitation.email == email.lower(),
                    UserInvitation.status == InvitationStatus.PENDING.value,
                )
            )
            invitation = invitation_result.scalar_one_or_none()
            if invitation and invitation.is_valid:
                await db.flush()  # Ensure user has ID
                await onboarding_service.accept_invitation(db, invitation, user)

    await db.commit()
    await db.refresh(user)

    # Sync user's teams from OIDC groups
    if user_info.groups:
        from app.core.team_service import team_service
        from app.models import TeamSource

        await team_service.sync_user_teams(
            db=db,
            user=user,
            team_names=user_info.groups,
            source=TeamSource.GITHUB if provider == "github" else TeamSource.OIDC,
        )
        await db.commit()

    # Create JWT token
    jwt_token = create_access_token(user.id, user.github_username)

    # Check if this is a CLI login
    cli_callback = request.cookies.get("cli_callback")

    if cli_callback:
        from urllib.parse import urlencode, urlparse

        parsed = urlparse(cli_callback)

        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid CLI callback",
            )

        callback_params = urlencode(
            {
                "session": jwt_token,
                "user": user.github_username,
            }
        )
        callback_url = f"{cli_callback}?{callback_params}"

        response = RedirectResponse(
            url=callback_url,
            status_code=status.HTTP_302_FOUND,
        )
        response.delete_cookie("cli_callback")
        response.delete_cookie("oauth_state")
        return response

    # Standard web login flow
    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
        domain=settings.cookie_domain,
    )
    response.delete_cookie("oauth_state")
    return response


# Backwards compatibility aliases for GitHub
@router.get("/github")
@limiter.limit("10/minute")
async def github_login(request: Request, cli_callback: str | None = None):
    """Redirect to GitHub OAuth (backwards compatibility).

    New code should use /auth/login/github instead.
    """
    return await oauth_login("github", request, cli_callback)


@router.get("/github/callback")
@limiter.limit("10/minute")
async def github_callback(
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub OAuth callback (backwards compatibility).

    New code should use /auth/callback/github instead.
    """
    return await oauth_callback("github", code, state, request, db)


@router.get("/dev-login")
@limiter.limit("5/minute")
async def dev_login(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cli_callback: str | None = None,
):
    """Development mode login - bypasses OAuth for testing."""
    if not settings.dev_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev login only available in dev mode",
        )

    if cli_callback:
        from urllib.parse import urlparse

        parsed = urlparse(cli_callback)
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CLI callback must be localhost",
            )

    from app.core.tenant import get_or_create_default_tenant

    default_tenant = await get_or_create_default_tenant(db)

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
            is_admin=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        user.last_login_at = datetime.now(timezone.utc)
        if not user.is_admin:
            user.is_admin = True
        await db.commit()

    # Add dev user to dev team
    from app.core.team_service import team_service

    dev_team = await team_service.get_or_create_dev_team(db, default_tenant.id)
    if dev_team not in user.teams:
        user.teams.append(dev_team)
        await db.commit()

    jwt_token = create_access_token(user.id, user.github_username)

    logger.warning(
        "Dev login activated",
        extra={
            "event": "dev_login",
            "client_ip": request.client.host if request.client else "unknown",
            "user_id": user.id if hasattr(user, 'id') else "dev-admin",
        }
    )

    if cli_callback:
        from urllib.parse import urlencode

        callback_params = urlencode(
            {
                "session": jwt_token,
                "user": user.github_username,
            }
        )
        callback_url = f"{cli_callback}?{callback_params}"

        return RedirectResponse(
            url=callback_url,
            status_code=status.HTTP_302_FOUND,
        )

    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
        domain=settings.cookie_domain,
    )
    return response


@router.post("/logout")
async def logout(response: RedirectResponse):
    """Log out by clearing the session cookie."""
    response = RedirectResponse(
        url=f"{settings.frontend_url}/",
        status_code=status.HTTP_302_FOUND,
    )
    response.delete_cookie("access_token")
    return response
