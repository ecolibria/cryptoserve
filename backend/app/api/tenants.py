"""Tenant management API routes.

Allows tenant admins to manage their own tenant settings,
users, and domain configurations.
"""

from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from slugify import slugify
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Tenant, Identity, IdentityStatus, Context, AuditLog


router = APIRouter(prefix="/api/tenants", tags=["tenants"])


# --- Pydantic Schemas ---

class TenantInfo(BaseModel):
    """Tenant information response."""
    id: str
    slug: str
    name: str
    organization_name: Optional[str]
    primary_domain: Optional[str]
    allowed_domains: list[str]
    require_domain_match: bool
    allow_any_github_user: bool
    admin_email: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TenantStats(BaseModel):
    """Tenant statistics."""
    total_users: int
    admin_users: int
    total_identities: int
    active_identities: int
    total_contexts: int
    total_operations: int


class TenantUpdate(BaseModel):
    """Request to update tenant settings."""
    name: Optional[str] = None
    organization_name: Optional[str] = None
    primary_domain: Optional[str] = None
    allowed_domains: Optional[list[str]] = None
    require_domain_match: Optional[bool] = None
    allow_any_github_user: Optional[bool] = None
    admin_email: Optional[str] = None


class TenantUserSummary(BaseModel):
    """User summary for tenant listing."""
    id: str
    github_username: str
    email: Optional[str]
    avatar_url: Optional[str]
    is_admin: bool
    created_at: datetime
    last_login_at: Optional[datetime]
    identity_count: int


class InviteUserRequest(BaseModel):
    """Request to invite a user to the tenant."""
    email: str = Field(..., description="Email address to invite")
    make_admin: bool = False


class TenantCreateRequest(BaseModel):
    """Request to create a new tenant (super-admin only)."""
    name: str = Field(..., min_length=1, max_length=256)
    slug: Optional[str] = Field(None, min_length=1, max_length=64)
    organization_name: Optional[str] = None
    primary_domain: Optional[str] = None
    allowed_domains: list[str] = Field(default_factory=list)
    admin_email: Optional[str] = None
    require_domain_match: bool = True
    allow_any_github_user: bool = False


# --- Helper Functions ---

async def require_tenant_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require the user to be a tenant admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant admin privileges required",
        )
    return current_user


# --- Endpoints ---

@router.get("/current", response_model=TenantInfo)
async def get_current_tenant(
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the current user's tenant information."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    return TenantInfo(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        organization_name=tenant.organization_name,
        primary_domain=tenant.primary_domain,
        allowed_domains=tenant.allowed_domains,
        require_domain_match=tenant.require_domain_match,
        allow_any_github_user=tenant.allow_any_github_user,
        admin_email=tenant.admin_email,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.get("/current/stats", response_model=TenantStats)
async def get_current_tenant_stats(
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get statistics for the current tenant."""
    # User counts
    total_users = await db.scalar(
        select(func.count(User.id)).where(User.tenant_id == admin.tenant_id)
    )
    admin_users = await db.scalar(
        select(func.count(User.id)).where(
            User.tenant_id == admin.tenant_id,
            User.is_admin == True  # noqa: E712
        )
    )

    # Identity counts
    total_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            Identity.tenant_id == admin.tenant_id
        )
    )
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            Identity.tenant_id == admin.tenant_id,
            Identity.status == IdentityStatus.ACTIVE
        )
    )

    # Context counts
    total_contexts = await db.scalar(
        select(func.count(Context.id)).where(
            Context.tenant_id == admin.tenant_id
        )
    )

    # Operation counts
    total_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == admin.tenant_id
        )
    )

    return TenantStats(
        total_users=total_users or 0,
        admin_users=admin_users or 0,
        total_identities=total_identities or 0,
        active_identities=active_identities or 0,
        total_contexts=total_contexts or 0,
        total_operations=total_operations or 0,
    )


@router.patch("/current", response_model=TenantInfo)
async def update_current_tenant(
    update: TenantUpdate,
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update the current tenant's settings."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    # Apply updates
    if update.name is not None:
        tenant.name = update.name
    if update.organization_name is not None:
        tenant.organization_name = update.organization_name
    if update.primary_domain is not None:
        # Validate domain uniqueness
        existing = await db.execute(
            select(Tenant).where(
                Tenant.primary_domain == update.primary_domain,
                Tenant.id != tenant.id
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain already claimed by another tenant",
            )
        tenant.primary_domain = update.primary_domain
    if update.allowed_domains is not None:
        tenant.allowed_domains = update.allowed_domains
    if update.require_domain_match is not None:
        tenant.require_domain_match = update.require_domain_match
    if update.allow_any_github_user is not None:
        tenant.allow_any_github_user = update.allow_any_github_user
    if update.admin_email is not None:
        tenant.admin_email = update.admin_email

    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(tenant)

    return TenantInfo(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        organization_name=tenant.organization_name,
        primary_domain=tenant.primary_domain,
        allowed_domains=tenant.allowed_domains,
        require_domain_match=tenant.require_domain_match,
        allow_any_github_user=tenant.allow_any_github_user,
        admin_email=tenant.admin_email,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.get("/current/users", response_model=list[TenantUserSummary])
async def list_tenant_users(
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 100,
    offset: int = 0,
):
    """List all users in the current tenant."""
    result = await db.execute(
        select(User)
        .where(User.tenant_id == admin.tenant_id)
        .order_by(User.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    users = result.scalars().all()

    summaries = []
    for user in users:
        # Get identity count
        identity_count = await db.scalar(
            select(func.count(Identity.id)).where(
                Identity.user_id == user.id,
                Identity.tenant_id == admin.tenant_id
            )
        )

        summaries.append(TenantUserSummary(
            id=user.id,
            github_username=user.github_username,
            email=user.email,
            avatar_url=user.avatar_url,
            is_admin=user.is_admin,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            identity_count=identity_count or 0,
        ))

    return summaries


@router.post("/current/users/{user_id}/toggle-admin")
async def toggle_tenant_user_admin(
    user_id: str,
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Toggle admin status for a user in the tenant."""
    # Find user in same tenant
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.tenant_id == admin.tenant_id
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in your tenant",
        )

    # Prevent self-demotion (to avoid losing all admins)
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own admin status",
        )

    # Toggle admin status
    user.is_admin = not user.is_admin
    await db.commit()

    return {
        "user_id": user.id,
        "is_admin": user.is_admin,
        "message": f"User {'promoted to' if user.is_admin else 'demoted from'} admin",
    }


@router.delete("/current/users/{user_id}")
async def remove_tenant_user(
    user_id: str,
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove a user from the tenant.

    This revokes all their identities but keeps audit history.
    """
    # Find user in same tenant
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.tenant_id == admin.tenant_id
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in your tenant",
        )

    # Prevent self-removal
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the tenant",
        )

    # Revoke all user's identities
    identities_result = await db.execute(
        select(Identity).where(
            Identity.user_id == user.id,
            Identity.tenant_id == admin.tenant_id
        )
    )
    identities = identities_result.scalars().all()

    for identity in identities:
        identity.status = IdentityStatus.REVOKED

    # Remove user's tenant association (but keep user for audit trail)
    user.tenant_id = None
    user.is_admin = False

    await db.commit()

    return {
        "message": f"User {user.github_username} removed from tenant",
        "identities_revoked": len(identities),
    }


@router.get("/current/domains")
async def get_tenant_domains(
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the current tenant's domain configuration."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    return {
        "primary_domain": tenant.primary_domain,
        "allowed_domains": tenant.allowed_domains,
        "require_domain_match": tenant.require_domain_match,
        "allow_any_github_user": tenant.allow_any_github_user,
    }


@router.post("/current/domains")
async def add_tenant_domain(
    domain: str,
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a domain to the tenant's allowed list."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    # Normalize domain
    domain = domain.lower().strip()

    if domain in tenant.allowed_domains:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain already in allowed list",
        )

    tenant.allowed_domains = tenant.allowed_domains + [domain]
    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "message": f"Domain {domain} added",
        "allowed_domains": tenant.allowed_domains,
    }


@router.delete("/current/domains/{domain}")
async def remove_tenant_domain(
    domain: str,
    admin: Annotated[User, Depends(require_tenant_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove a domain from the tenant's allowed list."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    domain = domain.lower().strip()

    if domain not in tenant.allowed_domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not in allowed list",
        )

    tenant.allowed_domains = [d for d in tenant.allowed_domains if d != domain]
    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "message": f"Domain {domain} removed",
        "allowed_domains": tenant.allowed_domains,
    }


# --- Super Admin Endpoints (platform-level tenant management) ---

async def require_super_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require the user to be a super admin (default tenant admin).

    For now, super admins are admins of the 'default' tenant.
    In production, this should be a separate privilege.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    # Check if user is in default tenant (super admin)
    if current_user.tenant_id != "default":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin privileges required",
        )

    return current_user


@router.get("", response_model=list[TenantInfo])
async def list_all_tenants(
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    include_inactive: bool = False,
):
    """List all tenants (super-admin only)."""
    query = select(Tenant)
    if not include_inactive:
        query = query.where(Tenant.is_active == True)  # noqa: E712
    query = query.order_by(Tenant.created_at.desc())

    result = await db.execute(query)
    tenants = result.scalars().all()

    return [
        TenantInfo(
            id=t.id,
            slug=t.slug,
            name=t.name,
            organization_name=t.organization_name,
            primary_domain=t.primary_domain,
            allowed_domains=t.allowed_domains,
            require_domain_match=t.require_domain_match,
            allow_any_github_user=t.allow_any_github_user,
            admin_email=t.admin_email,
            is_active=t.is_active,
            created_at=t.created_at,
            updated_at=t.updated_at,
        )
        for t in tenants
    ]


@router.post("", response_model=TenantInfo, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    request: TenantCreateRequest,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new tenant (super-admin only)."""
    # Generate slug from name if not provided
    slug = request.slug or slugify(request.name, max_length=64)

    # Check slug uniqueness
    existing = await db.execute(
        select(Tenant).where(Tenant.slug == slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant with slug '{slug}' already exists",
        )

    # Check primary domain uniqueness if provided
    if request.primary_domain:
        existing_domain = await db.execute(
            select(Tenant).where(Tenant.primary_domain == request.primary_domain)
        )
        if existing_domain.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Domain '{request.primary_domain}' already claimed",
            )

    tenant = Tenant(
        id=str(uuid4()),
        slug=slug,
        name=request.name,
        organization_name=request.organization_name,
        primary_domain=request.primary_domain,
        allowed_domains=request.allowed_domains,
        admin_email=request.admin_email,
        require_domain_match=request.require_domain_match,
        allow_any_github_user=request.allow_any_github_user,
        is_active=True,
    )

    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    return TenantInfo(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        organization_name=tenant.organization_name,
        primary_domain=tenant.primary_domain,
        allowed_domains=tenant.allowed_domains,
        require_domain_match=tenant.require_domain_match,
        allow_any_github_user=tenant.allow_any_github_user,
        admin_email=tenant.admin_email,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.get("/{tenant_id}", response_model=TenantInfo)
async def get_tenant(
    tenant_id: str,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific tenant (super-admin only)."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    return TenantInfo(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        organization_name=tenant.organization_name,
        primary_domain=tenant.primary_domain,
        allowed_domains=tenant.allowed_domains,
        require_domain_match=tenant.require_domain_match,
        allow_any_github_user=tenant.allow_any_github_user,
        admin_email=tenant.admin_email,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.patch("/{tenant_id}", response_model=TenantInfo)
async def update_tenant(
    tenant_id: str,
    update: TenantUpdate,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update a tenant's settings (super-admin only)."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    # Apply updates
    if update.name is not None:
        tenant.name = update.name
    if update.organization_name is not None:
        tenant.organization_name = update.organization_name
    if update.primary_domain is not None:
        # Validate domain uniqueness
        existing = await db.execute(
            select(Tenant).where(
                Tenant.primary_domain == update.primary_domain,
                Tenant.id != tenant.id
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain already claimed by another tenant",
            )
        tenant.primary_domain = update.primary_domain
    if update.allowed_domains is not None:
        tenant.allowed_domains = update.allowed_domains
    if update.require_domain_match is not None:
        tenant.require_domain_match = update.require_domain_match
    if update.allow_any_github_user is not None:
        tenant.allow_any_github_user = update.allow_any_github_user
    if update.admin_email is not None:
        tenant.admin_email = update.admin_email

    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(tenant)

    return TenantInfo(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        organization_name=tenant.organization_name,
        primary_domain=tenant.primary_domain,
        allowed_domains=tenant.allowed_domains,
        require_domain_match=tenant.require_domain_match,
        allow_any_github_user=tenant.allow_any_github_user,
        admin_email=tenant.admin_email,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.post("/{tenant_id}/deactivate")
async def deactivate_tenant(
    tenant_id: str,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Deactivate a tenant (super-admin only).

    This suspends the tenant without deleting data.
    """
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    if tenant.slug == "default":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate the default tenant",
        )

    tenant.is_active = False
    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": f"Tenant {tenant.slug} deactivated"}


@router.post("/{tenant_id}/activate")
async def activate_tenant(
    tenant_id: str,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Activate a deactivated tenant (super-admin only)."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    tenant.is_active = True
    tenant.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": f"Tenant {tenant.slug} activated"}


@router.get("/{tenant_id}/stats", response_model=TenantStats)
async def get_tenant_stats(
    tenant_id: str,
    admin: Annotated[User, Depends(require_super_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get statistics for a specific tenant (super-admin only)."""
    # Verify tenant exists
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    # User counts
    total_users = await db.scalar(
        select(func.count(User.id)).where(User.tenant_id == tenant_id)
    )
    admin_users = await db.scalar(
        select(func.count(User.id)).where(
            User.tenant_id == tenant_id,
            User.is_admin == True  # noqa: E712
        )
    )

    # Identity counts
    total_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            Identity.tenant_id == tenant_id
        )
    )
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            Identity.tenant_id == tenant_id,
            Identity.status == IdentityStatus.ACTIVE
        )
    )

    # Context counts
    total_contexts = await db.scalar(
        select(func.count(Context.id)).where(
            Context.tenant_id == tenant_id
        )
    )

    # Operation counts
    total_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tenant_id
        )
    )

    return TenantStats(
        total_users=total_users or 0,
        admin_users=admin_users or 0,
        total_identities=total_identities or 0,
        active_identities=active_identities or 0,
        total_contexts=total_contexts or 0,
        total_operations=total_operations or 0,
    )
