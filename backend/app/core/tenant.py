"""Tenant resolution and context management for multi-tenancy.

This module provides:
1. TenantContext - Request-scoped tenant state
2. TenantMiddleware - Resolves tenant from request
3. Helper functions for tenant operations
"""

import logging
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional

from fastapi import Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.tenant import Tenant, DEFAULT_TENANT_SLUG

logger = logging.getLogger(__name__)

# Context variable for storing tenant per request
_current_tenant: ContextVar[Optional["TenantContext"]] = ContextVar(
    "current_tenant",
    default=None
)


@dataclass
class TenantContext:
    """Tenant context for the current request."""
    id: str
    slug: str
    name: str
    is_default: bool = False

    @classmethod
    def from_tenant(cls, tenant: Tenant, is_default: bool = False) -> "TenantContext":
        """Create TenantContext from a Tenant model."""
        return cls(
            id=tenant.id,
            slug=tenant.slug,
            name=tenant.name,
            is_default=is_default,
        )


def get_current_tenant() -> TenantContext:
    """Get the current tenant context.

    Returns:
        TenantContext for the current request

    Raises:
        HTTPException: If no tenant context is set
    """
    tenant = _current_tenant.get()
    if tenant is None:
        raise HTTPException(
            status_code=500,
            detail="No tenant context available"
        )
    return tenant


def get_current_tenant_id() -> str:
    """Get the current tenant ID.

    Returns:
        Tenant ID string

    Raises:
        HTTPException: If no tenant context is set
    """
    return get_current_tenant().id


def set_current_tenant(tenant: TenantContext) -> None:
    """Set the current tenant context."""
    _current_tenant.set(tenant)


def clear_current_tenant() -> None:
    """Clear the current tenant context."""
    _current_tenant.set(None)


class TenantResolutionStrategy:
    """Strategy for resolving tenant from request."""

    # Header name for explicit tenant selection
    TENANT_HEADER = "X-Tenant-ID"
    TENANT_SLUG_HEADER = "X-Tenant-Slug"

    @classmethod
    async def resolve(
        cls,
        request: Request,
        db: AsyncSession,
    ) -> Optional[Tenant]:
        """Resolve tenant from request.

        Resolution order:
        1. X-Tenant-ID header (explicit tenant ID)
        2. X-Tenant-Slug header (explicit tenant slug)
        3. Subdomain extraction (tenant.example.com)
        4. Default tenant (for single-tenant deployments)

        Args:
            request: FastAPI request
            db: Database session

        Returns:
            Tenant if found, None otherwise
        """
        # 1. Check explicit tenant ID header
        tenant_id = request.headers.get(cls.TENANT_HEADER)
        if tenant_id:
            result = await db.execute(
                select(Tenant).where(
                    Tenant.id == tenant_id,
                    Tenant.is_active == True
                )
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                logger.debug(f"Resolved tenant from header: {tenant.slug}")
                return tenant
            else:
                logger.warning(f"Tenant ID from header not found: {tenant_id}")

        # 2. Check explicit tenant slug header
        tenant_slug = request.headers.get(cls.TENANT_SLUG_HEADER)
        if tenant_slug:
            result = await db.execute(
                select(Tenant).where(
                    Tenant.slug == tenant_slug,
                    Tenant.is_active == True
                )
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                logger.debug(f"Resolved tenant from slug header: {tenant.slug}")
                return tenant
            else:
                logger.warning(f"Tenant slug from header not found: {tenant_slug}")

        # 3. Try subdomain extraction
        host = request.headers.get("host", "")
        if host:
            subdomain = cls._extract_subdomain(host)
            if subdomain and subdomain != "www":
                result = await db.execute(
                    select(Tenant).where(
                        Tenant.slug == subdomain,
                        Tenant.is_active == True
                    )
                )
                tenant = result.scalar_one_or_none()
                if tenant:
                    logger.debug(f"Resolved tenant from subdomain: {tenant.slug}")
                    return tenant

        # 4. Fall back to default tenant
        result = await db.execute(
            select(Tenant).where(
                Tenant.slug == DEFAULT_TENANT_SLUG,
                Tenant.is_active == True
            )
        )
        tenant = result.scalar_one_or_none()
        if tenant:
            logger.debug("Using default tenant")
            return tenant

        return None

    @staticmethod
    def _extract_subdomain(host: str) -> Optional[str]:
        """Extract subdomain from host.

        Examples:
            acme.cryptoserve.io -> acme
            cryptoserve.io -> None
            localhost:8003 -> None
            acme.localhost:8003 -> acme
        """
        # Remove port if present
        host = host.split(":")[0]

        # Split by dots
        parts = host.split(".")

        # localhost or single-part domain
        if len(parts) <= 1:
            return None

        # IP address
        if all(p.isdigit() for p in parts):
            return None

        # Standard domain (example.com, cryptoserve.io)
        if len(parts) == 2:
            return None

        # Subdomain present (acme.example.com, acme.cryptoserve.io)
        if len(parts) >= 3:
            return parts[0]

        return None


async def get_or_create_default_tenant(db: AsyncSession) -> Tenant:
    """Get or create the default tenant for single-tenant deployments.

    This is called during startup to ensure a default tenant exists.
    """
    result = await db.execute(
        select(Tenant).where(Tenant.slug == DEFAULT_TENANT_SLUG)
    )
    tenant = result.scalar_one_or_none()

    if tenant:
        return tenant

    # Create default tenant
    from app.config import get_settings
    settings = get_settings()

    tenant = Tenant(
        slug=DEFAULT_TENANT_SLUG,
        name="Default Organization",
        organization_name=None,
        primary_domain=None,
        allowed_domains=settings.allowed_domains.split(",") if settings.allowed_domains else [],
        require_domain_match=settings.require_domain_verification,
        allow_any_github_user=not settings.require_domain_verification,
        admin_email=settings.admin_email or None,
        is_active=True,
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    logger.info(f"Created default tenant: {tenant.id}")
    return tenant


async def resolve_tenant_dependency(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """FastAPI dependency for resolving current tenant.

    Use this in route handlers:
        @app.get("/api/example")
        async def example(tenant: TenantContext = Depends(resolve_tenant_dependency)):
            # tenant is now available
    """
    tenant = await TenantResolutionStrategy.resolve(request, db)

    if tenant is None:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve tenant. Provide X-Tenant-ID header or use a valid subdomain."
        )

    is_default = tenant.slug == DEFAULT_TENANT_SLUG
    context = TenantContext.from_tenant(tenant, is_default=is_default)
    set_current_tenant(context)

    return context


# Alias for cleaner imports
CurrentTenant = TenantContext
