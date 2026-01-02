"""Tenant model for multi-tenancy support.

Each tenant represents an isolated organization with its own:
- Users and applications
- Encryption contexts and keys
- Policies and audit logs
- Settings and access controls
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import String, DateTime, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, StringList, JSONType, GUID


class Tenant(Base):
    """Tenant for multi-tenancy isolation.

    Each tenant has its own isolated namespace for all resources.
    Users, applications, contexts, keys, and audit logs are all
    scoped to a tenant.
    """

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        GUID(),
        primary_key=True,
        default=lambda: str(uuid4())
    )

    # URL-friendly unique identifier (e.g., "acme-corp", "demo")
    slug: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True
    )

    # Display name
    name: Mapped[str] = mapped_column(String(256), nullable=False)

    # Organization branding
    organization_name: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True
    )

    # Primary domain for this tenant (e.g., "acme.com")
    # Used for automatic tenant resolution from email domains
    primary_domain: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        unique=True,
        index=True
    )

    # Allowed email domains for login (JSON array)
    # Users with matching email domains can join this tenant
    allowed_domains: Mapped[list[str]] = mapped_column(
        StringList,
        default=list,
        nullable=False
    )

    # Access control settings
    require_domain_match: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Require email domain match for new users"
    )

    allow_any_github_user: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Allow any GitHub user (dev/testing mode)"
    )

    # Initial admin email (becomes admin on first login)
    admin_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    # Tenant-specific settings (JSON for flexibility)
    settings: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        default=None,
        comment="Tenant-specific configuration"
    )

    # Tenant status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether tenant is active (can be disabled for suspension)"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships (loaded lazily to avoid circular imports)
    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="tenant",
        lazy="dynamic"
    )
    applications: Mapped[list["Application"]] = relationship(
        "Application",
        back_populates="tenant",
        lazy="dynamic"
    )
    contexts: Mapped[list["Context"]] = relationship(
        "Context",
        back_populates="tenant",
        lazy="dynamic"
    )
    policies: Mapped[list["Policy"]] = relationship(
        "Policy",
        back_populates="tenant",
        lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<Tenant {self.slug}>"

    def matches_email_domain(self, email: str) -> bool:
        """Check if an email domain is allowed for this tenant."""
        if self.allow_any_github_user:
            return True

        if not email or "@" not in email:
            return False

        domain = email.split("@")[1].lower()

        # Check primary domain
        if self.primary_domain and domain == self.primary_domain.lower():
            return True

        # Check allowed domains list
        for allowed in self.allowed_domains:
            if domain == allowed.lower():
                return True
            # Support wildcard subdomains (e.g., "*.acme.com")
            if allowed.startswith("*."):
                base_domain = allowed[2:].lower()
                if domain == base_domain or domain.endswith("." + base_domain):
                    return True

        return False


# Default tenant ID for single-tenant deployments
DEFAULT_TENANT_ID = "default"
DEFAULT_TENANT_SLUG = "default"
