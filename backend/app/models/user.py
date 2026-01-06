"""User model for GitHub-authenticated users."""

from datetime import datetime, timezone
from uuid import uuid4
from typing import TYPE_CHECKING

from sqlalchemy import String, DateTime, BigInteger, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, GUID

if TYPE_CHECKING:
    from app.core.rbac import Role, Permission


class User(Base):
    """User account linked to GitHub."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        GUID(),
        primary_key=True,
        default=lambda: str(uuid4())
    )

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    github_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    github_username: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # RBAC fields
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    role: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        default="developer",
        doc="User role: owner, admin, developer, viewer, service_account"
    )
    custom_permissions: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
        default=None,
        doc="Additional permissions beyond role defaults"
    )
    denied_permissions: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
        default=None,
        doc="Permissions explicitly denied (overrides role)"
    )

    # Provisioning tracking
    provisioning_source: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        doc="How user was provisioned: first_user, domain, github_org, invitation, admin"
    )
    invitation_id: Mapped[str | None] = mapped_column(
        GUID(),
        ForeignKey("user_invitations.id"),
        nullable=True
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship(
        "Tenant",
        back_populates="users",
        lazy="selectin"
    )
    identities: Mapped[list["Identity"]] = relationship(
        "Identity",
        back_populates="user",
        lazy="selectin"
    )
    applications: Mapped[list["Application"]] = relationship(
        "Application",
        back_populates="user",
        lazy="selectin"
    )
    teams: Mapped[list["Team"]] = relationship(
        "Team",
        secondary="user_teams",
        back_populates="users",
        lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<User {self.github_username}>"
