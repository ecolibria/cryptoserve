"""Organization settings model for domain-based access control."""

from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, StringList, GUID


class OrganizationSettings(Base):
    """Organization-wide settings including allowed email domains.

    This is a singleton table - only one row should exist.
    """

    __tablename__ = "organization_settings"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)

    # Allowed email domains (JSON array stored as text)
    # Example: ["allstate.com", "contractor.allstate.com"]
    allowed_domains: Mapped[list[str]] = mapped_column(
        StringList,
        default=list,
        nullable=False
    )

    # Whether domain matching is required for login
    require_domain_match: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )

    # Escape hatch for dev/testing - allows any GitHub user
    allow_any_github_user: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    # Initial admin email from env var (set during bootstrap)
    admin_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    # Organization name (optional branding)
    organization_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    # --- Setup State Tracking ---

    # Whether initial admin setup has been completed
    setup_completed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    setup_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    setup_completed_by_id: Mapped[str | None] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=True
    )

    # --- Auto-Provisioning Settings ---

    # GitHub organizations whose members can auto-join
    allowed_github_orgs: Mapped[list[str]] = mapped_column(
        StringList,
        default=list,
        nullable=False
    )

    # Default role for auto-provisioned users
    default_role: Mapped[str] = mapped_column(
        String(50),
        default="developer",
        nullable=False
    )

    # Provisioning mode: domain, github_org, invitation_only, open, domain_and_github
    provisioning_mode: Mapped[str] = mapped_column(
        String(50),
        default="domain",
        nullable=False
    )

    # --- Timestamps ---

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<OrganizationSettings domains={len(self.allowed_domains)} mode={self.provisioning_mode}>"
