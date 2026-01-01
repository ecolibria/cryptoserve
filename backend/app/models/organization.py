"""Organization settings model for domain-based access control."""

from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, StringList


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
        return f"<OrganizationSettings domains={len(self.allowed_domains)}>"
