"""User invitation model for email-based invitations."""

from datetime import datetime, timezone, timedelta
from enum import Enum
from uuid import uuid4

from sqlalchemy import String, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, GUID


class InvitationStatus(str, Enum):
    """Invitation status."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class UserInvitation(Base):
    """Email-based user invitation.

    Invitations allow admins to invite specific users by email.
    Invitations expire after a configurable period (default 7 days).
    """

    __tablename__ = "user_invitations"

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

    # Invitation details
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )
    role: Mapped[str] = mapped_column(
        String(50),
        default="developer",
        nullable=False,
        doc="Role to assign on acceptance: owner, admin, developer, viewer"
    )

    # Invitation token (secure random token for URL)
    token: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True
    )

    # Status tracking
    status: Mapped[str] = mapped_column(
        String(16),
        default=InvitationStatus.PENDING.value,
        nullable=False
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc) + timedelta(days=7)
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Audit trail
    invited_by_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=False
    )
    accepted_by_user_id: Mapped[str | None] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=True
    )

    # Relationships (lazy loaded to avoid circular imports)
    tenant: Mapped["Tenant"] = relationship(
        "Tenant",
        lazy="selectin"
    )
    invited_by: Mapped["User"] = relationship(
        "User",
        foreign_keys=[invited_by_id],
        lazy="selectin"
    )
    accepted_by_user: Mapped["User"] = relationship(
        "User",
        foreign_keys=[accepted_by_user_id],
        lazy="selectin"
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_invitations_tenant_status", "tenant_id", "status"),
        Index("ix_invitations_email_status", "email", "status"),
    )

    def __repr__(self) -> str:
        return f"<UserInvitation {self.email} ({self.status})>"

    @property
    def is_expired(self) -> bool:
        """Check if invitation has expired."""
        now = datetime.now(timezone.utc)
        # Handle timezone-naive expires_at from database
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @property
    def is_valid(self) -> bool:
        """Check if invitation can be accepted."""
        return (
            self.status == InvitationStatus.PENDING.value
            and not self.is_expired
        )


# Type hints for relationships (avoid circular imports)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models import Tenant, User
