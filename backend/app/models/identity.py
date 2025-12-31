"""Identity model for SDK credentials."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, StringList


class IdentityType(str, Enum):
    """Type of identity."""
    DEVELOPER = "developer"
    SERVICE = "service"


class IdentityStatus(str, Enum):
    """Status of identity."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Identity(Base):
    """SDK identity with embedded credentials."""

    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("users.id"),
        nullable=False
    )
    type: Mapped[IdentityType] = mapped_column(
        SQLEnum(IdentityType),
        nullable=False
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    team: Mapped[str] = mapped_column(String(64), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    allowed_contexts: Mapped[list[str]] = mapped_column(
        StringList(),
        nullable=False
    )
    status: Mapped[IdentityStatus] = mapped_column(
        SQLEnum(IdentityStatus),
        default=IdentityStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="identities")

    def __repr__(self) -> str:
        return f"<Identity {self.id}>"

    @property
    def is_active(self) -> bool:
        """Check if identity is active and not expired."""
        if self.status != IdentityStatus.ACTIVE:
            return False
        if datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc):
            return False
        return True
