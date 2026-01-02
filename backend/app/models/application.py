"""Application model for SDK credentials.

An Application represents a service or app that uses CryptoServe for encryption.
Each application has:
- Ed25519 keypair for token signing
- Refresh token tracking for auto-refresh
- Allowed encryption contexts
"""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, StringList, GUID


class ApplicationStatus(str, Enum):
    """Status of application."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Application(Base):
    """SDK application with Ed25519 keypair credentials."""

    __tablename__ = "applications"

    # Core identification
    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    user_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=False
    )

    # Application metadata
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    team: Mapped[str] = mapped_column(String(64), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)

    # Encryption contexts this application can use
    allowed_contexts: Mapped[list[str]] = mapped_column(
        StringList(),
        nullable=False
    )

    # Status tracking
    status: Mapped[ApplicationStatus] = mapped_column(
        String(16),
        default=ApplicationStatus.ACTIVE.value
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

    # Ed25519 keypair (per-application)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    key_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Refresh token tracking (hash stored, not the token itself)
    refresh_token_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )
    refresh_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    refresh_token_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="applications")
    user: Mapped["User"] = relationship("User", back_populates="applications")

    def __repr__(self) -> str:
        return f"<Application {self.id}>"

    @property
    def is_active(self) -> bool:
        """Check if application is active and not expired."""
        if self.status != ApplicationStatus.ACTIVE.value:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now > expires:
            return False
        return True

    @property
    def has_valid_refresh_token(self) -> bool:
        """Check if refresh token is still valid."""
        if not self.refresh_token_hash:
            return False
        if not self.refresh_token_expires_at:
            return False
        now = datetime.now(timezone.utc)
        expires = self.refresh_token_expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now < expires


# Backward compatibility aliases
# TODO: Remove after migration is complete
IdentityStatus = ApplicationStatus
Identity = Application
IdentityType = None  # No longer needed, but keep for import compatibility
