"""Migration history model for tracking algorithm migrations."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, GUID


class MigrationHistory(Base):
    """Track algorithm migration history for audit and rollback."""

    __tablename__ = "migration_history"

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

    # Who performed the migration
    user_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # When
    migrated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # What was migrated
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )  # "algorithm_migration" or "bulk_algorithm_migration"

    context_name: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        index=True
    )  # Null for bulk migrations

    previous_algorithm: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    new_algorithm: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Additional details (for bulk migrations: count info, etc.)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<MigrationHistory {self.action} {self.context_name or 'bulk'}>"
