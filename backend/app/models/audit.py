"""Audit log model for tracking crypto operations."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import String, DateTime, Boolean, Integer, Text
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuditLog(Base):
    """Audit log entry for crypto operations."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    context: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    identity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    identity_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    team: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Algorithm tracking fields (for metrics and compliance)
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g., "AES-256-GCM"
    cipher: Mapped[str | None] = mapped_column(String(32), nullable=True)     # e.g., "AES", "ChaCha20"
    mode: Mapped[str | None] = mapped_column(String(16), nullable=True)       # e.g., "gcm", "cbc"
    key_bits: Mapped[int | None] = mapped_column(Integer, nullable=True)      # e.g., 128, 256
    key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)     # Which key was used
    quantum_safe: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    policy_violation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<AuditLog {self.operation} {self.identity_id}>"
