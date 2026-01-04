"""Approval models for expedited promotion requests."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import String, DateTime, Boolean, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, GUID


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalPriority(str, Enum):
    """Priority levels for approval requests."""
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"


class ExpeditedApprovalRequest(Base):
    """Expedited promotion approval request.

    Tracks requests to bypass normal promotion thresholds, providing
    an audit trail for compliance and governance.
    """

    __tablename__ = "expedited_approval_requests"

    id: Mapped[str] = mapped_column(
        GUID(),
        primary_key=True,
        default=lambda: str(uuid4())
    )

    # Human-readable request ID (e.g., EXP-2026-A1B2)
    request_id: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        nullable=False,
        index=True
    )

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Application being promoted
    application_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("applications.id"),
        nullable=False,
        index=True
    )
    application_name: Mapped[str] = mapped_column(String(256), nullable=False)

    # Request details
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)

    # Contexts and bypassed thresholds (stored as JSON arrays)
    contexts: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    thresholds_bypassed: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Requester info
    requester_user_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )
    requester_email: Mapped[str] = mapped_column(String(256), nullable=False)
    requester_trust_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Approval status
    status: Mapped[str] = mapped_column(
        String(20),
        default=ApprovalStatus.PENDING.value,
        nullable=False,
        index=True
    )

    # Approver info (filled when approved/rejected)
    approved_by_user_id: Mapped[str | None] = mapped_column(
        GUID(),
        ForeignKey("users.id"),
        nullable=True
    )
    approved_by_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    approval_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Follow-up tracking
    follow_up_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    follow_up_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    follow_up_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<ExpeditedApprovalRequest {self.request_id} {self.status}>"
