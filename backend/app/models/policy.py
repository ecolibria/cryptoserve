"""Policy model for cryptographic policy rules."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import String, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, StringList, JSONType


class Policy(Base):
    """Cryptographic policy rule stored in the database.

    Policies define rules that are evaluated during encrypt/decrypt operations.
    They can block operations, warn, or just provide information.

    Example:
        name: minimum-encryption-strength
        rule: context.sensitivity != 'critical' or algorithm.key_bits >= 256
        severity: block
        message: Critical data requires 256-bit encryption minimum
    """

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    rule: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16),
        default="warn",
        nullable=False
    )  # block, warn, info
    message: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Wizard-created policies use status to track publishing workflow
    status: Mapped[str] = mapped_column(
        String(16),
        default="published",
        nullable=False,
        comment="draft or published - controls visibility to developers"
    )

    # Link to the context created by this policy (for wizard-created policies)
    linked_context: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Context name created by this policy via wizard"
    )

    # Scope restrictions
    contexts: Mapped[list[str] | None] = mapped_column(
        StringList(),
        nullable=True,
        comment="Contexts this policy applies to (null = all)"
    )
    operations: Mapped[list[str] | None] = mapped_column(
        StringList(),
        nullable=True,
        comment="Operations this applies to (null = all)"
    )

    # Metadata for policy management
    policy_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        comment="Additional policy metadata"
    )

    # Audit fields
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=lambda: datetime.now(timezone.utc)
    )
    created_by: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="User who created the policy"
    )

    def __repr__(self) -> str:
        return f"<Policy {self.name} ({self.severity})>"

    def to_engine_policy(self):
        """Convert to a PolicyEngine Policy object."""
        from app.core.policy_engine import Policy as EnginePolicy, PolicySeverity

        return EnginePolicy(
            name=self.name,
            description=self.description or "",
            rule=self.rule,
            severity=PolicySeverity(self.severity),
            message=self.message,
            enabled=self.enabled,
            contexts=self.contexts or [],
            operations=self.operations or [],
        )


class PolicyViolationLog(Base):
    """Log of policy violations for audit and analysis."""

    __tablename__ = "policy_violations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    policy_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)

    # Context of the violation
    context_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    identity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    identity_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    team: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Rule evaluation details
    rule: Mapped[str] = mapped_column(Text, nullable=False)
    evaluation_context: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        comment="Snapshot of evaluation context"
    )

    # Request metadata
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    def __repr__(self) -> str:
        return f"<PolicyViolation {self.policy_name} @ {self.timestamp}>"
