"""Context model for crypto policy definitions.

The Context model now supports the 5-layer configuration:
1. Data Identity - What is this data, and how bad if it leaks?
2. Regulatory Mapping - What rules govern this data?
3. Threat Model - What are we protecting against?
4. Access Patterns - How is this data used?
5. Derived Requirements - Computed by algorithm resolver
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import String, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, StringList, JSONType, GUID


class Context(Base):
    """Cryptographic context with policy and metadata.

    The `config` field stores the 5-layer context configuration as JSONB:
    - data_identity: sensitivity, pii/phi/pci flags, notification_required
    - regulatory: frameworks, retention, data_residency
    - threat_model: adversaries, protection_lifetime_years
    - access_patterns: frequency, latency requirements

    The `algorithm` field is computed from config by the algorithm resolver,
    but cached here for quick access during encrypt/decrypt operations.
    """

    __tablename__ = "contexts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_context_tenant_name"),
    )

    name: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # 5-layer configuration stored as JSON
    config: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        default=None,
        comment="5-layer context configuration"
    )

    # Cached derived requirements (computed from config)
    derived: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        default=None,
        comment="Cached derived requirements from algorithm resolver"
    )

    # Legacy fields for backward compatibility
    data_examples: Mapped[list[str] | None] = mapped_column(
        StringList(),
        nullable=True
    )
    compliance_tags: Mapped[list[str] | None] = mapped_column(
        StringList(),
        nullable=True
    )
    algorithm: Mapped[str] = mapped_column(
        String(64),  # Increased for hybrid algorithm names
        default="AES-256-GCM"
    )

    # Algorithm policy enforcement (admin-controlled)
    # Policy structure: {"allowed_ciphers": ["AES"], "allowed_modes": ["gcm"],
    #                    "min_key_bits": 256, "require_quantum_safe": false}
    algorithm_policy: Mapped[dict[str, Any] | None] = mapped_column(
        JSONType(),
        nullable=True,
        default=None,
        comment="Admin-defined algorithm policy constraints"
    )
    # Enforcement level: "none" (dev override allowed), "warn" (log but allow),
    # "enforce" (reject violations)
    policy_enforcement: Mapped[str] = mapped_column(
        String(16),
        default="none",
        nullable=False,
        comment="Policy enforcement level: none, warn, enforce"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="contexts")

    def __repr__(self) -> str:
        return f"<Context {self.name}>"

    @property
    def sensitivity(self) -> str:
        """Get sensitivity level from config or default to medium."""
        if self.config and "data_identity" in self.config:
            return self.config["data_identity"].get("sensitivity", "medium")
        return "medium"

    @property
    def quantum_resistant(self) -> bool:
        """Check if context requires quantum-resistant encryption."""
        if self.derived:
            return self.derived.get("quantum_resistant", False)
        return False
