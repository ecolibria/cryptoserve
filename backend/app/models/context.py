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

from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, StringList, JSONType


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

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
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
