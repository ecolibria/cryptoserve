"""Crypto Inventory models for tracking detected cryptography across apps."""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, ForeignKey, Integer, Boolean, Text, JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, GUID


def generate_scan_ref() -> str:
    """Generate a short, human-readable scan reference ID."""
    # Format: cbom-{short_uuid} e.g., cbom-a7b3c9d2
    return f"cbom-{uuid.uuid4().hex[:8]}"


class QuantumRisk(str, Enum):
    """Quantum computing risk level."""
    NONE = "none"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementAction(str, Enum):
    """Policy enforcement action taken."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ScanSource(str, Enum):
    """Source of the inventory scan."""
    SDK_INIT = "sdk_init"  # From SDK init() at runtime
    CICD_GATE = "cicd_gate"  # From CI/CD pipeline gate
    MANUAL_SCAN = "manual_scan"  # Manual API call
    SCHEDULED = "scheduled"  # Periodic background scan
    CLI_SCAN = "cli_scan"  # From CLI cbom command


class CryptoInventoryReport(Base):
    """
    Historical record of crypto inventory scans.

    Each time an app reports its crypto usage (SDK init, CI/CD gate, etc.),
    a record is created here for historical tracking and trending.
    """

    __tablename__ = "crypto_inventory_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Human-readable reference ID for tracking (e.g., CBOM-A7B3C9D2)
    scan_ref: Mapped[str] = mapped_column(
        String(16),
        default=generate_scan_ref,
        unique=True,
        index=True,
        nullable=False
    )

    # User who uploaded (for CLI uploads without identity)
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    # Identity that reported (links to app/developer)
    # Nullable for CLI scans without a registered application
    identity_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("identities.id"),
        nullable=True,
        index=True
    )
    identity_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Team/department for aggregation
    team: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Scan metadata
    scan_source: Mapped[ScanSource] = mapped_column(
        SQLEnum(ScanSource),
        default=ScanSource.SDK_INIT
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # Enforcement result
    action: Mapped[EnforcementAction] = mapped_column(
        SQLEnum(EnforcementAction),
        default=EnforcementAction.ALLOW
    )

    # Counts for quick queries
    library_count: Mapped[int] = mapped_column(Integer, default=0)
    algorithm_count: Mapped[int] = mapped_column(Integer, default=0)
    violation_count: Mapped[int] = mapped_column(Integer, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, default=0)

    # Quantum readiness metrics
    quantum_safe_count: Mapped[int] = mapped_column(Integer, default=0)
    quantum_vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)
    has_pqc: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated_count: Mapped[int] = mapped_column(Integer, default=0)

    # Full inventory data (JSON for flexibility)
    libraries: Mapped[dict] = mapped_column(JSON, default=list)
    algorithms: Mapped[dict] = mapped_column(JSON, default=list)
    violations: Mapped[dict] = mapped_column(JSON, default=list)
    warnings: Mapped[dict] = mapped_column(JSON, default=list)

    # QBOM export data (optional, for premium)
    qbom_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # PQC-Bench recommendations (optional)
    pqc_recommendations: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Environment info
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True)
    python_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Git/deployment info (from CI/CD)
    git_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    git_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    git_repo: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Scan name/path (for CLI scans)
    scan_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    scan_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Relationships
    identity: Mapped["Identity"] = relationship("Identity", backref="inventory_reports")
    user: Mapped["User"] = relationship("User", backref="cbom_reports")

    def __repr__(self) -> str:
        return f"<CryptoInventoryReport {self.id} identity={self.identity_id} action={self.action.value}>"

    @property
    def is_compliant(self) -> bool:
        """Check if this scan passed policy checks."""
        return self.action != EnforcementAction.BLOCK

    @property
    def quantum_readiness_score(self) -> float:
        """
        Calculate quantum readiness score (0-100).

        - 100: All PQC, no quantum-vulnerable
        - 0: All quantum-vulnerable, no PQC
        """
        if self.library_count == 0:
            return 100.0  # No crypto = no risk

        safe = self.quantum_safe_count
        vulnerable = self.quantum_vulnerable_count
        total = safe + vulnerable

        if total == 0:
            return 100.0

        # Base score from safe/vulnerable ratio
        base_score = (safe / total) * 100

        # Bonus for having PQC
        if self.has_pqc:
            base_score = min(100, base_score + 20)

        # Penalty for deprecated libraries
        if self.deprecated_count > 0:
            base_score = max(0, base_score - (self.deprecated_count * 10))

        return round(base_score, 1)


class CryptoLibraryUsage(Base):
    """
    Aggregate view of library usage across all apps.

    Updated when inventory reports come in, enables quick queries like:
    - "How many apps use pycrypto?"
    - "Which apps use quantum-vulnerable RSA?"
    """

    __tablename__ = "crypto_library_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Library identification
    library_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    library_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Classification
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    quantum_risk: Mapped[QuantumRisk] = mapped_column(
        SQLEnum(QuantumRisk),
        default=QuantumRisk.NONE
    )
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Usage counts
    app_count: Mapped[int] = mapped_column(Integer, default=0)  # How many apps use this
    team_count: Mapped[int] = mapped_column(Integer, default=0)  # How many teams

    # Last seen
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # List of identity IDs using this library (for drill-down)
    identity_ids: Mapped[dict] = mapped_column(JSON, default=list)

    def __repr__(self) -> str:
        return f"<CryptoLibraryUsage {self.library_name} apps={self.app_count}>"
