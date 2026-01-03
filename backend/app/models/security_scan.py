"""Security Scan models for tracking code, dependency, and certificate scans."""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, ForeignKey, Integer, Boolean, Text, JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, GUID


def generate_scan_id() -> str:
    """Generate a short scan ID."""
    return f"scan-{uuid.uuid4().hex[:8]}"


class ScanType(str, Enum):
    """Type of security scan."""
    CODE = "code"
    DEPENDENCY = "dependency"
    CERTIFICATE = "certificate"


class SeverityLevel(str, Enum):
    """Severity level of findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityScan(Base):
    """
    Record of a security scan (code, dependency, or certificate).

    Tracks scan results over time for trending and aggregate reporting.
    """

    __tablename__ = "security_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Scan identifier
    scan_id: Mapped[str] = mapped_column(
        String(16),
        default=generate_scan_id,
        unique=True,
        index=True,
        nullable=False
    )

    # Scan metadata
    scan_type: Mapped[ScanType] = mapped_column(
        SQLEnum(ScanType),
        nullable=False,
        index=True
    )

    # User who performed the scan
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    # Application/identity that was scanned (if known)
    identity_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("identities.id"),
        nullable=True,
        index=True
    )

    # Scan target info
    target_name: Mapped[str] = mapped_column(String(256), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)  # language, package_type, etc.

    # Timestamps
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # Aggregate results
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Quantum vulnerability tracking
    quantum_vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)
    quantum_safe_count: Mapped[int] = mapped_column(Integer, default=0)

    # Deprecated/weak crypto tracking
    deprecated_count: Mapped[int] = mapped_column(Integer, default=0)
    weak_crypto_count: Mapped[int] = mapped_column(Integer, default=0)

    # Full scan results (JSON for flexibility)
    results: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Relationships
    findings: Mapped[list["SecurityFinding"]] = relationship(
        "SecurityFinding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<SecurityScan {self.scan_id} {self.scan_type.value}>"


class SecurityFinding(Base):
    """Individual security finding from a scan."""

    __tablename__ = "security_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Link to scan
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("security_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Finding details
    severity: Mapped[SeverityLevel] = mapped_column(
        SQLEnum(SeverityLevel),
        nullable=False,
        index=True
    )

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Location (for code scans)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Crypto details
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    library: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Risk assessment
    quantum_risk: Mapped[str | None] = mapped_column(String(16), nullable=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_weak: Mapped[bool] = mapped_column(Boolean, default=False)

    # Remediation
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship
    scan: Mapped["SecurityScan"] = relationship("SecurityScan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<SecurityFinding {self.severity.value}: {self.title}>"


class CertificateInventory(Base):
    """Tracked certificates for expiration monitoring."""

    __tablename__ = "certificate_inventory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Certificate identification
    common_name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Certificate details
    issuer_cn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    organization: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Validity
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Key info
    key_type: Mapped[str] = mapped_column(String(32), nullable=False)  # RSA, EC, Ed25519
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)

    # Risk assessment
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    is_expired: Mapped[bool] = mapped_column(Boolean, default=False)
    is_weak_key: Mapped[bool] = mapped_column(Boolean, default=False)
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, default=True)

    # Subject Alternative Names (JSON array)
    san_domains: Mapped[list] = mapped_column(JSON, default=list)

    # Tracking
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Source tracking
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)  # manual, scan, etc.

    def __repr__(self) -> str:
        return f"<CertificateInventory {self.common_name}>"

    @property
    def days_until_expiry(self) -> int:
        """Calculate days until certificate expires."""
        now = datetime.now(timezone.utc)
        delta = self.not_after - now
        return delta.days
