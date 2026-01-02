"""Key model for tracking encryption keys."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, Integer, ForeignKey, Enum as SQLEnum, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, GUID


class KeyStatus(str, Enum):
    """Status of encryption key."""
    ACTIVE = "active"
    ROTATED = "rotated"
    RETIRED = "retired"


class KeyType(str, Enum):
    """Type of cryptographic key."""
    SYMMETRIC = "symmetric"  # AES, ChaCha20
    PQC_KEM = "pqc_kem"      # ML-KEM for key encapsulation
    PQC_SIG = "pqc_sig"      # ML-DSA for signatures


class Key(Base):
    """Encryption key metadata (actual key derived from master key)."""

    __tablename__ = "keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    context: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("contexts.name"),
        nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[KeyStatus] = mapped_column(
        SQLEnum(KeyStatus),
        default=KeyStatus.ACTIVE
    )

    def __repr__(self) -> str:
        return f"<Key {self.id}>"


class PQCKey(Base):
    """Post-Quantum Cryptography key storage.

    Unlike classical keys which are derived from a master key,
    PQC keys (ML-KEM, ML-DSA) are randomly generated and must
    be stored. The private key is encrypted at rest using the
    context's derived key.

    Key sizes (ML-KEM-768):
    - Public key: 1184 bytes
    - Private key: 2400 bytes (encrypted for storage)
    """

    __tablename__ = "pqc_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    context: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("contexts.name"),
        nullable=False
    )
    key_type: Mapped[KeyType] = mapped_column(
        SQLEnum(KeyType),
        default=KeyType.PQC_KEM
    )
    algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )  # e.g., "ML-KEM-768", "ML-DSA-65"

    # Public key (stored plaintext - it's public)
    public_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    # Private key (encrypted with context's derived key)
    encrypted_private_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    # Nonce used for private key encryption
    private_key_nonce: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[KeyStatus] = mapped_column(
        SQLEnum(KeyStatus),
        default=KeyStatus.ACTIVE
    )

    def __repr__(self) -> str:
        return f"<PQCKey {self.id} algorithm={self.algorithm}>"
