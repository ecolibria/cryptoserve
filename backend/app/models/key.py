"""Key model for tracking encryption keys."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, DateTime, Integer, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class KeyStatus(str, Enum):
    """Status of encryption key."""
    ACTIVE = "active"
    ROTATED = "rotated"
    RETIRED = "retired"


class Key(Base):
    """Encryption key metadata (actual key derived from master key)."""

    __tablename__ = "keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
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
