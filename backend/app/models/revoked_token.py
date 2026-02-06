"""Revoked token model for persistent JWT revocation."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, GUID


class RevokedToken(Base):
    """Stores revoked JWT token identifiers (jti claims).

    Provides persistent token revocation that survives server restarts,
    unlike in-memory sets. Entries should be cleaned up after the
    corresponding JWT's expiration time has passed.
    """

    __tablename__ = "revoked_tokens"

    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=lambda: str(uuid4()))
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<RevokedToken jti={self.jti}>"
