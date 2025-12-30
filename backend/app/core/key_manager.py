"""Key derivation and management."""

import secrets
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import Key, KeyStatus

settings = get_settings()


class KeyManager:
    """Manages encryption key derivation and rotation."""

    def __init__(self):
        self.master_key = settings.cryptoserve_master_key.encode()

    def derive_key(self, context: str, version: int = 1) -> bytes:
        """Derive a key for a context using HKDF.

        Uses a configurable salt from settings to prevent precomputation attacks.
        The salt should be unique per deployment.
        """
        info = f"{context}:{version}".encode()

        # Use configurable salt from settings (unique per deployment)
        salt = settings.hkdf_salt.encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            info=info,
        )

        return hkdf.derive(self.master_key)

    async def get_or_create_key(
        self,
        db: AsyncSession,
        context: str,
    ) -> tuple[bytes, str]:
        """Get current key for context, creating if needed."""
        # Find active key for context
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.status == KeyStatus.ACTIVE)
            .order_by(Key.version.desc())
        )
        key_record = result.scalar_one_or_none()

        if not key_record:
            # Create new key record
            key_id = f"key_{context}_{secrets.token_hex(4)}"
            key_record = Key(
                id=key_id,
                context=context,
                version=1,
                status=KeyStatus.ACTIVE,
            )
            db.add(key_record)
            await db.commit()
            await db.refresh(key_record)

        # Derive actual key material
        key = self.derive_key(context, key_record.version)

        return key, key_record.id

    async def get_key_by_id(
        self,
        db: AsyncSession,
        key_id: str,
    ) -> bytes | None:
        """Get key by its ID (for decryption)."""
        result = await db.execute(select(Key).where(Key.id == key_id))
        key_record = result.scalar_one_or_none()

        if not key_record:
            return None

        return self.derive_key(key_record.context, key_record.version)

    async def rotate_key(
        self,
        db: AsyncSession,
        context: str,
    ) -> tuple[bytes, str]:
        """Rotate key by creating new version."""
        # Mark current key as rotated
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.status == KeyStatus.ACTIVE)
        )
        current_key = result.scalar_one_or_none()

        new_version = 1
        if current_key:
            current_key.status = KeyStatus.ROTATED
            new_version = current_key.version + 1

        # Create new key
        key_id = f"key_{context}_{secrets.token_hex(4)}"
        new_key = Key(
            id=key_id,
            context=context,
            version=new_version,
            status=KeyStatus.ACTIVE,
        )
        db.add(new_key)
        await db.commit()

        key = self.derive_key(context, new_version)
        return key, key_id


# Singleton instance
key_manager = KeyManager()
