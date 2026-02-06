"""Key derivation and management.

Integrates with KMS abstraction layer for production HSM support.
Supports variable key sizes for different algorithm families:
- AES-128: 16 bytes
- AES-192: 24 bytes
- AES-256: 32 bytes (default)
- XTS: 64 bytes (two 256-bit keys)

In production:
- Master key stored in HSM (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault)
- Envelope encryption: DEKs encrypted by KEK in HSM
- Key rotation creates new key version without re-encrypting existing data

In development:
- Master key from environment variable (CRYPTOSERVE_MASTER_KEY)
- Keys derived using HKDF from master key
"""

import secrets
import logging
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings
from app.models import Key, KeyStatus, KeyType, PQCKey
from .kms import get_kms_provider
from .kms.base import KMSError
from .secure_memory import secure_zero

if TYPE_CHECKING:
    from .kms.base import KMSProvider

logger = logging.getLogger(__name__)
settings = get_settings()

# Standard key sizes in bytes
KEY_SIZE_128 = 16
KEY_SIZE_192 = 24
KEY_SIZE_256 = 32
KEY_SIZE_XTS = 64  # XTS uses two 256-bit keys


class KeyManager:
    """Manages encryption key derivation and rotation.

    Uses the KMS abstraction layer for all key operations:
    - In production: HSM-backed keys via AWS KMS, GCP KMS, etc.
    - In development: Local key derivation via HKDF

    Key hierarchy:
    - Master Key (KEK): Stored in HSM, never leaves the HSM
    - Data Encryption Keys (DEKs): Generated per context, encrypted by KEK

    This implementation uses deterministic key derivation by default
    for backward compatibility. Production deployments can enable
    envelope encryption for stronger security.
    """

    def __init__(self):
        self._kms: "KMSProvider | None" = None
        self._initialized = False

    async def _ensure_initialized(self) -> "KMSProvider":
        """Lazy initialization of KMS provider."""
        if not self._initialized:
            try:
                self._kms = get_kms_provider()
                await self._kms.initialize()
                self._initialized = True
                logger.info(f"KeyManager initialized with KMS backend: " f"{self._kms.config.backend.value}")
            except KMSError as e:
                logger.error(f"Failed to initialize KMS: {e}")
                raise
        return self._kms

    async def derive_key(
        self,
        context: str,
        version: int = 1,
        key_size: int = KEY_SIZE_256,
        tenant_id: str | None = None,
    ) -> bytes:
        """Derive a key for a context using the KMS provider.

        Uses deterministic key derivation for consistent keys across
        restarts. The actual derivation method depends on the KMS backend.

        Args:
            context: Context name for key derivation
            version: Key version number
            key_size: Key size in bytes (16, 24, 32, or 64)
            tenant_id: Optional tenant ID for per-tenant key isolation

        Returns:
            Derived key material of specified size
        """
        kms = await self._ensure_initialized()
        # Per-tenant key isolation: qualify the context with tenant_id
        # so different tenants derive different keys for the same context name
        qualified_context = f"{context}:{tenant_id}" if tenant_id else context
        return await kms.derive_key(qualified_context, version, key_size)

    def derive_key_sync(
        self,
        context: str,
        version: int = 1,
        key_size: int = KEY_SIZE_256,
        tenant_id: str | None = None,
    ) -> bytes:
        """Synchronous key derivation for backward compatibility.

        WARNING: This bypasses the KMS layer and uses direct HKDF.
        Use derive_key() async method for production code.
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        info = f"{context}:{version}:{key_size}".encode()
        # Per-tenant key isolation: incorporate tenant_id into salt
        # so different tenants derive different keys for the same context
        if tenant_id:
            salt = f"{settings.hkdf_salt}:{tenant_id}".encode()
        else:
            salt = settings.hkdf_salt.encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            info=info,
        )

        return hkdf.derive(settings.cryptoserve_master_key.encode())

    async def generate_data_key(
        self,
        context: str,
        key_size: int = KEY_SIZE_256,
    ) -> tuple[bytes, bytes]:
        """Generate a new data encryption key (DEK) with envelope encryption.

        In production (AWS KMS, etc.):
        - DEK generated and encrypted by HSM
        - Plaintext DEK returned for immediate use
        - Encrypted DEK stored with ciphertext

        In development (local):
        - DEK generated locally
        - Encrypted with derived KEK

        Args:
            context: Encryption context for key binding
            key_size: Key size in bytes

        Returns:
            Tuple of (plaintext_dek, encrypted_dek)
        """
        kms = await self._ensure_initialized()
        return await kms.generate_data_key(context, key_size)

    async def decrypt_data_key(
        self,
        encrypted_dek: bytes,
        context: str,
    ) -> bytes:
        """Decrypt a data encryption key.

        Args:
            encrypted_dek: Encrypted DEK from ciphertext header
            context: Encryption context (must match original)

        Returns:
            Plaintext DEK for decryption
        """
        kms = await self._ensure_initialized()
        return await kms.decrypt_data_key(encrypted_dek, context)

    async def get_or_create_key(
        self,
        db: AsyncSession,
        context: str,
        tenant_id: str,
        key_size: int = KEY_SIZE_256,
    ) -> tuple[bytes, str]:
        """Get current key for context, creating if needed.

        Args:
            db: Database session
            context: Context name
            tenant_id: Tenant ID for isolation
            key_size: Key size in bytes (default 32 for AES-256)

        Returns:
            Tuple of (key_material, key_id)
        """
        # Find active key for context and tenant
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.tenant_id == tenant_id)
            .where(Key.status == KeyStatus.ACTIVE)
            .order_by(Key.version.desc())
        )
        key_record = result.scalar_one_or_none()

        if not key_record:
            # Create new key record
            key_id = f"key_{context}_{secrets.token_hex(4)}"
            key_record = Key(
                id=key_id,
                tenant_id=tenant_id,
                context=context,
                version=1,
                status=KeyStatus.ACTIVE,
            )
            db.add(key_record)
            await db.commit()
            await db.refresh(key_record)

        # Derive actual key material with specified size (per-tenant isolation)
        key = await self.derive_key(context, key_record.version, key_size, tenant_id=tenant_id)

        return key, key_record.id

    async def get_key_by_id(
        self,
        db: AsyncSession,
        key_id: str,
        key_size: int = KEY_SIZE_256,
    ) -> bytes | None:
        """Get key by its ID (for decryption).

        Args:
            db: Database session
            key_id: Key identifier
            key_size: Key size in bytes (must match encryption key size)

        Returns:
            Key material or None if not found
        """
        result = await db.execute(select(Key).where(Key.id == key_id))
        key_record = result.scalar_one_or_none()

        if not key_record:
            return None

        return await self.derive_key(
            key_record.context,
            key_record.version,
            key_size,
            tenant_id=str(key_record.tenant_id),
        )

    async def rotate_key(
        self,
        db: AsyncSession,
        context: str,
        tenant_id: str,
        key_size: int = KEY_SIZE_256,
    ) -> tuple[bytes, str]:
        """Rotate key by creating new version.

        Args:
            db: Database session
            context: Context name
            tenant_id: Tenant ID for isolation
            key_size: Key size in bytes for new key

        Returns:
            Tuple of (new_key_material, new_key_id)
        """
        # Mark current key as rotated
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.tenant_id == tenant_id)
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
            tenant_id=tenant_id,
            context=context,
            version=new_version,
            status=KeyStatus.ACTIVE,
        )
        db.add(new_key)
        await db.commit()

        key = await self.derive_key(context, new_version, key_size, tenant_id=tenant_id)

        logger.info(
            f"Key rotated for context '{context}': " f"v{new_version - 1 if new_version > 1 else 0} -> v{new_version}"
        )

        return key, key_id

    async def rotate_master_key(self) -> str:
        """Rotate the master key in the KMS.

        In production (AWS KMS):
        - Enables automatic key rotation on the CMK
        - Old versions remain available for decryption
        - New operations use the new key version

        In development (local):
        - Increments the local key version

        Returns:
            New master key version ID
        """
        kms = await self._ensure_initialized()
        new_version = await kms.rotate_master_key()
        logger.info(f"Master key rotated: {new_version}")
        return new_version

    async def get_kms_health(self) -> dict:
        """Get KMS provider health status.

        Returns:
            Health status dict with backend info, latency, etc.
        """
        kms = await self._ensure_initialized()
        return await kms.verify_health()

    async def close(self) -> None:
        """Close KMS connections."""
        if self._kms:
            await self._kms.close()
            self._kms = None
            self._initialized = False

    # =========================================================================
    # PQC Key Management (ML-KEM, ML-DSA)
    # =========================================================================

    async def store_pqc_key(
        self,
        db: AsyncSession,
        context: str,
        tenant_id: str,
        key_id: str,
        private_key: bytes,
        public_key: bytes,
        algorithm: str,
        key_type: KeyType = KeyType.PQC_KEM,
    ) -> None:
        """Store a PQC keypair with encrypted private key.

        PQC keys cannot be derived like classical keys - they are
        randomly generated and must be stored. The private key is
        encrypted using AES-256-GCM with a key derived from the
        context's master key.

        Args:
            db: Database session
            context: Context name
            tenant_id: Tenant ID for isolation
            key_id: Unique key identifier
            private_key: Raw private key bytes
            public_key: Raw public key bytes
            algorithm: PQC algorithm name (e.g., "ML-KEM-768")
            key_type: Type of PQC key (KEM or SIG)
        """
        # Derive encryption key for this context
        encryption_key_bytes = await self.derive_key(context, version=1, key_size=KEY_SIZE_256)
        encryption_key = bytearray(encryption_key_bytes)

        try:
            # Generate nonce and encrypt private key
            nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
            aesgcm = AESGCM(bytes(encryption_key))
            encrypted_private_key = aesgcm.encrypt(
                nonce, private_key, associated_data=f"{context}:{key_id}:{algorithm}".encode()
            )
        finally:
            secure_zero(encryption_key)

        # Store in database
        pqc_key = PQCKey(
            id=key_id,
            tenant_id=tenant_id,
            context=context,
            key_type=key_type,
            algorithm=algorithm,
            public_key=public_key,
            encrypted_private_key=encrypted_private_key,
            private_key_nonce=nonce,
            status=KeyStatus.ACTIVE,
        )
        db.add(pqc_key)
        await db.commit()

        logger.info(f"Stored PQC key: id={key_id}, algorithm={algorithm}, " f"context={context}, type={key_type.value}")

    async def get_pqc_key(
        self,
        db: AsyncSession,
        context: str,
        key_id: str,
    ) -> bytes | None:
        """Retrieve and decrypt a PQC private key.

        Args:
            db: Database session
            context: Context name (for key derivation)
            key_id: Key identifier

        Returns:
            Decrypted private key bytes, or None if not found
        """
        result = await db.execute(select(PQCKey).where(PQCKey.id == key_id))
        pqc_key = result.scalar_one_or_none()

        if not pqc_key:
            logger.warning(f"PQC key not found: {key_id}")
            return None

        # Derive decryption key
        encryption_key_bytes = await self.derive_key(context, version=1, key_size=KEY_SIZE_256)
        encryption_key = bytearray(encryption_key_bytes)

        # Decrypt private key
        try:
            aesgcm = AESGCM(bytes(encryption_key))
            private_key = aesgcm.decrypt(
                pqc_key.private_key_nonce,
                pqc_key.encrypted_private_key,
                associated_data=f"{context}:{key_id}:{pqc_key.algorithm}".encode(),
            )
            return private_key
        except Exception as e:
            logger.error(f"Failed to decrypt PQC key {key_id}: {e}")
            return None
        finally:
            secure_zero(encryption_key)

    async def get_pqc_public_key(
        self,
        db: AsyncSession,
        key_id: str,
    ) -> bytes | None:
        """Retrieve a PQC public key.

        Args:
            db: Database session
            key_id: Key identifier

        Returns:
            Public key bytes, or None if not found
        """
        result = await db.execute(select(PQCKey).where(PQCKey.id == key_id))
        pqc_key = result.scalar_one_or_none()

        if not pqc_key:
            return None

        return pqc_key.public_key

    async def list_pqc_keys(
        self,
        db: AsyncSession,
        context: str,
        key_type: KeyType | None = None,
    ) -> list[dict]:
        """List PQC keys for a context.

        Args:
            db: Database session
            context: Context name
            key_type: Optional filter by key type

        Returns:
            List of key metadata dicts
        """
        query = select(PQCKey).where(PQCKey.context == context)
        if key_type:
            query = query.where(PQCKey.key_type == key_type)

        result = await db.execute(query)
        keys = result.scalars().all()

        return [
            {
                "id": key.id,
                "algorithm": key.algorithm,
                "key_type": key.key_type.value,
                "created_at": key.created_at.isoformat(),
                "status": key.status.value,
            }
            for key in keys
        ]


# Singleton instance
key_manager = KeyManager()
