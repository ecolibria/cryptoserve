"""Local KMS provider for development.

WARNING: This provider is for DEVELOPMENT ONLY.
In production, use a proper KMS (AWS KMS, GCP KMS, Azure Key Vault, etc.)

The local provider:
- Derives keys using HKDF from a master key
- Stores master key in environment variable (INSECURE)
- Does not provide HSM protection
- Does not provide FIPS compliance
"""

import os
import secrets
import logging
from datetime import datetime, timezone

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import (
    KMSProvider,
    KMSConfig,
    KeyMetadata,
    KMSError,
    DecryptionError,
)

logger = logging.getLogger(__name__)


class LocalKMSProvider(KMSProvider):
    """Local KMS provider for development.

    Uses HKDF for key derivation and AES-GCM for DEK encryption.
    NOT suitable for production - master key is not HSM-protected.
    """

    def __init__(self, config: KMSConfig):
        super().__init__(config)
        self._master_key: bytes | None = None
        self._salt: bytes | None = None
        self._version = 1
        self._created_at = datetime.now(timezone.utc)

    async def initialize(self) -> None:
        """Initialize the local KMS provider."""
        # Get master key from config or environment
        master_key_str = self.config.master_key_id or os.environ.get(
            "CRYPTOSERVE_MASTER_KEY", ""
        )

        if not master_key_str:
            raise KMSError(
                "Master key not configured. Set CRYPTOSERVE_MASTER_KEY environment variable."
            )

        # Validate master key strength
        if len(master_key_str) < 32:
            logger.warning(
                "Master key is less than 32 characters. "
                "This is insecure for production use."
            )

        if "change-in-production" in master_key_str.lower():
            raise KMSError(
                "Default development master key detected. "
                "Set a secure CRYPTOSERVE_MASTER_KEY for production."
            )

        self._master_key = master_key_str.encode()

        # Get salt from config or environment
        salt_str = self.config.options.get("salt") or os.environ.get(
            "CRYPTOSERVE_HKDF_SALT", "cryptoserve-local-salt"
        )
        self._salt = salt_str.encode()

        self._initialized = True
        logger.info(
            "Local KMS provider initialized. "
            "WARNING: Use cloud KMS in production for HSM protection."
        )

    async def generate_data_key(
        self,
        context: str,
        key_size: int = 32,
    ) -> tuple[bytes, bytes]:
        """Generate a new data encryption key."""
        if not self._initialized:
            await self.initialize()

        # Generate random DEK
        plaintext_dek = secrets.token_bytes(key_size)

        # Derive a KEK for this context
        kek = await self._derive_kek(context)

        # Encrypt the DEK with the KEK
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(kek)
        encrypted_dek = nonce + aesgcm.encrypt(nonce, plaintext_dek, context.encode())

        return plaintext_dek, encrypted_dek

    async def decrypt_data_key(
        self,
        encrypted_dek: bytes,
        context: str,
    ) -> bytes:
        """Decrypt a data encryption key."""
        if not self._initialized:
            await self.initialize()

        if len(encrypted_dek) < 12:
            raise DecryptionError("Invalid encrypted DEK: too short")

        # Derive the same KEK
        kek = await self._derive_kek(context)

        # Extract nonce and ciphertext
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]

        try:
            aesgcm = AESGCM(kek)
            plaintext_dek = aesgcm.decrypt(nonce, ciphertext, context.encode())
            return plaintext_dek
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt DEK: {e}")

    async def derive_key(
        self,
        context: str,
        version: int = 1,
        key_size: int = 32,
    ) -> bytes:
        """Derive a deterministic key for a context."""
        if not self._initialized:
            await self.initialize()

        info = f"{context}:v{version}:sz{key_size}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=self._salt,
            info=info,
        )

        return hkdf.derive(self._master_key)

    async def _derive_kek(self, context: str) -> bytes:
        """Derive a key encryption key for a context."""
        info = f"kek:{context}:v{self._version}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # KEK is always 256-bit
            salt=self._salt,
            info=info,
        )

        return hkdf.derive(self._master_key)

    async def rotate_master_key(self) -> str:
        """Rotate the master key.

        For local provider, this just increments the version.
        In production KMS, this creates a new key in the HSM.
        """
        self._version += 1
        new_version_id = f"local-v{self._version}"
        logger.info(f"Local KMS: Master key rotated to version {self._version}")
        return new_version_id

    async def get_key_metadata(
        self,
        key_id: str | None = None,
    ) -> KeyMetadata:
        """Get metadata about the master key."""
        return KeyMetadata(
            key_id=f"local-master-v{self._version}",
            version=self._version,
            context="master",
            created_at=self._created_at,
            status="active",
            algorithm="HKDF-SHA256",
            usage="DERIVE_KEY",
            hsm_backed=False,
            fips_compliant=False,
        )

    async def list_key_versions(self) -> list[KeyMetadata]:
        """List all versions of the master key."""
        versions = []
        for v in range(1, self._version + 1):
            versions.append(
                KeyMetadata(
                    key_id=f"local-master-v{v}",
                    version=v,
                    context="master",
                    created_at=self._created_at,
                    status="active" if v == self._version else "rotated",
                    algorithm="HKDF-SHA256",
                    usage="DERIVE_KEY",
                    hsm_backed=False,
                    fips_compliant=False,
                )
            )
        return versions
