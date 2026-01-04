"""Key Provider Abstraction Layer.

Defines an interface for key storage and derivation that can be implemented
by different backends:
- LocalKeyProvider: In-memory key derivation (default)
- Future: CloudHSM, Azure HSM, Vault integrations

This abstraction allows crypto-serve to work with different key management
systems while maintaining a consistent API.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


class KeyProviderType(str, Enum):
    """Types of key providers."""
    LOCAL = "local"           # HKDF-based derivation (default)
    AWS_CLOUDHSM = "aws_cloudhsm"
    AZURE_HSM = "azure_hsm"
    GOOGLE_HSM = "google_hsm"
    VAULT = "vault"
    CUSTOM = "custom"


@dataclass
class KeyMetadata:
    """Metadata about a key."""
    key_id: str
    version: int
    algorithm: str
    key_size_bits: int
    created_at: datetime
    provider: KeyProviderType
    hsm_key_handle: Optional[str] = None  # HSM-specific identifier
    wrapped: bool = False  # True if key is wrapped/encrypted


@dataclass
class WrappedKey:
    """A key that is encrypted/wrapped for transport or storage."""
    wrapped_key_data: bytes
    wrapping_algorithm: str
    wrapping_key_id: str
    key_metadata: KeyMetadata


class KeyProvider(ABC):
    """Abstract base class for key providers.

    Key providers handle the generation, derivation, and storage of
    cryptographic keys. Different implementations allow integration
    with various key management systems.
    """

    @property
    @abstractmethod
    def provider_type(self) -> KeyProviderType:
        """Return the type of this provider."""
        pass

    @abstractmethod
    async def derive_key(
        self,
        context: str,
        version: int,
        key_size: int = 32,
    ) -> bytes:
        """Derive a key for a given context and version.

        Args:
            context: Context identifier for key derivation
            version: Key version number
            key_size: Desired key size in bytes

        Returns:
            Derived key material
        """
        pass

    @abstractmethod
    async def generate_key(
        self,
        key_size: int = 32,
        algorithm: str = "AES",
    ) -> tuple[bytes, str]:
        """Generate a new random key.

        Args:
            key_size: Key size in bytes
            algorithm: Algorithm the key is for

        Returns:
            Tuple of (key_material, key_id)
        """
        pass

    @abstractmethod
    async def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key.

        Args:
            key_id: Key identifier

        Returns:
            Key metadata or None if not found
        """
        pass

    async def wrap_key(
        self,
        key: bytes,
        wrapping_key_id: str,
    ) -> WrappedKey:
        """Wrap/encrypt a key for export.

        Default implementation raises NotImplementedError.
        HSM providers should override this.

        Args:
            key: Key material to wrap
            wrapping_key_id: ID of the key to use for wrapping

        Returns:
            Wrapped key data
        """
        raise NotImplementedError(
            f"{self.provider_type.value} does not support key wrapping."
        )

    async def unwrap_key(
        self,
        wrapped_key: WrappedKey,
    ) -> bytes:
        """Unwrap/decrypt a wrapped key.

        Default implementation raises NotImplementedError.
        HSM providers should override this.

        Args:
            wrapped_key: The wrapped key to unwrap

        Returns:
            Unwrapped key material
        """
        raise NotImplementedError(
            f"{self.provider_type.value} does not support key unwrapping."
        )

    async def rotate_key(
        self,
        context: str,
        current_version: int,
    ) -> tuple[bytes, int]:
        """Rotate a key to a new version.

        Default implementation increments version and derives new key.

        Args:
            context: Context identifier
            current_version: Current key version

        Returns:
            Tuple of (new_key_material, new_version)
        """
        new_version = current_version + 1
        new_key = await self.derive_key(context, new_version)
        return new_key, new_version

    async def health_check(self) -> dict:
        """Check provider health.

        Returns:
            Health status dict with 'healthy' boolean and optional details
        """
        return {
            "healthy": True,
            "provider": self.provider_type.value,
            "message": "Provider is operational",
        }


class LocalKeyProvider(KeyProvider):
    """Local key provider using HKDF derivation.

    This is the default provider included in the OSS version.
    Keys are derived from a master key using HKDF, providing
    cryptographic key separation without external dependencies.
    """

    def __init__(self, master_key: bytes, salt: bytes):
        """Initialize with master key and salt.

        Args:
            master_key: The master key for derivation
            salt: Salt for HKDF (should be unique per deployment)
        """
        self._master_key = master_key
        self._salt = salt
        self._key_cache: dict[str, KeyMetadata] = {}

    @property
    def provider_type(self) -> KeyProviderType:
        return KeyProviderType.LOCAL

    async def derive_key(
        self,
        context: str,
        version: int,
        key_size: int = 32,
    ) -> bytes:
        """Derive a key using HKDF."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        info = f"{context}:{version}:{key_size}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=self._salt,
            info=info,
        )

        return hkdf.derive(self._master_key)

    async def generate_key(
        self,
        key_size: int = 32,
        algorithm: str = "AES",
    ) -> tuple[bytes, str]:
        """Generate a random key."""
        import os
        import secrets

        key = os.urandom(key_size)
        key_id = f"key_{secrets.token_hex(8)}"

        # Store metadata
        self._key_cache[key_id] = KeyMetadata(
            key_id=key_id,
            version=1,
            algorithm=algorithm,
            key_size_bits=key_size * 8,
            created_at=datetime.now(timezone.utc),
            provider=KeyProviderType.LOCAL,
        )

        return key, key_id

    async def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata from cache."""
        return self._key_cache.get(key_id)


# Factory function to get the appropriate provider
# Note: For cloud KMS (AWS, GCP, Azure), use the kms/ module instead:
#   from app.core.kms import create_kms_provider, KMSProviderType
def create_key_provider(
    provider_type: KeyProviderType = KeyProviderType.LOCAL,
    master_key: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> KeyProvider:
    """Create a key provider instance.

    Args:
        provider_type: Type of provider to create
        master_key: Master key for local provider
        salt: Salt for local provider

    Returns:
        Configured KeyProvider instance

    Note:
        For cloud KMS providers (AWS, GCP, Azure), use the kms/ module instead:
        >>> from app.core.kms import create_kms_provider, KMSProviderType
        >>> provider = create_kms_provider(KMSProviderType.AWS)
    """
    if provider_type == KeyProviderType.LOCAL:
        if not master_key or not salt:
            raise ValueError("master_key and salt required for local provider")
        return LocalKeyProvider(master_key, salt)

    elif provider_type in [
        KeyProviderType.AWS_CLOUDHSM,
        KeyProviderType.AZURE_HSM,
        KeyProviderType.GOOGLE_HSM,
        KeyProviderType.VAULT,
    ]:
        raise ValueError(
            f"For {provider_type.value}, use the kms/ module instead: "
            "from app.core.kms import create_kms_provider"
        )

    else:
        raise ValueError(f"Unknown provider type: {provider_type}")


# Global provider instance
_key_provider: Optional[KeyProvider] = None


def get_key_provider() -> KeyProvider:
    """Get the global key provider instance.

    Returns:
        The configured KeyProvider
    """
    global _key_provider
    if _key_provider is None:
        from app.config import get_settings
        settings = get_settings()

        _key_provider = create_key_provider(
            provider_type=KeyProviderType.LOCAL,
            master_key=settings.cryptoserve_master_key.encode(),
            salt=settings.hkdf_salt.encode(),
        )

    return _key_provider


def set_key_provider(provider: KeyProvider) -> None:
    """Set the global key provider instance.

    Args:
        provider: The KeyProvider to use globally
    """
    global _key_provider
    _key_provider = provider
