"""Base KMS provider interface.

All KMS implementations must implement this interface to ensure
consistent behavior across different backends.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class KMSBackend(str, Enum):
    """Supported KMS backends."""
    LOCAL = "local"           # Development only - uses local key derivation
    AWS_KMS = "aws_kms"       # AWS Key Management Service
    GCP_KMS = "gcp_kms"       # Google Cloud Key Management
    AZURE_KV = "azure_kv"     # Azure Key Vault
    HASHICORP = "hashicorp"   # HashiCorp Vault Transit


@dataclass
class KMSConfig:
    """Configuration for KMS provider.

    Attributes:
        backend: Which KMS backend to use
        master_key_id: ID of the master key in the KMS (or local key for dev)
        region: Cloud region for cloud KMS providers
        endpoint: Custom endpoint (for local testing or private endpoints)
        credentials: Provider-specific credentials dict
        options: Additional provider-specific options
    """
    backend: KMSBackend = KMSBackend.LOCAL
    master_key_id: str = ""
    region: str = ""
    endpoint: str | None = None
    credentials: dict[str, str] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    # Key rotation settings
    rotation_period_days: int = 90
    auto_rotate: bool = False

    # Audit settings
    audit_enabled: bool = True


@dataclass
class KeyMetadata:
    """Metadata about a key in the KMS."""
    key_id: str
    version: int
    context: str
    created_at: datetime
    rotated_at: datetime | None = None
    expires_at: datetime | None = None
    status: str = "active"
    algorithm: str = "AES-256"
    usage: str = "ENCRYPT_DECRYPT"

    # HSM-specific metadata
    hsm_backed: bool = False
    fips_compliant: bool = False

    # Audit metadata
    created_by: str | None = None
    last_used_at: datetime | None = None
    usage_count: int = 0


@dataclass
class EncryptResult:
    """Result of a KMS encrypt operation."""
    ciphertext: bytes
    key_id: str
    key_version: int
    algorithm: str
    context_hash: str | None = None  # For envelope encryption


@dataclass
class DecryptResult:
    """Result of a KMS decrypt operation."""
    plaintext: bytes
    key_id: str
    key_version: int


class KMSProvider(ABC):
    """Abstract base class for KMS providers.

    All KMS implementations must provide:
    1. Key generation/derivation
    2. Encryption/decryption of data encryption keys (DEKs)
    3. Key rotation support
    4. Audit logging of operations

    The provider uses envelope encryption:
    - Master key (KEK) stored in HSM/KMS, never leaves the HSM
    - Data keys (DEKs) generated and encrypted by the KEK
    - Encrypted DEKs stored alongside ciphertext
    - Decryption: KMS decrypts DEK, application uses DEK for data
    """

    def __init__(self, config: KMSConfig):
        """Initialize the KMS provider.

        Args:
            config: KMS configuration
        """
        self.config = config
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the KMS provider.

        This may involve:
        - Connecting to the KMS service
        - Validating credentials
        - Verifying master key exists
        - Setting up audit logging

        Raises:
            KMSError: If initialization fails
        """
        pass

    @abstractmethod
    async def generate_data_key(
        self,
        context: str,
        key_size: int = 32,
    ) -> tuple[bytes, bytes]:
        """Generate a new data encryption key (DEK).

        Uses the master key (KEK) to generate and encrypt a new DEK.
        The plaintext DEK is used for encryption, then discarded.
        The encrypted DEK is stored with the ciphertext.

        Args:
            context: Encryption context for key binding
            key_size: Size of the DEK in bytes (16, 24, 32, 64)

        Returns:
            Tuple of (plaintext_dek, encrypted_dek)
            - plaintext_dek: Use for encryption, then discard securely
            - encrypted_dek: Store with ciphertext for later decryption

        Raises:
            KMSError: If key generation fails
        """
        pass

    @abstractmethod
    async def decrypt_data_key(
        self,
        encrypted_dek: bytes,
        context: str,
    ) -> bytes:
        """Decrypt a data encryption key.

        Uses the master key (KEK) to decrypt the DEK.

        Args:
            encrypted_dek: Encrypted DEK from ciphertext header
            context: Encryption context (must match original)

        Returns:
            Plaintext DEK for decryption

        Raises:
            KMSError: If decryption fails (wrong key, tampered, etc.)
        """
        pass

    @abstractmethod
    async def derive_key(
        self,
        context: str,
        version: int = 1,
        key_size: int = 32,
    ) -> bytes:
        """Derive a deterministic key for a context.

        Uses HKDF or similar KDF with the master key to derive
        a context-specific key. Useful for contexts that need
        consistent keys (e.g., for search indexes).

        Args:
            context: Context name for key derivation
            version: Key version number
            key_size: Key size in bytes

        Returns:
            Derived key material

        Raises:
            KMSError: If derivation fails
        """
        pass

    @abstractmethod
    async def rotate_master_key(self) -> str:
        """Rotate the master key (KEK).

        Creates a new version of the master key. The old version
        remains available for decryption but new operations use
        the new version.

        Returns:
            New master key version ID

        Raises:
            KMSError: If rotation fails
        """
        pass

    @abstractmethod
    async def get_key_metadata(
        self,
        key_id: str | None = None,
    ) -> KeyMetadata:
        """Get metadata about a key.

        Args:
            key_id: Specific key ID, or None for master key

        Returns:
            Key metadata

        Raises:
            KMSError: If key not found
        """
        pass

    @abstractmethod
    async def list_key_versions(self) -> list[KeyMetadata]:
        """List all versions of the master key.

        Returns:
            List of key metadata for each version
        """
        pass

    async def verify_health(self) -> dict[str, Any]:
        """Verify KMS provider health.

        Returns:
            Health status dict with:
            - healthy: bool
            - backend: str
            - master_key_status: str
            - latency_ms: float
            - details: dict
        """
        import time
        start = time.monotonic()

        try:
            metadata = await self.get_key_metadata()
            latency = (time.monotonic() - start) * 1000

            return {
                "healthy": True,
                "backend": self.config.backend.value,
                "master_key_status": metadata.status,
                "hsm_backed": metadata.hsm_backed,
                "fips_compliant": metadata.fips_compliant,
                "latency_ms": round(latency, 2),
                "details": {
                    "key_id": metadata.key_id,
                    "version": metadata.version,
                    "algorithm": metadata.algorithm,
                },
            }
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {
                "healthy": False,
                "backend": self.config.backend.value,
                "error": str(e),
                "latency_ms": round(latency, 2),
            }

    async def close(self) -> None:
        """Close any open connections."""
        pass


class KMSError(Exception):
    """Base exception for KMS operations."""
    pass


class KeyNotFoundError(KMSError):
    """Key not found in KMS."""
    pass


class DecryptionError(KMSError):
    """Decryption failed (wrong key, tampered, etc.)."""
    pass


class RotationError(KMSError):
    """Key rotation failed."""
    pass


class AuthenticationError(KMSError):
    """KMS authentication failed."""
    pass
