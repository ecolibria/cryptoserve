"""KMS provider factory.

Creates the appropriate KMS provider based on configuration.
"""

import os
import logging
from functools import lru_cache

from .base import KMSProvider, KMSConfig, KMSBackend, KMSError
from .local import LocalKMSProvider

logger = logging.getLogger(__name__)

# Registry of KMS providers
_providers: dict[KMSBackend, type[KMSProvider]] = {
    KMSBackend.LOCAL: LocalKMSProvider,
}

# Register AWS KMS if boto3 is available
try:
    from .aws import AWSKMSProvider
    _providers[KMSBackend.AWS_KMS] = AWSKMSProvider
except ImportError:
    pass  # boto3 not installed


def register_provider(backend: KMSBackend, provider_class: type[KMSProvider]) -> None:
    """Register a KMS provider class.

    Allows adding new providers without modifying this module.

    Args:
        backend: Backend identifier
        provider_class: Provider class implementing KMSProvider
    """
    _providers[backend] = provider_class
    logger.info(f"Registered KMS provider: {backend.value}")


def _get_config_from_env() -> KMSConfig:
    """Build KMS configuration from environment variables.

    Environment variables:
        KMS_BACKEND: Which backend to use (local, aws_kms, gcp_kms, azure_kv, hashicorp)
        KMS_MASTER_KEY_ID: ID of the master key
        KMS_REGION: Cloud region for cloud providers
        KMS_ENDPOINT: Custom endpoint URL

        AWS-specific:
        AWS_ACCESS_KEY_ID: AWS access key
        AWS_SECRET_ACCESS_KEY: AWS secret key
        AWS_SESSION_TOKEN: Optional session token

        GCP-specific:
        GOOGLE_APPLICATION_CREDENTIALS: Path to service account JSON
        GCP_PROJECT_ID: GCP project ID

        Azure-specific:
        AZURE_TENANT_ID: Azure tenant ID
        AZURE_CLIENT_ID: Azure client ID
        AZURE_CLIENT_SECRET: Azure client secret
        AZURE_KEYVAULT_URL: Key Vault URL

        HashiCorp-specific:
        VAULT_ADDR: Vault address
        VAULT_TOKEN: Vault token
        VAULT_TRANSIT_KEY: Transit key name
    """
    backend_str = os.environ.get("KMS_BACKEND", "local").lower()

    try:
        backend = KMSBackend(backend_str)
    except ValueError:
        raise KMSError(
            f"Unknown KMS backend: {backend_str}. "
            f"Supported: {', '.join(b.value for b in KMSBackend)}"
        )

    config = KMSConfig(
        backend=backend,
        master_key_id=os.environ.get("KMS_MASTER_KEY_ID", ""),
        region=os.environ.get("KMS_REGION", ""),
        endpoint=os.environ.get("KMS_ENDPOINT"),
    )

    # Build credentials based on backend
    if backend == KMSBackend.LOCAL:
        config.master_key_id = os.environ.get(
            "CRYPTOSERVE_MASTER_KEY", ""
        )
        config.options["salt"] = os.environ.get("CRYPTOSERVE_HKDF_SALT", "")

    elif backend == KMSBackend.AWS_KMS:
        config.credentials = {
            "access_key_id": os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            "session_token": os.environ.get("AWS_SESSION_TOKEN", ""),
        }

    elif backend == KMSBackend.GCP_KMS:
        config.credentials = {
            "credentials_file": os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""),
            "project_id": os.environ.get("GCP_PROJECT_ID", ""),
        }

    elif backend == KMSBackend.AZURE_KV:
        config.credentials = {
            "tenant_id": os.environ.get("AZURE_TENANT_ID", ""),
            "client_id": os.environ.get("AZURE_CLIENT_ID", ""),
            "client_secret": os.environ.get("AZURE_CLIENT_SECRET", ""),
        }
        config.endpoint = os.environ.get("AZURE_KEYVAULT_URL", "")

    elif backend == KMSBackend.HASHICORP:
        config.credentials = {
            "vault_addr": os.environ.get("VAULT_ADDR", ""),
            "vault_token": os.environ.get("VAULT_TOKEN", ""),
        }
        config.options["transit_key"] = os.environ.get("VAULT_TRANSIT_KEY", "cryptoserve")

    return config


@lru_cache(maxsize=1)
def get_kms_provider() -> KMSProvider:
    """Get the configured KMS provider.

    Returns a cached singleton instance.

    Returns:
        Configured KMS provider

    Raises:
        KMSError: If provider not available or configuration invalid
    """
    config = _get_config_from_env()

    provider_class = _providers.get(config.backend)
    if provider_class is None:
        # Check if it's a valid backend that's not yet registered
        if config.backend in KMSBackend:
            raise KMSError(
                f"KMS backend '{config.backend.value}' is not yet implemented. "
                f"Available backends: {', '.join(p.value for p in _providers.keys())}"
            )
        raise KMSError(f"Unknown KMS backend: {config.backend}")

    provider = provider_class(config)
    logger.info(f"Created KMS provider: {config.backend.value}")

    return provider


async def initialize_kms() -> KMSProvider:
    """Initialize and return the KMS provider.

    This should be called during application startup.

    Returns:
        Initialized KMS provider
    """
    provider = get_kms_provider()
    await provider.initialize()
    return provider


def reset_kms_provider() -> None:
    """Reset the cached KMS provider.

    Useful for testing or reconfiguration.
    """
    get_kms_provider.cache_clear()
