"""Key Management Service abstraction layer.

Supports multiple KMS backends for enterprise key management:
- Local: Development only, keys derived from master key
- AWS KMS: AWS Key Management Service integration
- GCP KMS: Google Cloud Key Management integration
- Azure Key Vault: Azure Key Vault integration
- HashiCorp Vault: HashiCorp Vault Transit secrets engine

This abstraction enables:
1. HSM-backed key storage in production
2. Master key rotation without code changes
3. Audit trail of all key operations
4. Compliance with FIPS 140-2/3 requirements
"""

from .base import KMSProvider, KMSConfig
from .local import LocalKMSProvider
from .factory import get_kms_provider

__all__ = [
    "KMSProvider",
    "KMSConfig",
    "LocalKMSProvider",
    "get_kms_provider",
]
