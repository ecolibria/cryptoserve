"""
CryptoServe Auto-Protect - Automatic encryption for third-party libraries.

Protects sensitive data flowing through dependencies by intercepting
outbound calls and encrypting detected sensitive fields.

Usage:
    import cryptoserve_auto
    cryptoserve_auto.protect(encryption_key=key)

    # Now all requests are automatically protected
    requests.post(url, json={"email": "user@example.com"})  # Auto-encrypted
"""

from cryptoserve_auto.config import AutoProtectConfig
from cryptoserve_auto.interceptor import (
    protect,
    unprotect,
    unprotected,
    is_protected,
    get_stats,
)
from cryptoserve_auto.detectors import (
    SensitiveFieldDetector,
    PatternType,
)

__version__ = "0.1.0"

__all__ = [
    # Main API
    "protect",
    "unprotect",
    "unprotected",
    "is_protected",
    "get_stats",
    # Configuration
    "AutoProtectConfig",
    # Detection
    "SensitiveFieldDetector",
    "PatternType",
]
