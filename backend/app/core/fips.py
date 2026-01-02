"""FIPS 140-2/140-3 compliance module.

This module provides FIPS mode enforcement for CryptoServe:
- Validates OpenSSL FIPS provider availability
- Restricts algorithms to FIPS-approved set
- Enforces FIPS compliance at startup and runtime

FIPS-Approved Algorithms (when in FIPS mode):
- Symmetric: AES (128, 192, 256) in approved modes (GCM, CBC, CTR, CCM)
- Hash: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
- MAC: HMAC with approved hash functions
- KDF: HKDF, PBKDF2 with approved hash functions
- Asymmetric: RSA (2048+), ECDSA (P-256, P-384, P-521), EdDSA (Ed25519, Ed448)
- Key Exchange: ECDH (P-256, P-384, P-521), X25519, X448
- Post-Quantum: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)

Non-FIPS Algorithms (blocked in FIPS mode):
- ChaCha20-Poly1305 (RFC 8439, not NIST)
- AES-GCM-SIV (RFC 8452, not NIST)
- Argon2 (not NIST approved)
- Bcrypt (not NIST approved)
"""

import os
import ssl
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Optional

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class FIPSMode(str, Enum):
    """FIPS enforcement modes."""

    DISABLED = "disabled"  # No FIPS enforcement
    ENABLED = "enabled"  # Enforce FIPS, fail if not available
    PREFERRED = "preferred"  # Use FIPS if available, warn if not


@dataclass
class FIPSStatus:
    """Current FIPS compliance status."""

    mode: FIPSMode
    openssl_fips_available: bool
    openssl_version: str
    fips_provider_loaded: bool
    compliant: bool
    message: str

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "mode": self.mode.value,
            "openssl_fips_available": self.openssl_fips_available,
            "openssl_version": self.openssl_version,
            "fips_provider_loaded": self.fips_provider_loaded,
            "compliant": self.compliant,
            "message": self.message,
        }


# FIPS-approved algorithms
FIPS_APPROVED_CIPHERS = frozenset([
    "AES",
])

FIPS_APPROVED_MODES = frozenset([
    "gcm",
    "cbc",
    "ctr",
    "ccm",
    "hybrid",  # Hybrid uses AES-GCM internally
])

FIPS_APPROVED_KEY_SIZES = frozenset([128, 192, 256])

FIPS_APPROVED_HASHES = frozenset([
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
])

FIPS_APPROVED_PQC = frozenset([
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-128f",
    "SLH-DSA-192f",
    "SLH-DSA-256f",
])

# Non-FIPS algorithms (blocked in FIPS mode)
NON_FIPS_ALGORITHMS = frozenset([
    "ChaCha20-Poly1305",
    "ChaCha20",
    "AES-256-GCM-SIV",
    "AES-128-GCM-SIV",
    "Argon2id",
    "Argon2i",
    "Argon2d",
    "Bcrypt",
])


def check_openssl_fips_available() -> tuple[bool, str]:
    """Check if OpenSSL FIPS provider is available.

    Returns:
        Tuple of (is_available, openssl_version)
    """
    try:
        openssl_version = ssl.OPENSSL_VERSION

        # Check for FIPS indicators in OpenSSL version/config
        # OpenSSL 3.x uses providers; FIPS provider must be loaded
        if "3." in openssl_version:
            # OpenSSL 3.x - check if FIPS provider can be loaded
            try:
                from cryptography.hazmat.backends.openssl import backend
                # Check if FIPS mode is enabled in OpenSSL
                # This is a heuristic - actual FIPS validation requires
                # proper FIPS provider configuration
                fips_enabled = getattr(backend, '_fips_enabled', False)
                if hasattr(backend, '_lib'):
                    # Try to check FIPS_mode() if available
                    try:
                        fips_enabled = backend._lib.FIPS_mode() == 1
                    except (AttributeError, TypeError):
                        pass
                return fips_enabled, openssl_version
            except Exception:
                pass

        # OpenSSL 1.x - check for FIPS mode
        # Note: OpenSSL 1.x FIPS requires special FIPS-validated build
        if "fips" in openssl_version.lower():
            return True, openssl_version

        return False, openssl_version

    except Exception as e:
        logger.warning("Failed to check OpenSSL FIPS status", error=str(e))
        return False, "unknown"


@lru_cache(maxsize=1)
def get_fips_status() -> FIPSStatus:
    """Get current FIPS compliance status.

    This function is cached - call invalidate_fips_cache() to refresh.
    """
    settings = get_settings()
    mode = FIPSMode(settings.fips_mode)

    openssl_fips_available, openssl_version = check_openssl_fips_available()

    if mode == FIPSMode.DISABLED:
        return FIPSStatus(
            mode=mode,
            openssl_fips_available=openssl_fips_available,
            openssl_version=openssl_version,
            fips_provider_loaded=False,
            compliant=True,  # Disabled mode is always "compliant" (no requirements)
            message="FIPS mode is disabled",
        )

    if mode == FIPSMode.ENABLED:
        if openssl_fips_available:
            return FIPSStatus(
                mode=mode,
                openssl_fips_available=True,
                openssl_version=openssl_version,
                fips_provider_loaded=True,
                compliant=True,
                message="FIPS mode enabled with validated OpenSSL FIPS provider",
            )
        else:
            return FIPSStatus(
                mode=mode,
                openssl_fips_available=False,
                openssl_version=openssl_version,
                fips_provider_loaded=False,
                compliant=False,
                message="FIPS mode enabled but OpenSSL FIPS provider not available",
            )

    # PREFERRED mode
    if openssl_fips_available:
        return FIPSStatus(
            mode=mode,
            openssl_fips_available=True,
            openssl_version=openssl_version,
            fips_provider_loaded=True,
            compliant=True,
            message="FIPS mode preferred and available",
        )
    else:
        return FIPSStatus(
            mode=mode,
            openssl_fips_available=False,
            openssl_version=openssl_version,
            fips_provider_loaded=False,
            compliant=True,  # Preferred mode doesn't fail if unavailable
            message="FIPS mode preferred but not available - using standard crypto",
        )


def invalidate_fips_cache() -> None:
    """Invalidate the cached FIPS status."""
    get_fips_status.cache_clear()


def is_algorithm_fips_approved(
    cipher: str,
    mode: str,
    key_bits: int,
) -> tuple[bool, str]:
    """Check if an algorithm configuration is FIPS-approved.

    Args:
        cipher: Cipher name (e.g., "AES", "ChaCha20")
        mode: Mode of operation (e.g., "gcm", "cbc")
        key_bits: Key size in bits

    Returns:
        Tuple of (is_approved, reason)
    """
    # Check cipher
    if cipher.upper() not in FIPS_APPROVED_CIPHERS:
        return False, f"Cipher '{cipher}' is not FIPS-approved"

    # Check mode
    if mode.lower() not in FIPS_APPROVED_MODES:
        return False, f"Mode '{mode}' is not FIPS-approved"

    # Check key size
    if key_bits not in FIPS_APPROVED_KEY_SIZES:
        return False, f"Key size {key_bits} bits is not FIPS-approved"

    return True, "Algorithm is FIPS-approved"


def is_hash_fips_approved(hash_name: str) -> tuple[bool, str]:
    """Check if a hash algorithm is FIPS-approved.

    Args:
        hash_name: Hash algorithm name (e.g., "SHA-256", "MD5")

    Returns:
        Tuple of (is_approved, reason)
    """
    normalized = hash_name.upper().replace("_", "-")
    if normalized in FIPS_APPROVED_HASHES:
        return True, "Hash algorithm is FIPS-approved"
    return False, f"Hash '{hash_name}' is not FIPS-approved"


def is_pqc_fips_approved(algorithm: str) -> tuple[bool, str]:
    """Check if a post-quantum algorithm is FIPS-approved.

    Args:
        algorithm: PQC algorithm name (e.g., "ML-KEM-768")

    Returns:
        Tuple of (is_approved, reason)
    """
    if algorithm in FIPS_APPROVED_PQC:
        return True, f"{algorithm} is FIPS-approved (FIPS 203/204/205)"
    return False, f"PQC algorithm '{algorithm}' is not FIPS-approved"


def enforce_fips_algorithm(
    cipher: str,
    mode: str,
    key_bits: int,
) -> None:
    """Enforce FIPS compliance for an algorithm.

    Raises:
        FIPSViolationError: If FIPS mode is enabled and algorithm is not approved
    """
    status = get_fips_status()

    if status.mode == FIPSMode.DISABLED:
        return  # No enforcement

    is_approved, reason = is_algorithm_fips_approved(cipher, mode, key_bits)

    if not is_approved:
        if status.mode == FIPSMode.ENABLED:
            raise FIPSViolationError(
                f"FIPS violation: {reason}. "
                f"Algorithm {cipher}-{key_bits}-{mode.upper()} is not allowed in FIPS mode."
            )
        else:  # PREFERRED mode
            logger.warning(
                "Non-FIPS algorithm used in FIPS-preferred mode",
                cipher=cipher,
                mode=mode,
                key_bits=key_bits,
                reason=reason,
            )


def validate_fips_startup() -> None:
    """Validate FIPS configuration at startup.

    Raises:
        FIPSConfigurationError: If FIPS mode is enabled but not available
    """
    status = get_fips_status()

    logger.info(
        "FIPS status",
        mode=status.mode.value,
        openssl_version=status.openssl_version,
        fips_available=status.openssl_fips_available,
        compliant=status.compliant,
    )

    if not status.compliant:
        raise FIPSConfigurationError(status.message)

    if status.mode == FIPSMode.ENABLED and status.fips_provider_loaded:
        logger.info("FIPS 140-2/140-3 mode is active")
    elif status.mode == FIPSMode.PREFERRED and not status.openssl_fips_available:
        logger.warning(
            "FIPS mode preferred but not available",
            recommendation="Install OpenSSL 3.x with FIPS provider for FIPS compliance",
        )


class FIPSError(Exception):
    """Base class for FIPS-related errors."""

    pass


class FIPSViolationError(FIPSError):
    """Raised when a FIPS-non-compliant algorithm is used in FIPS mode."""

    pass


class FIPSConfigurationError(FIPSError):
    """Raised when FIPS mode is misconfigured."""

    pass


def get_fips_approved_algorithms() -> dict:
    """Get list of FIPS-approved algorithms for documentation.

    Returns:
        Dictionary of approved algorithms by category
    """
    return {
        "symmetric_encryption": {
            "ciphers": list(FIPS_APPROVED_CIPHERS),
            "modes": list(FIPS_APPROVED_MODES),
            "key_sizes": list(FIPS_APPROVED_KEY_SIZES),
        },
        "hash_functions": list(FIPS_APPROVED_HASHES),
        "post_quantum": list(FIPS_APPROVED_PQC),
        "blocked_algorithms": list(NON_FIPS_ALGORITHMS),
    }
