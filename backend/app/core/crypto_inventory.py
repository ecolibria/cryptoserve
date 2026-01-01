"""Crypto Inventory Service.

Analyzes application imports and dependencies to build a comprehensive
inventory of cryptographic libraries and algorithms in use.

This service is designed for:
1. SDK startup scanning (one-time, minimal overhead)
2. CI/CD pipeline integration
3. Background reporting to platform

Design Principles:
- Zero runtime overhead after initialization
- Async reporting to avoid blocking app startup
- Comprehensive detection of crypto libraries
"""

import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class InventorySource(str, Enum):
    """Source of inventory data."""
    IMPORT_SCAN = "import_scan"  # sys.modules analysis
    DEPENDENCY_FILE = "dependency_file"  # requirements.txt, package.json
    CODE_SCAN = "code_scan"  # Static code analysis
    RUNTIME_DETECTION = "runtime_detection"  # Detected during encrypt/decrypt


class QuantumRisk(str, Enum):
    """Quantum computing risk level."""
    NONE = "none"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectedLibrary:
    """A detected cryptographic library."""
    name: str
    version: str | None
    category: str  # symmetric, asymmetric, hashing, kdf, signing, pqc
    algorithms: list[str]
    quantum_risk: QuantumRisk
    source: InventorySource
    is_deprecated: bool = False
    deprecation_reason: str | None = None
    recommendation: str | None = None


@dataclass
class DetectedAlgorithm:
    """A detected cryptographic algorithm."""
    name: str
    category: str
    library: str
    quantum_risk: QuantumRisk
    is_weak: bool
    source: InventorySource
    weakness_reason: str | None = None
    usage_locations: list[str] = field(default_factory=list)


@dataclass
class CryptoInventory:
    """Complete cryptographic inventory for an application."""
    identity_id: str
    identity_name: str
    scan_timestamp: str
    libraries: list[DetectedLibrary]
    algorithms: list[DetectedAlgorithm]
    secrets_detected: list[dict]  # From SecretScanner
    quantum_summary: dict
    risk_summary: dict
    source: InventorySource


# Known cryptographic libraries by ecosystem
CRYPTO_LIBRARIES = {
    # Python libraries
    "cryptography": {
        "category": "general",
        "algorithms": ["AES", "ChaCha20", "RSA", "ECDSA", "Ed25519", "X25519", "SHA-256", "SHA-512", "PBKDF2", "Scrypt"],
        "quantum_risk": QuantumRisk.HIGH,  # Contains RSA/ECDSA
        "is_deprecated": False,
    },
    "pycryptodome": {
        "category": "general",
        "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5", "HMAC"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "pycryptodomex": {
        "category": "general",
        "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5", "HMAC"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "nacl": {
        "category": "general",
        "algorithms": ["Curve25519", "Ed25519", "XSalsa20", "Poly1305", "Blake2b"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "pynacl": {
        "category": "general",
        "algorithms": ["Curve25519", "Ed25519", "XSalsa20", "Poly1305", "Blake2b"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "hashlib": {
        "category": "hashing",
        "algorithms": ["SHA-256", "SHA-512", "SHA-1", "MD5", "SHA3-256", "Blake2b", "Blake2s"],
        "quantum_risk": QuantumRisk.LOW,
        "is_deprecated": False,
    },
    "hmac": {
        "category": "mac",
        "algorithms": ["HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA1", "HMAC-MD5"],
        "quantum_risk": QuantumRisk.LOW,
        "is_deprecated": False,
    },
    "secrets": {
        "category": "random",
        "algorithms": ["CSPRNG"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "bcrypt": {
        "category": "kdf",
        "algorithms": ["bcrypt"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "argon2": {
        "category": "kdf",
        "algorithms": ["Argon2id", "Argon2i", "Argon2d"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "argon2_cffi": {
        "category": "kdf",
        "algorithms": ["Argon2id", "Argon2i", "Argon2d"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "passlib": {
        "category": "kdf",
        "algorithms": ["bcrypt", "Argon2", "PBKDF2", "scrypt", "SHA-512-crypt"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "pyjwt": {
        "category": "token",
        "algorithms": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "jwt": {
        "category": "token",
        "algorithms": ["HS256", "RS256", "ES256"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "jose": {
        "category": "token",
        "algorithms": ["JWS", "JWE", "JWK"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "python_jose": {
        "category": "token",
        "algorithms": ["JWS", "JWE", "JWK", "RS256", "ES256", "HS256"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "jwcrypto": {
        "category": "token",
        "algorithms": ["JWS", "JWE", "JWK"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "fernet": {
        "category": "symmetric",
        "algorithms": ["AES-128-CBC", "HMAC-SHA256"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "pyotp": {
        "category": "otp",
        "algorithms": ["TOTP", "HOTP", "HMAC-SHA1"],
        "quantum_risk": QuantumRisk.LOW,
        "is_deprecated": False,
    },
    "onetimepass": {
        "category": "otp",
        "algorithms": ["TOTP", "HOTP"],
        "quantum_risk": QuantumRisk.LOW,
        "is_deprecated": False,
    },
    # Post-quantum libraries
    "liboqs": {
        "category": "pqc",
        "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "oqs": {
        "category": "pqc",
        "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    "pqcrypto": {
        "category": "pqc",
        "algorithms": ["Kyber", "Dilithium", "NTRU"],
        "quantum_risk": QuantumRisk.NONE,
        "is_deprecated": False,
    },
    # Deprecated/weak libraries
    "pycrypto": {
        "category": "general",
        "algorithms": ["AES", "DES", "RSA"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": True,
        "deprecation_reason": "Unmaintained since 2013, security vulnerabilities",
        "recommendation": "Migrate to cryptography or pycryptodome",
    },
    "m2crypto": {
        "category": "general",
        "algorithms": ["AES", "RSA", "DSA"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": True,
        "deprecation_reason": "Limited maintenance, use cryptography instead",
        "recommendation": "Migrate to cryptography library",
    },
    "Crypto": {
        "category": "general",
        "algorithms": ["AES", "DES", "RSA"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": True,
        "deprecation_reason": "PyCrypto is unmaintained",
        "recommendation": "Migrate to pycryptodome (drop-in replacement)",
    },
    # SSL/TLS
    "ssl": {
        "category": "tls",
        "algorithms": ["TLS", "SSL", "RSA", "ECDHE", "AES-GCM", "ChaCha20-Poly1305"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "OpenSSL": {
        "category": "tls",
        "algorithms": ["TLS", "AES", "RSA", "ECDSA", "ChaCha20"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
    "pyOpenSSL": {
        "category": "tls",
        "algorithms": ["TLS", "X.509", "RSA", "ECDSA"],
        "quantum_risk": QuantumRisk.HIGH,
        "is_deprecated": False,
    },
}

# Module name to library name mapping (for import detection)
MODULE_TO_LIBRARY = {
    "cryptography": "cryptography",
    "cryptography.fernet": "fernet",
    "cryptography.hazmat": "cryptography",
    "Crypto": "pycrypto",
    "Cryptodome": "pycryptodome",
    "nacl": "pynacl",
    "hashlib": "hashlib",
    "hmac": "hmac",
    "secrets": "secrets",
    "bcrypt": "bcrypt",
    "argon2": "argon2_cffi",
    "passlib": "passlib",
    "jwt": "pyjwt",
    "jose": "python_jose",
    "jwcrypto": "jwcrypto",
    "pyotp": "pyotp",
    "oqs": "liboqs",
    "ssl": "ssl",
    "OpenSSL": "pyOpenSSL",
}


class CryptoInventoryScanner:
    """Scans application for cryptographic library usage."""

    def __init__(self):
        self.detected_libraries: list[DetectedLibrary] = []
        self.detected_algorithms: list[DetectedAlgorithm] = []

    def scan_imports(self) -> list[DetectedLibrary]:
        """
        Scan sys.modules for imported crypto libraries.

        This is designed to run once at app startup with minimal overhead.
        Only examines already-loaded modules, no file I/O.

        Returns:
            List of detected crypto libraries
        """
        detected = []

        for module_name in list(sys.modules.keys()):
            # Check if module matches any known crypto library
            for pattern, library_name in MODULE_TO_LIBRARY.items():
                if module_name == pattern or module_name.startswith(f"{pattern}."):
                    if library_name in CRYPTO_LIBRARIES:
                        lib_info = CRYPTO_LIBRARIES[library_name]

                        # Get version if available
                        version = None
                        module = sys.modules.get(module_name)
                        if module:
                            version = getattr(module, "__version__", None)
                            if not version:
                                version = getattr(module, "VERSION", None)

                        # Avoid duplicates
                        if not any(d.name == library_name for d in detected):
                            detected.append(DetectedLibrary(
                                name=library_name,
                                version=version,
                                category=lib_info["category"],
                                algorithms=lib_info["algorithms"],
                                quantum_risk=lib_info["quantum_risk"],
                                source=InventorySource.IMPORT_SCAN,
                                is_deprecated=lib_info.get("is_deprecated", False),
                                deprecation_reason=lib_info.get("deprecation_reason"),
                                recommendation=lib_info.get("recommendation"),
                            ))
                        break

        self.detected_libraries = detected
        return detected

    def scan_environment(self) -> dict[str, Any]:
        """
        Scan environment for crypto-related configuration.

        Checks:
        - Environment variables for crypto settings
        - Python crypto-related flags
        - OpenSSL version

        Returns:
            Dict with environment crypto info
        """
        import os

        env_info = {
            "python_version": sys.version,
            "openssl_version": None,
            "fips_mode": False,
            "crypto_env_vars": {},
        }

        # Check OpenSSL version
        try:
            import ssl
            env_info["openssl_version"] = ssl.OPENSSL_VERSION
        except Exception:
            pass

        # Check for crypto-related environment variables
        crypto_env_patterns = [
            "CRYPTO", "SSL", "TLS", "KEY", "SECRET", "ENCRYPT",
            "FIPS", "OPENSSL", "CIPHER", "HASH"
        ]

        for key in os.environ:
            for pattern in crypto_env_patterns:
                if pattern in key.upper():
                    # Don't capture actual values, just note presence
                    env_info["crypto_env_vars"][key] = "[PRESENT]"
                    break

        return env_info

    def build_inventory(
        self,
        identity_id: str,
        identity_name: str,
        secrets: list[dict] | None = None,
    ) -> CryptoInventory:
        """
        Build complete crypto inventory.

        Args:
            identity_id: SDK identity ID
            identity_name: SDK identity name
            secrets: Optional detected secrets from SecretScanner

        Returns:
            Complete CryptoInventory
        """
        # Scan imports if not already done
        if not self.detected_libraries:
            self.scan_imports()

        # Build algorithm list from libraries
        algorithms = []
        for lib in self.detected_libraries:
            for algo in lib.algorithms:
                algorithms.append(DetectedAlgorithm(
                    name=algo,
                    category=lib.category,
                    library=lib.name,
                    quantum_risk=lib.quantum_risk,
                    is_weak=lib.is_deprecated,
                    weakness_reason=lib.deprecation_reason,
                    source=lib.source,
                ))

        # Build quantum summary
        quantum_summary = {
            "total_libraries": len(self.detected_libraries),
            "quantum_safe": sum(1 for lib in self.detected_libraries if lib.quantum_risk == QuantumRisk.NONE),
            "quantum_vulnerable": sum(1 for lib in self.detected_libraries if lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]),
            "has_pqc": any(lib.category == "pqc" for lib in self.detected_libraries),
        }

        # Build risk summary
        risk_summary = {
            "deprecated_libraries": sum(1 for lib in self.detected_libraries if lib.is_deprecated),
            "weak_algorithms": sum(1 for algo in algorithms if algo.is_weak),
            "secrets_detected": len(secrets) if secrets else 0,
            "recommendations": [],
        }

        # Add recommendations
        for lib in self.detected_libraries:
            if lib.is_deprecated and lib.recommendation:
                risk_summary["recommendations"].append({
                    "type": "deprecated_library",
                    "library": lib.name,
                    "recommendation": lib.recommendation,
                })

        if quantum_summary["quantum_vulnerable"] > 0 and not quantum_summary["has_pqc"]:
            risk_summary["recommendations"].append({
                "type": "quantum_readiness",
                "recommendation": "Consider adding post-quantum cryptography support for long-term data protection",
            })

        return CryptoInventory(
            identity_id=identity_id,
            identity_name=identity_name,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            libraries=self.detected_libraries,
            algorithms=algorithms,
            secrets_detected=secrets or [],
            quantum_summary=quantum_summary,
            risk_summary=risk_summary,
            source=InventorySource.IMPORT_SCAN,
        )


# Singleton instance
crypto_inventory_scanner = CryptoInventoryScanner()
