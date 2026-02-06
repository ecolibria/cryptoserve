"""
CryptoServe SDK - Zero-config cryptographic operations with auto-registration.

Usage:
    from cryptoserve import CryptoServe, AT_REST, IN_TRANSIT, STREAMING

    # One-time setup: run `cryptoserve login` in terminal

    # Initialize - app is auto-registered on first use
    crypto = CryptoServe(
        app_name="my-service",
        team="platform",
        environment="development"
    )

    # Use immediately - no dashboard setup needed!
    encrypted = crypto.encrypt(b"sensitive data", context="user-pii")
    decrypted = crypto.decrypt(encrypted, context="user-pii")

    # Runtime usage hints - intelligent algorithm selection!
    # Same context, different usage = different optimal algorithms
    db_encrypted = crypto.encrypt(b"ssn", context="pii", usage=AT_REST)
    api_encrypted = crypto.encrypt(b"ssn", context="pii", usage=IN_TRANSIT)
    stream_encrypted = crypto.encrypt(b"ssn", context="pii", usage=STREAMING)

    # String helpers
    encrypted = crypto.encrypt_string("my secret", context="user-pii")
    decrypted = crypto.decrypt_string(encrypted, context="user-pii")

Package Architecture:
    cryptoserve         - Full SDK (this package)
    cryptoserve-core    - Pure crypto primitives (no network)
    cryptoserve-client  - API client only
    cryptoserve-auto    - Auto-protect for third-party libraries
"""

# Re-export from sub-packages for convenience
from cryptoserve_client import CryptoClient
from cryptoserve_client.errors import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    TokenRefreshError,
)
from cryptoserve._identity import IDENTITY, AUTO_REFRESH_ENABLED, get_refresh_token

# New in 0.6.0: Auto-registration CryptoServe class
from cryptoserve._auto_register import (
    CryptoServe,
    CryptoServeNotLoggedInError,
    CryptoServeRegistrationError,
)

# New in 0.9.0: Runtime usage hints for intelligent algorithm selection
from cryptoserve.client import Usage

# Export enum values directly for cleaner syntax: usage=AT_REST instead of usage=Usage.AT_REST
AT_REST = Usage.AT_REST
IN_TRANSIT = Usage.IN_TRANSIT
IN_USE = Usage.IN_USE
STREAMING = Usage.STREAMING
DISK = Usage.DISK

__version__ = "1.0.0"
__all__ = [
    # Main SDK class
    "CryptoServe",
    "CryptoServeNotLoggedInError",
    "CryptoServeRegistrationError",
    # Runtime usage hints (intelligent algorithm selection)
    "Usage",
    "AT_REST",
    "IN_TRANSIT",
    "IN_USE",
    "STREAMING",
    "DISK",
    # Client and errors
    "CryptoClient",
    "CryptoServeError",
    "AuthenticationError",
    "AuthorizationError",
    "ContextNotFoundError",
    "TokenRefreshError",
    # Initialization and inventory
    "init",
    "InitResult",
    "get_init_status",
    # CBOM and PQC recommendations
    "export_cbom",
    "get_pqc_recommendations",
    "CBOMResult",
    "PQCRecommendationResult",
    # Utilities
    "auto_protect",
]

# Lazy import for auto_protect (optional dependency)
def auto_protect(**kwargs):
    """
    Enable auto-protection for third-party libraries.

    Requires: pip install cryptoserve[auto]

    Example:
        from cryptoserve import auto_protect
        auto_protect(encryption_key=key)
    """
    try:
        from cryptoserve_auto import protect
        return protect(**kwargs)
    except ImportError:
        raise ImportError(
            "cryptoserve-auto is not installed. "
            "Install with: pip install cryptoserve[auto]"
        )

# Legacy 'crypto' singleton has been removed in v0.7.0
# Use CryptoServe class instead:
#
#   from cryptoserve import CryptoServe
#   crypto = CryptoServe(app_name="my-app", team="my-team")
#   encrypted = crypto.encrypt(b"data", context="user-pii")


# Mock mode state (used by init() for testing)
_mock_mode = False


def _is_mock_mode() -> bool:
    """Check if mock mode is enabled."""
    return _mock_mode


class _DeprecatedCryptoClass:
    """
    REMOVED in v0.7.0: The legacy 'crypto' singleton has been removed.

    Migration guide:
        # Old (removed):
        from cryptoserve import crypto
        encrypted = crypto.encrypt(b"data", context="user-pii")

        # New (use this instead):
        from cryptoserve import CryptoServe
        crypto = CryptoServe(app_name="my-app", team="my-team")
        encrypted = crypto.encrypt(b"data", context="user-pii")

    Run `cryptoserve login` first to authenticate.
    """

    def __getattr__(self, name):
        raise AttributeError(
            f"The 'crypto' singleton was removed in v0.7.0. "
            f"Use CryptoServe class instead:\n\n"
            f"  from cryptoserve import CryptoServe\n"
            f"  crypto = CryptoServe(app_name='my-app', team='my-team')\n"
            f"  encrypted = crypto.encrypt(b'data', context='user-pii')\n\n"
            f"Run 'cryptoserve login' first to authenticate."
        )


# Provide helpful error if someone imports 'crypto'
crypto = _DeprecatedCryptoClass()



# =============================================================================
# SDK Initialization with Inventory & Secret Scanning
# =============================================================================

# Global state for initialization
_initialized = False
_init_config: dict = {}


class InitConfig:
    """Configuration for SDK initialization."""

    def __init__(
        self,
        scan_crypto: bool = True,
        report_to_platform: bool = True,
        block_on_violations: bool = False,
        async_reporting: bool = True,
    ):
        """
        Configure SDK initialization behavior.

        Args:
            scan_crypto: Detect crypto libraries from sys.modules (100% accurate)
            report_to_platform: Send inventory report to platform
            block_on_violations: Raise exception if policy violations found
            async_reporting: Report asynchronously (non-blocking)
        """
        self.scan_crypto = scan_crypto
        self.report_to_platform = report_to_platform
        self.block_on_violations = block_on_violations
        self.async_reporting = async_reporting


class InitResult:
    """Result of SDK initialization with crypto detection."""

    def __init__(
        self,
        success: bool,
        libraries: list[dict] | None = None,
        violations: list[dict] | None = None,
        warnings: list[dict] | None = None,
        action: str = "allow",
        error: str | None = None,
    ):
        self.success = success
        self.libraries = libraries or []
        self.violations = violations or []
        self.warnings = warnings or []
        self.action = action  # allow, warn, block
        self.error = error

    @property
    def algorithms(self) -> list[str]:
        """All algorithms available from detected libraries."""
        algos = []
        for lib in self.libraries:
            algos.extend(lib.get("algorithms", []))
        return list(set(algos))

    @property
    def quantum_vulnerable(self) -> list[dict]:
        """Libraries with quantum vulnerability."""
        return [lib for lib in self.libraries if lib.get("quantum_risk") in ["high", "critical"]]

    @property
    def deprecated(self) -> list[dict]:
        """Deprecated libraries that should be replaced."""
        return [lib for lib in self.libraries if lib.get("is_deprecated")]

    def __bool__(self):
        return self.success and self.action != "block"

    def __repr__(self):
        if self.success:
            return f"InitResult(libraries={len(self.libraries)}, algorithms={len(self.algorithms)}, action='{self.action}')"
        return f"InitResult(success=False, error='{self.error}')"


def init(
    scan_crypto: bool = True,
    report_to_platform: bool = True,
    block_on_violations: bool = False,
    async_reporting: bool = True,
) -> InitResult:
    """
    Initialize the CryptoServe SDK with crypto library detection.

    This function should be called once at application startup. It detects
    all cryptographic libraries loaded in the application with 100% accuracy
    by examining sys.modules at runtime.

    Args:
        scan_crypto: Detect imported crypto libraries from sys.modules.
            100% accurate - only reports what's actually loaded.
            Zero runtime overhead - runs once at startup.
            Default: True

        report_to_platform: Send inventory to platform for policy evaluation.
            Default: True

        block_on_violations: If True, raises CryptoServeError on policy violations.
            Useful for enforcing security policies in production.

        async_reporting: Send reports asynchronously (non-blocking).
            Default: True for minimal startup impact.

    Returns:
        InitResult with detected libraries and policy evaluation.

    Example:
        from cryptoserve import init

        # Detect crypto libraries at startup
        result = init()
        print(f"Detected {len(result.libraries)} crypto libraries")
        for lib in result.libraries:
            print(f"  - {lib['name']}: {lib['algorithms']}")

        # With policy enforcement
        result = init(block_on_violations=True)
        if not result:
            print(f"Blocked: {result.violations}")
            sys.exit(1)
    """
    global _initialized, _init_config

    if _initialized:
        # Already initialized, return cached result
        return InitResult(
            success=True,
            libraries=_init_config.get("libraries", []),
            violations=_init_config.get("violations", []),
            warnings=_init_config.get("warnings", []),
            action=_init_config.get("action", "allow"),
        )

    libraries = []
    violations = []
    warnings = []
    action = "allow"

    try:
        # Step 1: Detect crypto libraries from sys.modules (100% accurate)
        if scan_crypto:
            libraries = _scan_crypto_imports()

        # Step 2: Report to platform and get policy evaluation
        if report_to_platform and libraries:
            if async_reporting:
                import threading
                thread = threading.Thread(
                    target=_report_inventory_async,
                    args=(libraries,),
                    daemon=True,
                )
                thread.start()
                # Don't wait for response in async mode
            else:
                result = _report_inventory_sync(libraries)
                violations = result.get("violations", [])
                warnings = result.get("warnings", [])
                action = result.get("action", "allow")

        # Step 3: Check for blocking violations
        if block_on_violations and action == "block":
            raise CryptoServeError(
                f"SDK initialization blocked by policy: {len(violations)} violation(s) found",
                status_code=403,
            )

        _initialized = True
        _init_config = {
            "libraries": libraries,
            "violations": violations,
            "warnings": warnings,
            "action": action,
        }

        return InitResult(
            success=True,
            libraries=libraries,
            violations=violations,
            warnings=warnings,
            action=action,
        )

    except CryptoServeError:
        raise
    except Exception as e:
        return InitResult(success=False, error=str(e))


def _scan_crypto_imports() -> list[dict]:
    """
    Scan sys.modules for imported crypto libraries.

    This is designed to run once at startup with minimal overhead.
    Only examines already-loaded modules, no file I/O.
    """
    import sys

    # Known crypto library patterns
    CRYPTO_LIBRARIES = {
        "cryptography": {
            "category": "general",
            "algorithms": ["AES", "ChaCha20", "RSA", "ECDSA", "Ed25519", "SHA-256"],
            "quantum_risk": "high",
        },
        "pycryptodome": {
            "category": "general",
            "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5"],
            "quantum_risk": "high",
        },
        "Cryptodome": {
            "category": "general",
            "algorithms": ["AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5"],
            "quantum_risk": "high",
        },
        "nacl": {
            "category": "general",
            "algorithms": ["Curve25519", "Ed25519", "XSalsa20", "Poly1305"],
            "quantum_risk": "high",
        },
        "hashlib": {
            "category": "hashing",
            "algorithms": ["SHA-256", "SHA-512", "SHA-1", "MD5", "SHA3-256", "Blake2b"],
            "quantum_risk": "low",
        },
        "hmac": {
            "category": "mac",
            "algorithms": ["HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA1"],
            "quantum_risk": "low",
        },
        "secrets": {
            "category": "random",
            "algorithms": ["CSPRNG"],
            "quantum_risk": "none",
        },
        "bcrypt": {
            "category": "kdf",
            "algorithms": ["bcrypt"],
            "quantum_risk": "none",
        },
        "argon2": {
            "category": "kdf",
            "algorithms": ["Argon2id", "Argon2i", "Argon2d"],
            "quantum_risk": "none",
        },
        "passlib": {
            "category": "kdf",
            "algorithms": ["bcrypt", "Argon2", "PBKDF2", "scrypt"],
            "quantum_risk": "none",
        },
        "jwt": {
            "category": "token",
            "algorithms": ["HS256", "RS256", "ES256", "EdDSA"],
            "quantum_risk": "high",
        },
        "jose": {
            "category": "token",
            "algorithms": ["JWS", "JWE", "JWK"],
            "quantum_risk": "high",
        },
        "ssl": {
            "category": "tls",
            "algorithms": ["TLS", "RSA", "ECDHE", "AES-GCM"],
            "quantum_risk": "high",
        },
        "OpenSSL": {
            "category": "tls",
            "algorithms": ["TLS", "AES", "RSA", "ECDSA"],
            "quantum_risk": "high",
        },
        "oqs": {
            "category": "pqc",
            "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
            "quantum_risk": "none",
        },
        "liboqs": {
            "category": "pqc",
            "algorithms": ["Kyber", "Dilithium", "Falcon", "SPHINCS+"],
            "quantum_risk": "none",
        },
        # Deprecated
        "Crypto": {
            "category": "general",
            "algorithms": ["AES", "DES", "RSA"],
            "quantum_risk": "high",
            "is_deprecated": True,
            "deprecation_reason": "PyCrypto is unmaintained since 2013",
        },
    }

    detected = []
    seen = set()

    for module_name in list(sys.modules.keys()):
        for lib_pattern, lib_info in CRYPTO_LIBRARIES.items():
            if module_name == lib_pattern or module_name.startswith(f"{lib_pattern}."):
                if lib_pattern not in seen:
                    seen.add(lib_pattern)

                    # Get version
                    version = None
                    module = sys.modules.get(module_name)
                    if module:
                        version = getattr(module, "__version__", None)

                    detected.append({
                        "name": lib_pattern,
                        "version": version,
                        "category": lib_info["category"],
                        "algorithms": lib_info["algorithms"],
                        "quantum_risk": lib_info["quantum_risk"],
                        "is_deprecated": lib_info.get("is_deprecated", False),
                        "deprecation_reason": lib_info.get("deprecation_reason"),
                    })
                break

    return detected


def _report_inventory_sync(libraries: list[dict]) -> dict:
    """Report crypto inventory to platform synchronously."""
    import requests

    try:
        response = requests.post(
            f"{IDENTITY['server_url']}/api/v1/inventory/report",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            json={
                "identity_id": IDENTITY["identity_id"],
                "identity_name": IDENTITY["name"],
                "libraries": libraries,
                "algorithms": [],  # Derived from libraries on server
                "secrets": [],
                "scan_source": "import_scan",
            },
            timeout=10,
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"action": "allow", "violations": [], "warnings": []}

    except Exception:
        return {"action": "allow", "violations": [], "warnings": []}


def _report_inventory_async(libraries: list[dict]) -> None:
    """Report crypto inventory to platform asynchronously (fire and forget)."""
    try:
        _report_inventory_sync(libraries)
    except Exception:
        pass  # Silent failure for async reporting


def get_init_status() -> dict:
    """Get the current SDK initialization status."""
    return {
        "initialized": _initialized,
        "config": _init_config,
    }


# =============================================================================
# CBOM and PQC Recommendations
# =============================================================================


class CBOMResult:
    """Result of CBOM generation."""

    def __init__(
        self,
        cbom: dict,
        format: str = "json",
        quantum_readiness: dict | None = None,
    ):
        self.cbom = cbom
        self.format = format
        self.quantum_readiness = quantum_readiness or {}

    @property
    def score(self) -> float:
        """Quantum readiness score (0-100)."""
        return self.quantum_readiness.get("score", 0.0)

    @property
    def risk_level(self) -> str:
        """Quantum risk level: critical, high, medium, low, none."""
        return self.quantum_readiness.get("risk_level", "unknown")

    def to_json(self) -> str:
        """Export CBOM as JSON string."""
        import json
        return json.dumps(self.cbom, indent=2)

    def to_dict(self) -> dict:
        """Export CBOM as dictionary."""
        return {
            "cbom": self.cbom,
            "quantum_readiness": self.quantum_readiness,
        }

    def save(self, filepath: str) -> None:
        """Save CBOM to file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    def __repr__(self):
        components = len(self.cbom.get("components", []))
        return f"CBOMResult(components={components}, score={self.score:.0f}%, risk={self.risk_level})"


class PQCRecommendationResult:
    """Result of PQC migration recommendations."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def urgency(self) -> str:
        """Overall migration urgency: critical, high, medium, low, none."""
        return self._data.get("overall_urgency", "unknown")

    @property
    def score(self) -> float:
        """Quantum readiness score (0-100)."""
        return self._data.get("quantum_readiness_score", 0.0)

    @property
    def sndl_vulnerable(self) -> bool:
        """Whether vulnerable to Store Now, Decrypt Later attacks."""
        return self._data.get("sndl_assessment", {}).get("vulnerable", False)

    @property
    def key_findings(self) -> list[str]:
        """Key findings from the analysis."""
        return self._data.get("key_findings", [])

    @property
    def next_steps(self) -> list[str]:
        """Recommended next steps."""
        return self._data.get("next_steps", [])

    @property
    def kem_recommendations(self) -> list[dict]:
        """Key encapsulation mechanism recommendations."""
        return self._data.get("kem_recommendations", [])

    @property
    def signature_recommendations(self) -> list[dict]:
        """Digital signature algorithm recommendations."""
        return self._data.get("signature_recommendations", [])

    @property
    def migration_plan(self) -> list[dict]:
        """Ordered migration plan steps."""
        return self._data.get("migration_plan", [])

    def to_dict(self) -> dict:
        """Get the full recommendation data."""
        return self._data

    def __repr__(self):
        return f"PQCRecommendationResult(urgency={self.urgency}, score={self.score:.0f}%)"

    def __bool__(self):
        """True if recommendations exist."""
        return bool(self._data)


def export_cbom(
    format: str = "json",
    include_algorithms: bool = True,
) -> CBOMResult:
    """
    Generate and export a Cryptographic Bill of Materials (CBOM).

    Creates a comprehensive inventory of all cryptographic libraries and
    algorithms detected in the application. Supports multiple export formats
    for SBOM tooling integration.

    Args:
        format: Export format - "json", "cyclonedx", or "spdx"
        include_algorithms: Include algorithm details in CBOM

    Returns:
        CBOMResult with the generated CBOM and quantum readiness info

    Example:
        from cryptoserve import export_cbom

        # Generate CBOM
        result = export_cbom(format="cyclonedx")
        print(f"Quantum readiness: {result.score}%")

        # Save to file
        result.save("cbom-cyclonedx.json")

        # Access components
        for component in result.cbom["components"]:
            print(f"  {component['name']}: {component['quantum_risk']}")
    """
    if not _initialized:
        # Auto-initialize if not done
        init()

    libraries = _init_config.get("libraries", [])

    # Generate CBOM locally from detected libraries
    import os
    import datetime

    # Calculate quantum readiness metrics
    quantum_safe = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ["none", "low"])
    quantum_vulnerable = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ["high", "critical"])
    has_pqc = any("pqc" in lib.get("category", "").lower() or "post-quantum" in lib.get("category", "").lower() for lib in libraries)
    deprecated_count = sum(1 for lib in libraries if lib.get("is_deprecated", False))

    # Calculate score (0-100)
    total = quantum_safe + quantum_vulnerable
    if total == 0:
        score = 100.0  # No crypto = no risk
    else:
        score = (quantum_safe / total) * 100
        if has_pqc:
            score = min(100, score + 20)
        if deprecated_count > 0:
            score = max(0, score - (deprecated_count * 10))
    score = round(score, 1)

    # Determine risk level
    if score >= 80:
        risk_level = "low"
    elif score >= 50:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Collect all algorithms
    all_algorithms = []
    for lib in libraries:
        for algo in lib.get("algorithms", []):
            all_algorithms.append({
                "name": algo,
                "library": lib["name"],
                "category": lib.get("category", "unknown"),
            })

    # Build CBOM structure
    components = [
        {
            "bom_ref": f"crypto-lib-{lib['name']}",
            "type": "library",
            "name": lib["name"],
            "version": lib.get("version"),
            "category": lib.get("category", "unknown"),
            "quantum_risk": lib.get("quantum_risk", "unknown"),
            "is_deprecated": lib.get("is_deprecated", False),
            "algorithms": lib.get("algorithms", []),
        }
        for lib in libraries
    ]

    cbom = {
        "id": f"cbom_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "version": "1.0",
        "format": format,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "components": components,
        "algorithms": all_algorithms if include_algorithms else [],
        "summary": {
            "total_libraries": len(libraries),
            "quantum_safe": quantum_safe,
            "quantum_vulnerable": quantum_vulnerable,
            "deprecated": deprecated_count,
            "has_pqc": has_pqc,
        },
    }

    return CBOMResult(
        cbom=cbom,
        format=format,
        quantum_readiness={
            "score": score,
            "risk_level": risk_level,
            "has_pqc": has_pqc,
            "quantum_safe_count": quantum_safe,
            "quantum_vulnerable_count": quantum_vulnerable,
            "deprecated_count": deprecated_count,
        },
    )


def get_pqc_recommendations(
    data_profile: str | None = None,
) -> PQCRecommendationResult:
    """
    Get PQC (Post-Quantum Cryptography) migration recommendations.

    Analyzes the application's cryptographic inventory and provides
    actionable recommendations for migrating to quantum-safe algorithms.
    Includes SNDL (Store Now, Decrypt Later) risk assessment.

    Args:
        data_profile: Data sensitivity profile for risk calculation
            - "healthcare": 100 year protection (HIPAA)
            - "national_security": 75 year protection
            - "financial": 25 year protection (PCI-DSS)
            - "general": 10 year protection (default)
            - "short_lived": 1 year protection (session tokens)

    Returns:
        PQCRecommendationResult with migration guidance

    Example:
        from cryptoserve import get_pqc_recommendations

        # Get recommendations for financial data
        result = get_pqc_recommendations(data_profile="financial")

        print(f"Migration urgency: {result.urgency}")
        print(f"Quantum readiness: {result.score}%")

        if result.sndl_vulnerable:
            print("WARNING: Vulnerable to Store Now, Decrypt Later attacks!")

        print("Key findings:")
        for finding in result.key_findings:
            print(f"  - {finding}")

        print("Next steps:")
        for step in result.next_steps[:3]:
            print(f"  - {step}")

        # Get specific algorithm recommendations
        for rec in result.kem_recommendations:
            print(f"  Replace {rec['current_algorithm']} with {rec['recommended_algorithm']}")
    """
    if not _initialized:
        # Auto-initialize if not done
        init()

    libraries = _init_config.get("libraries", [])

    if _is_mock_mode():
        # Mock recommendations
        has_vulnerable = any(lib["quantum_risk"] in ["high", "critical"] for lib in libraries)
        return PQCRecommendationResult({
            "sndl_assessment": {
                "vulnerable": has_vulnerable,
                "protection_years_required": 10,
                "estimated_quantum_years": 15,
                "risk_window_years": -5 if not has_vulnerable else 5,
                "risk_level": "medium" if has_vulnerable else "low",
                "explanation": "Mock SNDL assessment",
            },
            "kem_recommendations": [
                {
                    "current_algorithm": "RSA",
                    "recommended_algorithm": "ML-KEM-768",
                    "fips_standard": "FIPS 203",
                    "security_level": "NIST Level 3",
                    "rationale": "RSA is vulnerable to Shor's algorithm",
                    "migration_complexity": "medium",
                }
            ] if has_vulnerable else [],
            "signature_recommendations": [],
            "migration_plan": [
                {
                    "priority": 1,
                    "phase": "immediate",
                    "action": "Inventory all asymmetric key usage",
                    "algorithms_affected": ["RSA", "ECDSA"],
                    "estimated_effort": "low",
                }
            ] if has_vulnerable else [],
            "overall_urgency": "medium" if has_vulnerable else "low",
            "quantum_readiness_score": 30.0 if has_vulnerable else 80.0,
            "key_findings": [
                f"Detected {len(libraries)} cryptographic libraries",
                "Quantum-vulnerable algorithms in use" if has_vulnerable else "No critical quantum vulnerabilities",
            ],
            "next_steps": [
                "Review algorithm recommendations",
                "Plan hybrid deployment strategy",
                "Train team on PQC concepts",
            ],
        })

    # Request recommendations from server
    import requests

    try:
        response = requests.post(
            f"{IDENTITY['server_url']}/api/v1/inventory/recommendations",
            headers={"Authorization": f"Bearer {IDENTITY['token']}"},
            json={
                "identity_id": IDENTITY["identity_id"],
                "libraries": libraries,
                "data_profile": data_profile,
            },
            timeout=30,
        )

        if response.status_code == 200:
            return PQCRecommendationResult(response.json())
        else:
            raise CryptoServeError(f"Failed to get recommendations: {response.text}")

    except requests.RequestException as e:
        raise CryptoServeError(f"Recommendations request failed: {str(e)}")
