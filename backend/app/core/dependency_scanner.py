"""Dependency Scanner Engine.

Scans package files (package.json, requirements.txt, go.mod, etc.)
to detect cryptographic library dependencies.

This is complementary to code_scanner.py - it finds crypto at the
dependency level rather than in the actual code.
"""

import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PackageType(str, Enum):
    """Package ecosystem type."""
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    MAVEN = "maven"
    CARGO = "cargo"
    UNKNOWN = "unknown"


class QuantumRisk(str, Enum):
    """Quantum computing risk level."""
    NONE = "none"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CryptoDependency:
    """A detected cryptographic dependency."""
    name: str
    version: str | None
    package_type: PackageType
    category: str  # encryption, hashing, signing, tls, pqc, general
    algorithms: list[str]
    quantum_risk: QuantumRisk
    is_deprecated: bool = False
    deprecation_reason: str | None = None
    recommended_replacement: str | None = None
    description: str | None = None


@dataclass
class DependencyScanResult:
    """Result of dependency scanning."""
    dependencies: list[CryptoDependency]
    package_type: PackageType
    total_packages: int
    crypto_packages: int
    quantum_vulnerable_count: int
    deprecated_count: int
    recommendations: list[str]


class DependencyScannerError(Exception):
    """Dependency scanner error."""
    pass


# Known cryptographic packages database
CRYPTO_PACKAGES = {
    # NPM packages
    PackageType.NPM: {
        "crypto-js": {
            "category": "general",
            "algorithms": ["aes", "des", "3des", "rc4", "sha1", "sha256", "md5", "hmac"],
            "quantum_risk": QuantumRisk.LOW,
            "description": "JavaScript crypto library (includes weak algorithms)",
        },
        "bcrypt": {
            "category": "hashing",
            "algorithms": ["bcrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "bcryptjs": {
            "category": "hashing",
            "algorithms": ["bcrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "argon2": {
            "category": "hashing",
            "algorithms": ["argon2id", "argon2i", "argon2d"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "sodium-native": {
            "category": "general",
            "algorithms": ["xchacha20", "poly1305", "ed25519", "x25519", "blake2b", "argon2id"],
            "quantum_risk": QuantumRisk.HIGH,
            "description": "libsodium bindings (asymmetric is quantum vulnerable)",
        },
        "tweetnacl": {
            "category": "general",
            "algorithms": ["xsalsa20", "poly1305", "ed25519", "x25519", "sha512"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "jose": {
            "category": "signing",
            "algorithms": ["rsa", "ecdsa", "eddsa", "aes-gcm"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "jsonwebtoken": {
            "category": "signing",
            "algorithms": ["rsa", "ecdsa", "hmac"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "node-forge": {
            "category": "general",
            "algorithms": ["aes", "des", "3des", "rsa", "sha1", "sha256", "md5", "hmac"],
            "quantum_risk": QuantumRisk.HIGH,
            "description": "Full crypto library (includes deprecated algorithms)",
        },
        "openpgp": {
            "category": "encryption",
            "algorithms": ["rsa", "ecdsa", "ecdh", "aes", "sha256"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "libsodium-wrappers": {
            "category": "general",
            "algorithms": ["xchacha20", "poly1305", "ed25519", "x25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "scrypt-js": {
            "category": "hashing",
            "algorithms": ["scrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "pbkdf2": {
            "category": "hashing",
            "algorithms": ["pbkdf2"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "sjcl": {
            "category": "general",
            "algorithms": ["aes", "sha256", "hmac", "pbkdf2", "ccm", "gcm"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "aes-js": {
            "category": "encryption",
            "algorithms": ["aes"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "@noble/curves": {
            "category": "signing",
            "algorithms": ["ecdsa", "ed25519", "secp256k1"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "@noble/hashes": {
            "category": "hashing",
            "algorithms": ["sha256", "sha512", "blake2b", "blake3", "sha3", "keccak"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "@noble/ciphers": {
            "category": "encryption",
            "algorithms": ["aes", "chacha20", "salsa20"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "liboqs-node": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium", "sphincs", "falcon"],
            "quantum_risk": QuantumRisk.NONE,
            "description": "Post-quantum cryptography",
        },
        "@stablelib/x25519": {
            "category": "key_exchange",
            "algorithms": ["x25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "elliptic": {
            "category": "signing",
            "algorithms": ["ecdsa", "eddsa", "secp256k1"],
            "quantum_risk": QuantumRisk.HIGH,
        },
    },

    # PyPI packages
    PackageType.PYPI: {
        "cryptography": {
            "category": "general",
            "algorithms": ["aes", "chacha20", "rsa", "ecdsa", "ed25519", "x25519", "sha256", "sha512", "blake2b"],
            "quantum_risk": QuantumRisk.HIGH,
            "description": "Comprehensive crypto library (asymmetric is quantum vulnerable)",
        },
        "pycryptodome": {
            "category": "general",
            "algorithms": ["aes", "des", "3des", "rsa", "dsa", "ecdsa", "sha256", "md5"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "pycryptodomex": {
            "category": "general",
            "algorithms": ["aes", "des", "3des", "rsa", "dsa", "ecdsa", "sha256", "md5"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "pynacl": {
            "category": "general",
            "algorithms": ["xchacha20", "poly1305", "ed25519", "x25519", "blake2b", "argon2"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "bcrypt": {
            "category": "hashing",
            "algorithms": ["bcrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "argon2-cffi": {
            "category": "hashing",
            "algorithms": ["argon2id", "argon2i", "argon2d"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "passlib": {
            "category": "hashing",
            "algorithms": ["argon2", "bcrypt", "scrypt", "pbkdf2", "sha256_crypt", "md5_crypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "pyopenssl": {
            "category": "tls",
            "algorithms": ["tls", "rsa", "ecdsa", "aes"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "pyjwt": {
            "category": "signing",
            "algorithms": ["rsa", "ecdsa", "eddsa", "hmac"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "python-jose": {
            "category": "signing",
            "algorithms": ["rsa", "ecdsa", "hmac", "aes-gcm"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "ecdsa": {
            "category": "signing",
            "algorithms": ["ecdsa"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "ed25519": {
            "category": "signing",
            "algorithms": ["ed25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "liboqs-python": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium", "sphincs", "falcon"],
            "quantum_risk": QuantumRisk.NONE,
            "description": "Post-quantum cryptography",
        },
        "oqs": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "hashlib": {
            "category": "hashing",
            "algorithms": ["sha256", "sha512", "sha1", "md5", "blake2b"],
            "quantum_risk": QuantumRisk.LOW,
            "description": "Standard library hashing (stdlib)",
        },
        "scrypt": {
            "category": "hashing",
            "algorithms": ["scrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "cryptoserve-client": {
            "category": "general",
            "algorithms": ["aes-gcm", "chacha20-poly1305", "ed25519", "x25519", "argon2id", "sha256"],
            "quantum_risk": QuantumRisk.HIGH,
            "description": "CryptoServe SDK - manages crypto agility",
        },
    },

    # Go packages
    PackageType.GO: {
        "crypto/aes": {
            "category": "encryption",
            "algorithms": ["aes"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "crypto/des": {
            "category": "encryption",
            "algorithms": ["des", "3des"],
            "quantum_risk": QuantumRisk.CRITICAL,
            "is_deprecated": True,
            "deprecation_reason": "DES/3DES are deprecated",
        },
        "crypto/rsa": {
            "category": "encryption",
            "algorithms": ["rsa"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "crypto/ecdsa": {
            "category": "signing",
            "algorithms": ["ecdsa"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "crypto/ed25519": {
            "category": "signing",
            "algorithms": ["ed25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "crypto/sha256": {
            "category": "hashing",
            "algorithms": ["sha256"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "crypto/sha512": {
            "category": "hashing",
            "algorithms": ["sha512"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "crypto/sha1": {
            "category": "hashing",
            "algorithms": ["sha1"],
            "quantum_risk": QuantumRisk.CRITICAL,
            "is_deprecated": True,
            "deprecation_reason": "SHA-1 has collision attacks",
        },
        "crypto/md5": {
            "category": "hashing",
            "algorithms": ["md5"],
            "quantum_risk": QuantumRisk.CRITICAL,
            "is_deprecated": True,
            "deprecation_reason": "MD5 is cryptographically broken",
        },
        "golang.org/x/crypto/chacha20poly1305": {
            "category": "encryption",
            "algorithms": ["chacha20-poly1305"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "golang.org/x/crypto/argon2": {
            "category": "hashing",
            "algorithms": ["argon2"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "golang.org/x/crypto/bcrypt": {
            "category": "hashing",
            "algorithms": ["bcrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "golang.org/x/crypto/scrypt": {
            "category": "hashing",
            "algorithms": ["scrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "golang.org/x/crypto/nacl": {
            "category": "general",
            "algorithms": ["xchacha20", "poly1305", "x25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "golang.org/x/crypto/curve25519": {
            "category": "key_exchange",
            "algorithms": ["x25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "github.com/cloudflare/circl": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium", "x25519", "ed25519"],
            "quantum_risk": QuantumRisk.NONE,
            "description": "Post-quantum + classical crypto",
        },
    },

    # Cargo (Rust) packages
    PackageType.CARGO: {
        "ring": {
            "category": "general",
            "algorithms": ["aes-gcm", "chacha20-poly1305", "rsa", "ecdsa", "ed25519", "sha256", "sha512", "pbkdf2"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "rustcrypto": {
            "category": "general",
            "algorithms": ["aes", "chacha20", "sha2", "blake2", "pbkdf2"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "aes": {
            "category": "encryption",
            "algorithms": ["aes"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "chacha20poly1305": {
            "category": "encryption",
            "algorithms": ["chacha20-poly1305"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "ed25519-dalek": {
            "category": "signing",
            "algorithms": ["ed25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "x25519-dalek": {
            "category": "key_exchange",
            "algorithms": ["x25519"],
            "quantum_risk": QuantumRisk.HIGH,
        },
        "argon2": {
            "category": "hashing",
            "algorithms": ["argon2"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "bcrypt": {
            "category": "hashing",
            "algorithms": ["bcrypt"],
            "quantum_risk": QuantumRisk.NONE,
        },
        "sha2": {
            "category": "hashing",
            "algorithms": ["sha256", "sha512"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "blake2": {
            "category": "hashing",
            "algorithms": ["blake2b", "blake2s"],
            "quantum_risk": QuantumRisk.LOW,
        },
        "pqcrypto": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium", "sphincs"],
            "quantum_risk": QuantumRisk.NONE,
            "description": "Post-quantum cryptography",
        },
        "oqs": {
            "category": "pqc",
            "algorithms": ["kyber", "dilithium", "falcon"],
            "quantum_risk": QuantumRisk.NONE,
        },
    },
}


class DependencyScanner:
    """Scans package files for cryptographic dependencies."""

    def scan_package_json(self, content: str) -> DependencyScanResult:
        """Scan package.json for crypto dependencies."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise DependencyScannerError(f"Invalid JSON: {e}")

        deps = {}
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            deps.update(data.get(key, {}))

        crypto_deps = []
        packages = CRYPTO_PACKAGES[PackageType.NPM]

        for name, version in deps.items():
            if name in packages:
                pkg_info = packages[name]
                crypto_deps.append(CryptoDependency(
                    name=name,
                    version=version,
                    package_type=PackageType.NPM,
                    category=pkg_info["category"],
                    algorithms=pkg_info["algorithms"],
                    quantum_risk=pkg_info["quantum_risk"],
                    is_deprecated=pkg_info.get("is_deprecated", False),
                    deprecation_reason=pkg_info.get("deprecation_reason"),
                    recommended_replacement=pkg_info.get("recommended_replacement"),
                    description=pkg_info.get("description"),
                ))

        return self._build_result(crypto_deps, PackageType.NPM, len(deps))

    def scan_requirements_txt(self, content: str) -> DependencyScanResult:
        """Scan requirements.txt for crypto dependencies."""
        deps = {}
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package==version or package>=version etc.
            match = re.match(r"([a-zA-Z0-9_-]+)(?:[<>=!]+(.*))?", line)
            if match:
                name = match.group(1).lower().replace("_", "-")
                version = match.group(2)
                deps[name] = version

        crypto_deps = []
        packages = CRYPTO_PACKAGES[PackageType.PYPI]

        for name, version in deps.items():
            if name in packages:
                pkg_info = packages[name]
                crypto_deps.append(CryptoDependency(
                    name=name,
                    version=version,
                    package_type=PackageType.PYPI,
                    category=pkg_info["category"],
                    algorithms=pkg_info["algorithms"],
                    quantum_risk=pkg_info["quantum_risk"],
                    is_deprecated=pkg_info.get("is_deprecated", False),
                    deprecation_reason=pkg_info.get("deprecation_reason"),
                    recommended_replacement=pkg_info.get("recommended_replacement"),
                    description=pkg_info.get("description"),
                ))

        return self._build_result(crypto_deps, PackageType.PYPI, len(deps))

    def scan_go_mod(self, content: str) -> DependencyScanResult:
        """Scan go.mod for crypto dependencies."""
        deps = {}

        for line in content.split("\n"):
            line = line.strip()

            # Match require lines
            if line.startswith("require"):
                continue

            # Match dependency lines like: github.com/foo/bar v1.0.0
            match = re.match(r"([a-zA-Z0-9./_-]+)\s+(v[\d.]+(?:-[a-zA-Z0-9.-]+)?)", line)
            if match:
                path = match.group(1)
                version = match.group(2)
                deps[path] = version

        crypto_deps = []
        packages = CRYPTO_PACKAGES[PackageType.GO]

        for path, version in deps.items():
            # Check for stdlib crypto imports
            for pkg_path in packages:
                if path == pkg_path or path.endswith(pkg_path):
                    pkg_info = packages[pkg_path]
                    crypto_deps.append(CryptoDependency(
                        name=path,
                        version=version,
                        package_type=PackageType.GO,
                        category=pkg_info["category"],
                        algorithms=pkg_info["algorithms"],
                        quantum_risk=pkg_info["quantum_risk"],
                        is_deprecated=pkg_info.get("is_deprecated", False),
                        deprecation_reason=pkg_info.get("deprecation_reason"),
                        recommended_replacement=pkg_info.get("recommended_replacement"),
                        description=pkg_info.get("description"),
                    ))
                    break

        return self._build_result(crypto_deps, PackageType.GO, len(deps))

    def scan_cargo_toml(self, content: str) -> DependencyScanResult:
        """Scan Cargo.toml for crypto dependencies."""
        deps = {}

        in_deps = False
        for line in content.split("\n"):
            line = line.strip()

            if line.startswith("[dependencies]") or line.startswith("[dev-dependencies]"):
                in_deps = True
                continue
            elif line.startswith("[") and in_deps:
                in_deps = False
                continue

            if in_deps:
                # Match: package = "version" or package = { version = "..." }
                match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
                if match:
                    deps[match.group(1)] = match.group(2)
                else:
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*\{', line)
                    if match:
                        deps[match.group(1)] = None

        crypto_deps = []
        packages = CRYPTO_PACKAGES[PackageType.CARGO]

        for name, version in deps.items():
            if name in packages:
                pkg_info = packages[name]
                crypto_deps.append(CryptoDependency(
                    name=name,
                    version=version,
                    package_type=PackageType.CARGO,
                    category=pkg_info["category"],
                    algorithms=pkg_info["algorithms"],
                    quantum_risk=pkg_info["quantum_risk"],
                    is_deprecated=pkg_info.get("is_deprecated", False),
                    deprecation_reason=pkg_info.get("deprecation_reason"),
                    recommended_replacement=pkg_info.get("recommended_replacement"),
                    description=pkg_info.get("description"),
                ))

        return self._build_result(crypto_deps, PackageType.CARGO, len(deps))

    def scan(self, content: str, filename: str | None = None) -> DependencyScanResult:
        """Auto-detect file type and scan."""
        if filename:
            filename = filename.lower()
            if filename == "package.json":
                return self.scan_package_json(content)
            elif filename in ("requirements.txt", "requirements-dev.txt"):
                return self.scan_requirements_txt(content)
            elif filename == "go.mod":
                return self.scan_go_mod(content)
            elif filename == "cargo.toml":
                return self.scan_cargo_toml(content)

        # Try to auto-detect
        content = content.strip()
        if content.startswith("{"):
            return self.scan_package_json(content)
        elif "require" in content and "go " in content:
            return self.scan_go_mod(content)
        elif "[package]" in content or "[dependencies]" in content:
            return self.scan_cargo_toml(content)
        else:
            return self.scan_requirements_txt(content)

    def _build_result(
        self,
        deps: list[CryptoDependency],
        package_type: PackageType,
        total_packages: int,
    ) -> DependencyScanResult:
        """Build the scan result with recommendations."""
        quantum_vulnerable = [d for d in deps if d.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]]
        deprecated = [d for d in deps if d.is_deprecated]

        recommendations = []

        if quantum_vulnerable:
            algorithms = set()
            for d in quantum_vulnerable:
                algorithms.update(d.algorithms)
            recommendations.append(
                f"Plan quantum migration: {len(quantum_vulnerable)} packages use quantum-vulnerable algorithms ({', '.join(sorted(algorithms))})"
            )

        if deprecated:
            for d in deprecated:
                rec = f"Replace deprecated {d.name}"
                if d.recommended_replacement:
                    rec += f" with {d.recommended_replacement}"
                if d.deprecation_reason:
                    rec += f" ({d.deprecation_reason})"
                recommendations.append(rec)

        if not deps:
            recommendations.append("No known cryptographic dependencies detected")

        return DependencyScanResult(
            dependencies=deps,
            package_type=package_type,
            total_packages=total_packages,
            crypto_packages=len(deps),
            quantum_vulnerable_count=len(quantum_vulnerable),
            deprecated_count=len(deprecated),
            recommendations=recommendations,
        )

    def get_known_packages(self, package_type: PackageType | None = None) -> dict:
        """Get all known cryptographic packages."""
        if package_type:
            return {package_type.value: list(CRYPTO_PACKAGES.get(package_type, {}).keys())}

        return {
            pt.value: list(packages.keys())
            for pt, packages in CRYPTO_PACKAGES.items()
        }
