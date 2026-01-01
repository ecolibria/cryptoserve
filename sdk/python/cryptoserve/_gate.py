"""
Gate scanning logic for CryptoServe CI/CD integration.

Scans source files for cryptographic usage and applies policies.
Works offline without server connection.
"""

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generator

from ._policies import (
    Action,
    Finding,
    GateResult,
    PolicyEngine,
    Severity,
    get_policy,
    load_config,
    ALGORITHM_DATABASE,
)


# File extensions to scan by language
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py", ".pyx", ".pyi"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx", ".mts", ".cts"],
    "go": [".go"],
    "java": [".java"],
    "kotlin": [".kt", ".kts"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"],
    "csharp": [".cs"],
    "rust": [".rs"],
    "ruby": [".rb"],
    "php": [".php"],
}

# All scannable extensions
ALL_EXTENSIONS = set()
for exts in LANGUAGE_EXTENSIONS.values():
    ALL_EXTENSIONS.update(exts)


@dataclass
class CryptoUsage:
    """A detected crypto usage in source code."""

    file: str
    line: int
    algorithm: str
    library: str | None
    context: str  # Code snippet


# Patterns for detecting cryptographic usage
# Format: (pattern, algorithm, library_hint)
CRYPTO_PATTERNS: list[tuple[str, str, str | None]] = [
    # Hash algorithms
    (r"\bhashlib\.md5\b", "md5", "hashlib"),
    (r"\bhashlib\.sha1\b", "sha1", "hashlib"),
    (r"\bhashlib\.sha256\b", "sha256", "hashlib"),
    (r"\bhashlib\.sha384\b", "sha384", "hashlib"),
    (r"\bhashlib\.sha512\b", "sha512", "hashlib"),
    (r"\bhashlib\.sha3_", "sha3", "hashlib"),
    (r"\bhashlib\.blake2", "blake2", "hashlib"),
    (r"\.new\(['\"]md5['\"]", "md5", None),
    (r"\.new\(['\"]sha1['\"]", "sha1", None),
    (r"\.new\(['\"]sha256['\"]", "sha256", None),
    (r"MD5\.new\(", "md5", "pycryptodome"),
    (r"SHA\.new\(", "sha1", "pycryptodome"),
    (r"SHA256\.new\(", "sha256", "pycryptodome"),
    (r"SHA512\.new\(", "sha512", "pycryptodome"),
    # Symmetric encryption
    (r"\bDES\.new\(", "des", "pycryptodome"),
    (r"\bDES3\.new\(", "3des", "pycryptodome"),
    (r"\bAES\.new\(", "aes", "pycryptodome"),
    (r"\bARC4\.new\(", "rc4", "pycryptodome"),
    (r"\bRC2\.new\(", "rc2", "pycryptodome"),
    (r"\bBlowfish\.new\(", "blowfish", "pycryptodome"),
    (r"algorithms\.AES\b", "aes", "cryptography"),
    (r"algorithms\.TripleDES\b", "3des", "cryptography"),
    (r"Fernet\s*\(", "aes-128", "cryptography"),
    (r"ChaCha20Poly1305\s*\(", "chacha20-poly1305", "cryptography"),
    (r"AESGCM\s*\(", "aes", "cryptography"),
    (r"AESCCM\s*\(", "aes", "cryptography"),
    # Asymmetric/Key Exchange
    (r"RSA\.generate\(", "rsa", "pycryptodome"),
    (r"rsa\.generate_private_key\(", "rsa", "cryptography"),
    (r"ec\.generate_private_key\(", "ecdsa", "cryptography"),
    (r"dsa\.generate_private_key\(", "dsa", "cryptography"),
    (r"x25519\.X25519PrivateKey", "x25519", "cryptography"),
    (r"ed25519\.Ed25519PrivateKey", "ed25519", "cryptography"),
    (r"X25519PrivateKey\.generate\(", "x25519", "cryptography"),
    (r"Ed25519PrivateKey\.generate\(", "ed25519", "cryptography"),
    (r"ECDH\s*\(", "ecdh", None),
    (r"DiffieHellman", "diffie-hellman", None),
    # KDFs
    (r"\bpbkdf2_hmac\b", "pbkdf2", "hashlib"),
    (r"PBKDF2HMAC\s*\(", "pbkdf2", "cryptography"),
    (r"\bbcrypt\.", "bcrypt", "bcrypt"),
    (r"\bargon2\.", "argon2", "argon2"),
    (r"\bscrypt\(", "scrypt", None),
    # JavaScript/Node patterns
    (r"crypto\.createHash\(['\"]md5['\"]", "md5", "crypto"),
    (r"crypto\.createHash\(['\"]sha1['\"]", "sha1", "crypto"),
    (r"crypto\.createHash\(['\"]sha256['\"]", "sha256", "crypto"),
    (r"crypto\.createCipher\(", "des", "crypto"),  # Legacy, often DES
    (r"crypto\.createCipheriv\(['\"]aes", "aes", "crypto"),
    (r"crypto\.createCipheriv\(['\"]des", "des", "crypto"),
    (r"crypto\.generateKeyPair\(['\"]rsa", "rsa", "crypto"),
    (r"crypto\.generateKeyPair\(['\"]ec", "ecdsa", "crypto"),
    (r"crypto\.diffieHellman\(", "diffie-hellman", "crypto"),
    (r"SubtleCrypto", "aes", "webcrypto"),
    (r"subtle\.encrypt\(", "aes", "webcrypto"),
    (r"subtle\.generateKey\(", "aes", "webcrypto"),
    # Go patterns
    (r"crypto/md5", "md5", "crypto"),
    (r"crypto/sha1", "sha1", "crypto"),
    (r"crypto/sha256", "sha256", "crypto"),
    (r"crypto/sha512", "sha512", "crypto"),
    (r"crypto/des", "des", "crypto"),
    (r"crypto/aes", "aes", "crypto"),
    (r"crypto/rsa", "rsa", "crypto"),
    (r"crypto/ecdsa", "ecdsa", "crypto"),
    (r"crypto/ed25519", "ed25519", "crypto"),
    (r"x/crypto/chacha20poly1305", "chacha20-poly1305", "x/crypto"),
    (r"x/crypto/argon2", "argon2", "x/crypto"),
    (r"x/crypto/bcrypt", "bcrypt", "x/crypto"),
    # Java patterns
    (r'MessageDigest\.getInstance\(["\']MD5["\']', "md5", "java.security"),
    (r'MessageDigest\.getInstance\(["\']SHA-1["\']', "sha1", "java.security"),
    (r'MessageDigest\.getInstance\(["\']SHA-256["\']', "sha256", "java.security"),
    (r'Cipher\.getInstance\(["\']DES', "des", "javax.crypto"),
    (r'Cipher\.getInstance\(["\']DESede', "3des", "javax.crypto"),
    (r'Cipher\.getInstance\(["\']AES', "aes", "javax.crypto"),
    (r'Cipher\.getInstance\(["\']RSA', "rsa", "javax.crypto"),
    (r'KeyPairGenerator\.getInstance\(["\']RSA', "rsa", "java.security"),
    (r'KeyPairGenerator\.getInstance\(["\']EC', "ecdsa", "java.security"),
    (r'KeyPairGenerator\.getInstance\(["\']DSA', "dsa", "java.security"),
    # Post-quantum
    (r"\bkyber\b", "kyber", None),
    (r"\bml[_-]?kem\b", "ml-kem", None),
    (r"\bdilithium\b", "dilithium", None),
    (r"\bml[_-]?dsa\b", "ml-dsa", None),
    (r"\bsphincs\b", "sphincs", None),
    (r"\bslh[_-]?dsa\b", "slh-dsa", None),
]

# Compiled patterns for performance
COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), algo, lib) for p, algo, lib in CRYPTO_PATTERNS]


# Dependency file names to scan
DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
}


# Known crypto packages database (simplified for offline use)
CRYPTO_PACKAGES: dict[str, dict[str, Any]] = {
    # NPM packages
    "crypto-js": {"algorithms": ["aes", "des", "3des", "md5", "sha1"], "quantum_risk": "low", "deprecated": False},
    "bcrypt": {"algorithms": ["bcrypt"], "quantum_risk": "none", "deprecated": False},
    "bcryptjs": {"algorithms": ["bcrypt"], "quantum_risk": "none", "deprecated": False},
    "argon2": {"algorithms": ["argon2"], "quantum_risk": "none", "deprecated": False},
    "sodium-native": {"algorithms": ["ed25519", "x25519", "chacha20"], "quantum_risk": "high", "deprecated": False},
    "tweetnacl": {"algorithms": ["ed25519", "x25519", "salsa20"], "quantum_risk": "high", "deprecated": False},
    "jose": {"algorithms": ["rsa", "ecdsa", "eddsa"], "quantum_risk": "high", "deprecated": False},
    "jsonwebtoken": {"algorithms": ["rsa", "ecdsa", "hmac"], "quantum_risk": "high", "deprecated": False},
    "node-forge": {"algorithms": ["rsa", "aes", "des", "md5", "sha1"], "quantum_risk": "high", "deprecated": False},
    "openpgp": {"algorithms": ["rsa", "ecdsa", "ecdh", "aes"], "quantum_risk": "high", "deprecated": False},
    "elliptic": {"algorithms": ["ecdsa", "ecdh"], "quantum_risk": "high", "deprecated": False},
    "node-rsa": {"algorithms": ["rsa"], "quantum_risk": "high", "deprecated": False},
    # Python packages
    "cryptography": {"algorithms": ["aes", "rsa", "ecdsa", "ed25519"], "quantum_risk": "high", "deprecated": False},
    "pycryptodome": {"algorithms": ["aes", "rsa", "ecdsa", "des", "3des"], "quantum_risk": "high", "deprecated": False},
    "pycryptodomex": {"algorithms": ["aes", "rsa", "ecdsa", "des", "3des"], "quantum_risk": "high", "deprecated": False},
    "pycrypto": {"algorithms": ["aes", "rsa", "des"], "quantum_risk": "high", "deprecated": True, "reason": "Unmaintained, use pycryptodome"},
    "pynacl": {"algorithms": ["ed25519", "x25519", "chacha20"], "quantum_risk": "high", "deprecated": False},
    "pyopenssl": {"algorithms": ["rsa", "ecdsa", "aes"], "quantum_risk": "high", "deprecated": False},
    "paramiko": {"algorithms": ["rsa", "ecdsa", "ed25519", "aes"], "quantum_risk": "high", "deprecated": False},
    "passlib": {"algorithms": ["bcrypt", "argon2", "pbkdf2", "sha256", "md5"], "quantum_risk": "low", "deprecated": False},
    "python-jose": {"algorithms": ["rsa", "ecdsa", "hmac"], "quantum_risk": "high", "deprecated": False},
    "pyjwt": {"algorithms": ["rsa", "ecdsa", "hmac"], "quantum_risk": "high", "deprecated": False},
    # Go packages (module paths)
    "golang.org/x/crypto": {"algorithms": ["ed25519", "x25519", "chacha20", "argon2"], "quantum_risk": "high", "deprecated": False},
    "crypto/rsa": {"algorithms": ["rsa"], "quantum_risk": "high", "deprecated": False},
    "crypto/ecdsa": {"algorithms": ["ecdsa"], "quantum_risk": "high", "deprecated": False},
    "crypto/ed25519": {"algorithms": ["ed25519"], "quantum_risk": "high", "deprecated": False},
    "crypto/des": {"algorithms": ["des", "3des"], "quantum_risk": "none", "deprecated": True, "reason": "DES is cryptographically broken"},
    "crypto/md5": {"algorithms": ["md5"], "quantum_risk": "none", "deprecated": True, "reason": "MD5 is cryptographically broken"},
    "crypto/sha1": {"algorithms": ["sha1"], "quantum_risk": "none", "deprecated": True, "reason": "SHA1 has collision attacks"},
    # Rust packages
    "ring": {"algorithms": ["aes", "rsa", "ecdsa", "ed25519", "chacha20"], "quantum_risk": "high", "deprecated": False},
    "rustls": {"algorithms": ["aes", "chacha20", "ecdsa", "ed25519"], "quantum_risk": "high", "deprecated": False},
    "ed25519-dalek": {"algorithms": ["ed25519"], "quantum_risk": "high", "deprecated": False},
    "x25519-dalek": {"algorithms": ["x25519"], "quantum_risk": "high", "deprecated": False},
    "rsa": {"algorithms": ["rsa"], "quantum_risk": "high", "deprecated": False},
    "aes-gcm": {"algorithms": ["aes"], "quantum_risk": "none", "deprecated": False},
    "chacha20poly1305": {"algorithms": ["chacha20"], "quantum_risk": "none", "deprecated": False},
    # Post-quantum packages (safe)
    "liboqs": {"algorithms": ["kyber", "dilithium", "sphincs"], "quantum_risk": "none", "deprecated": False},
    "liboqs-python": {"algorithms": ["kyber", "dilithium", "sphincs"], "quantum_risk": "none", "deprecated": False},
    "liboqs-node": {"algorithms": ["kyber", "dilithium", "sphincs"], "quantum_risk": "none", "deprecated": False},
    "pqcrypto": {"algorithms": ["kyber", "dilithium", "sphincs"], "quantum_risk": "none", "deprecated": False},
    "oqs": {"algorithms": ["kyber", "dilithium", "sphincs"], "quantum_risk": "none", "deprecated": False},
}


@dataclass
class DepUsage:
    """A detected crypto dependency."""
    file: str
    package: str
    version: str | None
    algorithms: list[str]
    quantum_risk: str
    deprecated: bool
    deprecation_reason: str | None = None


# Directories to skip
SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    ".tox",
    ".eggs",
    "*.egg-info",
    ".mypy_cache",
    ".ruff_cache",
    "vendor",
    "third_party",
}


def scan_dependency_file(file_path: Path) -> list[DepUsage]:
    """Scan a dependency file for crypto packages."""
    usages: list[DepUsage] = []
    filename = file_path.name.lower()

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return usages

    if filename == "package.json" or filename == "package-lock.json":
        usages.extend(_scan_package_json(file_path, content))
    elif filename == "requirements.txt":
        usages.extend(_scan_requirements_txt(file_path, content))
    elif filename == "go.mod" or filename == "go.sum":
        usages.extend(_scan_go_mod(file_path, content))
    elif filename == "cargo.toml" or filename == "cargo.lock":
        usages.extend(_scan_cargo_toml(file_path, content))
    elif filename == "pyproject.toml":
        usages.extend(_scan_pyproject_toml(file_path, content))

    return usages


def _scan_package_json(file_path: Path, content: str) -> list[DepUsage]:
    """Scan package.json for crypto dependencies."""
    usages: list[DepUsage] = []
    try:
        import json
        data = json.loads(content)
        all_deps = {}
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            if key in data:
                all_deps.update(data[key])

        for pkg, version in all_deps.items():
            pkg_lower = pkg.lower()
            if pkg_lower in CRYPTO_PACKAGES:
                info = CRYPTO_PACKAGES[pkg_lower]
                usages.append(DepUsage(
                    file=str(file_path),
                    package=pkg,
                    version=version if isinstance(version, str) else None,
                    algorithms=info["algorithms"],
                    quantum_risk=info["quantum_risk"],
                    deprecated=info.get("deprecated", False),
                    deprecation_reason=info.get("reason"),
                ))
    except (json.JSONDecodeError, KeyError):
        pass
    return usages


def _scan_requirements_txt(file_path: Path, content: str) -> list[DepUsage]:
    """Scan requirements.txt for crypto dependencies."""
    usages: list[DepUsage] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Parse package name and version
        match = re.match(r"^([a-zA-Z0-9_-]+)(?:[<>=!~]+(.+))?", line)
        if match:
            pkg = match.group(1).lower()
            version = match.group(2)

            if pkg in CRYPTO_PACKAGES:
                info = CRYPTO_PACKAGES[pkg]
                usages.append(DepUsage(
                    file=str(file_path),
                    package=pkg,
                    version=version,
                    algorithms=info["algorithms"],
                    quantum_risk=info["quantum_risk"],
                    deprecated=info.get("deprecated", False),
                    deprecation_reason=info.get("reason"),
                ))
    return usages


def _scan_go_mod(file_path: Path, content: str) -> list[DepUsage]:
    """Scan go.mod for crypto dependencies."""
    usages: list[DepUsage] = []
    for line in content.splitlines():
        line = line.strip()
        for pkg_pattern, info in CRYPTO_PACKAGES.items():
            if pkg_pattern.startswith("crypto/") or pkg_pattern.startswith("golang.org/"):
                if pkg_pattern in line:
                    version_match = re.search(r"v[\d.]+", line)
                    usages.append(DepUsage(
                        file=str(file_path),
                        package=pkg_pattern,
                        version=version_match.group(0) if version_match else None,
                        algorithms=info["algorithms"],
                        quantum_risk=info["quantum_risk"],
                        deprecated=info.get("deprecated", False),
                        deprecation_reason=info.get("reason"),
                    ))
    return usages


def _scan_cargo_toml(file_path: Path, content: str) -> list[DepUsage]:
    """Scan Cargo.toml for crypto dependencies."""
    usages: list[DepUsage] = []
    in_deps = False
    for line in content.splitlines():
        if re.match(r"\[.*dependencies.*\]", line, re.IGNORECASE):
            in_deps = True
            continue
        elif line.startswith("["):
            in_deps = False
            continue

        if in_deps:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
            if match:
                pkg = match.group(1).lower()
                if pkg in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[pkg]
                    version_match = re.search(r'"([\d.]+)"', line)
                    usages.append(DepUsage(
                        file=str(file_path),
                        package=pkg,
                        version=version_match.group(1) if version_match else None,
                        algorithms=info["algorithms"],
                        quantum_risk=info["quantum_risk"],
                        deprecated=info.get("deprecated", False),
                        deprecation_reason=info.get("reason"),
                    ))
    return usages


def _scan_pyproject_toml(file_path: Path, content: str) -> list[DepUsage]:
    """Scan pyproject.toml for crypto dependencies."""
    usages: list[DepUsage] = []
    for line in content.splitlines():
        for pkg, info in CRYPTO_PACKAGES.items():
            # Check if it's a Python package (not Go/Rust)
            if pkg.startswith("crypto/") or pkg.startswith("golang.org/"):
                continue
            if f'"{pkg}"' in line.lower() or f"'{pkg}'" in line.lower() or f"{pkg} " in line.lower():
                version_match = re.search(r'["\']([<>=!~]*[\d.]+)["\']', line)
                usages.append(DepUsage(
                    file=str(file_path),
                    package=pkg,
                    version=version_match.group(1) if version_match else None,
                    algorithms=info["algorithms"],
                    quantum_risk=info["quantum_risk"],
                    deprecated=info.get("deprecated", False),
                    deprecation_reason=info.get("reason"),
                ))
    return usages


def get_dependency_files(
    paths: list[str],
    staged_only: bool = False,
) -> Generator[Path, None, None]:
    """Get list of dependency files to scan."""
    if staged_only:
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True,
                text=True,
                check=True,
            )
            staged_files = result.stdout.strip().split("\n")
            for file_str in staged_files:
                if file_str:
                    file_path = Path(file_str)
                    if file_path.name in DEPENDENCY_FILES and file_path.exists():
                        yield file_path
        except subprocess.CalledProcessError:
            pass
        return

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            if path.name in DEPENDENCY_FILES:
                yield path
        elif path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

                for file in files:
                    if file in DEPENDENCY_FILES:
                        yield Path(root) / file


def scan_file(file_path: Path) -> list[CryptoUsage]:
    """Scan a single file for crypto usage."""
    usages: list[CryptoUsage] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return usages

    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        for pattern, algorithm, library in COMPILED_PATTERNS:
            if pattern.search(line):
                usages.append(
                    CryptoUsage(
                        file=str(file_path),
                        line=line_num,
                        algorithm=algorithm,
                        library=library,
                        context=line.strip()[:200],  # Limit context length
                    )
                )
                break  # One finding per line

    return usages


def get_files_to_scan(
    paths: list[str],
    staged_only: bool = False,
    extensions: set[str] | None = None,
) -> Generator[Path, None, None]:
    """Get list of files to scan."""
    if extensions is None:
        extensions = ALL_EXTENSIONS

    if staged_only:
        # Get staged files from git
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True,
                text=True,
                check=True,
            )
            staged_files = result.stdout.strip().split("\n")
            for file_str in staged_files:
                if file_str:
                    file_path = Path(file_str)
                    if file_path.suffix in extensions and file_path.exists():
                        yield file_path
        except subprocess.CalledProcessError:
            # Not a git repo or git not available
            pass
        return

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            if path.suffix in extensions:
                yield path
        elif path.is_dir():
            for root, dirs, files in os.walk(path):
                # Skip unwanted directories
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in extensions:
                        yield file_path


def calculate_quantum_readiness(usages: list[CryptoUsage]) -> float:
    """Calculate quantum readiness score (0-100)."""
    if not usages:
        return 100.0

    safe_count = 0
    vulnerable_count = 0

    for usage in usages:
        algo_info = ALGORITHM_DATABASE.get(usage.algorithm.lower(), {})
        if algo_info.get("quantum_vulnerable", False):
            vulnerable_count += 1
        elif not algo_info.get("weak", False):
            safe_count += 1

    total = safe_count + vulnerable_count
    if total == 0:
        return 100.0

    return (safe_count / total) * 100


def run_gate(
    paths: list[str] | None = None,
    policy: str = "standard",
    staged_only: bool = False,
    fail_on: str = "violations",
    include_deps: bool = False,
) -> GateResult:
    """
    Run the gate check on source files.

    Args:
        paths: Paths to scan (defaults to current directory)
        policy: Policy preset name (strict, standard, permissive)
        staged_only: Only scan git staged files
        fail_on: What triggers failure (violations, warnings)
        include_deps: Also scan dependency files (package.json, requirements.txt, etc.)

    Returns:
        GateResult with pass/fail status and findings
    """
    if paths is None:
        paths = ["."]

    start_time = time.time()

    # Load config and policy
    config = load_config()
    policy_obj = get_policy(policy, config)
    engine = PolicyEngine(policy_obj)

    # Scan source files
    all_usages: list[CryptoUsage] = []
    files_scanned = 0

    for file_path in get_files_to_scan(paths, staged_only=staged_only):
        files_scanned += 1
        usages = scan_file(file_path)
        all_usages.extend(usages)

    # Scan dependency files if requested
    dep_usages: list[DepUsage] = []
    if include_deps:
        for file_path in get_dependency_files(paths, staged_only=staged_only):
            files_scanned += 1
            deps = scan_dependency_file(file_path)
            dep_usages.extend(deps)

    # Evaluate against policy
    violations: list[Finding] = []
    warnings: list[Finding] = []
    info: list[Finding] = []

    # Evaluate source code usages
    for usage in all_usages:
        finding = engine.evaluate_algorithm(usage.algorithm, usage.file, usage.line)
        if finding:
            if finding.action == Action.BLOCK:
                violations.append(finding)
            elif finding.action == Action.WARN:
                warnings.append(finding)
            else:
                info.append(finding)

    # Evaluate dependency usages
    for dep in dep_usages:
        # Deprecated packages are violations
        if dep.deprecated:
            violations.append(Finding(
                file=dep.file,
                line=None,
                algorithm=dep.package,
                severity=Severity.HIGH,
                action=Action.BLOCK,
                message=f"Deprecated crypto package: {dep.package}",
                recommendation=dep.deprecation_reason or f"Replace {dep.package} with a maintained alternative",
            ))
        # Quantum-vulnerable packages follow policy
        elif dep.quantum_risk == "high":
            for algo in dep.algorithms:
                finding = engine.evaluate_algorithm(algo, dep.file, None)
                if finding:
                    # Override message to mention the package
                    finding = Finding(
                        file=dep.file,
                        line=None,
                        algorithm=f"{dep.package} ({algo})",
                        severity=finding.severity,
                        action=finding.action,
                        message=f"Package {dep.package} uses quantum-vulnerable algorithm: {algo}",
                        recommendation=finding.recommendation,
                    )
                    if finding.action == Action.BLOCK:
                        violations.append(finding)
                    elif finding.action == Action.WARN:
                        warnings.append(finding)
                    break  # One finding per package

    # Calculate quantum readiness
    quantum_score = calculate_quantum_readiness(all_usages)

    # Determine pass/fail
    if fail_on == "warnings":
        passed = len(violations) == 0 and len(warnings) == 0
    else:
        passed = len(violations) == 0

    exit_code = 0 if passed else 1

    scan_time_ms = (time.time() - start_time) * 1000

    return GateResult(
        passed=passed,
        exit_code=exit_code,
        files_scanned=files_scanned,
        scan_time_ms=scan_time_ms,
        violations=violations,
        warnings=warnings,
        info=info,
        quantum_readiness_score=quantum_score,
    )


def format_text_output(result: GateResult) -> str:
    """Format result as human-readable text."""
    lines = []

    # Header
    if result.passed:
        lines.append("PASSED - No policy violations found")
    else:
        lines.append(f"FAILED - {len(result.violations)} violation(s) found")

    lines.append("")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Scan time: {result.scan_time_ms:.0f}ms")
    lines.append(f"Quantum readiness: {result.quantum_readiness_score:.0f}%")
    lines.append("")

    # Violations
    if result.violations:
        lines.append("VIOLATIONS (blocking):")
        lines.append("-" * 60)
        for f in result.violations:
            lines.append(f"  {f.file}:{f.line or '?'}")
            lines.append(f"    Algorithm: {f.algorithm}")
            lines.append(f"    Severity: {f.severity.value}")
            lines.append(f"    Message: {f.message}")
            if f.recommendation:
                lines.append(f"    Fix: {f.recommendation}")
            lines.append("")

    # Warnings
    if result.warnings:
        lines.append("WARNINGS:")
        lines.append("-" * 60)
        for f in result.warnings:
            lines.append(f"  {f.file}:{f.line or '?'}")
            lines.append(f"    Algorithm: {f.algorithm}")
            lines.append(f"    Message: {f.message}")
            lines.append("")

    # Summary
    lines.append("-" * 60)
    summary = result.summary
    lines.append(
        f"Summary: {summary['violations']} violations, "
        f"{summary['warnings']} warnings, "
        f"{summary['quantum_vulnerable']} quantum-vulnerable"
    )

    return "\n".join(lines)
