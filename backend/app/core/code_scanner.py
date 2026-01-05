"""AST-Based Code Scanner Engine.

Analyzes source code to detect cryptographic algorithm usage,
weak algorithms, and generates Cryptographic Bill of Materials (CBOM).

Supports: Python, JavaScript/TypeScript, Go, Java, C/C++
"""

import ast
import re
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Language(str, Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


class QuantumRisk(str, Enum):
    """Quantum computing risk level."""
    NONE = "none"  # Symmetric algorithms with adequate key size
    LOW = "low"  # Hash functions (Grover's gives sqrt speedup)
    HIGH = "high"  # RSA, ECC, DH - broken by Shor's algorithm
    CRITICAL = "critical"  # Already weak + quantum vulnerable


class Severity(str, Enum):
    """Finding severity."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CryptoUsage:
    """A detected cryptographic usage."""
    algorithm: str
    category: str  # encryption, signing, hashing, kdf, mac, key_exchange
    library: str
    function_call: str
    file_path: str
    line_number: int
    column: int
    confidence: float  # 0.0-1.0
    quantum_risk: QuantumRisk
    is_weak: bool
    weakness_reason: str | None = None
    recommendation: str | None = None
    cwe: str | None = None
    context: str | None = None  # surrounding code context


@dataclass
class CryptoFinding:
    """A security finding related to crypto usage."""
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    algorithm: str | None = None
    cwe: str | None = None
    recommendation: str | None = None


@dataclass
class CBOM:
    """Cryptographic Bill of Materials."""
    version: str = "1.0"
    scan_timestamp: str = ""
    files_scanned: int = 0
    algorithms: list[dict] = field(default_factory=list)
    libraries: list[dict] = field(default_factory=list)
    quantum_summary: dict = field(default_factory=dict)
    findings_summary: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Code scan result."""
    usages: list[CryptoUsage]
    findings: list[CryptoFinding]
    cbom: CBOM
    files_scanned: int
    scan_time_ms: float


class CodeScannerError(Exception):
    """Code scanner error."""
    pass


# Algorithm classification database
ALGORITHM_DB = {
    # Symmetric Encryption
    "aes": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False, "min_key_bits": 128},
    "aes-128": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "aes-256": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "aes-gcm": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "aes-cbc": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "aes-ctr": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "chacha20": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "chacha20-poly1305": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "xchacha20": {"category": "encryption", "quantum_risk": QuantumRisk.NONE, "is_weak": False},

    # Weak/Broken Symmetric
    "des": {"category": "encryption", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
            "weakness_reason": "56-bit key is trivially brutable", "cwe": "CWE-327"},
    "3des": {"category": "encryption", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
             "weakness_reason": "Deprecated, vulnerable to Sweet32 attack", "cwe": "CWE-327"},
    "triple-des": {"category": "encryption", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
                  "weakness_reason": "Deprecated, vulnerable to Sweet32 attack", "cwe": "CWE-327"},
    "rc4": {"category": "encryption", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
            "weakness_reason": "Biased keystream, prohibited by RFC 7465", "cwe": "CWE-327"},
    "rc2": {"category": "encryption", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
            "weakness_reason": "Weak algorithm with known attacks", "cwe": "CWE-327"},
    "blowfish": {"category": "encryption", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
                 "weakness_reason": "64-bit block size vulnerable to birthday attacks", "cwe": "CWE-327"},
    "idea": {"category": "encryption", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
             "weakness_reason": "Deprecated, use AES instead", "cwe": "CWE-327"},
    "cast5": {"category": "encryption", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
              "weakness_reason": "64-bit block size, deprecated", "cwe": "CWE-327"},

    # Asymmetric Encryption (Quantum Vulnerable)
    "rsa": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False,
            "recommendation": "Plan migration to post-quantum algorithms"},
    "rsa-2048": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "rsa-4096": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "rsa-1024": {"category": "encryption", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
                 "weakness_reason": "Key too small, can be factored", "cwe": "CWE-326"},
    "rsa-512": {"category": "encryption", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
                "weakness_reason": "Trivially breakable key size", "cwe": "CWE-326"},

    # Signatures (Quantum Vulnerable)
    "ecdsa": {"category": "signing", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "ed25519": {"category": "signing", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "ed448": {"category": "signing", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "dsa": {"category": "signing", "quantum_risk": QuantumRisk.HIGH, "is_weak": True,
            "weakness_reason": "Deprecated in favor of ECDSA/EdDSA", "cwe": "CWE-327"},

    # Key Exchange (Quantum Vulnerable)
    "ecdh": {"category": "key_exchange", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "x25519": {"category": "key_exchange", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "x448": {"category": "key_exchange", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "dh": {"category": "key_exchange", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "diffie-hellman": {"category": "key_exchange", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},

    # Post-Quantum (Safe)
    "kyber": {"category": "key_exchange", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "ml-kem": {"category": "key_exchange", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "dilithium": {"category": "signing", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "ml-dsa": {"category": "signing", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "sphincs": {"category": "signing", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "slh-dsa": {"category": "signing", "quantum_risk": QuantumRisk.NONE, "is_weak": False},

    # HPKE (RFC 9180 - Hybrid Public Key Encryption)
    "hpke": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False,
             "recommendation": "Plan migration to post-quantum variants"},
    "hpke-x25519": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "hpke-p256": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},
    "hpke-p384": {"category": "encryption", "quantum_risk": QuantumRisk.HIGH, "is_weak": False},

    # Hash Functions
    "sha256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha-256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha384": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha-384": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha512": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha-512": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha3-256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "sha3-512": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "blake2b": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "blake2s": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "blake3": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},

    # SP 800-185 SHA-3 Derived Functions
    "cshake128": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "cshake256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "tuplehash128": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "tuplehash256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "parallelhash128": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "parallelhash256": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "kmac128": {"category": "mac", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "kmac256": {"category": "mac", "quantum_risk": QuantumRisk.LOW, "is_weak": False},

    # Weak Hash Functions
    "md5": {"category": "hashing", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
            "weakness_reason": "Collision attacks demonstrated, never use for security", "cwe": "CWE-328"},
    "md4": {"category": "hashing", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
            "weakness_reason": "Completely broken, trivial collisions", "cwe": "CWE-328"},
    "sha1": {"category": "hashing", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
             "weakness_reason": "Collision attacks demonstrated (SHAttered)", "cwe": "CWE-328"},
    "sha-1": {"category": "hashing", "quantum_risk": QuantumRisk.CRITICAL, "is_weak": True,
              "weakness_reason": "Collision attacks demonstrated (SHAttered)", "cwe": "CWE-328"},
    "ripemd160": {"category": "hashing", "quantum_risk": QuantumRisk.LOW, "is_weak": True,
                  "weakness_reason": "Deprecated, use SHA-256 or better", "cwe": "CWE-328"},

    # Password Hashing / KDFs
    "argon2": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "argon2id": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "argon2i": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "argon2d": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "bcrypt": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "scrypt": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "pbkdf2": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False,
               "recommendation": "Use high iteration count (600k+ for SHA-256)"},
    "hkdf": {"category": "kdf", "quantum_risk": QuantumRisk.NONE, "is_weak": False},

    # MACs
    "hmac": {"category": "mac", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "hmac-sha256": {"category": "mac", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "hmac-sha512": {"category": "mac", "quantum_risk": QuantumRisk.LOW, "is_weak": False},
    "poly1305": {"category": "mac", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "gmac": {"category": "mac", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
    "cmac": {"category": "mac", "quantum_risk": QuantumRisk.NONE, "is_weak": False},
}

# Library patterns for detection
LIBRARY_PATTERNS = {
    Language.PYTHON: {
        "cryptography": {
            "imports": ["cryptography", "cryptography.fernet", "cryptography.hazmat"],
            "patterns": [
                (r"Fernet\s*\(", "aes-128", "encryption"),
                (r"AESGCM\s*\(", "aes-gcm", "encryption"),
                (r"ChaCha20Poly1305\s*\(", "chacha20-poly1305", "encryption"),
                (r"algorithms\.AES\s*\(", "aes", "encryption"),
                (r"algorithms\.TripleDES\s*\(", "3des", "encryption"),
                (r"algorithms\.Blowfish\s*\(", "blowfish", "encryption"),
                (r"algorithms\.CAST5\s*\(", "cast5", "encryption"),
                (r"algorithms\.ARC4\s*\(", "rc4", "encryption"),
                (r"hashes\.SHA256\s*\(", "sha256", "hashing"),
                (r"hashes\.SHA384\s*\(", "sha384", "hashing"),
                (r"hashes\.SHA512\s*\(", "sha512", "hashing"),
                (r"hashes\.SHA1\s*\(", "sha1", "hashing"),
                (r"hashes\.MD5\s*\(", "md5", "hashing"),
                (r"hashes\.BLAKE2b\s*\(", "blake2b", "hashing"),
                (r"hashes\.BLAKE2s\s*\(", "blake2s", "hashing"),
                (r"Ed25519", "ed25519", "signing"),
                (r"Ed448", "ed448", "signing"),
                (r"ECDSA", "ecdsa", "signing"),
                (r"X25519", "x25519", "key_exchange"),
                (r"X448", "x448", "key_exchange"),
                (r"ECDH", "ecdh", "key_exchange"),
                (r"RSA", "rsa", "encryption"),
                (r"rsa\.generate_private_key", "rsa", "encryption"),
                (r"dsa\.generate_private_key", "dsa", "signing"),
            ],
        },
        "hashlib": {
            "imports": ["hashlib"],
            "patterns": [
                (r"hashlib\.sha256", "sha256", "hashing"),
                (r"hashlib\.sha384", "sha384", "hashing"),
                (r"hashlib\.sha512", "sha512", "hashing"),
                (r"hashlib\.sha1", "sha1", "hashing"),
                (r"hashlib\.md5", "md5", "hashing"),
                (r"hashlib\.sha3_256", "sha3-256", "hashing"),
                (r"hashlib\.sha3_512", "sha3-512", "hashing"),
                (r"hashlib\.blake2b", "blake2b", "hashing"),
                (r"hashlib\.blake2s", "blake2s", "hashing"),
                (r"hashlib\.new\s*\(['\"]sha256", "sha256", "hashing"),
                (r"hashlib\.new\s*\(['\"]sha1", "sha1", "hashing"),
                (r"hashlib\.new\s*\(['\"]md5", "md5", "hashing"),
            ],
        },
        "pycryptodome": {
            "imports": ["Crypto", "Cryptodome"],
            "patterns": [
                (r"Crypto\.Cipher\.AES", "aes", "encryption"),
                (r"Crypto\.Cipher\.DES3", "3des", "encryption"),
                (r"Crypto\.Cipher\.DES\b", "des", "encryption"),
                (r"Crypto\.Cipher\.Blowfish", "blowfish", "encryption"),
                (r"Crypto\.Cipher\.ARC4", "rc4", "encryption"),
                (r"Crypto\.Cipher\.ChaCha20", "chacha20", "encryption"),
                (r"Crypto\.Hash\.SHA256", "sha256", "hashing"),
                (r"Crypto\.Hash\.SHA1", "sha1", "hashing"),
                (r"Crypto\.Hash\.MD5", "md5", "hashing"),
                (r"Crypto\.PublicKey\.RSA", "rsa", "encryption"),
                (r"Crypto\.PublicKey\.DSA", "dsa", "signing"),
                (r"Crypto\.PublicKey\.ECC", "ecdsa", "signing"),
                # SP 800-185 functions
                (r"Crypto\.Hash\.cSHAKE128", "cshake128", "hashing"),
                (r"Crypto\.Hash\.cSHAKE256", "cshake256", "hashing"),
                (r"Crypto\.Hash\.KMAC128", "kmac128", "mac"),
                (r"Crypto\.Hash\.KMAC256", "kmac256", "mac"),
                (r"Crypto\.Hash\.TupleHash128", "tuplehash128", "hashing"),
                (r"Crypto\.Hash\.TupleHash256", "tuplehash256", "hashing"),
            ],
        },
        "pyhpke": {
            "imports": ["pyhpke"],
            "patterns": [
                (r"CipherSuite\.new", "hpke", "encryption"),
                (r"DHKEM_X25519", "hpke-x25519", "encryption"),
                (r"DHKEM_P256", "hpke-p256", "encryption"),
                (r"DHKEM_P384", "hpke-p384", "encryption"),
            ],
        },
        "nacl": {
            "imports": ["nacl"],
            "patterns": [
                (r"nacl\.secret\.SecretBox", "xchacha20", "encryption"),
                (r"nacl\.public\.Box", "x25519", "key_exchange"),
                (r"nacl\.signing\.SigningKey", "ed25519", "signing"),
                (r"nacl\.hash\.sha256", "sha256", "hashing"),
                (r"nacl\.hash\.sha512", "sha512", "hashing"),
                (r"nacl\.hash\.blake2b", "blake2b", "hashing"),
            ],
        },
        "passlib": {
            "imports": ["passlib"],
            "patterns": [
                (r"argon2\.hash", "argon2", "kdf"),
                (r"bcrypt\.hash", "bcrypt", "kdf"),
                (r"scrypt\.hash", "scrypt", "kdf"),
                (r"pbkdf2_sha256\.hash", "pbkdf2", "kdf"),
            ],
        },
        "cryptoserve": {
            "imports": ["cryptoserve", "cryptoserve_client"],
            "patterns": [
                (r"\.encrypt\s*\(", "aes-gcm", "encryption"),
                (r"\.decrypt\s*\(", "aes-gcm", "encryption"),
                (r"\.hash\s*\(", "sha256", "hashing"),
                (r"\.hash_password\s*\(", "argon2id", "kdf"),
                (r"\.sign\s*\(", "ed25519", "signing"),
                (r"\.verify\s*\(", "ed25519", "signing"),
                (r"\.hybrid_encrypt\s*\(", "x25519+aes-gcm", "encryption"),
                (r"\.derive_shared_secret\s*\(", "x25519", "key_exchange"),
                (r"\.jws_sign\s*\(", "ed25519", "signing"),
                (r"\.jwe_encrypt\s*\(", "aes-gcm", "encryption"),
                # HPKE endpoints
                (r"\.hpke_encrypt\s*\(", "hpke", "encryption"),
                (r"\.hpke_decrypt\s*\(", "hpke", "encryption"),
                (r"\.hpke_keypair\s*\(", "hpke", "encryption"),
                # ParallelHash
                (r"\.parallelhash\s*\(", "parallelhash128", "hashing"),
                (r"parallelhash128", "parallelhash128", "hashing"),
                (r"parallelhash256", "parallelhash256", "hashing"),
            ],
        },
    },
    Language.JAVASCRIPT: {
        "crypto": {
            "imports": ["crypto", "node:crypto"],
            "patterns": [
                (r"createCipheriv\s*\(['\"]aes", "aes", "encryption"),
                (r"createCipheriv\s*\(['\"]des", "des", "encryption"),
                (r"createCipheriv\s*\(['\"]rc4", "rc4", "encryption"),
                (r"createHash\s*\(['\"]sha256", "sha256", "hashing"),
                (r"createHash\s*\(['\"]sha1", "sha1", "hashing"),
                (r"createHash\s*\(['\"]md5", "md5", "hashing"),
                (r"createHmac\s*\(['\"]sha256", "hmac-sha256", "mac"),
                (r"generateKeyPair\s*\(['\"]rsa", "rsa", "encryption"),
                (r"generateKeyPair\s*\(['\"]ed25519", "ed25519", "signing"),
                (r"generateKeyPair\s*\(['\"]x25519", "x25519", "key_exchange"),
                (r"scrypt\s*\(", "scrypt", "kdf"),
                (r"pbkdf2\s*\(", "pbkdf2", "kdf"),
            ],
        },
        "webcrypto": {
            "imports": ["SubtleCrypto", "crypto.subtle"],
            "patterns": [
                (r"subtle\.encrypt.*AES-GCM", "aes-gcm", "encryption"),
                (r"subtle\.encrypt.*AES-CBC", "aes-cbc", "encryption"),
                (r"subtle\.digest.*SHA-256", "sha256", "hashing"),
                (r"subtle\.digest.*SHA-1", "sha1", "hashing"),
                (r"subtle\.sign.*ECDSA", "ecdsa", "signing"),
                (r"subtle\.sign.*RSA", "rsa", "signing"),
                (r"subtle\.generateKey.*AES", "aes", "encryption"),
                (r"subtle\.generateKey.*RSA", "rsa", "encryption"),
                (r"subtle\.deriveKey.*ECDH", "ecdh", "key_exchange"),
                (r"subtle\.deriveBits.*PBKDF2", "pbkdf2", "kdf"),
            ],
        },
    },
    Language.GO: {
        "crypto": {
            "imports": ["crypto/aes", "crypto/des", "crypto/sha256", "crypto/sha1", "crypto/md5",
                       "crypto/rsa", "crypto/ecdsa", "crypto/ed25519", "golang.org/x/crypto"],
            "patterns": [
                (r"aes\.NewCipher", "aes", "encryption"),
                (r"des\.NewCipher", "des", "encryption"),
                (r"des\.NewTripleDESCipher", "3des", "encryption"),
                (r"sha256\.New\(\)", "sha256", "hashing"),
                (r"sha256\.Sum256", "sha256", "hashing"),
                (r"sha1\.New\(\)", "sha1", "hashing"),
                (r"sha1\.Sum", "sha1", "hashing"),
                (r"md5\.New\(\)", "md5", "hashing"),
                (r"md5\.Sum", "md5", "hashing"),
                (r"rsa\.GenerateKey", "rsa", "encryption"),
                (r"rsa\.EncryptOAEP", "rsa", "encryption"),
                (r"ecdsa\.GenerateKey", "ecdsa", "signing"),
                (r"ed25519\.GenerateKey", "ed25519", "signing"),
                (r"ed25519\.Sign", "ed25519", "signing"),
                (r"chacha20poly1305\.New", "chacha20-poly1305", "encryption"),
                (r"argon2\.IDKey", "argon2id", "kdf"),
                (r"bcrypt\.GenerateFromPassword", "bcrypt", "kdf"),
                (r"scrypt\.Key", "scrypt", "kdf"),
                (r"pbkdf2\.Key", "pbkdf2", "kdf"),
                (r"curve25519\.X25519", "x25519", "key_exchange"),
            ],
        },
    },
    Language.JAVA: {
        "javax.crypto": {
            "imports": ["javax.crypto", "java.security"],
            "patterns": [
                (r"Cipher\.getInstance\s*\(['\"]AES", "aes", "encryption"),
                (r"Cipher\.getInstance\s*\(['\"]DES", "des", "encryption"),
                (r"Cipher\.getInstance\s*\(['\"]DESede", "3des", "encryption"),
                (r"Cipher\.getInstance\s*\(['\"]RSA", "rsa", "encryption"),
                (r"Cipher\.getInstance\s*\(['\"]RC4", "rc4", "encryption"),
                (r"Cipher\.getInstance\s*\(['\"]Blowfish", "blowfish", "encryption"),
                (r"MessageDigest\.getInstance\s*\(['\"]SHA-256", "sha256", "hashing"),
                (r"MessageDigest\.getInstance\s*\(['\"]SHA-1", "sha1", "hashing"),
                (r"MessageDigest\.getInstance\s*\(['\"]MD5", "md5", "hashing"),
                (r"KeyPairGenerator\.getInstance\s*\(['\"]RSA", "rsa", "encryption"),
                (r"KeyPairGenerator\.getInstance\s*\(['\"]EC", "ecdsa", "signing"),
                (r"KeyPairGenerator\.getInstance\s*\(['\"]DSA", "dsa", "signing"),
                (r"KeyAgreement\.getInstance\s*\(['\"]ECDH", "ecdh", "key_exchange"),
                (r"SecretKeyFactory\.getInstance\s*\(['\"]PBKDF2", "pbkdf2", "kdf"),
            ],
        },
        "bouncycastle": {
            "imports": ["org.bouncycastle"],
            "patterns": [
                (r"AESEngine", "aes", "encryption"),
                (r"ChaCha20Poly1305", "chacha20-poly1305", "encryption"),
                (r"Ed25519Signer", "ed25519", "signing"),
                (r"X25519Agreement", "x25519", "key_exchange"),
                (r"Argon2BytesGenerator", "argon2", "kdf"),
                (r"BCrypt\.generate", "bcrypt", "kdf"),
            ],
        },
    },
}


class PythonCryptoVisitor(ast.NodeVisitor):
    """AST visitor for Python crypto detection."""

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.file_path = file_path
        self.usages: list[CryptoUsage] = []
        self.imports: set[str] = set()
        self.lines = source_code.split("\n")

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module)
            # Also add top-level module
            top_module = node.module.split(".")[0]
            self.imports.add(top_module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check function calls for crypto patterns."""
        call_str = self._get_call_string(node)

        for lib_name, lib_info in LIBRARY_PATTERNS[Language.PYTHON].items():
            # Check if any of the library's imports are present
            lib_imported = any(imp in self.imports for imp in lib_info["imports"])

            for pattern, algorithm, category in lib_info["patterns"]:
                if re.search(pattern, call_str):
                    algo_info = ALGORITHM_DB.get(algorithm, {})

                    # Get context (surrounding lines)
                    context = self._get_context(node.lineno)

                    usage = CryptoUsage(
                        algorithm=algorithm,
                        category=category,
                        library=lib_name,
                        function_call=call_str,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        confidence=0.95 if lib_imported else 0.7,
                        quantum_risk=algo_info.get("quantum_risk", QuantumRisk.NONE),
                        is_weak=algo_info.get("is_weak", False),
                        weakness_reason=algo_info.get("weakness_reason"),
                        recommendation=algo_info.get("recommendation"),
                        cwe=algo_info.get("cwe"),
                        context=context,
                    )
                    self.usages.append(usage)
                    break

        self.generic_visit(node)

    def _get_call_string(self, node: ast.Call) -> str:
        """Convert call AST node to string representation."""
        try:
            return ast.unparse(node)
        except Exception:
            # Fallback for older Python versions
            if isinstance(node.func, ast.Attribute):
                return f"{ast.unparse(node.func.value)}.{node.func.attr}("
            elif isinstance(node.func, ast.Name):
                return f"{node.func.id}("
            return ""

    def _get_context(self, line_num: int, context_lines: int = 2) -> str:
        """Get surrounding code context."""
        start = max(0, line_num - context_lines - 1)
        end = min(len(self.lines), line_num + context_lines)
        return "\n".join(self.lines[start:end])


class CodeScanner:
    """AST-based code scanner for cryptographic detection."""

    def __init__(self):
        self.supported_extensions = {
            ".py": Language.PYTHON,
            ".js": Language.JAVASCRIPT,
            ".ts": Language.TYPESCRIPT,
            ".jsx": Language.JAVASCRIPT,
            ".tsx": Language.TYPESCRIPT,
            ".go": Language.GO,
            ".java": Language.JAVA,
            ".c": Language.C,
            ".cpp": Language.CPP,
            ".cc": Language.CPP,
            ".h": Language.C,
            ".hpp": Language.CPP,
        }

    def scan_code(
        self,
        code: str,
        language: Language | None = None,
        filename: str | None = None,
    ) -> ScanResult:
        """Scan a single code string."""
        import time
        start = time.perf_counter()

        if language is None and filename:
            ext = Path(filename).suffix.lower()
            language = self.supported_extensions.get(ext, Language.UNKNOWN)

        usages = []
        findings = []

        if language == Language.PYTHON:
            usages, findings = self._scan_python(code, filename or "<string>")
        else:
            # Fall back to regex-based scanning for other languages
            usages, findings = self._scan_regex(code, language, filename or "<string>")

        # Generate CBOM
        cbom = self._generate_cbom(usages, findings, 1)

        elapsed = (time.perf_counter() - start) * 1000

        return ScanResult(
            usages=usages,
            findings=findings,
            cbom=cbom,
            files_scanned=1,
            scan_time_ms=elapsed,
        )

    def scan_file(self, file_path: str | Path) -> ScanResult:
        """Scan a single file."""
        file_path = Path(file_path)

        if not file_path.exists():
            raise CodeScannerError(f"File not found: {file_path}")

        ext = file_path.suffix.lower()
        language = self.supported_extensions.get(ext, Language.UNKNOWN)

        try:
            code = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            code = file_path.read_text(encoding="latin-1")

        return self.scan_code(code, language, str(file_path))

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> ScanResult:
        """Scan all supported files in a directory."""
        import time
        start = time.perf_counter()

        directory = Path(directory)
        if not directory.is_dir():
            raise CodeScannerError(f"Not a directory: {directory}")

        exclude_patterns = exclude_patterns or [
            "**/node_modules/**",
            "**/.git/**",
            "**/venv/**",
            "**/__pycache__/**",
            "**/dist/**",
            "**/build/**",
            "**/.venv/**",
            "**/vendor/**",
        ]

        all_usages = []
        all_findings = []
        files_scanned = 0

        pattern = "**/*" if recursive else "*"

        for file_path in directory.glob(pattern):
            # Skip excluded patterns
            skip = False
            for exclude in exclude_patterns:
                if file_path.match(exclude):
                    skip = True
                    break

            if skip or not file_path.is_file():
                continue

            ext = file_path.suffix.lower()
            if ext not in self.supported_extensions:
                continue

            try:
                result = self.scan_file(file_path)
                all_usages.extend(result.usages)
                all_findings.extend(result.findings)
                files_scanned += 1
            except Exception:
                # Skip files that can't be parsed
                continue

        cbom = self._generate_cbom(all_usages, all_findings, files_scanned)
        elapsed = (time.perf_counter() - start) * 1000

        return ScanResult(
            usages=all_usages,
            findings=all_findings,
            cbom=cbom,
            files_scanned=files_scanned,
            scan_time_ms=elapsed,
        )

    def _scan_python(self, code: str, filename: str) -> tuple[list[CryptoUsage], list[CryptoFinding]]:
        """Scan Python code using AST."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to regex if AST parsing fails
            return self._scan_regex(code, Language.PYTHON, filename)

        visitor = PythonCryptoVisitor(code, filename)
        visitor.visit(tree)

        # Generate findings from usages
        findings = self._generate_findings(visitor.usages)

        return visitor.usages, findings

    def _scan_regex(
        self,
        code: str,
        language: Language,
        filename: str,
    ) -> tuple[list[CryptoUsage], list[CryptoFinding]]:
        """Scan code using regex patterns (fallback for non-Python)."""
        usages = []
        lines = code.split("\n")

        patterns = LIBRARY_PATTERNS.get(language, {})

        for lib_name, lib_info in patterns.items():
            for pattern, algorithm, category in lib_info["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        algo_info = ALGORITHM_DB.get(algorithm, {})

                        # Get context
                        start = max(0, line_num - 3)
                        end = min(len(lines), line_num + 2)
                        context = "\n".join(lines[start:end])

                        usage = CryptoUsage(
                            algorithm=algorithm,
                            category=category,
                            library=lib_name,
                            function_call=line.strip(),
                            file_path=filename,
                            line_number=line_num,
                            column=0,
                            confidence=0.8,  # Lower confidence for regex
                            quantum_risk=algo_info.get("quantum_risk", QuantumRisk.NONE),
                            is_weak=algo_info.get("is_weak", False),
                            weakness_reason=algo_info.get("weakness_reason"),
                            recommendation=algo_info.get("recommendation"),
                            cwe=algo_info.get("cwe"),
                            context=context,
                        )
                        usages.append(usage)

        findings = self._generate_findings(usages)
        return usages, findings

    def _generate_findings(self, usages: list[CryptoUsage]) -> list[CryptoFinding]:
        """Generate security findings from usages."""
        findings = []

        for usage in usages:
            if usage.is_weak:
                severity = Severity.CRITICAL if "CRITICAL" in str(usage.quantum_risk) else Severity.HIGH
                findings.append(CryptoFinding(
                    severity=severity,
                    title=f"Weak Algorithm: {usage.algorithm.upper()}",
                    description=usage.weakness_reason or f"The algorithm {usage.algorithm} is considered weak",
                    file_path=usage.file_path,
                    line_number=usage.line_number,
                    algorithm=usage.algorithm,
                    cwe=usage.cwe,
                    recommendation=usage.recommendation or f"Replace {usage.algorithm} with a secure alternative",
                ))

            if usage.quantum_risk == QuantumRisk.HIGH:
                findings.append(CryptoFinding(
                    severity=Severity.MEDIUM,
                    title=f"Quantum Vulnerable: {usage.algorithm.upper()}",
                    description=f"{usage.algorithm} is vulnerable to quantum attacks (Shor's algorithm)",
                    file_path=usage.file_path,
                    line_number=usage.line_number,
                    algorithm=usage.algorithm,
                    recommendation="Plan migration to post-quantum algorithms (ML-KEM, ML-DSA)",
                ))

        return findings

    def _generate_cbom(
        self,
        usages: list[CryptoUsage],
        findings: list[CryptoFinding],
        files_scanned: int,
    ) -> CBOM:
        """Generate Cryptographic Bill of Materials."""
        from datetime import datetime, timezone

        # Aggregate algorithms
        algo_counts: dict[str, dict] = {}
        for usage in usages:
            if usage.algorithm not in algo_counts:
                algo_counts[usage.algorithm] = {
                    "name": usage.algorithm,
                    "category": usage.category,
                    "count": 0,
                    "quantum_risk": usage.quantum_risk.value,
                    "is_weak": usage.is_weak,
                    "files": set(),
                }
            algo_counts[usage.algorithm]["count"] += 1
            algo_counts[usage.algorithm]["files"].add(usage.file_path)

        # Convert sets to lists for JSON serialization
        algorithms = []
        for algo in algo_counts.values():
            algo["files"] = list(algo["files"])
            algorithms.append(algo)

        # Aggregate libraries
        lib_counts: dict[str, dict] = {}
        for usage in usages:
            if usage.library not in lib_counts:
                lib_counts[usage.library] = {
                    "name": usage.library,
                    "usage_count": 0,
                    "algorithms": set(),
                }
            lib_counts[usage.library]["usage_count"] += 1
            lib_counts[usage.library]["algorithms"].add(usage.algorithm)

        libraries = []
        for lib in lib_counts.values():
            lib["algorithms"] = list(lib["algorithms"])
            libraries.append(lib)

        # Quantum summary
        quantum_high = sum(1 for u in usages if u.quantum_risk == QuantumRisk.HIGH)
        quantum_critical = sum(1 for u in usages if u.quantum_risk == QuantumRisk.CRITICAL)

        # Findings summary
        finding_counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        }

        return CBOM(
            version="1.0",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            files_scanned=files_scanned,
            algorithms=algorithms,
            libraries=libraries,
            quantum_summary={
                "high_risk_usages": quantum_high,
                "critical_risk_usages": quantum_critical,
                "quantum_safe_percentage": (
                    100 * (len(usages) - quantum_high - quantum_critical) / len(usages)
                    if usages else 100
                ),
            },
            findings_summary=finding_counts,
        )

    def get_supported_languages(self) -> list[dict]:
        """Return list of supported languages and extensions."""
        lang_ext: dict[Language, list[str]] = {}
        for ext, lang in self.supported_extensions.items():
            if lang not in lang_ext:
                lang_ext[lang] = []
            lang_ext[lang].append(ext)

        return [
            {"language": lang.value, "extensions": exts}
            for lang, exts in lang_ext.items()
        ]

    def get_detectable_algorithms(self) -> dict:
        """Return all detectable algorithms and their properties."""
        return {
            algo: {
                "category": info["category"],
                "quantum_risk": info["quantum_risk"].value,
                "is_weak": info["is_weak"],
                "weakness_reason": info.get("weakness_reason"),
                "recommendation": info.get("recommendation"),
            }
            for algo, info in ALGORITHM_DB.items()
        }
