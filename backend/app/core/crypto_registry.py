"""Comprehensive Cryptography Registry.

A knowledge base of cryptographic algorithms, their properties, security status,
and relationships. This enables:
- Intelligent algorithm selection in policy engine
- Self-aware SDK pattern recognition
- Admin-friendly policy management
- Automated security assessments and recommendations

The registry includes:
- Symmetric encryption (AES, ChaCha20, DES, etc.)
- Asymmetric encryption (RSA, ECDH, etc.)
- Hash functions (SHA-2, SHA-3, MD5, etc.)
- Digital signatures (RSA, ECDSA, Ed25519, etc.)
- Key derivation (HKDF, PBKDF2, Argon2, etc.)
- Post-quantum algorithms (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+)

Official Standards Sources:
- NIST FIPS: Federal Information Processing Standards
  - FIPS 197: AES (2001)
  - FIPS 180-4: SHA-1, SHA-2 (2015)
  - FIPS 186-5: Digital Signature Standard - RSA, ECDSA, EdDSA (2023)
  - FIPS 198-1: HMAC (2008)
  - FIPS 202: SHA-3 (2015)
  - FIPS 203: ML-KEM (Kyber) - Post-Quantum KEM (2024)
  - FIPS 204: ML-DSA (Dilithium) - Post-Quantum Signatures (2024)
  - FIPS 205: SLH-DSA (SPHINCS+) - Stateless Hash-Based Signatures (2024)

- NIST SP 800-Series:
  - SP 800-38A: Block Cipher Modes (ECB, CBC, CFB, OFB, CTR)
  - SP 800-38D: GCM Mode
  - SP 800-56A Rev 3: Key Establishment (ECDH, DH)
  - SP 800-56C Rev 2: Key Derivation
  - SP 800-57: Key Management Recommendations
  - SP 800-131A Rev 2: Transitioning Cryptographic Algorithms
  - SP 800-132: Password-Based Key Derivation
  - SP 800-185: SHA-3 Derived Functions (cSHAKE, KMAC, TupleHash)

- IETF RFCs: Internet Engineering Task Force Standards
  - RFC 5869: HKDF
  - RFC 7693: BLAKE2
  - RFC 7748: X25519, X448
  - RFC 8032: EdDSA (Ed25519, Ed448)
  - RFC 8439: ChaCha20-Poly1305
  - RFC 8452: AES-GCM-SIV
  - RFC 9180: HPKE

Deprecation Guidance (NIST SP 800-131A Rev 2):
- DES: Disallowed after 2023
- 3DES (TDEA): Disallowed after 2023 for encryption
- SHA-1: Disallowed for digital signatures after 2013
- MD5: Disallowed for all cryptographic uses
- RSA < 2048: Disallowed after 2023
- 112-bit security: Disallowed after 2030
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AlgorithmType(str, Enum):
    """Categories of cryptographic algorithms."""
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"
    HASH = "hash"
    SIGNATURE = "signature"
    KEY_EXCHANGE = "key_exchange"
    KEY_DERIVATION = "key_derivation"
    MAC = "mac"  # Message Authentication Code
    AEAD = "aead"  # Authenticated Encryption with Associated Data


class SecurityStatus(str, Enum):
    """Security status of an algorithm."""
    RECOMMENDED = "recommended"      # Best practice, actively recommended
    ACCEPTABLE = "acceptable"        # Safe to use, but newer options exist
    LEGACY = "legacy"                # Should migrate away, but not immediately vulnerable
    DEPRECATED = "deprecated"        # Known weaknesses, migrate immediately
    BROKEN = "broken"                # Actively exploitable, must not use


class StandardsBody(str, Enum):
    """Standards organizations."""
    NIST = "NIST"
    IETF = "IETF"
    ISO = "ISO"
    IEEE = "IEEE"
    ECRYPT = "ECRYPT"
    ANSSI = "ANSSI"


@dataclass
class Algorithm:
    """A cryptographic algorithm with full metadata."""

    # Identity
    name: str                          # Canonical name (e.g., "AES-256-GCM")
    family: str                        # Algorithm family (e.g., "AES")
    variant: str | None = None         # Specific variant (e.g., "GCM")
    aliases: list[str] = field(default_factory=list)  # Other names

    # Classification
    algorithm_type: AlgorithmType = AlgorithmType.SYMMETRIC_ENCRYPTION
    use_cases: list[str] = field(default_factory=list)  # What it's used for

    # Security properties
    security_bits: int = 128           # Effective security level in bits
    key_sizes: list[int] = field(default_factory=list)  # Supported key sizes in bits
    block_size: int | None = None      # Block size in bits (for block ciphers)
    output_size: int | None = None     # Output size in bits (for hashes)

    # Quantum resistance
    quantum_resistant: bool = False
    quantum_security_bits: int | None = None  # Security against quantum attacks

    # Status and recommendations
    status: SecurityStatus = SecurityStatus.ACCEPTABLE
    deprecated_date: str | None = None
    replacement: str | None = None     # Recommended replacement algorithm
    vulnerabilities: list[str] = field(default_factory=list)

    # Standards and compliance
    standards: list[str] = field(default_factory=list)  # e.g., ["FIPS 197", "NIST SP 800-38D"]
    approved_by: list[StandardsBody] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)  # HIPAA, PCI-DSS, etc.

    # Performance characteristics
    hardware_acceleration: bool = False  # Has common HW support (AES-NI, etc.)
    relative_speed: str = "medium"       # fast, medium, slow
    memory_usage: str = "low"            # low, medium, high

    # Implementation notes
    implementation_notes: list[str] = field(default_factory=list)
    common_mistakes: list[str] = field(default_factory=list)

    # Pattern matching for self-aware SDK
    code_patterns: list[str] = field(default_factory=list)  # Regex patterns to find in code
    library_imports: list[str] = field(default_factory=list)  # Common import patterns

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "name": self.name,
            "family": self.family,
            "variant": self.variant,
            "aliases": self.aliases,
            "type": self.algorithm_type.value,
            "use_cases": self.use_cases,
            "security_bits": self.security_bits,
            "key_sizes": self.key_sizes,
            "quantum_resistant": self.quantum_resistant,
            "status": self.status.value,
            "replacement": self.replacement,
            "standards": self.standards,
            "hardware_acceleration": self.hardware_acceleration,
        }


class CryptoRegistry:
    """Registry of all known cryptographic algorithms."""

    def __init__(self):
        self._algorithms: dict[str, Algorithm] = {}
        self._load_builtin_algorithms()

    def register(self, algorithm: Algorithm) -> None:
        """Register an algorithm in the registry."""
        self._algorithms[algorithm.name.lower()] = algorithm
        # Also register aliases
        for alias in algorithm.aliases:
            self._algorithms[alias.lower()] = algorithm

    def get(self, name: str) -> Algorithm | None:
        """Get an algorithm by name or alias."""
        return self._algorithms.get(name.lower())

    def search(
        self,
        algorithm_type: AlgorithmType | None = None,
        quantum_resistant: bool | None = None,
        status: SecurityStatus | None = None,
        min_security_bits: int | None = None,
        compliance_framework: str | None = None,
    ) -> list[Algorithm]:
        """Search for algorithms matching criteria."""
        seen = set()  # Avoid duplicates from aliases
        results = []

        for algo in self._algorithms.values():
            if algo.name in seen:
                continue

            if algorithm_type and algo.algorithm_type != algorithm_type:
                continue
            if quantum_resistant is not None and algo.quantum_resistant != quantum_resistant:
                continue
            if status and algo.status != status:
                continue
            if min_security_bits and algo.security_bits < min_security_bits:
                continue
            if compliance_framework and compliance_framework not in algo.compliance_frameworks:
                continue

            seen.add(algo.name)
            results.append(algo)

        return results

    def get_recommended(self, algorithm_type: AlgorithmType) -> list[Algorithm]:
        """Get recommended algorithms of a specific type."""
        return self.search(
            algorithm_type=algorithm_type,
            status=SecurityStatus.RECOMMENDED,
        )

    def get_quantum_resistant(self) -> list[Algorithm]:
        """Get all quantum-resistant algorithms."""
        return self.search(quantum_resistant=True)

    def get_deprecated(self) -> list[Algorithm]:
        """Get all deprecated or broken algorithms."""
        results = []
        for algo in self._algorithms.values():
            if algo.status in [SecurityStatus.DEPRECATED, SecurityStatus.BROKEN]:
                if algo.name not in [a.name for a in results]:
                    results.append(algo)
        return results

    def is_secure(self, name: str) -> bool:
        """Check if an algorithm is considered secure."""
        algo = self.get(name)
        if not algo:
            return False
        return algo.status in [SecurityStatus.RECOMMENDED, SecurityStatus.ACCEPTABLE]

    def is_quantum_resistant(self, name: str) -> bool:
        """Check if an algorithm is quantum-resistant."""
        algo = self.get(name)
        return algo.quantum_resistant if algo else False

    def get_replacement(self, name: str) -> str | None:
        """Get the recommended replacement for an algorithm."""
        algo = self.get(name)
        return algo.replacement if algo else None

    def all_algorithms(self) -> list[Algorithm]:
        """Get all unique algorithms."""
        seen = set()
        results = []
        for algo in self._algorithms.values():
            if algo.name not in seen:
                seen.add(algo.name)
                results.append(algo)
        return sorted(results, key=lambda a: a.name)

    def _load_builtin_algorithms(self) -> None:
        """Load the built-in algorithm database."""

        # =====================================================================
        # SYMMETRIC ENCRYPTION - AEAD
        # =====================================================================

        self.register(Algorithm(
            name="AES-256-GCM",
            family="AES",
            variant="GCM",
            aliases=["aes256-gcm", "aes-gcm-256"],
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["data encryption", "authenticated encryption", "disk encryption"],
            security_bits=256,
            key_sizes=[256],
            block_size=128,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 197", "NIST SP 800-38D"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["HIPAA", "PCI-DSS", "GDPR", "SOX"],
            hardware_acceleration=True,
            relative_speed="fast",
            code_patterns=[
                r"AES\.new\([^)]*MODE_GCM",
                r"AESGCM\(",
                r"aes-256-gcm",
                r"CipherMode\.GCM",
            ],
            library_imports=[
                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
                "from Crypto.Cipher import AES",
            ],
            implementation_notes=[
                "Use random 96-bit nonce (never reuse)",
                "Limit data to 2^39 - 256 bits per key",
            ],
        ))

        self.register(Algorithm(
            name="AES-128-GCM",
            family="AES",
            variant="GCM",
            aliases=["aes128-gcm", "aes-gcm-128"],
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["data encryption", "authenticated encryption"],
            security_bits=128,
            key_sizes=[128],
            block_size=128,
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            replacement="AES-256-GCM",
            standards=["FIPS 197", "NIST SP 800-38D"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["GDPR"],
            hardware_acceleration=True,
            relative_speed="fast",
            code_patterns=[r"aes-128-gcm"],
        ))

        self.register(Algorithm(
            name="ChaCha20-Poly1305",
            family="ChaCha20",
            variant="Poly1305",
            aliases=["chacha20poly1305", "chacha-poly"],
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["data encryption", "authenticated encryption", "TLS"],
            security_bits=256,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8439"],
            approved_by=[StandardsBody.IETF],
            compliance_frameworks=["GDPR"],
            hardware_acceleration=False,
            relative_speed="fast",
            implementation_notes=["Good for systems without AES-NI"],
            code_patterns=[
                r"ChaCha20Poly1305\(",
                r"chacha20-poly1305",
            ],
        ))

        self.register(Algorithm(
            name="AES-256-GCM-SIV",
            family="AES",
            variant="GCM-SIV",
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["data encryption", "nonce-misuse resistant encryption"],
            security_bits=256,
            key_sizes=[256],
            block_size=128,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8452"],
            approved_by=[StandardsBody.IETF],
            hardware_acceleration=True,
            relative_speed="medium",
            implementation_notes=["Resistant to nonce reuse (degrades gracefully)"],
        ))

        # =====================================================================
        # SYMMETRIC ENCRYPTION - LEGACY/DEPRECATED
        # =====================================================================

        self.register(Algorithm(
            name="AES-128-CBC",
            family="AES",
            variant="CBC",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            use_cases=["legacy encryption"],
            security_bits=128,
            key_sizes=[128],
            block_size=128,
            quantum_resistant=False,
            status=SecurityStatus.LEGACY,
            replacement="AES-256-GCM",
            vulnerabilities=["Padding oracle attacks if not properly implemented"],
            standards=["FIPS 197", "NIST SP 800-38A"],
            approved_by=[StandardsBody.NIST],
            hardware_acceleration=True,
            common_mistakes=["Not using HMAC for authentication", "Predictable IV"],
            code_patterns=[r"MODE_CBC", r"aes-128-cbc"],
            implementation_notes=["CBC does not provide authentication - use AEAD instead"],
        ))

        self.register(Algorithm(
            name="AES-128-ECB",
            family="AES",
            variant="ECB",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_bits=128,
            key_sizes=[128],
            block_size=128,
            quantum_resistant=False,
            status=SecurityStatus.BROKEN,
            replacement="AES-256-GCM",
            vulnerabilities=["Pattern preservation", "No semantic security"],
            common_mistakes=["Using for any real encryption"],
            code_patterns=[r"MODE_ECB", r"aes.*ecb"],
        ))

        self.register(Algorithm(
            name="DES",
            family="DES",
            aliases=["des-cbc"],
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_bits=56,
            key_sizes=[56],
            block_size=64,
            quantum_resistant=False,
            status=SecurityStatus.BROKEN,
            deprecated_date="1999",
            replacement="AES-256-GCM",
            vulnerabilities=[
                "56-bit key brute-forceable (demonstrated 1999)",
                "Sweet32 birthday attack on 64-bit block",
            ],
            standards=["FIPS 46-3 (withdrawn 2005)"],
            implementation_notes=["NIST withdrew FIPS 46-3 in 2005 - must not use"],
            code_patterns=[r"DES\.", r"from.*DES"],
        ))

        self.register(Algorithm(
            name="3DES",
            family="DES",
            aliases=["triple-des", "des-ede3", "tdea", "tdes"],
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_bits=112,
            key_sizes=[168, 112],
            block_size=64,
            quantum_resistant=False,
            status=SecurityStatus.DEPRECATED,
            deprecated_date="2023-12-31",
            replacement="AES-256-GCM",
            vulnerabilities=[
                "Sweet32 birthday attack on 64-bit block (CVE-2016-2183)",
                "Limited to 2^20 blocks per key for security",
            ],
            standards=["NIST SP 800-67 Rev 2", "NIST SP 800-131A Rev 2"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST SP 800-131A Rev 2: Disallowed after 2023-12-31",
                "May be used for decryption only through 2030",
            ],
            code_patterns=[r"DES3", r"triple.?des", r"3des", r"TDEA"],
        ))

        self.register(Algorithm(
            name="RC4",
            family="RC4",
            aliases=["arcfour", "arc4"],
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_bits=0,  # Effectively broken
            key_sizes=[40, 128, 256],
            quantum_resistant=False,
            status=SecurityStatus.BROKEN,
            deprecated_date="2015",
            replacement="AES-256-GCM",
            vulnerabilities=[
                "Statistical biases in keystream (2013)",
                "Plaintext recovery attacks in TLS (RC4NOMORE, Bar Mitzvah)",
                "NIST SP 800-131A Rev 2: Disallowed for all uses",
            ],
            standards=["NIST SP 800-131A Rev 2 (prohibits)"],
            implementation_notes=["RFC 7465 prohibits RC4 in TLS"],
            code_patterns=[r"RC4", r"ARC4", r"arcfour"],
        ))

        self.register(Algorithm(
            name="Blowfish",
            family="Blowfish",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_bits=128,
            key_sizes=[32, 448],
            block_size=64,
            quantum_resistant=False,
            status=SecurityStatus.DEPRECATED,
            replacement="AES-256-GCM",
            vulnerabilities=["Small block size (Sweet32)"],
            code_patterns=[r"Blowfish"],
        ))

        # =====================================================================
        # HASH FUNCTIONS
        # =====================================================================

        self.register(Algorithm(
            name="SHA-256",
            family="SHA-2",
            variant="256",
            aliases=["sha256", "sha2-256"],
            algorithm_type=AlgorithmType.HASH,
            use_cases=["integrity verification", "digital signatures", "HMAC"],
            security_bits=128,  # Collision resistance
            output_size=256,
            quantum_resistant=False,
            quantum_security_bits=128,  # Grover's algorithm
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 180-4"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["HIPAA", "PCI-DSS", "GDPR"],
            hardware_acceleration=True,
            relative_speed="fast",
            code_patterns=[r"sha256", r"SHA256", r"hashlib\.sha256"],
        ))

        self.register(Algorithm(
            name="SHA-384",
            family="SHA-2",
            variant="384",
            aliases=["sha384", "sha2-384"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=192,
            output_size=384,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 180-4"],
            approved_by=[StandardsBody.NIST],
            code_patterns=[r"sha384", r"SHA384"],
        ))

        self.register(Algorithm(
            name="SHA-512",
            family="SHA-2",
            variant="512",
            aliases=["sha512", "sha2-512"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=512,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 180-4"],
            approved_by=[StandardsBody.NIST],
            code_patterns=[r"sha512", r"SHA512"],
        ))

        self.register(Algorithm(
            name="SHA-3-256",
            family="SHA-3",
            variant="256",
            aliases=["sha3-256", "keccak-256"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=256,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=["Alternative to SHA-2 with different construction"],
            code_patterns=[r"sha3.256", r"SHA3"],
        ))

        self.register(Algorithm(
            name="SHA-3-224",
            family="SHA-3",
            variant="224",
            aliases=["sha3-224"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=112,
            output_size=224,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=["SHA-3 with 224-bit output"],
            code_patterns=[r"sha3.224", r"SHA3_224"],
        ))

        self.register(Algorithm(
            name="SHA-3-384",
            family="SHA-3",
            variant="384",
            aliases=["sha3-384"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=192,
            output_size=384,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=["SHA-3 with 384-bit output"],
            code_patterns=[r"sha3.384", r"SHA3_384"],
        ))

        self.register(Algorithm(
            name="SHA-3-512",
            family="SHA-3",
            variant="512",
            aliases=["sha3-512"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=512,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=["SHA-3 with 512-bit output, highest security"],
            code_patterns=[r"sha3.512", r"SHA3_512"],
        ))

        # FIPS 202 Extendable Output Functions (XOFs)
        self.register(Algorithm(
            name="SHAKE128",
            family="SHA-3",
            variant="XOF-128",
            aliases=["shake-128"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Extendable Output Function (XOF) with 128-bit security",
                "Output length is variable and specified at runtime",
                "Used in ML-KEM and ML-DSA for key derivation",
            ],
            code_patterns=[r"shake_128", r"SHAKE128", r"shake128"],
        ))

        self.register(Algorithm(
            name="SHAKE256",
            family="SHA-3",
            variant="XOF-256",
            aliases=["shake-256"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 202"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Extendable Output Function (XOF) with 256-bit security",
                "Output length is variable and specified at runtime",
                "Higher security than SHAKE128 for critical applications",
            ],
            code_patterns=[r"shake_256", r"SHAKE256", r"shake256"],
        ))

        # SP 800-185 Customizable XOFs
        self.register(Algorithm(
            name="cSHAKE128",
            family="SHA-3",
            variant="cXOF-128",
            aliases=["cshake-128", "customizable-shake128"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Customizable SHAKE with function name and customization string",
                "Base for KMAC128 and TupleHash128",
                "Domain separation built-in",
            ],
            code_patterns=[r"cshake128", r"cSHAKE128"],
        ))

        self.register(Algorithm(
            name="cSHAKE256",
            family="SHA-3",
            variant="cXOF-256",
            aliases=["cshake-256", "customizable-shake256"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Customizable SHAKE with function name and customization string",
                "Base for KMAC256 and TupleHash256",
                "Domain separation built-in",
            ],
            code_patterns=[r"cshake256", r"cSHAKE256"],
        ))

        # SP 800-185 TupleHash
        self.register(Algorithm(
            name="TupleHash128",
            family="SHA-3",
            variant="TupleHash-128",
            aliases=["tuple-hash-128", "tuplehash128"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=0,  # Variable output (XOF mode) or fixed
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Hashes tuples of variable-length strings unambiguously",
                "Prevents length-extension and concatenation attacks",
                "Built on cSHAKE128",
            ],
            code_patterns=[r"tuplehash128", r"TupleHash128", r"tuple_hash_128"],
        ))

        self.register(Algorithm(
            name="TupleHash256",
            family="SHA-3",
            variant="TupleHash-256",
            aliases=["tuple-hash-256", "tuplehash256"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=0,  # Variable output (XOF mode) or fixed
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "Hashes tuples of variable-length strings unambiguously",
                "Prevents length-extension and concatenation attacks",
                "Built on cSHAKE256",
            ],
            code_patterns=[r"tuplehash256", r"TupleHash256", r"tuple_hash_256"],
        ))

        # SP 800-185 ParallelHash
        self.register(Algorithm(
            name="ParallelHash128",
            family="SHA-3",
            variant="ParallelHash-128",
            aliases=["parallel-hash-128", "parallelhash128"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            relative_speed="fast",
            implementation_notes=[
                "Parallelizable hash for large messages",
                "Splits input into blocks for parallel processing",
                "Built on cSHAKE128",
            ],
            code_patterns=[r"parallelhash128", r"ParallelHash128", r"parallel_hash_128"],
        ))

        self.register(Algorithm(
            name="ParallelHash256",
            family="SHA-3",
            variant="ParallelHash-256",
            aliases=["parallel-hash-256", "parallelhash256"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=0,  # Variable output
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["SP 800-185"],
            approved_by=[StandardsBody.NIST],
            relative_speed="fast",
            implementation_notes=[
                "Parallelizable hash for large messages",
                "Splits input into blocks for parallel processing",
                "Built on cSHAKE256",
            ],
            code_patterns=[r"parallelhash256", r"ParallelHash256", r"parallel_hash_256"],
        ))

        self.register(Algorithm(
            name="BLAKE2b",
            family="BLAKE2",
            variant="b",
            algorithm_type=AlgorithmType.HASH,
            security_bits=256,
            output_size=512,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 7693"],
            approved_by=[StandardsBody.IETF],
            relative_speed="fast",
            implementation_notes=["Faster than SHA-2 on modern CPUs"],
            code_patterns=[r"blake2b", r"BLAKE2b"],
        ))

        self.register(Algorithm(
            name="BLAKE3",
            family="BLAKE3",
            algorithm_type=AlgorithmType.HASH,
            security_bits=128,
            output_size=256,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            relative_speed="fast",
            implementation_notes=["Parallelizable, very fast"],
            code_patterns=[r"blake3", r"BLAKE3"],
        ))

        self.register(Algorithm(
            name="MD5",
            family="MD5",
            algorithm_type=AlgorithmType.HASH,
            security_bits=0,  # Collision attacks are practical
            output_size=128,
            quantum_resistant=False,
            status=SecurityStatus.BROKEN,
            deprecated_date="2004",
            replacement="SHA-256",
            vulnerabilities=[
                "Collision attacks practical (2004, Wang et al.)",
                "Chosen-prefix collisions in seconds (2009)",
                "Used to create rogue CA certificate (2008)",
            ],
            standards=["RFC 1321 (informational)", "NIST SP 800-131A Rev 2 (prohibits)"],
            implementation_notes=[
                "NIST: Disallowed for all cryptographic uses",
                "Only acceptable for non-security checksums",
            ],
            code_patterns=[r"md5", r"MD5", r"hashlib\.md5"],
        ))

        self.register(Algorithm(
            name="SHA-1",
            family="SHA-1",
            aliases=["sha1"],
            algorithm_type=AlgorithmType.HASH,
            security_bits=0,  # Collision attacks demonstrated
            output_size=160,
            quantum_resistant=False,
            status=SecurityStatus.BROKEN,
            deprecated_date="2017",
            replacement="SHA-256",
            vulnerabilities=[
                "SHAttered collision attack demonstrated (2017, Google)",
                "SHA-1 is a Shambles: Chosen-prefix collision (2020)",
                "Collision cost ~$45,000 in 2020",
            ],
            standards=["FIPS 180-4", "NIST SP 800-131A Rev 2 (disallows)"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST: Disallowed for digital signatures since 2013",
                "Disallowed for most uses after 2030",
                "Only allowed for HMAC-SHA-1 and legacy verification",
            ],
            code_patterns=[r"sha1", r"SHA1", r"hashlib\.sha1"],
        ))

        # =====================================================================
        # PASSWORD HASHING / KEY DERIVATION
        # =====================================================================

        self.register(Algorithm(
            name="Argon2id",
            family="Argon2",
            variant="id",
            aliases=["argon2"],
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            use_cases=["password hashing", "key derivation"],
            security_bits=256,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 9106", "OWASP Password Storage Cheat Sheet"],
            implementation_notes=[
                "Winner of Password Hashing Competition (PHC) 2015",
                "Memory-hard, GPU/ASIC resistant",
                "OWASP recommended: m=19456 (19 MiB), t=2, p=1",
                "Hybrid of Argon2d (GPU-resistant) and Argon2i (side-channel resistant)",
            ],
            code_patterns=[r"argon2", r"Argon2"],
        ))

        self.register(Algorithm(
            name="bcrypt",
            family="bcrypt",
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            use_cases=["password hashing"],
            security_bits=128,
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            replacement="Argon2id",
            standards=["OWASP Password Storage Cheat Sheet"],
            implementation_notes=[
                "72-byte password limit (truncates longer passwords)",
                "OWASP recommended: cost factor >= 10 (2024)",
                "Widely deployed and battle-tested",
            ],
            code_patterns=[r"bcrypt"],
        ))

        self.register(Algorithm(
            name="scrypt",
            family="scrypt",
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            use_cases=["password hashing", "key derivation"],
            security_bits=256,
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            replacement="Argon2id",
            standards=["RFC 7914"],
            approved_by=[StandardsBody.IETF],
            implementation_notes=[
                "Memory-hard, designed to be costly on custom hardware",
                "OWASP recommended: N=2^17, r=8, p=1",
            ],
            code_patterns=[r"scrypt"],
        ))

        self.register(Algorithm(
            name="PBKDF2-HMAC-SHA256",
            family="PBKDF2",
            variant="HMAC-SHA256",
            aliases=["pbkdf2-sha256", "pbkdf2"],
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            use_cases=["password hashing", "key derivation"],
            security_bits=128,
            quantum_resistant=False,
            status=SecurityStatus.LEGACY,
            replacement="Argon2id",
            standards=["RFC 8018", "NIST SP 800-132"],
            approved_by=[StandardsBody.NIST, StandardsBody.IETF],
            compliance_frameworks=["FIPS 140-2", "PCI-DSS"],
            implementation_notes=[
                "OWASP recommended: >= 600,000 iterations (2024)",
                "NIST SP 800-132: minimum 1,000 iterations",
                "Not memory-hard - vulnerable to GPU/ASIC attacks",
                "Use for FIPS compliance when Argon2 not available",
            ],
            code_patterns=[r"PBKDF2", r"pbkdf2"],
        ))

        self.register(Algorithm(
            name="HKDF",
            family="HKDF",
            aliases=["hkdf-sha256"],
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            use_cases=["key derivation from high-entropy input", "key expansion"],
            security_bits=256,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 5869", "NIST SP 800-56C Rev 2"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            implementation_notes=[
                "NOT for password hashing - input must be high-entropy",
                "Two-step: Extract (optional) + Expand",
                "Used in TLS 1.3, Signal Protocol, Noise Framework",
            ],
            code_patterns=[r"HKDF"],
        ))

        # =====================================================================
        # MESSAGE AUTHENTICATION CODES (MAC)
        # =====================================================================

        self.register(Algorithm(
            name="HMAC-SHA256",
            family="HMAC",
            variant="SHA256",
            aliases=["hmac-sha-256"],
            algorithm_type=AlgorithmType.MAC,
            use_cases=["message authentication", "integrity verification", "key derivation"],
            security_bits=128,
            output_size=256,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 198-1", "RFC 2104"],
            approved_by=[StandardsBody.NIST, StandardsBody.IETF],
            compliance_frameworks=["HIPAA", "PCI-DSS", "GDPR"],
            hardware_acceleration=True,
            relative_speed="fast",
            implementation_notes=[
                "Key should be at least 128 bits",
                "Truncation to 128 bits acceptable per FIPS 198-1",
            ],
            code_patterns=[r"hmac.*sha256", r"HMAC.*SHA256", r"hmac\.new.*sha256"],
        ))

        self.register(Algorithm(
            name="HMAC-SHA512",
            family="HMAC",
            variant="SHA512",
            aliases=["hmac-sha-512"],
            algorithm_type=AlgorithmType.MAC,
            use_cases=["message authentication", "high-security integrity"],
            security_bits=256,
            output_size=512,
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 198-1", "RFC 2104"],
            approved_by=[StandardsBody.NIST, StandardsBody.IETF],
            code_patterns=[r"hmac.*sha512", r"HMAC.*SHA512"],
        ))

        self.register(Algorithm(
            name="KMAC128",
            family="KMAC",
            variant="128",
            aliases=["kmac-128"],
            algorithm_type=AlgorithmType.MAC,
            use_cases=["message authentication", "PRF", "key derivation", "domain separation"],
            security_bits=128,
            output_size=256,  # Default, but variable
            quantum_resistant=False,
            quantum_security_bits=64,  # Grover's algorithm halves security
            status=SecurityStatus.RECOMMENDED,
            standards=["NIST SP 800-185"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["FIPS 140-3"],
            relative_speed="medium",
            implementation_notes=[
                "Keccak-based MAC derived from cSHAKE128",
                "Supports customization string for domain separation",
                "Variable output length (XOF-based)",
                "More efficient than HMAC-SHA3 for MAC use cases",
                "NIST PQC Security Level 1 compatible",
            ],
            code_patterns=[r"KMAC128", r"kmac128", r"KMAC.*128"],
        ))

        self.register(Algorithm(
            name="KMAC256",
            family="KMAC",
            variant="256",
            aliases=["kmac-256"],
            algorithm_type=AlgorithmType.MAC,
            use_cases=["message authentication", "PRF", "key derivation", "high-security applications"],
            security_bits=256,
            output_size=512,  # Default, but variable
            quantum_resistant=False,
            quantum_security_bits=128,  # Grover's algorithm halves security
            status=SecurityStatus.RECOMMENDED,
            standards=["NIST SP 800-185"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["FIPS 140-3"],
            relative_speed="medium",
            implementation_notes=[
                "Keccak-based MAC derived from cSHAKE256",
                "Supports customization string for domain separation",
                "Variable output length (XOF-based)",
                "256-bit security - suitable for high-security applications",
                "NIST PQC Security Level 5 compatible",
            ],
            code_patterns=[r"KMAC256", r"kmac256", r"KMAC.*256"],
        ))

        # =====================================================================
        # ASYMMETRIC ENCRYPTION / KEY EXCHANGE
        # =====================================================================

        self.register(Algorithm(
            name="RSA-2048",
            family="RSA",
            variant="2048",
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["key encapsulation", "digital signatures"],
            security_bits=112,
            key_sizes=[2048],
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            replacement="RSA-3072",
            standards=["FIPS 186-5", "NIST SP 800-56B Rev 2"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["PCI-DSS", "HIPAA"],
            relative_speed="slow",
            implementation_notes=[
                "Minimum key size per NIST SP 800-131A Rev 2",
                "112-bit security deprecated after 2030",
                "Use RSA-OAEP for encryption, PSS for signatures",
            ],
            code_patterns=[r"RSA.*2048", r"rsa2048"],
        ))

        self.register(Algorithm(
            name="RSA-3072",
            family="RSA",
            variant="3072",
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["key encapsulation", "digital signatures"],
            security_bits=128,
            key_sizes=[3072],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 186-5", "NIST SP 800-56B Rev 2"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
            relative_speed="slow",
            implementation_notes=["128-bit security - recommended minimum"],
            code_patterns=[r"RSA.*3072", r"rsa3072"],
        ))

        self.register(Algorithm(
            name="RSA-4096",
            family="RSA",
            variant="4096",
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["key encapsulation", "digital signatures"],
            security_bits=140,
            key_sizes=[4096],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 186-5", "NIST SP 800-56B Rev 2"],
            approved_by=[StandardsBody.NIST],
            relative_speed="slow",
            code_patterns=[r"RSA.*4096", r"rsa4096"],
        ))

        self.register(Algorithm(
            name="ECDH-P256",
            family="ECDH",
            variant="P-256",
            aliases=["ecdh-secp256r1", "ecdh-prime256v1"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["key exchange", "ECDHE", "TLS key agreement"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 186-5", "NIST SP 800-56A Rev 3"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
            code_patterns=[r"P-256", r"secp256r1", r"prime256v1"],
        ))

        self.register(Algorithm(
            name="ECDH-P384",
            family="ECDH",
            variant="P-384",
            aliases=["ecdh-secp384r1"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["key exchange", "ECDHE"],
            security_bits=192,
            key_sizes=[384],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 186-5", "NIST SP 800-56A Rev 3"],
            approved_by=[StandardsBody.NIST],
            code_patterns=[r"P-384", r"secp384r1"],
        ))

        self.register(Algorithm(
            name="X25519",
            family="Curve25519",
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["key exchange", "TLS 1.3"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 7748", "FIPS 186-5"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            relative_speed="fast",
            implementation_notes=["Added to FIPS 186-5 (2023)"],
            code_patterns=[r"X25519", r"Curve25519"],
        ))

        self.register(Algorithm(
            name="X448",
            family="Curve448",
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["key exchange", "high-security applications"],
            security_bits=224,
            key_sizes=[448],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 7748", "FIPS 186-5"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            relative_speed="medium",
            implementation_notes=["224-bit security level"],
            code_patterns=[r"X448", r"Curve448"],
        ))

        # =====================================================================
        # HPKE (Hybrid Public Key Encryption) - RFC 9180
        # =====================================================================

        self.register(Algorithm(
            name="HPKE-X25519-SHA256-AES128GCM",
            family="HPKE",
            variant="X25519-SHA256-AES128GCM",
            aliases=["hpke-x25519-aes128gcm", "x25519-sha256-aes128gcm"],
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["hybrid encryption", "key encapsulation", "secure messaging"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 9180"],
            approved_by=[StandardsBody.IETF],
            relative_speed="fast",
            implementation_notes=[
                "DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM",
                "Recommended for most applications",
                "Supports Base, PSK, Auth, and AuthPSK modes",
            ],
            code_patterns=[r"hpke", r"HPKE", r"x25519.*aes.*gcm"],
        ))

        self.register(Algorithm(
            name="HPKE-X25519-SHA256-ChaCha20",
            family="HPKE",
            variant="X25519-SHA256-ChaCha20Poly1305",
            aliases=["hpke-x25519-chacha20", "x25519-sha256-chacha20poly1305"],
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["hybrid encryption", "key encapsulation", "secure messaging"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 9180"],
            approved_by=[StandardsBody.IETF],
            relative_speed="fast",
            implementation_notes=[
                "DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305",
                "Good alternative when hardware AES acceleration unavailable",
            ],
            code_patterns=[r"hpke.*chacha", r"x25519.*chacha"],
        ))

        self.register(Algorithm(
            name="HPKE-P256-SHA256-AES128GCM",
            family="HPKE",
            variant="P256-SHA256-AES128GCM",
            aliases=["hpke-p256-aes128gcm", "p256-sha256-aes128gcm"],
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["hybrid encryption", "NIST compliance", "government applications"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 9180"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            compliance_frameworks=["FIPS 140-3"],
            relative_speed="medium",
            implementation_notes=[
                "DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM",
                "Uses NIST P-256 curve for compliance requirements",
            ],
            code_patterns=[r"hpke.*p256", r"p256.*aes.*gcm"],
        ))

        self.register(Algorithm(
            name="HPKE-P384-SHA384-AES256GCM",
            family="HPKE",
            variant="P384-SHA384-AES256GCM",
            aliases=["hpke-p384-aes256gcm", "p384-sha384-aes256gcm"],
            algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION,
            use_cases=["hybrid encryption", "high-security", "government applications"],
            security_bits=192,
            key_sizes=[384],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 9180"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            compliance_frameworks=["FIPS 140-3"],
            relative_speed="medium",
            implementation_notes=[
                "DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM",
                "Higher security level for sensitive applications",
            ],
            code_patterns=[r"hpke.*p384", r"p384.*aes.*gcm"],
        ))

        # =====================================================================
        # DIGITAL SIGNATURES
        # =====================================================================

        self.register(Algorithm(
            name="Ed25519",
            family="EdDSA",
            variant="Ed25519",
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["digital signatures", "code signing", "authentication"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8032", "FIPS 186-5"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            compliance_frameworks=["PCI-DSS", "HIPAA"],
            relative_speed="fast",
            implementation_notes=[
                "Deterministic signatures (no nonce issues)",
                "Added to FIPS 186-5 (2023)",
                "Preferred over ECDSA for new applications",
            ],
            code_patterns=[r"Ed25519", r"ed25519"],
        ))

        self.register(Algorithm(
            name="Ed448",
            family="EdDSA",
            variant="Ed448",
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["digital signatures", "high-security applications"],
            security_bits=224,
            key_sizes=[448],
            quantum_resistant=False,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8032", "FIPS 186-5"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            relative_speed="medium",
            implementation_notes=["224-bit security level"],
            code_patterns=[r"Ed448", r"ed448"],
        ))

        self.register(Algorithm(
            name="ECDSA-P256",
            family="ECDSA",
            variant="P-256",
            aliases=["ecdsa-secp256r1"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["digital signatures", "TLS", "code signing"],
            security_bits=128,
            key_sizes=[256],
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            replacement="Ed25519",
            standards=["FIPS 186-5", "NIST SP 800-186"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
            common_mistakes=["Nonce reuse (catastrophic - full key recovery)"],
            implementation_notes=["Use RFC 6979 for deterministic nonces"],
            code_patterns=[r"ECDSA.*P-256", r"secp256r1"],
        ))

        self.register(Algorithm(
            name="ECDSA-P384",
            family="ECDSA",
            variant="P-384",
            aliases=["ecdsa-secp384r1"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["digital signatures"],
            security_bits=192,
            key_sizes=[384],
            quantum_resistant=False,
            status=SecurityStatus.ACCEPTABLE,
            standards=["FIPS 186-5", "NIST SP 800-186"],
            approved_by=[StandardsBody.NIST],
            code_patterns=[r"ECDSA.*P-384", r"secp384r1"],
        ))

        # =====================================================================
        # POST-QUANTUM CRYPTOGRAPHY (NIST Finalized Standards - August 2024)
        # =====================================================================

        # ML-KEM (Module-Lattice Key Encapsulation Mechanism) - FIPS 203
        # Formerly known as CRYSTALS-Kyber

        self.register(Algorithm(
            name="ML-KEM-512",
            family="ML-KEM",
            variant="512",
            aliases=["kyber512", "kyber-512"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["post-quantum key encapsulation", "hybrid TLS"],
            security_bits=128,
            quantum_resistant=True,
            quantum_security_bits=128,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 203"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST PQC Security Level 1 (AES-128 equivalent)",
                "Finalized August 2024",
                "Smallest parameter set - use for bandwidth-constrained",
            ],
            code_patterns=[r"ML.KEM.512", r"Kyber512", r"mlkem512"],
        ))

        self.register(Algorithm(
            name="ML-KEM-768",
            family="ML-KEM",
            variant="768",
            aliases=["kyber768", "kyber-768"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["post-quantum key encapsulation", "hybrid TLS", "general use"],
            security_bits=192,
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 203"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["CNSA 2.0"],
            implementation_notes=[
                "NIST PQC Security Level 3 (AES-192 equivalent)",
                "RECOMMENDED DEFAULT for most applications",
                "Finalized August 2024",
                "NSA CNSA 2.0 compliant",
            ],
            code_patterns=[r"ML.KEM.768", r"Kyber768", r"mlkem768"],
        ))

        self.register(Algorithm(
            name="ML-KEM-1024",
            family="ML-KEM",
            variant="1024",
            aliases=["kyber1024", "kyber-1024"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["post-quantum key encapsulation", "high-security applications"],
            security_bits=256,
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 203"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST PQC Security Level 5 (AES-256 equivalent)",
                "Highest security level",
                "Finalized August 2024",
            ],
            code_patterns=[r"ML.KEM.1024", r"Kyber1024", r"mlkem1024"],
        ))

        # ML-DSA (Module-Lattice Digital Signature Algorithm) - FIPS 204
        # Formerly known as CRYSTALS-Dilithium

        self.register(Algorithm(
            name="ML-DSA-44",
            family="ML-DSA",
            variant="44",
            aliases=["dilithium2", "dilithium-2"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "code signing"],
            security_bits=128,
            quantum_resistant=True,
            quantum_security_bits=128,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 204"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST PQC Security Level 2",
                "Finalized August 2024",
                "Smallest signatures in lattice family",
            ],
            code_patterns=[r"ML.DSA.44", r"Dilithium2", r"mldsa44"],
        ))

        self.register(Algorithm(
            name="ML-DSA-65",
            family="ML-DSA",
            variant="65",
            aliases=["dilithium3", "dilithium-3"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "code signing", "document signing"],
            security_bits=192,
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 204"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["CNSA 2.0"],
            implementation_notes=[
                "NIST PQC Security Level 3",
                "RECOMMENDED DEFAULT for signatures",
                "Finalized August 2024",
                "NSA CNSA 2.0 compliant",
            ],
            code_patterns=[r"ML.DSA.65", r"Dilithium3", r"mldsa65"],
        ))

        self.register(Algorithm(
            name="ML-DSA-87",
            family="ML-DSA",
            variant="87",
            aliases=["dilithium5", "dilithium-5"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "high-security applications"],
            security_bits=256,
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 204"],
            approved_by=[StandardsBody.NIST],
            implementation_notes=[
                "NIST PQC Security Level 5",
                "Highest security level",
                "Finalized August 2024",
            ],
            code_patterns=[r"ML.DSA.87", r"Dilithium5", r"mldsa87"],
        ))

        # SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - FIPS 205
        # Formerly known as SPHINCS+

        self.register(Algorithm(
            name="SLH-DSA-SHA2-128f",
            family="SLH-DSA",
            variant="SHA2-128f",
            aliases=["sphincs+-sha256-128f", "sphincs-sha2-128f"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "stateless signatures", "conservative security"],
            security_bits=128,
            quantum_resistant=True,
            quantum_security_bits=128,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            relative_speed="slow",
            memory_usage="low",
            implementation_notes=[
                "NIST PQC Security Level 1",
                "Finalized August 2024",
                "Stateless - no state management required",
                "Conservative security (hash-based, well-understood)",
                "'f' = fast variant (larger signatures)",
            ],
            code_patterns=[r"SLH.DSA.*128f", r"SPHINCS.*128f", r"slhdsa128f"],
        ))

        self.register(Algorithm(
            name="SLH-DSA-SHA2-128s",
            family="SLH-DSA",
            variant="SHA2-128s",
            aliases=["sphincs+-sha256-128s", "sphincs-sha2-128s"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "small signatures"],
            security_bits=128,
            quantum_resistant=True,
            quantum_security_bits=128,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            relative_speed="slow",
            implementation_notes=[
                "NIST PQC Security Level 1",
                "'s' = small variant (smaller signatures, slower signing)",
            ],
            code_patterns=[r"SLH.DSA.*128s", r"SPHINCS.*128s", r"slhdsa128s"],
        ))

        self.register(Algorithm(
            name="SLH-DSA-SHA2-192f",
            family="SLH-DSA",
            variant="SHA2-192f",
            aliases=["sphincs+-sha256-192f"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures"],
            security_bits=192,
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["CNSA 2.0"],
            relative_speed="slow",
            implementation_notes=[
                "NIST PQC Security Level 3",
                "NSA CNSA 2.0 compliant",
                "'f' = fast variant (larger signatures)",
            ],
            code_patterns=[r"SLH.DSA.*192f", r"SPHINCS.*192f"],
        ))

        self.register(Algorithm(
            name="SLH-DSA-SHA2-192s",
            family="SLH-DSA",
            variant="SHA2-192s",
            aliases=["sphincs+-sha256-192s"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "balanced size/security"],
            security_bits=192,
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            compliance_frameworks=["CNSA 2.0"],
            relative_speed="slow",
            implementation_notes=[
                "NIST PQC Security Level 3",
                "NSA CNSA 2.0 compliant",
                "'s' = small variant (smaller signatures, slower signing)",
            ],
            code_patterns=[r"SLH.DSA.*192s", r"SPHINCS.*192s"],
        ))

        self.register(Algorithm(
            name="SLH-DSA-SHA2-256f",
            family="SLH-DSA",
            variant="SHA2-256f",
            aliases=["sphincs+-sha256-256f"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "highest security"],
            security_bits=256,
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            relative_speed="slow",
            implementation_notes=[
                "NIST PQC Security Level 5",
                "Highest security level for hash-based signatures",
                "'f' = fast variant (larger signatures)",
            ],
            code_patterns=[r"SLH.DSA.*256f", r"SPHINCS.*256f"],
        ))

        self.register(Algorithm(
            name="SLH-DSA-SHA2-256s",
            family="SLH-DSA",
            variant="SHA2-256s",
            aliases=["sphincs+-sha256-256s"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["post-quantum digital signatures", "maximum security", "bandwidth-sensitive"],
            security_bits=256,
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            standards=["FIPS 205"],
            approved_by=[StandardsBody.NIST],
            relative_speed="slow",
            implementation_notes=[
                "NIST PQC Security Level 5",
                "Highest security level for hash-based signatures",
                "'s' = small variant (smaller signatures, slower signing)",
            ],
            code_patterns=[r"SLH.DSA.*256s", r"SPHINCS.*256s"],
        ))

        # =====================================================================
        # HYBRID ALGORITHMS (Classical + PQC)
        # Per NIST guidance: Use hybrid mode during PQC transition
        # =====================================================================

        self.register(Algorithm(
            name="X25519+ML-KEM-768",
            family="Hybrid-KEM",
            variant="X25519-MLKEM768",
            aliases=["x25519-kyber768", "hybrid-kem-768"],
            algorithm_type=AlgorithmType.KEY_EXCHANGE,
            use_cases=["hybrid key exchange", "quantum-safe TLS", "transition security"],
            security_bits=192,
            key_sizes=[256, 768],
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["draft-ietf-tls-hybrid-design"],
            implementation_notes=[
                "Combines X25519 with ML-KEM-768",
                "Used in Chrome/Firefox for hybrid TLS",
                "Secure if either algorithm remains unbroken",
                "Recommended for PQC transition period",
            ],
            code_patterns=[r"X25519.*Kyber", r"hybrid.*kem", r"X25519MLKEM768"],
        ))

        self.register(Algorithm(
            name="AES-256-GCM+ML-KEM-768",
            family="Hybrid-Encryption",
            variant="AES-MLKEM768",
            aliases=["aes-kyber768", "hybrid-aead-768"],
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["hybrid encryption", "quantum-safe data encryption"],
            security_bits=256,
            key_sizes=[256],
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            implementation_notes=[
                "Combines AES-256-GCM with ML-KEM-768 KEM",
                "Secure if either algorithm remains unbroken",
                "RECOMMENDED for new applications requiring PQC",
            ],
            code_patterns=[r"AES.*Kyber", r"aes.*mlkem"],
        ))

        self.register(Algorithm(
            name="AES-256-GCM+ML-KEM-1024",
            family="Hybrid-Encryption",
            variant="AES-MLKEM1024",
            aliases=["aes-kyber1024", "hybrid-aead-1024"],
            algorithm_type=AlgorithmType.AEAD,
            use_cases=["hybrid encryption", "maximum security"],
            security_bits=256,
            key_sizes=[256],
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            implementation_notes=[
                "Highest security hybrid mode",
                "NIST PQC Level 5 quantum security",
            ],
            code_patterns=[r"AES.*1024", r"aes.*mlkem.*1024"],
        ))

        self.register(Algorithm(
            name="ECDSA-P256+ML-DSA-65",
            family="Hybrid-Signature",
            variant="ECDSA-MLDSA65",
            aliases=["ecdsa-dilithium3", "hybrid-sig-65"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["hybrid signatures", "quantum-safe code signing"],
            security_bits=192,
            key_sizes=[256],
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            implementation_notes=[
                "Combines ECDSA-P256 with ML-DSA-65",
                "Both signatures required for verification",
                "Secure if either algorithm remains unbroken",
            ],
            code_patterns=[r"ECDSA.*Dilithium", r"hybrid.*sig"],
        ))

        self.register(Algorithm(
            name="Ed25519+ML-DSA-65",
            family="Hybrid-Signature",
            variant="Ed25519-MLDSA65",
            aliases=["eddsa-dilithium3", "ed25519-mldsa-65", "hybrid-ed-mldsa"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["hybrid signatures", "quantum-safe authentication", "code signing"],
            security_bits=192,
            key_sizes=[256],
            quantum_resistant=True,
            quantum_security_bits=192,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8032 + FIPS 204"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            implementation_notes=[
                "Combines Ed25519 with ML-DSA-65 for hybrid quantum safety",
                "Both signatures required for verification",
                "Secure if either algorithm remains unbroken",
                "Deterministic Ed25519 eliminates nonce risks",
                "Preferred over ECDSA hybrid for new applications",
            ],
            code_patterns=[r"Ed25519.*ML-DSA", r"ed25519.*mldsa", r"hybrid.*ed.*sig"],
        ))

        self.register(Algorithm(
            name="Ed25519+ML-DSA-87",
            family="Hybrid-Signature",
            variant="Ed25519-MLDSA87",
            aliases=["eddsa-dilithium5", "ed25519-mldsa-87"],
            algorithm_type=AlgorithmType.SIGNATURE,
            use_cases=["hybrid signatures", "maximum security applications"],
            security_bits=256,
            key_sizes=[256],
            quantum_resistant=True,
            quantum_security_bits=256,
            status=SecurityStatus.RECOMMENDED,
            standards=["RFC 8032 + FIPS 204"],
            approved_by=[StandardsBody.IETF, StandardsBody.NIST],
            implementation_notes=[
                "Combines Ed25519 with ML-DSA-87 (NIST Level 5)",
                "Maximum quantum security level",
                "Both signatures required for verification",
                "Secure if either algorithm remains unbroken",
            ],
            code_patterns=[r"Ed25519.*ML-DSA.*87", r"ed25519.*mldsa.*87"],
        ))


# Singleton instance
crypto_registry = CryptoRegistry()


# =============================================================================
# Convenience Functions
# =============================================================================

def is_algorithm_secure(name: str) -> bool:
    """Check if an algorithm is considered secure."""
    return crypto_registry.is_secure(name)


def is_algorithm_quantum_resistant(name: str) -> bool:
    """Check if an algorithm is quantum-resistant."""
    return crypto_registry.is_quantum_resistant(name)


def get_algorithm_info(name: str) -> Algorithm | None:
    """Get full information about an algorithm."""
    return crypto_registry.get(name)


def get_recommended_algorithms(algorithm_type: AlgorithmType) -> list[Algorithm]:
    """Get recommended algorithms of a specific type."""
    return crypto_registry.get_recommended(algorithm_type)


def get_deprecated_algorithms() -> list[Algorithm]:
    """Get all deprecated or broken algorithms."""
    return crypto_registry.get_deprecated()
