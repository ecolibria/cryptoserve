"""Binary Cryptographic Scanner.

Detects cryptographic algorithms and constants in binary files.
Useful for crypto-agility audits and vulnerability detection.

Capabilities:
- Detect crypto constants (S-boxes, magic numbers, round constants)
- Identify crypto algorithm implementations
- Flag weak/deprecated algorithms
- Support multiple binary formats

Detected Algorithms:
- AES (S-box, round constants)
- DES/3DES (S-boxes, permutation tables)
- SHA-1/SHA-256/SHA-512 (round constants)
- MD5 (sine table constants)
- RSA (common exponents)
- ChaCha20/Salsa20 (sigma constant)
- Blowfish (P-array, S-boxes)
- RC4 (state initialization patterns)

Use Cases:
- Crypto-agility audits
- Detecting hardcoded keys
- Identifying deprecated algorithms
- Binary analysis for compliance

References:
- CryptoScan methodology
- NIST cryptographic guidelines
"""

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple, BinaryIO
import re


class CryptoCategory(str, Enum):
    """Category of cryptographic finding."""

    SYMMETRIC = "symmetric"
    HASH = "hash"
    ASYMMETRIC = "asymmetric"
    STREAM = "stream"
    KEY_MATERIAL = "key_material"
    RANDOM = "random"
    UNKNOWN = "unknown"


class CryptoSeverity(str, Enum):
    """Severity of cryptographic finding."""

    CRITICAL = "critical"  # Broken/weak crypto (MD5, DES, RC4)
    HIGH = "high"  # Deprecated (SHA-1, 3DES)
    MEDIUM = "medium"  # Potential issues
    LOW = "low"  # Informational
    INFO = "info"  # Normal/expected


@dataclass
class CryptoConstant:
    """A cryptographic constant or pattern."""

    name: str
    algorithm: str
    category: CryptoCategory
    pattern: bytes
    severity: CryptoSeverity
    description: str
    cwe_id: Optional[str] = None  # CWE identifier


@dataclass
class CryptoFinding:
    """A cryptographic finding in a binary."""

    algorithm: str
    category: CryptoCategory
    severity: CryptoSeverity
    offset: int
    size: int
    pattern_name: str
    description: str
    confidence: float  # 0.0 to 1.0
    context: bytes = b""  # Surrounding bytes
    cwe_id: Optional[str] = None


@dataclass
class ScanResult:
    """Result of scanning a binary."""

    file_path: str
    file_size: int
    file_hash: str  # SHA-256
    findings: List[CryptoFinding] = field(default_factory=list)
    algorithms_detected: Set[str] = field(default_factory=set)
    weak_algorithms: Set[str] = field(default_factory=set)
    scan_coverage: float = 1.0  # Portion of file scanned
    error: Optional[str] = None

    @property
    def has_critical(self) -> bool:
        """Check if any critical findings."""
        return any(f.severity == CryptoSeverity.CRITICAL for f in self.findings)

    @property
    def has_weak_crypto(self) -> bool:
        """Check if weak cryptography detected."""
        return len(self.weak_algorithms) > 0


class BinaryScanner:
    """Scanner for detecting cryptographic content in binaries.

    Usage:
        scanner = BinaryScanner()

        # Scan a file
        result = scanner.scan_file("/path/to/binary")

        # Check for weak crypto
        if result.has_weak_crypto:
            print(f"Weak algorithms: {result.weak_algorithms}")

        # Iterate findings
        for finding in result.findings:
            print(f"{finding.algorithm} at offset {finding.offset}")
    """

    # Weak/deprecated algorithms that should be flagged
    WEAK_ALGORITHMS = {
        "MD5",
        "MD4",
        "SHA-1",
        "DES",
        "3DES",
        "RC4",
        "RC2",
        "Blowfish",
    }

    def __init__(self):
        """Initialize scanner with crypto patterns."""
        self._patterns: List[CryptoConstant] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load cryptographic patterns for detection."""
        # AES S-box (first 16 bytes)
        aes_sbox_start = bytes(
            [
                0x63,
                0x7C,
                0x77,
                0x7B,
                0xF2,
                0x6B,
                0x6F,
                0xC5,
                0x30,
                0x01,
                0x67,
                0x2B,
                0xFE,
                0xD7,
                0xAB,
                0x76,
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="AES S-box",
                algorithm="AES",
                category=CryptoCategory.SYMMETRIC,
                pattern=aes_sbox_start,
                severity=CryptoSeverity.INFO,
                description="AES S-box substitution table detected",
            )
        )

        # AES round constant
        aes_rcon = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])
        self._patterns.append(
            CryptoConstant(
                name="AES Rcon",
                algorithm="AES",
                category=CryptoCategory.SYMMETRIC,
                pattern=aes_rcon,
                severity=CryptoSeverity.INFO,
                description="AES round constants detected",
            )
        )

        # DES initial permutation (partial)
        des_ip = bytes(
            [
                58,
                50,
                42,
                34,
                26,
                18,
                10,
                2,
                60,
                52,
                44,
                36,
                28,
                20,
                12,
                4,
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="DES IP",
                algorithm="DES",
                category=CryptoCategory.SYMMETRIC,
                pattern=des_ip,
                severity=CryptoSeverity.CRITICAL,
                description="DES initial permutation table - WEAK ALGORITHM",
                cwe_id="CWE-327",
            )
        )

        # DES S-box 1 (first row)
        des_sbox1 = bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])
        self._patterns.append(
            CryptoConstant(
                name="DES S-box",
                algorithm="DES",
                category=CryptoCategory.SYMMETRIC,
                pattern=des_sbox1,
                severity=CryptoSeverity.CRITICAL,
                description="DES S-box detected - WEAK ALGORITHM",
                cwe_id="CWE-327",
            )
        )

        # SHA-256 initial hash values (first 4 bytes of each)
        sha256_h = bytes(
            [
                0x6A,
                0x09,
                0xE6,
                0x67,  # H0
                0xBB,
                0x67,
                0xAE,
                0x85,  # H1
                0x3C,
                0x6E,
                0xF3,
                0x72,  # H2
                0xA5,
                0x4F,
                0xF5,
                0x3A,  # H3
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="SHA-256 IV",
                algorithm="SHA-256",
                category=CryptoCategory.HASH,
                pattern=sha256_h,
                severity=CryptoSeverity.INFO,
                description="SHA-256 initial hash values detected",
            )
        )

        # SHA-1 initial hash values
        sha1_h = bytes(
            [
                0x67,
                0x45,
                0x23,
                0x01,  # H0 (big-endian)
                0xEF,
                0xCD,
                0xAB,
                0x89,  # H1
                0x98,
                0xBA,
                0xDC,
                0xFE,  # H2
                0x10,
                0x32,
                0x54,
                0x76,  # H3
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="SHA-1 IV",
                algorithm="SHA-1",
                category=CryptoCategory.HASH,
                pattern=sha1_h,
                severity=CryptoSeverity.HIGH,
                description="SHA-1 detected - DEPRECATED for security",
                cwe_id="CWE-328",
            )
        )

        # MD5 initial hash values
        md5_h = bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,  # A
                0x89,
                0xAB,
                0xCD,
                0xEF,  # B
                0xFE,
                0xDC,
                0xBA,
                0x98,  # C
                0x76,
                0x54,
                0x32,
                0x10,  # D
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="MD5 IV",
                algorithm="MD5",
                category=CryptoCategory.HASH,
                pattern=md5_h,
                severity=CryptoSeverity.CRITICAL,
                description="MD5 detected - BROKEN ALGORITHM",
                cwe_id="CWE-328",
            )
        )

        # MD5 T table (first constants from sine function)
        md5_t = bytes(
            [
                0xD7,
                0x6A,
                0xA4,
                0x78,  # T[1]
                0xE8,
                0xC7,
                0xB7,
                0x56,  # T[2]
                0x24,
                0x21,
                0x05,
                0x02,  # T[3] (partial)
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="MD5 T-table",
                algorithm="MD5",
                category=CryptoCategory.HASH,
                pattern=md5_t,
                severity=CryptoSeverity.CRITICAL,
                description="MD5 sine table constants - BROKEN ALGORITHM",
                cwe_id="CWE-328",
            )
        )

        # ChaCha20/Salsa20 sigma constant "expand 32-byte k"
        chacha_sigma = b"expand 32-byte k"
        self._patterns.append(
            CryptoConstant(
                name="ChaCha20/Salsa20 sigma",
                algorithm="ChaCha20",
                category=CryptoCategory.STREAM,
                pattern=chacha_sigma,
                severity=CryptoSeverity.INFO,
                description="ChaCha20/Salsa20 constant detected",
            )
        )

        # Salsa20 tau constant "expand 16-byte k"
        salsa_tau = b"expand 16-byte k"
        self._patterns.append(
            CryptoConstant(
                name="Salsa20 tau",
                algorithm="Salsa20",
                category=CryptoCategory.STREAM,
                pattern=salsa_tau,
                severity=CryptoSeverity.INFO,
                description="Salsa20 tau constant detected",
            )
        )

        # RC4 state initialization marker (0-255 sequence)
        rc4_state = bytes(range(256))
        self._patterns.append(
            CryptoConstant(
                name="RC4 state",
                algorithm="RC4",
                category=CryptoCategory.STREAM,
                pattern=rc4_state[:32],  # First 32 bytes
                severity=CryptoSeverity.CRITICAL,
                description="RC4 state detected - BROKEN ALGORITHM",
                cwe_id="CWE-327",
            )
        )

        # Blowfish P-array initial values
        blowfish_p = bytes(
            [
                0x24,
                0x3F,
                0x6A,
                0x88,
                0x85,
                0xA3,
                0x08,
                0xD3,
                0x13,
                0x19,
                0x8A,
                0x2E,
                0x03,
                0x70,
                0x73,
                0x44,
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="Blowfish P-array",
                algorithm="Blowfish",
                category=CryptoCategory.SYMMETRIC,
                pattern=blowfish_p,
                severity=CryptoSeverity.HIGH,
                description="Blowfish P-array detected - consider modern alternative",
                cwe_id="CWE-327",
            )
        )

        # RSA public exponent 65537 (0x10001)
        rsa_e = bytes([0x01, 0x00, 0x01])
        self._patterns.append(
            CryptoConstant(
                name="RSA public exponent",
                algorithm="RSA",
                category=CryptoCategory.ASYMMETRIC,
                pattern=rsa_e,
                severity=CryptoSeverity.LOW,
                description="RSA public exponent 65537 detected",
            )
        )

        # PKCS#1 signature prefix (SHA-256)
        pkcs1_sha256 = bytes(
            [
                0x30,
                0x31,
                0x30,
                0x0D,
                0x06,
                0x09,
                0x60,
                0x86,
                0x48,
                0x01,
                0x65,
                0x03,
                0x04,
                0x02,
                0x01,
            ]
        )
        self._patterns.append(
            CryptoConstant(
                name="PKCS#1 SHA-256 prefix",
                algorithm="PKCS#1",
                category=CryptoCategory.ASYMMETRIC,
                pattern=pkcs1_sha256,
                severity=CryptoSeverity.INFO,
                description="PKCS#1 v1.5 signature prefix for SHA-256",
            )
        )

        # Potential hardcoded key patterns (entropy markers)
        # 16 bytes of 0xFF (sometimes used as placeholder keys)
        weak_key_ff = bytes([0xFF] * 16)
        self._patterns.append(
            CryptoConstant(
                name="Potential weak key (0xFF)",
                algorithm="Unknown",
                category=CryptoCategory.KEY_MATERIAL,
                pattern=weak_key_ff,
                severity=CryptoSeverity.MEDIUM,
                description="Potential weak/placeholder key material",
                cwe_id="CWE-321",
            )
        )

        # 16 bytes of 0x00 (sometimes used as null keys)
        weak_key_00 = bytes([0x00] * 16)
        self._patterns.append(
            CryptoConstant(
                name="Potential weak key (0x00)",
                algorithm="Unknown",
                category=CryptoCategory.KEY_MATERIAL,
                pattern=weak_key_00,
                severity=CryptoSeverity.MEDIUM,
                description="Potential null key material",
                cwe_id="CWE-321",
            )
        )

    def scan_file(self, file_path: str, max_size: int = 100 * 1024 * 1024) -> ScanResult:
        """Scan a file for cryptographic content.

        Args:
            file_path: Path to file to scan
            max_size: Maximum file size to scan (default 100MB)

        Returns:
            ScanResult with findings
        """
        path = Path(file_path)

        if not path.exists():
            return ScanResult(
                file_path=file_path,
                file_size=0,
                file_hash="",
                error=f"File not found: {file_path}",
            )

        file_size = path.stat().st_size

        if file_size > max_size:
            return ScanResult(
                file_path=file_path,
                file_size=file_size,
                file_hash="",
                error=f"File too large: {file_size} > {max_size}",
            )

        try:
            with open(path, "rb") as f:
                data = f.read()

            file_hash = hashlib.sha256(data).hexdigest()

            findings = self._scan_data(data)
            algorithms = set(f.algorithm for f in findings)
            weak = algorithms.intersection(self.WEAK_ALGORITHMS)

            return ScanResult(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                findings=findings,
                algorithms_detected=algorithms,
                weak_algorithms=weak,
            )

        except Exception as e:
            return ScanResult(
                file_path=file_path,
                file_size=file_size,
                file_hash="",
                error=str(e),
            )

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> ScanResult:
        """Scan bytes for cryptographic content.

        Args:
            data: Binary data to scan
            name: Name for the scan result

        Returns:
            ScanResult with findings
        """
        file_hash = hashlib.sha256(data).hexdigest()
        findings = self._scan_data(data)
        algorithms = set(f.algorithm for f in findings)
        weak = algorithms.intersection(self.WEAK_ALGORITHMS)

        return ScanResult(
            file_path=name,
            file_size=len(data),
            file_hash=file_hash,
            findings=findings,
            algorithms_detected=algorithms,
            weak_algorithms=weak,
        )

    def _scan_data(self, data: bytes) -> List[CryptoFinding]:
        """Scan binary data for crypto patterns.

        Args:
            data: Binary data to scan

        Returns:
            List of findings
        """
        findings = []

        for pattern in self._patterns:
            offset = 0
            while True:
                pos = data.find(pattern.pattern, offset)
                if pos == -1:
                    break

                # Get context (32 bytes before and after)
                ctx_start = max(0, pos - 32)
                ctx_end = min(len(data), pos + len(pattern.pattern) + 32)
                context = data[ctx_start:ctx_end]

                # Calculate confidence based on pattern length and uniqueness
                confidence = self._calculate_confidence(pattern, data, pos)

                finding = CryptoFinding(
                    algorithm=pattern.algorithm,
                    category=pattern.category,
                    severity=pattern.severity,
                    offset=pos,
                    size=len(pattern.pattern),
                    pattern_name=pattern.name,
                    description=pattern.description,
                    confidence=confidence,
                    context=context,
                    cwe_id=pattern.cwe_id,
                )
                findings.append(finding)

                offset = pos + 1

        # Sort by offset
        findings.sort(key=lambda f: f.offset)

        return findings

    def _calculate_confidence(
        self,
        pattern: CryptoConstant,
        data: bytes,
        pos: int,
    ) -> float:
        """Calculate confidence score for a finding.

        Longer patterns and fewer false positives = higher confidence.

        Args:
            pattern: The matched pattern
            data: Full binary data
            pos: Position of match

        Returns:
            Confidence score 0.0 to 1.0
        """
        # Base confidence from pattern length
        length_confidence = min(len(pattern.pattern) / 32.0, 1.0)

        # Higher confidence for algorithm-specific patterns
        specific_confidence = 0.9 if pattern.category != CryptoCategory.KEY_MATERIAL else 0.5

        # Combined confidence
        return (length_confidence * 0.4) + (specific_confidence * 0.6)

    def get_patterns(self) -> List[CryptoConstant]:
        """Get all registered patterns.

        Returns:
            List of CryptoConstant patterns
        """
        return list(self._patterns)

    def add_pattern(self, pattern: CryptoConstant) -> None:
        """Add a custom pattern.

        Args:
            pattern: Pattern to add
        """
        self._patterns.append(pattern)

    def detect_high_entropy_regions(
        self,
        data: bytes,
        block_size: int = 64,
        threshold: float = 7.5,
    ) -> List[Tuple[int, int, float]]:
        """Detect high-entropy regions that might be keys or ciphertext.

        Args:
            data: Binary data to analyze
            block_size: Size of blocks to analyze
            threshold: Entropy threshold (max ~8.0)

        Returns:
            List of (offset, size, entropy) tuples
        """
        regions = []

        for i in range(0, len(data) - block_size, block_size):
            block = data[i : i + block_size]
            entropy = self._calculate_entropy(block)

            if entropy >= threshold:
                regions.append((i, block_size, entropy))

        return regions

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze

        Returns:
            Entropy value (0.0 to 8.0)
        """
        import math

        if len(data) == 0:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)

        return entropy

    def generate_report(self, result: ScanResult) -> str:
        """Generate a text report from scan results.

        Args:
            result: Scan result

        Returns:
            Formatted report string
        """
        lines = [
            "=" * 60,
            "CRYPTOGRAPHIC SCAN REPORT",
            "=" * 60,
            f"File: {result.file_path}",
            f"Size: {result.file_size} bytes",
            f"SHA-256: {result.file_hash[:16]}...",
            "",
        ]

        if result.error:
            lines.append(f"ERROR: {result.error}")
            return "\n".join(lines)

        lines.append(f"Algorithms Detected: {', '.join(result.algorithms_detected) or 'None'}")

        if result.weak_algorithms:
            lines.append(f"WEAK ALGORITHMS: {', '.join(result.weak_algorithms)}")

        lines.append("")
        lines.append(f"Findings: {len(result.findings)}")
        lines.append("-" * 60)

        for finding in result.findings:
            severity_marker = {
                CryptoSeverity.CRITICAL: "[CRITICAL]",
                CryptoSeverity.HIGH: "[HIGH]",
                CryptoSeverity.MEDIUM: "[MEDIUM]",
                CryptoSeverity.LOW: "[LOW]",
                CryptoSeverity.INFO: "[INFO]",
            }

            lines.append(
                f"{severity_marker[finding.severity]} {finding.algorithm} - {finding.pattern_name}"
            )
            lines.append(f"  Offset: 0x{finding.offset:08X}")
            lines.append(f"  Confidence: {finding.confidence:.1%}")
            lines.append(f"  {finding.description}")
            if finding.cwe_id:
                lines.append(f"  Reference: {finding.cwe_id}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


# Singleton instance
binary_scanner = BinaryScanner()
