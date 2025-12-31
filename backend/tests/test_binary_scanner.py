"""Tests for binary cryptographic scanner."""

import os
import tempfile

import pytest

from app.core.binary_scanner import (
    BinaryScanner,
    CryptoCategory,
    CryptoConstant,
    CryptoFinding,
    CryptoSeverity,
    ScanResult,
    binary_scanner,
)


class TestScannerBasics:
    """Test basic scanner functionality."""

    def test_create_scanner(self):
        """Test creating scanner instance."""
        scanner = BinaryScanner()
        assert scanner is not None

    def test_patterns_loaded(self):
        """Test that patterns are loaded."""
        scanner = BinaryScanner()
        patterns = scanner.get_patterns()
        assert len(patterns) > 0

    def test_has_aes_pattern(self):
        """Test that AES patterns are included."""
        scanner = BinaryScanner()
        patterns = scanner.get_patterns()
        aes_patterns = [p for p in patterns if p.algorithm == "AES"]
        assert len(aes_patterns) >= 1

    def test_has_weak_algo_patterns(self):
        """Test that weak algorithm patterns are included."""
        scanner = BinaryScanner()
        patterns = scanner.get_patterns()
        weak_patterns = [
            p
            for p in patterns
            if p.severity in (CryptoSeverity.CRITICAL, CryptoSeverity.HIGH)
        ]
        assert len(weak_patterns) >= 1


class TestScanBytes:
    """Test scanning bytes."""

    def test_scan_empty_bytes(self):
        """Test scanning empty bytes."""
        scanner = BinaryScanner()
        result = scanner.scan_bytes(b"")
        assert result.file_size == 0
        assert len(result.findings) == 0
        assert result.error is None

    def test_scan_random_bytes(self):
        """Test scanning random bytes (no crypto)."""
        scanner = BinaryScanner()
        data = os.urandom(1024)
        result = scanner.scan_bytes(data)
        # Random bytes unlikely to contain crypto constants
        # (though possible by chance)
        assert result.error is None

    def test_detect_aes_sbox(self):
        """Test detecting AES S-box."""
        scanner = BinaryScanner()

        # AES S-box (first 16 bytes)
        aes_sbox = bytes(
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

        # Embed in larger data
        data = b"\x00" * 100 + aes_sbox + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert "AES" in result.algorithms_detected
        assert len(result.findings) >= 1

        aes_finding = [f for f in result.findings if f.algorithm == "AES"][0]
        assert aes_finding.offset == 100
        assert aes_finding.severity == CryptoSeverity.INFO

    def test_detect_md5(self):
        """Test detecting MD5 constants."""
        scanner = BinaryScanner()

        # MD5 initial hash values
        md5_h = bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        )

        data = b"\xFF" * 50 + md5_h + b"\xFF" * 50

        result = scanner.scan_bytes(data)
        assert "MD5" in result.algorithms_detected
        assert result.has_weak_crypto
        assert "MD5" in result.weak_algorithms

        md5_finding = [f for f in result.findings if f.algorithm == "MD5"][0]
        assert md5_finding.severity == CryptoSeverity.CRITICAL

    def test_detect_chacha(self):
        """Test detecting ChaCha20 constant."""
        scanner = BinaryScanner()

        # ChaCha20 sigma constant
        chacha_sigma = b"expand 32-byte k"
        data = b"\x00" * 100 + chacha_sigma + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert "ChaCha20" in result.algorithms_detected

    def test_detect_des(self):
        """Test detecting DES constants."""
        scanner = BinaryScanner()

        # DES initial permutation table (first 16 values)
        des_ip = bytes(
            [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]
        )
        data = b"\x00" * 100 + des_ip + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert "DES" in result.algorithms_detected
        assert result.has_weak_crypto

    def test_detect_multiple_algorithms(self):
        """Test detecting multiple algorithms in same data."""
        scanner = BinaryScanner()

        # AES S-box
        aes_sbox = bytes(
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

        # ChaCha constant
        chacha_sigma = b"expand 32-byte k"

        data = b"\x00" * 50 + aes_sbox + b"\x00" * 50 + chacha_sigma + b"\x00" * 50

        result = scanner.scan_bytes(data)
        assert "AES" in result.algorithms_detected
        assert "ChaCha20" in result.algorithms_detected
        assert len(result.findings) >= 2

    def test_detect_potential_weak_key(self):
        """Test detecting potential weak key patterns."""
        scanner = BinaryScanner()

        # All zeros (potential null key)
        null_key = bytes([0x00] * 16)
        data = b"\xFF" * 100 + null_key + b"\xFF" * 100

        result = scanner.scan_bytes(data)
        key_findings = [
            f for f in result.findings if f.category == CryptoCategory.KEY_MATERIAL
        ]
        assert len(key_findings) >= 1


class TestScanFile:
    """Test scanning files."""

    def test_scan_nonexistent_file(self):
        """Test scanning non-existent file."""
        scanner = BinaryScanner()
        result = scanner.scan_file("/nonexistent/path/file.bin")
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_scan_file_with_crypto(self):
        """Test scanning file with crypto content."""
        scanner = BinaryScanner()

        # Create temp file with AES S-box
        aes_sbox = bytes(
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
        data = b"\x00" * 100 + aes_sbox + b"\x00" * 100

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path)
            assert result.error is None
            assert result.file_size == len(data)
            assert len(result.file_hash) == 64  # SHA-256 hex
            assert "AES" in result.algorithms_detected
        finally:
            os.unlink(temp_path)

    def test_scan_file_too_large(self):
        """Test scanning file that exceeds size limit."""
        scanner = BinaryScanner()

        # Create a small file but set max_size very low
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 1000)
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path, max_size=100)
            assert result.error is not None
            assert "too large" in result.error.lower()
        finally:
            os.unlink(temp_path)


class TestFindingDetails:
    """Test finding details."""

    def test_finding_offset_correct(self):
        """Test that finding offset is correct."""
        scanner = BinaryScanner()

        chacha_sigma = b"expand 32-byte k"
        offset = 256

        data = b"\x00" * offset + chacha_sigma + b"\x00" * 100

        result = scanner.scan_bytes(data)
        finding = [f for f in result.findings if f.algorithm == "ChaCha20"][0]
        assert finding.offset == offset

    def test_finding_context_included(self):
        """Test that finding includes context."""
        scanner = BinaryScanner()

        chacha_sigma = b"expand 32-byte k"
        data = b"\xAA" * 50 + chacha_sigma + b"\xBB" * 50

        result = scanner.scan_bytes(data)
        finding = [f for f in result.findings if f.algorithm == "ChaCha20"][0]

        # Context should include surrounding bytes
        assert len(finding.context) > len(chacha_sigma)
        assert chacha_sigma in finding.context

    def test_finding_confidence_score(self):
        """Test that finding has confidence score."""
        scanner = BinaryScanner()

        aes_sbox = bytes(
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
        data = b"\x00" * 100 + aes_sbox + b"\x00" * 100

        result = scanner.scan_bytes(data)
        finding = result.findings[0]

        assert 0.0 <= finding.confidence <= 1.0

    def test_cwe_id_included(self):
        """Test that CWE IDs are included for weak algorithms."""
        scanner = BinaryScanner()

        # MD5 should have CWE-328
        md5_h = bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        )
        data = b"\x00" * 100 + md5_h + b"\x00" * 100

        result = scanner.scan_bytes(data)
        md5_finding = [f for f in result.findings if f.algorithm == "MD5"][0]
        assert md5_finding.cwe_id is not None
        assert "CWE" in md5_finding.cwe_id


class TestScanResult:
    """Test ScanResult properties."""

    def test_has_critical(self):
        """Test has_critical property."""
        scanner = BinaryScanner()

        # MD5 is critical
        md5_h = bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        )
        data = b"\x00" * 100 + md5_h + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert result.has_critical is True

    def test_has_weak_crypto(self):
        """Test has_weak_crypto property."""
        scanner = BinaryScanner()

        # DES is weak
        des_ip = bytes(
            [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]
        )
        data = b"\x00" * 100 + des_ip + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert result.has_weak_crypto is True

    def test_no_weak_crypto(self):
        """Test when no weak crypto detected."""
        scanner = BinaryScanner()

        # ChaCha20 is not weak
        chacha_sigma = b"expand 32-byte k"
        data = b"\x00" * 100 + chacha_sigma + b"\x00" * 100

        result = scanner.scan_bytes(data)
        assert result.has_weak_crypto is False


class TestEntropyAnalysis:
    """Test entropy analysis."""

    def test_detect_high_entropy_regions(self):
        """Test detecting high entropy regions."""
        scanner = BinaryScanner()

        # Low entropy data + guaranteed high entropy (all unique bytes)
        low_entropy = b"\x00" * 128
        # Use bytes 0-255 - guarantees max entropy (8.0) for 256 bytes
        high_entropy = bytes(range(256))

        data = low_entropy + high_entropy

        # Use smaller block_size (64) to ensure we hit the high-entropy region
        # With 384 bytes total, we get blocks at 0, 64, 128, 192, 256, 320
        regions = scanner.detect_high_entropy_regions(data, block_size=64, threshold=5.0)

        # Should detect regions in the high-entropy area
        # The high entropy region starts at offset 128
        high_entropy_region = [r for r in regions if r[0] >= 128]
        assert len(high_entropy_region) >= 1

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        scanner = BinaryScanner()

        # All same byte = 0 entropy
        low = b"\x00" * 256
        entropy_low = scanner._calculate_entropy(low)
        assert entropy_low == 0.0

        # All different bytes = max entropy (~8)
        high = bytes(range(256))
        entropy_high = scanner._calculate_entropy(high)
        assert entropy_high == 8.0

    def test_empty_entropy(self):
        """Test entropy of empty data."""
        scanner = BinaryScanner()
        entropy = scanner._calculate_entropy(b"")
        assert entropy == 0.0


class TestCustomPatterns:
    """Test custom pattern functionality."""

    def test_add_custom_pattern(self):
        """Test adding custom pattern."""
        scanner = BinaryScanner()
        initial_count = len(scanner.get_patterns())

        custom_pattern = CryptoConstant(
            name="Custom Test Pattern",
            algorithm="CustomAlgo",
            category=CryptoCategory.SYMMETRIC,
            pattern=b"CUSTOM_MARKER",
            severity=CryptoSeverity.INFO,
            description="Test custom pattern",
        )

        scanner.add_pattern(custom_pattern)
        assert len(scanner.get_patterns()) == initial_count + 1

    def test_custom_pattern_detected(self):
        """Test that custom pattern is detected."""
        scanner = BinaryScanner()

        custom_pattern = CryptoConstant(
            name="MyMarker",
            algorithm="MyAlgo",
            category=CryptoCategory.SYMMETRIC,
            pattern=b"MY_SPECIAL_MARKER",
            severity=CryptoSeverity.MEDIUM,
            description="My custom crypto marker",
        )
        scanner.add_pattern(custom_pattern)

        data = b"\x00" * 100 + b"MY_SPECIAL_MARKER" + b"\x00" * 100
        result = scanner.scan_bytes(data)

        assert "MyAlgo" in result.algorithms_detected
        my_finding = [f for f in result.findings if f.algorithm == "MyAlgo"][0]
        assert my_finding.pattern_name == "MyMarker"


class TestReportGeneration:
    """Test report generation."""

    def test_generate_report(self):
        """Test generating text report."""
        scanner = BinaryScanner()

        aes_sbox = bytes(
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
        data = b"\x00" * 100 + aes_sbox + b"\x00" * 100

        result = scanner.scan_bytes(data, name="test.bin")
        report = scanner.generate_report(result)

        assert "CRYPTOGRAPHIC SCAN REPORT" in report
        assert "test.bin" in report
        assert "AES" in report

    def test_report_with_error(self):
        """Test report generation when error occurred."""
        scanner = BinaryScanner()
        result = scanner.scan_file("/nonexistent/file")
        report = scanner.generate_report(result)

        assert "ERROR" in report

    def test_report_shows_weak_algorithms(self):
        """Test that report highlights weak algorithms."""
        scanner = BinaryScanner()

        md5_h = bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        )
        data = b"\x00" * 100 + md5_h + b"\x00" * 100

        result = scanner.scan_bytes(data)
        report = scanner.generate_report(result)

        assert "WEAK ALGORITHMS" in report
        assert "MD5" in report
        assert "[CRITICAL]" in report


class TestSingletonInstance:
    """Test singleton instance."""

    def test_singleton_exists(self):
        """Test singleton instance exists."""
        assert binary_scanner is not None
        assert isinstance(binary_scanner, BinaryScanner)

    def test_singleton_scans(self):
        """Test singleton can scan."""
        result = binary_scanner.scan_bytes(b"\x00" * 100)
        assert result is not None
        assert result.error is None


class TestMultipleMatches:
    """Test handling multiple matches."""

    def test_same_pattern_multiple_times(self):
        """Test detecting same pattern multiple times."""
        scanner = BinaryScanner()

        chacha_sigma = b"expand 32-byte k"

        # Pattern appears twice
        data = b"\x00" * 50 + chacha_sigma + b"\x00" * 50 + chacha_sigma + b"\x00" * 50

        result = scanner.scan_bytes(data)
        chacha_findings = [f for f in result.findings if f.algorithm == "ChaCha20"]
        assert len(chacha_findings) == 2

        # Offsets should be different
        offsets = [f.offset for f in chacha_findings]
        assert offsets[0] != offsets[1]

    def test_overlapping_patterns_not_possible(self):
        """Test that patterns don't overlap incorrectly."""
        scanner = BinaryScanner()

        # This shouldn't cause issues
        chacha_sigma = b"expand 32-byte k"
        data = chacha_sigma + chacha_sigma

        result = scanner.scan_bytes(data)
        chacha_findings = [f for f in result.findings if f.algorithm == "ChaCha20"]
        assert len(chacha_findings) == 2
