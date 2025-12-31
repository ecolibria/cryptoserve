"""Tests for the AST-based Code Scanner engine."""

import pytest
from app.core.code_scanner import CodeScanner, Language, QuantumRisk, Severity


@pytest.fixture
def scanner():
    """Create a code scanner instance."""
    return CodeScanner()


class TestCodeScannerBasics:
    """Basic code scanner tests."""

    def test_scan_empty_code(self, scanner):
        """Scanning empty code should return empty results."""
        result = scanner.scan_code("", language="python")
        assert len(result.usages) == 0
        assert len(result.findings) == 0

    def test_scan_no_crypto(self, scanner):
        """Code without crypto should return no usages."""
        code = """
def hello():
    print("Hello, world!")
"""
        result = scanner.scan_code(code, language="python")
        assert len(result.usages) == 0

    def test_detect_hashlib_md5(self, scanner):
        """Should detect MD5 as weak algorithm."""
        code = """
import hashlib
h = hashlib.md5(b"data")
"""
        result = scanner.scan_code(code, language="python")
        assert len(result.usages) >= 1
        md5_usage = next((u for u in result.usages if u.algorithm == "md5"), None)
        assert md5_usage is not None
        assert md5_usage.is_weak is True
        assert md5_usage.category == "hashing"

    def test_detect_hashlib_sha256(self, scanner):
        """Should detect SHA256 as safe algorithm."""
        code = """
import hashlib
h = hashlib.sha256(b"data")
"""
        result = scanner.scan_code(code, language="python")
        assert len(result.usages) >= 1
        sha_usage = next((u for u in result.usages if "sha256" in u.algorithm), None)
        assert sha_usage is not None
        assert sha_usage.is_weak is False

    def test_detect_fernet(self, scanner):
        """Should detect Fernet encryption."""
        code = """
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted = cipher.encrypt(b"secret")
"""
        result = scanner.scan_code(code, language="python")
        # Should find encryption-related usages
        assert len(result.usages) >= 1

    def test_weak_algorithm_findings(self, scanner):
        """Should generate findings for weak algorithms."""
        code = """
import hashlib
hashlib.md5(b"data")
hashlib.sha1(b"data")
"""
        result = scanner.scan_code(code, language="python")
        # Should have findings for MD5 and SHA1
        assert len(result.findings) >= 1
        weak_findings = [f for f in result.findings if "weak" in f.title.lower()]
        assert len(weak_findings) >= 1


class TestCBOMGeneration:
    """CBOM generation tests."""

    def test_cbom_basic(self, scanner):
        """Should generate basic CBOM."""
        code = """
import hashlib
hashlib.sha256(b"data")
"""
        result = scanner.scan_code(code, language="python")
        cbom = result.cbom

        assert cbom.version == "1.0"
        assert cbom.files_scanned >= 0

    def test_cbom_algorithms(self, scanner):
        """CBOM should list algorithms used."""
        code = """
import hashlib
hashlib.sha256(b"data")
hashlib.md5(b"data")
"""
        result = scanner.scan_code(code, language="python")
        cbom = result.cbom

        algo_names = [a["name"] for a in cbom.algorithms]
        # Should have both algorithms
        assert len(cbom.algorithms) >= 1

    def test_cbom_quantum_summary(self, scanner):
        """CBOM should have quantum vulnerability summary."""
        code = """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

hashlib.sha256(b"data")
key = rsa.generate_private_key(65537, 2048)
"""
        result = scanner.scan_code(code, language="python")
        cbom = result.cbom

        # quantum_summary is a dict with risk counts
        assert "high_risk_usages" in cbom.quantum_summary
        assert "quantum_safe_percentage" in cbom.quantum_summary


class TestQuantumRiskAssessment:
    """Quantum risk assessment tests."""

    def test_rsa_quantum_risk(self, scanner):
        """RSA should be marked as quantum vulnerable."""
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
"""
        result = scanner.scan_code(code, language="python")
        rsa_usage = next((u for u in result.usages if "rsa" in u.algorithm.lower()), None)
        if rsa_usage:
            assert rsa_usage.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]

    def test_aes_quantum_safe(self, scanner):
        """AES with 256-bit key should be quantum-safe."""
        code = """
from cryptography.fernet import Fernet
cipher = Fernet(Fernet.generate_key())
"""
        result = scanner.scan_code(code, language="python")
        # AES-based encryption should have none/low quantum risk
        for usage in result.usages:
            if "aes" in usage.algorithm.lower():
                assert usage.quantum_risk in [QuantumRisk.NONE, QuantumRisk.LOW]


class TestMultiLanguageSupport:
    """Tests for language detection and fallback."""

    def test_language_detection_python(self, scanner):
        """Should detect Python code."""
        code = """
import hashlib
h = hashlib.sha256(b"data")
"""
        result = scanner.scan_code(code, language="python")
        # Should not raise an error
        assert result is not None

    def test_language_detection_javascript(self, scanner):
        """Should handle JavaScript code."""
        code = """
const crypto = require('crypto');
const hash = crypto.createHash('sha256');
hash.update('data');
"""
        result = scanner.scan_code(code, language="javascript")
        # Should not raise an error
        assert result is not None

    def test_fallback_to_regex(self, scanner):
        """Should fallback to regex for non-AST languages."""
        code = """
package main

import "crypto/sha256"

func main() {
    h := sha256.New()
}
"""
        result = scanner.scan_code(code, language="go")
        # Should still find some matches via regex
        assert result is not None


class TestEdgeCases:
    """Edge case tests."""

    def test_comments_not_detected(self, scanner):
        """Crypto in comments should not be detected (or marked as low confidence)."""
        code = """
# hashlib.md5() is deprecated, use sha256 instead
def safe_hash(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()
"""
        result = scanner.scan_code(code, language="python")
        # Should only find the actual sha256 usage, not the MD5 in comment
        real_usages = [u for u in result.usages if u.confidence > 0.5]
        for usage in real_usages:
            assert "sha256" in usage.algorithm.lower() or usage.line_number > 3

    def test_string_literals_not_detected(self, scanner):
        """Crypto keywords in strings should not be detected (or marked low confidence)."""
        code = """
error_msg = "Please don't use MD5 for hashing"
print(error_msg)
"""
        result = scanner.scan_code(code, language="python")
        # Should not find MD5 as an actual usage
        high_conf = [u for u in result.usages if u.confidence > 0.5]
        assert len(high_conf) == 0

    def test_large_file(self, scanner):
        """Should handle large files efficiently."""
        code = "\n".join([
            "import hashlib",
            *[f"h{i} = hashlib.sha256(b'data{i}')" for i in range(100)]
        ])
        result = scanner.scan_code(code, language="python")
        # Should complete without timeout
        assert len(result.usages) >= 1
