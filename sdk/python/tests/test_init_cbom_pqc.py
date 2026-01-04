"""Integration tests for SDK initialization, CBOM, and PQC recommendations.

These tests verify:
- init() function and crypto library scanning
- InitResult class and properties
- export_cbom() function and CBOMResult class
- get_pqc_recommendations() function and PQCRecommendationResult class
"""

import pytest
from unittest.mock import MagicMock, patch
import sys


class TestInit:
    """Tests for init() function and crypto library scanning."""

    def test_init_default(self, mock_identity):
        """Test default initialization."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            with patch("cryptoserve._initialized", False):
                with patch("cryptoserve._init_config", {}):
                    # Reset module state
                    import cryptoserve
                    cryptoserve._initialized = False
                    cryptoserve._init_config = {}

                    result = cryptoserve.init()

                    assert result.success is True
                    assert isinstance(result.libraries, list)
                    assert result.action in ["allow", "warn", "block"]

    def test_init_detects_hashlib(self, mock_identity):
        """Test that init detects hashlib if imported."""
        # Ensure hashlib is imported
        import hashlib  # noqa: F401

        with patch("cryptoserve.IDENTITY", mock_identity):
            # Reset module state
            import cryptoserve
            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            result = cryptoserve.init(report_to_platform=False)

            # hashlib should be detected
            lib_names = [lib["name"] for lib in result.libraries]
            assert "hashlib" in lib_names

    def test_init_returns_cached_result(self, mock_identity):
        """Test that subsequent init calls return cached result."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve
            cryptoserve._initialized = True
            cryptoserve._init_config = {
                "libraries": [{"name": "test-lib"}],
                "violations": [],
                "warnings": [],
                "action": "allow",
            }

            result = cryptoserve.init()

            assert result.success is True
            assert len(result.libraries) == 1
            assert result.libraries[0]["name"] == "test-lib"

    def test_init_with_blocking(self, mock_identity):
        """Test init with block_on_violations=True."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve
            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            # Should not raise with allow action
            result = cryptoserve.init(
                block_on_violations=True,
                report_to_platform=False
            )

            assert result.success is True


class TestInitResult:
    """Tests for InitResult class."""

    def test_init_result_properties(self):
        """Test InitResult properties."""
        from cryptoserve import InitResult

        result = InitResult(
            success=True,
            libraries=[
                {"name": "cryptography", "algorithms": ["AES", "RSA"], "quantum_risk": "high"},
                {"name": "hashlib", "algorithms": ["SHA-256"], "quantum_risk": "low"},
            ],
            violations=[{"rule": "no-deprecated"}],
            warnings=[{"message": "Consider PQC migration"}],
            action="warn",
        )

        assert result.success is True
        assert len(result.libraries) == 2
        assert len(result.violations) == 1
        assert len(result.warnings) == 1
        assert result.action == "warn"

    def test_init_result_algorithms_property(self):
        """Test algorithms aggregation property."""
        from cryptoserve import InitResult

        result = InitResult(
            success=True,
            libraries=[
                {"name": "lib1", "algorithms": ["AES", "RSA"]},
                {"name": "lib2", "algorithms": ["RSA", "SHA-256"]},
            ],
        )

        algos = result.algorithms
        assert "AES" in algos
        assert "RSA" in algos
        assert "SHA-256" in algos
        # Should deduplicate
        assert len([a for a in algos if a == "RSA"]) == 1

    def test_init_result_quantum_vulnerable_property(self):
        """Test quantum_vulnerable property."""
        from cryptoserve import InitResult

        result = InitResult(
            success=True,
            libraries=[
                {"name": "cryptography", "quantum_risk": "high"},
                {"name": "hashlib", "quantum_risk": "low"},
                {"name": "oqs", "quantum_risk": "none"},
            ],
        )

        vulnerable = result.quantum_vulnerable
        assert len(vulnerable) == 1
        assert vulnerable[0]["name"] == "cryptography"

    def test_init_result_deprecated_property(self):
        """Test deprecated property."""
        from cryptoserve import InitResult

        result = InitResult(
            success=True,
            libraries=[
                {"name": "Crypto", "is_deprecated": True},
                {"name": "cryptography", "is_deprecated": False},
            ],
        )

        deprecated = result.deprecated
        assert len(deprecated) == 1
        assert deprecated[0]["name"] == "Crypto"

    def test_init_result_bool(self):
        """Test InitResult bool conversion."""
        from cryptoserve import InitResult

        # Success with allow = True
        result1 = InitResult(success=True, action="allow")
        assert bool(result1) is True

        # Success with block = False
        result2 = InitResult(success=True, action="block")
        assert bool(result2) is False

        # Failure = False
        result3 = InitResult(success=False)
        assert bool(result3) is False

    def test_init_result_repr(self):
        """Test InitResult string representation."""
        from cryptoserve import InitResult

        result = InitResult(
            success=True,
            libraries=[{"algorithms": ["AES"]}, {"algorithms": ["RSA"]}],
            action="allow",
        )

        repr_str = repr(result)
        assert "libraries=2" in repr_str
        assert "allow" in repr_str


class TestExportCBOM:
    """Tests for export_cbom() function."""

    def test_export_cbom_basic(self, mock_identity):
        """Test basic CBOM export."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            # Initialize first
            cryptoserve._initialized = True
            cryptoserve._init_config = {
                "libraries": [
                    {"name": "cryptography", "quantum_risk": "high", "algorithms": ["AES"]},
                ],
            }

            result = cryptoserve.export_cbom()

            assert result.cbom is not None
            assert "components" in result.cbom
            assert "summary" in result.cbom

    def test_export_cbom_json_format(self, mock_identity):
        """Test CBOM JSON format."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = True
            cryptoserve._init_config = {
                "libraries": [{"name": "test", "quantum_risk": "low", "algorithms": []}],
            }

            result = cryptoserve.export_cbom(format="json")

            assert result.format == "json"
            json_str = result.to_json()
            assert "components" in json_str

    def test_export_cbom_cyclonedx_format(self, mock_identity):
        """Test CBOM CycloneDX format."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = True
            cryptoserve._init_config = {
                "libraries": [{"name": "test", "quantum_risk": "low", "algorithms": []}],
            }

            result = cryptoserve.export_cbom(format="cyclonedx")

            assert result.format == "cyclonedx"


class TestCBOMResult:
    """Tests for CBOMResult class."""

    def test_cbom_result_properties(self):
        """Test CBOMResult properties."""
        from cryptoserve import CBOMResult

        result = CBOMResult(
            cbom={
                "components": [{"name": "test"}],
                "summary": {"total_libraries": 1},
            },
            format="json",
            quantum_readiness={
                "score": 75.5,
                "risk_level": "medium",
            },
        )

        assert result.score == 75.5
        assert result.risk_level == "medium"

    def test_cbom_result_to_dict(self):
        """Test CBOMResult to_dict method."""
        from cryptoserve import CBOMResult

        cbom_data = {"components": [], "summary": {}}
        qr_data = {"score": 50.0}

        result = CBOMResult(cbom=cbom_data, quantum_readiness=qr_data)

        d = result.to_dict()
        assert "cbom" in d
        assert "quantum_readiness" in d

    def test_cbom_result_repr(self):
        """Test CBOMResult string representation."""
        from cryptoserve import CBOMResult

        result = CBOMResult(
            cbom={"components": [1, 2, 3]},
            quantum_readiness={"score": 80.0, "risk_level": "low"},
        )

        repr_str = repr(result)
        assert "components=3" in repr_str
        assert "score=80" in repr_str
        assert "risk=low" in repr_str


class TestGetPQCRecommendations:
    """Tests for get_pqc_recommendations() function."""

    def test_get_pqc_recommendations_mock_mode(self, mock_identity):
        """Test PQC recommendations in mock mode."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            with patch("cryptoserve._is_mock_mode", return_value=True):
                import cryptoserve

                cryptoserve._initialized = True
                cryptoserve._init_config = {
                    "libraries": [
                        {"name": "cryptography", "quantum_risk": "high"},
                    ],
                }

                result = cryptoserve.get_pqc_recommendations()

                assert result is not None
                assert result.urgency in ["low", "medium", "high", "critical"]

    def test_get_pqc_recommendations_from_server(self, mock_identity):
        """Test PQC recommendations from server."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            with patch("cryptoserve._is_mock_mode", return_value=False):
                with patch("requests.post") as mock_post:
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        "overall_urgency": "medium",
                        "quantum_readiness_score": 45.0,
                        "sndl_assessment": {"vulnerable": True},
                        "key_findings": ["RSA in use"],
                        "next_steps": ["Migrate to ML-KEM"],
                        "kem_recommendations": [],
                        "signature_recommendations": [],
                        "migration_plan": [],
                    }
                    mock_post.return_value = mock_response

                    import cryptoserve

                    cryptoserve._initialized = True
                    cryptoserve._init_config = {
                        "libraries": [{"name": "cryptography", "quantum_risk": "high"}],
                    }

                    result = cryptoserve.get_pqc_recommendations(data_profile="financial")

                    assert result.urgency == "medium"
                    assert result.score == 45.0


class TestPQCRecommendationResult:
    """Tests for PQCRecommendationResult class."""

    def test_pqc_result_properties(self):
        """Test PQCRecommendationResult properties."""
        from cryptoserve import PQCRecommendationResult

        result = PQCRecommendationResult({
            "overall_urgency": "high",
            "quantum_readiness_score": 30.0,
            "sndl_assessment": {
                "vulnerable": True,
                "risk_level": "high",
            },
            "key_findings": ["Finding 1", "Finding 2"],
            "next_steps": ["Step 1", "Step 2"],
            "kem_recommendations": [
                {"current_algorithm": "RSA", "recommended_algorithm": "ML-KEM-768"}
            ],
            "signature_recommendations": [
                {"current_algorithm": "ECDSA", "recommended_algorithm": "ML-DSA-65"}
            ],
            "migration_plan": [
                {"priority": 1, "action": "Inventory"}
            ],
        })

        assert result.urgency == "high"
        assert result.score == 30.0
        assert result.sndl_vulnerable is True
        assert len(result.key_findings) == 2
        assert len(result.next_steps) == 2
        assert len(result.kem_recommendations) == 1
        assert len(result.signature_recommendations) == 1
        assert len(result.migration_plan) == 1

    def test_pqc_result_to_dict(self):
        """Test PQCRecommendationResult to_dict method."""
        from cryptoserve import PQCRecommendationResult

        data = {"overall_urgency": "low", "quantum_readiness_score": 90.0}
        result = PQCRecommendationResult(data)

        assert result.to_dict() == data

    def test_pqc_result_bool(self):
        """Test PQCRecommendationResult bool conversion."""
        from cryptoserve import PQCRecommendationResult

        # Non-empty data = True
        result1 = PQCRecommendationResult({"urgency": "low"})
        assert bool(result1) is True

        # Empty data = False
        result2 = PQCRecommendationResult({})
        assert bool(result2) is False

    def test_pqc_result_repr(self):
        """Test PQCRecommendationResult string representation."""
        from cryptoserve import PQCRecommendationResult

        result = PQCRecommendationResult({
            "overall_urgency": "medium",
            "quantum_readiness_score": 55.0,
        })

        repr_str = repr(result)
        assert "urgency=medium" in repr_str
        assert "score=55" in repr_str


class TestCryptoLibraryScanning:
    """Tests for crypto library scanning functionality."""

    def test_scan_detects_imported_libraries(self, mock_identity):
        """Test that scanning detects actually imported libraries."""
        # Import some crypto libraries
        import hashlib  # noqa: F401
        import hmac  # noqa: F401

        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            # Reset and rescan
            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            result = cryptoserve.init(report_to_platform=False)

            lib_names = [lib["name"] for lib in result.libraries]
            assert "hashlib" in lib_names
            assert "hmac" in lib_names

    def test_scan_includes_version_when_available(self, mock_identity):
        """Test that scanning includes version when available."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            result = cryptoserve.init(report_to_platform=False)

            # Version may or may not be available depending on library
            for lib in result.libraries:
                assert "version" in lib

    def test_scan_includes_quantum_risk(self, mock_identity):
        """Test that scanning includes quantum risk assessment."""
        import hashlib  # noqa: F401

        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            result = cryptoserve.init(report_to_platform=False)

            for lib in result.libraries:
                assert "quantum_risk" in lib
                assert lib["quantum_risk"] in ["none", "low", "medium", "high", "critical"]


class TestGetInitStatus:
    """Tests for get_init_status() function."""

    def test_get_init_status_not_initialized(self, mock_identity):
        """Test status when not initialized."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = False
            cryptoserve._init_config = {}

            status = cryptoserve.get_init_status()

            assert status["initialized"] is False

    def test_get_init_status_initialized(self, mock_identity):
        """Test status when initialized."""
        with patch("cryptoserve.IDENTITY", mock_identity):
            import cryptoserve

            cryptoserve._initialized = True
            cryptoserve._init_config = {
                "libraries": [{"name": "test"}],
                "action": "allow",
            }

            status = cryptoserve.get_init_status()

            assert status["initialized"] is True
            assert "libraries" in status["config"]
