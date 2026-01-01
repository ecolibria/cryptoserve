"""Tests for PQC Recommendations service."""

import pytest
from app.core.pqc_recommendations import (
    pqc_recommendation_service,
    PQCRecommendationService,
    DataProfile,
    ThreatUrgency,
    PQC_ALGORITHMS,
    DATA_PROFILES,
)
from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    DetectedAlgorithm,
    InventorySource,
    QuantumRisk,
)


@pytest.fixture
def vulnerable_inventory():
    """Create an inventory with quantum-vulnerable libraries."""
    libraries = [
        DetectedLibrary(
            name="cryptography",
            version="41.0.0",
            category="general",
            algorithms=["AES", "RSA", "ECDSA", "SHA-256"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
        DetectedLibrary(
            name="pyjwt",
            version="2.8.0",
            category="token",
            algorithms=["RS256", "ES256", "HS256"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
    ]

    algorithms = [
        DetectedAlgorithm(
            name="RSA",
            category="asymmetric",
            library="cryptography",
            quantum_risk=QuantumRisk.HIGH,
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        ),
        DetectedAlgorithm(
            name="ECDSA",
            category="asymmetric",
            library="cryptography",
            quantum_risk=QuantumRisk.HIGH,
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        ),
    ]

    return CryptoInventory(
        identity_id="vulnerable-app",
        identity_name="Vulnerable App",
        scan_timestamp="2024-01-15T10:30:00Z",
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary={
            "total_libraries": 2,
            "quantum_safe": 0,
            "quantum_vulnerable": 2,
            "has_pqc": False,
        },
        risk_summary={
            "deprecated_libraries": 0,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )


@pytest.fixture
def deprecated_inventory():
    """Create an inventory with deprecated libraries."""
    libraries = [
        DetectedLibrary(
            name="pycrypto",
            version="2.6.1",
            category="general",
            algorithms=["AES", "DES", "RSA"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=True,
            deprecation_reason="Unmaintained since 2013",
            recommendation="Migrate to pycryptodome",
        ),
    ]

    return CryptoInventory(
        identity_id="deprecated-app",
        identity_name="Deprecated App",
        scan_timestamp="2024-01-15T10:30:00Z",
        libraries=libraries,
        algorithms=[],
        secrets_detected=[],
        quantum_summary={
            "total_libraries": 1,
            "quantum_safe": 0,
            "quantum_vulnerable": 1,
            "has_pqc": False,
        },
        risk_summary={
            "deprecated_libraries": 1,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )


@pytest.fixture
def pqc_ready_inventory():
    """Create an inventory with PQC libraries."""
    libraries = [
        DetectedLibrary(
            name="liboqs",
            version="0.9.0",
            category="pqc",
            algorithms=["Kyber", "Dilithium"],
            quantum_risk=QuantumRisk.NONE,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
        DetectedLibrary(
            name="bcrypt",
            version="4.0.1",
            category="kdf",
            algorithms=["bcrypt"],
            quantum_risk=QuantumRisk.NONE,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
    ]

    return CryptoInventory(
        identity_id="pqc-ready-app",
        identity_name="PQC Ready App",
        scan_timestamp="2024-01-15T10:30:00Z",
        libraries=libraries,
        algorithms=[],
        secrets_detected=[],
        quantum_summary={
            "total_libraries": 2,
            "quantum_safe": 2,
            "quantum_vulnerable": 0,
            "has_pqc": True,
        },
        risk_summary={
            "deprecated_libraries": 0,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )


class TestSNDLAssessment:
    """Tests for SNDL (Store Now, Decrypt Later) assessment."""

    def test_sndl_critical_for_healthcare(self, vulnerable_inventory):
        """Test SNDL assessment for healthcare data (100-year lifespan)."""
        result = pqc_recommendation_service.recommend(
            vulnerable_inventory,
            data_profile=DataProfile.HEALTHCARE_RECORDS,
        )

        sndl = result.sndl_assessment
        assert sndl.is_at_risk is True
        assert sndl.urgency == ThreatUrgency.CRITICAL
        assert sndl.years_margin < 0  # Already overdue
        assert "CRITICAL" in sndl.risk_explanation

    def test_sndl_critical_for_national_security(self, vulnerable_inventory):
        """Test SNDL assessment for national security data."""
        result = pqc_recommendation_service.recommend(
            vulnerable_inventory,
            data_profile=DataProfile.NATIONAL_SECURITY,
        )

        assert result.sndl_assessment.is_at_risk is True
        assert result.sndl_assessment.urgency == ThreatUrgency.CRITICAL

    def test_sndl_low_for_ephemeral(self, vulnerable_inventory):
        """Test SNDL assessment for ephemeral data."""
        result = pqc_recommendation_service.recommend(
            vulnerable_inventory,
            data_profile=DataProfile.EPHEMERAL_COMMUNICATIONS,
        )

        sndl = result.sndl_assessment
        # Ephemeral data has 1-year lifespan, so should be safe
        assert sndl.years_margin > 0
        assert sndl.urgency in [ThreatUrgency.LOW, ThreatUrgency.MEDIUM]

    def test_sndl_default_profile(self, vulnerable_inventory):
        """Test SNDL uses default profile when not specified."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        # Should use inferred profile
        assert result.sndl_assessment is not None
        assert result.sndl_assessment.urgency is not None

    def test_sndl_immediate_for_deprecated(self, deprecated_inventory):
        """Test deprecated libraries trigger immediate urgency."""
        result = pqc_recommendation_service.recommend(deprecated_inventory)

        assert result.sndl_assessment.urgency == ThreatUrgency.CRITICAL
        assert result.overall_urgency == ThreatUrgency.CRITICAL


class TestKEMRecommendations:
    """Tests for KEM algorithm recommendations."""

    def test_kem_recommendations_for_asymmetric(self, vulnerable_inventory):
        """Test KEM recommendations when asymmetric crypto is detected."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert len(result.kem_recommendations) > 0

        # ML-KEM-768 should be top recommendation
        top_kem = result.kem_recommendations[0]
        assert top_kem.algorithm_id == "ml-kem-768"
        assert top_kem.fips == "FIPS 203"
        assert top_kem.security_level == 3
        assert top_kem.type == "kem"
        assert top_kem.score > 0

    def test_kem_recommendations_include_hybrid(self, vulnerable_inventory):
        """Test KEM recommendations include hybrid options."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        top_kem = result.kem_recommendations[0]
        assert top_kem.hybrid_option is not None
        assert "Kyber" in top_kem.hybrid_option

    def test_kem_recommendations_have_reasons(self, vulnerable_inventory):
        """Test KEM recommendations include reasons."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        top_kem = result.kem_recommendations[0]
        assert len(top_kem.reasons) > 0
        assert any("NIST" in r or "standardized" in r for r in top_kem.reasons)

    def test_no_kem_for_symmetric_only(self):
        """Test no KEM recommendations for symmetric-only crypto."""
        libraries = [
            DetectedLibrary(
                name="bcrypt",
                version="4.0.1",
                category="kdf",
                algorithms=["bcrypt"],
                quantum_risk=QuantumRisk.NONE,
                source=InventorySource.IMPORT_SCAN,
                is_deprecated=False,
            ),
        ]

        inventory = CryptoInventory(
            identity_id="symmetric-only",
            identity_name="Symmetric Only",
            scan_timestamp="2024-01-15T10:30:00Z",
            libraries=libraries,
            algorithms=[],
            secrets_detected=[],
            quantum_summary={"total_libraries": 1, "quantum_safe": 1, "quantum_vulnerable": 0, "has_pqc": False},
            risk_summary={"deprecated_libraries": 0, "weak_algorithms": 0},
            source=InventorySource.IMPORT_SCAN,
        )

        result = pqc_recommendation_service.recommend(inventory)
        assert len(result.kem_recommendations) == 0


class TestSignatureRecommendations:
    """Tests for signature algorithm recommendations."""

    def test_signature_recommendations_for_tokens(self, vulnerable_inventory):
        """Test signature recommendations when JWT/tokens are detected."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert len(result.signature_recommendations) > 0

        # ML-DSA-65 should be top recommendation
        top_sig = result.signature_recommendations[0]
        assert top_sig.algorithm_id == "ml-dsa-65"
        assert top_sig.fips == "FIPS 204"
        assert top_sig.security_level == 3
        assert top_sig.type == "signature"

    def test_signature_recommendations_sorted_by_score(self, vulnerable_inventory):
        """Test signature recommendations are sorted by score."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        scores = [r.score for r in result.signature_recommendations]
        assert scores == sorted(scores, reverse=True)


class TestMigrationPlan:
    """Tests for migration plan generation."""

    def test_migration_plan_generated(self, vulnerable_inventory):
        """Test migration plan is generated."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert len(result.migration_plan) > 0

    def test_migration_plan_ordered(self, vulnerable_inventory):
        """Test migration plan steps are ordered."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        orders = [step.order for step in result.migration_plan]
        assert orders == sorted(orders)

    def test_deprecated_first_in_migration(self, deprecated_inventory):
        """Test deprecated library replacement is first step."""
        result = pqc_recommendation_service.recommend(deprecated_inventory)

        first_step = result.migration_plan[0]
        assert "deprecated" in first_step.action.lower()
        assert first_step.priority == "critical"
        assert "pycrypto" in first_step.affected_libraries

    def test_hybrid_deployment_step(self, vulnerable_inventory):
        """Test migration plan includes hybrid deployment."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        hybrid_steps = [s for s in result.migration_plan if "hybrid" in s.action.lower()]
        assert len(hybrid_steps) > 0

    def test_migration_plan_complete_steps(self, vulnerable_inventory):
        """Test migration plan ends with full PQC migration."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        last_step = result.migration_plan[-1]
        assert "complete" in last_step.action.lower() or "pqc" in last_step.action.lower()


class TestOverallUrgency:
    """Tests for overall urgency calculation."""

    def test_critical_urgency_for_deprecated(self, deprecated_inventory):
        """Test deprecated libraries result in critical urgency."""
        result = pqc_recommendation_service.recommend(deprecated_inventory)

        assert result.overall_urgency == ThreatUrgency.CRITICAL

    def test_lower_urgency_for_pqc_ready(self, pqc_ready_inventory):
        """Test PQC-ready apps have lower urgency."""
        result = pqc_recommendation_service.recommend(pqc_ready_inventory)

        assert result.overall_urgency in [ThreatUrgency.LOW, ThreatUrgency.MONITORING]


class TestQuantumReadinessScore:
    """Tests for quantum readiness score calculation."""

    def test_low_score_for_vulnerable(self, vulnerable_inventory):
        """Test vulnerable inventory has low quantum readiness score."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert result.quantum_readiness_score < 50

    def test_high_score_for_pqc_ready(self, pqc_ready_inventory):
        """Test PQC-ready inventory has high score."""
        result = pqc_recommendation_service.recommend(pqc_ready_inventory)

        assert result.quantum_readiness_score >= 80


class TestKeyFindings:
    """Tests for key findings generation."""

    def test_findings_include_vulnerable_count(self, vulnerable_inventory):
        """Test findings mention vulnerable libraries."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert any("vulnerable" in f.lower() for f in result.key_findings)

    def test_findings_include_deprecated(self, deprecated_inventory):
        """Test findings mention deprecated libraries."""
        result = pqc_recommendation_service.recommend(deprecated_inventory)

        assert any("deprecated" in f.lower() for f in result.key_findings)

    def test_findings_include_pqc_status(self, pqc_ready_inventory):
        """Test findings mention PQC status."""
        result = pqc_recommendation_service.recommend(pqc_ready_inventory)

        assert any("post-quantum" in f.lower() or "pqc" in f.lower() for f in result.key_findings)


class TestNextSteps:
    """Tests for next steps generation."""

    def test_next_steps_generated(self, vulnerable_inventory):
        """Test next steps are generated."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        assert len(result.next_steps) > 0

    def test_next_steps_actionable(self, vulnerable_inventory):
        """Test next steps are actionable."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        # Should contain actionable language
        action_words = ["deploy", "begin", "plan", "evaluate", "include", "monitor", "priority", "train"]
        for step in result.next_steps:
            assert any(word in step.lower() for word in action_words), f"Step not actionable: {step}"


class TestDataProfiles:
    """Tests for data profile configurations."""

    def test_all_profiles_have_config(self):
        """Test all DataProfile enum values have configurations."""
        for profile in DataProfile:
            assert profile in DATA_PROFILES
            config = DATA_PROFILES[profile]
            assert "name" in config
            assert "lifespan_years" in config
            assert "urgency" in config

    def test_profiles_ordered_by_lifespan(self):
        """Test profiles are roughly ordered by lifespan."""
        healthcare = DATA_PROFILES[DataProfile.HEALTHCARE_RECORDS]["lifespan_years"]
        national = DATA_PROFILES[DataProfile.NATIONAL_SECURITY]["lifespan_years"]
        ephemeral = DATA_PROFILES[DataProfile.EPHEMERAL_COMMUNICATIONS]["lifespan_years"]

        assert healthcare >= national
        assert national > ephemeral


class TestPQCAlgorithmsCatalog:
    """Tests for PQC algorithms catalog."""

    def test_kem_algorithms_defined(self):
        """Test KEM algorithms are defined."""
        assert "kem" in PQC_ALGORITHMS
        assert len(PQC_ALGORITHMS["kem"]) > 0

    def test_signature_algorithms_defined(self):
        """Test signature algorithms are defined."""
        assert "signature" in PQC_ALGORITHMS
        assert len(PQC_ALGORITHMS["signature"]) > 0

    def test_algorithms_have_fips(self):
        """Test NIST-standardized algorithms have FIPS numbers."""
        for algo in PQC_ALGORITHMS["kem"]:
            if algo.get("status") == "standardized":
                assert algo.get("fips") is not None

        for algo in PQC_ALGORITHMS["signature"]:
            if algo.get("status") == "standardized":
                assert algo.get("fips") is not None

    def test_ml_kem_768_is_default(self):
        """Test ML-KEM-768 is in the KEM list."""
        kem_ids = [a["id"] for a in PQC_ALGORITHMS["kem"]]
        assert "ml-kem-768" in kem_ids

    def test_ml_dsa_65_is_default(self):
        """Test ML-DSA-65 is in the signature list."""
        sig_ids = [a["id"] for a in PQC_ALGORITHMS["signature"]]
        assert "ml-dsa-65" in sig_ids


class TestServiceConfiguration:
    """Tests for service configuration."""

    def test_default_timeline_values(self):
        """Test default timeline values are reasonable."""
        service = PQCRecommendationService()

        assert service.migration_timeline_years > 0
        assert service.quantum_threat_years > 0
        assert service.quantum_threat_years > service.migration_timeline_years

    def test_custom_timeline_values(self):
        """Test custom timeline values can be set."""
        service = PQCRecommendationService(
            migration_timeline_years=5,
            quantum_threat_years=10,
        )

        assert service.migration_timeline_years == 5
        assert service.quantum_threat_years == 10


class TestResultSerialization:
    """Tests for result serialization."""

    def test_result_to_dict(self, vulnerable_inventory):
        """Test result can be converted to dict."""
        result = pqc_recommendation_service.recommend(vulnerable_inventory)

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert "sndl_assessment" in result_dict
        assert "kem_recommendations" in result_dict
        assert "migration_plan" in result_dict

    def test_result_dict_serializable(self, vulnerable_inventory):
        """Test result dict is JSON serializable."""
        import json

        result = pqc_recommendation_service.recommend(vulnerable_inventory)
        result_dict = result.to_dict()

        # Should not raise
        json_str = json.dumps(result_dict)
        assert len(json_str) > 0
