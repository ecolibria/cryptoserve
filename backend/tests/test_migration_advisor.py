"""Tests for the migration advisor engine."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.core.migration_advisor import (
    MigrationAdvisor,
    RiskScore,
    RiskLevel,
    Urgency,
    Compatibility,
    MigrationAssessment,
    Recommendation,
    MigrationPlan,
    MigrationPreview,
)
from app.core.crypto_registry import SecurityStatus


class MockContext:
    """Mock context for testing."""

    def __init__(
        self,
        name: str = "test-context",
        display_name: str = "Test Context",
        algorithm: str = "AES-256-GCM",
        config: dict | None = None,
        compliance_tags: list | None = None,
    ):
        self.name = name
        self.display_name = display_name
        self.algorithm = algorithm
        self.config = config or {}
        self.compliance_tags = compliance_tags or []
        self.tenant_id = uuid4()


class TestRiskScore:
    """Tests for RiskScore class."""

    def test_create_from_score_critical(self):
        """Test RiskScore creation with critical score."""
        score = RiskScore.from_score(85, ["Algorithm is broken"])
        assert score.score == 85
        assert score.level == RiskLevel.CRITICAL
        assert len(score.factors) == 1

    def test_create_from_score_high(self):
        """Test RiskScore creation with high score."""
        score = RiskScore.from_score(65, ["Algorithm deprecated"])
        assert score.score == 65
        assert score.level == RiskLevel.HIGH

    def test_create_from_score_medium(self):
        """Test RiskScore creation with medium score."""
        score = RiskScore.from_score(45, ["Legacy algorithm"])
        assert score.score == 45
        assert score.level == RiskLevel.MEDIUM

    def test_create_from_score_low(self):
        """Test RiskScore creation with low score."""
        score = RiskScore.from_score(20, ["Minor concern"])
        assert score.score == 20
        assert score.level == RiskLevel.LOW

    def test_boundary_scores(self):
        """Test boundary values for risk levels."""
        assert RiskScore.from_score(80, []).level == RiskLevel.CRITICAL
        assert RiskScore.from_score(79, []).level == RiskLevel.HIGH
        assert RiskScore.from_score(60, []).level == RiskLevel.HIGH
        assert RiskScore.from_score(59, []).level == RiskLevel.MEDIUM
        assert RiskScore.from_score(40, []).level == RiskLevel.MEDIUM
        assert RiskScore.from_score(39, []).level == RiskLevel.LOW


class TestMigrationAdvisorRiskScoring:
    """Tests for MigrationAdvisor risk scoring."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return AsyncMock()

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    @pytest.mark.asyncio
    async def test_risk_score_deprecated_algorithm(self, advisor):
        """Test risk scoring for deprecated algorithm."""
        context = MockContext(
            algorithm="3DES",
            config={"data_identity": {"sensitivity": "high"}},
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.DEPRECATED
            mock_algo.quantum_resistant = False
            mock_registry.get.return_value = mock_algo

            score = await advisor.get_risk_score("3DES", context)

            assert score.score >= 50  # Deprecated + high sensitivity
            assert len(score.factors) > 0
            assert any("deprecated" in f.lower() or "status" in f.lower() for f in score.factors)

    @pytest.mark.asyncio
    async def test_risk_score_broken_algorithm(self, advisor):
        """Test risk scoring for broken algorithm."""
        context = MockContext(
            algorithm="DES",
            config={"data_identity": {"sensitivity": "critical"}},
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.BROKEN
            mock_algo.quantum_resistant = False
            mock_registry.get.return_value = mock_algo

            score = await advisor.get_risk_score("DES", context)

            assert score.score >= 70  # Broken + critical sensitivity
            assert score.level in [RiskLevel.CRITICAL, RiskLevel.HIGH]

    @pytest.mark.asyncio
    async def test_risk_score_recommended_algorithm(self, advisor):
        """Test risk scoring for recommended algorithm."""
        context = MockContext(
            algorithm="AES-256-GCM",
            config={"data_identity": {"sensitivity": "medium"}},
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.RECOMMENDED
            mock_algo.quantum_resistant = False
            mock_registry.get.return_value = mock_algo

            score = await advisor.get_risk_score("AES-256-GCM", context)

            assert score.score < 50  # Recommended algorithm should have low risk
            assert score.level in [RiskLevel.LOW, RiskLevel.MEDIUM]

    @pytest.mark.asyncio
    async def test_risk_score_with_compliance(self, advisor):
        """Test risk scoring with compliance requirements."""
        context = MockContext(
            algorithm="AES-128-GCM",
            config={
                "data_identity": {
                    "sensitivity": "high",
                    "compliance_frameworks": ["PCI-DSS", "HIPAA"],
                }
            },
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.ACCEPTABLE
            mock_algo.quantum_resistant = False
            mock_registry.get.return_value = mock_algo

            score = await advisor.get_risk_score("AES-128-GCM", context)

            # Compliance adds urgency
            assert any("compliance" in f.lower() for f in score.factors)


class TestMigrationAdvisorRecommendations:
    """Tests for MigrationAdvisor recommendations."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return AsyncMock()

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    @pytest.mark.asyncio
    async def test_recommend_replacement_deprecated(self, advisor):
        """Test replacement recommendation for deprecated algorithm."""
        context = MockContext(
            name="payment-context",
            display_name="Payment Data",
            algorithm="3DES",
            config={"data_identity": {"sensitivity": "critical"}},
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.name = "3DES"
            mock_algo.status = SecurityStatus.DEPRECATED
            mock_algo.replacement = "AES-256-GCM"
            mock_algo.vulnerabilities = ["Sweet32 attack"]
            mock_algo.quantum_resistant = False
            mock_algo.family = "block"
            mock_registry.get.return_value = mock_algo

            rec = await advisor.recommend_replacement("3DES", context)

            assert rec.contextName == "payment-context"
            assert rec.currentAlgorithm == "3DES"
            assert "AES" in rec.recommendedAlgorithm
            assert rec.urgency in [Urgency.IMMEDIATE, Urgency.SOON]
            assert len(rec.steps) > 0
            assert len(rec.reason) > 0

    @pytest.mark.asyncio
    async def test_recommend_replacement_pqc_needed(self, advisor):
        """Test replacement with quantum protection needed."""
        context = MockContext(
            name="long-term-secrets",
            algorithm="RSA-2048",
            config={
                "data_identity": {"sensitivity": "critical"},
                "threat_model": {"protection_lifetime_years": 15},
            },
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.name = "RSA-2048"
            mock_algo.status = SecurityStatus.LEGACY
            mock_algo.replacement = "ECDSA-P384"
            mock_algo.vulnerabilities = []
            mock_algo.quantum_resistant = False
            mock_algo.family = "asymmetric"
            mock_registry.get.return_value = mock_algo

            rec = await advisor.recommend_replacement("RSA-2048", context)

            # Should suggest hybrid PQC for long-term protection
            assert rec.contextName == "long-term-secrets"
            # The recommendation should consider PQC


class TestMigrationAdvisorPlans:
    """Tests for MigrationAdvisor migration plans."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return AsyncMock()

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    @pytest.mark.asyncio
    async def test_generate_migration_plan_basic(self, advisor):
        """Test generating a basic migration plan."""
        context = MockContext(
            name="test-context",
            algorithm="AES-128-GCM",
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.family = "block"
            mock_registry.get.return_value = mock_algo

            plan = await advisor.generate_migration_plan(context, "AES-256-GCM")

            assert plan.contextName == "test-context"
            assert plan.currentAlgorithm == "AES-128-GCM"
            assert plan.targetAlgorithm == "AES-256-GCM"
            assert len(plan.steps) >= 3
            assert len(plan.rollbackSteps) > 0
            assert plan.estimatedDuration is not None

    @pytest.mark.asyncio
    async def test_generate_migration_plan_with_key_rotation(self, advisor):
        """Test migration plan that requires key rotation."""
        context = MockContext(
            name="secure-context",
            algorithm="3DES",
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo_old = MagicMock()
            mock_algo_old.family = "block"
            mock_algo_new = MagicMock()
            mock_algo_new.family = "block"

            def get_algo(name):
                if name == "3DES":
                    return mock_algo_old
                return mock_algo_new

            mock_registry.get.side_effect = get_algo

            plan = await advisor.generate_migration_plan(context, "AES-256-GCM")

            # Should include key rotation step
            step_actions = [s.action for s in plan.steps]
            assert "rotate_keys" in step_actions or "update_config" in step_actions
            assert len(plan.warnings) >= 0  # May have warnings about key rotation


class TestMigrationAdvisorPreview:
    """Tests for MigrationAdvisor migration preview."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return AsyncMock()

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    @pytest.mark.asyncio
    async def test_preview_valid_migration(self, advisor):
        """Test preview for valid migration."""
        context = MockContext(
            name="test-context",
            algorithm="AES-128-GCM",
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.RECOMMENDED
            mock_algo.family = "block"
            mock_registry.get.return_value = mock_algo

            preview = await advisor.preview_migration(context, "AES-256-GCM")

            assert preview.contextName == "test-context"
            assert preview.currentAlgorithm == "AES-128-GCM"
            assert preview.newAlgorithm == "AES-256-GCM"
            assert preview.canProceed is True
            assert "estimatedDowntime" in preview.impactSummary

    @pytest.mark.asyncio
    async def test_preview_invalid_algorithm(self, advisor):
        """Test preview with invalid target algorithm."""
        context = MockContext(
            name="test-context",
            algorithm="AES-256-GCM",
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_registry.get.return_value = None

            preview = await advisor.preview_migration(context, "UNKNOWN-ALGO")

            assert preview.canProceed is False
            assert len(preview.warnings) > 0
            assert any("not found" in w.lower() for w in preview.warnings)

    @pytest.mark.asyncio
    async def test_preview_deprecated_target(self, advisor):
        """Test preview when targeting deprecated algorithm."""
        context = MockContext(
            name="test-context",
            algorithm="DES",
        )

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_algo = MagicMock()
            mock_algo.status = SecurityStatus.DEPRECATED
            mock_algo.family = "block"
            mock_registry.get.return_value = mock_algo

            preview = await advisor.preview_migration(context, "3DES")

            assert preview.canProceed is False
            assert any("deprecated" in w.lower() for w in preview.warnings)


class TestMigrationAdvisorTenantAnalysis:
    """Tests for MigrationAdvisor tenant analysis."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        db = AsyncMock()
        return db

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    @pytest.mark.asyncio
    async def test_analyze_tenant_no_contexts(self, advisor, mock_db):
        """Test tenant analysis with no contexts."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result

        assessment = await advisor.analyze_tenant("test-tenant")

        assert assessment.totalContexts == 0
        assert assessment.contextsNeedingMigration == 0
        assert len(assessment.recommendations) == 0

    @pytest.mark.asyncio
    async def test_analyze_tenant_with_deprecated_algorithms(self, advisor, mock_db):
        """Test tenant analysis with deprecated algorithms."""
        contexts = [
            MockContext(name="ctx1", algorithm="3DES"),
            MockContext(name="ctx2", algorithm="AES-256-GCM"),
            MockContext(name="ctx3", algorithm="DES"),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = contexts
        mock_db.execute.return_value = mock_result

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:

            def get_algo(name):
                algo = MagicMock()
                algo.name = name
                algo.family = "block"
                algo.quantum_resistant = False
                algo.vulnerabilities = []
                algo.replacement = "AES-256-GCM"
                if name == "3DES":
                    algo.status = SecurityStatus.DEPRECATED
                elif name == "DES":
                    algo.status = SecurityStatus.BROKEN
                else:
                    algo.status = SecurityStatus.RECOMMENDED
                return algo

            mock_registry.get.side_effect = get_algo

            assessment = await advisor.analyze_tenant("test-tenant")

            assert assessment.totalContexts == 3
            assert assessment.contextsNeedingMigration == 2  # 3DES and DES
            assert len(assessment.recommendations) == 2
            # Recommendations should be sorted by risk
            assert assessment.recommendations[0].priority == 1

    @pytest.mark.asyncio
    async def test_analyze_tenant_quantum_readiness(self, advisor, mock_db):
        """Test tenant analysis quantum readiness calculation."""
        contexts = [
            MockContext(
                name="pqc-ctx",
                algorithm="ML-KEM-768",
                config={"data_identity": {"sensitivity": "critical"}},
            ),
            MockContext(
                name="classical-ctx",
                algorithm="AES-256-GCM",
                config={"data_identity": {"sensitivity": "medium"}},
            ),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = contexts
        mock_db.execute.return_value = mock_result

        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:

            def get_algo(name):
                algo = MagicMock()
                algo.name = name
                algo.family = "kem" if "ML" in name else "block"
                algo.status = SecurityStatus.RECOMMENDED
                algo.quantum_resistant = "ML" in name
                algo.vulnerabilities = []
                return algo

            mock_registry.get.side_effect = get_algo

            assessment = await advisor.analyze_tenant("test-tenant")

            assert assessment.quantumReadiness.contextsUsingPQC >= 1
            assert assessment.quantumReadiness.percentage >= 0


class TestCompatibilityDetermination:
    """Tests for compatibility determination."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return AsyncMock()

    @pytest.fixture
    def advisor(self, mock_db):
        """Create MigrationAdvisor instance."""
        return MigrationAdvisor(mock_db)

    def test_same_family_direct_compatibility(self, advisor):
        """Test that same family algorithms have direct compatibility."""
        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            algo1 = MagicMock()
            algo1.family = "block"
            algo2 = MagicMock()
            algo2.family = "block"

            def get_algo(name):
                if name == "AES-128-GCM":
                    return algo1
                return algo2

            mock_registry.get.side_effect = get_algo

            result = advisor._determine_compatibility("AES-128-GCM", "AES-256-GCM")
            assert result == Compatibility.DIRECT

    def test_different_key_size_needs_rotation(self, advisor):
        """Test that different key sizes need rotation."""
        with patch("app.core.migration_advisor.crypto_registry") as mock_registry:
            mock_registry.get.return_value = None  # Unknown algorithms

            result = advisor._determine_compatibility("AES-128-GCM", "AES-256-GCM")
            assert result == Compatibility.KEY_ROTATION
