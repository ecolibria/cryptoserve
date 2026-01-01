"""Tests for the promotion module.

Tests cover:
- Context tier lookup and display
- Tier requirements structure
- ContextReadiness model
- PromotionReadiness model
- ExpeditedRequest model
- Promotion readiness checking (async)
- Expedited request creation (async)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from app.core.promotion import (
    ContextTier,
    ExpediteePriority,
    ContextReadiness,
    PromotionReadiness,
    ExpeditedRequest,
    CONTEXT_TIERS,
    TIER_REQUIREMENTS,
    get_context_tier,
    get_tier_display,
    get_context_stats,
    check_context_readiness,
    check_promotion_readiness,
    create_expedited_request,
)


class TestContextTierLookup:
    """Tests for context tier lookup functions."""

    def test_get_context_tier_tier1_contexts(self):
        """Test Tier 1 contexts return correct tier."""
        tier1_contexts = ["session-tokens", "cache-data", "temp-data", "analytics"]
        for context in tier1_contexts:
            assert get_context_tier(context) == ContextTier.TIER_1

    def test_get_context_tier_tier2_contexts(self):
        """Test Tier 2 contexts return correct tier."""
        tier2_contexts = ["user-pii", "api-keys", "internal-data", "customer-data"]
        for context in tier2_contexts:
            assert get_context_tier(context) == ContextTier.TIER_2

    def test_get_context_tier_tier3_contexts(self):
        """Test Tier 3 contexts return correct tier."""
        tier3_contexts = ["pci", "payment-data", "health-data", "phi", "secrets", "encryption-keys"]
        for context in tier3_contexts:
            assert get_context_tier(context) == ContextTier.TIER_3

    def test_get_context_tier_unknown_defaults_to_tier2(self):
        """Test unknown contexts default to Tier 2."""
        unknown_contexts = ["unknown-context", "custom-data", "other"]
        for context in unknown_contexts:
            assert get_context_tier(context) == ContextTier.TIER_2


class TestTierDisplay:
    """Tests for tier display function."""

    def test_get_tier_display_tier1(self):
        """Test Tier 1 display name."""
        assert get_tier_display(ContextTier.TIER_1) == "Tier 1 (Low)"

    def test_get_tier_display_tier2(self):
        """Test Tier 2 display name."""
        assert get_tier_display(ContextTier.TIER_2) == "Tier 2 (Medium)"

    def test_get_tier_display_tier3(self):
        """Test Tier 3 display name."""
        assert get_tier_display(ContextTier.TIER_3) == "Tier 3 (High)"


class TestTierRequirements:
    """Tests for tier requirements structure."""

    def test_tier1_requirements(self):
        """Test Tier 1 requirements are correct."""
        reqs = TIER_REQUIREMENTS[ContextTier.TIER_1]
        assert reqs["min_operations"] == 10
        assert reqs["min_hours_in_dev"] == 1
        assert reqs["min_unique_days"] == 1
        assert reqs["requires_approval"] is False

    def test_tier2_requirements(self):
        """Test Tier 2 requirements are correct."""
        reqs = TIER_REQUIREMENTS[ContextTier.TIER_2]
        assert reqs["min_operations"] == 50
        assert reqs["min_hours_in_dev"] == 24
        assert reqs["min_unique_days"] == 2
        assert reqs["requires_approval"] is False

    def test_tier3_requirements(self):
        """Test Tier 3 requirements are correct."""
        reqs = TIER_REQUIREMENTS[ContextTier.TIER_3]
        assert reqs["min_operations"] == 100
        assert reqs["min_hours_in_dev"] == 48
        assert reqs["min_unique_days"] == 3
        assert reqs["requires_approval"] is True

    def test_tier_requirements_increase_with_sensitivity(self):
        """Test that requirements increase with tier sensitivity."""
        tier1 = TIER_REQUIREMENTS[ContextTier.TIER_1]
        tier2 = TIER_REQUIREMENTS[ContextTier.TIER_2]
        tier3 = TIER_REQUIREMENTS[ContextTier.TIER_3]

        # Operations increase
        assert tier1["min_operations"] < tier2["min_operations"] < tier3["min_operations"]
        # Hours increase
        assert tier1["min_hours_in_dev"] < tier2["min_hours_in_dev"] < tier3["min_hours_in_dev"]
        # Days increase
        assert tier1["min_unique_days"] < tier2["min_unique_days"] < tier3["min_unique_days"]


class TestContextReadinessModel:
    """Tests for ContextReadiness Pydantic model."""

    def test_create_context_readiness_ready(self):
        """Test creating a ready context."""
        readiness = ContextReadiness(
            context="user-pii",
            tier="tier_2",
            tier_display="Tier 2 (Medium)",
            required_operations=50,
            required_hours=24,
            required_days=2,
            requires_approval=False,
            current_operations=100,
            current_hours=48.0,
            current_unique_days=5,
            operations_met=True,
            hours_met=True,
            days_met=True,
            is_ready=True,
        )
        assert readiness.is_ready is True
        assert readiness.blocking_reason is None
        assert readiness.estimated_ready_at is None

    def test_create_context_readiness_not_ready(self):
        """Test creating a not-ready context with blocking reason."""
        estimated = datetime.now(timezone.utc) + timedelta(hours=12)
        readiness = ContextReadiness(
            context="pci",
            tier="tier_3",
            tier_display="Tier 3 (High)",
            required_operations=100,
            required_hours=48,
            required_days=3,
            requires_approval=True,
            current_operations=50,
            current_hours=24.0,
            current_unique_days=1,
            operations_met=False,
            hours_met=False,
            days_met=False,
            is_ready=False,
            estimated_ready_at=estimated,
            blocking_reason="Need 50 more operations; Need 24 more hours in dev; Need 2 more unique days",
        )
        assert readiness.is_ready is False
        assert readiness.blocking_reason is not None
        assert readiness.estimated_ready_at == estimated


class TestPromotionReadinessModel:
    """Tests for PromotionReadiness Pydantic model."""

    def test_create_promotion_readiness_ready(self):
        """Test creating a promotion-ready application."""
        context1 = ContextReadiness(
            context="user-pii",
            tier="tier_2",
            tier_display="Tier 2 (Medium)",
            required_operations=50,
            required_hours=24,
            required_days=2,
            requires_approval=False,
            current_operations=100,
            current_hours=48.0,
            current_unique_days=5,
            operations_met=True,
            hours_met=True,
            days_met=True,
            is_ready=True,
        )
        readiness = PromotionReadiness(
            app_id="app_123",
            app_name="Test App",
            current_environment="development",
            target_environment="production",
            is_ready=True,
            requires_approval=False,
            contexts=[context1],
            ready_count=1,
            total_count=1,
            blocking_contexts=[],
        )
        assert readiness.is_ready is True
        assert readiness.ready_count == 1
        assert readiness.total_count == 1
        assert len(readiness.blocking_contexts) == 0

    def test_create_promotion_readiness_not_ready(self):
        """Test creating a not-ready promotion."""
        context1 = ContextReadiness(
            context="user-pii",
            tier="tier_2",
            tier_display="Tier 2 (Medium)",
            required_operations=50,
            required_hours=24,
            required_days=2,
            requires_approval=False,
            current_operations=100,
            current_hours=48.0,
            current_unique_days=5,
            operations_met=True,
            hours_met=True,
            days_met=True,
            is_ready=True,
        )
        context2 = ContextReadiness(
            context="pci",
            tier="tier_3",
            tier_display="Tier 3 (High)",
            required_operations=100,
            required_hours=48,
            required_days=3,
            requires_approval=True,
            current_operations=25,
            current_hours=12.0,
            current_unique_days=1,
            operations_met=False,
            hours_met=False,
            days_met=False,
            is_ready=False,
            blocking_reason="Need 75 more operations",
        )
        readiness = PromotionReadiness(
            app_id="app_123",
            app_name="Test App",
            current_environment="development",
            target_environment="production",
            is_ready=False,
            requires_approval=True,
            contexts=[context1, context2],
            ready_count=1,
            total_count=2,
            blocking_contexts=["pci"],
        )
        assert readiness.is_ready is False
        assert readiness.ready_count == 1
        assert readiness.total_count == 2
        assert "pci" in readiness.blocking_contexts


class TestExpeditedRequestModel:
    """Tests for ExpeditedRequest Pydantic model."""

    def test_create_expedited_request(self):
        """Test creating an expedited request."""
        request = ExpeditedRequest(
            app_id="app_123",
            app_name="Test App",
            priority=ExpediteePriority.HIGH,
            justification="Critical business deadline",
            contexts=["user-pii", "pci"],
            thresholds_bypassed=["pci: 50/100 ops"],
            requester_email="dev@example.com",
            requester_trust_score=0.85,
        )
        assert request.app_id == "app_123"
        assert request.priority == ExpediteePriority.HIGH
        assert request.status == "pending"
        assert request.approved_by is None
        assert request.request_id.startswith("EXP-")

    def test_expedited_request_priorities(self):
        """Test all priority levels."""
        for priority in ExpediteePriority:
            request = ExpeditedRequest(
                app_id="app_123",
                app_name="Test App",
                priority=priority,
                justification="Test justification for expedited request",
                contexts=["user-pii"],
                thresholds_bypassed=[],
                requester_email="dev@example.com",
                requester_trust_score=1.0,
            )
            assert request.priority == priority


class TestCheckContextReadiness:
    """Tests for check_context_readiness async function using mocked get_context_stats."""

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_ready(self, mock_stats):
        """Test checking readiness when context is ready."""
        mock_db = AsyncMock()

        # Mock get_context_stats to return ready values for Tier 2
        mock_stats.return_value = (100, 48.0, 5)  # ops, hours, days

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is True
        assert readiness.operations_met is True
        assert readiness.hours_met is True
        assert readiness.days_met is True
        assert readiness.blocking_reason is None

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_not_ready_operations(self, mock_stats):
        """Test checking readiness when operations not met."""
        mock_db = AsyncMock()

        # Mock: not enough operations for Tier 2
        mock_stats.return_value = (25, 48.0, 5)  # ops < 50 required

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is False
        assert readiness.operations_met is False
        assert readiness.hours_met is True
        assert readiness.days_met is True
        assert "operations" in readiness.blocking_reason.lower()

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_not_ready_hours(self, mock_stats):
        """Test checking readiness when hours not met."""
        mock_db = AsyncMock()

        # Mock: not enough hours for Tier 2
        mock_stats.return_value = (100, 10.0, 5)  # hours < 24 required

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is False
        assert readiness.operations_met is True
        assert readiness.hours_met is False
        assert readiness.days_met is True
        assert "hours" in readiness.blocking_reason.lower()

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_not_ready_days(self, mock_stats):
        """Test checking readiness when days not met."""
        mock_db = AsyncMock()

        # Mock: not enough days for Tier 2
        mock_stats.return_value = (100, 48.0, 1)  # days < 2 required

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is False
        assert readiness.operations_met is True
        assert readiness.hours_met is True
        assert readiness.days_met is False
        assert "days" in readiness.blocking_reason.lower()

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_tier1(self, mock_stats):
        """Test Tier 1 context has lower requirements."""
        mock_db = AsyncMock()

        # Tier 1 requirements: 10 ops, 1 hour, 1 day
        mock_stats.return_value = (15, 2.0, 1)

        readiness = await check_context_readiness(mock_db, "app_123", "session-tokens")

        assert readiness.is_ready is True
        assert readiness.tier == "tier_1"
        assert readiness.requires_approval is False

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_context_readiness_tier3_requires_approval(self, mock_stats):
        """Test that Tier 3 contexts require approval even when ready."""
        mock_db = AsyncMock()

        # Tier 3 requirements: 100 ops, 48 hours, 3 days
        mock_stats.return_value = (150, 72.0, 5)

        readiness = await check_context_readiness(mock_db, "app_123", "pci")

        assert readiness.is_ready is True
        assert readiness.tier == "tier_3"
        assert readiness.requires_approval is True


class TestCheckPromotionReadiness:
    """Tests for check_promotion_readiness async function."""

    @pytest.mark.asyncio
    async def test_check_promotion_readiness_no_contexts(self):
        """Test readiness check with no allowed contexts."""
        mock_db = AsyncMock()

        # Create mock application with no contexts
        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = []

        readiness = await check_promotion_readiness(mock_db, mock_app, "production")

        assert readiness.is_ready is False
        assert readiness.total_count == 0
        assert readiness.ready_count == 0

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_promotion_readiness_all_ready(self, mock_stats):
        """Test readiness when all contexts are ready."""
        mock_db = AsyncMock()

        # Create mock application
        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["session-tokens"]  # Tier 1

        # Tier 1: needs 10 ops, 1 hour, 1 day
        mock_stats.return_value = (50, 24.0, 3)

        readiness = await check_promotion_readiness(mock_db, mock_app, "production")

        assert readiness.is_ready is True
        assert readiness.total_count == 1
        assert readiness.ready_count == 1
        assert len(readiness.blocking_contexts) == 0

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_check_promotion_readiness_partial_ready(self, mock_stats):
        """Test readiness when some contexts are not ready."""
        mock_db = AsyncMock()

        # Create mock application with 2 contexts
        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["session-tokens", "user-pii"]

        # Return different values for each context call
        # session-tokens (Tier 1): ready
        # user-pii (Tier 2): not ready
        mock_stats.side_effect = [
            (50, 24.0, 3),   # session-tokens: ready
            (10, 5.0, 1),    # user-pii: not ready (needs 50 ops, 24h, 2 days)
        ]

        readiness = await check_promotion_readiness(mock_db, mock_app, "production")

        assert readiness.is_ready is False
        assert readiness.total_count == 2
        assert readiness.ready_count == 1
        assert "user-pii" in readiness.blocking_contexts


class TestCreateExpeditedRequest:
    """Tests for create_expedited_request async function."""

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_create_expedited_request_critical(self, mock_stats):
        """Test creating a critical expedited request."""
        mock_db = AsyncMock()

        # Create mock application
        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["user-pii"]

        # Not ready: needs 50 ops, 24h, 2 days
        mock_stats.return_value = (10, 5.0, 1)

        request = await create_expedited_request(
            db=mock_db,
            application=mock_app,
            priority=ExpediteePriority.CRITICAL,
            justification="Production is down, critical fix needed",
            requester_email="dev@example.com",
        )

        assert request.priority == ExpediteePriority.CRITICAL
        assert request.status == "pending"
        assert len(request.thresholds_bypassed) > 0
        assert request.request_id.startswith("EXP-")
        assert request.requester_email == "dev@example.com"

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_create_expedited_request_captures_bypassed_thresholds(self, mock_stats):
        """Test that expedited request captures all bypassed thresholds."""
        mock_db = AsyncMock()

        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["pci"]  # Tier 3

        # All Tier 3 requirements not met (needs 100 ops, 48h, 3 days)
        mock_stats.return_value = (25, 12.0, 1)

        request = await create_expedited_request(
            db=mock_db,
            application=mock_app,
            priority=ExpediteePriority.HIGH,
            justification="Customer deadline approaching",
            requester_email="dev@example.com",
        )

        # Should have 3 bypassed thresholds (ops, hours, days)
        assert len(request.thresholds_bypassed) == 3
        # Check that thresholds mention the context
        assert any("pci" in t for t in request.thresholds_bypassed)


class TestExpediteePriority:
    """Tests for ExpediteePriority enum."""

    def test_priority_values(self):
        """Test priority enum values."""
        assert ExpediteePriority.CRITICAL.value == "critical"
        assert ExpediteePriority.HIGH.value == "high"
        assert ExpediteePriority.NORMAL.value == "normal"

    def test_all_priorities_exist(self):
        """Test all expected priorities exist."""
        priorities = [p.value for p in ExpediteePriority]
        assert "critical" in priorities
        assert "high" in priorities
        assert "normal" in priorities


class TestContextTiersMapping:
    """Tests for CONTEXT_TIERS mapping completeness."""

    def test_all_tier1_contexts_defined(self):
        """Test that Tier 1 contexts are defined."""
        tier1_expected = ["session-tokens", "cache-data", "temp-data", "analytics"]
        for context in tier1_expected:
            assert context in CONTEXT_TIERS
            assert CONTEXT_TIERS[context] == ContextTier.TIER_1

    def test_all_tier2_contexts_defined(self):
        """Test that Tier 2 contexts are defined."""
        tier2_expected = ["user-pii", "api-keys", "internal-data", "customer-data"]
        for context in tier2_expected:
            assert context in CONTEXT_TIERS
            assert CONTEXT_TIERS[context] == ContextTier.TIER_2

    def test_all_tier3_contexts_defined(self):
        """Test that Tier 3 contexts are defined."""
        tier3_expected = ["pci", "payment-data", "health-data", "phi", "secrets", "encryption-keys"]
        for context in tier3_expected:
            assert context in CONTEXT_TIERS
            assert CONTEXT_TIERS[context] == ContextTier.TIER_3


# ============================================================================
# API Integration Tests
# ============================================================================


class TestPromotionAPIModels:
    """Tests for promotion API request/response models."""

    def test_import_api_models(self):
        """Test that API models can be imported."""
        from app.api.promotion import (
            PromotionRequest,
            ExpeditedPromotionRequest,
            PromotionResponse,
            ExpeditedResponse,
        )
        assert PromotionRequest is not None
        assert ExpeditedPromotionRequest is not None
        assert PromotionResponse is not None
        assert ExpeditedResponse is not None

    def test_promotion_request_defaults(self):
        """Test PromotionRequest default values."""
        from app.api.promotion import PromotionRequest

        request = PromotionRequest()
        assert request.target_environment == "production"

    def test_promotion_request_custom_environment(self):
        """Test PromotionRequest with custom environment."""
        from app.api.promotion import PromotionRequest

        request = PromotionRequest(target_environment="staging")
        assert request.target_environment == "staging"

    def test_expedited_request_validation(self):
        """Test ExpeditedPromotionRequest validation."""
        from app.api.promotion import ExpeditedPromotionRequest

        # Valid request
        request = ExpeditedPromotionRequest(
            priority=ExpediteePriority.CRITICAL,
            justification="Critical production issue requiring immediate fix",
        )
        assert request.priority == ExpediteePriority.CRITICAL
        assert len(request.justification) >= 10

    def test_expedited_request_justification_min_length(self):
        """Test ExpeditedPromotionRequest justification minimum length."""
        from app.api.promotion import ExpeditedPromotionRequest
        from pydantic import ValidationError

        # Too short justification should fail
        with pytest.raises(ValidationError):
            ExpeditedPromotionRequest(
                priority=ExpediteePriority.NORMAL,
                justification="short",  # < 10 chars
            )

    def test_promotion_response_creation(self):
        """Test PromotionResponse creation."""
        from app.api.promotion import PromotionResponse

        response = PromotionResponse(
            app_id="app_123",
            app_name="Test App",
            current_environment="development",
            target_environment="production",
            is_ready=True,
            requires_approval=False,
            ready_count=2,
            total_count=2,
            blocking_contexts=[],
            estimated_ready_at=None,
            contexts=[],
            message="Ready for promotion!",
        )
        assert response.is_ready is True
        assert response.app_id == "app_123"

    def test_expedited_response_creation(self):
        """Test ExpeditedResponse creation."""
        from app.api.promotion import ExpeditedResponse

        response = ExpeditedResponse(
            request_id="EXP-2025-ABCD",
            app_id="app_123",
            app_name="Test App",
            priority="critical",
            status="pending",
            thresholds_bypassed=["user-pii: 25/50 ops"],
            message="Critical expedited request submitted.",
            next_steps=["On-call admin has been paged"],
        )
        assert response.request_id == "EXP-2025-ABCD"
        assert response.status == "pending"


class TestPromotionAPIRouter:
    """Tests for promotion API router configuration."""

    def test_router_exists(self):
        """Test that promotion router exists."""
        from app.api.promotion import router

        assert router is not None
        assert router.prefix == "/api/v1/applications"
        assert "promotion" in router.tags

    def test_router_has_promotion_endpoints(self):
        """Test that promotion endpoints are registered."""
        from app.api.promotion import router

        # Get all route paths
        route_paths = []
        for route in router.routes:
            if hasattr(route, 'path'):
                route_paths.append(route.path)

        # Check for promotion paths (path includes app_id parameter)
        promotion_paths = [p for p in route_paths if "promotion" in p]
        assert len(promotion_paths) >= 2  # At least GET and POST

    def test_router_has_expedite_endpoint(self):
        """Test that expedite endpoint is registered."""
        from app.api.promotion import router

        # Get all route paths
        route_paths = []
        for route in router.routes:
            if hasattr(route, 'path'):
                route_paths.append(route.path)

        # Check for expedite path
        expedite_paths = [p for p in route_paths if "expedite" in p]
        assert len(expedite_paths) >= 1


class TestEstimatedReadyAtCalculation:
    """Tests for estimated ready at calculation logic."""

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_estimated_ready_at_based_on_hours(self, mock_stats):
        """Test estimated time is based on hours remaining."""
        mock_db = AsyncMock()

        # Context needs more hours (24h required, only 10h so far)
        # Tier 2: needs 50 ops, 24 hours, 2 days
        mock_stats.return_value = (100, 10.0, 5)  # Enough ops and days, not enough hours

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is False
        assert readiness.hours_met is False
        assert readiness.estimated_ready_at is not None
        # Should be roughly 14 hours from now (24 - 10 = 14)
        hours_until_ready = (readiness.estimated_ready_at - datetime.now(timezone.utc)).total_seconds() / 3600
        assert 13 <= hours_until_ready <= 15

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_estimated_ready_at_based_on_days(self, mock_stats):
        """Test estimated time accounts for days remaining."""
        mock_db = AsyncMock()

        # Context needs more days (2 required, only 1 so far)
        # Tier 2: needs 50 ops, 24 hours, 2 days
        mock_stats.return_value = (100, 48.0, 1)  # Enough ops and hours, not enough days

        readiness = await check_context_readiness(mock_db, "app_123", "user-pii")

        assert readiness.is_ready is False
        assert readiness.days_met is False
        assert readiness.estimated_ready_at is not None
        # Should be at least 24 hours (1 more day needed)
        hours_until_ready = (readiness.estimated_ready_at - datetime.now(timezone.utc)).total_seconds() / 3600
        assert hours_until_ready >= 20  # Allow some buffer


class TestPromotionReadinessAggregation:
    """Tests for promotion readiness aggregation across contexts."""

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_requires_approval_if_any_tier3(self, mock_stats):
        """Test requires_approval is True if any Tier 3 context exists."""
        mock_db = AsyncMock()

        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["session-tokens", "pci"]  # Tier 1 + Tier 3

        # Both contexts ready
        mock_stats.side_effect = [
            (50, 24.0, 3),     # session-tokens (Tier 1): ready
            (150, 72.0, 5),   # pci (Tier 3): ready
        ]

        readiness = await check_promotion_readiness(mock_db, mock_app, "production")

        assert readiness.is_ready is True
        assert readiness.requires_approval is True  # Due to Tier 3 context

    @pytest.mark.asyncio
    @patch("app.core.promotion.get_context_stats")
    async def test_estimated_ready_at_is_latest(self, mock_stats):
        """Test estimated_ready_at is the latest of all contexts."""
        mock_db = AsyncMock()

        mock_app = MagicMock()
        mock_app.id = "app_123"
        mock_app.name = "Test App"
        mock_app.environment = "development"
        mock_app.allowed_contexts = ["session-tokens", "user-pii"]

        # Both contexts not ready
        mock_stats.side_effect = [
            (5, 0.5, 1),   # session-tokens (Tier 1): not ready
            (25, 4.0, 1),  # user-pii (Tier 2): not ready, needs more time
        ]

        readiness = await check_promotion_readiness(mock_db, mock_app, "production")

        assert readiness.is_ready is False
        assert readiness.estimated_ready_at is not None
        # Should be the later of the two estimates
        hours_until_ready = (readiness.estimated_ready_at - datetime.now(timezone.utc)).total_seconds() / 3600
        assert hours_until_ready >= 15  # Should be at least 15h (for user-pii)
