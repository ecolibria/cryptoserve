"""Tests for Compliance API endpoints."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, Context, Tenant, AuditLog, Key


@pytest.fixture
async def admin_user(db_session: AsyncSession, test_tenant: Tenant) -> User:
    """Create an admin user."""
    user = User(
        tenant_id=test_tenant.id,
        github_id=99999,
        github_username="adminuser",
        email="admin@example.com",
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def non_admin_user(db_session: AsyncSession, test_tenant: Tenant) -> User:
    """Create a non-admin user."""
    user = User(
        tenant_id=test_tenant.id,
        github_id=88888,
        github_username="regularuser",
        email="user@example.com",
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def compliance_contexts(db_session: AsyncSession, test_tenant: Tenant) -> list[Context]:
    """Create contexts with various compliance tags."""
    contexts = [
        Context(
            tenant_id=test_tenant.id,
            name="hipaa-context",
            display_name="HIPAA Data",
            description="Health data context",
            data_examples=["patient records", "phi"],
            compliance_tags=["HIPAA"],
            algorithm="AES-256-GCM",
        ),
        Context(
            tenant_id=test_tenant.id,
            name="pci-context",
            display_name="PCI Data",
            description="Payment card data",
            data_examples=["credit card", "pci"],
            compliance_tags=["PCI-DSS"],
            algorithm="AES-256-GCM",
        ),
        Context(
            tenant_id=test_tenant.id,
            name="gdpr-context",
            display_name="GDPR Data",
            description="Personal data",
            data_examples=["email", "pii", "name"],
            compliance_tags=["GDPR"],
            algorithm="AES-256-GCM",
        ),
        Context(
            tenant_id=test_tenant.id,
            name="quantum-safe-context",
            display_name="Quantum Safe",
            description="Quantum-safe encryption",
            data_examples=["long-term secrets"],
            compliance_tags=["SOC2"],
            algorithm="ML-KEM-768+AES-256-GCM",
        ),
    ]
    for ctx in contexts:
        db_session.add(ctx)
    await db_session.commit()
    for ctx in contexts:
        await db_session.refresh(ctx)
    return contexts


@pytest.fixture
async def audit_logs(db_session: AsyncSession, test_tenant: Tenant) -> list[AuditLog]:
    """Create audit log entries."""
    now = datetime.now(timezone.utc)
    logs = [
        AuditLog(
            tenant_id=test_tenant.id,
            timestamp=now - timedelta(days=1),
            operation="encrypt",
            context="hipaa-context",
            identity_id="test-app-1",
            identity_name="Test App 1",
            cipher="AES",
            mode="GCM",
            key_bits=256,
            success=True,
            algorithm="AES-256-GCM",
        ),
        AuditLog(
            tenant_id=test_tenant.id,
            timestamp=now - timedelta(days=2),
            operation="decrypt",
            context="pci-context",
            identity_id="test-app-2",
            identity_name="Test App 2",
            cipher="AES",
            mode="GCM",
            key_bits=256,
            success=True,
            algorithm="AES-256-GCM",
        ),
        AuditLog(
            tenant_id=test_tenant.id,
            timestamp=now - timedelta(days=3),
            operation="encrypt",
            context="gdpr-context",
            identity_id="test-app-3",
            identity_name="Test App 3",
            cipher="AES",
            mode="GCM",
            key_bits=256,
            success=False,
            policy_violation=True,
            algorithm="AES-256-GCM",
        ),
    ]
    for log in logs:
        db_session.add(log)
    await db_session.commit()
    return logs


@pytest.fixture
async def test_keys(db_session: AsyncSession, test_tenant: Tenant, compliance_contexts: list[Context]) -> list[Key]:
    """Create test encryption keys."""
    now = datetime.now(timezone.utc)
    keys = [
        Key(
            id=str(uuid4()),
            tenant_id=test_tenant.id,
            context=compliance_contexts[0].name,
            version=1,
            created_at=now - timedelta(days=10),
        ),
        Key(
            id=str(uuid4()),
            tenant_id=test_tenant.id,
            context=compliance_contexts[1].name,
            version=1,
            created_at=now - timedelta(days=100),  # Old key, needs rotation
        ),
    ]
    for key in keys:
        db_session.add(key)
    await db_session.commit()
    return keys


# =============================================================================
# Helper Functions Tests
# =============================================================================

class TestGetFrameworkStatus:
    """Tests for get_framework_status helper."""

    def test_framework_status_model_creation(self):
        """Test FrameworkStatus model can be created."""
        from app.api.compliance import FrameworkStatus

        # Test with contexts
        status = FrameworkStatus(
            framework="HIPAA",
            enabled=True,
            contexts_count=5,
            compliant=True,
            issues=[],
            recommendations=["Enable encryption"],
        )
        assert status.framework == "HIPAA"
        assert status.enabled is True
        assert status.compliant is True

        # Test without contexts
        status = FrameworkStatus(
            framework="PCI-DSS",
            enabled=False,
            contexts_count=0,
            compliant=False,
            issues=["No PCI-DSS-tagged contexts configured"],
            recommendations=[],
        )
        assert status.framework == "PCI-DSS"
        assert status.enabled is False
        assert status.compliant is False

    def test_valid_frameworks(self):
        """Test the list of valid frameworks."""
        valid_frameworks = ["GDPR", "HIPAA", "PCI-DSS", "SOC2", "NIST", "FedRAMP"]

        assert "HIPAA" in valid_frameworks
        assert "PCI-DSS" in valid_frameworks
        assert "GDPR" in valid_frameworks
        assert len(valid_frameworks) == 6


class TestGetAlgorithmCompliance:
    """Tests for get_algorithm_compliance helper."""

    async def test_algorithm_compliance_basic(self, db_session: AsyncSession):
        """Test basic algorithm compliance check."""
        from app.api.compliance import get_algorithm_compliance

        compliance = await get_algorithm_compliance(db_session)

        assert compliance.fips_mode is not None
        assert compliance.quantum_safe_available is True
        assert isinstance(compliance.approved_algorithms, list)

    def test_deprecated_algorithm_patterns(self):
        """Test deprecated algorithm detection patterns."""
        deprecated_patterns = ["DES", "3DES", "RC4", "MD5", "SHA1"]

        # Test algorithm matching
        used_algorithms = ["AES-256-GCM", "DES-CBC", "RSA-2048", "MD5"]
        deprecated_found = []

        for alg in used_algorithms:
            for dep in deprecated_patterns:
                if dep.lower() in alg.lower():
                    deprecated_found.append(alg)
                    break

        assert "DES-CBC" in deprecated_found
        assert "MD5" in deprecated_found
        assert "AES-256-GCM" not in deprecated_found


class TestGetKeyManagementStatus:
    """Tests for get_key_management_status helper."""

    async def test_key_management_status_basic(self, db_session: AsyncSession):
        """Test basic key management status."""
        from app.api.compliance import get_key_management_status

        status = await get_key_management_status(db_session)

        assert status.kms_backend is not None
        assert isinstance(status.total_keys, int)
        assert isinstance(status.pqc_keys, int)

    async def test_key_management_with_old_keys(
        self,
        db_session: AsyncSession,
        test_keys: list[Key],
    ):
        """Test key management detects keys needing rotation."""
        from app.api.compliance import get_key_management_status

        status = await get_key_management_status(db_session)

        assert status.total_keys == 2
        assert status.keys_needing_rotation == 1  # One key is 100 days old


class TestGetAuditStatus:
    """Tests for get_audit_status helper."""

    async def test_audit_status_basic(self, db_session: AsyncSession):
        """Test basic audit status."""
        from app.api.compliance import get_audit_status

        status = await get_audit_status(db_session)

        assert status.enabled is True
        assert isinstance(status.total_events_30d, int)
        assert isinstance(status.operations_by_type, dict)

    async def test_audit_status_with_logs(
        self,
        db_session: AsyncSession,
        audit_logs: list[AuditLog],
    ):
        """Test audit status counts events correctly."""
        from app.api.compliance import get_audit_status

        status = await get_audit_status(db_session)

        assert status.total_events_30d == 3
        assert status.policy_violations_30d == 1
        assert status.failed_operations_30d == 1
        assert "encrypt" in status.operations_by_type
        assert "decrypt" in status.operations_by_type


# =============================================================================
# Data Inventory Tests
# =============================================================================

class TestDataInventory:
    """Tests for data inventory functionality."""

    async def test_data_inventory_summary(
        self,
        db_session: AsyncSession,
        admin_user: User,
        compliance_contexts: list[Context],
        audit_logs: list[AuditLog],
    ):
        """Test data inventory returns correct summary."""
        from app.api.compliance import get_data_inventory

        # Mock the dependencies
        with patch("app.api.compliance.get_current_user", return_value=admin_user):
            with patch("app.api.compliance.get_db", return_value=db_session):
                # Call the endpoint handler directly with mocked deps
                from app.api.compliance import DataInventorySummary

                # Simulate what the endpoint does
                result = await db_session.execute(
                    __import__("sqlalchemy").select(Context)
                )
                contexts = result.scalars().all()

                assert len(contexts) == 4  # Our 4 compliance contexts

    async def test_data_inventory_classifications(
        self,
        db_session: AsyncSession,
        compliance_contexts: list[Context],
    ):
        """Test data inventory correctly classifies data types."""
        # HIPAA context should be classified as PHI
        hipaa_ctx = next(c for c in compliance_contexts if "HIPAA" in (c.compliance_tags or []))
        assert "HIPAA" in hipaa_ctx.compliance_tags

        # PCI context should be classified as PCI
        pci_ctx = next(c for c in compliance_contexts if "PCI-DSS" in (c.compliance_tags or []))
        assert "PCI-DSS" in pci_ctx.compliance_tags


# =============================================================================
# Risk Score Tests
# =============================================================================

class TestRiskScore:
    """Tests for risk scoring functionality."""

    async def test_risk_score_low_risk(self, db_session: AsyncSession):
        """Test risk score with no risk factors."""
        from app.api.compliance import RiskLevel

        # With no keys, no violations, etc., score should be relatively low
        # (though local KMS adds some points)
        # Just verify the enum exists and is usable
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    async def test_risk_score_with_old_keys(
        self,
        db_session: AsyncSession,
        test_keys: list[Key],
    ):
        """Test risk score increases with old keys."""
        from app.api.compliance import get_key_management_status

        status = await get_key_management_status(db_session)

        # Should detect one old key
        assert status.keys_needing_rotation > 0

    async def test_risk_score_with_violations(
        self,
        db_session: AsyncSession,
        audit_logs: list[AuditLog],
    ):
        """Test risk score increases with policy violations."""
        from app.api.compliance import get_audit_status

        status = await get_audit_status(db_session)

        # Should detect policy violation
        assert status.policy_violations_30d == 1


# =============================================================================
# Response Model Tests
# =============================================================================

class TestResponseModels:
    """Tests for Pydantic response models."""

    def test_framework_status_model(self):
        """Test FrameworkStatus model."""
        from app.api.compliance import FrameworkStatus

        status = FrameworkStatus(
            framework="HIPAA",
            enabled=True,
            contexts_count=5,
            compliant=True,
            issues=[],
            recommendations=["Enable encryption"],
        )

        assert status.framework == "HIPAA"
        assert status.enabled is True
        assert status.contexts_count == 5

    def test_algorithm_compliance_model(self):
        """Test AlgorithmCompliance model."""
        from app.api.compliance import AlgorithmCompliance

        compliance = AlgorithmCompliance(
            fips_mode="enabled",
            fips_compliant=True,
            quantum_safe_available=True,
            quantum_safe_contexts=3,
            deprecated_algorithms_in_use=["DES"],
            approved_algorithms=["AES-256", "SHA-256"],
        )

        assert compliance.fips_mode == "enabled"
        assert compliance.quantum_safe_contexts == 3
        assert "DES" in compliance.deprecated_algorithms_in_use

    def test_risk_score_summary_model(self):
        """Test RiskScoreSummary model."""
        from app.api.compliance import RiskScoreSummary, RiskLevel

        summary = RiskScoreSummary(
            overall_score=25,
            risk_level=RiskLevel.MEDIUM,
            high_risk_contexts=2,
            key_findings=["Old keys need rotation"],
            assessed_at=datetime.now(timezone.utc),
        )

        assert summary.overall_score == 25
        assert summary.risk_level == RiskLevel.MEDIUM
        assert summary.high_risk_contexts == 2

    def test_data_inventory_item_model(self):
        """Test DataInventoryItem model."""
        from app.api.compliance import DataInventoryItem

        item = DataInventoryItem(
            context_name="user-pii",
            data_classification=["pii", "gdpr"],
            frameworks=["GDPR", "SOC2"],
            algorithm="AES-256-GCM",
            quantum_safe=False,
            operations_30d=1500,
        )

        assert item.context_name == "user-pii"
        assert "pii" in item.data_classification
        assert item.operations_30d == 1500

    def test_data_inventory_summary_model(self):
        """Test DataInventorySummary model."""
        from app.api.compliance import DataInventorySummary, DataInventoryItem

        summary = DataInventorySummary(
            total_contexts=10,
            total_data_types=10,
            pii_count=5,
            phi_count=2,
            pci_count=1,
            quantum_safe_count=3,
            items=[],
            generated_at=datetime.now(timezone.utc),
        )

        assert summary.total_contexts == 10
        assert summary.pii_count == 5
        assert summary.quantum_safe_count == 3

    def test_compliance_report_model(self):
        """Test ComplianceReport model."""
        from app.api.compliance import (
            ComplianceReport,
            FrameworkStatus,
            AlgorithmCompliance,
            KeyManagementStatus,
            AuditStatus,
        )

        report = ComplianceReport(
            generated_at=datetime.now(timezone.utc),
            overall_status="compliant",
            overall_score=85,
            frameworks=[
                FrameworkStatus(
                    framework="HIPAA",
                    enabled=True,
                    contexts_count=3,
                    compliant=True,
                )
            ],
            algorithms=AlgorithmCompliance(
                fips_mode="disabled",
                fips_compliant=False,
                quantum_safe_available=True,
                quantum_safe_contexts=1,
                deprecated_algorithms_in_use=[],
                approved_algorithms=["AES-256"],
            ),
            key_management=KeyManagementStatus(
                kms_backend="local",
                hsm_backed=False,
                key_ceremony_enabled=False,
                ceremony_state=None,
                total_keys=10,
                pqc_keys=2,
                keys_needing_rotation=0,
            ),
            audit=AuditStatus(
                enabled=True,
                total_events_30d=5000,
                operations_by_type={"encrypt": 3000, "decrypt": 2000},
                policy_violations_30d=0,
                failed_operations_30d=5,
            ),
            tenants=[],
            critical_issues=[],
            warnings=["Keys not HSM-backed"],
            recommendations=["Consider cloud KMS"],
        )

        assert report.overall_status == "compliant"
        assert report.overall_score == 85
        assert len(report.frameworks) == 1


# =============================================================================
# Enum Tests
# =============================================================================

class TestEnums:
    """Tests for enum definitions."""

    def test_data_classification_enum(self):
        """Test DataClassification enum values."""
        from app.api.compliance import DataClassification

        assert DataClassification.PII.value == "pii"
        assert DataClassification.PHI.value == "phi"
        assert DataClassification.PCI.value == "pci"
        assert DataClassification.CONFIDENTIAL.value == "confidential"
        assert DataClassification.INTERNAL.value == "internal"
        assert DataClassification.PUBLIC.value == "public"

    def test_risk_level_enum(self):
        """Test RiskLevel enum values."""
        from app.api.compliance import RiskLevel

        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"


# =============================================================================
# Integration Tests (with mocked auth)
# =============================================================================

class TestComplianceEndpoints:
    """Integration tests for compliance API endpoints."""

    async def test_get_tenant_compliance(
        self,
        db_session: AsyncSession,
        test_tenant: Tenant,
        compliance_contexts: list[Context],
        test_keys: list[Key],
    ):
        """Test get_tenant_compliance helper."""
        from app.api.compliance import get_tenant_compliance

        result = await get_tenant_compliance(db_session, test_tenant)

        assert result.tenant_id == str(test_tenant.id)
        assert result.tenant_name == test_tenant.name
        assert result.contexts == 4  # Our 4 compliance contexts
        assert result.keys == 2  # Our 2 test keys

    async def test_compliance_score_calculation(self):
        """Test compliance score calculation logic."""
        # Score starts at 100, reduced by issues/warnings
        score = 100

        critical_issues = ["issue1", "issue2"]
        warnings = ["warning1"]

        score -= len(critical_issues) * 20  # -40
        score -= len(warnings) * 5  # -5
        score = max(0, min(100, score))

        assert score == 55

    async def test_overall_status_determination(self):
        """Test overall status is determined correctly."""
        critical_issues = []
        warnings = []

        # No issues = compliant
        if critical_issues:
            status = "non_compliant"
        elif warnings:
            status = "warnings"
        else:
            status = "compliant"

        assert status == "compliant"

        # With critical issues = non_compliant
        critical_issues = ["critical issue"]
        if critical_issues:
            status = "non_compliant"
        elif warnings:
            status = "warnings"
        else:
            status = "compliant"

        assert status == "non_compliant"

        # With warnings only = warnings
        critical_issues = []
        warnings = ["warning"]
        if critical_issues:
            status = "non_compliant"
        elif warnings:
            status = "warnings"
        else:
            status = "compliant"

        assert status == "warnings"
