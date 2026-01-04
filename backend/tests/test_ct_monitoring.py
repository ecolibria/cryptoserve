"""Tests for Certificate Transparency monitoring."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.core.ct_monitoring import (
    CTMonitor,
    CTLogEntry,
    CTAlert,
    CTAlertSeverity,
    CTAlertType,
    CTMonitoringResult,
    DomainConfig,
)


@pytest.fixture
def ct_monitor():
    """Create a CT monitor instance."""
    return CTMonitor()


@pytest.fixture
def sample_cert_entry():
    """Create a sample CT log entry."""
    return CTLogEntry(
        id=12345,
        issuer_name="Let's Encrypt",
        issuer_ca_id=1,
        common_name="example.com",
        name_value="example.com\nwww.example.com",
        not_before=datetime.now(timezone.utc) - timedelta(days=30),
        not_after=datetime.now(timezone.utc) + timedelta(days=335),
        serial_number="ABC123",
        sha256_fingerprint="abcd1234",
        entry_timestamp=datetime.now(timezone.utc) - timedelta(days=30),
    )


@pytest.fixture
def expired_cert_entry():
    """Create an expired certificate entry."""
    return CTLogEntry(
        id=12346,
        issuer_name="DigiCert",
        issuer_ca_id=2,
        common_name="old.example.com",
        name_value="old.example.com",
        not_before=datetime.now(timezone.utc) - timedelta(days=400),
        not_after=datetime.now(timezone.utc) - timedelta(days=35),
        serial_number="DEF456",
        sha256_fingerprint="efgh5678",
    )


@pytest.fixture
def expiring_cert_entry():
    """Create a certificate expiring soon."""
    return CTLogEntry(
        id=12347,
        issuer_name="Cloudflare",
        issuer_ca_id=3,
        common_name="expiring.example.com",
        name_value="expiring.example.com",
        not_before=datetime.now(timezone.utc) - timedelta(days=80),
        not_after=datetime.now(timezone.utc) + timedelta(days=10),
        serial_number="GHI789",
        sha256_fingerprint="ijkl9012",
    )


@pytest.fixture
def wildcard_cert_entry():
    """Create a wildcard certificate entry."""
    return CTLogEntry(
        id=12348,
        issuer_name="Let's Encrypt",
        issuer_ca_id=1,
        common_name="*.example.com",
        name_value="*.example.com",
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
        not_after=datetime.now(timezone.utc) + timedelta(days=80),
        serial_number="JKL012",
        sha256_fingerprint="mnop3456",
    )


class TestCTLogEntry:
    """Tests for CTLogEntry data class."""

    def test_is_expired(self, sample_cert_entry, expired_cert_entry):
        """Test expiration detection."""
        assert sample_cert_entry.is_expired is False
        assert expired_cert_entry.is_expired is True

    def test_days_until_expiry(self, sample_cert_entry):
        """Test days until expiry calculation."""
        days = sample_cert_entry.days_until_expiry
        assert 330 <= days <= 340  # Approximately 335 days

    def test_is_wildcard(self, sample_cert_entry, wildcard_cert_entry):
        """Test wildcard detection."""
        assert sample_cert_entry.is_wildcard is False
        assert wildcard_cert_entry.is_wildcard is True

    def test_domains(self, sample_cert_entry):
        """Test domain parsing from name_value."""
        domains = sample_cert_entry.domains
        assert len(domains) == 2
        assert "example.com" in domains
        assert "www.example.com" in domains


class TestCTMonitorAnalysis:
    """Tests for certificate analysis and alert generation."""

    def test_analyze_expired_cert(self, ct_monitor, expired_cert_entry):
        """Test that expired certs do NOT generate alerts (not actionable)."""
        config = DomainConfig(domain="example.com")
        alerts = ct_monitor.analyze_certificates([expired_cert_entry], config)

        # Expired cert alerts were removed as they are not actionable
        expired_alerts = [a for a in alerts if a.alert_type == CTAlertType.EXPIRED_CERT]
        assert len(expired_alerts) == 0

    def test_analyze_expiring_soon(self, ct_monitor, expiring_cert_entry):
        """Test detection of certificates expiring soon."""
        config = DomainConfig(domain="example.com", expiry_warning_days=30)
        alerts = ct_monitor.analyze_certificates([expiring_cert_entry], config)

        expiring_alerts = [a for a in alerts if a.alert_type == CTAlertType.EXPIRING_SOON]
        assert len(expiring_alerts) == 1
        assert expiring_alerts[0].severity == CTAlertSeverity.MEDIUM

    def test_analyze_unexpected_issuer(self, ct_monitor, sample_cert_entry):
        """Test detection of unexpected CA issuer."""
        config = DomainConfig(
            domain="example.com",
            expected_issuers=["DigiCert", "Sectigo"],  # Not Let's Encrypt
        )
        alerts = ct_monitor.analyze_certificates([sample_cert_entry], config)

        issuer_alerts = [a for a in alerts if a.alert_type == CTAlertType.UNEXPECTED_ISSUER]
        assert len(issuer_alerts) == 1
        assert issuer_alerts[0].severity == CTAlertSeverity.HIGH

    def test_analyze_expected_issuer(self, ct_monitor, sample_cert_entry):
        """Test no alert when issuer is expected."""
        config = DomainConfig(
            domain="example.com",
            expected_issuers=["Let's Encrypt"],  # Matches
        )
        alerts = ct_monitor.analyze_certificates([sample_cert_entry], config)

        issuer_alerts = [a for a in alerts if a.alert_type == CTAlertType.UNEXPECTED_ISSUER]
        assert len(issuer_alerts) == 0

    def test_analyze_wildcard_cert(self, ct_monitor, wildcard_cert_entry):
        """Test detection of wildcard certificates (informational only)."""
        config = DomainConfig(domain="example.com", alert_on_wildcard=True)
        alerts = ct_monitor.analyze_certificates([wildcard_cert_entry], config)

        wildcard_alerts = [a for a in alerts if a.alert_type == CTAlertType.WILDCARD_ISSUED]
        assert len(wildcard_alerts) == 1
        # Wildcards are INFO level - informational, not a security issue
        assert wildcard_alerts[0].severity == CTAlertSeverity.INFO

    def test_analyze_wildcard_disabled(self, ct_monitor, wildcard_cert_entry):
        """Test no wildcard alert when disabled."""
        config = DomainConfig(domain="example.com", alert_on_wildcard=False)
        alerts = ct_monitor.analyze_certificates([wildcard_cert_entry], config)

        wildcard_alerts = [a for a in alerts if a.alert_type == CTAlertType.WILDCARD_ISSUED]
        assert len(wildcard_alerts) == 0

    def test_analyze_no_duplicate_serial_alerts(self, ct_monitor):
        """Test that duplicate serials do NOT generate alerts.

        Duplicate serial detection was removed because:
        1. Same cert appears in multiple CT logs (normal behavior)
        2. Deduplication is now handled at the search level
        3. Same serial from different CAs is technically valid
        """
        cert1 = CTLogEntry(
            id=1, issuer_name="CA1", issuer_ca_id=1, common_name="a.example.com",
            name_value="a.example.com", not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=90),
            serial_number="SAME_SERIAL", sha256_fingerprint="fp1",
        )
        cert2 = CTLogEntry(
            id=2, issuer_name="CA2", issuer_ca_id=2, common_name="b.example.com",
            name_value="b.example.com", not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=90),
            serial_number="SAME_SERIAL", sha256_fingerprint="fp2",
        )

        config = DomainConfig(domain="example.com")
        alerts = ct_monitor.analyze_certificates([cert1, cert2], config)

        # Duplicate serial alerts were removed - deduplication happens at search level
        dup_alerts = [a for a in alerts if a.alert_type == CTAlertType.DUPLICATE_SERIAL]
        assert len(dup_alerts) == 0


class TestCTMonitorSearch:
    """Tests for CT log searching (with mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_search_success(self, ct_monitor):
        """Test successful certificate search."""
        mock_response = [
            {
                "id": 12345,
                "issuer_name": "Let's Encrypt",
                "issuer_ca_id": 1,
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2025-01-01T00:00:00",
                "not_after": "2025-12-31T23:59:59",
                "serial_number": "ABC123",
            }
        ]

        with patch.object(ct_monitor, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock()
            mock_client.get.return_value.raise_for_status = MagicMock()
            mock_client.get.return_value.json = MagicMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            certs = await ct_monitor.search_certificates("example.com")

            assert len(certs) == 1
            assert certs[0].common_name == "example.com"
            assert certs[0].issuer_name == "Let's Encrypt"

    @pytest.mark.asyncio
    async def test_search_empty_results(self, ct_monitor):
        """Test search with no results."""
        with patch.object(ct_monitor, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock()
            mock_client.get.return_value.raise_for_status = MagicMock()
            mock_client.get.return_value.json = MagicMock(return_value=[])
            mock_get_client.return_value = mock_client

            certs = await ct_monitor.search_certificates("nonexistent.example.com")
            assert len(certs) == 0


class TestDomainConfig:
    """Tests for DomainConfig."""

    def test_default_config(self):
        """Test default domain configuration."""
        config = DomainConfig(domain="example.com")
        assert config.include_subdomains is True
        assert config.expected_issuers == []
        assert config.alert_on_wildcard is True
        assert config.expiry_warning_days == 30

    def test_custom_config(self):
        """Test custom domain configuration."""
        config = DomainConfig(
            domain="example.com",
            include_subdomains=False,
            expected_issuers=["DigiCert"],
            alert_on_wildcard=False,
            expiry_warning_days=60,
        )
        assert config.include_subdomains is False
        assert config.expected_issuers == ["DigiCert"]
        assert config.alert_on_wildcard is False
        assert config.expiry_warning_days == 60


class TestMonitoringResult:
    """Tests for CTMonitoringResult."""

    def test_result_summary(self, sample_cert_entry, expired_cert_entry):
        """Test monitoring result statistics."""
        result = CTMonitoringResult(
            domain="example.com",
            certificates=[sample_cert_entry, expired_cert_entry],
            alerts=[],
            scanned_at=datetime.now(timezone.utc),
            total_certs=2,
            active_certs=1,
            expired_certs=1,
            issuers={"Let's Encrypt": 1, "DigiCert": 1},
        )

        assert result.total_certs == 2
        assert result.active_certs == 1
        assert result.expired_certs == 1
        assert len(result.issuers) == 2
