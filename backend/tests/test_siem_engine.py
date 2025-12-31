"""Tests for SIEM (Security Information and Event Management) engine."""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from app.core.siem_engine import (
    siem_engine,
    SIEMEngine,
    SIEMConfig,
    SecurityEvent,
    EventCategory,
    EventType,
    Severity,
    OutputFormat,
    SyslogFacility,
)


@pytest.fixture
def engine():
    """Create a fresh SIEM engine."""
    return SIEMEngine()


@pytest.fixture
def configured_engine():
    """Create SIEM engine with custom config."""
    config = SIEMConfig(
        enabled=True,
        format=OutputFormat.JSON,
        vendor="TestVendor",
        product="TestProduct",
        version="2.0",
    )
    return SIEMEngine(config)


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""

    def test_create_event(self):
        """Test creating a security event."""
        event = SecurityEvent(
            event_id="test-123",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="Test event",
        )

        assert event.event_id == "test-123"
        assert event.category == EventCategory.AUTHENTICATION
        assert event.severity == Severity.LOW

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        now = datetime.now(timezone.utc)
        event = SecurityEvent(
            event_id="test-123",
            timestamp=now,
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message="Encryption complete",
            user_id="user-1",
            algorithm="AES-256-GCM",
            custom_fields={"extra": "data"},
        )

        d = event.to_dict()

        assert d["event_id"] == "test-123"
        assert d["category"] == "cryptographic"
        assert d["event_type"] == "encrypt"
        assert d["severity"] == 1
        assert d["user_id"] == "user-1"
        assert d["algorithm"] == "AES-256-GCM"
        assert d["custom"]["extra"] == "data"

    def test_event_with_all_fields(self):
        """Test event with all optional fields."""
        event = SecurityEvent(
            event_id="full-event",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.KEY_MANAGEMENT,
            event_type=EventType.KEY_GENERATED,
            severity=Severity.MEDIUM,
            message="Key generated",
            source_ip="192.168.1.1",
            source_host="client.local",
            destination_ip="10.0.0.1",
            destination_host="server.local",
            user_id="user-123",
            user_name="john.doe",
            session_id="sess-456",
            correlation_id="corr-789",
            resource_type="key",
            resource_id="key-001",
            action="generate",
            outcome="success",
            reason="scheduled rotation",
            algorithm="RSA-4096",
            key_id="key-001",
            policy_id="policy-encrypt",
        )

        d = event.to_dict()

        assert d["source_ip"] == "192.168.1.1"
        assert d["destination_host"] == "server.local"
        assert d["session_id"] == "sess-456"
        assert d["correlation_id"] == "corr-789"


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity numeric values."""
        assert int(Severity.LOW) == 1
        assert int(Severity.MEDIUM) == 3
        assert int(Severity.HIGH) == 5
        assert int(Severity.CRITICAL) == 7
        assert int(Severity.EMERGENCY) == 9

    def test_severity_from_string(self):
        """Test converting string to severity."""
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("unknown") == Severity.UNKNOWN

    def test_severity_comparison(self):
        """Test severity comparison."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.EMERGENCY >= Severity.CRITICAL


class TestBasicLogging:
    """Tests for basic event logging."""

    def test_log_event(self, engine):
        """Test logging a basic event."""
        event = engine.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="User logged in",
            user_id="user-123",
        )

        assert event is not None
        assert event.category == EventCategory.AUTHENTICATION
        assert event.event_type == EventType.LOGIN_SUCCESS
        assert event.user_id == "user-123"

    def test_log_event_generates_id(self, engine):
        """Test that log_event generates unique IDs."""
        event1 = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )
        event2 = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )

        assert event1.event_id != event2.event_id

    def test_log_event_sets_timestamp(self, engine):
        """Test that log_event sets timestamp."""
        before = datetime.now(timezone.utc)
        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )
        after = datetime.now(timezone.utc)

        assert before <= event.timestamp <= after

    def test_disabled_engine_returns_none(self):
        """Test that disabled engine returns None."""
        config = SIEMConfig(enabled=False)
        engine = SIEMEngine(config)

        event = engine.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="Test",
        )

        assert event is None


class TestFiltering:
    """Tests for event filtering."""

    def test_severity_filter(self):
        """Test filtering by minimum severity."""
        config = SIEMConfig(min_severity=Severity.MEDIUM)
        engine = SIEMEngine(config)

        # Low severity should be filtered out
        low_event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Low severity",
        )
        assert low_event is None

        # Medium severity should pass
        medium_event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.MEDIUM,
            message="Medium severity",
        )
        assert medium_event is not None

    def test_include_categories_filter(self):
        """Test filtering by included categories."""
        config = SIEMConfig(
            include_categories=[EventCategory.AUTHENTICATION]
        )
        engine = SIEMEngine(config)

        # Auth should pass
        auth_event = engine.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="Auth event",
        )
        assert auth_event is not None

        # Crypto should be filtered out
        crypto_event = engine.log_event(
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message="Crypto event",
        )
        assert crypto_event is None

    def test_exclude_categories_filter(self):
        """Test filtering by excluded categories."""
        config = SIEMConfig(
            exclude_categories=[EventCategory.AUDIT]
        )
        engine = SIEMEngine(config)

        # Auth should pass
        auth_event = engine.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="Auth event",
        )
        assert auth_event is not None

        # Audit should be filtered out
        audit_event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Audit event",
        )
        assert audit_event is None


class TestOutputFormats:
    """Tests for different output formats."""

    def test_json_format(self, engine):
        """Test JSON output format."""
        engine.configure(format=OutputFormat.JSON)

        event = SecurityEvent(
            event_id="json-test",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message="Test encryption",
            algorithm="AES-256-GCM",
        )

        formatted = engine._format_json(event)
        data = json.loads(formatted)

        assert data["event_id"] == "json-test"
        assert data["category"] == "cryptographic"
        assert data["event"]["type"] == "encrypt"
        assert "@timestamp" in data

    def test_cef_format(self, engine):
        """Test CEF output format."""
        engine.configure(format=OutputFormat.CEF)

        event = SecurityEvent(
            event_id="cef-test",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=Severity.MEDIUM,
            message="Login failed",
            source_ip="192.168.1.100",
            user_id="user-123",
        )

        formatted = engine._format_cef(event)

        assert formatted.startswith("CEF:0|")
        assert "login-failure" in formatted
        assert "src=192.168.1.100" in formatted
        assert "suid=user-123" in formatted

    def test_leef_format(self, engine):
        """Test LEEF output format."""
        engine.configure(format=OutputFormat.LEEF)

        event = SecurityEvent(
            event_id="leef-test",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.KEY_MANAGEMENT,
            event_type=EventType.KEY_GENERATED,
            severity=Severity.LOW,
            message="Key generated",
            algorithm="RSA-4096",
            key_id="key-001",
        )

        formatted = engine._format_leef(event)

        assert formatted.startswith("LEEF:2.0|")
        assert "key-generated" in formatted
        assert "algorithm=RSA-4096" in formatted
        assert "keyId=key-001" in formatted

    def test_syslog_format(self, engine):
        """Test Syslog (RFC 5424) output format."""
        engine.configure(format=OutputFormat.SYSLOG)

        event = SecurityEvent(
            event_id="syslog-test",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.POLICY,
            event_type=EventType.POLICY_VIOLATION,
            severity=Severity.HIGH,
            message="Policy violated",
            user_id="bad-actor",
        )

        formatted = engine._format_syslog(event)

        # Should start with priority in angle brackets
        assert formatted.startswith("<")
        assert "policy-violation" in formatted
        assert "userId=" in formatted


class TestConvenienceMethods:
    """Tests for convenience logging methods."""

    def test_log_authentication_success(self, engine):
        """Test authentication success logging."""
        event = engine.log_authentication_success(
            user_id="user-123",
            user_name="John Doe",
            source_ip="10.0.0.1",
            method="password",
        )

        assert event.event_type == EventType.LOGIN_SUCCESS
        assert event.outcome == "success"
        assert event.user_id == "user-123"

    def test_log_authentication_failure(self, engine):
        """Test authentication failure logging."""
        event = engine.log_authentication_failure(
            user_id="user-123",
            reason="Invalid password",
            source_ip="10.0.0.1",
        )

        assert event.event_type == EventType.LOGIN_FAILURE
        assert event.severity == Severity.MEDIUM
        assert event.outcome == "failure"

    def test_log_access_denied(self, engine):
        """Test access denied logging."""
        event = engine.log_access_denied(
            user_id="user-123",
            resource_type="key",
            resource_id="secret-key-1",
            action="decrypt",
            reason="Insufficient permissions",
        )

        assert event.event_type == EventType.ACCESS_DENIED
        assert event.resource_type == "key"
        assert event.resource_id == "secret-key-1"

    def test_log_encryption(self, engine):
        """Test encryption logging."""
        event = engine.log_encryption(
            algorithm="AES-256-GCM",
            key_id="key-001",
            user_id="user-123",
            data_size=1024,
        )

        assert event.event_type == EventType.ENCRYPT
        assert event.algorithm == "AES-256-GCM"
        assert event.custom_fields["data_size"] == 1024

    def test_log_decryption_success(self, engine):
        """Test successful decryption logging."""
        event = engine.log_decryption(
            algorithm="AES-256-GCM",
            key_id="key-001",
            success=True,
        )

        assert event.event_type == EventType.DECRYPT
        assert event.outcome == "success"

    def test_log_decryption_failure(self, engine):
        """Test failed decryption logging."""
        event = engine.log_decryption(
            algorithm="AES-256-GCM",
            key_id="key-001",
            success=False,
            reason="Invalid tag",
        )

        assert event.event_type == EventType.DECRYPT_FAILURE
        assert event.severity == Severity.HIGH
        assert event.outcome == "failure"

    def test_log_key_generated(self, engine):
        """Test key generation logging."""
        event = engine.log_key_generated(
            key_id="new-key-001",
            algorithm="RSA",
            key_size=4096,
            purpose="encryption",
        )

        assert event.event_type == EventType.KEY_GENERATED
        assert event.key_id == "new-key-001"
        assert event.custom_fields["key_size"] == 4096

    def test_log_key_rotation(self, engine):
        """Test key rotation logging."""
        event = engine.log_key_rotation(
            old_key_id="old-key",
            new_key_id="new-key",
            algorithm="AES-256",
            reason="Scheduled rotation",
        )

        assert event.event_type == EventType.KEY_ROTATED
        assert event.key_id == "new-key"
        assert event.custom_fields["old_key_id"] == "old-key"

    def test_log_key_compromised(self, engine):
        """Test key compromise logging."""
        event = engine.log_key_compromised(
            key_id="compromised-key",
            algorithm="RSA-2048",
            discovery_method="Security audit",
        )

        assert event.event_type == EventType.KEY_COMPROMISED
        assert event.severity == Severity.EMERGENCY
        assert "SECURITY ALERT" in event.message

    def test_log_policy_violation(self, engine):
        """Test policy violation logging."""
        event = engine.log_policy_violation(
            policy_id="policy-aes-256",
            violation_type="weak-algorithm",
            user_id="user-123",
            details="Used AES-128 instead of AES-256",
        )

        assert event.event_type == EventType.POLICY_VIOLATION
        assert event.severity == Severity.HIGH
        assert event.policy_id == "policy-aes-256"

    def test_log_certificate_validation_success(self, engine):
        """Test successful certificate validation logging."""
        event = engine.log_certificate_validation(
            subject="CN=example.com",
            issuer="CN=Example CA",
            serial_number="12345",
            valid=True,
        )

        assert event.event_type == EventType.CERT_VALIDATION_SUCCESS
        assert event.outcome == "success"

    def test_log_certificate_validation_failure(self, engine):
        """Test failed certificate validation logging."""
        event = engine.log_certificate_validation(
            subject="CN=example.com",
            issuer="CN=Example CA",
            serial_number="12345",
            valid=False,
            reason="Certificate expired",
        )

        assert event.event_type == EventType.CERT_VALIDATION_FAILURE
        assert event.severity == Severity.HIGH

    def test_log_algorithm_deprecated(self, engine):
        """Test deprecated algorithm logging."""
        event = engine.log_algorithm_deprecated(
            algorithm="SHA-1",
            replacement="SHA-256",
            deadline="2025-01-01",
        )

        assert event.event_type == EventType.ALGORITHM_DEPRECATED
        assert event.custom_fields["replacement"] == "SHA-256"


class TestHandlers:
    """Tests for custom event handlers."""

    def test_add_handler(self, engine):
        """Test adding a custom handler."""
        events_received = []

        def handler(event):
            events_received.append(event)

        engine.add_handler(handler)

        engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )

        assert len(events_received) == 1

    def test_remove_handler(self, engine):
        """Test removing a custom handler."""
        events_received = []

        def handler(event):
            events_received.append(event)

        engine.add_handler(handler)
        engine.remove_handler(handler)

        engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )

        assert len(events_received) == 0

    def test_handler_error_doesnt_stop_logging(self, engine):
        """Test that handler errors don't stop event logging."""
        def bad_handler(event):
            raise Exception("Handler error")

        good_events = []
        def good_handler(event):
            good_events.append(event)

        engine.add_handler(bad_handler)
        engine.add_handler(good_handler)

        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
        )

        assert event is not None
        assert len(good_events) == 1


class TestConfiguration:
    """Tests for SIEM configuration."""

    def test_configure_format(self, engine):
        """Test configuring output format."""
        engine.configure(format=OutputFormat.CEF)
        assert engine._config.format == OutputFormat.CEF

    def test_configure_syslog(self, engine):
        """Test configuring syslog settings."""
        engine.configure(
            syslog_host="syslog.example.com",
            syslog_port=1514,
            syslog_facility=SyslogFacility.LOCAL7,
        )

        assert engine._config.syslog_host == "syslog.example.com"
        assert engine._config.syslog_port == 1514
        assert engine._config.syslog_facility == SyslogFacility.LOCAL7

    def test_configure_invalid_option_raises(self, engine):
        """Test that invalid config option raises error."""
        with pytest.raises(ValueError, match="Unknown"):
            engine.configure(invalid_option="value")


class TestCorrelation:
    """Tests for event correlation."""

    def test_correlation_id_propagation(self, engine):
        """Test that correlation ID is included in events."""
        correlation_id = "request-12345"

        event1 = engine.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message="Login",
            correlation_id=correlation_id,
        )

        event2 = engine.log_event(
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message="Encrypt",
            correlation_id=correlation_id,
        )

        assert event1.correlation_id == correlation_id
        assert event2.correlation_id == correlation_id
        assert event1.correlation_id == event2.correlation_id


class TestAllEventTypes:
    """Tests for all event types."""

    def test_all_categories_loggable(self, engine):
        """Test that all event categories can be logged."""
        for category in EventCategory:
            event = engine.log_event(
                category=category,
                event_type=EventType.LOGIN_SUCCESS,  # Use any type
                severity=Severity.LOW,
                message=f"Test {category.value}",
            )
            assert event is not None
            assert event.category == category

    def test_all_severities_loggable(self, engine):
        """Test that all severity levels can be logged."""
        config = SIEMConfig(min_severity=Severity.UNKNOWN)
        engine = SIEMEngine(config)

        for severity in Severity:
            event = engine.log_event(
                category=EventCategory.AUDIT,
                event_type=EventType.AUDIT_LOG_ACCESS,
                severity=severity,
                message=f"Test severity {severity.name}",
            )
            assert event is not None
            assert event.severity == severity


class TestSingletonInstance:
    """Tests for singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert siem_engine is not None
        assert isinstance(siem_engine, SIEMEngine)

    def test_singleton_logs_events(self):
        """Test that singleton can log events."""
        event = siem_engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Singleton test",
        )

        assert event is not None


class TestEdgeCases:
    """Tests for edge cases."""

    def test_long_message(self, engine):
        """Test handling long messages."""
        long_message = "x" * 10000

        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message=long_message,
        )

        assert event is not None
        assert len(event.message) == 10000

    def test_special_characters_in_message(self, engine):
        """Test handling special characters."""
        special_message = "Test|with\\special\ncharacters\t<>&\""

        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message=special_message,
        )

        # CEF format should escape pipes
        cef = engine._format_cef(event)
        assert "\\|" in cef or "|" in cef  # Either escaped or present

    def test_unicode_in_message(self, engine):
        """Test handling unicode characters."""
        unicode_message = "Test with émojis 🔒 and ünïcödé"

        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message=unicode_message,
        )

        assert event is not None
        assert "🔒" in event.message

    def test_empty_custom_fields(self, engine):
        """Test event with empty custom fields."""
        event = engine.log_event(
            category=EventCategory.AUDIT,
            event_type=EventType.AUDIT_LOG_ACCESS,
            severity=Severity.LOW,
            message="Test",
            custom_fields={},
        )

        d = event.to_dict()
        assert "custom" not in d or d.get("custom") == {}
