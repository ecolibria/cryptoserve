"""Tests for lease management engine."""

import time
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.core.lease_engine import (
    LeaseEngine,
    LeaseError,
    LeaseExpiredError,
    LeaseMaxDurationError,
    LeaseNotFoundError,
    LeaseRevokedError,
    LeaseStatus,
    LeaseEventType,
    Lease,
    LeaseStats,
    lease_engine,
)


@pytest.fixture
def engine():
    """Create a fresh lease engine for testing."""
    eng = LeaseEngine(
        max_ttl_seconds=3600,  # 1 hour max
        cleanup_interval_seconds=1000,  # Disable auto-cleanup for tests
        enable_audit=True,
    )
    yield eng
    eng.shutdown()


class TestLeaseCreation:
    """Test lease creation."""

    def test_create_lease(self, engine):
        """Test creating a basic lease."""
        lease = engine.create_lease(
            secret_id="test-secret-1",
            ttl_seconds=60,
        )

        assert lease.lease_id is not None
        assert lease.secret_id == "test-secret-1"
        assert lease.status == LeaseStatus.ACTIVE
        assert lease.ttl_seconds == 60
        assert lease.renewable is True
        assert lease.renewals == 0

    def test_create_lease_with_metadata(self, engine):
        """Test creating lease with metadata."""
        metadata = {"user": "alice", "purpose": "testing"}
        lease = engine.create_lease(
            secret_id="secret-2",
            ttl_seconds=60,
            metadata=metadata,
        )

        assert lease.metadata == metadata

    def test_create_lease_with_client_id(self, engine):
        """Test creating lease with client ID."""
        lease = engine.create_lease(
            secret_id="secret-3",
            ttl_seconds=60,
            client_id="client-123",
        )

        assert lease.client_id == "client-123"

    def test_create_non_renewable_lease(self, engine):
        """Test creating non-renewable lease."""
        lease = engine.create_lease(
            secret_id="secret-4",
            ttl_seconds=60,
            renewable=False,
        )

        assert lease.renewable is False
        assert lease.can_renew is False

    def test_create_lease_with_max_renewals(self, engine):
        """Test creating lease with max renewals."""
        lease = engine.create_lease(
            secret_id="secret-5",
            ttl_seconds=60,
            max_renewals=3,
        )

        assert lease.max_renewals == 3

    def test_create_lease_exceeds_max_ttl_fails(self, engine):
        """Test that creating lease exceeding max TTL fails."""
        with pytest.raises(LeaseMaxDurationError):
            engine.create_lease(
                secret_id="secret-6",
                ttl_seconds=7200,  # 2 hours > 1 hour max
            )

    def test_create_lease_default_ttl(self, engine):
        """Test creating lease with default TTL."""
        lease = engine.create_lease(secret_id="secret-7")
        assert lease.ttl_seconds == LeaseEngine.DEFAULT_TTL

    def test_lease_id_unique(self, engine):
        """Test that lease IDs are unique."""
        lease1 = engine.create_lease(secret_id="secret-8", ttl_seconds=60)
        lease2 = engine.create_lease(secret_id="secret-8", ttl_seconds=60)

        assert lease1.lease_id != lease2.lease_id


class TestLeaseValidity:
    """Test lease validity checks."""

    def test_lease_valid_when_active(self, engine):
        """Test that active lease is valid."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        assert engine.is_lease_valid(lease.lease_id) is True

    def test_lease_invalid_when_expired(self, engine):
        """Test that expired lease is invalid."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=1)
        time.sleep(1.5)  # Wait for expiration

        assert engine.is_lease_valid(lease.lease_id) is False
        assert lease.status == LeaseStatus.EXPIRED

    def test_lease_invalid_when_revoked(self, engine):
        """Test that revoked lease is invalid."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)

        assert engine.is_lease_valid(lease.lease_id) is False

    def test_lease_invalid_when_not_found(self, engine):
        """Test that non-existent lease is invalid."""
        assert engine.is_lease_valid("nonexistent") is False


class TestLeaseAccess:
    """Test lease access."""

    def test_access_valid_lease(self, engine):
        """Test accessing valid lease."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        accessed = engine.access_lease(lease.lease_id)

        assert accessed.lease_id == lease.lease_id

    def test_access_expired_lease_raises(self, engine):
        """Test that accessing expired lease raises."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=1)
        time.sleep(1.5)

        with pytest.raises(LeaseExpiredError):
            engine.access_lease(lease.lease_id)

    def test_access_revoked_lease_raises(self, engine):
        """Test that accessing revoked lease raises."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)

        with pytest.raises(LeaseRevokedError):
            engine.access_lease(lease.lease_id)

    def test_access_nonexistent_lease_raises(self, engine):
        """Test that accessing non-existent lease raises."""
        with pytest.raises(LeaseNotFoundError):
            engine.access_lease("nonexistent")


class TestLeaseRenewal:
    """Test lease renewal."""

    def test_renew_lease(self, engine):
        """Test renewing a lease."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        original_expires = lease.expires_at

        time.sleep(0.1)  # Small delay
        renewed = engine.renew_lease(lease.lease_id)

        assert renewed.expires_at > original_expires
        assert renewed.renewals == 1
        assert renewed.last_renewed_at is not None

    def test_renew_with_increment(self, engine):
        """Test renewing with custom increment."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=30)

        renewed = engine.renew_lease(lease.lease_id, increment_seconds=120)
        assert renewed.remaining_seconds > 100

    def test_renew_non_renewable_fails(self, engine):
        """Test that renewing non-renewable lease fails."""
        lease = engine.create_lease(
            secret_id="secret",
            ttl_seconds=60,
            renewable=False,
        )

        with pytest.raises(LeaseError, match="not renewable"):
            engine.renew_lease(lease.lease_id)

    def test_renew_at_max_renewals_fails(self, engine):
        """Test that renewing at max renewals fails."""
        lease = engine.create_lease(
            secret_id="secret",
            ttl_seconds=60,
            max_renewals=2,
        )

        engine.renew_lease(lease.lease_id)
        engine.renew_lease(lease.lease_id)

        with pytest.raises(LeaseError, match="max renewals"):
            engine.renew_lease(lease.lease_id)

    def test_renew_expired_lease_fails(self, engine):
        """Test that renewing expired lease fails."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=1)
        time.sleep(1.5)

        with pytest.raises(LeaseExpiredError):
            engine.renew_lease(lease.lease_id)

    def test_renew_capped_at_max_ttl(self, engine):
        """Test that renewal is capped at max TTL."""
        # Create lease with max_ttl of 10 seconds, initial ttl of 5
        lease = engine.create_lease(
            secret_id="secret",
            ttl_seconds=5,
            max_ttl_seconds=10,
        )

        # Wait a bit, then try to renew for more than max allows
        time.sleep(3)  # 3 seconds passed, max 7 seconds remaining
        renewed = engine.renew_lease(lease.lease_id, increment_seconds=60)

        # Should be capped - remaining should be roughly 7 seconds (10 - 3)
        assert renewed.remaining_seconds <= 8


class TestLeaseRevocation:
    """Test lease revocation."""

    def test_revoke_lease(self, engine):
        """Test revoking a lease."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)

        assert lease.status == LeaseStatus.REVOKED
        assert lease.revoked_at is not None

    def test_revoke_with_reason(self, engine):
        """Test revoking with reason."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id, reason="Security incident")

        # Check audit log for reason
        events = engine.get_audit_log(lease_id=lease.lease_id)
        revoke_events = [e for e in events if e.event_type == LeaseEventType.REVOKED]
        assert len(revoke_events) == 1
        assert "Security incident" in revoke_events[0].details

    def test_revoke_nonexistent_raises(self, engine):
        """Test that revoking non-existent lease raises."""
        with pytest.raises(LeaseNotFoundError):
            engine.revoke_lease("nonexistent")

    def test_revoke_secret_leases(self, engine):
        """Test revoking all leases for a secret."""
        lease1 = engine.create_lease(secret_id="secret-x", ttl_seconds=60)
        lease2 = engine.create_lease(secret_id="secret-x", ttl_seconds=60)
        lease3 = engine.create_lease(secret_id="other-secret", ttl_seconds=60)

        count = engine.revoke_secret_leases("secret-x")

        assert count == 2
        assert lease1.status == LeaseStatus.REVOKED
        assert lease2.status == LeaseStatus.REVOKED
        assert lease3.status == LeaseStatus.ACTIVE

    def test_revocation_callback(self, engine):
        """Test revocation callback is called."""
        callback_data = []

        def callback(lease_id, secret_id):
            callback_data.append((lease_id, secret_id))

        engine.register_revocation_callback(callback)
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)

        assert len(callback_data) == 1
        assert callback_data[0] == (lease.lease_id, "secret")


class TestLeaseQueries:
    """Test lease query methods."""

    def test_get_lease(self, engine):
        """Test getting a lease by ID."""
        created = engine.create_lease(secret_id="secret", ttl_seconds=60)
        fetched = engine.get_lease(created.lease_id)

        assert fetched.lease_id == created.lease_id

    def test_get_nonexistent_raises(self, engine):
        """Test that getting non-existent lease raises."""
        with pytest.raises(LeaseNotFoundError):
            engine.get_lease("nonexistent")

    def test_get_leases_for_secret(self, engine):
        """Test getting leases for a secret."""
        engine.create_lease(secret_id="my-secret", ttl_seconds=60)
        engine.create_lease(secret_id="my-secret", ttl_seconds=60)
        engine.create_lease(secret_id="other-secret", ttl_seconds=60)

        leases = engine.get_leases_for_secret("my-secret")
        assert len(leases) == 2

    def test_get_leases_for_unknown_secret(self, engine):
        """Test getting leases for unknown secret."""
        leases = engine.get_leases_for_secret("unknown")
        assert len(leases) == 0

    def test_get_active_leases(self, engine):
        """Test getting active leases."""
        engine.create_lease(secret_id="s1", ttl_seconds=60)
        engine.create_lease(secret_id="s2", ttl_seconds=60)
        lease3 = engine.create_lease(secret_id="s3", ttl_seconds=60)
        engine.revoke_lease(lease3.lease_id)

        active = engine.get_active_leases()
        assert len(active) == 2


class TestLeaseProperties:
    """Test Lease properties."""

    def test_is_expired_property(self, engine):
        """Test is_expired property."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=1)
        assert lease.is_expired is False

        time.sleep(1.5)
        assert lease.is_expired is True

    def test_remaining_seconds_property(self, engine):
        """Test remaining_seconds property."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        assert 55 <= lease.remaining_seconds <= 60

        # After expiration
        expired = engine.create_lease(secret_id="secret2", ttl_seconds=1)
        time.sleep(1.5)
        assert expired.remaining_seconds == 0

    def test_can_renew_property(self, engine):
        """Test can_renew property."""
        renewable = engine.create_lease(
            secret_id="s1", ttl_seconds=60, renewable=True
        )
        assert renewable.can_renew is True

        non_renewable = engine.create_lease(
            secret_id="s2", ttl_seconds=60, renewable=False
        )
        assert non_renewable.can_renew is False


class TestLeaseStats:
    """Test lease statistics."""

    def test_stats_track_creations(self, engine):
        """Test stats track lease creations."""
        initial = engine.get_stats()
        engine.create_lease(secret_id="s1", ttl_seconds=60)
        engine.create_lease(secret_id="s2", ttl_seconds=60)

        stats = engine.get_stats()
        assert stats.total_leases_created == initial.total_leases_created + 2
        assert stats.active_leases == initial.active_leases + 2

    def test_stats_track_expirations(self, engine):
        """Test stats track expirations."""
        lease = engine.create_lease(secret_id="s", ttl_seconds=1)
        initial = engine.get_stats()

        time.sleep(1.5)
        engine.is_lease_valid(lease.lease_id)  # Trigger expiration check

        stats = engine.get_stats()
        assert stats.expired_leases == initial.expired_leases + 1
        assert stats.active_leases == initial.active_leases - 1

    def test_stats_track_revocations(self, engine):
        """Test stats track revocations."""
        lease = engine.create_lease(secret_id="s", ttl_seconds=60)
        initial = engine.get_stats()

        engine.revoke_lease(lease.lease_id)

        stats = engine.get_stats()
        assert stats.revoked_leases == initial.revoked_leases + 1

    def test_stats_track_renewals(self, engine):
        """Test stats track renewals."""
        lease = engine.create_lease(secret_id="s", ttl_seconds=60)
        initial = engine.get_stats()

        engine.renew_lease(lease.lease_id)
        engine.renew_lease(lease.lease_id)

        stats = engine.get_stats()
        assert stats.total_renewals == initial.total_renewals + 2

    def test_stats_peak_active(self, engine):
        """Test stats track peak active leases."""
        lease1 = engine.create_lease(secret_id="s1", ttl_seconds=60)
        lease2 = engine.create_lease(secret_id="s2", ttl_seconds=60)
        lease3 = engine.create_lease(secret_id="s3", ttl_seconds=60)

        peak = engine.get_stats().peak_active_leases

        engine.revoke_lease(lease1.lease_id)
        engine.revoke_lease(lease2.lease_id)

        # Peak should remain unchanged
        assert engine.get_stats().peak_active_leases == peak


class TestAuditLog:
    """Test audit logging."""

    def test_audit_creation(self, engine):
        """Test audit logs creation."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        events = engine.get_audit_log(lease_id=lease.lease_id)

        create_events = [e for e in events if e.event_type == LeaseEventType.CREATED]
        assert len(create_events) == 1

    def test_audit_access(self, engine):
        """Test audit logs access."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.access_lease(lease.lease_id)

        events = engine.get_audit_log(lease_id=lease.lease_id)
        access_events = [e for e in events if e.event_type == LeaseEventType.ACCESSED]
        assert len(access_events) >= 1

    def test_audit_renewal(self, engine):
        """Test audit logs renewal."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.renew_lease(lease.lease_id)

        events = engine.get_audit_log(lease_id=lease.lease_id)
        renew_events = [e for e in events if e.event_type == LeaseEventType.RENEWED]
        assert len(renew_events) == 1

    def test_audit_revocation(self, engine):
        """Test audit logs revocation."""
        lease = engine.create_lease(secret_id="secret", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)

        events = engine.get_audit_log(lease_id=lease.lease_id)
        revoke_events = [e for e in events if e.event_type == LeaseEventType.REVOKED]
        assert len(revoke_events) == 1

    def test_audit_filter_by_type(self, engine):
        """Test filtering audit log by event type."""
        engine.create_lease(secret_id="s1", ttl_seconds=60)
        engine.create_lease(secret_id="s2", ttl_seconds=60)

        events = engine.get_audit_log(event_type=LeaseEventType.CREATED, limit=100)
        assert all(e.event_type == LeaseEventType.CREATED for e in events)

    def test_audit_limit(self, engine):
        """Test audit log limit."""
        for i in range(10):
            engine.create_lease(secret_id=f"s{i}", ttl_seconds=60)

        events = engine.get_audit_log(limit=5)
        assert len(events) == 5


class TestSingletonInstance:
    """Test singleton instance."""

    def test_singleton_exists(self):
        """Test singleton instance exists."""
        assert lease_engine is not None
        assert isinstance(lease_engine, LeaseEngine)

    def test_singleton_creates_leases(self):
        """Test singleton can create leases."""
        lease = lease_engine.create_lease(
            secret_id="singleton-test",
            ttl_seconds=60,
        )
        assert lease is not None
        lease_engine.revoke_lease(lease.lease_id)


class TestConcurrency:
    """Test thread safety."""

    def test_concurrent_lease_creation(self, engine):
        """Test concurrent lease creation."""
        errors = []
        leases = []
        lock = threading.Lock()

        def create_lease(i):
            try:
                lease = engine.create_lease(
                    secret_id=f"secret-{i}",
                    ttl_seconds=60,
                )
                with lock:
                    leases.append(lease)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=create_lease, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(leases) == 20

        # All lease IDs should be unique
        lease_ids = [l.lease_id for l in leases]
        assert len(set(lease_ids)) == 20

    def test_concurrent_access_and_renew(self, engine):
        """Test concurrent access and renewal."""
        lease = engine.create_lease(secret_id="shared", ttl_seconds=60)
        errors = []

        def access_lease():
            try:
                for _ in range(10):
                    engine.is_lease_valid(lease.lease_id)
            except Exception as e:
                errors.append(e)

        def renew_lease():
            try:
                for _ in range(5):
                    engine.renew_lease(lease.lease_id)
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=access_lease))
            threads.append(threading.Thread(target=renew_lease))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Filter out expected errors (max renewals could be hit in race)
        unexpected_errors = [e for e in errors if not isinstance(e, LeaseError)]
        assert len(unexpected_errors) == 0


class TestEdgeCases:
    """Test edge cases."""

    def test_very_short_ttl(self, engine):
        """Test very short TTL lease."""
        lease = engine.create_lease(secret_id="short", ttl_seconds=1)
        assert lease.remaining_seconds <= 1

    def test_lease_with_empty_metadata(self, engine):
        """Test lease with empty metadata."""
        lease = engine.create_lease(
            secret_id="meta",
            ttl_seconds=60,
            metadata={},
        )
        assert lease.metadata == {}

    def test_multiple_revoke_calls(self, engine):
        """Test multiple revoke calls on same lease."""
        lease = engine.create_lease(secret_id="multi", ttl_seconds=60)
        engine.revoke_lease(lease.lease_id)
        engine.revoke_lease(lease.lease_id)  # Should not error

        assert lease.status == LeaseStatus.REVOKED

    def test_revoke_nonexistent_secret(self, engine):
        """Test revoking leases for non-existent secret."""
        count = engine.revoke_secret_leases("nonexistent-secret")
        assert count == 0
