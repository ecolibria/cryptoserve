"""Lease Management Engine for Time-Limited Secrets.

Provides time-limited access to secrets with automatic expiration,
renewal, and revocation capabilities.

Features:
- Time-limited secret access (TTL-based leases)
- Automatic expiration and cleanup
- Lease renewal and extension
- Immediate revocation
- Audit logging for compliance
- Maximum lease duration policies

Use Cases:
- Dynamic database credentials
- Temporary API tokens
- Short-lived certificates
- Ephemeral encryption keys
- Session-bound secrets

Security Properties:
- Secrets automatically expire
- Cannot exceed maximum duration
- Revocation takes immediate effect
- Full audit trail

References:
- HashiCorp Vault lease concepts
- AWS STS temporary credentials
- NIST SP 800-57 key management
"""

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid


class LeaseError(Exception):
    """Lease management error."""

    pass


class LeaseExpiredError(LeaseError):
    """Lease has expired."""

    pass


class LeaseNotFoundError(LeaseError):
    """Lease not found."""

    pass


class LeaseRevokedError(LeaseError):
    """Lease has been revoked."""

    pass


class LeaseMaxDurationError(LeaseError):
    """Lease exceeds maximum allowed duration."""

    pass


class LeaseStatus(str, Enum):
    """Status of a lease."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    RENEWED = "renewed"


class LeaseEventType(str, Enum):
    """Type of lease event for audit logging."""

    CREATED = "created"
    ACCESSED = "accessed"
    RENEWED = "renewed"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class LeaseEvent:
    """An audit event for a lease."""

    event_type: LeaseEventType
    lease_id: str
    timestamp: datetime
    details: Optional[str] = None
    client_id: Optional[str] = None


@dataclass
class Lease:
    """A lease for time-limited secret access."""

    lease_id: str
    secret_id: str
    created_at: datetime
    expires_at: datetime
    ttl_seconds: int
    max_ttl_seconds: int
    renewable: bool
    status: LeaseStatus = LeaseStatus.ACTIVE
    renewals: int = 0
    max_renewals: int = 0  # 0 = unlimited
    last_renewed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    client_id: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        """Check if lease has expired."""
        if self.status in (LeaseStatus.EXPIRED, LeaseStatus.REVOKED):
            return True
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def remaining_seconds(self) -> int:
        """Get remaining seconds before expiration."""
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, int(delta.total_seconds()))

    @property
    def can_renew(self) -> bool:
        """Check if lease can be renewed."""
        if not self.renewable:
            return False
        if self.status != LeaseStatus.ACTIVE:
            return False
        if self.max_renewals > 0 and self.renewals >= self.max_renewals:
            return False
        return True


@dataclass
class LeaseStats:
    """Statistics about lease management."""

    total_leases_created: int = 0
    active_leases: int = 0
    expired_leases: int = 0
    revoked_leases: int = 0
    total_renewals: int = 0
    peak_active_leases: int = 0


class LeaseEngine:
    """Engine for managing time-limited secret access.

    Usage:
        engine = LeaseEngine()

        # Create a lease for a secret (60 second TTL)
        lease = engine.create_lease(
            secret_id="db-password-123",
            ttl_seconds=60,
            renewable=True,
        )

        # Access the secret (checks lease validity)
        if engine.is_lease_valid(lease.lease_id):
            secret = get_secret(lease.secret_id)

        # Renew before expiration
        engine.renew_lease(lease.lease_id, increment_seconds=60)

        # Revoke when done
        engine.revoke_lease(lease.lease_id)
    """

    # Default maximum TTL (24 hours)
    DEFAULT_MAX_TTL = 24 * 60 * 60

    # Default TTL (1 hour)
    DEFAULT_TTL = 60 * 60

    def __init__(
        self,
        max_ttl_seconds: int = DEFAULT_MAX_TTL,
        cleanup_interval_seconds: int = 60,
        enable_audit: bool = True,
    ):
        """Initialize lease engine.

        Args:
            max_ttl_seconds: Maximum allowed lease duration
            cleanup_interval_seconds: Interval for expired lease cleanup
            enable_audit: Enable audit logging
        """
        self._lock = threading.RLock()
        self._leases: Dict[str, Lease] = {}
        self._secret_leases: Dict[str, Set[str]] = {}  # secret_id -> lease_ids
        self._audit_log: List[LeaseEvent] = []
        self._stats = LeaseStats()

        self._max_ttl = max_ttl_seconds
        self._cleanup_interval = cleanup_interval_seconds
        self._enable_audit = enable_audit

        # Revocation callbacks
        self._revocation_callbacks: List[Callable[[str, str], None]] = []

        # Start cleanup thread
        self._shutdown = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def create_lease(
        self,
        secret_id: str,
        ttl_seconds: Optional[int] = None,
        max_ttl_seconds: Optional[int] = None,
        renewable: bool = True,
        max_renewals: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
        client_id: Optional[str] = None,
    ) -> Lease:
        """Create a new lease for a secret.

        Args:
            secret_id: ID of the secret to lease
            ttl_seconds: Time-to-live in seconds (default: 1 hour)
            max_ttl_seconds: Maximum TTL even with renewals
            renewable: Whether the lease can be renewed
            max_renewals: Maximum number of renewals (0 = unlimited)
            metadata: Additional metadata to store
            client_id: Optional client identifier

        Returns:
            The created Lease

        Raises:
            LeaseMaxDurationError: If TTL exceeds maximum
        """
        ttl = ttl_seconds or self.DEFAULT_TTL
        max_ttl = max_ttl_seconds or self._max_ttl

        if ttl > max_ttl:
            raise LeaseMaxDurationError(
                f"TTL {ttl}s exceeds maximum {max_ttl}s"
            )

        if max_ttl > self._max_ttl:
            raise LeaseMaxDurationError(
                f"Max TTL {max_ttl}s exceeds system maximum {self._max_ttl}s"
            )

        now = datetime.now(timezone.utc)
        lease_id = self._generate_lease_id()

        lease = Lease(
            lease_id=lease_id,
            secret_id=secret_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            ttl_seconds=ttl,
            max_ttl_seconds=max_ttl,
            renewable=renewable,
            max_renewals=max_renewals,
            metadata=metadata or {},
            client_id=client_id,
        )

        with self._lock:
            self._leases[lease_id] = lease

            if secret_id not in self._secret_leases:
                self._secret_leases[secret_id] = set()
            self._secret_leases[secret_id].add(lease_id)

            self._stats.total_leases_created += 1
            self._stats.active_leases += 1
            self._stats.peak_active_leases = max(
                self._stats.peak_active_leases,
                self._stats.active_leases,
            )

            self._audit(LeaseEventType.CREATED, lease_id, "Lease created", client_id)

        return lease

    def get_lease(self, lease_id: str) -> Lease:
        """Get a lease by ID.

        Args:
            lease_id: The lease ID

        Returns:
            The Lease

        Raises:
            LeaseNotFoundError: If lease doesn't exist
        """
        with self._lock:
            if lease_id not in self._leases:
                raise LeaseNotFoundError(f"Lease not found: {lease_id}")
            return self._leases[lease_id]

    def is_lease_valid(self, lease_id: str) -> bool:
        """Check if a lease is still valid.

        Args:
            lease_id: The lease ID

        Returns:
            True if lease is active and not expired
        """
        with self._lock:
            if lease_id not in self._leases:
                return False

            lease = self._leases[lease_id]

            if lease.status != LeaseStatus.ACTIVE:
                return False

            if lease.is_expired:
                # Mark as expired
                self._expire_lease(lease)
                return False

            self._audit(
                LeaseEventType.ACCESSED,
                lease_id,
                "Lease validity checked",
                lease.client_id,
            )
            return True

    def access_lease(self, lease_id: str) -> Lease:
        """Access a lease, verifying it's still valid.

        Args:
            lease_id: The lease ID

        Returns:
            The valid Lease

        Raises:
            LeaseNotFoundError: If lease doesn't exist
            LeaseExpiredError: If lease has expired
            LeaseRevokedError: If lease was revoked
        """
        with self._lock:
            if lease_id not in self._leases:
                raise LeaseNotFoundError(f"Lease not found: {lease_id}")

            lease = self._leases[lease_id]

            if lease.status == LeaseStatus.REVOKED:
                raise LeaseRevokedError(f"Lease was revoked: {lease_id}")

            if lease.status == LeaseStatus.EXPIRED or lease.is_expired:
                if lease.status != LeaseStatus.EXPIRED:
                    self._expire_lease(lease)
                raise LeaseExpiredError(f"Lease has expired: {lease_id}")

            self._audit(
                LeaseEventType.ACCESSED,
                lease_id,
                "Lease accessed",
                lease.client_id,
            )
            return lease

    def renew_lease(
        self,
        lease_id: str,
        increment_seconds: Optional[int] = None,
    ) -> Lease:
        """Renew a lease to extend its lifetime.

        Args:
            lease_id: The lease ID
            increment_seconds: TTL to add (default: original TTL)

        Returns:
            The renewed Lease

        Raises:
            LeaseNotFoundError: If lease doesn't exist
            LeaseExpiredError: If lease has already expired
            LeaseError: If lease is not renewable
            LeaseMaxDurationError: If renewal would exceed max TTL
        """
        with self._lock:
            if lease_id not in self._leases:
                raise LeaseNotFoundError(f"Lease not found: {lease_id}")

            lease = self._leases[lease_id]

            if lease.is_expired:
                if lease.status == LeaseStatus.ACTIVE:
                    self._expire_lease(lease)
                raise LeaseExpiredError(f"Lease has expired: {lease_id}")

            if not lease.can_renew:
                if not lease.renewable:
                    raise LeaseError(f"Lease is not renewable: {lease_id}")
                if lease.max_renewals > 0 and lease.renewals >= lease.max_renewals:
                    raise LeaseError(
                        f"Lease has reached max renewals ({lease.max_renewals}): {lease_id}"
                    )
                raise LeaseError(f"Lease cannot be renewed: {lease_id}")

            # Calculate new expiration
            increment = increment_seconds or lease.ttl_seconds
            now = datetime.now(timezone.utc)
            new_expires = now + timedelta(seconds=increment)

            # Check against max TTL from creation
            max_expires = lease.created_at + timedelta(seconds=lease.max_ttl_seconds)
            if new_expires > max_expires:
                # Cap at max TTL
                new_expires = max_expires
                if new_expires <= now:
                    raise LeaseMaxDurationError(
                        f"Lease has reached maximum lifetime: {lease_id}"
                    )

            # Apply renewal
            lease.expires_at = new_expires
            lease.last_renewed_at = now
            lease.renewals += 1
            lease.status = LeaseStatus.ACTIVE

            self._stats.total_renewals += 1

            self._audit(
                LeaseEventType.RENEWED,
                lease_id,
                f"Renewed for {increment}s (renewal #{lease.renewals})",
                lease.client_id,
            )

            return lease

    def revoke_lease(self, lease_id: str, reason: Optional[str] = None) -> None:
        """Immediately revoke a lease.

        Args:
            lease_id: The lease ID
            reason: Optional reason for revocation

        Raises:
            LeaseNotFoundError: If lease doesn't exist
        """
        with self._lock:
            if lease_id not in self._leases:
                raise LeaseNotFoundError(f"Lease not found: {lease_id}")

            lease = self._leases[lease_id]

            if lease.status != LeaseStatus.REVOKED:
                lease.status = LeaseStatus.REVOKED
                lease.revoked_at = datetime.now(timezone.utc)

                if lease.status == LeaseStatus.ACTIVE:
                    self._stats.active_leases -= 1
                self._stats.revoked_leases += 1

                # Call revocation callbacks
                for callback in self._revocation_callbacks:
                    try:
                        callback(lease_id, lease.secret_id)
                    except Exception:
                        pass  # Don't let callbacks break revocation

            self._audit(
                LeaseEventType.REVOKED,
                lease_id,
                reason or "Lease revoked",
                lease.client_id,
            )

    def revoke_secret_leases(self, secret_id: str, reason: Optional[str] = None) -> int:
        """Revoke all leases for a secret.

        Args:
            secret_id: The secret ID
            reason: Optional reason for revocation

        Returns:
            Number of leases revoked
        """
        with self._lock:
            if secret_id not in self._secret_leases:
                return 0

            lease_ids = list(self._secret_leases[secret_id])
            count = 0

            for lease_id in lease_ids:
                try:
                    self.revoke_lease(lease_id, reason)
                    count += 1
                except LeaseNotFoundError:
                    pass

            return count

    def get_leases_for_secret(self, secret_id: str) -> List[Lease]:
        """Get all leases for a secret.

        Args:
            secret_id: The secret ID

        Returns:
            List of leases
        """
        with self._lock:
            if secret_id not in self._secret_leases:
                return []

            leases = []
            for lease_id in self._secret_leases[secret_id]:
                if lease_id in self._leases:
                    leases.append(self._leases[lease_id])

            return leases

    def get_active_leases(self) -> List[Lease]:
        """Get all active leases.

        Returns:
            List of active leases
        """
        with self._lock:
            return [
                lease
                for lease in self._leases.values()
                if lease.status == LeaseStatus.ACTIVE and not lease.is_expired
            ]

    def get_stats(self) -> LeaseStats:
        """Get lease statistics.

        Returns:
            Current statistics
        """
        with self._lock:
            return LeaseStats(
                total_leases_created=self._stats.total_leases_created,
                active_leases=self._stats.active_leases,
                expired_leases=self._stats.expired_leases,
                revoked_leases=self._stats.revoked_leases,
                total_renewals=self._stats.total_renewals,
                peak_active_leases=self._stats.peak_active_leases,
            )

    def get_audit_log(
        self,
        lease_id: Optional[str] = None,
        event_type: Optional[LeaseEventType] = None,
        limit: int = 100,
    ) -> List[LeaseEvent]:
        """Get audit log entries.

        Args:
            lease_id: Filter by lease ID
            event_type: Filter by event type
            limit: Maximum entries to return

        Returns:
            List of audit events (newest first)
        """
        with self._lock:
            events = self._audit_log

            if lease_id:
                events = [e for e in events if e.lease_id == lease_id]

            if event_type:
                events = [e for e in events if e.event_type == event_type]

            # Return newest first
            return list(reversed(events[-limit:]))

    def register_revocation_callback(
        self,
        callback: Callable[[str, str], None],
    ) -> None:
        """Register a callback for lease revocation.

        Callback receives (lease_id, secret_id).

        Args:
            callback: Function to call on revocation
        """
        self._revocation_callbacks.append(callback)

    def shutdown(self) -> None:
        """Shutdown the lease engine and cleanup thread."""
        self._shutdown.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)

    def _generate_lease_id(self) -> str:
        """Generate a unique lease ID."""
        random_bytes = secrets.token_bytes(16)
        timestamp = int(time.time() * 1000)
        combined = random_bytes + timestamp.to_bytes(8, "big")
        return f"lease_{hashlib.sha256(combined).hexdigest()[:24]}"

    def _expire_lease(self, lease: Lease) -> None:
        """Mark a lease as expired."""
        if lease.status == LeaseStatus.ACTIVE:
            lease.status = LeaseStatus.EXPIRED
            self._stats.active_leases -= 1
            self._stats.expired_leases += 1

            self._audit(
                LeaseEventType.EXPIRED,
                lease.lease_id,
                "Lease expired",
                lease.client_id,
            )

    def _audit(
        self,
        event_type: LeaseEventType,
        lease_id: str,
        details: str,
        client_id: Optional[str],
    ) -> None:
        """Record an audit event."""
        if not self._enable_audit:
            return

        event = LeaseEvent(
            event_type=event_type,
            lease_id=lease_id,
            timestamp=datetime.now(timezone.utc),
            details=details,
            client_id=client_id,
        )
        self._audit_log.append(event)

        # Limit audit log size
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]

    def _cleanup_loop(self) -> None:
        """Background thread to cleanup expired leases."""
        while not self._shutdown.wait(self._cleanup_interval):
            self._cleanup_expired()

    def _cleanup_expired(self) -> None:
        """Cleanup expired leases."""
        with self._lock:
            now = datetime.now(timezone.utc)
            for lease in list(self._leases.values()):
                if lease.status == LeaseStatus.ACTIVE and lease.is_expired:
                    self._expire_lease(lease)


# Singleton instance
lease_engine = LeaseEngine()
