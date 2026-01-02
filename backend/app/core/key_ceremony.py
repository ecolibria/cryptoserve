"""Key Ceremony and Master Key Sharding Service.

Implements enterprise-grade key protection through:
1. Master key sharding using Shamir's Secret Sharing
2. Key custodian management
3. Sealed/Unsealed state (like HashiCorp Vault)
4. Key ceremony workflows for secure key generation

Use Cases:
- Initial deployment: Generate and distribute master key shares
- Disaster recovery: Reconstruct master key from custodian shares
- Key rotation: Generate new shares without downtime
- Compliance: SOC2, PCI-DSS, FedRAMP key splitting requirements

Security Model:
- No single person can access the master key alone
- Threshold of custodians required to unseal
- Audit trail for all key ceremonies
- Shares can be stored in separate geographic locations
"""

import secrets
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from app.core.secret_sharing_engine import SecretSharingEngine, Share, SecretSharingError

logger = logging.getLogger(__name__)


class CeremonyState(str, Enum):
    """State of the key ceremony/service."""
    UNINITIALIZED = "uninitialized"  # No master key exists
    SEALED = "sealed"                 # Master key exists but locked
    UNSEALING = "unsealing"           # Collecting shares to unseal
    UNSEALED = "unsealed"             # Service is operational


class CeremonyError(Exception):
    """Key ceremony operation failed."""
    pass


class AlreadyInitializedError(CeremonyError):
    """Master key already initialized."""
    pass


class NotInitializedError(CeremonyError):
    """Master key not yet initialized."""
    pass


class AlreadySealedError(CeremonyError):
    """Service is already sealed."""
    pass


class AlreadyUnsealedError(CeremonyError):
    """Service is already unsealed."""
    pass


class InvalidShareError(CeremonyError):
    """Invalid or incorrect share provided."""
    pass


class InsufficientSharesError(CeremonyError):
    """Not enough shares to unseal."""
    pass


@dataclass
class KeyCustodian:
    """A key custodian who holds a share."""
    id: str
    name: str
    email: str
    share_index: int
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: Optional[datetime] = None


@dataclass
class CeremonyAuditEvent:
    """Audit event for key ceremony."""
    timestamp: datetime
    event_type: str
    actor: str
    details: dict


@dataclass
class InitializationResult:
    """Result of master key initialization."""
    recovery_shares: list[str]  # Hex-encoded shares
    root_token: str            # Initial root token for setup
    threshold: int
    total_shares: int
    share_fingerprints: list[str]  # SHA-256 fingerprints for verification


@dataclass
class UnsealProgress:
    """Progress toward unsealing."""
    shares_provided: int
    shares_required: int
    is_sealed: bool
    progress_percent: float


class KeyCeremonyService:
    """Manages master key ceremonies and seal/unseal operations.

    This service implements the Vault-style seal/unseal pattern:

    1. UNINITIALIZED: First run - no master key exists
       -> Call initialize() to generate master key and shares

    2. SEALED: Master key exists but is encrypted
       -> Call unseal(share) repeatedly until threshold reached

    3. UNSEALING: Collecting shares toward threshold
       -> Continue calling unseal(share)

    4. UNSEALED: Service is operational
       -> Call seal() to lock the service

    Usage:
        ceremony = KeyCeremonyService()

        # First-time initialization
        result = ceremony.initialize(
            threshold=3,
            total_shares=5,
            custodians=["alice@corp.com", "bob@corp.com", ...]
        )
        # Distribute result.recovery_shares to custodians

        # After restart (sealed state)
        ceremony.unseal(share1)  # Returns progress
        ceremony.unseal(share2)  # Returns progress
        ceremony.unseal(share3)  # Unsealed!

        # To lock the service
        ceremony.seal()
    """

    def __init__(self):
        self._engine = SecretSharingEngine()
        self._state = CeremonyState.UNINITIALIZED
        self._master_key: Optional[bytes] = None
        self._threshold: int = 0
        self._total_shares: int = 0
        self._pending_shares: list[Share] = []
        self._custodians: dict[int, KeyCustodian] = {}
        self._audit_log: list[CeremonyAuditEvent] = []
        self._share_fingerprints: list[str] = []

        # For persistence (would be stored encrypted in production)
        self._encrypted_master_key: Optional[bytes] = None
        self._key_salt: Optional[bytes] = None

    @property
    def state(self) -> CeremonyState:
        """Current ceremony state."""
        return self._state

    @property
    def is_sealed(self) -> bool:
        """Check if service is sealed."""
        return self._state in (CeremonyState.SEALED, CeremonyState.UNSEALING)

    @property
    def is_initialized(self) -> bool:
        """Check if master key has been initialized."""
        return self._state != CeremonyState.UNINITIALIZED

    def _log_event(self, event_type: str, actor: str, details: dict):
        """Add audit event."""
        event = CeremonyAuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            actor=actor,
            details=details,
        )
        self._audit_log.append(event)
        logger.info(f"Key ceremony event: {event_type} by {actor}")

    def _compute_share_fingerprint(self, share: Share) -> str:
        """Compute SHA-256 fingerprint of a share for verification."""
        return hashlib.sha256(share.to_bytes()).hexdigest()[:16]

    def initialize(
        self,
        threshold: int,
        total_shares: int,
        custodian_emails: Optional[list[str]] = None,
        actor: str = "system",
    ) -> InitializationResult:
        """Initialize the master key and generate recovery shares.

        This should only be called once during initial setup.
        The recovery shares must be securely distributed to custodians.

        Args:
            threshold: Minimum shares needed to unseal (k)
            total_shares: Total shares to generate (n)
            custodian_emails: Optional list of custodian emails
            actor: Who is performing the ceremony

        Returns:
            InitializationResult with shares and root token

        Raises:
            AlreadyInitializedError: If already initialized
            CeremonyError: If parameters are invalid
        """
        if self._state != CeremonyState.UNINITIALIZED:
            raise AlreadyInitializedError(
                "Master key already initialized. Use rotate_master_key() to change it."
            )

        if threshold < 2:
            raise CeremonyError("Threshold must be at least 2")
        if total_shares < threshold:
            raise CeremonyError("Total shares must be >= threshold")
        if threshold > 10:
            raise CeremonyError("Threshold cannot exceed 10 (practical limit)")
        if total_shares > 20:
            raise CeremonyError("Total shares cannot exceed 20 (practical limit)")

        # Generate cryptographically secure master key
        master_key = secrets.token_bytes(32)  # 256-bit key

        # Split into shares
        shares = self._engine.split(
            secret=master_key,
            threshold=threshold,
            total_shares=total_shares,
        )

        # Compute fingerprints for each share
        fingerprints = [self._compute_share_fingerprint(s) for s in shares]

        # Create custodians if emails provided
        if custodian_emails and len(custodian_emails) >= total_shares:
            for i, (share, email) in enumerate(zip(shares, custodian_emails)):
                custodian = KeyCustodian(
                    id=f"custodian_{i+1}",
                    name=email.split("@")[0],
                    email=email,
                    share_index=share.x,
                )
                self._custodians[share.x] = custodian

        # Generate root token for initial setup
        root_token = secrets.token_urlsafe(32)

        # Store encrypted master key (in production, this would go to secure storage)
        self._master_key = master_key
        self._threshold = threshold
        self._total_shares = total_shares
        self._share_fingerprints = fingerprints

        # Start in unsealed state for initial configuration
        self._state = CeremonyState.UNSEALED

        self._log_event(
            "initialize",
            actor,
            {
                "threshold": threshold,
                "total_shares": total_shares,
                "custodians": len(self._custodians),
            }
        )

        return InitializationResult(
            recovery_shares=[s.to_hex() for s in shares],
            root_token=root_token,
            threshold=threshold,
            total_shares=total_shares,
            share_fingerprints=fingerprints,
        )

    def seal(self, actor: str = "system") -> None:
        """Seal the service, requiring unseal to access master key.

        Args:
            actor: Who is sealing the service

        Raises:
            AlreadySealedError: If already sealed
            NotInitializedError: If not initialized
        """
        if self._state == CeremonyState.UNINITIALIZED:
            raise NotInitializedError("Cannot seal uninitialized service")

        if self._state in (CeremonyState.SEALED, CeremonyState.UNSEALING):
            raise AlreadySealedError("Service is already sealed")

        # Clear master key from memory
        if self._master_key:
            # Securely clear the key (in Python, this is best-effort)
            self._master_key = None

        self._pending_shares = []
        self._state = CeremonyState.SEALED

        self._log_event("seal", actor, {})

    def unseal(self, share_hex: str, actor: str = "unknown") -> UnsealProgress:
        """Provide a share toward unsealing.

        Call repeatedly with different shares until threshold is reached.

        Args:
            share_hex: Hex-encoded share from a custodian
            actor: Who is providing the share

        Returns:
            UnsealProgress with current progress

        Raises:
            NotInitializedError: If not initialized
            AlreadyUnsealedError: If already unsealed
            InvalidShareError: If share is invalid
        """
        if self._state == CeremonyState.UNINITIALIZED:
            raise NotInitializedError("Service not initialized")

        if self._state == CeremonyState.UNSEALED:
            raise AlreadyUnsealedError("Service is already unsealed")

        # Parse and validate share
        try:
            share = Share.from_hex(share_hex)
        except Exception as e:
            raise InvalidShareError(f"Invalid share format: {e}")

        # Check share parameters match
        if share.threshold != self._threshold or share.total != self._total_shares:
            raise InvalidShareError(
                "Share parameters don't match (different ceremony?)"
            )

        # Check for duplicate
        if any(s.x == share.x for s in self._pending_shares):
            raise InvalidShareError(f"Share {share.x} already provided")

        # Verify share fingerprint
        fingerprint = self._compute_share_fingerprint(share)
        if fingerprint not in self._share_fingerprints:
            raise InvalidShareError("Share fingerprint verification failed")

        # Add share
        self._pending_shares.append(share)
        self._state = CeremonyState.UNSEALING

        # Update custodian last used
        if share.x in self._custodians:
            self._custodians[share.x].last_used_at = datetime.now(timezone.utc)

        self._log_event(
            "unseal_share",
            actor,
            {
                "share_index": share.x,
                "shares_provided": len(self._pending_shares),
                "shares_required": self._threshold,
            }
        )

        # Check if threshold reached
        if len(self._pending_shares) >= self._threshold:
            try:
                self._master_key = self._engine.combine(self._pending_shares)
                self._state = CeremonyState.UNSEALED
                self._pending_shares = []

                self._log_event("unseal_complete", actor, {})

                logger.info("Service successfully unsealed")
            except SecretSharingError as e:
                # Shares didn't combine correctly
                self._pending_shares = []
                self._state = CeremonyState.SEALED
                raise InvalidShareError(f"Shares failed to combine: {e}")

        return UnsealProgress(
            shares_provided=len(self._pending_shares) if self._state == CeremonyState.UNSEALING else 0,
            shares_required=self._threshold,
            is_sealed=self.is_sealed,
            progress_percent=(
                len(self._pending_shares) / self._threshold * 100
                if self._state == CeremonyState.UNSEALING else
                (0 if self.is_sealed else 100)
            ),
        )

    def get_master_key(self) -> bytes:
        """Get the master key (only when unsealed).

        Returns:
            The master key bytes

        Raises:
            NotInitializedError: If not initialized
            CeremonyError: If service is sealed
        """
        if self._state == CeremonyState.UNINITIALIZED:
            raise NotInitializedError("Service not initialized")

        if self._state != CeremonyState.UNSEALED:
            raise CeremonyError("Service is sealed - unseal required")

        if not self._master_key:
            raise CeremonyError("Master key not available")

        return self._master_key

    def get_unseal_progress(self) -> UnsealProgress:
        """Get current unseal progress.

        Returns:
            Current progress toward unsealing
        """
        return UnsealProgress(
            shares_provided=len(self._pending_shares),
            shares_required=self._threshold,
            is_sealed=self.is_sealed,
            progress_percent=(
                len(self._pending_shares) / self._threshold * 100
                if self._threshold > 0 and self._state == CeremonyState.UNSEALING
                else (0 if self.is_sealed else 100)
            ),
        )

    def reset_unseal_progress(self, actor: str = "system") -> None:
        """Reset unseal progress (clear pending shares).

        Useful if incorrect shares were provided.

        Args:
            actor: Who is resetting
        """
        self._pending_shares = []
        if self._state == CeremonyState.UNSEALING:
            self._state = CeremonyState.SEALED

        self._log_event("reset_unseal", actor, {})

    def get_status(self) -> dict:
        """Get ceremony status.

        Returns:
            Status dict with state and configuration
        """
        return {
            "state": self._state.value,
            "is_initialized": self.is_initialized,
            "is_sealed": self.is_sealed,
            "threshold": self._threshold,
            "total_shares": self._total_shares,
            "custodians": len(self._custodians),
            "unseal_progress": self.get_unseal_progress().__dict__ if self._state == CeremonyState.UNSEALING else None,
        }

    def get_custodians(self) -> list[dict]:
        """Get list of custodians (without share data).

        Returns:
            List of custodian info dicts
        """
        return [
            {
                "id": c.id,
                "name": c.name,
                "email": c.email,
                "share_index": c.share_index,
                "created_at": c.created_at.isoformat(),
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in self._custodians.values()
        ]

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        """Get recent audit events.

        Args:
            limit: Maximum events to return

        Returns:
            List of audit event dicts
        """
        events = self._audit_log[-limit:]
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "actor": e.actor,
                "details": e.details,
            }
            for e in events
        ]

    def verify_share(self, share_hex: str) -> dict:
        """Verify a share is valid without using it.

        Args:
            share_hex: Hex-encoded share to verify

        Returns:
            Verification result dict
        """
        try:
            share = Share.from_hex(share_hex)

            # Check parameters
            params_match = (
                share.threshold == self._threshold and
                share.total == self._total_shares
            )

            # Check fingerprint
            fingerprint = self._compute_share_fingerprint(share)
            fingerprint_valid = fingerprint in self._share_fingerprints

            return {
                "valid": params_match and fingerprint_valid,
                "share_index": share.x,
                "fingerprint": fingerprint,
                "params_match": params_match,
                "fingerprint_valid": fingerprint_valid,
            }

        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
            }


# Singleton instance
key_ceremony_service = KeyCeremonyService()


def get_ceremony_master_key() -> bytes | None:
    """Get master key from ceremony if initialized and unsealed.

    Returns None if:
    - Ceremony is not initialized
    - Ceremony is sealed
    - Key ceremony mode is not enabled
    """
    from app.config import get_settings
    settings = get_settings()

    if not settings.key_ceremony_enabled:
        return None

    if not key_ceremony_service.is_initialized:
        return None

    if key_ceremony_service.is_sealed:
        return None

    try:
        return key_ceremony_service.get_master_key()
    except CeremonyError:
        return None


def is_service_sealed() -> bool:
    """Check if service is in sealed state (ceremony enabled but not unsealed)."""
    from app.config import get_settings
    settings = get_settings()

    if not settings.key_ceremony_enabled:
        return False  # Not using ceremony, so not "sealed"

    if not key_ceremony_service.is_initialized:
        return True  # Needs initialization

    return key_ceremony_service.is_sealed
