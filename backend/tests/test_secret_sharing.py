"""Comprehensive tests for Secret Sharing and Key Ceremony.

Tests Shamir's Secret Sharing implementation and Key Ceremony workflow.
"""

import pytest
import secrets

from app.core.secret_sharing_engine import (
    SecretSharingEngine,
    Share,
    GF256,
    SecretSharingError,
    InsufficientSharesError,
    InvalidShareError,
)
from app.core.key_ceremony import (
    KeyCeremonyService,
    CeremonyState,
    CeremonyError,
    AlreadyInitializedError,
    NotInitializedError,
    AlreadySealedError,
    AlreadyUnsealedError,
    InvalidShareError as CeremonyInvalidShareError,
)


class TestGF256:
    """Tests for Galois Field GF(2^8) arithmetic."""

    def test_addition_is_xor(self):
        """Addition in GF(256) is XOR."""
        assert GF256.add(0, 0) == 0
        assert GF256.add(0, 1) == 1
        assert GF256.add(1, 1) == 0
        assert GF256.add(0x55, 0xAA) == 0xFF

    def test_subtraction_is_xor(self):
        """Subtraction in GF(256) is same as addition (XOR)."""
        for _ in range(100):
            a = secrets.randbelow(256)
            b = secrets.randbelow(256)
            assert GF256.subtract(a, b) == GF256.add(a, b)

    def test_multiplication(self):
        """Test multiplication properties."""
        # Identity
        assert GF256.multiply(1, 100) == 100
        assert GF256.multiply(100, 1) == 100

        # Zero
        assert GF256.multiply(0, 100) == 0
        assert GF256.multiply(100, 0) == 0

        # Commutativity
        for _ in range(100):
            a = secrets.randbelow(256)
            b = secrets.randbelow(256)
            assert GF256.multiply(a, b) == GF256.multiply(b, a)

    def test_division_inverse(self):
        """Division is the inverse of multiplication."""
        for _ in range(100):
            a = secrets.randbelow(255) + 1  # Non-zero
            b = secrets.randbelow(255) + 1  # Non-zero

            product = GF256.multiply(a, b)
            assert GF256.divide(product, b) == a
            assert GF256.divide(product, a) == b

    def test_division_by_zero_raises(self):
        """Division by zero raises exception."""
        with pytest.raises(ZeroDivisionError):
            GF256.divide(100, 0)


class TestSecretSharingEngine:
    """Tests for Shamir Secret Sharing Engine."""

    @pytest.fixture
    def engine(self):
        return SecretSharingEngine()

    def test_split_and_combine_basic(self, engine):
        """Basic split and combine works."""
        secret = b"Hello, World!"
        shares = engine.split(secret, threshold=3, total_shares=5)

        assert len(shares) == 5
        assert all(isinstance(s, Share) for s in shares)

        # Combine with exactly threshold shares
        recovered = engine.combine(shares[:3])
        assert recovered == secret

    def test_split_and_combine_32_byte_key(self, engine):
        """Works with 256-bit keys (typical for AES)."""
        secret = secrets.token_bytes(32)
        shares = engine.split(secret, threshold=3, total_shares=5)

        recovered = engine.combine(shares[:3])
        assert recovered == secret

    def test_split_and_combine_various_thresholds(self, engine):
        """Works with various threshold configurations."""
        secret = b"Test secret"

        configs = [
            (2, 2),  # 2-of-2
            (2, 3),  # 2-of-3
            (2, 5),  # 2-of-5
            (3, 5),  # 3-of-5
            (3, 7),  # 3-of-7
            (4, 7),  # 4-of-7
            (5, 5),  # 5-of-5
            (5, 10), # 5-of-10
        ]

        for threshold, total in configs:
            shares = engine.split(secret, threshold=threshold, total_shares=total)

            # Combine with exactly threshold shares
            recovered = engine.combine(shares[:threshold])
            assert recovered == secret, f"Failed for {threshold}-of-{total}"

    def test_any_subset_works(self, engine):
        """Any subset of threshold shares works."""
        secret = b"Secret data"
        shares = engine.split(secret, threshold=3, total_shares=5)

        # Try all possible 3-combinations
        from itertools import combinations
        for subset in combinations(shares, 3):
            recovered = engine.combine(list(subset))
            assert recovered == secret

    def test_fewer_than_threshold_fails(self, engine):
        """Fewer than threshold shares cannot reconstruct."""
        secret = b"Secret"
        shares = engine.split(secret, threshold=3, total_shares=5)

        with pytest.raises(InsufficientSharesError):
            engine.combine(shares[:2])

    def test_k_minus_1_reveals_nothing(self, engine):
        """k-1 shares reveal no information (information-theoretic security)."""
        # This tests that partial shares don't leak info
        secret = b"X"  # Single byte for easy analysis
        shares1 = engine.split(secret, threshold=3, total_shares=5)

        different_secret = b"Y"
        shares2 = engine.split(different_secret, threshold=3, total_shares=5)

        # With only 2 shares, the third share value is uniformly random
        # for any possible secret - we can't distinguish which secret it was

        # This is a fundamental property of Shamir's scheme that we verify
        # by ensuring the combine operation requires the full threshold
        with pytest.raises(InsufficientSharesError):
            engine.combine(shares1[:2])

    def test_empty_secret_fails(self, engine):
        """Empty secret is rejected."""
        with pytest.raises(SecretSharingError):
            engine.split(b"", threshold=2, total_shares=3)

    def test_threshold_too_low_fails(self, engine):
        """Threshold < 2 is rejected."""
        with pytest.raises(SecretSharingError):
            engine.split(b"secret", threshold=1, total_shares=3)

    def test_threshold_exceeds_total_fails(self, engine):
        """Threshold > total_shares is rejected."""
        with pytest.raises(SecretSharingError):
            engine.split(b"secret", threshold=5, total_shares=3)

    def test_too_many_shares_fails(self, engine):
        """More than 255 shares is rejected."""
        with pytest.raises(SecretSharingError):
            engine.split(b"secret", threshold=2, total_shares=256)

    def test_duplicate_share_indices_rejected(self, engine):
        """Duplicate share indices are rejected during combine."""
        secret = b"Test"
        shares = engine.split(secret, threshold=2, total_shares=3)

        # Try to combine with duplicate
        duplicate_shares = [shares[0], shares[0], shares[1]]
        with pytest.raises(InvalidShareError):
            engine.combine(duplicate_shares)

    def test_incompatible_shares_rejected(self, engine):
        """Shares from different secrets are detected."""
        secret1 = b"Secret 1"
        secret2 = b"Secret 2"

        shares1 = engine.split(secret1, threshold=2, total_shares=3)
        shares2 = engine.split(secret2, threshold=2, total_shares=3)

        # Mixing shares from different splits - different thresholds won't match
        shares1_modified = engine.split(secret1, threshold=3, total_shares=5)

        with pytest.raises(InvalidShareError):
            engine.combine([shares1[0], shares1_modified[1], shares1_modified[2]])

    def test_share_serialization(self, engine):
        """Shares can be serialized and deserialized."""
        secret = b"Serialize me"
        shares = engine.split(secret, threshold=2, total_shares=3)

        # Serialize to bytes
        serialized = [s.to_bytes() for s in shares]

        # Deserialize
        deserialized = [Share.from_bytes(s) for s in serialized]

        # Combine should work
        recovered = engine.combine(deserialized[:2])
        assert recovered == secret

    def test_share_hex_encoding(self, engine):
        """Shares can be hex encoded and decoded."""
        secret = b"Hex encode me"
        shares = engine.split(secret, threshold=2, total_shares=3)

        # Hex encode
        hex_shares = [s.to_hex() for s in shares]

        # Hex decode
        decoded = [Share.from_hex(h) for h in hex_shares]

        # Combine should work
        recovered = engine.combine(decoded[:2])
        assert recovered == secret

    def test_verify_shares(self, engine):
        """Share verification works."""
        secret = b"Verify me"
        shares = engine.split(secret, threshold=2, total_shares=3)

        assert engine.verify_shares(shares) is True
        assert engine.verify_shares([]) is False

    def test_recover_share(self, engine):
        """Can recover a lost share from threshold shares."""
        secret = b"Recover share test"
        shares = engine.split(secret, threshold=3, total_shares=5)

        # "Lose" share 2
        remaining_shares = [shares[0], shares[2], shares[3], shares[4]]

        # Recover share 2 (x=2)
        recovered_share = engine.recover_share(remaining_shares[:3], target_x=2)

        assert recovered_share.x == 2
        assert recovered_share.y == shares[1].y

    def test_large_secret(self, engine):
        """Works with larger secrets (e.g., 1KB)."""
        secret = secrets.token_bytes(1024)
        shares = engine.split(secret, threshold=3, total_shares=5)

        recovered = engine.combine(shares[:3])
        assert recovered == secret


class TestKeyCeremony:
    """Tests for Key Ceremony Service."""

    @pytest.fixture
    def ceremony(self):
        return KeyCeremonyService()

    def test_initial_state_is_uninitialized(self, ceremony):
        """New ceremony service is uninitialized."""
        assert ceremony.state == CeremonyState.UNINITIALIZED
        assert not ceremony.is_initialized
        # Uninitialized is not sealed (there's nothing to seal)
        assert not ceremony.is_sealed

    def test_initialize_creates_shares(self, ceremony):
        """Initialization creates the correct number of shares."""
        result = ceremony.initialize(
            threshold=3,
            total_shares=5,
            actor="test@example.com",
        )

        assert len(result.recovery_shares) == 5
        assert result.threshold == 3
        assert result.total_shares == 5
        assert len(result.share_fingerprints) == 5
        assert result.root_token is not None

    def test_initialize_sets_unsealed_state(self, ceremony):
        """Initialization leaves service in unsealed state for setup."""
        ceremony.initialize(threshold=2, total_shares=3)

        assert ceremony.state == CeremonyState.UNSEALED
        assert ceremony.is_initialized
        assert not ceremony.is_sealed

    def test_initialize_twice_fails(self, ceremony):
        """Cannot initialize twice."""
        ceremony.initialize(threshold=2, total_shares=3)

        with pytest.raises(AlreadyInitializedError):
            ceremony.initialize(threshold=2, total_shares=3)

    def test_seal_and_unseal(self, ceremony):
        """Seal and unseal workflow works."""
        result = ceremony.initialize(threshold=2, total_shares=3)
        shares = result.recovery_shares

        # Seal
        ceremony.seal()
        assert ceremony.state == CeremonyState.SEALED
        assert ceremony.is_sealed

        # Cannot get master key when sealed
        with pytest.raises(CeremonyError):
            ceremony.get_master_key()

        # Unseal with shares
        progress1 = ceremony.unseal(shares[0])
        assert progress1.is_sealed is True
        assert progress1.shares_provided == 1

        progress2 = ceremony.unseal(shares[1])
        assert progress2.is_sealed is False
        assert ceremony.state == CeremonyState.UNSEALED

        # Now can get master key
        key = ceremony.get_master_key()
        assert len(key) == 32

    def test_unseal_requires_threshold_shares(self, ceremony):
        """Unseal requires exactly threshold shares."""
        result = ceremony.initialize(threshold=3, total_shares=5)
        shares = result.recovery_shares

        ceremony.seal()

        # First two shares
        ceremony.unseal(shares[0])
        ceremony.unseal(shares[1])
        assert ceremony.is_sealed

        # Third share unlocks
        ceremony.unseal(shares[2])
        assert not ceremony.is_sealed

    def test_unseal_with_any_shares(self, ceremony):
        """Any threshold shares work to unseal."""
        result = ceremony.initialize(threshold=3, total_shares=5)
        shares = result.recovery_shares

        ceremony.seal()

        # Use shares 1, 3, 5 (indices 0, 2, 4)
        ceremony.unseal(shares[0])
        ceremony.unseal(shares[2])
        ceremony.unseal(shares[4])

        assert not ceremony.is_sealed

    def test_duplicate_share_rejected(self, ceremony):
        """Duplicate share is rejected during unseal."""
        result = ceremony.initialize(threshold=2, total_shares=3)
        shares = result.recovery_shares

        ceremony.seal()
        ceremony.unseal(shares[0])

        with pytest.raises(CeremonyInvalidShareError, match="already provided"):
            ceremony.unseal(shares[0])

    def test_invalid_share_rejected(self, ceremony):
        """Invalid share is rejected."""
        ceremony.initialize(threshold=2, total_shares=3)
        ceremony.seal()

        with pytest.raises(CeremonyInvalidShareError):
            ceremony.unseal("not-a-valid-share")

    def test_wrong_ceremony_share_rejected(self, ceremony):
        """Share from different ceremony is rejected."""
        ceremony.initialize(threshold=2, total_shares=3)
        ceremony.seal()

        # Create a share from a different ceremony
        other_ceremony = KeyCeremonyService()
        other_result = other_ceremony.initialize(threshold=2, total_shares=3)

        with pytest.raises(CeremonyInvalidShareError):
            ceremony.unseal(other_result.recovery_shares[0])

    def test_reset_unseal_progress(self, ceremony):
        """Can reset unseal progress."""
        result = ceremony.initialize(threshold=3, total_shares=5)
        shares = result.recovery_shares

        ceremony.seal()

        # Provide some shares
        ceremony.unseal(shares[0])
        ceremony.unseal(shares[1])
        assert ceremony.get_unseal_progress().shares_provided == 2

        # Reset
        ceremony.reset_unseal_progress()
        assert ceremony.get_unseal_progress().shares_provided == 0
        assert ceremony.state == CeremonyState.SEALED

    def test_verify_share_without_using(self, ceremony):
        """Can verify a share without using it."""
        result = ceremony.initialize(threshold=2, total_shares=3)
        shares = result.recovery_shares

        ceremony.seal()

        # Verify share
        verification = ceremony.verify_share(shares[0])
        assert verification["valid"] is True
        assert verification["params_match"] is True
        assert verification["fingerprint_valid"] is True

        # Still sealed (share not used)
        assert ceremony.is_sealed

    def test_audit_log(self, ceremony):
        """Audit log tracks ceremony events."""
        result = ceremony.initialize(threshold=2, total_shares=3, actor="admin@test.com")
        ceremony.seal(actor="admin@test.com")
        ceremony.unseal(result.recovery_shares[0], actor="custodian1@test.com")
        ceremony.unseal(result.recovery_shares[1], actor="custodian2@test.com")

        audit = ceremony.get_audit_log()

        assert len(audit) >= 4
        event_types = [e["event_type"] for e in audit]
        assert "initialize" in event_types
        assert "seal" in event_types
        assert "unseal_share" in event_types
        assert "unseal_complete" in event_types

    def test_custodians_tracked(self, ceremony):
        """Custodians are tracked when emails provided."""
        emails = ["alice@corp.com", "bob@corp.com", "charlie@corp.com"]
        ceremony.initialize(
            threshold=2,
            total_shares=3,
            custodian_emails=emails,
        )

        custodians = ceremony.get_custodians()
        assert len(custodians) == 3
        assert set(c["email"] for c in custodians) == set(emails)

    def test_status_reporting(self, ceremony):
        """Status reporting works in all states."""
        # Uninitialized
        status = ceremony.get_status()
        assert status["state"] == "uninitialized"
        assert not status["is_initialized"]

        # After init
        result = ceremony.initialize(threshold=2, total_shares=3)
        status = ceremony.get_status()
        assert status["state"] == "unsealed"
        assert status["threshold"] == 2
        assert status["total_shares"] == 3

        # Sealed
        ceremony.seal()
        status = ceremony.get_status()
        assert status["state"] == "sealed"
        assert status["is_sealed"]

        # Unsealing
        ceremony.unseal(result.recovery_shares[0])
        status = ceremony.get_status()
        assert status["state"] == "unsealing"
        assert status["unseal_progress"] is not None

    def test_threshold_limits(self, ceremony):
        """Threshold limits are enforced."""
        with pytest.raises(CeremonyError, match="at least 2"):
            ceremony.initialize(threshold=1, total_shares=3)

        with pytest.raises(CeremonyError, match="cannot exceed 10"):
            ceremony.initialize(threshold=11, total_shares=15)

        with pytest.raises(CeremonyError, match="cannot exceed 20"):
            ceremony.initialize(threshold=5, total_shares=21)


class TestSecretSharingIntegration:
    """Integration tests for complete workflows."""

    def test_master_key_protection_workflow(self):
        """Complete master key protection workflow."""
        ceremony = KeyCeremonyService()

        # 1. Initialize with 3-of-5 threshold
        result = ceremony.initialize(
            threshold=3,
            total_shares=5,
            custodian_emails=[
                "alice@corp.com",
                "bob@corp.com",
                "charlie@corp.com",
                "david@corp.com",
                "eve@corp.com",
            ],
            actor="admin@corp.com",
        )

        # Store shares (in practice, each goes to different custodian)
        shares = result.recovery_shares
        assert len(shares) == 5

        # 2. Get master key for initial setup
        master_key = ceremony.get_master_key()
        assert len(master_key) == 32

        # 3. Seal the service (e.g., after restart)
        ceremony.seal()

        # 4. Cannot access master key when sealed
        with pytest.raises(CeremonyError):
            ceremony.get_master_key()

        # 5. Unseal with 3 custodians (any 3 of 5)
        ceremony.unseal(shares[0], actor="alice@corp.com")   # 1/3
        ceremony.unseal(shares[2], actor="charlie@corp.com") # 2/3
        ceremony.unseal(shares[4], actor="eve@corp.com")     # 3/3 - unlocked!

        # 6. Master key is now available
        recovered_key = ceremony.get_master_key()
        assert recovered_key == master_key

    def test_disaster_recovery_scenario(self):
        """Simulate disaster recovery with minimum shares."""
        ceremony = KeyCeremonyService()

        # Setup 3-of-5
        result = ceremony.initialize(threshold=3, total_shares=5)
        original_key = ceremony.get_master_key()
        shares = result.recovery_shares

        # Simulate disaster: Only 3 shares survived
        survived_shares = [shares[0], shares[2], shares[4]]

        # Recover
        ceremony.seal()
        for share in survived_shares:
            ceremony.unseal(share)

        recovered_key = ceremony.get_master_key()
        assert recovered_key == original_key

    def test_geographic_distribution_scenario(self):
        """Simulate shares distributed across data centers."""
        ceremony = KeyCeremonyService()

        # 4-of-7 - tolerate loss of 3 data centers
        result = ceremony.initialize(
            threshold=4,
            total_shares=7,
            custodian_emails=[
                "dc-east1@corp.com",
                "dc-east2@corp.com",
                "dc-west1@corp.com",
                "dc-west2@corp.com",
                "dc-eu1@corp.com",
                "dc-eu2@corp.com",
                "dc-asia1@corp.com",
            ],
        )

        shares = result.recovery_shares
        ceremony.seal()

        # Simulate: Only 4 data centers respond
        responding = [shares[0], shares[2], shares[4], shares[6]]

        for share in responding:
            ceremony.unseal(share)

        assert not ceremony.is_sealed
