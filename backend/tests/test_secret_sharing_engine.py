"""Tests for Shamir Secret Sharing engine."""

import os
import pytest

from app.core.secret_sharing_engine import (
    secret_sharing_engine,
    SecretSharingEngine,
    Share,
    GF256,
    SecretSharingError,
    InsufficientSharesError,
    InvalidShareError,
)


@pytest.fixture
def engine():
    """Create a fresh secret sharing engine."""
    return SecretSharingEngine()


class TestBasicSplitCombine:
    """Tests for basic split and combine operations."""

    def test_split_combine_basic(self, engine):
        """Test basic 3-of-5 split and combine."""
        secret = b"Hello, World!"

        shares = engine.split(secret, threshold=3, total_shares=5)

        assert len(shares) == 5
        for share in shares:
            assert share.threshold == 3
            assert share.total == 5
            assert len(share.y) == len(secret)

        # Combine with exactly threshold shares
        recovered = engine.combine([shares[0], shares[2], shares[4]])
        assert recovered == secret

    def test_split_combine_2_of_3(self, engine):
        """Test 2-of-3 split and combine."""
        secret = b"short"

        shares = engine.split(secret, threshold=2, total_shares=3)
        recovered = engine.combine([shares[0], shares[1]])

        assert recovered == secret

    def test_split_combine_5_of_5(self, engine):
        """Test 5-of-5 (all shares required)."""
        secret = b"all required"

        shares = engine.split(secret, threshold=5, total_shares=5)
        recovered = engine.combine(shares)

        assert recovered == secret

    def test_any_threshold_shares_work(self, engine):
        """Test that any threshold number of shares work."""
        secret = b"test secret"

        shares = engine.split(secret, threshold=3, total_shares=5)

        # Try all combinations of 3 shares
        from itertools import combinations
        for combo in combinations(shares, 3):
            recovered = engine.combine(list(combo))
            assert recovered == secret

    def test_more_than_threshold_works(self, engine):
        """Test that using more shares than threshold works."""
        secret = b"extra shares"

        shares = engine.split(secret, threshold=2, total_shares=5)

        # Use 4 shares when only 2 are needed
        recovered = engine.combine(shares[:4])
        assert recovered == secret

    def test_random_secret(self, engine):
        """Test with random binary secret."""
        secret = os.urandom(64)

        shares = engine.split(secret, threshold=3, total_shares=5)
        recovered = engine.combine(shares[:3])

        assert recovered == secret


class TestEdgeCases:
    """Tests for edge cases."""

    def test_single_byte_secret(self, engine):
        """Test with single byte secret."""
        secret = b"\x42"

        shares = engine.split(secret, threshold=2, total_shares=3)
        recovered = engine.combine(shares[:2])

        assert recovered == secret

    def test_large_secret(self, engine):
        """Test with large secret (1KB)."""
        secret = os.urandom(1024)

        shares = engine.split(secret, threshold=3, total_shares=5)
        recovered = engine.combine(shares[:3])

        assert recovered == secret

    def test_all_zero_bytes(self, engine):
        """Test with all zero bytes."""
        secret = b"\x00" * 16

        shares = engine.split(secret, threshold=2, total_shares=3)
        recovered = engine.combine(shares[:2])

        assert recovered == secret

    def test_all_ff_bytes(self, engine):
        """Test with all 0xFF bytes."""
        secret = b"\xff" * 16

        shares = engine.split(secret, threshold=2, total_shares=3)
        recovered = engine.combine(shares[:2])

        assert recovered == secret

    def test_all_byte_values(self, engine):
        """Test with all possible byte values."""
        secret = bytes(range(256))

        shares = engine.split(secret, threshold=3, total_shares=5)
        recovered = engine.combine(shares[:3])

        assert recovered == secret


class TestShareSerialization:
    """Tests for share serialization."""

    def test_share_to_bytes_roundtrip(self, engine):
        """Test share serialization roundtrip."""
        secret = b"test"

        shares = engine.split(secret, threshold=2, total_shares=3)

        for share in shares:
            serialized = share.to_bytes()
            deserialized = Share.from_bytes(serialized)

            assert deserialized.x == share.x
            assert deserialized.y == share.y
            assert deserialized.threshold == share.threshold
            assert deserialized.total == share.total

    def test_share_to_hex_roundtrip(self, engine):
        """Test share hex serialization roundtrip."""
        secret = b"test"

        shares = engine.split(secret, threshold=2, total_shares=3)

        for share in shares:
            hex_str = share.to_hex()
            recovered = Share.from_hex(hex_str)

            assert recovered.x == share.x
            assert recovered.y == share.y

    def test_combine_from_serialized(self, engine):
        """Test combining shares after serialization."""
        secret = b"serialize test"

        shares = engine.split(secret, threshold=3, total_shares=5)

        # Serialize and deserialize
        serialized = [share.to_bytes() for share in shares]
        deserialized = [Share.from_bytes(s) for s in serialized]

        recovered = engine.combine(deserialized[:3])
        assert recovered == secret


class TestValidation:
    """Tests for input validation."""

    def test_threshold_too_low(self, engine):
        """Test that threshold must be at least 2."""
        with pytest.raises(SecretSharingError, match="at least 2"):
            engine.split(b"test", threshold=1, total_shares=3)

    def test_total_less_than_threshold(self, engine):
        """Test that total must be >= threshold."""
        with pytest.raises(SecretSharingError, match=">="):
            engine.split(b"test", threshold=5, total_shares=3)

    def test_too_many_shares(self, engine):
        """Test maximum share limit."""
        with pytest.raises(SecretSharingError, match="255"):
            engine.split(b"test", threshold=2, total_shares=256)

    def test_empty_secret(self, engine):
        """Test that empty secret is rejected."""
        with pytest.raises(SecretSharingError, match="empty"):
            engine.split(b"", threshold=2, total_shares=3)

    def test_insufficient_shares(self, engine):
        """Test combining with too few shares."""
        secret = b"test"
        shares = engine.split(secret, threshold=3, total_shares=5)

        with pytest.raises(InsufficientSharesError):
            engine.combine(shares[:2])

    def test_no_shares(self, engine):
        """Test combining with no shares."""
        with pytest.raises(InsufficientSharesError):
            engine.combine([])

    def test_duplicate_shares(self, engine):
        """Test combining duplicate shares."""
        secret = b"test"
        shares = engine.split(secret, threshold=2, total_shares=3)

        with pytest.raises(InvalidShareError, match="Duplicate"):
            engine.combine([shares[0], shares[0]])

    def test_incompatible_thresholds(self, engine):
        """Test combining shares with different thresholds."""
        shares1 = engine.split(b"secret1", threshold=2, total_shares=3)
        shares2 = engine.split(b"secret2", threshold=3, total_shares=5)

        # Manually create incompatible share
        bad_share = Share(
            x=shares2[0].x,
            y=shares2[0].y,
            threshold=3,  # Different threshold
            total=5,
        )

        with pytest.raises(InvalidShareError, match="different thresholds"):
            engine.combine([shares1[0], bad_share])


class TestVerifyShares:
    """Tests for share verification."""

    def test_verify_valid_shares(self, engine):
        """Test verifying valid shares."""
        shares = engine.split(b"test", threshold=2, total_shares=3)

        assert engine.verify_shares(shares)

    def test_verify_empty_list(self, engine):
        """Test verifying empty share list."""
        assert not engine.verify_shares([])

    def test_verify_different_thresholds(self, engine):
        """Test verifying shares with different thresholds."""
        shares1 = engine.split(b"a", threshold=2, total_shares=3)
        shares2 = engine.split(b"b", threshold=3, total_shares=5)

        mixed = [shares1[0], shares2[0]]
        assert not engine.verify_shares(mixed)

    def test_verify_different_lengths(self, engine):
        """Test verifying shares with different lengths."""
        shares1 = engine.split(b"short", threshold=2, total_shares=3)
        shares2 = engine.split(b"longer secret", threshold=2, total_shares=3)

        mixed = [shares1[0], shares2[0]]
        assert not engine.verify_shares(mixed)


class TestShareRecovery:
    """Tests for recovering lost shares."""

    def test_recover_share(self, engine):
        """Test recovering a lost share."""
        secret = b"recovery test"
        shares = engine.split(secret, threshold=3, total_shares=5)

        # "Lose" share 3 (x=3)
        remaining = [s for s in shares if s.x != 3]

        # Recover share 3
        recovered_share = engine.recover_share(remaining[:3], target_x=3)

        assert recovered_share.x == 3
        assert recovered_share.y == shares[2].y

    def test_recover_and_combine(self, engine):
        """Test recovering a share then combining."""
        secret = b"recovery test"
        shares = engine.split(secret, threshold=3, total_shares=5)

        # Keep only first 3 shares
        kept_shares = shares[:3]

        # Recover share 4
        recovered = engine.recover_share(kept_shares, target_x=4)

        # Combine with recovered share
        result = engine.combine([kept_shares[0], kept_shares[1], recovered])
        assert result == secret

    def test_recover_existing_share_fails(self, engine):
        """Test that recovering an existing share fails."""
        shares = engine.split(b"test", threshold=2, total_shares=3)

        with pytest.raises(SecretSharingError, match="already exists"):
            engine.recover_share(shares[:2], target_x=1)

    def test_recover_insufficient_shares(self, engine):
        """Test recovery with insufficient shares."""
        shares = engine.split(b"test", threshold=3, total_shares=5)

        with pytest.raises(InsufficientSharesError):
            engine.recover_share(shares[:2], target_x=4)


class TestGF256:
    """Tests for GF(256) arithmetic."""

    def test_multiplication_identity(self):
        """Test that 1 is the multiplicative identity."""
        for i in range(256):
            assert GF256.multiply(i, 1) == i
            assert GF256.multiply(1, i) == i

    def test_multiplication_zero(self):
        """Test that 0 absorbs multiplication."""
        for i in range(256):
            assert GF256.multiply(i, 0) == 0
            assert GF256.multiply(0, i) == 0

    def test_division_by_self(self):
        """Test that x/x = 1."""
        for i in range(1, 256):  # Skip 0
            assert GF256.divide(i, i) == 1

    def test_division_by_zero(self):
        """Test division by zero raises error."""
        with pytest.raises(ZeroDivisionError):
            GF256.divide(5, 0)

    def test_add_is_xor(self):
        """Test that addition is XOR."""
        for i in range(256):
            for j in range(256):
                assert GF256.add(i, j) == i ^ j

    def test_subtract_is_xor(self):
        """Test that subtraction is XOR (same as addition)."""
        for i in range(10):
            for j in range(10):
                assert GF256.subtract(i, j) == i ^ j

    def test_power_zero(self):
        """Test x^0 = 1."""
        for i in range(256):
            assert GF256.power(i, 0) == 1

    def test_power_one(self):
        """Test x^1 = x."""
        for i in range(256):
            assert GF256.power(i, 1) == i

    def test_multiplicative_inverse(self):
        """Test that a * (1/a) = 1."""
        for i in range(1, 256):
            inverse = GF256.divide(1, i)
            assert GF256.multiply(i, inverse) == 1


class TestDeterminism:
    """Tests for randomness and determinism."""

    def test_different_shares_each_split(self, engine):
        """Test that splitting produces different shares each time."""
        secret = b"test"

        shares1 = engine.split(secret, threshold=2, total_shares=3)
        shares2 = engine.split(secret, threshold=2, total_shares=3)

        # Shares should be different (due to random coefficients)
        # but both should reconstruct to the same secret
        assert shares1[0].y != shares2[0].y

        recovered1 = engine.combine(shares1[:2])
        recovered2 = engine.combine(shares2[:2])

        assert recovered1 == secret
        assert recovered2 == secret


class TestSingletonInstance:
    """Tests for singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert secret_sharing_engine is not None
        assert isinstance(secret_sharing_engine, SecretSharingEngine)

    def test_singleton_split_combine(self):
        """Test split/combine with singleton."""
        secret = b"singleton test"

        shares = secret_sharing_engine.split(secret, threshold=2, total_shares=3)
        recovered = secret_sharing_engine.combine(shares[:2])

        assert recovered == secret


class TestShareIndex:
    """Tests for share indexing."""

    def test_share_indices(self, engine):
        """Test that shares have correct indices."""
        shares = engine.split(b"test", threshold=2, total_shares=5)

        for i, share in enumerate(shares):
            assert share.x == i + 1  # 1-indexed

    def test_max_shares(self, engine):
        """Test creating maximum number of shares."""
        secret = b"max"

        shares = engine.split(secret, threshold=2, total_shares=255)

        assert len(shares) == 255
        assert shares[-1].x == 255

        # Can still reconstruct
        recovered = engine.combine([shares[0], shares[254]])
        assert recovered == secret
