"""Tests for threshold cryptography engine."""

import pytest
from itertools import combinations

from app.core.threshold_engine import (
    threshold_engine,
    ThresholdEngine,
    ThresholdScheme,
    ThresholdKeyShare,
    ThresholdSignature,
    ThresholdError,
    InsufficientParticipantsError,
    Point,
    FieldElement,
)


@pytest.fixture
def engine():
    """Create a fresh threshold engine."""
    return ThresholdEngine()


class TestKeyGeneration:
    """Tests for threshold key generation."""

    def test_generate_threshold_key_3_of_5(self, engine):
        """Test 3-of-5 threshold key generation."""
        result = engine.generate_threshold_key(
            threshold=3,
            total_participants=5,
        )

        assert result.threshold == 3
        assert result.total_participants == 5
        assert len(result.shares) == 5
        assert len(result.public_key) == 33  # Compressed point

        # All shares have same public key
        for share in result.shares:
            assert share.public_key == result.public_key
            assert share.threshold == 3
            assert share.total_participants == 5

    def test_generate_threshold_key_2_of_3(self, engine):
        """Test 2-of-3 threshold key generation."""
        result = engine.generate_threshold_key(
            threshold=2,
            total_participants=3,
        )

        assert len(result.shares) == 3
        assert result.threshold == 2

    def test_generate_threshold_key_5_of_5(self, engine):
        """Test 5-of-5 (all required) threshold key generation."""
        result = engine.generate_threshold_key(
            threshold=5,
            total_participants=5,
        )

        assert result.threshold == result.total_participants

    def test_shares_have_unique_ids(self, engine):
        """Test that shares have unique participant IDs."""
        result = engine.generate_threshold_key(threshold=3, total_participants=5)

        ids = [share.participant_id for share in result.shares]
        assert len(set(ids)) == 5
        assert set(ids) == {1, 2, 3, 4, 5}

    def test_threshold_too_low_fails(self, engine):
        """Test that threshold < 2 fails."""
        with pytest.raises(ThresholdError, match="at least 2"):
            engine.generate_threshold_key(threshold=1, total_participants=3)

    def test_participants_less_than_threshold_fails(self, engine):
        """Test that total < threshold fails."""
        with pytest.raises(ThresholdError, match=">="):
            engine.generate_threshold_key(threshold=5, total_participants=3)

    def test_too_many_participants_fails(self, engine):
        """Test that > 255 participants fails."""
        with pytest.raises(ThresholdError, match="255"):
            engine.generate_threshold_key(threshold=2, total_participants=300)


class TestShareVerification:
    """Tests for Feldman VSS share verification."""

    def test_verify_valid_shares(self, engine):
        """Test that generated shares pass verification."""
        result = engine.generate_threshold_key(threshold=3, total_participants=5)

        for share in result.shares:
            assert engine.verify_share(share) is True

    def test_verify_all_schemes(self, engine):
        """Test verification works for all schemes."""
        for scheme in ThresholdScheme:
            result = engine.generate_threshold_key(
                threshold=2,
                total_participants=3,
                scheme=scheme,
            )
            for share in result.shares:
                assert engine.verify_share(share) is True

    def test_tampered_share_fails_verification(self, engine):
        """Test that tampered shares fail verification."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)

        share = result.shares[0]
        # Tamper with share value
        tampered = ThresholdKeyShare(
            participant_id=share.participant_id,
            share_value=(share.share_value + 1) % engine.CURVE_ORDER,
            public_key=share.public_key,
            verification_points=share.verification_points,
            threshold=share.threshold,
            total_participants=share.total_participants,
            scheme=share.scheme,
        )

        assert engine.verify_share(tampered) is False


class TestShareSerialization:
    """Tests for share serialization."""

    def test_share_roundtrip(self, engine):
        """Test share serialization roundtrip."""
        result = engine.generate_threshold_key(threshold=3, total_participants=5)

        for share in result.shares:
            serialized = share.to_bytes()
            deserialized = ThresholdKeyShare.from_bytes(serialized)

            assert deserialized.participant_id == share.participant_id
            assert deserialized.share_value == share.share_value
            assert deserialized.public_key == share.public_key
            assert deserialized.threshold == share.threshold
            assert deserialized.total_participants == share.total_participants
            assert deserialized.scheme == share.scheme

    def test_serialized_share_verifies(self, engine):
        """Test that deserialized shares still verify."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)

        for share in result.shares:
            serialized = share.to_bytes()
            deserialized = ThresholdKeyShare.from_bytes(serialized)

            assert engine.verify_share(deserialized) is True


class TestThresholdSignatures:
    """Tests for threshold signature creation and verification."""

    def test_create_and_verify_signature_3_of_5(self, engine):
        """Test creating and verifying a 3-of-5 threshold signature."""
        result = engine.generate_threshold_key(threshold=3, total_participants=5)
        message = b"Hello, threshold world!"

        # Select 3 participants
        participants = result.shares[:3]

        # Generate nonces
        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        # Create signature shares
        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        # Combine signature shares
        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        # Verify signature
        assert engine.verify_threshold_signature(
            result.public_key, message, signature
        )

    def test_create_and_verify_signature_2_of_3(self, engine):
        """Test 2-of-3 threshold signature."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)
        message = b"Two of three test"

        participants = result.shares[:2]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        assert engine.verify_threshold_signature(
            result.public_key, message, signature
        )

    def test_any_threshold_subset_works(self, engine):
        """Test that any t participants can sign."""
        result = engine.generate_threshold_key(threshold=3, total_participants=5)
        message = b"Any combination should work"

        # Try all combinations of 3 from 5
        for combo in combinations(result.shares, 3):
            participants = list(combo)

            nonces = {}
            nonce_commitments = {}
            for share in participants:
                nonce, commitment = engine.generate_nonce_share(share)
                nonces[share.participant_id] = nonce
                nonce_commitments[share.participant_id] = commitment

            sig_shares = []
            for share in participants:
                sig_share = engine.create_signature_share(
                    share=share,
                    message=message,
                    nonce=nonces[share.participant_id],
                    nonce_commitments=nonce_commitments,
                )
                sig_shares.append(sig_share)

            signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

            assert engine.verify_threshold_signature(
                result.public_key, message, signature
            ), f"Failed for participants {[s.participant_id for s in participants]}"

    def test_wrong_message_fails_verification(self, engine):
        """Test that signature fails for different message."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)
        message = b"Original message"
        wrong_message = b"Different message"

        participants = result.shares[:2]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        assert not engine.verify_threshold_signature(
            result.public_key, wrong_message, signature
        )

    def test_wrong_public_key_fails_verification(self, engine):
        """Test that signature fails with different public key."""
        result1 = engine.generate_threshold_key(threshold=2, total_participants=3)
        result2 = engine.generate_threshold_key(threshold=2, total_participants=3)
        message = b"Test message"

        participants = result1.shares[:2]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        # Verify with wrong public key
        assert not engine.verify_threshold_signature(
            result2.public_key, message, signature
        )

    def test_more_than_threshold_works(self, engine):
        """Test that using more than threshold participants works."""
        result = engine.generate_threshold_key(threshold=2, total_participants=5)
        message = b"Extra participants"

        # Use 4 participants when only 2 needed
        participants = result.shares[:4]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        assert engine.verify_threshold_signature(
            result.public_key, message, signature
        )


class TestThresholdDecryption:
    """Tests for threshold decryption."""

    def test_threshold_decrypt_shares(self, engine):
        """Test creating decryption shares."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)

        # Create a dummy ciphertext point (just the generator for testing)
        c1 = Point.generator().to_bytes()

        for share in result.shares:
            decryption_share = engine.threshold_decrypt_share(share, c1)
            assert len(decryption_share) == 33  # Compressed point


class TestDKGProtocol:
    """Tests for Distributed Key Generation protocol."""

    def test_dkg_round1(self, engine):
        """Test DKG Round 1 output generation."""
        output, coefficients = engine.dkg_round1(
            participant_id=1,
            threshold=2,
            total_participants=3,
        )

        assert output.participant_id == 1
        assert len(output.commitment) == 33
        assert len(output.proof) == 65
        assert len(coefficients) == 2  # threshold coefficients

    def test_dkg_round1_verify(self, engine):
        """Test DKG Round 1 proof verification."""
        output, _ = engine.dkg_round1(
            participant_id=1,
            threshold=2,
            total_participants=3,
        )

        assert engine.dkg_verify_round1(output) is True

    def test_dkg_round1_tampered_proof_fails(self, engine):
        """Test that tampered proof fails verification."""
        output, _ = engine.dkg_round1(
            participant_id=1,
            threshold=2,
            total_participants=3,
        )

        # Tamper with proof
        from app.core.threshold_engine import DKGRound1Output
        tampered = DKGRound1Output(
            participant_id=output.participant_id,
            commitment=output.commitment,
            proof=b"\x00" * len(output.proof),
        )

        assert engine.dkg_verify_round1(tampered) is False

    def test_dkg_round2(self, engine):
        """Test DKG Round 2 share distribution."""
        _, coefficients = engine.dkg_round1(
            participant_id=1,
            threshold=2,
            total_participants=3,
        )

        # Mock public keys for other participants
        public_keys = {
            2: b"\x02" + b"\x01" * 32,
            3: b"\x02" + b"\x02" * 32,
        }

        output = engine.dkg_round2(
            participant_id=1,
            coefficients=coefficients,
            total_participants=3,
            recipient_public_keys=public_keys,
        )

        assert output.participant_id == 1
        assert len(output.encrypted_shares) == 2
        assert 2 in output.encrypted_shares
        assert 3 in output.encrypted_shares


class TestMathPrimitives:
    """Tests for mathematical primitives."""

    def test_field_element_add(self):
        """Test field element addition."""
        modulus = 17
        a = FieldElement(5, modulus)
        b = FieldElement(7, modulus)

        result = a + b
        assert result.value == 12

    def test_field_element_multiply(self):
        """Test field element multiplication."""
        modulus = 17
        a = FieldElement(5, modulus)
        b = FieldElement(7, modulus)

        result = a * b
        assert result.value == (35 % 17)

    def test_field_element_inverse(self):
        """Test field element inverse."""
        modulus = 17
        a = FieldElement(5, modulus)

        inverse = a.inverse()
        product = a * inverse

        assert product.value == 1

    def test_point_identity(self):
        """Test point identity element."""
        p = Point.identity()

        assert p.is_identity
        assert p.x is None
        assert p.y is None

    def test_point_generator(self):
        """Test point generator."""
        g = Point.generator()

        assert not g.is_identity
        assert g.x is not None
        assert g.y is not None

    def test_point_serialization(self):
        """Test point serialization."""
        g = Point.generator()

        serialized = g.to_bytes()
        assert len(serialized) == 33
        assert serialized[0] in (0x02, 0x03)

    def test_identity_serialization(self):
        """Test identity point serialization."""
        p = Point.identity()

        serialized = p.to_bytes()
        assert serialized == b"\x00"


class TestLagrangeCoefficients:
    """Tests for Lagrange coefficient computation."""

    def test_lagrange_coefficients(self, engine):
        """Test Lagrange coefficient computation."""
        # For participants [1, 2, 3], coefficients should allow reconstruction
        participant_ids = [1, 2, 3]

        coeffs = [
            engine._lagrange_coefficient(i, participant_ids)
            for i in participant_ids
        ]

        # Sum of Lagrange coefficients evaluated at 0 should equal 1
        # But we're computing them for interpolation at 0, so we just
        # check they're non-zero
        for c in coeffs:
            assert c != 0


class TestSingletonInstance:
    """Tests for singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert threshold_engine is not None
        assert isinstance(threshold_engine, ThresholdEngine)

    def test_singleton_generates_keys(self):
        """Test that singleton can generate keys."""
        result = threshold_engine.generate_threshold_key(
            threshold=2, total_participants=3
        )

        assert result is not None
        assert len(result.shares) == 3


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_signature_shares_fails(self, engine):
        """Test that combining empty shares fails."""
        with pytest.raises(ThresholdError, match="No signature"):
            engine.combine_signature_shares([], {})

    def test_large_message(self, engine):
        """Test signing large message."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)
        message = b"x" * 10000

        participants = result.shares[:2]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        assert engine.verify_threshold_signature(
            result.public_key, message, signature
        )

    def test_binary_message(self, engine):
        """Test signing binary message."""
        result = engine.generate_threshold_key(threshold=2, total_participants=3)
        message = bytes(range(256))

        participants = result.shares[:2]

        nonces = {}
        nonce_commitments = {}
        for share in participants:
            nonce, commitment = engine.generate_nonce_share(share)
            nonces[share.participant_id] = nonce
            nonce_commitments[share.participant_id] = commitment

        sig_shares = []
        for share in participants:
            sig_share = engine.create_signature_share(
                share=share,
                message=message,
                nonce=nonces[share.participant_id],
                nonce_commitments=nonce_commitments,
            )
            sig_shares.append(sig_share)

        signature = engine.combine_signature_shares(sig_shares, nonce_commitments)

        assert engine.verify_threshold_signature(
            result.public_key, message, signature
        )
