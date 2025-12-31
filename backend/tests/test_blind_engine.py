"""Tests for blinded cryptographic operations engine."""

import pytest

from app.core.blind_engine import (
    blind_engine,
    BlindEngine,
    BlindScheme,
    BlindError,
    BlindingError,
    UnblindingError,
    RSABlindKeyPair,
    SchnorrBlindKeyPair,
)


@pytest.fixture
def engine():
    """Create a fresh blind engine."""
    return BlindEngine()


@pytest.fixture
def rsa_key_pair(engine):
    """Generate RSA key pair."""
    return engine.generate_rsa_key_pair()


@pytest.fixture
def schnorr_key_pair(engine):
    """Generate Schnorr key pair."""
    return engine.generate_schnorr_key_pair()


class TestRSAKeyGeneration:
    """Tests for RSA key pair generation."""

    def test_generate_2048_bit_key(self, engine):
        """Test generating 2048-bit RSA key."""
        key_pair = engine.generate_rsa_key_pair(key_size=2048)

        assert key_pair.private_key_pem is not None
        assert key_pair.public_key_pem is not None
        assert key_pair.modulus > 0
        assert key_pair.public_exponent == 65537

    def test_generate_3072_bit_key(self, engine):
        """Test generating 3072-bit RSA key."""
        key_pair = engine.generate_rsa_key_pair(key_size=3072)

        assert key_pair.modulus.bit_length() >= 3072

    def test_generate_4096_bit_key(self, engine):
        """Test generating 4096-bit RSA key."""
        key_pair = engine.generate_rsa_key_pair(key_size=4096)

        assert key_pair.modulus.bit_length() >= 4096

    def test_invalid_key_size_fails(self, engine):
        """Test that invalid key size fails."""
        with pytest.raises(BlindError, match="Invalid key size"):
            engine.generate_rsa_key_pair(key_size=1024)


class TestBlindRSA:
    """Tests for blind RSA signatures."""

    def test_complete_blind_signature_flow(self, engine, rsa_key_pair):
        """Test complete blind signature flow."""
        message = b"Secret message"

        # Step 1: Requester blinds message
        blinding = engine.blind_rsa(
            message=message,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        assert blinding.scheme == BlindScheme.BLIND_RSA
        assert blinding.blinded_message != message
        assert len(blinding.blinding_factor) > 0

        # Step 2: Signer signs blinded message
        blind_sig = engine.sign_blinded_rsa(
            blinded_message=blinding.blinded_message,
            private_key_pem=rsa_key_pair.private_key_pem,
        )

        assert blind_sig.scheme == BlindScheme.BLIND_RSA
        assert len(blind_sig.blind_signature) > 0

        # Step 3: Requester unblinds signature
        signature = engine.unblind_rsa(
            blind_signature=blind_sig.blind_signature,
            blinding_factor=blinding.blinding_factor,
            message=message,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        assert signature.message == message
        assert signature.scheme == BlindScheme.BLIND_RSA

        # Step 4: Verify signature
        valid = engine.verify_rsa(
            message=message,
            signature=signature.signature,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        assert valid is True

    def test_different_messages_produce_different_blindings(
        self, engine, rsa_key_pair
    ):
        """Test that different messages produce different blinded values."""
        msg1 = b"Message 1"
        msg2 = b"Message 2"

        blind1 = engine.blind_rsa(msg1, rsa_key_pair.public_key_pem)
        blind2 = engine.blind_rsa(msg2, rsa_key_pair.public_key_pem)

        assert blind1.blinded_message != blind2.blinded_message

    def test_same_message_produces_different_blindings(
        self, engine, rsa_key_pair
    ):
        """Test that same message with different factors produces different blindings."""
        message = b"Same message"

        blind1 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind2 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)

        # Different blinding factors produce different blinded messages
        assert blind1.blinding_factor != blind2.blinding_factor
        assert blind1.blinded_message != blind2.blinded_message

    def test_wrong_blinding_factor_fails_verification(
        self, engine, rsa_key_pair
    ):
        """Test that wrong blinding factor produces invalid signature."""
        message = b"Test message"

        blind1 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind2 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)

        blind_sig = engine.sign_blinded_rsa(
            blind1.blinded_message,
            rsa_key_pair.private_key_pem,
        )

        # Unblind with wrong factor
        signature = engine.unblind_rsa(
            blind_sig.blind_signature,
            blind2.blinding_factor,  # Wrong factor!
            message,
            rsa_key_pair.public_key_pem,
        )

        # Verification should fail
        valid = engine.verify_rsa(
            message, signature.signature, rsa_key_pair.public_key_pem
        )
        assert valid is False

    def test_wrong_message_fails_verification(self, engine, rsa_key_pair):
        """Test that wrong message fails verification."""
        original = b"Original message"
        wrong = b"Wrong message"

        blinding = engine.blind_rsa(original, rsa_key_pair.public_key_pem)
        blind_sig = engine.sign_blinded_rsa(
            blinding.blinded_message, rsa_key_pair.private_key_pem
        )
        signature = engine.unblind_rsa(
            blind_sig.blind_signature,
            blinding.blinding_factor,
            original,
            rsa_key_pair.public_key_pem,
        )

        # Verify with wrong message
        valid = engine.verify_rsa(
            wrong, signature.signature, rsa_key_pair.public_key_pem
        )
        assert valid is False

    def test_wrong_public_key_fails_verification(self, engine):
        """Test that wrong public key fails verification."""
        key1 = engine.generate_rsa_key_pair()
        key2 = engine.generate_rsa_key_pair()
        message = b"Test message"

        blinding = engine.blind_rsa(message, key1.public_key_pem)
        blind_sig = engine.sign_blinded_rsa(
            blinding.blinded_message, key1.private_key_pem
        )
        signature = engine.unblind_rsa(
            blind_sig.blind_signature,
            blinding.blinding_factor,
            message,
            key1.public_key_pem,
        )

        # Verify with wrong key
        valid = engine.verify_rsa(
            message, signature.signature, key2.public_key_pem
        )
        assert valid is False

    def test_empty_message_fails(self, engine, rsa_key_pair):
        """Test that empty message fails."""
        with pytest.raises(BlindingError, match="empty"):
            engine.blind_rsa(b"", rsa_key_pair.public_key_pem)

    def test_large_message(self, engine, rsa_key_pair):
        """Test signing large message."""
        message = b"x" * 10000

        blinding = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind_sig = engine.sign_blinded_rsa(
            blinding.blinded_message, rsa_key_pair.private_key_pem
        )
        signature = engine.unblind_rsa(
            blind_sig.blind_signature,
            blinding.blinding_factor,
            message,
            rsa_key_pair.public_key_pem,
        )

        assert engine.verify_rsa(
            message, signature.signature, rsa_key_pair.public_key_pem
        )


class TestPartiallyBlindRSA:
    """Tests for partially blind RSA signatures."""

    def test_complete_partial_blind_flow(self, engine, rsa_key_pair):
        """Test complete partially blind signature flow."""
        message = b"Secret vote"
        metadata = b"election-2024"

        # Blind with metadata
        blinding = engine.blind_rsa_partial(
            message=message,
            public_metadata=metadata,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        assert blinding.scheme == BlindScheme.PARTIALLY_BLIND_RSA
        assert blinding.public_metadata == metadata

        # Sign (signer sees metadata)
        blind_sig = engine.sign_blinded_rsa_partial(
            blinded_message=blinding.blinded_message,
            public_metadata=metadata,
            private_key_pem=rsa_key_pair.private_key_pem,
        )

        # Unblind
        signature = engine.unblind_rsa_partial(
            blind_signature=blind_sig.blind_signature,
            blinding_factor=blinding.blinding_factor,
            message=message,
            public_metadata=metadata,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        # Verify
        valid = engine.verify_rsa_partial(
            message=message,
            public_metadata=metadata,
            signature=signature.signature,
            public_key_pem=rsa_key_pair.public_key_pem,
        )

        assert valid is True

    def test_different_metadata_fails_verification(self, engine, rsa_key_pair):
        """Test that different metadata fails verification."""
        message = b"Secret vote"
        metadata1 = b"election-2024"
        metadata2 = b"election-2025"

        blinding = engine.blind_rsa_partial(
            message, metadata1, rsa_key_pair.public_key_pem
        )
        blind_sig = engine.sign_blinded_rsa_partial(
            blinding.blinded_message,
            metadata1,
            rsa_key_pair.private_key_pem,
        )
        signature = engine.unblind_rsa_partial(
            blind_sig.blind_signature,
            blinding.blinding_factor,
            message,
            metadata1,
            rsa_key_pair.public_key_pem,
        )

        # Verify with different metadata
        valid = engine.verify_rsa_partial(
            message,
            metadata2,  # Wrong metadata!
            signature.signature,
            rsa_key_pair.public_key_pem,
        )

        assert valid is False

    def test_metadata_binds_to_signature(self, engine, rsa_key_pair):
        """Test that metadata is bound to signature."""
        message = b"Same message"
        metadata1 = b"context-1"
        metadata2 = b"context-2"

        # Create two signatures with different metadata
        blind1 = engine.blind_rsa_partial(
            message, metadata1, rsa_key_pair.public_key_pem
        )
        blind2 = engine.blind_rsa_partial(
            message, metadata2, rsa_key_pair.public_key_pem
        )

        sig1 = engine.sign_blinded_rsa_partial(
            blind1.blinded_message, metadata1, rsa_key_pair.private_key_pem
        )
        sig2 = engine.sign_blinded_rsa_partial(
            blind2.blinded_message, metadata2, rsa_key_pair.private_key_pem
        )

        unblind1 = engine.unblind_rsa_partial(
            sig1.blind_signature,
            blind1.blinding_factor,
            message,
            metadata1,
            rsa_key_pair.public_key_pem,
        )
        unblind2 = engine.unblind_rsa_partial(
            sig2.blind_signature,
            blind2.blinding_factor,
            message,
            metadata2,
            rsa_key_pair.public_key_pem,
        )

        # Both verify with correct metadata
        assert engine.verify_rsa_partial(
            message, metadata1, unblind1.signature, rsa_key_pair.public_key_pem
        )
        assert engine.verify_rsa_partial(
            message, metadata2, unblind2.signature, rsa_key_pair.public_key_pem
        )

        # Neither verifies with wrong metadata
        assert not engine.verify_rsa_partial(
            message, metadata2, unblind1.signature, rsa_key_pair.public_key_pem
        )


class TestSchnorrKeyGeneration:
    """Tests for Schnorr key generation."""

    def test_generate_schnorr_key_pair(self, engine):
        """Test generating Schnorr key pair."""
        key_pair = engine.generate_schnorr_key_pair()

        assert key_pair.private_key > 0
        assert len(key_pair.public_key) == 32


class TestBlindSchnorr:
    """Tests for blind Schnorr signatures."""

    def test_complete_blind_schnorr_flow(self, engine, schnorr_key_pair):
        """Test complete blind Schnorr signature flow."""
        message = b"Schnorr blind test"

        # Step 1: Signer generates commitment
        commitment = engine.schnorr_signer_commit(schnorr_key_pair)

        assert len(commitment.R) == 32
        assert commitment.k > 0

        # Step 2: Requester blinds message
        blinding, challenge = engine.blind_schnorr(
            message=message,
            R=commitment.R,
            public_key=schnorr_key_pair.public_key,
        )

        assert blinding.scheme == BlindScheme.BLIND_SCHNORR

        # Step 3: Signer responds to challenge
        s = engine.sign_schnorr_challenge(
            commitment=commitment,
            challenge=challenge,
            key_pair=schnorr_key_pair,
        )

        # Step 4: Requester unblinds
        signature = engine.unblind_schnorr(s, blinding)

        assert signature.scheme == BlindScheme.BLIND_SCHNORR
        assert len(signature.signature) == 96

        # Step 5: Verify
        valid = engine.verify_schnorr(
            message=message,
            signature=signature.signature,
            public_key=schnorr_key_pair.public_key,
        )

        assert valid is True

    def test_wrong_message_fails_schnorr_verification(
        self, engine, schnorr_key_pair
    ):
        """Test that wrong message fails Schnorr verification."""
        original = b"Original"
        wrong = b"Wrong"

        commitment = engine.schnorr_signer_commit(schnorr_key_pair)
        blinding, challenge = engine.blind_schnorr(
            original, commitment.R, schnorr_key_pair.public_key
        )
        s = engine.sign_schnorr_challenge(
            commitment, challenge, schnorr_key_pair
        )
        signature = engine.unblind_schnorr(s, blinding)

        valid = engine.verify_schnorr(
            wrong, signature.signature, schnorr_key_pair.public_key
        )
        assert valid is False

    def test_wrong_key_fails_schnorr_verification(self, engine):
        """Test that wrong key fails Schnorr verification."""
        key1 = engine.generate_schnorr_key_pair()
        key2 = engine.generate_schnorr_key_pair()
        message = b"Test"

        commitment = engine.schnorr_signer_commit(key1)
        blinding, challenge = engine.blind_schnorr(
            message, commitment.R, key1.public_key
        )
        s = engine.sign_schnorr_challenge(commitment, challenge, key1)
        signature = engine.unblind_schnorr(s, blinding)

        valid = engine.verify_schnorr(
            message, signature.signature, key2.public_key
        )
        assert valid is False

    def test_empty_message_fails_schnorr(self, engine, schnorr_key_pair):
        """Test that empty message fails."""
        commitment = engine.schnorr_signer_commit(schnorr_key_pair)

        with pytest.raises(BlindingError, match="empty"):
            engine.blind_schnorr(b"", commitment.R, schnorr_key_pair.public_key)


class TestUnlinkability:
    """Tests for unlinkability property.

    In blind signatures, unlinkability means:
    - The signer sees different blinded messages for the same underlying message
    - The signer cannot link a signing session to the final unblinded signature
    - The final signatures ARE identical for the same message (deterministic)
    """

    def test_blinded_messages_differ(self, engine, rsa_key_pair):
        """Test that same message produces different blinded values."""
        message = b"Same message"

        # Two separate blind signature sessions
        blind1 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind2 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)

        # Blinded messages should be different (signer can't link them)
        assert blind1.blinded_message != blind2.blinded_message
        assert blind1.blinding_factor != blind2.blinding_factor

    def test_final_signatures_are_deterministic(self, engine, rsa_key_pair):
        """Test that unblinded signatures are deterministic for same message."""
        message = b"Same message"

        # Two separate blind signature sessions
        blind1 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind2 = engine.blind_rsa(message, rsa_key_pair.public_key_pem)

        sig1 = engine.sign_blinded_rsa(
            blind1.blinded_message, rsa_key_pair.private_key_pem
        )
        sig2 = engine.sign_blinded_rsa(
            blind2.blinded_message, rsa_key_pair.private_key_pem
        )

        # Blind signatures ARE different (signer sees different values)
        assert sig1.blind_signature != sig2.blind_signature

        unblind1 = engine.unblind_rsa(
            sig1.blind_signature,
            blind1.blinding_factor,
            message,
            rsa_key_pair.public_key_pem,
        )
        unblind2 = engine.unblind_rsa(
            sig2.blind_signature,
            blind2.blinding_factor,
            message,
            rsa_key_pair.public_key_pem,
        )

        # Unblinded signatures MUST be identical (FDH is deterministic)
        assert unblind1.signature == unblind2.signature

        # Both should verify
        assert engine.verify_rsa(
            message, unblind1.signature, rsa_key_pair.public_key_pem
        )
        assert engine.verify_rsa(
            message, unblind2.signature, rsa_key_pair.public_key_pem
        )


class TestSingletonInstance:
    """Tests for singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert blind_engine is not None
        assert isinstance(blind_engine, BlindEngine)

    def test_singleton_generates_keys(self):
        """Test that singleton can generate keys."""
        key_pair = blind_engine.generate_rsa_key_pair()
        assert key_pair is not None


class TestEdgeCases:
    """Tests for edge cases."""

    def test_binary_message(self, engine, rsa_key_pair):
        """Test signing binary message."""
        message = bytes(range(256))

        blinding = engine.blind_rsa(message, rsa_key_pair.public_key_pem)
        blind_sig = engine.sign_blinded_rsa(
            blinding.blinded_message, rsa_key_pair.private_key_pem
        )
        signature = engine.unblind_rsa(
            blind_sig.blind_signature,
            blinding.blinding_factor,
            message,
            rsa_key_pair.public_key_pem,
        )

        assert engine.verify_rsa(
            message, signature.signature, rsa_key_pair.public_key_pem
        )

    def test_invalid_signature_fails_verification(self, engine, rsa_key_pair):
        """Test that invalid signature fails verification."""
        message = b"Test"
        invalid_sig = b"\x00" * 256

        valid = engine.verify_rsa(
            message, invalid_sig, rsa_key_pair.public_key_pem
        )
        assert valid is False

    def test_invalid_schnorr_signature_fails(self, engine, schnorr_key_pair):
        """Test that invalid Schnorr signature fails verification."""
        message = b"Test"
        invalid_sig = b"\x00" * 96

        valid = engine.verify_schnorr(
            message, invalid_sig, schnorr_key_pair.public_key
        )
        assert valid is False
