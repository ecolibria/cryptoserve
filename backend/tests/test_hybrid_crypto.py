"""Tests for hybrid post-quantum cryptography implementation.

Tests real ML-KEM (FIPS 203) and ML-DSA (FIPS 204) using liboqs.
"""

import pytest

from app.core.hybrid_crypto import (
    MLKEM,
    MLDSA,
    HybridCryptoEngine,
    HybridCiphertext,
    HybridKeyPair,
    HybridMode,
    PQCSignatureEngine,
    SignatureAlgorithm,
    SignatureKeyPair,
    is_pqc_available,
    get_mlkem,
    get_mldsa,
    hybrid_encrypt,
    hybrid_decrypt,
    pqc_sign,
    pqc_verify,
    get_available_kem_algorithms,
    get_available_sig_algorithms,
    PQCError,
)


# Skip all tests if liboqs is not available
pytestmark = pytest.mark.skipif(
    not is_pqc_available(),
    reason="liboqs not installed"
)


class TestMLKEM:
    """Tests for ML-KEM key encapsulation mechanism."""

    def test_mlkem_768_keygen(self):
        """Test ML-KEM-768 key generation."""
        kem = get_mlkem("ML-KEM-768")
        public_key = kem.generate_keypair()

        assert len(public_key) == 1184  # FIPS 203 spec
        assert len(kem.private_key) == 2400

    def test_mlkem_1024_keygen(self):
        """Test ML-KEM-1024 key generation."""
        kem = get_mlkem("ML-KEM-1024")
        public_key = kem.generate_keypair()

        assert len(public_key) == 1568
        assert len(kem.private_key) == 3168

    def test_mlkem_encap_decap(self):
        """Test encapsulation and decapsulation roundtrip."""
        kem = get_mlkem("ML-KEM-768")
        public_key = kem.generate_keypair()

        # Encapsulate
        ciphertext, shared_secret_enc = kem.encap_secret(public_key)

        # Decapsulate
        shared_secret_dec = kem.decap_secret(ciphertext)

        # Shared secrets must match
        assert shared_secret_enc == shared_secret_dec
        assert len(shared_secret_enc) == 32  # 256-bit shared secret

    def test_mlkem_ciphertext_size(self):
        """Test ML-KEM ciphertext sizes match FIPS 203."""
        for algo, expected_ct_len in [
            ("ML-KEM-512", 768),
            ("ML-KEM-768", 1088),
            ("ML-KEM-1024", 1568),
        ]:
            kem = get_mlkem(algo)
            public_key = kem.generate_keypair()
            ciphertext, _ = kem.encap_secret(public_key)
            assert len(ciphertext) == expected_ct_len, f"{algo} ciphertext size mismatch"

    def test_mlkem_different_keys_different_secrets(self):
        """Test that different keys produce different shared secrets."""
        kem1 = get_mlkem("ML-KEM-768")
        pk1 = kem1.generate_keypair()

        kem2 = get_mlkem("ML-KEM-768")
        pk2 = kem2.generate_keypair()

        # Encapsulate with same plaintext but different keys
        ct1, ss1 = kem1.encap_secret(pk1)
        ct2, ss2 = kem2.encap_secret(pk2)

        # Shared secrets should be different
        assert ss1 != ss2


class TestMLDSA:
    """Tests for ML-DSA digital signature algorithm."""

    def test_mldsa_65_keygen(self):
        """Test ML-DSA-65 key generation."""
        sig = get_mldsa("ML-DSA-65")
        public_key = sig.generate_keypair()

        assert len(public_key) == 1952  # FIPS 204 spec
        assert len(sig.private_key) == 4032

    def test_mldsa_sign_verify(self):
        """Test signing and verification roundtrip."""
        sig = get_mldsa("ML-DSA-65")
        public_key = sig.generate_keypair()

        message = b"Test message for PQC signing"
        signature = sig.sign(message)

        # Verify signature
        assert sig.verify(message, signature, public_key)

    def test_mldsa_signature_sizes(self):
        """Test ML-DSA signature sizes match FIPS 204."""
        for algo, expected_sig_len in [
            ("ML-DSA-44", 2420),
            ("ML-DSA-65", 3309),
            ("ML-DSA-87", 4627),
        ]:
            sig = get_mldsa(algo)
            public_key = sig.generate_keypair()
            signature = sig.sign(b"test")
            assert len(signature) == expected_sig_len, f"{algo} signature size mismatch"

    def test_mldsa_wrong_message_fails(self):
        """Test that wrong message fails verification."""
        sig = get_mldsa("ML-DSA-65")
        public_key = sig.generate_keypair()

        message = b"Original message"
        signature = sig.sign(message)

        # Verify with wrong message should fail
        assert not sig.verify(b"Wrong message", signature, public_key)

    def test_mldsa_wrong_signature_fails(self):
        """Test that corrupted signature fails verification."""
        sig = get_mldsa("ML-DSA-65")
        public_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message)

        # Corrupt signature
        corrupted = bytes([signature[0] ^ 0xFF]) + signature[1:]

        assert not sig.verify(message, corrupted, public_key)


class TestHybridCryptoEngine:
    """Tests for the hybrid encryption engine."""

    @pytest.mark.parametrize("mode", list(HybridMode))
    def test_hybrid_encrypt_decrypt_roundtrip(self, mode: HybridMode):
        """Test hybrid encrypt/decrypt roundtrip for all modes."""
        engine = HybridCryptoEngine(mode)
        keypair = engine.generate_keypair()

        plaintext = b"Secret data protected by hybrid PQC encryption"
        ciphertext = engine.encrypt(plaintext, keypair.public_key, keypair.key_id)
        decrypted = engine.decrypt(ciphertext, keypair.private_key)

        assert decrypted == plaintext

    def test_hybrid_with_aad(self):
        """Test hybrid encryption with associated authenticated data."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()

        plaintext = b"Secret data"
        aad = b"context:user-pii:v1"

        ciphertext = engine.encrypt(plaintext, keypair.public_key, keypair.key_id, aad)
        decrypted = engine.decrypt(ciphertext, keypair.private_key, aad)

        assert decrypted == plaintext

    def test_hybrid_wrong_aad_fails(self):
        """Test that wrong AAD fails decryption."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()

        plaintext = b"Secret data"
        aad = b"correct-aad"

        ciphertext = engine.encrypt(plaintext, keypair.public_key, keypair.key_id, aad)

        with pytest.raises(ValueError, match="Decryption failed"):
            engine.decrypt(ciphertext, keypair.private_key, b"wrong-aad")

    def test_hybrid_wrong_key_fails(self):
        """Test that wrong key fails decryption."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair1 = engine.generate_keypair()
        keypair2 = engine.generate_keypair()

        plaintext = b"Secret data"
        ciphertext = engine.encrypt(plaintext, keypair1.public_key, keypair1.key_id)

        with pytest.raises(ValueError, match="Decryption failed"):
            engine.decrypt(ciphertext, keypair2.private_key)

    def test_hybrid_ciphertext_serialization(self):
        """Test hybrid ciphertext serialization roundtrip."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()

        plaintext = b"Test data for serialization"
        ciphertext = engine.encrypt(plaintext, keypair.public_key, keypair.key_id)

        # Serialize and deserialize
        serialized = ciphertext.serialize()
        deserialized = HybridCiphertext.deserialize(serialized)

        # Decrypt with deserialized ciphertext
        decrypted = engine.decrypt(deserialized, keypair.private_key)
        assert decrypted == plaintext

    def test_hybrid_keypair_uniqueness(self):
        """Test that each keypair is unique."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)

        keypairs = [engine.generate_keypair() for _ in range(5)]

        # All public keys should be unique
        public_keys = [kp.public_key for kp in keypairs]
        assert len(set(public_keys)) == 5

        # All key IDs should be unique
        key_ids = [kp.key_id for kp in keypairs]
        assert len(set(key_ids)) == 5


class TestPQCSignatureEngine:
    """Tests for the PQC signature engine."""

    @pytest.mark.parametrize("algorithm", [
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    ])
    def test_signature_roundtrip(self, algorithm: SignatureAlgorithm):
        """Test sign/verify roundtrip for all algorithms."""
        engine = PQCSignatureEngine(algorithm)
        keypair = engine.generate_keypair()

        message = b"Message to sign with PQC"
        signature = engine.sign(message, keypair.private_key)
        valid = engine.verify(message, signature, keypair.public_key)

        assert valid


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_hybrid_encrypt_decrypt(self):
        """Test simple hybrid encrypt/decrypt interface."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()

        plaintext = b"Simple API test"
        ciphertext = hybrid_encrypt(plaintext, keypair.public_key, keypair.key_id)
        decrypted = hybrid_decrypt(ciphertext, keypair.private_key)

        assert decrypted == plaintext

    def test_pqc_sign_verify(self):
        """Test simple PQC sign/verify interface."""
        engine = PQCSignatureEngine(SignatureAlgorithm.ML_DSA_65)
        keypair = engine.generate_keypair()

        message = b"Simple signing API test"
        signature = pqc_sign(message, keypair.private_key)
        valid = pqc_verify(message, signature, keypair.public_key)

        assert valid

    def test_get_available_algorithms(self):
        """Test that available algorithms are returned."""
        kem_algos = get_available_kem_algorithms()
        sig_algos = get_available_sig_algorithms()

        assert "ML-KEM-768" in kem_algos
        assert "ML-KEM-1024" in kem_algos
        assert "ML-DSA-65" in sig_algos


class TestAlgorithmInfo:
    """Tests for algorithm information functions."""

    def test_mlkem_details(self):
        """Test ML-KEM algorithm details."""
        kem = get_mlkem("ML-KEM-768")
        details = kem.get_details()

        assert details["algorithm"] == "ML-KEM-768"
        assert details["nist_level"] == 3
        assert details["standard"] == "NIST FIPS 203"
        assert details["public_key_bytes"] == 1184

    def test_mldsa_details(self):
        """Test ML-DSA algorithm details."""
        sig = get_mldsa("ML-DSA-65")
        details = sig.get_details()

        assert details["algorithm"] == "ML-DSA-65"
        assert details["nist_level"] == 3
        assert details["standard"] == "NIST FIPS 204"


class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_kem_algorithm(self):
        """Test that invalid KEM algorithm raises error."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            get_mlkem("INVALID-KEM")

    def test_invalid_sig_algorithm(self):
        """Test that invalid signature algorithm raises error."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            get_mldsa("INVALID-SIG")

    def test_decap_without_private_key(self):
        """Test that decapsulation without private key raises error."""
        kem = get_mlkem("ML-KEM-768")
        # Don't generate keypair

        with pytest.raises(PQCError, match="No private key"):
            kem.decap_secret(b"fake_ciphertext")
