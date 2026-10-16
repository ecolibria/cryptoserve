"""Tests for hybrid post-quantum cryptography implementation.

Tests real ML-KEM (FIPS 203) and ML-DSA (FIPS 204) using liboqs.
"""

import pytest

from app.core.hybrid_crypto import (
    HybridCryptoEngine,
    HybridCiphertext,
    HybridMode,
    PQCSignatureEngine,
    SignatureAlgorithm,
    is_pqc_available,
    get_mlkem,
    get_mldsa,
    get_slhdsa,
    hybrid_encrypt,
    hybrid_decrypt,
    pqc_sign,
    pqc_verify,
    get_available_kem_algorithms,
    get_available_sig_algorithms,
    get_available_slhdsa_algorithms,
    PQCError,
)

# Skip all tests if liboqs is not available
pytestmark = pytest.mark.skipif(not is_pqc_available(), reason="liboqs not installed")


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

    @pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    @pytest.mark.parametrize(
        "malform",
        [lambda ct: ct[:-1], lambda ct: ct + b"\x00", lambda ct: b""],
        ids=["one-byte-short", "one-byte-long", "empty"],
    )
    def test_mlkem_decap_rejects_wrong_length_ciphertext(self, algorithm, malform):
        """FIPS 203 7.3: a ciphertext of the wrong length is refused before decapsulation."""
        kem = get_mlkem(algorithm)
        ciphertext, _ = kem.encap_secret(kem.generate_keypair())
        malformed = malform(ciphertext)
        refusal = rf"{algorithm} ciphertext must be {len(ciphertext)} bytes, got {len(malformed)}"

        with pytest.raises(PQCError, match=refusal):
            kem.decap_secret(malformed)

    @pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    @pytest.mark.parametrize(
        "malform",
        [lambda pk: pk[:-1], lambda pk: pk + b"\x00"],
        ids=["one-byte-short", "one-byte-long"],
    )
    def test_mlkem_encap_rejects_wrong_length_public_key(self, algorithm, malform):
        """FIPS 203 7.2: an encapsulation key of the wrong length is refused before encapsulation."""
        kem = get_mlkem(algorithm)
        public_key = kem.generate_keypair()
        malformed = malform(public_key)
        refusal = rf"{algorithm} public key must be {len(public_key)} bytes, got {len(malformed)}"

        with pytest.raises(PQCError, match=refusal):
            kem.encap_secret(malformed)

    def test_mlkem_set_keypair_rejects_wrong_length_private_key(self):
        """A decapsulation key of the wrong length is refused when it is set."""
        kem = get_mlkem("ML-KEM-768")
        kem.generate_keypair()
        private_key = kem.private_key

        with pytest.raises(PQCError, match="ML-KEM-768 private key must be 2400 bytes, got 2399"):
            get_mlkem("ML-KEM-768").set_keypair(b"", private_key[:-1])

    def test_mlkem_wrong_length_input_is_a_value_error(self):
        """The refusal is also a ValueError, so callers that map bad input to ValueError keep working."""
        from app.core.hybrid_crypto import PQCInputError

        kem = get_mlkem("ML-KEM-768")
        ciphertext, _ = kem.encap_secret(kem.generate_keypair())

        with pytest.raises(PQCInputError) as refused:
            kem.decap_secret(ciphertext[:-1])
        assert isinstance(refused.value, ValueError)
        assert isinstance(refused.value, PQCError)

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
            sig.generate_keypair()
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


class TestSLHDSA:
    """Tests for SLH-DSA (FIPS 205) hash-based digital signature algorithm."""

    def test_slhdsa_128f_keygen(self):
        """Test SLH-DSA-SHA2-128f key generation."""
        sig = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = sig.generate_keypair()

        assert len(public_key) == 32  # FIPS 205 spec: tiny keys
        assert len(sig.private_key) == 64

    def test_slhdsa_sign_verify(self):
        """Test SLH-DSA signing and verification roundtrip."""
        sig = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = sig.generate_keypair()

        message = b"Test message for SLH-DSA signing"
        signature = sig.sign(message)

        # Verify signature
        assert sig.verify(message, signature, public_key)

    def test_slhdsa_signature_sizes(self):
        """Test SLH-DSA signature sizes match FIPS 205."""
        test_cases = [
            ("SLH-DSA-SHA2-128f", 17088),
            ("SLH-DSA-SHA2-128s", 7856),
            ("SLH-DSA-SHA2-192f", 35664),
            ("SLH-DSA-SHA2-192s", 16224),
            ("SLH-DSA-SHA2-256f", 49856),
            ("SLH-DSA-SHA2-256s", 29792),
        ]
        for algo, expected_sig_len in test_cases:
            sig = get_slhdsa(algo)
            sig.generate_keypair()
            signature = sig.sign(b"test")
            assert len(signature) == expected_sig_len, f"{algo} signature size mismatch"

    def test_slhdsa_key_sizes(self):
        """Test SLH-DSA key sizes match FIPS 205."""
        test_cases = [
            ("SLH-DSA-SHA2-128f", 32, 64),
            ("SLH-DSA-SHA2-128s", 32, 64),
            ("SLH-DSA-SHA2-192f", 48, 96),
            ("SLH-DSA-SHA2-192s", 48, 96),
            ("SLH-DSA-SHA2-256f", 64, 128),
            ("SLH-DSA-SHA2-256s", 64, 128),
        ]
        for algo, expected_pk, expected_sk in test_cases:
            sig = get_slhdsa(algo)
            public_key = sig.generate_keypair()
            assert len(public_key) == expected_pk, f"{algo} public key size mismatch"
            assert len(sig.private_key) == expected_sk, f"{algo} secret key size mismatch"

    def test_slhdsa_wrong_message_fails(self):
        """Test that wrong message fails verification."""
        sig = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = sig.generate_keypair()

        message = b"Original message"
        signature = sig.sign(message)

        # Verify with wrong message should fail
        assert not sig.verify(b"Wrong message", signature, public_key)

    def test_slhdsa_wrong_signature_fails(self):
        """Test that corrupted signature fails verification."""
        sig = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message)

        # Corrupt signature
        corrupted = bytes([signature[0] ^ 0xFF]) + signature[1:]

        assert not sig.verify(message, corrupted, public_key)

    def test_slhdsa_details(self):
        """Test SLH-DSA algorithm details."""
        sig = get_slhdsa("SLH-DSA-SHA2-128f")
        details = sig.get_details()

        assert details["algorithm"] == "SLH-DSA-SHA2-128f"
        assert details["nist_level"] == 1
        assert details["variant"] == "fast"
        assert details["standard"] == "NIST FIPS 205"
        assert details["security_basis"] == "hash-based (conservative)"

    def test_slhdsa_available_algorithms(self):
        """Test that all SLH-DSA algorithms are available."""
        algorithms = get_available_slhdsa_algorithms()
        assert len(algorithms) == 6
        assert "SLH-DSA-SHA2-128f" in algorithms
        assert "SLH-DSA-SHA2-256s" in algorithms


class TestSLHDSAEngine:
    """Tests for PQCSignatureEngine with SLH-DSA algorithms."""

    @pytest.mark.parametrize(
        "algorithm",
        [
            SignatureAlgorithm.SLH_DSA_SHA2_128F,
            SignatureAlgorithm.SLH_DSA_SHA2_128S,
            SignatureAlgorithm.SLH_DSA_SHA2_192F,
            SignatureAlgorithm.SLH_DSA_SHA2_192S,
            SignatureAlgorithm.SLH_DSA_SHA2_256F,
            SignatureAlgorithm.SLH_DSA_SHA2_256S,
        ],
    )
    def test_engine_sign_verify_roundtrip(self, algorithm: SignatureAlgorithm):
        """Test PQCSignatureEngine sign/verify with all SLH-DSA variants."""
        engine = PQCSignatureEngine(algorithm)
        keypair = engine.generate_keypair()

        message = b"Test message for SLH-DSA engine"
        signature = engine.sign(message, keypair.private_key)
        valid = engine.verify(message, signature, keypair.public_key)

        assert valid

    def test_engine_keypair_has_correct_algorithm(self):
        """Test that generated keypair has correct algorithm."""
        engine = PQCSignatureEngine(SignatureAlgorithm.SLH_DSA_SHA2_128F)
        keypair = engine.generate_keypair()

        assert keypair.algorithm == SignatureAlgorithm.SLH_DSA_SHA2_128F
        assert keypair.key_id is not None

    def test_engine_algorithm_info(self):
        """Test PQCSignatureEngine.get_algorithm_info() for SLH-DSA."""
        engine = PQCSignatureEngine(SignatureAlgorithm.SLH_DSA_SHA2_192F)
        info = engine.get_algorithm_info()

        assert info["algorithm"] == "SLH-DSA-SHA2-192f"
        assert info["nist_level"] == 3
        assert info["standard"] == "NIST FIPS 205"


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

    def test_hybrid_ciphertext_deserialize_rejects_truncated_kem_ciphertext(self):
        """A blob shorter than its header's kem_ct_len is refused, not sliced short."""
        engine = HybridCryptoEngine(HybridMode.AES_MLKEM_768)
        keypair = engine.generate_keypair()
        serialized = engine.encrypt(b"Test data", keypair.public_key, keypair.key_id).serialize()

        header_len = int.from_bytes(serialized[:2], "big")
        truncated = serialized[: 2 + header_len + 1087]

        with pytest.raises(ValueError, match="KEM ciphertext truncated"):
            HybridCiphertext.deserialize(truncated)

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

    @pytest.mark.parametrize(
        "algorithm",
        [
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
        ],
    )
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

    def test_invalid_slhdsa_algorithm(self):
        """Test that invalid SLH-DSA algorithm raises error."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            get_slhdsa("INVALID-SLHDSA")

    def test_decap_without_private_key(self):
        """Test that decapsulation without private key raises error."""
        kem = get_mlkem("ML-KEM-768")
        # Don't generate keypair

        with pytest.raises(PQCError, match="No private key"):
            kem.decap_secret(b"fake_ciphertext")
