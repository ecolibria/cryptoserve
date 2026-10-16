"""Tests for PQC enhancement features.

Tests for:
1. AES-XTS disk encryption with HMAC integrity
2. X25519 + ML-KEM hybrid key exchange
3. All ML-DSA sizes (44/65/87)
"""

import pytest
import base64
import os

from app.core.crypto_engine import CipherFactory, CryptoError, DecryptionError
from app.core.hybrid_crypto import (
    is_pqc_available,
    get_mldsa,
    SignatureAlgorithm,
    PQCSignatureEngine,
)

# Skip PQC tests if liboqs is not available
pqc_skip = pytest.mark.skipif(not is_pqc_available(), reason="liboqs not installed")


class TestAESXTS:
    """Tests for AES-XTS disk encryption mode."""

    def test_xts_encrypt_decrypt_roundtrip(self):
        """Test AES-XTS encrypt/decrypt roundtrip."""
        key = os.urandom(64)  # XTS requires 64-byte key (two 256-bit keys)
        tweak = os.urandom(16)  # 16-byte tweak (like sector number)
        plaintext = os.urandom(512)  # Typical disk sector size

        ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak)
        decrypted = CipherFactory.decrypt_xts(key, ciphertext, tweak)

        assert decrypted == plaintext

    def test_xts_minimum_plaintext_size(self):
        """Test XTS requires minimum 16 bytes plaintext."""
        key = os.urandom(64)
        tweak = os.urandom(16)
        plaintext = b"short"  # Less than 16 bytes

        with pytest.raises(CryptoError, match="plaintext >= 16 bytes"):
            CipherFactory.encrypt_xts(key, plaintext, tweak)

    def test_xts_requires_64_byte_key(self):
        """Test XTS requires exactly 64-byte key."""
        tweak = os.urandom(16)
        plaintext = os.urandom(64)

        with pytest.raises(CryptoError, match="64-byte key"):
            CipherFactory.encrypt_xts(os.urandom(32), plaintext, tweak)

        with pytest.raises(CryptoError, match="64-byte key"):
            CipherFactory.encrypt_xts(os.urandom(48), plaintext, tweak)

    def test_xts_requires_16_byte_tweak(self):
        """Test XTS requires exactly 16-byte tweak."""
        key = os.urandom(64)
        plaintext = os.urandom(64)

        with pytest.raises(CryptoError, match="16-byte tweak"):
            CipherFactory.encrypt_xts(key, plaintext, os.urandom(12))

    def test_xts_hmac_integrity(self):
        """Test XTS HMAC detects tampering."""
        key = os.urandom(64)
        tweak = os.urandom(16)
        plaintext = os.urandom(256)

        ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak)

        # Tamper with ciphertext (before HMAC)
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        with pytest.raises(DecryptionError, match="HMAC verification failed"):
            CipherFactory.decrypt_xts(key, tampered, tweak)

    def test_xts_wrong_tweak_fails(self):
        """Test XTS decryption fails with wrong tweak."""
        key = os.urandom(64)
        tweak1 = os.urandom(16)
        tweak2 = os.urandom(16)
        plaintext = os.urandom(64)

        ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak1)

        # Decryption with wrong tweak should fail HMAC
        with pytest.raises(DecryptionError, match="HMAC verification failed"):
            CipherFactory.decrypt_xts(key, ciphertext, tweak2)

    def test_xts_wrong_key_fails(self):
        """Test XTS decryption fails with wrong key."""
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        tweak = os.urandom(16)
        plaintext = os.urandom(64)

        ciphertext = CipherFactory.encrypt_xts(key1, plaintext, tweak)

        with pytest.raises(DecryptionError, match="HMAC verification failed"):
            CipherFactory.decrypt_xts(key2, ciphertext, tweak)

    def test_xts_sector_based_encryption(self):
        """Test XTS with different tweaks for different sectors."""
        key = os.urandom(64)
        sector0 = b"This is sector 0 data!" + os.urandom(42)
        sector1 = b"This is sector 1 data!" + os.urandom(42)

        # Different tweaks for different sectors
        tweak0 = (0).to_bytes(16, "little")  # Sector 0
        tweak1 = (1).to_bytes(16, "little")  # Sector 1

        ct0 = CipherFactory.encrypt_xts(key, sector0, tweak0)
        ct1 = CipherFactory.encrypt_xts(key, sector1, tweak1)

        # Ciphertexts should be different
        assert ct0 != ct1

        # Each decrypts correctly with its own tweak
        assert CipherFactory.decrypt_xts(key, ct0, tweak0) == sector0
        assert CipherFactory.decrypt_xts(key, ct1, tweak1) == sector1

    def test_xts_various_sizes(self):
        """Test XTS with various plaintext sizes."""
        key = os.urandom(64)
        tweak = os.urandom(16)

        for size in [16, 32, 64, 128, 256, 512, 1024, 4096]:
            plaintext = os.urandom(size)
            ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak)
            decrypted = CipherFactory.decrypt_xts(key, ciphertext, tweak)
            assert decrypted == plaintext, f"Failed for size {size}"


@pqc_skip
class TestHybridKeyExchange:
    """Tests for X25519 + ML-KEM hybrid key exchange."""

    def test_generate_keypair(self):
        """Test hybrid KEX keypair generation."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        assert len(keypair.x25519_public) == 32
        assert len(keypair.x25519_private) == 32
        assert len(keypair.mlkem_public) == 1184  # ML-KEM-768 public key size
        assert keypair.key_id is not None

    def test_encapsulate_decapsulate_roundtrip(self):
        """Test encapsulation and decapsulation produce same shared secret."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        # Encapsulate (sender)
        encap, shared_secret_sender = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)

        # Decapsulate (recipient)
        shared_secret_recipient = kex.decapsulate(encap, keypair)

        assert shared_secret_sender == shared_secret_recipient
        assert len(shared_secret_sender) == 32

    def test_different_keypairs_different_secrets(self):
        """Test that different keypairs produce different shared secrets."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)

        keypair1 = kex.generate_keypair()
        keypair2 = kex.generate_keypair()

        _, ss1 = kex.encapsulate(keypair1.x25519_public, keypair1.mlkem_public)
        _, ss2 = kex.encapsulate(keypair2.x25519_public, keypair2.mlkem_public)

        assert ss1 != ss2

    def test_encapsulation_serialization(self):
        """Test encapsulation serialization roundtrip."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        encap, shared_secret1 = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)

        # Serialize and deserialize
        serialized = kex.serialize_encapsulation(encap)
        deserialized = HybridKeyExchange.deserialize_encapsulation(serialized)

        # Decapsulate with deserialized encapsulation
        shared_secret2 = kex.decapsulate(deserialized, keypair)

        assert shared_secret1 == shared_secret2

    def test_keypair_serialization(self):
        """Test keypair serialization roundtrip."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        # Serialize and deserialize
        serialized = kex.serialize_keypair(keypair)
        deserialized = HybridKeyExchange.deserialize_keypair(serialized)

        assert deserialized.x25519_public == keypair.x25519_public
        assert deserialized.x25519_private == keypair.x25519_private
        assert deserialized.mlkem_public == keypair.mlkem_public
        assert deserialized.mlkem_private == keypair.mlkem_private
        assert deserialized.key_id == keypair.key_id
        assert deserialized.mode == keypair.mode

    @pytest.mark.parametrize(
        "mode",
        [
            pytest.param("X25519+ML-KEM-768", id="768"),
            pytest.param("X25519+ML-KEM-1024", id="1024"),
        ],
    )
    def test_all_modes(self, mode):
        """Test all hybrid KEX modes work correctly."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex_mode = HybridKEXMode(mode)
        kex = HybridKeyExchange(kex_mode)
        keypair = kex.generate_keypair()

        encap, ss1 = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)
        ss2 = kex.decapsulate(encap, keypair)

        assert ss1 == ss2

    def test_mode_mismatch_fails(self):
        """Test that mode mismatch is detected during decapsulation."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode, HybridKEXEncapsulation
        from app.core.hybrid_crypto import PQCError

        kex768 = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair768 = kex768.generate_keypair()

        encap, _ = kex768.encapsulate(keypair768.x25519_public, keypair768.mlkem_public)

        # Tamper with encapsulation mode
        wrong_mode_encap = HybridKEXEncapsulation(
            x25519_public=encap.x25519_public,
            mlkem_ciphertext=encap.mlkem_ciphertext,
            mode=HybridKEXMode.X25519_MLKEM_1024,  # Wrong mode
        )

        with pytest.raises(PQCError, match="Mode mismatch"):
            kex768.decapsulate(wrong_mode_encap, keypair768)

    def test_deserialize_rejects_truncated_mlkem_ciphertext(self):
        """A blob shorter than its header's declared lengths is refused, not sliced short."""
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()
        encap, _ = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)
        serialized = kex.serialize_encapsulation(encap)

        with pytest.raises(ValueError, match="truncated"):
            HybridKeyExchange.deserialize_encapsulation(serialized[:-1])

    def test_kex_info(self):
        """Test hybrid KEX mode information."""
        from app.core.hybrid_kex import HybridKEXMode, get_hybrid_kex_info

        info768 = get_hybrid_kex_info(HybridKEXMode.X25519_MLKEM_768)
        assert info768["nist_pqc_level"] == 3
        assert info768["shared_secret_bytes"] == 32
        assert info768["classical_algorithm"] == "X25519 (Curve25519 ECDH)"

        info1024 = get_hybrid_kex_info(HybridKEXMode.X25519_MLKEM_1024)
        assert info1024["nist_pqc_level"] == 5
        assert info1024["quantum_security_bits"] == 256


@pytest.fixture
def kex_client():
    """The key exchange routes, with the SDK identity check stubbed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api import hybrid_kex as kex_api

    app = FastAPI()
    app.include_router(kex_api.router)
    app.dependency_overrides[kex_api.get_sdk_identity] = lambda: object()
    stored_before = set(kex_api._kex_key_store)
    with TestClient(app) as client:
        yield client
    for key_id in set(kex_api._kex_key_store) - stored_before:
        del kex_api._kex_key_store[key_id]


@pqc_skip
class TestHybridKEXRoutes:
    """The key exchange routes refuse a wrong-length ML-KEM input as a client error."""

    def test_decapsulate_refuses_a_one_byte_short_mlkem_ciphertext(self, kex_client):
        from app.core.hybrid_kex import HybridKeyExchange, HybridKEXEncapsulation, HybridKEXMode

        key = kex_client.post("/api/v1/kex/keys/generate", json={"mode": "X25519+ML-KEM-768"})
        assert key.status_code == 200, key.text
        key = key.json()
        sent = kex_client.post(
            "/api/v1/kex/encapsulate",
            json={
                "x25519PublicKey": key["x25519PublicKey"],
                "mlkemPublicKey": key["mlkemPublicKey"],
                "mode": key["mode"],
            },
        )
        assert sent.status_code == 200, sent.text

        # The well-formed blob decapsulates, so the refusal below is the length check.
        received = kex_client.post(
            "/api/v1/kex/decapsulate",
            json={"encapsulation": sent.json()["encapsulation"], "keyId": key["keyId"]},
        )
        assert received.status_code == 200, received.text
        assert received.json()["sharedSecret"] == sent.json()["sharedSecret"]

        encap = HybridKeyExchange.deserialize_encapsulation(base64.b64decode(sent.json()["encapsulation"]))
        short = HybridKEXEncapsulation(
            x25519_public=encap.x25519_public,
            mlkem_ciphertext=encap.mlkem_ciphertext[:-1],
            mode=encap.mode,
        )
        blob = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768).serialize_encapsulation(short)

        response = kex_client.post(
            "/api/v1/kex/decapsulate",
            json={"encapsulation": base64.b64encode(blob).decode("ascii"), "keyId": key["keyId"]},
        )

        assert response.status_code == 400, response.text
        assert "sharedSecret" not in response.json()
        assert "must be 1088 bytes, got 1087" in response.json()["detail"]

    def test_encapsulate_refuses_a_one_byte_short_mlkem_public_key(self, kex_client):
        key = kex_client.post("/api/v1/kex/keys/generate", json={"mode": "X25519+ML-KEM-768"})
        assert key.status_code == 200, key.text
        key = key.json()
        short_public_key = base64.b64decode(key["mlkemPublicKey"])[:-1]

        response = kex_client.post(
            "/api/v1/kex/encapsulate",
            json={
                "x25519PublicKey": key["x25519PublicKey"],
                "mlkemPublicKey": base64.b64encode(short_public_key).decode("ascii"),
                "mode": key["mode"],
            },
        )

        assert response.status_code == 400, response.text
        assert "sharedSecret" not in response.json()
        assert "must be 1184 bytes, got 1183" in response.json()["detail"]


@pqc_skip
class TestMLDSAAllSizes:
    """Tests for all ML-DSA sizes (44/65/87)."""

    @pytest.mark.parametrize(
        "algorithm,expected_pk_len,expected_sk_len,expected_sig_len,level",
        [
            ("ML-DSA-44", 1312, 2560, 2420, 2),
            ("ML-DSA-65", 1952, 4032, 3309, 3),
            ("ML-DSA-87", 2592, 4896, 4627, 5),
        ],
    )
    def test_mldsa_key_sizes(self, algorithm, expected_pk_len, expected_sk_len, expected_sig_len, level):
        """Test ML-DSA key and signature sizes match FIPS 204."""
        sig = get_mldsa(algorithm)
        public_key = sig.generate_keypair()

        assert len(public_key) == expected_pk_len
        assert len(sig.private_key) == expected_sk_len

        signature = sig.sign(b"test message")
        assert len(signature) == expected_sig_len

        details = sig.get_details()
        assert details["nist_level"] == level

    @pytest.mark.parametrize(
        "algorithm",
        [
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
        ],
    )
    def test_mldsa_engine_all_variants(self, algorithm):
        """Test PQCSignatureEngine works with all ML-DSA variants."""
        engine = PQCSignatureEngine(algorithm)
        keypair = engine.generate_keypair()

        message = b"Test message for all ML-DSA variants"
        signature = engine.sign(message, keypair.private_key)
        valid = engine.verify(message, signature, keypair.public_key)

        assert valid

    @pytest.mark.parametrize("algorithm", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_mldsa_sign_verify_roundtrip(self, algorithm):
        """Test sign/verify roundtrip for all ML-DSA sizes."""
        sig = get_mldsa(algorithm)
        public_key = sig.generate_keypair()

        message = b"Test message for ML-DSA"
        signature = sig.sign(message)

        assert sig.verify(message, signature, public_key)

    @pytest.mark.parametrize("algorithm", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_mldsa_wrong_message_fails(self, algorithm):
        """Test all ML-DSA variants reject wrong message."""
        sig = get_mldsa(algorithm)
        public_key = sig.generate_keypair()

        message = b"Original message"
        signature = sig.sign(message)

        assert not sig.verify(b"Wrong message", signature, public_key)

    @pytest.mark.parametrize("algorithm", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_mldsa_wrong_signature_fails(self, algorithm):
        """Test all ML-DSA variants reject corrupted signature."""
        sig = get_mldsa(algorithm)
        public_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message)

        # Corrupt signature
        corrupted = bytes([signature[0] ^ 0xFF]) + signature[1:]
        assert not sig.verify(message, corrupted, public_key)

    def test_mldsa_all_sizes_different_keys(self):
        """Test that different ML-DSA sizes produce different key sizes."""
        pk_sizes = {}
        for algorithm in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            sig = get_mldsa(algorithm)
            pk = sig.generate_keypair()
            pk_sizes[algorithm] = len(pk)

        # All should be different sizes
        assert pk_sizes["ML-DSA-44"] < pk_sizes["ML-DSA-65"]
        assert pk_sizes["ML-DSA-65"] < pk_sizes["ML-DSA-87"]
