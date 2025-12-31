"""Tests for the asymmetric encryption engine."""

import pytest
import os

from app.core.asymmetric_engine import (
    asymmetric_engine,
    AsymmetricEngine,
    AsymmetricAlgorithm,
    AsymmetricError,
    KeyNotFoundError,
    DecryptionError,
    UnsupportedAlgorithmError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh asymmetric engine for each test."""
    return AsymmetricEngine()


class TestKeyGeneration:
    """Tests for key pair generation."""

    def test_generate_x25519_key(self, fresh_engine):
        """Test X25519 key pair generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
            context="test",
        )

        assert key_pair.key_id.startswith("asym_test_")
        assert key_pair.algorithm == AsymmetricAlgorithm.X25519_AESGCM
        assert key_pair.private_key is not None
        assert key_pair.public_key is not None
        assert key_pair.created_at is not None

    def test_generate_x25519_chacha20_key(self, fresh_engine):
        """Test X25519+ChaCha20 key pair generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_CHACHA20,
            context="test",
        )

        assert key_pair.algorithm == AsymmetricAlgorithm.X25519_CHACHA20

    def test_generate_ecies_p256_key(self, fresh_engine):
        """Test ECIES P-256 key pair generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P256,
            context="test",
        )

        assert key_pair.algorithm == AsymmetricAlgorithm.ECIES_P256

    def test_generate_ecies_p384_key(self, fresh_engine):
        """Test ECIES P-384 key pair generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P384,
            context="test",
        )

        assert key_pair.algorithm == AsymmetricAlgorithm.ECIES_P384

    def test_generate_rsa_key(self, fresh_engine):
        """Test RSA key pair generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
            context="test",
            rsa_key_size=2048,  # Faster for tests
        )

        assert key_pair.algorithm == AsymmetricAlgorithm.RSA_OAEP_SHA256

    def test_rsa_key_size_validation(self, fresh_engine):
        """Test RSA key size validation."""
        with pytest.raises(AsymmetricError):
            fresh_engine.generate_key_pair(
                algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
                rsa_key_size=1024,  # Too small
            )

    def test_keys_are_unique(self, fresh_engine):
        """Test that generated keys are unique."""
        key1 = fresh_engine.generate_key_pair(context="test")
        key2 = fresh_engine.generate_key_pair(context="test")

        assert key1.key_id != key2.key_id


class TestX25519Encryption:
    """Tests for X25519 encryption."""

    def test_encrypt_decrypt_x25519_aesgcm(self, fresh_engine):
        """Test X25519+AES-GCM encrypt/decrypt roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        assert encrypted.algorithm == AsymmetricAlgorithm.X25519_AESGCM
        assert encrypted.ephemeral_public_key is not None
        assert len(encrypted.ephemeral_public_key) == 32

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        assert decrypted.plaintext == plaintext

    def test_encrypt_decrypt_x25519_chacha20(self, fresh_engine):
        """Test X25519+ChaCha20 encrypt/decrypt roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_CHACHA20,
        )

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.X25519_CHACHA20,
        )

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.X25519_CHACHA20,
        )

        assert decrypted.plaintext == plaintext

    def test_encrypt_by_key_id(self, fresh_engine):
        """Test encryption using key ID."""
        key_pair = fresh_engine.generate_key_pair()

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(plaintext, key_pair.key_id)

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.key_id,
        )

        assert decrypted.plaintext == plaintext


class TestECIESEncryption:
    """Tests for ECIES encryption."""

    def test_encrypt_decrypt_ecies_p256(self, fresh_engine):
        """Test ECIES P-256 encrypt/decrypt roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P256,
        )

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.ECIES_P256,
        )

        assert encrypted.algorithm == AsymmetricAlgorithm.ECIES_P256
        assert encrypted.ephemeral_public_key is not None
        assert len(encrypted.ephemeral_public_key) == 65  # Uncompressed point

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.ECIES_P256,
        )

        assert decrypted.plaintext == plaintext

    def test_encrypt_decrypt_ecies_p384(self, fresh_engine):
        """Test ECIES P-384 encrypt/decrypt roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P384,
        )

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.ECIES_P384,
        )

        assert len(encrypted.ephemeral_public_key) == 97  # P-384 uncompressed point

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.ECIES_P384,
        )

        assert decrypted.plaintext == plaintext


class TestRSAEncryption:
    """Tests for RSA-OAEP encryption."""

    def test_encrypt_decrypt_rsa_sha256_direct(self, fresh_engine):
        """Test RSA-OAEP-SHA256 direct encryption for small messages."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
            rsa_key_size=2048,
        )

        # Small message - direct RSA encryption
        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
        )

        assert encrypted.algorithm == AsymmetricAlgorithm.RSA_OAEP_SHA256
        assert encrypted.ephemeral_public_key is None  # No ephemeral for RSA
        # First byte is mode indicator (0x00 for direct)
        assert encrypted.ciphertext[0] == 0x00

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
        )

        assert decrypted.plaintext == plaintext

    def test_encrypt_decrypt_rsa_sha256_hybrid(self, fresh_engine):
        """Test RSA-OAEP-SHA256 hybrid encryption for large messages."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
            rsa_key_size=2048,
        )

        # Large message - hybrid encryption
        plaintext = os.urandom(1000)
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
        )

        # First byte is mode indicator (0x01 for hybrid)
        assert encrypted.ciphertext[0] == 0x01

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
        )

        assert decrypted.plaintext == plaintext

    def test_encrypt_decrypt_rsa_sha384(self, fresh_engine):
        """Test RSA-OAEP-SHA384 encryption."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA384,
            rsa_key_size=2048,
        )

        plaintext = b"Hello, World!"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair.public_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA384,
        )

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.private_key,
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA384,
        )

        assert decrypted.plaintext == plaintext


class TestKeyManagement:
    """Tests for key management operations."""

    def test_get_public_key_raw(self, fresh_engine):
        """Test getting public key in raw format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        public_key = fresh_engine.get_public_key(key_pair.key_id, format="raw")

        assert isinstance(public_key, bytes)
        assert len(public_key) == 32  # X25519 key size

    def test_get_public_key_pem(self, fresh_engine):
        """Test getting public key in PEM format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        public_key = fresh_engine.get_public_key(key_pair.key_id, format="pem")

        assert isinstance(public_key, bytes)
        assert b"-----BEGIN PUBLIC KEY-----" in public_key

    def test_get_public_key_jwk(self, fresh_engine):
        """Test getting public key in JWK format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        jwk = fresh_engine.get_public_key(key_pair.key_id, format="jwk")

        assert isinstance(jwk, dict)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "X25519"
        assert "x" in jwk
        assert jwk["kid"] == key_pair.key_id
        assert jwk["use"] == "enc"

    def test_get_public_key_jwk_ec(self, fresh_engine):
        """Test getting EC public key in JWK format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P256,
        )

        jwk = fresh_engine.get_public_key(key_pair.key_id, format="jwk")

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_get_public_key_jwk_rsa(self, fresh_engine):
        """Test getting RSA public key in JWK format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
            rsa_key_size=2048,
        )

        jwk = fresh_engine.get_public_key(key_pair.key_id, format="jwk")

        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk

    def test_get_public_key_not_found(self, fresh_engine):
        """Test getting non-existent key."""
        with pytest.raises(KeyNotFoundError):
            fresh_engine.get_public_key("nonexistent-key")

    def test_import_public_key_raw(self, fresh_engine):
        """Test importing a public key in raw format."""
        # Generate a key pair
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        # Export public key
        public_key_bytes = fresh_engine.get_public_key(key_pair.key_id, format="raw")

        # Import into new engine
        new_engine = AsymmetricEngine()
        imported_key_id = new_engine.import_public_key(
            public_key_bytes,
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
            key_id="imported-key",
        )

        assert imported_key_id == "imported-key"

        # Encrypt with imported key, decrypt with original
        plaintext = b"Hello, World!"
        encrypted = new_engine.encrypt(plaintext, imported_key_id)

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.key_id,
        )

        assert decrypted.plaintext == plaintext

    def test_import_public_key_jwk(self, fresh_engine):
        """Test importing a public key in JWK format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
        )

        jwk = fresh_engine.get_public_key(key_pair.key_id, format="jwk")

        new_engine = AsymmetricEngine()
        imported_key_id = new_engine.import_public_key(
            jwk,
            algorithm=AsymmetricAlgorithm.X25519_AESGCM,
            format="jwk",
        )

        # Encrypt with imported key
        plaintext = b"Test message"
        encrypted = new_engine.encrypt(plaintext, imported_key_id)

        decrypted = fresh_engine.decrypt(
            encrypted.ciphertext,
            key_pair.key_id,
        )

        assert decrypted.plaintext == plaintext

    def test_list_keys(self, fresh_engine):
        """Test listing keys."""
        key1 = fresh_engine.generate_key_pair(context="ctx1")
        key2 = fresh_engine.generate_key_pair(context="ctx2")
        key3 = fresh_engine.generate_key_pair(context="ctx1")

        all_keys = fresh_engine.list_keys()
        assert len(all_keys) == 3

        ctx1_keys = fresh_engine.list_keys(context="ctx1")
        assert len(ctx1_keys) == 2

        ctx2_keys = fresh_engine.list_keys(context="ctx2")
        assert len(ctx2_keys) == 1

    def test_delete_key(self, fresh_engine):
        """Test deleting a key."""
        key_pair = fresh_engine.generate_key_pair()

        assert fresh_engine.delete_key(key_pair.key_id)
        assert not fresh_engine.delete_key(key_pair.key_id)  # Already deleted

        with pytest.raises(KeyNotFoundError):
            fresh_engine.get_public_key(key_pair.key_id)


class TestDecryptionErrors:
    """Tests for decryption error handling."""

    def test_wrong_key_x25519(self, fresh_engine):
        """Test decryption with wrong X25519 key."""
        key_pair1 = fresh_engine.generate_key_pair()
        key_pair2 = fresh_engine.generate_key_pair()

        plaintext = b"Secret message"
        encrypted = fresh_engine.encrypt(plaintext, key_pair1.key_id)

        with pytest.raises(DecryptionError):
            fresh_engine.decrypt(encrypted.ciphertext, key_pair2.key_id)

    def test_wrong_key_ecies(self, fresh_engine):
        """Test decryption with wrong ECIES key."""
        key_pair1 = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P256
        )
        key_pair2 = fresh_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.ECIES_P256
        )

        plaintext = b"Secret message"
        encrypted = fresh_engine.encrypt(
            plaintext,
            key_pair1.key_id,
        )

        with pytest.raises(DecryptionError):
            fresh_engine.decrypt(
                encrypted.ciphertext,
                key_pair2.key_id,
            )

    def test_corrupted_ciphertext(self, fresh_engine):
        """Test decryption with corrupted ciphertext."""
        key_pair = fresh_engine.generate_key_pair()

        plaintext = b"Secret message"
        encrypted = fresh_engine.encrypt(plaintext, key_pair.key_id)

        # Corrupt the ciphertext
        corrupted = bytearray(encrypted.ciphertext)
        corrupted[-1] ^= 0xFF
        corrupted = bytes(corrupted)

        with pytest.raises(DecryptionError):
            fresh_engine.decrypt(corrupted, key_pair.key_id)

    def test_key_not_found(self, fresh_engine):
        """Test decryption with non-existent key."""
        with pytest.raises(KeyNotFoundError):
            fresh_engine.decrypt(b"ciphertext", "nonexistent-key")


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_plaintext(self, fresh_engine):
        """Test encrypting empty data."""
        key_pair = fresh_engine.generate_key_pair()

        encrypted = fresh_engine.encrypt(b"", key_pair.key_id)
        decrypted = fresh_engine.decrypt(encrypted.ciphertext, key_pair.key_id)

        assert decrypted.plaintext == b""

    def test_large_plaintext(self, fresh_engine):
        """Test encrypting large data."""
        key_pair = fresh_engine.generate_key_pair()

        plaintext = os.urandom(1024 * 1024)  # 1MB
        encrypted = fresh_engine.encrypt(plaintext, key_pair.key_id)
        decrypted = fresh_engine.decrypt(encrypted.ciphertext, key_pair.key_id)

        assert decrypted.plaintext == plaintext

    def test_binary_data(self, fresh_engine):
        """Test encrypting binary data."""
        key_pair = fresh_engine.generate_key_pair()

        plaintext = bytes(range(256))
        encrypted = fresh_engine.encrypt(plaintext, key_pair.key_id)
        decrypted = fresh_engine.decrypt(encrypted.ciphertext, key_pair.key_id)

        assert decrypted.plaintext == plaintext


class TestAlgorithmMetadata:
    """Tests for algorithm metadata."""

    def test_algorithm_info(self, fresh_engine):
        """Test algorithm metadata."""
        assert AsymmetricAlgorithm.X25519_AESGCM in fresh_engine.ALGORITHMS
        info = fresh_engine.ALGORITHMS[AsymmetricAlgorithm.X25519_AESGCM]

        assert info["key_exchange"] == "X25519"
        assert info["encryption"] == "AES-256-GCM"
        assert info["security_bits"] == 128

    def test_all_algorithms_have_metadata(self, fresh_engine):
        """Test all algorithms have metadata."""
        for algo in AsymmetricAlgorithm:
            assert algo in fresh_engine.ALGORITHMS
            info = fresh_engine.ALGORITHMS[algo]
            assert "encryption" in info
            assert "security_bits" in info
