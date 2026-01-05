"""Tests for HPKE (Hybrid Public Key Encryption) engine."""

import pytest

from app.core.hpke_engine import (
    HPKEEngine,
    HPKECipherSuite,
    HPKEMode,
    HPKEKeyPair,
    HPKEEncryptedMessage,
    HPKEError,
    get_hpke_engine,
    hpke_available,
    HPKE_AVAILABLE,
)


# Skip all tests if pyhpke is not available
pytestmark = pytest.mark.skipif(
    not HPKE_AVAILABLE,
    reason="pyhpke not installed"
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def engine():
    """Create HPKE engine for testing."""
    return HPKEEngine()


@pytest.fixture
def x25519_keypair(engine):
    """Generate X25519 key pair."""
    return engine.generate_keypair(HPKECipherSuite.X25519_SHA256_AES128GCM)


@pytest.fixture
def p256_keypair(engine):
    """Generate P-256 key pair."""
    return engine.generate_keypair(HPKECipherSuite.P256_SHA256_AES128GCM)


# =============================================================================
# Key Generation Tests
# =============================================================================


class TestKeyGeneration:
    """Tests for HPKE key generation."""

    def test_generate_x25519_keypair(self, engine):
        """Test X25519 key pair generation."""
        keypair = engine.generate_keypair(HPKECipherSuite.X25519_SHA256_AES128GCM)

        assert keypair is not None
        assert isinstance(keypair, HPKEKeyPair)
        assert len(keypair.private_key) == 32  # X25519 private key
        assert len(keypair.public_key) == 32   # X25519 public key
        assert keypair.suite == HPKECipherSuite.X25519_SHA256_AES128GCM

    def test_generate_p256_keypair(self, engine):
        """Test P-256 key pair generation."""
        keypair = engine.generate_keypair(HPKECipherSuite.P256_SHA256_AES128GCM)

        assert keypair is not None
        assert len(keypair.private_key) > 0
        assert len(keypair.public_key) > 0
        assert keypair.suite == HPKECipherSuite.P256_SHA256_AES128GCM

    def test_generate_p384_keypair(self, engine):
        """Test P-384 key pair generation."""
        keypair = engine.generate_keypair(HPKECipherSuite.P384_SHA384_AES256GCM)

        assert keypair is not None
        assert len(keypair.private_key) > 0
        assert len(keypair.public_key) > 0
        assert keypair.suite == HPKECipherSuite.P384_SHA384_AES256GCM

    def test_keypairs_are_unique(self, engine):
        """Test that generated key pairs are unique."""
        kp1 = engine.generate_keypair()
        kp2 = engine.generate_keypair()

        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key


# =============================================================================
# Base Mode Encryption Tests
# =============================================================================


class TestBaseEncryption:
    """Tests for HPKE Base mode encryption."""

    def test_encrypt_decrypt_x25519(self, engine, x25519_keypair):
        """Test encryption/decryption with X25519."""
        plaintext = b"Hello, HPKE!"

        encrypted = engine.encrypt(
            x25519_keypair.public_key,
            plaintext,
            suite=HPKECipherSuite.X25519_SHA256_AES128GCM,
        )

        assert encrypted.enc is not None
        assert encrypted.ciphertext is not None
        assert encrypted.ciphertext != plaintext
        assert encrypted.mode == HPKEMode.BASE

        decrypted = engine.decrypt(x25519_keypair.private_key, encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_p256(self, engine, p256_keypair):
        """Test encryption/decryption with P-256."""
        plaintext = b"Hello, P-256 HPKE!"

        encrypted = engine.encrypt(
            p256_keypair.public_key,
            plaintext,
            suite=HPKECipherSuite.P256_SHA256_AES128GCM,
        )

        decrypted = engine.decrypt(p256_keypair.private_key, encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_chacha20(self, engine):
        """Test encryption/decryption with ChaCha20-Poly1305."""
        keypair = engine.generate_keypair(HPKECipherSuite.X25519_SHA256_CHACHA20)
        plaintext = b"ChaCha20 test message"

        encrypted = engine.encrypt(
            keypair.public_key,
            plaintext,
            suite=HPKECipherSuite.X25519_SHA256_CHACHA20,
        )

        decrypted = engine.decrypt(keypair.private_key, encrypted)
        assert decrypted == plaintext

    def test_encrypt_with_info(self, engine, x25519_keypair):
        """Test encryption with context info."""
        plaintext = b"Message with context"
        info = b"application-specific-context"

        encrypted = engine.encrypt(
            x25519_keypair.public_key,
            plaintext,
            info=info,
        )

        assert encrypted.info == info
        decrypted = engine.decrypt(x25519_keypair.private_key, encrypted)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self, engine, x25519_keypair):
        """Test encryption with additional authenticated data."""
        plaintext = b"Message with AAD"
        aad = b"additional-authenticated-data"

        encrypted = engine.encrypt(
            x25519_keypair.public_key,
            plaintext,
            aad=aad,
        )

        assert encrypted.aad == aad
        decrypted = engine.decrypt(x25519_keypair.private_key, encrypted)
        assert decrypted == plaintext

    def test_decrypt_wrong_key_fails(self, engine, x25519_keypair):
        """Test that decryption with wrong key fails."""
        plaintext = b"Secret message"
        wrong_keypair = engine.generate_keypair()

        encrypted = engine.encrypt(x25519_keypair.public_key, plaintext)

        with pytest.raises(Exception):  # pyhpke raises various exceptions
            engine.decrypt(wrong_keypair.private_key, encrypted)

    def test_encrypt_empty_message(self, engine, x25519_keypair):
        """Test encryption of empty message."""
        plaintext = b""

        encrypted = engine.encrypt(x25519_keypair.public_key, plaintext)
        decrypted = engine.decrypt(x25519_keypair.private_key, encrypted)

        assert decrypted == plaintext

    def test_encrypt_large_message(self, engine, x25519_keypair):
        """Test encryption of large message."""
        plaintext = b"A" * 10000  # 10KB message

        encrypted = engine.encrypt(x25519_keypair.public_key, plaintext)
        decrypted = engine.decrypt(x25519_keypair.private_key, encrypted)

        assert decrypted == plaintext


# =============================================================================
# Auth Mode Encryption Tests
# =============================================================================


class TestAuthEncryption:
    """Tests for HPKE Auth mode (sender authentication)."""

    def test_encrypt_decrypt_with_auth(self, engine):
        """Test authenticated encryption/decryption."""
        sender = engine.generate_keypair()
        recipient = engine.generate_keypair()
        plaintext = b"Authenticated message"

        encrypted = engine.encrypt_with_auth(
            sender.private_key,
            recipient.public_key,
            plaintext,
        )

        assert encrypted.mode == HPKEMode.AUTH

        decrypted = engine.decrypt_with_auth(
            recipient.private_key,
            sender.public_key,
            encrypted,
        )

        assert decrypted == plaintext

    def test_auth_wrong_sender_key_fails(self, engine):
        """Test that auth decryption fails with wrong sender key."""
        sender = engine.generate_keypair()
        recipient = engine.generate_keypair()
        wrong_sender = engine.generate_keypair()
        plaintext = b"Authenticated message"

        encrypted = engine.encrypt_with_auth(
            sender.private_key,
            recipient.public_key,
            plaintext,
        )

        with pytest.raises(Exception):
            engine.decrypt_with_auth(
                recipient.private_key,
                wrong_sender.public_key,  # Wrong sender key
                encrypted,
            )


# =============================================================================
# PSK Mode Encryption Tests
# =============================================================================


class TestPSKEncryption:
    """Tests for HPKE PSK mode (pre-shared key)."""

    def test_encrypt_decrypt_with_psk(self, engine, x25519_keypair):
        """Test PSK encryption/decryption."""
        plaintext = b"PSK authenticated message"
        psk = b"shared-secret-key-32bytes!!!!"  # At least 32 bytes
        psk_id = b"psk-identifier"

        encrypted = engine.encrypt_with_psk(
            x25519_keypair.public_key,
            plaintext,
            psk=psk,
            psk_id=psk_id,
        )

        assert encrypted.mode == HPKEMode.PSK

        decrypted = engine.decrypt_with_psk(
            x25519_keypair.private_key,
            encrypted,
            psk=psk,
            psk_id=psk_id,
        )

        assert decrypted == plaintext

    def test_psk_wrong_key_fails(self, engine, x25519_keypair):
        """Test that PSK decryption fails with wrong PSK."""
        plaintext = b"PSK message"
        psk = b"correct-shared-secret-32bytes!"
        wrong_psk = b"wrong-shared-secret-32bytes!!"
        psk_id = b"psk-id"

        encrypted = engine.encrypt_with_psk(
            x25519_keypair.public_key,
            plaintext,
            psk=psk,
            psk_id=psk_id,
        )

        with pytest.raises(Exception):
            engine.decrypt_with_psk(
                x25519_keypair.private_key,
                encrypted,
                psk=wrong_psk,
                psk_id=psk_id,
            )


# =============================================================================
# Cipher Suite Tests
# =============================================================================


class TestCipherSuites:
    """Tests for cipher suite functionality."""

    def test_list_cipher_suites(self, engine):
        """Test listing all cipher suites."""
        suites = engine.list_cipher_suites()

        assert len(suites) == 5
        assert all("suite" in s for s in suites)
        assert all("name" in s for s in suites)
        assert all("security_level" in s for s in suites)

    def test_get_suite_info_x25519(self, engine):
        """Test getting X25519 suite info."""
        info = engine.get_suite_info(HPKECipherSuite.X25519_SHA256_AES128GCM)

        assert info["kem"] == "X25519"
        assert info["kdf"] == "HKDF-SHA256"
        assert info["aead"] == "AES-128-GCM"
        assert info["security_level"] == 128
        assert info["recommended"] is True

    def test_get_suite_info_p256(self, engine):
        """Test getting P-256 suite info."""
        info = engine.get_suite_info(HPKECipherSuite.P256_SHA256_AES128GCM)

        assert info["kem"] == "P-256"
        assert info["nist_approved"] is True

    def test_get_suite_info_p384(self, engine):
        """Test getting P-384 suite info."""
        info = engine.get_suite_info(HPKECipherSuite.P384_SHA384_AES256GCM)

        assert info["kem"] == "P-384"
        assert info["security_level"] == 192
        assert info["nist_approved"] is True

    @pytest.mark.parametrize("suite", list(HPKECipherSuite))
    def test_all_suites_work(self, engine, suite):
        """Test that all cipher suites can encrypt/decrypt."""
        keypair = engine.generate_keypair(suite)
        plaintext = b"Test message for suite"

        encrypted = engine.encrypt(keypair.public_key, plaintext, suite=suite)
        decrypted = engine.decrypt(keypair.private_key, encrypted)

        assert decrypted == plaintext


# =============================================================================
# Singleton and Utility Tests
# =============================================================================


class TestUtilities:
    """Tests for utility functions."""

    def test_hpke_available(self):
        """Test HPKE availability check."""
        assert hpke_available() is True

    def test_get_hpke_engine_singleton(self):
        """Test singleton engine access."""
        engine1 = get_hpke_engine()
        engine2 = get_hpke_engine()

        assert engine1 is engine2
        assert isinstance(engine1, HPKEEngine)


# =============================================================================
# Data Structure Tests
# =============================================================================


class TestDataStructures:
    """Tests for HPKE data structures."""

    def test_hpke_keypair_fields(self, x25519_keypair):
        """Test HPKEKeyPair fields."""
        assert hasattr(x25519_keypair, "private_key")
        assert hasattr(x25519_keypair, "public_key")
        assert hasattr(x25519_keypair, "suite")

    def test_hpke_encrypted_message_fields(self, engine, x25519_keypair):
        """Test HPKEEncryptedMessage fields."""
        encrypted = engine.encrypt(
            x25519_keypair.public_key,
            b"test",
            info=b"info",
            aad=b"aad",
        )

        assert hasattr(encrypted, "enc")
        assert hasattr(encrypted, "ciphertext")
        assert hasattr(encrypted, "suite")
        assert hasattr(encrypted, "mode")
        assert hasattr(encrypted, "info")
        assert hasattr(encrypted, "aad")


# =============================================================================
# Cross-Suite Compatibility Tests
# =============================================================================


class TestCrossCompatibility:
    """Tests for cross-suite behavior."""

    def test_different_suites_incompatible(self, engine):
        """Test that different suites cannot decrypt each other."""
        kp_x25519 = engine.generate_keypair(HPKECipherSuite.X25519_SHA256_AES128GCM)
        kp_p256 = engine.generate_keypair(HPKECipherSuite.P256_SHA256_AES128GCM)
        plaintext = b"Test message"

        # Encrypt with X25519
        encrypted = engine.encrypt(
            kp_x25519.public_key,
            plaintext,
            suite=HPKECipherSuite.X25519_SHA256_AES128GCM,
        )

        # Try to decrypt with P-256 key (should fail)
        with pytest.raises(Exception):
            engine.decrypt(kp_p256.private_key, encrypted)
