"""Tests for the AEAD modes engine (OCB and EAX)."""

import os
import pytest

from app.core.aead_modes_engine import (
    aead_modes_engine,
    AEADModesEngine,
    AEADMode,
    AEADResult,
    DecryptResult,
    AEADModesError,
    AuthenticationError,
    InvalidKeyError,
    InvalidNonceError,
)


@pytest.fixture
def engine():
    """Create a fresh AEAD modes engine."""
    return AEADModesEngine()


@pytest.fixture
def key_128():
    """128-bit key."""
    return os.urandom(16)


@pytest.fixture
def key_192():
    """192-bit key."""
    return os.urandom(24)


@pytest.fixture
def key_256():
    """256-bit key."""
    return os.urandom(32)


class TestOCBMode:
    """Tests for OCB (Offset Codebook) mode."""

    def test_encrypt_decrypt_basic(self, engine, key_256):
        """Test basic OCB encryption/decryption."""
        plaintext = b"Hello, OCB mode!"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.OCB)

        assert result.ciphertext != plaintext
        assert len(result.nonce) == 15  # Default OCB nonce
        assert len(result.tag) == 16
        assert result.algorithm == AEADMode.OCB
        assert result.key_size_bits == 256

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.OCB,
        )

        assert decrypted.plaintext == plaintext
        assert decrypted.verified is True

    def test_encrypt_with_aad(self, engine, key_256):
        """Test OCB encryption with associated data."""
        plaintext = b"Secret message"
        aad = b"header:value"

        result = engine.encrypt(
            plaintext, key_256, mode=AEADMode.OCB, associated_data=aad
        )

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.OCB,
            associated_data=aad,
        )

        assert decrypted.plaintext == plaintext

    def test_wrong_aad_fails(self, engine, key_256):
        """Test that wrong AAD causes authentication failure."""
        plaintext = b"Secret message"

        result = engine.encrypt(
            plaintext, key_256, mode=AEADMode.OCB, associated_data=b"correct"
        )

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.OCB,
                associated_data=b"wrong",
            )

    def test_key_sizes(self, engine):
        """Test OCB with different key sizes."""
        plaintext = b"Test data"

        for key_size in [16, 24, 32]:
            key = os.urandom(key_size)
            result = engine.encrypt(plaintext, key, mode=AEADMode.OCB)
            assert result.key_size_bits == key_size * 8

            decrypted = engine.decrypt(
                result.ciphertext,
                key,
                result.nonce,
                result.tag,
                mode=AEADMode.OCB,
            )
            assert decrypted.plaintext == plaintext

    def test_nonce_sizes(self, engine, key_256):
        """Test OCB with various nonce sizes (1-15 bytes)."""
        plaintext = b"Test"

        for nonce_size in range(1, 16):
            nonce = os.urandom(nonce_size)
            result = engine.encrypt(
                plaintext, key_256, mode=AEADMode.OCB, nonce=nonce
            )
            assert result.nonce == nonce

            decrypted = engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.OCB,
            )
            assert decrypted.plaintext == plaintext

    def test_invalid_nonce_size(self, engine, key_256):
        """Test that invalid nonce size raises error."""
        plaintext = b"Test"

        # 16 bytes is too long for OCB
        with pytest.raises(InvalidNonceError):
            engine.encrypt(
                plaintext, key_256, mode=AEADMode.OCB, nonce=os.urandom(16)
            )

        # Empty nonce
        with pytest.raises(InvalidNonceError):
            engine.encrypt(plaintext, key_256, mode=AEADMode.OCB, nonce=b"")

    def test_empty_plaintext(self, engine, key_256):
        """Test OCB with empty plaintext."""
        result = engine.encrypt(b"", key_256, mode=AEADMode.OCB)

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.OCB,
        )

        assert decrypted.plaintext == b""

    def test_large_plaintext(self, engine, key_256):
        """Test OCB with large plaintext."""
        plaintext = os.urandom(1024 * 1024)  # 1 MB

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.OCB)

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.OCB,
        )

        assert decrypted.plaintext == plaintext

    def test_corrupted_ciphertext(self, engine, key_256):
        """Test that corrupted ciphertext fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.OCB)

        # Corrupt ciphertext
        corrupted = bytearray(result.ciphertext)
        corrupted[0] ^= 0xFF

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                bytes(corrupted),
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.OCB,
            )

    def test_corrupted_tag(self, engine, key_256):
        """Test that corrupted tag fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.OCB)

        # Corrupt tag
        corrupted_tag = bytearray(result.tag)
        corrupted_tag[0] ^= 0xFF

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                bytes(corrupted_tag),
                mode=AEADMode.OCB,
            )

    def test_wrong_key(self, engine, key_256):
        """Test that wrong key fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.OCB)

        wrong_key = os.urandom(32)

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                wrong_key,
                result.nonce,
                result.tag,
                mode=AEADMode.OCB,
            )


class TestEAXMode:
    """Tests for EAX mode."""

    def test_encrypt_decrypt_basic(self, engine, key_256):
        """Test basic EAX encryption/decryption."""
        plaintext = b"Hello, EAX mode!"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.EAX)

        assert result.ciphertext != plaintext
        assert len(result.nonce) == 16  # Default EAX nonce
        assert len(result.tag) == 16
        assert result.algorithm == AEADMode.EAX
        assert result.key_size_bits == 256

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.EAX,
        )

        assert decrypted.plaintext == plaintext
        assert decrypted.verified is True

    def test_encrypt_with_aad(self, engine, key_256):
        """Test EAX encryption with associated data."""
        plaintext = b"Secret message"
        aad = b"context:12345"

        result = engine.encrypt(
            plaintext, key_256, mode=AEADMode.EAX, associated_data=aad
        )

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.EAX,
            associated_data=aad,
        )

        assert decrypted.plaintext == plaintext
        assert result.aad_size == len(aad)

    def test_wrong_aad_fails(self, engine, key_256):
        """Test that wrong AAD causes authentication failure."""
        plaintext = b"Secret message"

        result = engine.encrypt(
            plaintext, key_256, mode=AEADMode.EAX, associated_data=b"correct"
        )

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.EAX,
                associated_data=b"wrong",
            )

    def test_key_sizes(self, engine):
        """Test EAX with different key sizes."""
        plaintext = b"Test data"

        for key_size in [16, 24, 32]:
            key = os.urandom(key_size)
            result = engine.encrypt(plaintext, key, mode=AEADMode.EAX)
            assert result.key_size_bits == key_size * 8

            decrypted = engine.decrypt(
                result.ciphertext,
                key,
                result.nonce,
                result.tag,
                mode=AEADMode.EAX,
            )
            assert decrypted.plaintext == plaintext

    def test_variable_nonce_sizes(self, engine, key_256):
        """Test EAX with various nonce sizes."""
        plaintext = b"Test"

        for nonce_size in [8, 12, 16, 24, 32]:
            nonce = os.urandom(nonce_size)
            result = engine.encrypt(
                plaintext, key_256, mode=AEADMode.EAX, nonce=nonce
            )
            assert result.nonce == nonce

            decrypted = engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.EAX,
            )
            assert decrypted.plaintext == plaintext

    def test_empty_nonce_fails(self, engine, key_256):
        """Test that empty nonce raises error for EAX."""
        with pytest.raises(InvalidNonceError):
            engine.encrypt(b"Test", key_256, mode=AEADMode.EAX, nonce=b"")

    def test_empty_plaintext(self, engine, key_256):
        """Test EAX with empty plaintext."""
        result = engine.encrypt(b"", key_256, mode=AEADMode.EAX)

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.EAX,
        )

        assert decrypted.plaintext == b""

    def test_large_plaintext(self, engine, key_256):
        """Test EAX with large plaintext."""
        plaintext = os.urandom(1024 * 1024)  # 1 MB

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.EAX)

        decrypted = engine.decrypt(
            result.ciphertext,
            key_256,
            result.nonce,
            result.tag,
            mode=AEADMode.EAX,
        )

        assert decrypted.plaintext == plaintext

    def test_corrupted_ciphertext(self, engine, key_256):
        """Test that corrupted ciphertext fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.EAX)

        corrupted = bytearray(result.ciphertext)
        corrupted[0] ^= 0xFF

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                bytes(corrupted),
                key_256,
                result.nonce,
                result.tag,
                mode=AEADMode.EAX,
            )

    def test_corrupted_tag(self, engine, key_256):
        """Test that corrupted tag fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.EAX)

        corrupted_tag = bytearray(result.tag)
        corrupted_tag[0] ^= 0xFF

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                bytes(corrupted_tag),
                mode=AEADMode.EAX,
            )

    def test_wrong_key(self, engine, key_256):
        """Test that wrong key fails authentication."""
        plaintext = b"Secret"

        result = engine.encrypt(plaintext, key_256, mode=AEADMode.EAX)

        wrong_key = os.urandom(32)

        with pytest.raises(AuthenticationError):
            engine.decrypt(
                result.ciphertext,
                wrong_key,
                result.nonce,
                result.tag,
                mode=AEADMode.EAX,
            )


class TestSelfDescribingFormat:
    """Tests for self-describing ciphertext format."""

    def test_encrypt_decrypt_with_header_ocb(self, engine, key_256):
        """Test OCB with self-describing header."""
        plaintext = b"Secret message with header"

        encrypted = engine.encrypt_with_header(
            plaintext, key_256, mode=AEADMode.OCB
        )

        # Verify header structure
        assert encrypted[0] == 0x01  # Version
        assert encrypted[1] == 0x01  # OCB mode

        decrypted = engine.decrypt_with_header(encrypted, key_256)

        assert decrypted.plaintext == plaintext
        assert decrypted.algorithm == AEADMode.OCB

    def test_encrypt_decrypt_with_header_eax(self, engine, key_256):
        """Test EAX with self-describing header."""
        plaintext = b"Secret message with header"

        encrypted = engine.encrypt_with_header(
            plaintext, key_256, mode=AEADMode.EAX
        )

        # Verify header structure
        assert encrypted[0] == 0x01  # Version
        assert encrypted[1] == 0x02  # EAX mode

        decrypted = engine.decrypt_with_header(encrypted, key_256)

        assert decrypted.plaintext == plaintext
        assert decrypted.algorithm == AEADMode.EAX

    def test_header_with_aad(self, engine, key_256):
        """Test header format with AAD."""
        plaintext = b"Secret"
        aad = b"context"

        encrypted = engine.encrypt_with_header(
            plaintext, key_256, mode=AEADMode.OCB, associated_data=aad
        )

        decrypted = engine.decrypt_with_header(
            encrypted, key_256, associated_data=aad
        )

        assert decrypted.plaintext == plaintext

    def test_header_wrong_aad_fails(self, engine, key_256):
        """Test that wrong AAD fails with header format."""
        encrypted = engine.encrypt_with_header(
            b"Secret", key_256, associated_data=b"correct"
        )

        with pytest.raises(AuthenticationError):
            engine.decrypt_with_header(
                encrypted, key_256, associated_data=b"wrong"
            )

    def test_truncated_data_fails(self, engine, key_256):
        """Test that truncated data raises error."""
        with pytest.raises(AEADModesError):
            engine.decrypt_with_header(b"\x01\x01", key_256)

    def test_invalid_version_fails(self, engine, key_256):
        """Test that invalid version raises error."""
        encrypted = engine.encrypt_with_header(b"test", key_256)

        # Change version
        modified = b"\x99" + encrypted[1:]

        with pytest.raises(AEADModesError, match="Unsupported version"):
            engine.decrypt_with_header(modified, key_256)


class TestKeyValidation:
    """Tests for key validation."""

    def test_invalid_key_size(self, engine):
        """Test that invalid key sizes raise errors."""
        for key_size in [8, 15, 17, 20, 31, 33, 64]:
            with pytest.raises(InvalidKeyError):
                engine.encrypt(b"test", os.urandom(key_size))

    def test_key_not_bytes(self, engine):
        """Test that non-bytes key raises error."""
        with pytest.raises(InvalidKeyError):
            engine.encrypt(b"test", "not bytes")  # type: ignore

    def test_valid_key_sizes(self, engine):
        """Test that valid key sizes work."""
        for key_size in [16, 24, 32]:
            result = engine.encrypt(b"test", os.urandom(key_size))
            assert result is not None


class TestModeRecommendations:
    """Tests for mode recommendation logic."""

    def test_performance_recommendation(self, engine):
        """Test performance mode recommendation."""
        mode = engine.get_recommended_mode("performance")
        assert mode == AEADMode.OCB

    def test_safety_recommendation(self, engine):
        """Test safety mode recommendation."""
        mode = engine.get_recommended_mode("safety")
        assert mode == AEADMode.EAX

    def test_general_recommendation(self, engine):
        """Test general mode recommendation."""
        mode = engine.get_recommended_mode("general")
        assert mode == AEADMode.OCB

    def test_unknown_recommendation(self, engine):
        """Test unknown use case defaults to OCB."""
        mode = engine.get_recommended_mode("unknown")
        assert mode == AEADMode.OCB


class TestDefaultMode:
    """Tests for default mode configuration."""

    def test_default_mode_ocb(self):
        """Test engine with OCB as default."""
        engine = AEADModesEngine(default_mode=AEADMode.OCB)
        key = os.urandom(32)

        result = engine.encrypt(b"test", key)
        assert result.algorithm == AEADMode.OCB

    def test_default_mode_eax(self):
        """Test engine with EAX as default."""
        engine = AEADModesEngine(default_mode=AEADMode.EAX)
        key = os.urandom(32)

        result = engine.encrypt(b"test", key)
        assert result.algorithm == AEADMode.EAX

    def test_override_default_mode(self):
        """Test overriding default mode."""
        engine = AEADModesEngine(default_mode=AEADMode.OCB)
        key = os.urandom(32)

        result = engine.encrypt(b"test", key, mode=AEADMode.EAX)
        assert result.algorithm == AEADMode.EAX


class TestSingletonInstance:
    """Tests for the singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert aead_modes_engine is not None
        assert isinstance(aead_modes_engine, AEADModesEngine)

    def test_singleton_encryption(self):
        """Test encryption with singleton."""
        key = os.urandom(32)
        result = aead_modes_engine.encrypt(b"test", key)
        assert result is not None


class TestBinaryData:
    """Tests for binary data handling."""

    def test_all_byte_values(self, engine, key_256):
        """Test encryption of all possible byte values."""
        plaintext = bytes(range(256))

        for mode in [AEADMode.OCB, AEADMode.EAX]:
            result = engine.encrypt(plaintext, key_256, mode=mode)
            decrypted = engine.decrypt(
                result.ciphertext,
                key_256,
                result.nonce,
                result.tag,
                mode=mode,
            )
            assert decrypted.plaintext == plaintext

    def test_random_binary_data(self, engine, key_256):
        """Test encryption of random binary data."""
        for size in [0, 1, 15, 16, 17, 255, 256, 1000]:
            plaintext = os.urandom(size)

            for mode in [AEADMode.OCB, AEADMode.EAX]:
                result = engine.encrypt(plaintext, key_256, mode=mode)
                decrypted = engine.decrypt(
                    result.ciphertext,
                    key_256,
                    result.nonce,
                    result.tag,
                    mode=mode,
                )
                assert decrypted.plaintext == plaintext
