"""Tests for the Key Derivation Function engine."""

import os
import pytest

from app.core.kdf_engine import (
    kdf_engine,
    KDFEngine,
    KDFAlgorithm,
    KBKDFCounterLocation,
    DeriveResult,
    MultiKeyResult,
    KDFError,
    InvalidKeyMaterialError,
)


@pytest.fixture
def engine():
    """Create a fresh KDF engine."""
    return KDFEngine()


@pytest.fixture
def master_key():
    """Generate a random master key."""
    return os.urandom(32)


class TestHKDFSHA256:
    """Tests for HKDF-SHA256."""

    def test_derive_basic(self, engine, master_key):
        """Test basic HKDF derivation."""
        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert result.algorithm == KDFAlgorithm.HKDF_SHA256
        assert len(result.derived_key) == 32
        assert result.key_length == 32

    def test_derive_with_info(self, engine, master_key):
        """Test HKDF with info parameter."""
        info = b"encryption-key"

        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=info,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert result.info_used == info

    def test_derive_with_salt(self, engine, master_key):
        """Test HKDF with salt."""
        salt = os.urandom(32)

        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            salt=salt,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert result.salt_used == salt

    def test_different_info_different_keys(self, engine, master_key):
        """Test that different info produces different keys."""
        result1 = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=b"key-1",
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        result2 = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=b"key-2",
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert result1.derived_key != result2.derived_key

    def test_deterministic(self, engine, master_key):
        """Test that HKDF is deterministic."""
        info = b"test"
        salt = b"fixed-salt"

        result1 = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=info,
            salt=salt,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        result2 = engine.derive_hkdf(
            input_key_material=master_key,
            length=32,
            info=info,
            salt=salt,
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert result1.derived_key == result2.derived_key

    def test_variable_lengths(self, engine, master_key):
        """Test deriving keys of various lengths."""
        for length in [16, 24, 32, 48, 64, 128]:
            result = engine.derive_hkdf(
                input_key_material=master_key,
                length=length,
                algorithm=KDFAlgorithm.HKDF_SHA256,
            )
            assert len(result.derived_key) == length


class TestHKDFSHA384:
    """Tests for HKDF-SHA384."""

    def test_derive_basic(self, engine, master_key):
        """Test basic HKDF-SHA384 derivation."""
        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=48,
            algorithm=KDFAlgorithm.HKDF_SHA384,
        )

        assert result.algorithm == KDFAlgorithm.HKDF_SHA384
        assert len(result.derived_key) == 48

    def test_derive_with_info_and_salt(self, engine, master_key):
        """Test HKDF-SHA384 with info and salt."""
        info = b"session-key"
        salt = os.urandom(48)

        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=48,
            info=info,
            salt=salt,
            algorithm=KDFAlgorithm.HKDF_SHA384,
        )

        assert result.info_used == info
        assert result.salt_used == salt


class TestHKDFSHA512:
    """Tests for HKDF-SHA512."""

    def test_derive_basic(self, engine, master_key):
        """Test basic HKDF-SHA512 derivation."""
        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=64,
            algorithm=KDFAlgorithm.HKDF_SHA512,
        )

        assert result.algorithm == KDFAlgorithm.HKDF_SHA512
        assert len(result.derived_key) == 64

    def test_derive_large_output(self, engine, master_key):
        """Test deriving large output with HKDF-SHA512."""
        # SHA-512 can derive up to 255 * 64 bytes
        result = engine.derive_hkdf(
            input_key_material=master_key,
            length=256,
            algorithm=KDFAlgorithm.HKDF_SHA512,
        )

        assert len(result.derived_key) == 256


class TestHKDFExpand:
    """Tests for HKDF expand-only operation."""

    def test_expand_basic(self, engine, master_key):
        """Test HKDF expand operation."""
        result = engine.hkdf_expand(
            prk=master_key,
            length=32,
            info=b"derived-key",
            algorithm=KDFAlgorithm.HKDF_SHA256,
        )

        assert len(result.derived_key) == 32
        assert result.salt_used is None

    def test_expand_different_lengths(self, engine, master_key):
        """Test expand with different output lengths."""
        for length in [16, 32, 64, 128]:
            result = engine.hkdf_expand(
                prk=master_key,
                length=length,
                algorithm=KDFAlgorithm.HKDF_SHA256,
            )
            assert len(result.derived_key) == length


class TestKBKDF:
    """Tests for KBKDF (NIST SP 800-108)."""

    def test_kbkdf_sha256_basic(self, engine, master_key):
        """Test basic KBKDF-HMAC-SHA256."""
        result = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"session-key",
            context=b"user-12345",
            algorithm=KDFAlgorithm.KBKDF_HMAC_SHA256,
        )

        assert result.algorithm == KDFAlgorithm.KBKDF_HMAC_SHA256
        assert len(result.derived_key) == 32

    def test_kbkdf_sha384(self, engine, master_key):
        """Test KBKDF-HMAC-SHA384."""
        result = engine.derive_kbkdf(
            key=master_key,
            length=48,
            label=b"encryption",
            context=b"context",
            algorithm=KDFAlgorithm.KBKDF_HMAC_SHA384,
        )

        assert result.algorithm == KDFAlgorithm.KBKDF_HMAC_SHA384
        assert len(result.derived_key) == 48

    def test_kbkdf_sha512(self, engine, master_key):
        """Test KBKDF-HMAC-SHA512."""
        result = engine.derive_kbkdf(
            key=master_key,
            length=64,
            label=b"master-secret",
            context=b"session-context",
            algorithm=KDFAlgorithm.KBKDF_HMAC_SHA512,
        )

        assert result.algorithm == KDFAlgorithm.KBKDF_HMAC_SHA512
        assert len(result.derived_key) == 64

    def test_kbkdf_counter_locations(self, engine, master_key):
        """Test KBKDF with different counter locations."""
        for location in [
            KBKDFCounterLocation.BEFORE_FIXED,
            KBKDFCounterLocation.AFTER_FIXED,
        ]:
            result = engine.derive_kbkdf(
                key=master_key,
                length=32,
                label=b"key",
                context=b"context",
                counter_location=location,
            )
            assert len(result.derived_key) == 32

    def test_kbkdf_different_labels(self, engine, master_key):
        """Test that different labels produce different keys."""
        result1 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"key-1",
            context=b"context",
        )

        result2 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"key-2",
            context=b"context",
        )

        assert result1.derived_key != result2.derived_key

    def test_kbkdf_different_contexts(self, engine, master_key):
        """Test that different contexts produce different keys."""
        result1 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"key",
            context=b"context-1",
        )

        result2 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"key",
            context=b"context-2",
        )

        assert result1.derived_key != result2.derived_key

    def test_kbkdf_deterministic(self, engine, master_key):
        """Test that KBKDF is deterministic."""
        result1 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"fixed-label",
            context=b"fixed-context",
        )

        result2 = engine.derive_kbkdf(
            key=master_key,
            length=32,
            label=b"fixed-label",
            context=b"fixed-context",
        )

        assert result1.derived_key == result2.derived_key


class TestMultipleKeys:
    """Tests for deriving multiple keys."""

    def test_derive_multiple_basic(self, engine, master_key):
        """Test deriving multiple keys."""
        result = engine.derive_multiple_keys(
            master_key=master_key,
            key_specs=[
                ("encryption", 32),
                ("authentication", 32),
            ],
        )

        assert len(result.keys) == 2
        assert len(result.keys[0]) == 32
        assert len(result.keys[1]) == 32
        assert result.labels == ["encryption", "authentication"]

    def test_derive_multiple_different_lengths(self, engine, master_key):
        """Test deriving multiple keys with different lengths."""
        result = engine.derive_multiple_keys(
            master_key=master_key,
            key_specs=[
                ("enc-key", 32),
                ("mac-key", 48),
                ("iv", 16),
            ],
        )

        assert len(result.keys) == 3
        assert len(result.keys[0]) == 32
        assert len(result.keys[1]) == 48
        assert len(result.keys[2]) == 16

    def test_derived_keys_are_unique(self, engine, master_key):
        """Test that derived keys are unique."""
        result = engine.derive_multiple_keys(
            master_key=master_key,
            key_specs=[
                ("key-1", 32),
                ("key-2", 32),
                ("key-3", 32),
            ],
        )

        # All keys should be different
        assert result.keys[0] != result.keys[1]
        assert result.keys[1] != result.keys[2]
        assert result.keys[0] != result.keys[2]

    def test_derive_multiple_with_salt(self, engine, master_key):
        """Test deriving multiple keys with salt."""
        salt = os.urandom(32)

        result = engine.derive_multiple_keys(
            master_key=master_key,
            key_specs=[("key", 32)],
            salt=salt,
        )

        assert len(result.keys) == 1

    def test_derive_multiple_with_kbkdf(self, engine, master_key):
        """Test deriving multiple keys with KBKDF."""
        result = engine.derive_multiple_keys(
            master_key=master_key,
            key_specs=[
                ("enc", 32),
                ("mac", 32),
            ],
            algorithm=KDFAlgorithm.KBKDF_HMAC_SHA256,
        )

        assert len(result.keys) == 2
        assert result.algorithm == KDFAlgorithm.KBKDF_HMAC_SHA256


class TestEncryptionAndMACKeys:
    """Tests for convenience method to derive enc/mac keys."""

    def test_derive_enc_mac_keys(self, engine, master_key):
        """Test deriving encryption and MAC keys."""
        enc_key, mac_key = engine.derive_encryption_and_mac_keys(
            master_key=master_key
        )

        assert len(enc_key) == 32
        assert len(mac_key) == 32
        assert enc_key != mac_key

    def test_derive_enc_mac_custom_lengths(self, engine, master_key):
        """Test with custom key lengths."""
        enc_key, mac_key = engine.derive_encryption_and_mac_keys(
            master_key=master_key,
            enc_key_length=24,
            mac_key_length=48,
        )

        assert len(enc_key) == 24
        assert len(mac_key) == 48

    def test_derive_enc_mac_with_salt(self, engine, master_key):
        """Test with salt."""
        salt = os.urandom(32)

        enc_key, mac_key = engine.derive_encryption_and_mac_keys(
            master_key=master_key,
            salt=salt,
        )

        assert len(enc_key) == 32
        assert len(mac_key) == 32


class TestDeriveWithContext:
    """Tests for context-based derivation."""

    def test_derive_with_context(self, engine, master_key):
        """Test deriving key with context."""
        key = engine.derive_with_context(
            master_key=master_key,
            context_id="user-12345",
            key_purpose="file-encryption",
        )

        assert len(key) == 32

    def test_different_contexts_different_keys(self, engine, master_key):
        """Test that different contexts produce different keys."""
        key1 = engine.derive_with_context(
            master_key=master_key,
            context_id="user-1",
            key_purpose="encryption",
        )

        key2 = engine.derive_with_context(
            master_key=master_key,
            context_id="user-2",
            key_purpose="encryption",
        )

        assert key1 != key2

    def test_different_purposes_different_keys(self, engine, master_key):
        """Test that different purposes produce different keys."""
        key1 = engine.derive_with_context(
            master_key=master_key,
            context_id="user-1",
            key_purpose="encryption",
        )

        key2 = engine.derive_with_context(
            master_key=master_key,
            context_id="user-1",
            key_purpose="signing",
        )

        assert key1 != key2

    def test_derive_with_context_custom_length(self, engine, master_key):
        """Test with custom length."""
        key = engine.derive_with_context(
            master_key=master_key,
            context_id="user",
            key_purpose="key",
            length=64,
        )

        assert len(key) == 64


class TestSaltGeneration:
    """Tests for salt generation."""

    def test_generate_salt_default(self, engine):
        """Test generating default salt."""
        salt = engine.generate_salt()
        assert len(salt) == 32

    def test_generate_salt_custom_length(self, engine):
        """Test generating salt with custom length."""
        for length in [16, 24, 32, 64, 128]:
            salt = engine.generate_salt(length)
            assert len(salt) == length

    def test_salts_are_unique(self, engine):
        """Test that generated salts are unique."""
        salts = {engine.generate_salt().hex() for _ in range(100)}
        assert len(salts) == 100


class TestErrorHandling:
    """Tests for error handling."""

    def test_empty_input_key_material(self, engine):
        """Test that empty input raises error."""
        with pytest.raises(InvalidKeyMaterialError):
            engine.derive_hkdf(
                input_key_material=b"",
                length=32,
            )

    def test_empty_prk(self, engine):
        """Test that empty PRK raises error."""
        with pytest.raises(InvalidKeyMaterialError):
            engine.hkdf_expand(prk=b"", length=32)

    def test_empty_kbkdf_key(self, engine):
        """Test that empty key raises error for KBKDF."""
        with pytest.raises(InvalidKeyMaterialError):
            engine.derive_kbkdf(
                key=b"",
                length=32,
                label=b"label",
                context=b"context",
            )

    def test_empty_master_key_multiple(self, engine):
        """Test that empty master key raises error."""
        with pytest.raises(InvalidKeyMaterialError):
            engine.derive_multiple_keys(
                master_key=b"",
                key_specs=[("key", 32)],
            )


class TestSingletonInstance:
    """Tests for the singleton instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert kdf_engine is not None
        assert isinstance(kdf_engine, KDFEngine)

    def test_singleton_derive(self):
        """Test derivation with singleton."""
        key = os.urandom(32)
        result = kdf_engine.derive_hkdf(
            input_key_material=key,
            length=32,
        )
        assert len(result.derived_key) == 32


class TestCrossAlgorithmConsistency:
    """Tests for cross-algorithm behavior."""

    def test_same_input_different_algorithms(self, engine, master_key):
        """Test that different algorithms produce different keys."""
        results = {}

        for algo in [
            KDFAlgorithm.HKDF_SHA256,
            KDFAlgorithm.HKDF_SHA384,
            KDFAlgorithm.HKDF_SHA512,
        ]:
            result = engine.derive_hkdf(
                input_key_material=master_key,
                length=32,
                info=b"test",
                algorithm=algo,
            )
            results[algo] = result.derived_key

        # All should be different
        keys = list(results.values())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j]
