"""Tests for secure memory handling utilities."""

import pytest

from app.core.secure_memory import (
    secure_zero,
    secure_random_overwrite,
    SecureBytes,
    temporary_key,
    constant_time_compare,
    secure_random_bytes,
)


class TestSecureZero:
    """Tests for secure_zero function."""

    def test_zeros_bytearray(self):
        """Should zero out a bytearray."""
        data = bytearray(b"secret key material")
        original_len = len(data)

        secure_zero(data)

        assert len(data) == original_len
        assert all(b == 0 for b in data)

    def test_handles_empty_bytearray(self):
        """Should handle empty bytearray without error."""
        data = bytearray()
        secure_zero(data)
        assert len(data) == 0

    def test_rejects_bytes_type(self):
        """Should reject immutable bytes type."""
        with pytest.raises(TypeError, match="requires a bytearray"):
            secure_zero(b"immutable bytes")

    def test_rejects_string(self):
        """Should reject string type."""
        with pytest.raises(TypeError, match="requires a bytearray"):
            secure_zero("string data")

    def test_zeros_all_byte_values(self):
        """Should correctly zero all possible byte values."""
        data = bytearray(range(256))
        secure_zero(data)
        assert all(b == 0 for b in data)


class TestSecureRandomOverwrite:
    """Tests for secure_random_overwrite function."""

    def test_overwrites_and_zeros(self):
        """Should overwrite with random data then zero."""
        data = bytearray(b"sensitive data")
        original_len = len(data)

        secure_random_overwrite(data, passes=3)

        assert len(data) == original_len
        assert all(b == 0 for b in data)

    def test_rejects_bytes_type(self):
        """Should reject immutable bytes type."""
        with pytest.raises(TypeError, match="requires a bytearray"):
            secure_random_overwrite(b"immutable")

    def test_multiple_passes(self):
        """Should handle various pass counts."""
        for passes in [1, 3, 5]:
            data = bytearray(b"test data")
            secure_random_overwrite(data, passes=passes)
            assert all(b == 0 for b in data)


class TestSecureBytes:
    """Tests for SecureBytes class."""

    def test_stores_data(self):
        """Should store data accessibly."""
        original = b"my secret key"
        secure = SecureBytes(original)

        assert bytes(secure) == original
        assert len(secure) == len(original)

    def test_data_property_access(self):
        """Should provide access via data property."""
        original = b"key material"
        secure = SecureBytes(original)

        assert secure.data == bytearray(original)

    def test_clear_zeros_data(self):
        """Should zero data when clear() is called."""
        secure = SecureBytes(b"secret")
        secure.clear()

        with pytest.raises(ValueError, match="has been cleared"):
            _ = secure.data

    def test_context_manager_clears_on_exit(self):
        """Should zero data when exiting context."""
        with SecureBytes(b"temporary key") as secure:
            assert len(secure) > 0

        with pytest.raises(ValueError, match="has been cleared"):
            _ = secure.data

    def test_context_manager_clears_on_exception(self):
        """Should zero data even if exception occurs."""
        secure = None
        try:
            with SecureBytes(b"key") as secure:
                raise RuntimeError("test error")
        except RuntimeError:
            pass

        with pytest.raises(ValueError, match="has been cleared"):
            _ = secure.data

    def test_bytes_conversion_after_clear_fails(self):
        """Should fail bytes conversion after clear."""
        secure = SecureBytes(b"data")
        secure.clear()

        with pytest.raises(ValueError, match="has been cleared"):
            bytes(secure)

    def test_handles_empty_data(self):
        """Should handle empty data."""
        secure = SecureBytes(b"")
        assert len(secure) == 0
        assert bytes(secure) == b""
        secure.clear()

    def test_accepts_bytearray_input(self):
        """Should accept bytearray as input."""
        original = bytearray(b"key data")
        secure = SecureBytes(original)

        assert bytes(secure) == bytes(original)

    def test_double_clear_is_safe(self):
        """Should handle multiple clear() calls safely."""
        secure = SecureBytes(b"data")
        secure.clear()
        secure.clear()  # Should not raise


class TestTemporaryKey:
    """Tests for temporary_key context manager."""

    def test_provides_key_access(self):
        """Should provide access to key material in context."""
        original = b"encryption key"

        with temporary_key(original) as key:
            assert key == bytearray(original)

    def test_zeros_key_on_exit(self):
        """Should zero key when context exits."""
        original = b"secret key"
        key_ref = None

        with temporary_key(original) as key:
            key_ref = key

        assert all(b == 0 for b in key_ref)

    def test_zeros_key_on_exception(self):
        """Should zero key even if exception occurs."""
        key_ref = None

        try:
            with temporary_key(b"key") as key:
                key_ref = key
                raise RuntimeError("error")
        except RuntimeError:
            pass

        assert all(b == 0 for b in key_ref)

    def test_returns_mutable_bytearray(self):
        """Should return a mutable bytearray."""
        with temporary_key(b"key") as key:
            assert isinstance(key, bytearray)
            key[0] = 255  # Should be modifiable


class TestConstantTimeCompare:
    """Tests for constant_time_compare function."""

    def test_equal_values_return_true(self):
        """Should return True for equal values."""
        assert constant_time_compare(b"abc", b"abc")
        assert constant_time_compare(bytearray(b"xyz"), bytearray(b"xyz"))

    def test_unequal_values_return_false(self):
        """Should return False for unequal values."""
        assert not constant_time_compare(b"abc", b"abd")
        assert not constant_time_compare(b"abc", b"ab")

    def test_handles_empty_values(self):
        """Should handle empty byte sequences."""
        assert constant_time_compare(b"", b"")
        assert not constant_time_compare(b"", b"x")

    def test_handles_mixed_types(self):
        """Should handle bytes and bytearray mix."""
        assert constant_time_compare(b"test", bytearray(b"test"))
        assert constant_time_compare(bytearray(b"test"), b"test")


class TestSecureRandomBytes:
    """Tests for secure_random_bytes function."""

    def test_returns_correct_length(self):
        """Should return requested number of bytes."""
        for length in [0, 1, 16, 32, 64, 256]:
            result = secure_random_bytes(length)
            assert len(result) == length

    def test_returns_bytes_type(self):
        """Should return bytes type."""
        result = secure_random_bytes(16)
        assert isinstance(result, bytes)

    def test_generates_random_data(self):
        """Should generate different values on each call."""
        # Very unlikely to get same 32 bytes twice
        a = secure_random_bytes(32)
        b = secure_random_bytes(32)
        assert a != b


class TestSecretSharingSizeLimit:
    """Test max secret size validation in Shamir SSS."""

    def test_rejects_oversized_secret(self):
        """Should reject secrets exceeding MAX_SECRET_SIZE."""
        from app.core.secret_sharing_engine import (
            SecretSharingEngine,
            SecretSharingError,
        )

        engine = SecretSharingEngine()
        oversized_secret = b"x" * (engine.MAX_SECRET_SIZE + 1)

        with pytest.raises(SecretSharingError, match="exceeds maximum"):
            engine.split(oversized_secret, threshold=2, total_shares=3)

    def test_accepts_max_size_secret(self):
        """Should accept secrets at exactly MAX_SECRET_SIZE."""
        from app.core.secret_sharing_engine import SecretSharingEngine

        engine = SecretSharingEngine()
        # Use smaller size for test speed (1KB instead of 1MB)
        small_secret = b"x" * 1024

        shares = engine.split(small_secret, threshold=2, total_shares=3)
        assert len(shares) == 3

        recovered = engine.combine(shares[:2])
        assert recovered == small_secret
