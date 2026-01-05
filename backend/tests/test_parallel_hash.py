"""Tests for ParallelHash (NIST SP 800-185) implementation."""

import pytest

from app.core.parallel_hash import (
    ParallelHashEngine,
    ParallelHashVariant,
    ParallelHashResult,
    ParallelHashError,
    get_parallel_hash_engine,
    parallel_hash_available,
    parallel_hash_128,
    parallel_hash_256,
    _left_encode,
    _right_encode,
    _encode_string,
    CSHAKE_AVAILABLE,
)


# Skip all tests if pycryptodome cSHAKE is not available
pytestmark = pytest.mark.skipif(
    not CSHAKE_AVAILABLE,
    reason="pycryptodome cSHAKE not installed"
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def engine():
    """Create ParallelHash engine for testing."""
    return ParallelHashEngine()


# =============================================================================
# Encoding Function Tests
# =============================================================================


class TestEncodingFunctions:
    """Tests for NIST SP 800-185 encoding functions."""

    def test_left_encode_zero(self):
        """Test left_encode(0)."""
        result = _left_encode(0)
        assert result == b'\x01\x00'

    def test_left_encode_small(self):
        """Test left_encode for small values."""
        # 1 byte values
        assert _left_encode(1) == b'\x01\x01'
        assert _left_encode(255) == b'\x01\xff'

    def test_left_encode_large(self):
        """Test left_encode for larger values."""
        # 2 byte value
        assert _left_encode(256) == b'\x02\x01\x00'
        # Value that needs 2 bytes
        assert _left_encode(65535) == b'\x02\xff\xff'

    def test_right_encode_zero(self):
        """Test right_encode(0)."""
        result = _right_encode(0)
        assert result == b'\x00\x01'

    def test_right_encode_small(self):
        """Test right_encode for small values."""
        assert _right_encode(1) == b'\x01\x01'
        assert _right_encode(255) == b'\xff\x01'

    def test_right_encode_large(self):
        """Test right_encode for larger values."""
        assert _right_encode(256) == b'\x01\x00\x02'
        assert _right_encode(65535) == b'\xff\xff\x02'

    def test_encode_string_empty(self):
        """Test encode_string with empty string."""
        result = _encode_string(b"")
        # left_encode(0) = \x01\x00
        assert result == b'\x01\x00'

    def test_encode_string_short(self):
        """Test encode_string with short string."""
        result = _encode_string(b"test")
        # len("test") = 4 bytes = 32 bits
        # left_encode(32) = \x01\x20
        assert result == b'\x01\x20' + b"test"


# =============================================================================
# Basic Hash Tests
# =============================================================================


class TestBasicHash:
    """Tests for basic ParallelHash functionality."""

    def test_hash_empty_data(self, engine):
        """Test hashing empty data."""
        result = engine.hash(b"")

        assert result is not None
        assert isinstance(result, ParallelHashResult)
        assert len(result.digest) == 16  # Default for PH128
        assert result.num_blocks == 0
        assert result.variant == ParallelHashVariant.PARALLEL_HASH_128

    def test_hash_simple_data(self, engine):
        """Test hashing simple data."""
        data = b"Hello, ParallelHash!"
        result = engine.hash(data)

        assert result is not None
        assert len(result.digest) == 16
        assert result.num_blocks >= 1
        assert result.hex == result.digest.hex()

    def test_hash_deterministic(self, engine):
        """Test that hashing is deterministic."""
        data = b"Deterministic test data"

        result1 = engine.hash(data)
        result2 = engine.hash(data)

        assert result1.digest == result2.digest
        assert result1.hex == result2.hex

    def test_hash_different_data_produces_different_hash(self, engine):
        """Test that different data produces different hashes."""
        result1 = engine.hash(b"Data A")
        result2 = engine.hash(b"Data B")

        assert result1.digest != result2.digest


# =============================================================================
# Variant Tests
# =============================================================================


class TestVariants:
    """Tests for ParallelHash variants."""

    def test_parallel_hash_128(self, engine):
        """Test ParallelHash128 variant."""
        data = b"Test data for PH128"
        result = engine.hash(
            data,
            variant=ParallelHashVariant.PARALLEL_HASH_128,
        )

        assert result.variant == ParallelHashVariant.PARALLEL_HASH_128
        assert len(result.digest) == 16  # 128 bits default

    def test_parallel_hash_256(self, engine):
        """Test ParallelHash256 variant."""
        data = b"Test data for PH256"
        result = engine.hash(
            data,
            variant=ParallelHashVariant.PARALLEL_HASH_256,
        )

        assert result.variant == ParallelHashVariant.PARALLEL_HASH_256
        assert len(result.digest) == 32  # 256 bits default

    def test_variants_produce_different_hashes(self, engine):
        """Test that different variants produce different hashes."""
        data = b"Same data, different variants"

        result_128 = engine.hash(
            data,
            variant=ParallelHashVariant.PARALLEL_HASH_128,
            output_length=32,
        )
        result_256 = engine.hash(
            data,
            variant=ParallelHashVariant.PARALLEL_HASH_256,
            output_length=32,
        )

        assert result_128.digest != result_256.digest


# =============================================================================
# Output Length Tests
# =============================================================================


class TestOutputLength:
    """Tests for variable output length (XOF)."""

    def test_custom_output_length(self, engine):
        """Test custom output length."""
        data = b"Test data"

        result_16 = engine.hash(data, output_length=16)
        result_32 = engine.hash(data, output_length=32)
        result_64 = engine.hash(data, output_length=64)

        assert len(result_16.digest) == 16
        assert len(result_32.digest) == 32
        assert len(result_64.digest) == 64

    def test_xof_prefix_consistency(self, engine):
        """Test that shorter outputs are prefixes of longer ones."""
        data = b"XOF consistency test"

        result_16 = engine.hash(data, output_length=16)
        result_32 = engine.hash(data, output_length=32)

        # Note: This is NOT true for ParallelHash because L is part of the input
        # Different L values produce completely different outputs
        # This test verifies they are indeed different
        assert result_16.digest != result_32.digest[:16]

    def test_hash_xof_method(self, engine):
        """Test hash_xof convenience method."""
        data = b"XOF method test"
        digest = engine.hash_xof(data, output_length=48)

        assert len(digest) == 48
        assert isinstance(digest, bytes)


# =============================================================================
# Block Size Tests
# =============================================================================


class TestBlockSize:
    """Tests for block size parameter."""

    def test_small_block_size(self, engine):
        """Test with small block size."""
        data = b"A" * 100
        result = engine.hash(data, block_size=16)

        assert result.num_blocks == 7  # ceil(100/16) = 7
        assert result.block_size == 16

    def test_large_block_size(self, engine):
        """Test with large block size."""
        data = b"B" * 100
        result = engine.hash(data, block_size=1024)

        assert result.num_blocks == 1
        assert result.block_size == 1024

    def test_default_block_size(self, engine):
        """Test default block size."""
        data = b"C" * 100
        result = engine.hash(data)

        assert result.block_size == 8192  # Default

    def test_invalid_block_size_raises(self, engine):
        """Test that invalid block size raises error."""
        with pytest.raises(ParallelHashError):
            engine.hash(b"test", block_size=0)

        with pytest.raises(ParallelHashError):
            engine.hash(b"test", block_size=-1)

    def test_different_block_sizes_produce_different_hashes(self, engine):
        """Test that different block sizes affect the hash."""
        data = b"D" * 100

        result_16 = engine.hash(data, block_size=16)
        result_32 = engine.hash(data, block_size=32)

        # Different block sizes should produce different hashes
        assert result_16.digest != result_32.digest


# =============================================================================
# Customization Tests
# =============================================================================


class TestCustomization:
    """Tests for customization string."""

    def test_empty_customization(self, engine):
        """Test with empty customization string."""
        data = b"Test data"
        result = engine.hash(data, customization=b"")

        assert result.customization == b""

    def test_customization_affects_hash(self, engine):
        """Test that customization affects the hash."""
        data = b"Same data"

        result_no_custom = engine.hash(data, customization=b"")
        result_custom_a = engine.hash(data, customization=b"application-a")
        result_custom_b = engine.hash(data, customization=b"application-b")

        # All should be different
        assert result_no_custom.digest != result_custom_a.digest
        assert result_custom_a.digest != result_custom_b.digest
        assert result_no_custom.digest != result_custom_b.digest

    def test_customization_stored_in_result(self, engine):
        """Test that customization is stored in result."""
        custom = b"my-custom-string"
        result = engine.hash(b"data", customization=custom)

        assert result.customization == custom


# =============================================================================
# Verification Tests
# =============================================================================


class TestVerification:
    """Tests for hash verification."""

    def test_verify_correct_hash(self, engine):
        """Test verification with correct hash."""
        data = b"Verify this data"
        result = engine.hash(data)

        assert engine.verify(data, result.digest) is True
        assert engine.verify(data, result.hex) is True

    def test_verify_wrong_hash(self, engine):
        """Test verification with wrong hash."""
        data = b"Verify this data"
        wrong_hash = b"\x00" * 16

        assert engine.verify(data, wrong_hash) is False

    def test_verify_wrong_data(self, engine):
        """Test verification with wrong data."""
        original_data = b"Original data"
        tampered_data = b"Tampered data"
        result = engine.hash(original_data)

        assert engine.verify(tampered_data, result.digest) is False


# =============================================================================
# Large Data Tests
# =============================================================================


class TestLargeData:
    """Tests for large data inputs."""

    def test_hash_large_data(self, engine):
        """Test hashing large data."""
        data = b"X" * (1024 * 1024)  # 1 MB
        result = engine.hash(data)

        assert result is not None
        assert len(result.digest) == 16
        assert result.num_blocks == 128  # 1MB / 8KB = 128 blocks

    def test_hash_multiple_blocks(self, engine):
        """Test data spanning multiple blocks."""
        data = b"Y" * 50000  # ~50KB
        result = engine.hash(data, block_size=8192)

        assert result.num_blocks == 7  # ceil(50000/8192) = 7


# =============================================================================
# Singleton and Utility Tests
# =============================================================================


class TestUtilities:
    """Tests for utility functions."""

    def test_parallel_hash_available(self):
        """Test availability check."""
        assert parallel_hash_available() is True

    def test_get_engine_singleton(self):
        """Test singleton engine access."""
        engine1 = get_parallel_hash_engine()
        engine2 = get_parallel_hash_engine()

        assert engine1 is engine2
        assert isinstance(engine1, ParallelHashEngine)

    def test_parallel_hash_128_convenience(self):
        """Test parallel_hash_128 convenience function."""
        data = b"Test data"
        digest = parallel_hash_128(data)

        assert len(digest) == 16
        assert isinstance(digest, bytes)

    def test_parallel_hash_256_convenience(self):
        """Test parallel_hash_256 convenience function."""
        data = b"Test data"
        digest = parallel_hash_256(data)

        assert len(digest) == 32
        assert isinstance(digest, bytes)

    def test_convenience_with_custom_length(self):
        """Test convenience functions with custom output length."""
        data = b"Test data"

        digest_128 = parallel_hash_128(data, output_length=32)
        digest_256 = parallel_hash_256(data, output_length=64)

        assert len(digest_128) == 32
        assert len(digest_256) == 64


# =============================================================================
# Variant Info Tests
# =============================================================================


class TestVariantInfo:
    """Tests for variant information."""

    def test_get_variant_info_128(self, engine):
        """Test getting PH128 variant info."""
        info = engine.get_variant_info(ParallelHashVariant.PARALLEL_HASH_128)

        assert info["name"] == "ParallelHash128"
        assert info["security_level"] == 128
        assert info["inner_hash"] == "cSHAKE128"
        assert info["inner_output_bits"] == 256
        assert info["nist_standard"] == "SP 800-185 Section 6"

    def test_get_variant_info_256(self, engine):
        """Test getting PH256 variant info."""
        info = engine.get_variant_info(ParallelHashVariant.PARALLEL_HASH_256)

        assert info["name"] == "ParallelHash256"
        assert info["security_level"] == 256
        assert info["inner_hash"] == "cSHAKE256"
        assert info["inner_output_bits"] == 512


# =============================================================================
# Parallel Execution Tests
# =============================================================================


class TestParallelExecution:
    """Tests for parallel hash execution."""

    def test_parallel_hash_small_data_falls_back(self, engine):
        """Test that small data uses sequential processing."""
        # Small data should use sequential hash
        data = b"Small data"
        result = engine.hash_parallel(data)

        assert result is not None
        assert len(result.digest) == 16

    def test_parallel_hash_consistency(self, engine):
        """Test that parallel and sequential produce same result."""
        # Use larger data to trigger parallel processing
        data = b"Z" * (128 * 1024)  # 128 KB

        result_sequential = engine.hash(data)
        result_parallel = engine.hash_parallel(data, use_processes=False)

        assert result_sequential.digest == result_parallel.digest


# =============================================================================
# Result Structure Tests
# =============================================================================


class TestResultStructure:
    """Tests for ParallelHashResult structure."""

    def test_result_has_all_fields(self, engine):
        """Test that result has all expected fields."""
        result = engine.hash(b"test", customization=b"custom")

        assert hasattr(result, "digest")
        assert hasattr(result, "variant")
        assert hasattr(result, "block_size")
        assert hasattr(result, "num_blocks")
        assert hasattr(result, "output_length")
        assert hasattr(result, "hex")
        assert hasattr(result, "customization")

    def test_result_output_length_in_bits(self, engine):
        """Test that output_length is in bits."""
        result = engine.hash(b"test", output_length=32)

        assert result.output_length == 256  # 32 bytes * 8 = 256 bits


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_data_exactly_one_block(self, engine):
        """Test data exactly equal to block size."""
        data = b"A" * 8192  # Exactly one block
        result = engine.hash(data, block_size=8192)

        assert result.num_blocks == 1

    def test_data_one_byte_over_block(self, engine):
        """Test data one byte over block size."""
        data = b"B" * 8193  # One byte over
        result = engine.hash(data, block_size=8192)

        assert result.num_blocks == 2

    def test_single_byte_data(self, engine):
        """Test hashing a single byte."""
        result = engine.hash(b"X")

        assert result is not None
        assert result.num_blocks == 1

    def test_binary_data_with_nulls(self, engine):
        """Test hashing binary data with null bytes."""
        data = b"\x00\x01\x02\x00\xff\x00"
        result = engine.hash(data)

        assert result is not None
        assert len(result.digest) == 16
