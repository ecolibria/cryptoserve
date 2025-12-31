"""Tests for the hash and MAC engine."""

import pytest
import os
import io
import tempfile

from app.core.hash_engine import (
    hash_engine,
    mac_engine,
    HashEngine,
    MACEngine,
    HashAlgorithm,
    MACAlgorithm,
    HashResult,
    MACResult,
    HashError,
    MACError,
    UnsupportedAlgorithmError,
    HashStreamer,
    MACStreamer,
    BLAKE3_AVAILABLE,
    KMAC_AVAILABLE,
)


@pytest.fixture
def fresh_hash_engine():
    """Create a fresh hash engine for each test."""
    return HashEngine()


@pytest.fixture
def fresh_mac_engine():
    """Create a fresh MAC engine for each test."""
    return MACEngine()


class TestSHA2Hashing:
    """Tests for SHA-2 family hashing."""

    def test_sha256(self, fresh_hash_engine):
        """Test SHA-256 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        assert result.algorithm == HashAlgorithm.SHA256
        assert result.length == 256
        assert len(result.digest) == 32
        assert result.hex == result.digest.hex()
        # Known SHA-256 hash
        assert result.hex == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

    def test_sha384(self, fresh_hash_engine):
        """Test SHA-384 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA384)

        assert result.algorithm == HashAlgorithm.SHA384
        assert result.length == 384
        assert len(result.digest) == 48

    def test_sha512(self, fresh_hash_engine):
        """Test SHA-512 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA512)

        assert result.algorithm == HashAlgorithm.SHA512
        assert result.length == 512
        assert len(result.digest) == 64

    def test_sha512_256(self, fresh_hash_engine):
        """Test SHA-512/256 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA512_256)

        assert result.algorithm == HashAlgorithm.SHA512_256
        assert result.length == 256
        assert len(result.digest) == 32


class TestSHA3Hashing:
    """Tests for SHA-3 family hashing."""

    def test_sha3_256(self, fresh_hash_engine):
        """Test SHA3-256 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA3_256)

        assert result.algorithm == HashAlgorithm.SHA3_256
        assert result.length == 256
        assert len(result.digest) == 32

    def test_sha3_384(self, fresh_hash_engine):
        """Test SHA3-384 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA3_384)

        assert result.algorithm == HashAlgorithm.SHA3_384
        assert result.length == 384
        assert len(result.digest) == 48

    def test_sha3_512(self, fresh_hash_engine):
        """Test SHA3-512 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA3_512)

        assert result.algorithm == HashAlgorithm.SHA3_512
        assert result.length == 512
        assert len(result.digest) == 64

    def test_shake128(self, fresh_hash_engine):
        """Test SHAKE128 XOF."""
        data = b"Hello, World!"

        # Default output
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHAKE128)
        assert result.algorithm == HashAlgorithm.SHAKE128
        assert len(result.digest) == 16  # Default

        # Custom output length
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHAKE128, output_length=32)
        assert len(result.digest) == 32

    def test_shake256(self, fresh_hash_engine):
        """Test SHAKE256 XOF."""
        data = b"Hello, World!"

        # Default output
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHAKE256)
        assert result.algorithm == HashAlgorithm.SHAKE256
        assert len(result.digest) == 32  # Default

        # Custom output length
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHAKE256, output_length=64)
        assert len(result.digest) == 64


class TestBLAKEHashing:
    """Tests for BLAKE family hashing."""

    def test_blake2b(self, fresh_hash_engine):
        """Test BLAKE2b hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE2B)

        assert result.algorithm == HashAlgorithm.BLAKE2B
        assert len(result.digest) == 64  # Default

    def test_blake2b_custom_length(self, fresh_hash_engine):
        """Test BLAKE2b with custom output length."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE2B, output_length=32)

        assert len(result.digest) == 32

    def test_blake2s(self, fresh_hash_engine):
        """Test BLAKE2s hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE2S)

        assert result.algorithm == HashAlgorithm.BLAKE2S
        assert len(result.digest) == 32  # Default

    def test_blake2s_custom_length(self, fresh_hash_engine):
        """Test BLAKE2s with custom output length."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE2S, output_length=16)

        assert len(result.digest) == 16

    @pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="blake3 not installed")
    def test_blake3(self, fresh_hash_engine):
        """Test BLAKE3 hashing."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE3)

        assert result.algorithm == HashAlgorithm.BLAKE3
        assert len(result.digest) == 32  # Default

    @pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="blake3 not installed")
    def test_blake3_custom_length(self, fresh_hash_engine):
        """Test BLAKE3 with custom output length."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.BLAKE3, output_length=64)

        assert len(result.digest) == 64


class TestHashVerification:
    """Tests for hash verification."""

    def test_verify_valid_hash(self, fresh_hash_engine):
        """Test verification of a valid hash."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        assert fresh_hash_engine.verify(data, result.digest, HashAlgorithm.SHA256)
        assert fresh_hash_engine.verify(data, result.hex, HashAlgorithm.SHA256)

    def test_verify_invalid_hash(self, fresh_hash_engine):
        """Test verification of an invalid hash."""
        data = b"Hello, World!"
        wrong_data = b"Hello, World?"

        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        assert not fresh_hash_engine.verify(wrong_data, result.digest, HashAlgorithm.SHA256)

    def test_verify_different_algorithms(self, fresh_hash_engine):
        """Test verification with multiple algorithms."""
        data = b"test data"

        for algo in [HashAlgorithm.SHA256, HashAlgorithm.SHA3_256, HashAlgorithm.BLAKE2B]:
            result = fresh_hash_engine.hash(data, algo)
            assert fresh_hash_engine.verify(data, result.digest, algo)


class TestFileHashing:
    """Tests for file hashing."""

    def test_hash_file_by_path(self, fresh_hash_engine):
        """Test hashing a file by path."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hello, World!")
            f.flush()
            temp_path = f.name

        try:
            result = fresh_hash_engine.hash_file(temp_path, HashAlgorithm.SHA256)

            assert result.algorithm == HashAlgorithm.SHA256
            # Same as in-memory hash
            expected = fresh_hash_engine.hash(b"Hello, World!", HashAlgorithm.SHA256)
            assert result.hex == expected.hex
        finally:
            os.unlink(temp_path)

    def test_hash_file_object(self, fresh_hash_engine):
        """Test hashing a file-like object."""
        data = b"Hello, World!"
        file_obj = io.BytesIO(data)

        result = fresh_hash_engine.hash_file(file_obj, HashAlgorithm.SHA256)

        expected = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)
        assert result.hex == expected.hex

    def test_hash_large_file(self, fresh_hash_engine):
        """Test hashing a large file in chunks."""
        # Create 1MB of data
        data = os.urandom(1024 * 1024)
        file_obj = io.BytesIO(data)

        result = fresh_hash_engine.hash_file(file_obj, HashAlgorithm.SHA256, chunk_size=4096)

        expected = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)
        assert result.hex == expected.hex


class TestMAC:
    """Tests for MAC operations."""

    def test_hmac_sha256(self, fresh_mac_engine):
        """Test HMAC-SHA256."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA256)

        assert result.algorithm == MACAlgorithm.HMAC_SHA256
        assert result.length == 256
        assert len(result.tag) == 32

    def test_hmac_sha384(self, fresh_mac_engine):
        """Test HMAC-SHA384."""
        data = b"Hello, World!"
        key = os.urandom(48)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA384)

        assert result.algorithm == MACAlgorithm.HMAC_SHA384
        assert result.length == 384
        assert len(result.tag) == 48

    def test_hmac_sha512(self, fresh_mac_engine):
        """Test HMAC-SHA512."""
        data = b"Hello, World!"
        key = os.urandom(64)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA512)

        assert result.algorithm == MACAlgorithm.HMAC_SHA512
        assert result.length == 512
        assert len(result.tag) == 64

    def test_hmac_sha3_256(self, fresh_mac_engine):
        """Test HMAC-SHA3-256."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA3_256)

        assert result.algorithm == MACAlgorithm.HMAC_SHA3_256
        assert result.length == 256

    def test_hmac_blake2b(self, fresh_mac_engine):
        """Test HMAC-BLAKE2B (keyed BLAKE2b)."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_BLAKE2B)

        assert result.algorithm == MACAlgorithm.HMAC_BLAKE2B
        assert result.length == 512


class TestMACVerification:
    """Tests for MAC verification."""

    def test_verify_valid_mac(self, fresh_mac_engine):
        """Test verification of a valid MAC."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA256)

        assert fresh_mac_engine.verify(data, key, result.tag, MACAlgorithm.HMAC_SHA256)
        assert fresh_mac_engine.verify(data, key, result.hex, MACAlgorithm.HMAC_SHA256)

    def test_verify_invalid_mac(self, fresh_mac_engine):
        """Test verification of an invalid MAC."""
        data = b"Hello, World!"
        key = os.urandom(32)
        wrong_key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_SHA256)

        # Wrong key
        assert not fresh_mac_engine.verify(data, wrong_key, result.tag, MACAlgorithm.HMAC_SHA256)

        # Wrong data
        assert not fresh_mac_engine.verify(b"wrong", key, result.tag, MACAlgorithm.HMAC_SHA256)

    def test_verify_blake2b_mac(self, fresh_mac_engine):
        """Test verification of BLAKE2b keyed hash."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.HMAC_BLAKE2B)

        assert fresh_mac_engine.verify(data, key, result.tag, MACAlgorithm.HMAC_BLAKE2B)


class TestMACKeyGeneration:
    """Tests for MAC key generation."""

    def test_generate_key_hmac_sha256(self, fresh_mac_engine):
        """Test key generation for HMAC-SHA256."""
        key = fresh_mac_engine.generate_key(MACAlgorithm.HMAC_SHA256)

        assert len(key) == 32

    def test_generate_key_hmac_sha384(self, fresh_mac_engine):
        """Test key generation for HMAC-SHA384."""
        key = fresh_mac_engine.generate_key(MACAlgorithm.HMAC_SHA384)

        assert len(key) == 48

    def test_generate_key_hmac_sha512(self, fresh_mac_engine):
        """Test key generation for HMAC-SHA512."""
        key = fresh_mac_engine.generate_key(MACAlgorithm.HMAC_SHA512)

        assert len(key) == 64

    def test_keys_are_unique(self, fresh_mac_engine):
        """Test that generated keys are unique."""
        keys = {fresh_mac_engine.generate_key().hex() for _ in range(100)}
        assert len(keys) == 100


class TestHashStreamer:
    """Tests for streaming hash computation."""

    def test_streaming_hash(self):
        """Test streaming hash computation."""
        streamer = HashStreamer(HashAlgorithm.SHA256)

        streamer.update(b"Hello, ")
        streamer.update(b"World!")

        digest = streamer.digest()

        # Should match non-streaming hash
        expected = hash_engine.hash(b"Hello, World!", HashAlgorithm.SHA256)
        assert digest == expected.digest

    def test_streaming_hexdigest(self):
        """Test streaming hexdigest."""
        streamer = HashStreamer(HashAlgorithm.SHA256)
        streamer.update(b"Hello, World!")

        hex_digest = streamer.hexdigest()

        expected = hash_engine.hash(b"Hello, World!", HashAlgorithm.SHA256)
        assert hex_digest == expected.hex

    def test_cannot_update_after_finalize(self):
        """Test that update fails after finalization."""
        streamer = HashStreamer()
        streamer.update(b"data")
        streamer.digest()

        with pytest.raises(HashError):
            streamer.update(b"more data")

    def test_streaming_different_algorithms(self):
        """Test streaming with different algorithms."""
        for algo in [HashAlgorithm.SHA256, HashAlgorithm.SHA3_256, HashAlgorithm.BLAKE2B]:
            streamer = HashStreamer(algo)
            streamer.update(b"test data")
            digest = streamer.digest()

            expected = hash_engine.hash(b"test data", algo)
            assert digest == expected.digest


class TestMACStreamer:
    """Tests for streaming MAC computation."""

    def test_streaming_mac(self):
        """Test streaming MAC computation."""
        key = os.urandom(32)
        streamer = MACStreamer(key, MACAlgorithm.HMAC_SHA256)

        streamer.update(b"Hello, ")
        streamer.update(b"World!")

        tag = streamer.finalize()

        # Should match non-streaming MAC
        expected = mac_engine.mac(b"Hello, World!", key, MACAlgorithm.HMAC_SHA256)
        assert tag == expected.tag

    def test_streaming_mac_verify(self):
        """Test streaming MAC verification."""
        key = os.urandom(32)
        expected = mac_engine.mac(b"Hello, World!", key, MACAlgorithm.HMAC_SHA256)

        streamer = MACStreamer(key, MACAlgorithm.HMAC_SHA256)
        streamer.update(b"Hello, ")
        streamer.update(b"World!")

        assert streamer.verify(expected.tag)

    def test_cannot_update_after_finalize(self):
        """Test that update fails after finalization."""
        key = os.urandom(32)
        streamer = MACStreamer(key)
        streamer.update(b"data")
        streamer.finalize()

        with pytest.raises(MACError):
            streamer.update(b"more data")


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_data_hash(self, fresh_hash_engine):
        """Test hashing empty data."""
        result = fresh_hash_engine.hash(b"", HashAlgorithm.SHA256)

        # Known SHA-256 of empty string
        assert result.hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_large_data_hash(self, fresh_hash_engine):
        """Test hashing large data."""
        data = os.urandom(10 * 1024 * 1024)  # 10MB
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        assert len(result.digest) == 32

    def test_base64_encoding(self, fresh_hash_engine):
        """Test base64 encoding of hash."""
        data = b"Hello, World!"
        result = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        import base64
        decoded = base64.b64decode(result.base64)
        assert decoded == result.digest

    def test_consistent_hashing(self, fresh_hash_engine):
        """Test that hashing is deterministic."""
        data = b"test data"

        result1 = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)
        result2 = fresh_hash_engine.hash(data, HashAlgorithm.SHA256)

        assert result1.hex == result2.hex


class TestAlgorithmMetadata:
    """Tests for algorithm metadata."""

    def test_algorithm_info(self, fresh_hash_engine):
        """Test algorithm metadata."""
        assert HashAlgorithm.SHA256 in fresh_hash_engine.ALGORITHMS
        info = fresh_hash_engine.ALGORITHMS[HashAlgorithm.SHA256]

        assert info["bits"] == 256
        assert info["block_size"] == 64

    def test_xof_metadata(self, fresh_hash_engine):
        """Test XOF algorithm metadata."""
        info = fresh_hash_engine.ALGORITHMS[HashAlgorithm.SHAKE256]

        assert info.get("xof") is True


class TestKMAC:
    """Tests for KMAC (Keccak Message Authentication Code) - NIST SP 800-185."""

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac128_basic(self, fresh_mac_engine):
        """Test basic KMAC128."""
        data = b"Hello, World!"
        key = os.urandom(16)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC128)

        assert result.algorithm == MACAlgorithm.KMAC128
        assert result.length == 128  # Default 16 bytes
        assert len(result.tag) == 16

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac256_basic(self, fresh_mac_engine):
        """Test basic KMAC256."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)

        assert result.algorithm == MACAlgorithm.KMAC256
        assert result.length == 256  # Default 32 bytes
        assert len(result.tag) == 32

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac128_custom_output_length(self, fresh_mac_engine):
        """Test KMAC128 with custom output length."""
        data = b"Hello, World!"
        key = os.urandom(16)

        result = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC128, output_length=32
        )

        assert len(result.tag) == 32

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac256_custom_output_length(self, fresh_mac_engine):
        """Test KMAC256 with custom output length."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC256, output_length=64
        )

        assert len(result.tag) == 64

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac128_with_customization(self, fresh_mac_engine):
        """Test KMAC128 with customization string."""
        data = b"Hello, World!"
        key = os.urandom(16)

        # Different customization strings should produce different MACs
        result1 = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC128, customization=b"custom1"
        )
        result2 = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC128, customization=b"custom2"
        )

        assert result1.tag != result2.tag

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac256_with_customization(self, fresh_mac_engine):
        """Test KMAC256 with customization string."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result1 = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC256, customization=b"context-A"
        )
        result2 = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC256, customization=b"context-B"
        )

        assert result1.tag != result2.tag

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac128_verify(self, fresh_mac_engine):
        """Test KMAC128 verification."""
        data = b"Hello, World!"
        key = os.urandom(16)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC128)

        # Valid verification
        assert fresh_mac_engine.verify(data, key, result.tag, MACAlgorithm.KMAC128)

        # Invalid verification - wrong data
        assert not fresh_mac_engine.verify(b"wrong", key, result.tag, MACAlgorithm.KMAC128)

        # Invalid verification - wrong key
        wrong_key = os.urandom(16)
        assert not fresh_mac_engine.verify(data, wrong_key, result.tag, MACAlgorithm.KMAC128)

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac256_verify(self, fresh_mac_engine):
        """Test KMAC256 verification."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)

        # Valid verification
        assert fresh_mac_engine.verify(data, key, result.tag, MACAlgorithm.KMAC256)

        # Invalid verification - wrong data
        assert not fresh_mac_engine.verify(b"wrong", key, result.tag, MACAlgorithm.KMAC256)

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_verify_with_customization(self, fresh_mac_engine):
        """Test KMAC verification with customization string."""
        data = b"Hello, World!"
        key = os.urandom(32)
        custom = b"my-context"

        result = fresh_mac_engine.mac(
            data, key, MACAlgorithm.KMAC256, customization=custom
        )

        # Valid with same customization
        assert fresh_mac_engine.verify(
            data, key, result.tag, MACAlgorithm.KMAC256, customization=custom
        )

        # Invalid with different customization
        assert not fresh_mac_engine.verify(
            data, key, result.tag, MACAlgorithm.KMAC256, customization=b"wrong-context"
        )

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_deterministic(self, fresh_mac_engine):
        """Test that KMAC is deterministic."""
        data = b"test data"
        key = os.urandom(32)

        result1 = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)
        result2 = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)

        assert result1.tag == result2.tag

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_empty_data(self, fresh_mac_engine):
        """Test KMAC with empty data."""
        key = os.urandom(32)

        result = fresh_mac_engine.mac(b"", key, MACAlgorithm.KMAC256)

        assert len(result.tag) == 32

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_large_data(self, fresh_mac_engine):
        """Test KMAC with large data."""
        data = os.urandom(1024 * 1024)  # 1 MB
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)

        assert len(result.tag) == 32

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_key_generation(self, fresh_mac_engine):
        """Test key generation for KMAC."""
        key128 = fresh_mac_engine.generate_key(MACAlgorithm.KMAC128)
        key256 = fresh_mac_engine.generate_key(MACAlgorithm.KMAC256)

        assert len(key128) == 16
        assert len(key256) == 32

    @pytest.mark.skipif(not KMAC_AVAILABLE, reason="pycryptodome not installed")
    def test_kmac_hex_encoding(self, fresh_mac_engine):
        """Test KMAC hex encoding."""
        data = b"Hello, World!"
        key = os.urandom(32)

        result = fresh_mac_engine.mac(data, key, MACAlgorithm.KMAC256)

        assert result.hex == result.tag.hex()
        assert fresh_mac_engine.verify(data, key, result.hex, MACAlgorithm.KMAC256)
