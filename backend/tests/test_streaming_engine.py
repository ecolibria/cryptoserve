"""Tests for the streaming encryption engine."""

import pytest
import os
import io
import tempfile

from app.core.streaming_engine import (
    streaming_engine,
    StreamingEngine,
    StreamingAlgorithm,
    StreamingConfig,
    StreamingEncryptor,
    StreamingDecryptor,
    StreamingError,
    ChunkAuthenticationError,
    ChunkSequenceError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh streaming engine for each test."""
    return StreamingEngine()


@pytest.fixture
def encryption_key():
    """Generate a random encryption key."""
    return os.urandom(32)


class TestStreamEncryption:
    """Tests for stream encryption/decryption."""

    def test_encrypt_decrypt_stream_aesgcm(self, fresh_engine, encryption_key):
        """Test AES-GCM stream encryption/decryption."""
        plaintext = b"Hello, World! This is a test message."

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        # Encrypt
        result = fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
        )

        assert result.bytes_processed == len(plaintext)
        assert result.chunks_processed >= 1
        assert result.algorithm == StreamingAlgorithm.AES_256_GCM

        # Decrypt
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        result = fresh_engine.decrypt_stream(
            encrypted_stream,
            decrypted_stream,
            encryption_key,
        )

        assert result.bytes_processed == len(plaintext)
        assert decrypted_stream.getvalue() == plaintext

    def test_encrypt_decrypt_stream_chacha20(self, encryption_key):
        """Test ChaCha20-Poly1305 stream encryption/decryption."""
        config = StreamingConfig(algorithm=StreamingAlgorithm.CHACHA20_POLY1305)
        engine = StreamingEngine(config)

        plaintext = b"Hello, World! This is a test message."

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        result = engine.decrypt_stream(encrypted_stream, decrypted_stream, encryption_key)

        assert result.algorithm == StreamingAlgorithm.CHACHA20_POLY1305
        assert decrypted_stream.getvalue() == plaintext

    def test_encrypt_decrypt_with_aad(self, fresh_engine, encryption_key):
        """Test encryption with associated data."""
        plaintext = b"Secret message"
        aad = b"context-id:12345"

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
            associated_data=aad,
        )

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        fresh_engine.decrypt_stream(
            encrypted_stream,
            decrypted_stream,
            encryption_key,
            associated_data=aad,
        )

        assert decrypted_stream.getvalue() == plaintext

    def test_wrong_aad_fails(self, fresh_engine, encryption_key):
        """Test that wrong AAD causes decryption failure."""
        plaintext = b"Secret message"

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
            associated_data=b"correct-aad",
        )

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        with pytest.raises(ChunkAuthenticationError):
            fresh_engine.decrypt_stream(
                encrypted_stream,
                decrypted_stream,
                encryption_key,
                associated_data=b"wrong-aad",
            )

    def test_large_stream(self, fresh_engine, encryption_key):
        """Test encrypting a large stream."""
        # 1MB of data
        plaintext = os.urandom(1024 * 1024)

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        result = fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
        )

        # Should have multiple chunks
        assert result.chunks_processed > 1

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        fresh_engine.decrypt_stream(
            encrypted_stream,
            decrypted_stream,
            encryption_key,
        )

        assert decrypted_stream.getvalue() == plaintext

    def test_custom_chunk_size(self, encryption_key):
        """Test encryption with custom chunk size."""
        config = StreamingConfig(chunk_size=1024)  # 1KB chunks
        engine = StreamingEngine(config)

        plaintext = os.urandom(10 * 1024)  # 10KB

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        result = engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        # Should have 10 chunks
        assert result.chunks_processed == 10

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        engine.decrypt_stream(encrypted_stream, decrypted_stream, encryption_key)

        assert decrypted_stream.getvalue() == plaintext

    def test_progress_callback(self, fresh_engine, encryption_key):
        """Test progress callback during encryption."""
        plaintext = os.urandom(256 * 1024)  # 256KB
        progress_calls = []

        def progress_callback(processed, total):
            progress_calls.append((processed, total))

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
            progress_callback=progress_callback,
        )

        assert len(progress_calls) > 0
        # Last call should have processed == total
        assert progress_calls[-1][0] == progress_calls[-1][1]


class TestFileEncryption:
    """Tests for file encryption/decryption."""

    def test_encrypt_decrypt_file(self, fresh_engine, encryption_key):
        """Test file encryption and decryption."""
        plaintext = b"Hello, World! This is file content."

        with tempfile.NamedTemporaryFile(delete=False) as input_file:
            input_file.write(plaintext)
            input_path = input_file.name

        encrypted_path = input_path + ".enc"
        decrypted_path = input_path + ".dec"

        try:
            # Encrypt
            result = fresh_engine.encrypt_file(
                input_path,
                encrypted_path,
                encryption_key,
            )

            assert result.bytes_processed == len(plaintext)
            assert os.path.exists(encrypted_path)

            # Decrypt
            fresh_engine.decrypt_file(
                encrypted_path,
                decrypted_path,
                encryption_key,
            )

            with open(decrypted_path, "rb") as f:
                assert f.read() == plaintext

        finally:
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)


class TestIteratorEncryption:
    """Tests for iterator-based encryption."""

    def test_encrypt_iterator(self, fresh_engine, encryption_key):
        """Test encrypting from an iterator."""
        chunks = [b"Hello, ", b"World!", b" How are you?"]

        encrypted_chunks = list(fresh_engine.encrypt_iterator(
            iter(chunks),
            encryption_key,
        ))

        # Should have header + data chunks
        assert len(encrypted_chunks) >= 2

        # Decrypt
        decrypted_chunks = list(fresh_engine.decrypt_iterator(
            iter(encrypted_chunks),
            encryption_key,
        ))

        # Combine and verify
        decrypted = b"".join(decrypted_chunks)
        expected = b"".join(chunks)
        assert decrypted == expected

    def test_encrypt_iterator_with_aad(self, fresh_engine, encryption_key):
        """Test iterator encryption with AAD."""
        chunks = [b"Secret ", b"data"]
        aad = b"context-id"

        encrypted = list(fresh_engine.encrypt_iterator(
            iter(chunks),
            encryption_key,
            associated_data=aad,
        ))

        decrypted = list(fresh_engine.decrypt_iterator(
            iter(encrypted),
            encryption_key,
            associated_data=aad,
        ))

        assert b"".join(decrypted) == b"".join(chunks)


class TestStreamingEncryptor:
    """Tests for StreamingEncryptor context manager."""

    def test_encryptor_context_manager(self, encryption_key):
        """Test streaming encryptor as context manager."""
        output = io.BytesIO()

        with StreamingEncryptor(output, encryption_key) as encryptor:
            encryptor.write(b"Hello, ")
            encryptor.write(b"World!")

        # Decrypt
        output.seek(0)
        decrypted = io.BytesIO()
        StreamingEngine().decrypt_stream(output, decrypted, encryption_key)

        assert decrypted.getvalue() == b"Hello, World!"

    def test_encryptor_auto_finalize(self, encryption_key):
        """Test that encryptor auto-finalizes on exit."""
        output = io.BytesIO()

        with StreamingEncryptor(output, encryption_key) as encryptor:
            encryptor.write(b"Data")

        # Should be finalized
        output.seek(0)
        decrypted = io.BytesIO()
        StreamingEngine().decrypt_stream(output, decrypted, encryption_key)

        assert decrypted.getvalue() == b"Data"

    def test_encryptor_write_after_finalize_fails(self, encryption_key):
        """Test that writing after finalization fails."""
        output = io.BytesIO()

        encryptor = StreamingEncryptor(output, encryption_key)
        encryptor.__enter__()
        encryptor.write(b"Data")
        encryptor.finalize()

        with pytest.raises(StreamingError):
            encryptor.write(b"More data")


class TestStreamingDecryptor:
    """Tests for StreamingDecryptor context manager."""

    def test_decryptor_context_manager(self, encryption_key):
        """Test streaming decryptor as context manager."""
        # Encrypt first
        plaintext = b"Hello, World!"
        encrypted = io.BytesIO()
        StreamingEngine().encrypt_stream(
            io.BytesIO(plaintext),
            encrypted,
            encryption_key,
        )

        # Decrypt with context manager
        encrypted.seek(0)
        decrypted_chunks = []

        with StreamingDecryptor(encrypted, encryption_key) as decryptor:
            for chunk in decryptor:
                decrypted_chunks.append(chunk)

        assert b"".join(decrypted_chunks) == plaintext

    def test_decryptor_read_chunk(self, encryption_key):
        """Test reading chunks individually."""
        config = StreamingConfig(chunk_size=10)
        engine = StreamingEngine(config)

        plaintext = b"Hello, World! This is a test."
        encrypted = io.BytesIO()
        engine.encrypt_stream(io.BytesIO(plaintext), encrypted, encryption_key)

        encrypted.seek(0)
        chunks = []

        with StreamingDecryptor(encrypted, encryption_key) as decryptor:
            while True:
                chunk = decryptor.read_chunk()
                if chunk is None:
                    break
                chunks.append(chunk)

        assert b"".join(chunks) == plaintext


class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_key_length(self, fresh_engine):
        """Test that invalid key length raises error."""
        with pytest.raises(StreamingError):
            fresh_engine.encrypt_stream(
                io.BytesIO(b"data"),
                io.BytesIO(),
                b"short",  # Not 32 bytes
            )

    def test_corrupted_ciphertext(self, fresh_engine, encryption_key):
        """Test that corrupted ciphertext raises error."""
        plaintext = b"Hello, World!"

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        # Corrupt the ciphertext
        encrypted_data = bytearray(encrypted_stream.getvalue())
        encrypted_data[-1] ^= 0xFF
        corrupted_stream = io.BytesIO(bytes(encrypted_data))

        with pytest.raises(ChunkAuthenticationError):
            fresh_engine.decrypt_stream(
                corrupted_stream,
                io.BytesIO(),
                encryption_key,
            )

    def test_wrong_key(self, fresh_engine, encryption_key):
        """Test that wrong key raises error."""
        plaintext = b"Hello, World!"

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        encrypted_stream.seek(0)
        wrong_key = os.urandom(32)

        with pytest.raises(ChunkAuthenticationError):
            fresh_engine.decrypt_stream(
                encrypted_stream,
                io.BytesIO(),
                wrong_key,
            )

    def test_truncated_stream(self, fresh_engine, encryption_key):
        """Test that truncated stream raises error."""
        plaintext = os.urandom(100 * 1024)  # 100KB

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        # Truncate the encrypted data
        encrypted_data = encrypted_stream.getvalue()
        truncated = io.BytesIO(encrypted_data[:len(encrypted_data) // 2])

        with pytest.raises(StreamingError):
            fresh_engine.decrypt_stream(
                truncated,
                io.BytesIO(),
                encryption_key,
            )

    def test_invalid_header(self, fresh_engine, encryption_key):
        """Test that invalid header raises error."""
        invalid_stream = io.BytesIO(b"invalid header data" * 10)

        with pytest.raises(StreamingError):
            fresh_engine.decrypt_stream(
                invalid_stream,
                io.BytesIO(),
                encryption_key,
            )


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_stream(self, fresh_engine, encryption_key):
        """Test encrypting empty stream."""
        input_stream = io.BytesIO(b"")
        encrypted_stream = io.BytesIO()

        result = fresh_engine.encrypt_stream(
            input_stream,
            encrypted_stream,
            encryption_key,
        )

        assert result.bytes_processed == 0
        # One empty final chunk to mark end of stream
        assert result.chunks_processed == 1

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        fresh_engine.decrypt_stream(
            encrypted_stream,
            decrypted_stream,
            encryption_key,
        )

        assert decrypted_stream.getvalue() == b""

    def test_exactly_chunk_size(self, encryption_key):
        """Test data that's exactly chunk size."""
        config = StreamingConfig(chunk_size=1024)
        engine = StreamingEngine(config)

        plaintext = os.urandom(1024)  # Exactly 1 chunk

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        result = engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        # Single chunk with is_final=True when data exactly matches chunk size
        assert result.chunks_processed == 1

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        engine.decrypt_stream(encrypted_stream, decrypted_stream, encryption_key)

        assert decrypted_stream.getvalue() == plaintext

    def test_binary_data(self, fresh_engine, encryption_key):
        """Test encrypting binary data."""
        plaintext = bytes(range(256)) * 100

        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()

        fresh_engine.encrypt_stream(input_stream, encrypted_stream, encryption_key)

        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        fresh_engine.decrypt_stream(encrypted_stream, decrypted_stream, encryption_key)

        assert decrypted_stream.getvalue() == plaintext


class TestHeaderParsing:
    """Tests for header creation and parsing."""

    def test_header_roundtrip(self, fresh_engine):
        """Test header creation and parsing roundtrip."""
        nonce_prefix = os.urandom(8)
        header = fresh_engine._create_header(nonce_prefix)

        assert len(header) == fresh_engine.HEADER_SIZE
        assert header[:4] == fresh_engine.MAGIC

        algorithm, chunk_size, parsed_prefix = fresh_engine._parse_header(header)

        assert algorithm == fresh_engine.config.algorithm
        assert chunk_size == fresh_engine.config.chunk_size
        assert parsed_prefix == nonce_prefix

    def test_header_version(self, fresh_engine):
        """Test that header contains correct version."""
        header = fresh_engine._create_header(os.urandom(8))
        assert header[4] == fresh_engine.VERSION
