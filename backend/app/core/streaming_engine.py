"""Streaming Encryption Engine.

Provides streaming encryption for large files and data streams:
- Chunked encryption/decryption
- Memory-efficient processing
- Progress callbacks
- Authenticated encryption with AEAD

Security model:
- Each chunk is independently authenticated
- Chunk sequence is protected from reordering
- Final chunk is marked to prevent truncation
"""

import os
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import BinaryIO, Callable, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class StreamingAlgorithm(str, Enum):
    """Supported streaming encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


@dataclass
class StreamingConfig:
    """Configuration for streaming encryption."""
    algorithm: StreamingAlgorithm = StreamingAlgorithm.AES_256_GCM
    chunk_size: int = 64 * 1024  # 64KB default
    nonce_prefix: bytes | None = None  # Optional nonce prefix


@dataclass
class StreamingResult:
    """Result of streaming operation."""
    bytes_processed: int
    chunks_processed: int
    algorithm: StreamingAlgorithm
    completed_at: datetime


class StreamingError(Exception):
    """Streaming operation failed."""
    pass


class ChunkAuthenticationError(StreamingError):
    """Chunk authentication failed."""
    pass


class ChunkSequenceError(StreamingError):
    """Chunk sequence error (reordering detected)."""
    pass


class StreamingEngine:
    """Handles streaming encryption operations."""

    # Header format: magic (4) + version (1) + algorithm (1) + chunk_size (4) + nonce_prefix (8)
    HEADER_SIZE = 18
    MAGIC = b"STRM"
    VERSION = 1

    # Chunk format: length (4) + chunk_index (4) + is_final (1) + ciphertext
    CHUNK_OVERHEAD = 9 + 16  # 9 bytes header + 16 bytes auth tag

    def __init__(self, config: StreamingConfig | None = None):
        self.config = config or StreamingConfig()

    def encrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        key: bytes,
        associated_data: bytes | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> StreamingResult:
        """Encrypt a stream of data.

        Args:
            input_stream: Input data stream
            output_stream: Output stream for encrypted data
            key: 32-byte encryption key
            associated_data: Optional AAD for all chunks
            progress_callback: Optional callback(bytes_processed, total_bytes)

        Returns:
            StreamingResult with operation details
        """
        if len(key) != 32:
            raise StreamingError("Key must be 32 bytes")

        # Get total size if possible
        try:
            current_pos = input_stream.tell()
            input_stream.seek(0, 2)
            total_size = input_stream.tell()
            input_stream.seek(current_pos)
        except (OSError, AttributeError):
            total_size = -1

        # Generate nonce prefix (8 bytes) - used with chunk index for unique nonces
        nonce_prefix = self.config.nonce_prefix or os.urandom(8)

        # Write header
        header = self._create_header(nonce_prefix)
        output_stream.write(header)

        # Initialize cipher
        cipher = self._get_cipher(key)

        bytes_processed = 0
        chunk_index = 0
        wrote_final = False

        while True:
            chunk = input_stream.read(self.config.chunk_size)
            if not chunk:
                break

            # Check if this is the final chunk
            next_chunk = input_stream.read(1)
            is_final = len(next_chunk) == 0
            if next_chunk:
                # Put the byte back
                input_stream.seek(-1, 1)

            # Encrypt chunk
            encrypted_chunk = self._encrypt_chunk(
                cipher,
                chunk,
                nonce_prefix,
                chunk_index,
                is_final,
                associated_data,
            )
            output_stream.write(encrypted_chunk)

            bytes_processed += len(chunk)
            chunk_index += 1
            wrote_final = is_final

            if progress_callback and total_size > 0:
                progress_callback(bytes_processed, total_size)

        # Handle empty stream - write an empty final chunk
        if not wrote_final:
            encrypted_chunk = self._encrypt_chunk(
                cipher,
                b"",
                nonce_prefix,
                chunk_index,
                True,
                associated_data,
            )
            output_stream.write(encrypted_chunk)
            chunk_index += 1

        return StreamingResult(
            bytes_processed=bytes_processed,
            chunks_processed=chunk_index,
            algorithm=self.config.algorithm,
            completed_at=datetime.now(timezone.utc),
        )

    def decrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        key: bytes,
        associated_data: bytes | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> StreamingResult:
        """Decrypt a stream of data.

        Args:
            input_stream: Input encrypted stream
            output_stream: Output stream for decrypted data
            key: 32-byte decryption key
            associated_data: Optional AAD (must match encryption)
            progress_callback: Optional callback(bytes_processed, total_bytes)

        Returns:
            StreamingResult with operation details
        """
        if len(key) != 32:
            raise StreamingError("Key must be 32 bytes")

        # Get total size if possible
        try:
            current_pos = input_stream.tell()
            input_stream.seek(0, 2)
            total_size = input_stream.tell()
            input_stream.seek(current_pos)
        except (OSError, AttributeError):
            total_size = -1

        # Read and parse header
        header = input_stream.read(self.HEADER_SIZE)
        if len(header) < self.HEADER_SIZE:
            raise StreamingError("Invalid stream: header too short")

        algorithm, chunk_size, nonce_prefix = self._parse_header(header)

        # Initialize cipher
        cipher = self._get_cipher(key)

        bytes_processed = 0
        expected_chunk_index = 0
        found_final = False

        while True:
            # Read chunk length
            length_bytes = input_stream.read(4)
            if not length_bytes:
                break

            if len(length_bytes) < 4:
                raise StreamingError("Unexpected end of stream")

            chunk_length = struct.unpack(">I", length_bytes)[0]

            # Read rest of chunk
            chunk_data = input_stream.read(chunk_length)
            if len(chunk_data) < chunk_length:
                raise StreamingError("Unexpected end of stream")

            # Decrypt chunk
            plaintext, chunk_index, is_final = self._decrypt_chunk(
                cipher,
                chunk_data,
                nonce_prefix,
                associated_data,
            )

            # Verify sequence
            if chunk_index != expected_chunk_index:
                raise ChunkSequenceError(
                    f"Expected chunk {expected_chunk_index}, got {chunk_index}"
                )

            output_stream.write(plaintext)
            bytes_processed += len(plaintext)
            expected_chunk_index += 1

            if is_final:
                found_final = True
                break

            if progress_callback and total_size > 0:
                progress_callback(input_stream.tell(), total_size)

        if not found_final:
            raise StreamingError("Stream truncated: no final chunk marker")

        return StreamingResult(
            bytes_processed=bytes_processed,
            chunks_processed=expected_chunk_index,
            algorithm=algorithm,
            completed_at=datetime.now(timezone.utc),
        )

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        key: bytes,
        associated_data: bytes | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> StreamingResult:
        """Encrypt a file.

        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            key: 32-byte encryption key
            associated_data: Optional AAD
            progress_callback: Optional progress callback

        Returns:
            StreamingResult with operation details
        """
        with open(input_path, "rb") as input_file:
            with open(output_path, "wb") as output_file:
                return self.encrypt_stream(
                    input_file,
                    output_file,
                    key,
                    associated_data,
                    progress_callback,
                )

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        key: bytes,
        associated_data: bytes | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> StreamingResult:
        """Decrypt a file.

        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            key: 32-byte decryption key
            associated_data: Optional AAD (must match encryption)
            progress_callback: Optional progress callback

        Returns:
            StreamingResult with operation details
        """
        with open(input_path, "rb") as input_file:
            with open(output_path, "wb") as output_file:
                return self.decrypt_stream(
                    input_file,
                    output_file,
                    key,
                    associated_data,
                    progress_callback,
                )

    def encrypt_iterator(
        self,
        data_iterator: Iterator[bytes],
        key: bytes,
        associated_data: bytes | None = None,
    ) -> Iterator[bytes]:
        """Encrypt data from an iterator, yielding encrypted chunks.

        Args:
            data_iterator: Iterator yielding data chunks
            key: 32-byte encryption key
            associated_data: Optional AAD

        Yields:
            Encrypted chunks
        """
        if len(key) != 32:
            raise StreamingError("Key must be 32 bytes")

        nonce_prefix = os.urandom(8)

        # Yield header first
        yield self._create_header(nonce_prefix)

        cipher = self._get_cipher(key)
        chunk_index = 0

        # Buffer for combining small chunks
        buffer = b""

        for data in data_iterator:
            buffer += data

            while len(buffer) >= self.config.chunk_size:
                chunk = buffer[:self.config.chunk_size]
                buffer = buffer[self.config.chunk_size:]

                encrypted = self._encrypt_chunk(
                    cipher,
                    chunk,
                    nonce_prefix,
                    chunk_index,
                    False,
                    associated_data,
                )
                yield encrypted
                chunk_index += 1

        # Final chunk (may be empty)
        encrypted = self._encrypt_chunk(
            cipher,
            buffer,
            nonce_prefix,
            chunk_index,
            True,
            associated_data,
        )
        yield encrypted

    def decrypt_iterator(
        self,
        encrypted_iterator: Iterator[bytes],
        key: bytes,
        associated_data: bytes | None = None,
    ) -> Iterator[bytes]:
        """Decrypt data from an iterator, yielding decrypted chunks.

        Args:
            encrypted_iterator: Iterator yielding encrypted data
            key: 32-byte decryption key
            associated_data: Optional AAD

        Yields:
            Decrypted chunks
        """
        if len(key) != 32:
            raise StreamingError("Key must be 32 bytes")

        buffer = b""
        header_parsed = False
        nonce_prefix = None
        cipher = None
        expected_chunk_index = 0

        for data in encrypted_iterator:
            buffer += data

            # Parse header if not done
            if not header_parsed:
                if len(buffer) >= self.HEADER_SIZE:
                    header = buffer[:self.HEADER_SIZE]
                    buffer = buffer[self.HEADER_SIZE:]
                    _, _, nonce_prefix = self._parse_header(header)
                    cipher = self._get_cipher(key)
                    header_parsed = True
                else:
                    continue

            # Process complete chunks
            while len(buffer) >= 4:
                chunk_length = struct.unpack(">I", buffer[:4])[0]
                total_length = 4 + chunk_length

                if len(buffer) < total_length:
                    break

                chunk_data = buffer[4:total_length]
                buffer = buffer[total_length:]

                plaintext, chunk_index, is_final = self._decrypt_chunk(
                    cipher,
                    chunk_data,
                    nonce_prefix,
                    associated_data,
                )

                if chunk_index != expected_chunk_index:
                    raise ChunkSequenceError(
                        f"Expected chunk {expected_chunk_index}, got {chunk_index}"
                    )

                yield plaintext
                expected_chunk_index += 1

                if is_final:
                    return

    # ==================== Internal Methods ====================

    def _get_cipher(self, key: bytes):
        """Get cipher for the configured algorithm."""
        if self.config.algorithm == StreamingAlgorithm.AES_256_GCM:
            return AESGCM(key)
        elif self.config.algorithm == StreamingAlgorithm.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key)
        else:
            raise StreamingError(f"Unknown algorithm: {self.config.algorithm}")

    def _create_header(self, nonce_prefix: bytes) -> bytes:
        """Create stream header."""
        algorithm_byte = 0 if self.config.algorithm == StreamingAlgorithm.AES_256_GCM else 1
        return (
            self.MAGIC +
            bytes([self.VERSION, algorithm_byte]) +
            struct.pack(">I", self.config.chunk_size) +
            nonce_prefix
        )

    def _parse_header(self, header: bytes) -> tuple[StreamingAlgorithm, int, bytes]:
        """Parse stream header."""
        if header[:4] != self.MAGIC:
            raise StreamingError("Invalid stream: bad magic")

        version = header[4]
        if version != self.VERSION:
            raise StreamingError(f"Unsupported stream version: {version}")

        algorithm_byte = header[5]
        if algorithm_byte == 0:
            algorithm = StreamingAlgorithm.AES_256_GCM
        elif algorithm_byte == 1:
            algorithm = StreamingAlgorithm.CHACHA20_POLY1305
        else:
            raise StreamingError(f"Unknown algorithm: {algorithm_byte}")

        chunk_size = struct.unpack(">I", header[6:10])[0]
        nonce_prefix = header[10:18]

        return algorithm, chunk_size, nonce_prefix

    def _encrypt_chunk(
        self,
        cipher,
        plaintext: bytes,
        nonce_prefix: bytes,
        chunk_index: int,
        is_final: bool,
        associated_data: bytes | None,
    ) -> bytes:
        """Encrypt a single chunk."""
        # Create unique nonce: prefix (8) + chunk_index (4)
        nonce = nonce_prefix + struct.pack(">I", chunk_index)

        # Create chunk header: chunk_index (4) + is_final (1)
        chunk_header = struct.pack(">I?", chunk_index, is_final)

        # Encrypt with chunk header as additional AAD
        aad = chunk_header
        if associated_data:
            aad = aad + associated_data

        ciphertext = cipher.encrypt(nonce, plaintext, aad)

        # Package: length (4) + chunk_header (5) + ciphertext
        chunk_data = chunk_header + ciphertext
        length = struct.pack(">I", len(chunk_data))

        return length + chunk_data

    def _decrypt_chunk(
        self,
        cipher,
        chunk_data: bytes,
        nonce_prefix: bytes,
        associated_data: bytes | None,
    ) -> tuple[bytes, int, bool]:
        """Decrypt a single chunk."""
        # Parse chunk header
        chunk_index = struct.unpack(">I", chunk_data[:4])[0]
        is_final = struct.unpack("?", chunk_data[4:5])[0]
        ciphertext = chunk_data[5:]

        # Recreate nonce
        nonce = nonce_prefix + struct.pack(">I", chunk_index)

        # Recreate AAD
        chunk_header = chunk_data[:5]
        aad = chunk_header
        if associated_data:
            aad = aad + associated_data

        try:
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ChunkAuthenticationError(f"Chunk {chunk_index} authentication failed: {e}")

        return plaintext, chunk_index, is_final


class StreamingEncryptor:
    """Context manager for streaming encryption."""

    def __init__(
        self,
        output_stream: BinaryIO,
        key: bytes,
        config: StreamingConfig | None = None,
        associated_data: bytes | None = None,
    ):
        self.output_stream = output_stream
        self.key = key
        self.config = config or StreamingConfig()
        self.associated_data = associated_data
        self._engine = StreamingEngine(self.config)
        self._cipher = None
        self._nonce_prefix = None
        self._chunk_index = 0
        self._buffer = b""
        self._finalized = False

    def __enter__(self):
        if len(self.key) != 32:
            raise StreamingError("Key must be 32 bytes")

        self._nonce_prefix = os.urandom(8)
        header = self._engine._create_header(self._nonce_prefix)
        self.output_stream.write(header)
        self._cipher = self._engine._get_cipher(self.key)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._finalized and exc_type is None:
            self.finalize()
        return False

    def write(self, data: bytes) -> None:
        """Write data to the encrypted stream."""
        if self._finalized:
            raise StreamingError("Encryptor already finalized")

        self._buffer += data

        while len(self._buffer) >= self.config.chunk_size:
            chunk = self._buffer[:self.config.chunk_size]
            self._buffer = self._buffer[self.config.chunk_size:]

            encrypted = self._engine._encrypt_chunk(
                self._cipher,
                chunk,
                self._nonce_prefix,
                self._chunk_index,
                False,
                self.associated_data,
            )
            self.output_stream.write(encrypted)
            self._chunk_index += 1

    def finalize(self) -> None:
        """Finalize the encrypted stream."""
        if self._finalized:
            return

        # Write final chunk (may be empty)
        encrypted = self._engine._encrypt_chunk(
            self._cipher,
            self._buffer,
            self._nonce_prefix,
            self._chunk_index,
            True,
            self.associated_data,
        )
        self.output_stream.write(encrypted)
        self._finalized = True


class StreamingDecryptor:
    """Context manager for streaming decryption."""

    def __init__(
        self,
        input_stream: BinaryIO,
        key: bytes,
        associated_data: bytes | None = None,
    ):
        self.input_stream = input_stream
        self.key = key
        self.associated_data = associated_data
        self._engine = None
        self._cipher = None
        self._nonce_prefix = None
        self._expected_chunk_index = 0
        self._finished = False

    def __enter__(self):
        if len(self.key) != 32:
            raise StreamingError("Key must be 32 bytes")

        # Read header
        header = self.input_stream.read(StreamingEngine.HEADER_SIZE)
        if len(header) < StreamingEngine.HEADER_SIZE:
            raise StreamingError("Invalid stream: header too short")

        self._engine = StreamingEngine()
        algorithm, chunk_size, self._nonce_prefix = self._engine._parse_header(header)
        self._engine.config.algorithm = algorithm
        self._engine.config.chunk_size = chunk_size
        self._cipher = self._engine._get_cipher(self.key)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def read_chunk(self) -> bytes | None:
        """Read and decrypt the next chunk.

        Returns:
            Decrypted data or None if stream is finished
        """
        if self._finished:
            return None

        # Read chunk length
        length_bytes = self.input_stream.read(4)
        if not length_bytes:
            raise StreamingError("Stream truncated: no final chunk marker")

        if len(length_bytes) < 4:
            raise StreamingError("Unexpected end of stream")

        chunk_length = struct.unpack(">I", length_bytes)[0]

        # Read chunk data
        chunk_data = self.input_stream.read(chunk_length)
        if len(chunk_data) < chunk_length:
            raise StreamingError("Unexpected end of stream")

        # Decrypt
        plaintext, chunk_index, is_final = self._engine._decrypt_chunk(
            self._cipher,
            chunk_data,
            self._nonce_prefix,
            self.associated_data,
        )

        if chunk_index != self._expected_chunk_index:
            raise ChunkSequenceError(
                f"Expected chunk {self._expected_chunk_index}, got {chunk_index}"
            )

        self._expected_chunk_index += 1

        if is_final:
            self._finished = True

        return plaintext

    def __iter__(self):
        return self

    def __next__(self) -> bytes:
        chunk = self.read_chunk()
        if chunk is None:
            raise StopIteration
        return chunk


# Singleton with default config
streaming_engine = StreamingEngine()
