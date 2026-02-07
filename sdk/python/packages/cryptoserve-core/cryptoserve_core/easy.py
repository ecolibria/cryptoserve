"""
Easy password-based encryption for CryptoServe Core.

Provides simple encrypt/decrypt functions that handle key derivation,
nonce generation, and authenticated encryption automatically.

Blob format (version 1 - single blob):
    [version:1][salt:16][nonce:12][ciphertext+tag]

Blob format (version 2 - chunked file):
    [version:2][salt:16][chunk_count:4]
    Per chunk: [nonce:12][chunk_len:4][ciphertext+tag]
"""

import os
import struct
from typing import Union

from cryptoserve_core.ciphers import AESGCMCipher, CipherError
from cryptoserve_core.keys import KeyDerivation


class EasyEncryptionError(CipherError):
    """Exception for easy encryption operations."""
    pass


# Constants
_VERSION_SINGLE = 1
_VERSION_CHUNKED = 2
_SALT_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16
_PBKDF2_ITERATIONS = 600_000
_CHUNK_SIZE = 64 * 1024  # 64KB
_FILE_CHUNK_THRESHOLD = _CHUNK_SIZE  # Files larger than this use chunked format


def encrypt(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt data with a password.

    Uses PBKDF2 key derivation (600K iterations) and AES-256-GCM.
    Each call generates a fresh random salt and nonce.

    Args:
        plaintext: Data to encrypt (can be empty).
        password: Password for key derivation.

    Returns:
        Encrypted blob: [version:1][salt:16][nonce:12][ciphertext+tag]

    Raises:
        EasyEncryptionError: If encryption fails.
    """
    try:
        salt = os.urandom(_SALT_SIZE)
        key, _ = KeyDerivation.from_password(
            password, salt=salt, bits=256, iterations=_PBKDF2_ITERATIONS
        )
        cipher = AESGCMCipher(key)
        ciphertext, nonce = cipher.encrypt(plaintext)
        return struct.pack("B", _VERSION_SINGLE) + salt + nonce + ciphertext
    except CipherError:
        raise
    except Exception as e:
        raise EasyEncryptionError(f"Encryption failed: {e}") from e


def decrypt(ciphertext: bytes, password: str) -> bytes:
    """
    Decrypt data encrypted with encrypt().

    Args:
        ciphertext: Encrypted blob from encrypt().
        password: Password used during encryption.

    Returns:
        Decrypted plaintext.

    Raises:
        EasyEncryptionError: If decryption fails (wrong password, corrupted data).
    """
    min_len = 1 + _SALT_SIZE + _NONCE_SIZE + _TAG_SIZE
    if len(ciphertext) < min_len:
        raise EasyEncryptionError(
            f"Ciphertext too short: expected at least {min_len} bytes, got {len(ciphertext)}"
        )

    version = ciphertext[0]
    if version != _VERSION_SINGLE:
        raise EasyEncryptionError(f"Unsupported blob version: {version}")

    salt = ciphertext[1 : 1 + _SALT_SIZE]
    nonce = ciphertext[1 + _SALT_SIZE : 1 + _SALT_SIZE + _NONCE_SIZE]
    encrypted = ciphertext[1 + _SALT_SIZE + _NONCE_SIZE :]

    try:
        key, _ = KeyDerivation.from_password(
            password, salt=salt, bits=256, iterations=_PBKDF2_ITERATIONS
        )
        cipher = AESGCMCipher(key)
        return cipher.decrypt(encrypted, nonce)
    except CipherError as e:
        raise EasyEncryptionError(f"Decryption failed (wrong password or corrupted data): {e}") from e
    except Exception as e:
        raise EasyEncryptionError(f"Decryption failed: {e}") from e


def encrypt_string(text: str, password: str) -> str:
    """
    Encrypt a string and return URL-safe base64 output.

    Args:
        text: String to encrypt.
        password: Password for key derivation.

    Returns:
        URL-safe base64-encoded ciphertext.
    """
    import base64
    blob = encrypt(text.encode("utf-8"), password)
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_string(encoded: str, password: str) -> str:
    """
    Decrypt a base64-encoded string from encrypt_string().

    Args:
        encoded: URL-safe base64-encoded ciphertext.
        password: Password used during encryption.

    Returns:
        Decrypted string.
    """
    import base64
    blob = base64.urlsafe_b64decode(encoded.encode("ascii"))
    return decrypt(blob, password).decode("utf-8")


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypt a file.

    Small files (< 64KB) use a single encrypted blob.
    Large files use chunked encryption for memory efficiency.

    Args:
        input_path: Path to the file to encrypt.
        output_path: Path for the encrypted output file.
        password: Password for key derivation.

    Raises:
        EasyEncryptionError: If encryption fails.
        FileNotFoundError: If input file doesn't exist.
    """
    try:
        file_size = os.path.getsize(input_path)
    except OSError as e:
        raise FileNotFoundError(f"Cannot access input file: {e}") from e

    try:
        if file_size <= _FILE_CHUNK_THRESHOLD:
            _encrypt_file_single(input_path, output_path, password)
        else:
            _encrypt_file_chunked(input_path, output_path, password)
    except (EasyEncryptionError, FileNotFoundError):
        raise
    except Exception as e:
        raise EasyEncryptionError(f"File encryption failed: {e}") from e


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Decrypt a file encrypted with encrypt_file().

    Automatically detects single-blob vs chunked format.

    Args:
        input_path: Path to the encrypted file.
        output_path: Path for the decrypted output file.
        password: Password used during encryption.

    Raises:
        EasyEncryptionError: If decryption fails.
        FileNotFoundError: If input file doesn't exist.
    """
    try:
        with open(input_path, "rb") as f:
            version_byte = f.read(1)
    except OSError as e:
        raise FileNotFoundError(f"Cannot access input file: {e}") from e

    if not version_byte:
        raise EasyEncryptionError("Encrypted file is empty")

    version = version_byte[0]

    try:
        if version == _VERSION_SINGLE:
            _decrypt_file_single(input_path, output_path, password)
        elif version == _VERSION_CHUNKED:
            _decrypt_file_chunked(input_path, output_path, password)
        else:
            raise EasyEncryptionError(f"Unsupported file version: {version}")
    except (EasyEncryptionError, FileNotFoundError):
        raise
    except Exception as e:
        raise EasyEncryptionError(f"File decryption failed: {e}") from e


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encrypt_file_single(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a small file as a single blob."""
    with open(input_path, "rb") as f:
        plaintext = f.read()

    blob = encrypt(plaintext, password)

    with open(output_path, "wb") as f:
        f.write(blob)


def _decrypt_file_single(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a single-blob file."""
    with open(input_path, "rb") as f:
        blob = f.read()

    plaintext = decrypt(blob, password)

    with open(output_path, "wb") as f:
        f.write(plaintext)


def _encrypt_file_chunked(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a large file in chunks."""
    salt = os.urandom(_SALT_SIZE)
    key, _ = KeyDerivation.from_password(
        password, salt=salt, bits=256, iterations=_PBKDF2_ITERATIONS
    )

    # First pass: count chunks
    file_size = os.path.getsize(input_path)
    chunk_count = (file_size + _CHUNK_SIZE - 1) // _CHUNK_SIZE
    if file_size == 0:
        chunk_count = 1  # Empty files still get one chunk

    with open(output_path, "wb") as out_f:
        # Write header
        out_f.write(struct.pack("B", _VERSION_CHUNKED))
        out_f.write(salt)
        out_f.write(struct.pack(">I", chunk_count))

        cipher = AESGCMCipher(key)

        with open(input_path, "rb") as in_f:
            chunks_written = 0
            while True:
                chunk = in_f.read(_CHUNK_SIZE)
                if not chunk and chunks_written > 0:
                    break

                ciphertext, nonce = cipher.encrypt(chunk)
                out_f.write(nonce)
                out_f.write(struct.pack(">I", len(ciphertext)))
                out_f.write(ciphertext)
                chunks_written += 1

                if not chunk:
                    break


def _decrypt_file_chunked(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a chunked file."""
    with open(input_path, "rb") as in_f:
        # Read header
        version = struct.unpack("B", in_f.read(1))[0]
        if version != _VERSION_CHUNKED:
            raise EasyEncryptionError(f"Expected chunked version {_VERSION_CHUNKED}, got {version}")

        salt = in_f.read(_SALT_SIZE)
        if len(salt) != _SALT_SIZE:
            raise EasyEncryptionError("Truncated file: missing salt")

        chunk_count_bytes = in_f.read(4)
        if len(chunk_count_bytes) != 4:
            raise EasyEncryptionError("Truncated file: missing chunk count")
        chunk_count = struct.unpack(">I", chunk_count_bytes)[0]

        key, _ = KeyDerivation.from_password(
            password, salt=salt, bits=256, iterations=_PBKDF2_ITERATIONS
        )
        cipher = AESGCMCipher(key)

        with open(output_path, "wb") as out_f:
            for i in range(chunk_count):
                nonce = in_f.read(_NONCE_SIZE)
                if len(nonce) != _NONCE_SIZE:
                    raise EasyEncryptionError(f"Truncated file: chunk {i} missing nonce")

                chunk_len_bytes = in_f.read(4)
                if len(chunk_len_bytes) != 4:
                    raise EasyEncryptionError(f"Truncated file: chunk {i} missing length")
                chunk_len = struct.unpack(">I", chunk_len_bytes)[0]

                ciphertext = in_f.read(chunk_len)
                if len(ciphertext) != chunk_len:
                    raise EasyEncryptionError(f"Truncated file: chunk {i} incomplete")

                try:
                    plaintext = cipher.decrypt(ciphertext, nonce)
                except CipherError as e:
                    raise EasyEncryptionError(
                        f"Chunk {i} decryption failed (wrong password or corrupted data): {e}"
                    ) from e

                out_f.write(plaintext)
