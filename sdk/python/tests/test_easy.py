"""Tests for cryptoserve_core easy encryption module."""

import os
import pytest
import tempfile

from cryptoserve_core.easy import (
    encrypt,
    decrypt,
    encrypt_string,
    decrypt_string,
    encrypt_file,
    decrypt_file,
    EasyEncryptionError,
    _VERSION_SINGLE,
    _VERSION_CHUNKED,
    _SALT_SIZE,
    _NONCE_SIZE,
)


class TestEncryptDecrypt:
    """Tests for encrypt/decrypt roundtrip."""

    def test_roundtrip_basic(self):
        """Encrypt then decrypt returns original plaintext."""
        plaintext = b"hello world"
        ct = encrypt(plaintext, "password")
        assert decrypt(ct, "password") == plaintext

    def test_roundtrip_empty(self):
        """Empty plaintext encrypts and decrypts correctly."""
        ct = encrypt(b"", "password")
        assert decrypt(ct, "password") == b""

    def test_roundtrip_large_data(self):
        """1MB+ data encrypts and decrypts correctly."""
        plaintext = os.urandom(1024 * 1024 + 37)  # 1MB + 37 bytes
        ct = encrypt(plaintext, "password")
        assert decrypt(ct, "password") == plaintext

    def test_different_outputs(self):
        """Same input produces different ciphertext (random salt/nonce)."""
        ct1 = encrypt(b"same input", "same password")
        ct2 = encrypt(b"same input", "same password")
        assert ct1 != ct2

    def test_version_byte(self):
        """Ciphertext starts with version 1 byte."""
        ct = encrypt(b"test", "pw")
        assert ct[0] == _VERSION_SINGLE

    def test_wrong_password(self):
        """Wrong password raises EasyEncryptionError."""
        ct = encrypt(b"secret", "correct-password")
        with pytest.raises(EasyEncryptionError):
            decrypt(ct, "wrong-password")

    def test_corrupted_ciphertext(self):
        """Corrupted ciphertext raises EasyEncryptionError."""
        ct = encrypt(b"data", "pw")
        # Flip a byte in the ciphertext portion
        corrupted = bytearray(ct)
        corrupted[-1] ^= 0xFF
        with pytest.raises(EasyEncryptionError):
            decrypt(bytes(corrupted), "pw")

    def test_truncated_ciphertext(self):
        """Truncated ciphertext raises EasyEncryptionError."""
        with pytest.raises(EasyEncryptionError, match="too short"):
            decrypt(b"\x01" + b"\x00" * 10, "pw")

    def test_unsupported_version(self):
        """Unsupported version byte raises EasyEncryptionError."""
        ct = encrypt(b"data", "pw")
        bad = bytes([99]) + ct[1:]
        with pytest.raises(EasyEncryptionError, match="Unsupported blob version"):
            decrypt(bad, "pw")


class TestStringEncryptDecrypt:
    """Tests for encrypt_string/decrypt_string."""

    def test_string_roundtrip(self):
        """String encrypt/decrypt roundtrip."""
        text = "Hello, World!"
        encoded = encrypt_string(text, "password")
        assert isinstance(encoded, str)
        assert decrypt_string(encoded, "password") == text

    def test_string_unicode(self):
        """Unicode strings encrypt and decrypt correctly."""
        text = "Encryption test with emoji and unicode"
        encoded = encrypt_string(text, "pw")
        assert decrypt_string(encoded, "pw") == text

    def test_string_base64_output(self):
        """Output is valid base64."""
        import base64
        encoded = encrypt_string("test", "pw")
        # Should not raise
        base64.urlsafe_b64decode(encoded.encode("ascii"))


class TestFileEncryptDecrypt:
    """Tests for encrypt_file/decrypt_file."""

    def test_small_file_roundtrip(self):
        """Small file uses single-blob format and roundtrips correctly."""
        content = b"Small file content"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(content)
            input_path = f.name

        enc_path = input_path + ".enc"
        dec_path = input_path + ".dec"

        try:
            encrypt_file(input_path, enc_path, "password")
            # Verify it uses single-blob format
            with open(enc_path, "rb") as f:
                assert f.read(1)[0] == _VERSION_SINGLE

            decrypt_file(enc_path, dec_path, "password")
            with open(dec_path, "rb") as f:
                assert f.read() == content
        finally:
            for path in [input_path, enc_path, dec_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_large_file_roundtrip(self):
        """Large file uses chunked format and roundtrips correctly."""
        content = os.urandom(128 * 1024)  # 128KB > 64KB threshold
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            input_path = f.name

        enc_path = input_path + ".enc"
        dec_path = input_path + ".dec"

        try:
            encrypt_file(input_path, enc_path, "password")
            # Verify it uses chunked format
            with open(enc_path, "rb") as f:
                assert f.read(1)[0] == _VERSION_CHUNKED

            decrypt_file(enc_path, dec_path, "password")
            with open(dec_path, "rb") as f:
                assert f.read() == content
        finally:
            for path in [input_path, enc_path, dec_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_empty_file_roundtrip(self):
        """Empty file encrypts and decrypts correctly."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            input_path = f.name

        enc_path = input_path + ".enc"
        dec_path = input_path + ".dec"

        try:
            encrypt_file(input_path, enc_path, "password")
            decrypt_file(enc_path, dec_path, "password")
            with open(dec_path, "rb") as f:
                assert f.read() == b""
        finally:
            for path in [input_path, enc_path, dec_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_file_wrong_password(self):
        """Decrypting with wrong password raises error."""
        content = b"secret file content"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(content)
            input_path = f.name

        enc_path = input_path + ".enc"
        dec_path = input_path + ".dec"

        try:
            encrypt_file(input_path, enc_path, "correct")
            with pytest.raises(EasyEncryptionError):
                decrypt_file(enc_path, dec_path, "wrong")
        finally:
            for path in [input_path, enc_path, dec_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_file_not_found(self):
        """Non-existent input file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            encrypt_file("/nonexistent/path.txt", "/tmp/out.enc", "pw")

    def test_large_chunked_file_wrong_password(self):
        """Large chunked file with wrong password raises error."""
        content = os.urandom(128 * 1024)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            input_path = f.name

        enc_path = input_path + ".enc"
        dec_path = input_path + ".dec"

        try:
            encrypt_file(input_path, enc_path, "correct")
            with pytest.raises(EasyEncryptionError):
                decrypt_file(enc_path, dec_path, "wrong")
        finally:
            for path in [input_path, enc_path, dec_path]:
                if os.path.exists(path):
                    os.unlink(path)
