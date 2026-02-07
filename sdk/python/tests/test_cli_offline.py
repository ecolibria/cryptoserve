"""Tests for CLI offline commands (encrypt, decrypt, hash-password, token)."""

import json
import os
import subprocess
import sys
import tempfile

import pytest


def run_cli(*args):
    """Run the cryptoserve CLI and return result."""
    result = subprocess.run(
        [sys.executable, "-m", "cryptoserve", *args],
        capture_output=True,
        text=True,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )
    return result


class TestEncryptDecryptRoundtrip:
    """Test encrypt/decrypt string roundtrip via CLI."""

    def test_encrypt_decrypt_string(self):
        """Encrypt then decrypt a string produces original text."""
        enc = run_cli("encrypt", "hello world", "--password", "test-pw")
        assert enc.returncode == 0
        encrypted = enc.stdout.strip()
        assert len(encrypted) > 0

        dec = run_cli("decrypt", encrypted, "--password", "test-pw")
        assert dec.returncode == 0
        assert dec.stdout.strip() == "hello world"

    def test_encrypt_decrypt_empty_string(self):
        """Empty string encrypts and decrypts."""
        enc = run_cli("encrypt", "", "--password", "test-pw")
        assert enc.returncode == 0
        encrypted = enc.stdout.strip()

        dec = run_cli("decrypt", encrypted, "--password", "test-pw")
        assert dec.returncode == 0
        assert dec.stdout.strip() == ""

    def test_wrong_password_fails(self):
        """Decrypt with wrong password fails."""
        enc = run_cli("encrypt", "secret", "--password", "correct")
        assert enc.returncode == 0
        encrypted = enc.stdout.strip()

        dec = run_cli("decrypt", encrypted, "--password", "wrong")
        assert dec.returncode == 1

    def test_encrypt_missing_password(self):
        """Encrypt without --password shows error."""
        result = run_cli("encrypt", "hello")
        assert result.returncode == 1
        assert "password" in result.stdout.lower() or "password" in result.stderr.lower()

    def test_decrypt_missing_password(self):
        """Decrypt without --password shows error."""
        result = run_cli("decrypt", "abc123")
        assert result.returncode == 1


class TestEncryptDecryptFile:
    """Test file encryption/decryption via CLI."""

    def test_file_roundtrip(self):
        """Encrypt then decrypt a file produces original content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            enc_path = os.path.join(tmpdir, "input.txt.enc")
            dec_path = os.path.join(tmpdir, "output.txt")

            with open(input_path, "w") as f:
                f.write("file content here")

            enc = run_cli(
                "encrypt", "--file", input_path,
                "--output", enc_path, "--password", "file-pw"
            )
            assert enc.returncode == 0

            dec = run_cli(
                "decrypt", "--file", enc_path,
                "--output", dec_path, "--password", "file-pw"
            )
            assert dec.returncode == 0

            with open(dec_path, "r") as f:
                assert f.read() == "file content here"

    def test_encrypt_file_default_output(self):
        """Encrypt file without --output uses .enc suffix."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "data.bin")
            with open(input_path, "wb") as f:
                f.write(b"binary data")

            enc = run_cli(
                "encrypt", "--file", input_path, "--password", "pw"
            )
            assert enc.returncode == 0
            assert os.path.exists(input_path + ".enc")


class TestHashPassword:
    """Test hash-password CLI command."""

    def test_hash_password_positional(self):
        """Hash password provided as positional arg."""
        result = run_cli("hash-password", "test-password")
        assert result.returncode == 0
        output = result.stdout.strip()
        assert output.startswith("$scrypt$")

    def test_hash_password_pbkdf2(self):
        """Hash with PBKDF2 algorithm."""
        result = run_cli("hash-password", "test-password", "--algo", "pbkdf2")
        assert result.returncode == 0
        output = result.stdout.strip()
        assert output.startswith("$pbkdf2-sha256$")

    def test_hash_password_invalid_algo(self):
        """Invalid algorithm shows error."""
        result = run_cli("hash-password", "pw", "--algo", "md5")
        assert result.returncode == 1


class TestToken:
    """Test token CLI command."""

    def test_create_token(self):
        """Create a JWT token."""
        result = run_cli(
            "token", "--key", "test-secret-key-1234",
            "--payload", '{"sub":"user-1"}'
        )
        assert result.returncode == 0
        token = result.stdout.strip()
        # JWT format: header.payload.signature
        parts = token.split(".")
        assert len(parts) == 3

    def test_create_token_with_expires(self):
        """Create token with custom expiry."""
        result = run_cli(
            "token", "--key", "test-secret-key-1234",
            "--payload", '{"sub":"user-1"}', "--expires", "7200"
        )
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token.split(".")) == 3

    def test_create_token_no_payload(self):
        """Create token without payload (empty claims)."""
        result = run_cli("token", "--key", "test-secret-key-1234")
        assert result.returncode == 0
        assert len(result.stdout.strip().split(".")) == 3

    def test_token_missing_key(self):
        """Token without --key shows error."""
        result = run_cli("token")
        assert result.returncode == 1
        assert "key" in result.stdout.lower() or "key" in result.stderr.lower()

    def test_token_key_too_short(self):
        """Token with key < 16 bytes shows error."""
        result = run_cli("token", "--key", "short")
        assert result.returncode == 1

    def test_token_invalid_payload(self):
        """Token with invalid JSON payload shows error."""
        result = run_cli("token", "--key", "test-secret-key-1234", "--payload", "not-json")
        assert result.returncode == 1


class TestHelpShowsOfflineTools:
    """Test that help output includes offline tools."""

    def test_help_contains_offline_tools(self):
        """Help output includes OFFLINE TOOLS section."""
        result = run_cli("help")
        assert result.returncode == 0
        output = result.stdout
        assert "OFFLINE TOOLS" in output
        assert "encrypt" in output
        assert "decrypt" in output
        assert "hash-password" in output
        assert "token" in output

    def test_no_args_shows_help(self):
        """Running with no args shows help."""
        result = run_cli()
        assert result.returncode == 0
        assert "OFFLINE TOOLS" in result.stdout
