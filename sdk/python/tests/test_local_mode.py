"""Tests for CryptoServe local mode."""

import os
import pytest
from unittest.mock import patch, MagicMock

from cryptoserve._auto_register import CryptoServe, CryptoServeError


class TestLocalModeInit:
    """Tests for CryptoServe.local() initialization."""

    def test_init_with_master_key(self):
        """Initialize with explicit master key."""
        key = os.urandom(32)
        crypto = CryptoServe.local(master_key=key)
        assert crypto._local_mode is True
        assert crypto._master_key == key

    def test_init_with_password(self):
        """Initialize with password."""
        crypto = CryptoServe.local(password="my-secret")
        assert crypto._local_mode is True
        assert crypto._master_key is not None
        assert len(crypto._master_key) == 32

    def test_missing_key_and_password(self):
        """Missing both raises ValueError."""
        with pytest.raises(ValueError, match="master_key or password"):
            CryptoServe.local()

    def test_wrong_key_size(self):
        """Wrong master key size raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            CryptoServe.local(master_key=b"too-short")

    def test_no_server_connection(self):
        """Local mode doesn't try to connect to server."""
        crypto = CryptoServe.local(password="test")
        assert crypto._client is None
        assert crypto.server_url is None

    def test_repr(self):
        """Local mode repr shows mode."""
        crypto = CryptoServe.local(password="test")
        assert "local" in repr(crypto)

    def test_health_check_local(self):
        """Health check returns True in local mode."""
        crypto = CryptoServe.local(password="test")
        assert crypto.health_check() is True


class TestLocalModeEncryption:
    """Tests for encrypt/decrypt in local mode."""

    def test_encrypt_decrypt_roundtrip(self):
        """Basic encrypt/decrypt roundtrip."""
        crypto = CryptoServe.local(password="test-password")
        plaintext = b"hello world"
        ciphertext = crypto.encrypt(plaintext, context="default")
        assert crypto.decrypt(ciphertext, context="default") == plaintext

    def test_different_contexts_different_keys(self):
        """Different contexts produce different ciphertext."""
        crypto = CryptoServe.local(password="test")
        plaintext = b"same data"

        ct1 = crypto.encrypt(plaintext, context="ctx-a")
        ct2 = crypto.encrypt(plaintext, context="ctx-b")

        # Different contexts = different keys = can't cross-decrypt
        assert ct1 != ct2
        with pytest.raises(CryptoServeError):
            crypto.decrypt(ct1, context="ctx-b")

    def test_same_password_interoperable(self):
        """Two instances with same password can decrypt each other's data."""
        crypto1 = CryptoServe.local(password="shared-secret")
        crypto2 = CryptoServe.local(password="shared-secret")

        plaintext = b"interop test"
        ciphertext = crypto1.encrypt(plaintext, context="default")
        assert crypto2.decrypt(ciphertext, context="default") == plaintext

    def test_different_password_not_interoperable(self):
        """Different passwords can't decrypt each other's data."""
        crypto1 = CryptoServe.local(password="password-1")
        crypto2 = CryptoServe.local(password="password-2")

        ciphertext = crypto1.encrypt(b"secret", context="default")
        with pytest.raises(CryptoServeError):
            crypto2.decrypt(ciphertext, context="default")

    def test_encrypt_empty(self):
        """Empty plaintext encrypts and decrypts."""
        crypto = CryptoServe.local(password="test")
        ct = crypto.encrypt(b"", context="default")
        assert crypto.decrypt(ct, context="default") == b""

    def test_encrypt_large_data(self):
        """Large data encrypts and decrypts."""
        crypto = CryptoServe.local(password="test")
        plaintext = os.urandom(100_000)
        ct = crypto.encrypt(plaintext, context="default")
        assert crypto.decrypt(ct, context="default") == plaintext


class TestLocalModeStringHelpers:
    """Tests for string/JSON helpers in local mode."""

    def test_encrypt_string(self):
        """String encrypt/decrypt roundtrip."""
        crypto = CryptoServe.local(password="test")
        encoded = crypto.encrypt_string("my secret", context="default")
        assert isinstance(encoded, str)
        assert crypto.decrypt_string(encoded, context="default") == "my secret"

    def test_encrypt_json(self):
        """JSON encrypt/decrypt roundtrip."""
        crypto = CryptoServe.local(password="test")
        obj = {"user": "alice", "role": "admin", "count": 42}
        encoded = crypto.encrypt_json(obj, context="default")
        result = crypto.decrypt_json(encoded, context="default")
        assert result == obj


class TestLocalModeHashMac:
    """Tests for hash and MAC in local mode."""

    def test_hash_sha256(self):
        """SHA-256 hash works locally."""
        crypto = CryptoServe.local(password="test")
        result = crypto.hash(b"hello world")
        # Known SHA-256 of "hello world"
        assert result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_hash_sha512(self):
        """SHA-512 hash works locally."""
        crypto = CryptoServe.local(password="test")
        result = crypto.hash(b"hello world", algorithm="sha512")
        assert len(result) == 128  # SHA-512 hex is 128 chars

    def test_hash_unsupported(self):
        """Unsupported hash algorithm raises error."""
        crypto = CryptoServe.local(password="test")
        with pytest.raises(CryptoServeError, match="Unsupported hash"):
            crypto.hash(b"data", algorithm="md5")

    def test_mac_hmac_sha256(self):
        """HMAC-SHA256 works locally."""
        crypto = CryptoServe.local(password="test")
        key = b"secret-key-for-hmac-testing!!!!!"
        result = crypto.mac(b"message", key)
        assert isinstance(result, str)
        assert len(result) == 64  # HMAC-SHA256 hex

    def test_mac_hmac_sha512(self):
        """HMAC-SHA512 works locally."""
        crypto = CryptoServe.local(password="test")
        key = b"secret-key-for-hmac-testing!!!!!"
        result = crypto.mac(b"message", key, algorithm="hmac-sha512")
        assert len(result) == 128  # HMAC-SHA512 hex

    def test_mac_unsupported(self):
        """Unsupported MAC algorithm raises error."""
        crypto = CryptoServe.local(password="test")
        with pytest.raises(CryptoServeError, match="Unsupported MAC"):
            crypto.mac(b"data", b"key", algorithm="hmac-md5")


class TestLocalModeSigningRejection:
    """Tests that signing operations are rejected in local mode."""

    def test_sign_raises_error(self):
        """sign() raises CryptoServeError in local mode."""
        crypto = CryptoServe.local(password="test")
        with pytest.raises(CryptoServeError, match="Signing requires server mode"):
            crypto.sign(b"data", key_id="some-key")

    def test_verify_signature_raises_error(self):
        """verify_signature() raises CryptoServeError in local mode."""
        crypto = CryptoServe.local(password="test")
        with pytest.raises(CryptoServeError, match="Signing requires server mode"):
            crypto.verify_signature(b"data", b"sig", key_id="some-key")


class TestLocalModeNoNetwork:
    """Verify that local mode makes no network calls."""

    def test_no_network_on_init(self):
        """Local mode init doesn't make network requests."""
        with patch("cryptoserve._auto_register.requests") as mock_requests:
            crypto = CryptoServe.local(password="test")
            mock_requests.post.assert_not_called()
            mock_requests.get.assert_not_called()

    def test_no_network_on_operations(self):
        """Local mode operations don't make network requests."""
        with patch("cryptoserve._auto_register.requests") as mock_requests:
            crypto = CryptoServe.local(password="test")

            # Encrypt/decrypt
            ct = crypto.encrypt(b"data", context="default")
            crypto.decrypt(ct, context="default")

            # Hash/MAC
            crypto.hash(b"data")
            crypto.mac(b"data", b"key-at-least-some-bytes")

            mock_requests.post.assert_not_called()
            mock_requests.get.assert_not_called()
