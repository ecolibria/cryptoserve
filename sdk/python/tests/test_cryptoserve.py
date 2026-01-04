"""Integration tests for CryptoServe class.

These tests verify the high-level SDK API including:
- Initialization and configuration
- Encryption/decryption operations
- String and JSON helpers
- Hash and MAC operations
- Cache management
"""

import base64
import pytest
from unittest.mock import MagicMock, patch, Mock
import requests


class TestCryptoServeInitialization:
    """Tests for CryptoServe class initialization."""

    def test_init_with_defaults(self, patch_credentials):
        """Test initialization with default parameters."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client:
            mock_client.return_value = MagicMock()

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", auto_register=False)
            crypto._client = mock_client.return_value

            assert crypto.app_name == "test-app"
            assert crypto.team == "default"
            assert crypto.environment == "development"
            assert crypto.contexts == ["default"]

    def test_init_with_custom_params(self, patch_credentials):
        """Test initialization with custom parameters."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client:
            mock_client.return_value = MagicMock()

            from cryptoserve import CryptoServe
            crypto = CryptoServe(
                app_name="my-service",
                team="platform",
                environment="production",
                contexts=["user-pii", "payment-data"],
                enable_cache=False,
                auto_register=False,
            )

            assert crypto.app_name == "my-service"
            assert crypto.team == "platform"
            assert crypto.environment == "production"
            assert crypto.contexts == ["user-pii", "payment-data"]
            assert crypto._enable_cache is False

    def test_init_with_cache_config(self, patch_credentials):
        """Test initialization with cache configuration."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client:
            mock_client.return_value = MagicMock()

            from cryptoserve import CryptoServe
            crypto = CryptoServe(
                app_name="test-app",
                enable_cache=True,
                cache_ttl=600.0,
                cache_size=200,
                auto_register=False,
            )

            assert crypto.app_name == "test-app"
            # Cache availability depends on cryptography library

    def test_repr(self, patch_credentials):
        """Test string representation."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client:
            mock_client.return_value = MagicMock()

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)

            repr_str = repr(crypto)
            assert "test-app" in repr_str
            assert "development" in repr_str


class TestCryptoServeEncryption:
    """Tests for encryption and decryption operations."""

    def test_encrypt_decrypt_bytes(self, patch_credentials):
        """Test encrypt/decrypt with bytes."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.encrypt.return_value = b"encrypted-data"
            mock_client.decrypt.return_value = b"hello world"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            # Encrypt
            plaintext = b"hello world"
            ciphertext = crypto.encrypt(plaintext, context="default")
            assert ciphertext == b"encrypted-data"
            mock_client.encrypt.assert_called_once_with(plaintext, "default", None)

            # Decrypt
            decrypted = crypto.decrypt(ciphertext, context="default")
            assert decrypted == b"hello world"
            mock_client.decrypt.assert_called_once_with(ciphertext, "default", None)

    def test_encrypt_decrypt_with_aad(self, patch_credentials):
        """Test encrypt/decrypt with associated data."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.encrypt.return_value = b"encrypted-with-aad"
            mock_client.decrypt.return_value = b"sensitive"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            aad = b"user-id-123"
            plaintext = b"sensitive"

            ciphertext = crypto.encrypt(plaintext, context="user-pii", associated_data=aad)
            assert ciphertext == b"encrypted-with-aad"
            mock_client.encrypt.assert_called_with(plaintext, "user-pii", aad)

    def test_encrypt_string(self, patch_credentials):
        """Test string encryption helper."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.encrypt.return_value = b"encrypted-string"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            result = crypto.encrypt_string("my secret", context="default")

            # Result should be base64 encoded
            assert isinstance(result, str)
            decoded = base64.b64decode(result)
            assert decoded == b"encrypted-string"

    def test_decrypt_string(self, patch_credentials):
        """Test string decryption helper."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.decrypt.return_value = b"my secret"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            ciphertext_b64 = base64.b64encode(b"encrypted").decode("ascii")
            result = crypto.decrypt_string(ciphertext_b64, context="default")

            assert result == "my secret"

    def test_encrypt_decrypt_json(self, patch_credentials):
        """Test JSON encryption/decryption helpers."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.encrypt.return_value = b"encrypted-json"
            mock_client.decrypt.return_value = b'{"key": "value", "number": 42}'
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            # Encrypt JSON
            obj = {"key": "value", "number": 42}
            encrypted = crypto.encrypt_json(obj, context="default")
            assert isinstance(encrypted, str)

            # Decrypt JSON
            decrypted = crypto.decrypt_json(encrypted, context="default")
            assert decrypted["key"] == "value"
            assert decrypted["number"] == 42


class TestCryptoServeHashing:
    """Tests for hash and MAC operations."""

    def test_hash_sha256(self, patch_credentials):
        """Test SHA-256 hashing."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            # Real SHA-256 hash of "hello world"
            expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            mock_client.hash.return_value = expected_hash
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            result = crypto.hash(b"hello world")
            assert result == expected_hash

    def test_hash_sha512(self, patch_credentials):
        """Test SHA-512 hashing."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.hash.return_value = "sha512-hash-hex"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            result = crypto.hash(b"data", algorithm="sha512")
            mock_client.hash.assert_called_with(b"data", "sha512")

    def test_mac_hmac_sha256(self, patch_credentials):
        """Test HMAC-SHA256 MAC."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.mac.return_value = "hmac-hex-value"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            key = b"secret-key-32-bytes-long!!!!!!!!"
            result = crypto.mac(b"message", key)

            mock_client.mac.assert_called_with(b"message", key, "hmac-sha256")


class TestCryptoServeSignatures:
    """Tests for digital signature operations."""

    def test_sign(self, patch_credentials):
        """Test signing data."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.sign.return_value = b"signature-bytes"
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            signature = crypto.sign(b"document", key_id="my-key-id")

            assert signature == b"signature-bytes"
            mock_client.sign.assert_called_with(b"document", "my-key-id")

    def test_verify_signature(self, patch_credentials):
        """Test signature verification."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.verify.return_value = True
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
            crypto._client = mock_client

            is_valid = crypto.verify_signature(
                b"document",
                b"signature",
                key_id="my-key-id"
            )

            assert is_valid is True


class TestCryptoServeCacheManagement:
    """Tests for cache management operations."""

    def test_cache_stats_disabled(self, patch_credentials):
        """Test cache stats when cache is disabled."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)

            stats = crypto.cache_stats()
            assert stats["enabled"] is False

    def test_invalidate_cache_disabled(self, patch_credentials):
        """Test cache invalidation when cache is disabled."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            from cryptoserve import CryptoServe
            crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)

            count = crypto.invalidate_cache()
            assert count == 0


class TestCryptoServeHealthCheck:
    """Tests for health check operations."""

    def test_health_check_success(self, patch_credentials):
        """Test successful health check."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            with patch("requests.get") as mock_get:
                mock_get.return_value.status_code = 200

                from cryptoserve import CryptoServe
                crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
                crypto._client = mock_client

                result = crypto.health_check()
                assert result is True

    def test_health_check_failure(self, patch_credentials):
        """Test failed health check."""
        with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client._access_token = "test-token"
            mock_client_class.return_value = mock_client

            with patch("requests.get") as mock_get:
                mock_get.side_effect = requests.RequestException("Connection failed")

                from cryptoserve import CryptoServe
                crypto = CryptoServe(app_name="test-app", enable_cache=False, auto_register=False)
                crypto._client = mock_client

                result = crypto.health_check()
                assert result is False


class TestCryptoServeRegistration:
    """Tests for application registration flow."""

    def test_registration_not_logged_in(self):
        """Test registration fails when not logged in."""
        with patch("cryptoserve._auto_register.load_app_credentials", return_value=None):
            with patch("cryptoserve._auto_register.get_session_cookie", return_value=None):
                with patch("cryptoserve._auto_register.get_server_url", return_value="http://localhost:8000"):
                    with patch("cryptoserve._auto_register.get_api_url", return_value="http://localhost:8000/api"):
                        from cryptoserve import CryptoServe, CryptoServeNotLoggedInError

                        with pytest.raises(CryptoServeNotLoggedInError):
                            CryptoServe(app_name="test-app")

    def test_registration_success(self, patch_no_credentials):
        """Test successful registration flow."""
        with patch("cryptoserve._auto_register.load_app_credentials", return_value=None):
            with patch("cryptoserve._auto_register.get_session_cookie", return_value="test-cookie"):
                with patch("cryptoserve._auto_register.get_server_url", return_value="http://localhost:8000"):
                    with patch("cryptoserve._auto_register.get_api_url", return_value="http://localhost:8000/api"):
                        with patch("cryptoserve._auto_register.save_app_credentials"):
                            with patch("requests.post") as mock_post:
                                mock_response = MagicMock()
                                mock_response.status_code = 200
                                mock_response.json.return_value = {
                                    "app_id": "new-app-id",
                                    "access_token": "new-access-token.payload.signature",
                                    "refresh_token": "new-refresh-token",
                                    "contexts": ["default"],
                                    "is_new": True,
                                }
                                mock_post.return_value = mock_response

                                with patch("cryptoserve._auto_register.CryptoClient") as mock_client_class:
                                    mock_client = MagicMock()
                                    mock_client._access_token = "test-token"
                                    mock_client_class.return_value = mock_client

                                    from cryptoserve import CryptoServe
                                    crypto = CryptoServe(app_name="new-app")

                                    assert crypto.app_id == "new-app-id"
