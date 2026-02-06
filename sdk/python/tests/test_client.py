"""Unit tests for CryptoClient class.

These tests verify the low-level API client including:
- HTTP request handling
- Token management and refresh
- Error handling and exceptions
- Hash and MAC operations (local)
"""

import base64
import pytest
from unittest.mock import MagicMock, patch, Mock
import requests


class TestCryptoClientInitialization:
    """Tests for CryptoClient initialization."""

    def test_init_basic(self):
        """Test basic client initialization."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        assert client.server_url == "http://localhost:8000"
        assert client._access_token == "test-token.payload.signature"
        assert client._refresh_token is None
        assert client._auto_refresh is False

    def test_init_with_refresh_token(self):
        """Test client initialization with refresh token."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000/",  # Trailing slash should be removed
            token="test-token.payload.signature",
            refresh_token="refresh-token",
            auto_refresh=True,
        )

        assert client.server_url == "http://localhost:8000"
        assert client._refresh_token == "refresh-token"
        assert client._auto_refresh is True

    def test_init_strips_trailing_slash(self):
        """Test that server URL trailing slash is stripped."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000/",
            token="test-token",
        )

        assert client.server_url == "http://localhost:8000"


class TestCryptoClientEncryptDecrypt:
    """Tests for encrypt/decrypt operations."""

    def test_encrypt_success(self):
        """Test successful encryption."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "ciphertext": base64.b64encode(b"encrypted-data").decode("ascii")
            }
            mock_post.return_value = mock_response

            result = client.encrypt(b"plaintext", "default")

            assert result == b"encrypted-data"
            mock_post.assert_called_once()

    def test_decrypt_success(self):
        """Test successful decryption."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "plaintext": base64.b64encode(b"decrypted-data").decode("ascii")
            }
            mock_post.return_value = mock_response

            result = client.decrypt(b"ciphertext", "default")

            assert result == b"decrypted-data"

    def test_encrypt_with_aad(self):
        """Test encryption with associated data."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "ciphertext": base64.b64encode(b"encrypted").decode("ascii")
            }
            mock_post.return_value = mock_response

            client.encrypt(b"plaintext", "default", associated_data=b"aad")

            # Verify associated_data was included in request
            call_args = mock_post.call_args
            json_data = call_args.kwargs.get("json", call_args[1].get("json"))
            assert "associated_data" in json_data


class TestCryptoClientErrors:
    """Tests for error handling."""

    def test_authentication_error(self):
        """Test authentication error handling."""
        from cryptoserve.client import CryptoClient, AuthenticationError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="invalid-token",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.json.return_value = {"detail": "Invalid token"}
            mock_post.return_value = mock_response

            with pytest.raises(AuthenticationError) as exc_info:
                client.encrypt(b"data", "default")

            assert "Invalid" in str(exc_info.value)

    def test_authorization_error(self):
        """Test authorization error handling."""
        from cryptoserve.client import CryptoClient, AuthorizationError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="valid-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.json.return_value = {"detail": "Not authorized for context"}
            mock_post.return_value = mock_response

            with pytest.raises(AuthorizationError) as exc_info:
                client.encrypt(b"data", "restricted-context")

            assert "restricted-context" in str(exc_info.value)

    def test_context_not_found_error(self):
        """Test context not found error handling."""
        from cryptoserve.client import CryptoClient, ContextNotFoundError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="valid-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {"detail": "Context 'unknown' not found"}
            mock_post.return_value = mock_response

            with pytest.raises(ContextNotFoundError):
                client.encrypt(b"data", "unknown")

    def test_server_error(self):
        """Test server error handling."""
        from cryptoserve.client import CryptoClient, ServerError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="valid-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.json.return_value = {"detail": "Internal server error"}
            mock_post.return_value = mock_response

            with pytest.raises(ServerError):
                client.encrypt(b"data", "default")


class TestCryptoClientTokenRefresh:
    """Tests for token refresh functionality."""

    def test_auto_refresh_on_401(self):
        """Test automatic token refresh on 401 response."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="expired-token.payload.signature",
            refresh_token="valid-refresh-token",
            auto_refresh=True,
        )

        with patch.object(client.session, "post") as mock_session_post:
            with patch("requests.post") as mock_refresh_post:
                # First call returns 401
                first_response = MagicMock()
                first_response.status_code = 401
                first_response.json.return_value = {"detail": "Token expired"}

                # Refresh succeeds
                refresh_response = MagicMock()
                refresh_response.status_code = 200
                refresh_response.json.return_value = {
                    "access_token": "new-token.payload.signature"
                }
                mock_refresh_post.return_value = refresh_response

                # Retry succeeds
                retry_response = MagicMock()
                retry_response.status_code = 200
                retry_response.json.return_value = {
                    "ciphertext": base64.b64encode(b"encrypted").decode("ascii")
                }

                mock_session_post.side_effect = [first_response, retry_response]

                result = client.encrypt(b"data", "default")

                # Verify refresh was called
                mock_refresh_post.assert_called_once()
                assert result == b"encrypted"


class TestCryptoClientHash:
    """Tests for local hash operations."""

    def test_hash_sha256(self):
        """Test SHA-256 hashing."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        result = client.hash(b"hello world")

        # Known SHA-256 hash of "hello world"
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert result == expected

    def test_hash_sha512(self):
        """Test SHA-512 hashing."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        result = client.hash(b"hello world", algorithm="sha512")

        assert len(result) == 128  # SHA-512 produces 64 bytes = 128 hex chars

    def test_hash_sha3_256(self):
        """Test SHA3-256 hashing."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        result = client.hash(b"hello world", algorithm="sha3-256")

        assert len(result) == 64  # SHA3-256 produces 32 bytes = 64 hex chars

    def test_hash_blake2b(self):
        """Test BLAKE2b hashing."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        result = client.hash(b"hello world", algorithm="blake2b")

        assert len(result) == 128  # BLAKE2b default 64 bytes = 128 hex chars

    def test_hash_unsupported_algorithm(self):
        """Test unsupported hash algorithm."""
        from cryptoserve.client import CryptoClient, CryptoServeError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        with pytest.raises(CryptoServeError) as exc_info:
            client.hash(b"data", algorithm="md4")

        assert "Unsupported" in str(exc_info.value)


class TestCryptoClientMAC:
    """Tests for local MAC operations."""

    def test_mac_hmac_sha256(self):
        """Test HMAC-SHA256."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        key = b"secret-key-for-hmac-testing!!!!"
        result = client.mac(b"hello world", key)

        assert len(result) == 64  # HMAC-SHA256 produces 32 bytes = 64 hex chars

    def test_mac_hmac_sha512(self):
        """Test HMAC-SHA512."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        key = b"secret-key-for-hmac-testing!!!!"
        result = client.mac(b"hello world", key, algorithm="hmac-sha512")

        assert len(result) == 128  # HMAC-SHA512 produces 64 bytes = 128 hex chars

    def test_mac_unsupported_algorithm(self):
        """Test unsupported MAC algorithm."""
        from cryptoserve.client import CryptoClient, CryptoServeError

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token",
        )

        with pytest.raises(CryptoServeError) as exc_info:
            client.mac(b"data", b"key", algorithm="hmac-md5")

        assert "Unsupported" in str(exc_info.value)


class TestCryptoClientSignVerify:
    """Tests for sign and verify operations."""

    def test_sign_success(self):
        """Test successful signing."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "signature": base64.b64encode(b"signature-bytes").decode("ascii")
            }
            mock_post.return_value = mock_response

            result = client.sign(b"document", "key-id")

            assert result == b"signature-bytes"

    def test_verify_success(self):
        """Test successful signature verification."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"valid": True}
            mock_post.return_value = mock_response

            result = client.verify(b"document", b"signature", "key-id")

            assert result is True

    def test_verify_invalid_signature(self):
        """Test invalid signature verification."""
        from cryptoserve.client import CryptoClient

        client = CryptoClient(
            server_url="http://localhost:8000",
            token="test-token.payload.signature",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"valid": False}
            mock_post.return_value = mock_response

            result = client.verify(b"document", b"bad-signature", "key-id")

            assert result is False
