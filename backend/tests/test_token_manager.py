"""Tests for the Ed25519 token manager.

Tests cover:
- Ed25519 keypair generation
- Private key encryption/decryption
- Access token creation and verification
- Refresh token creation and verification
- Token decoding (unverified)
- Token hashing
"""

import time
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app.core.token_manager import (
    TokenManager,
    token_manager,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    REFRESH_TOKEN_LIFETIME_DAYS,
)


class TestKeypairGeneration:
    """Tests for Ed25519 keypair generation."""

    def test_generate_keypair_returns_pem_format(self):
        """Test that keypairs are returned in PEM format."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_generate_keypair_returns_valid_keys(self):
        """Test that generated keys can be loaded."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        # Should load without error
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)

        assert private_key is not None
        assert public_key is not None

    def test_generate_keypair_creates_unique_keys(self):
        """Test that each call generates unique keys."""
        tm = TokenManager()

        private1, public1 = tm.generate_keypair()
        private2, public2 = tm.generate_keypair()

        assert private1 != private2
        assert public1 != public2


class TestPrivateKeyEncryption:
    """Tests for private key encryption/decryption."""

    def test_encrypt_decrypt_private_key(self):
        """Test encrypting and decrypting private key."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        encrypted = tm.encrypt_private_key(private_pem)
        decrypted = tm.decrypt_private_key(encrypted)

        assert decrypted == private_pem

    def test_encrypted_key_is_different_from_original(self):
        """Test that encrypted key differs from original."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        encrypted = tm.encrypt_private_key(private_pem)

        assert encrypted != private_pem.decode('utf-8')
        assert encrypted != private_pem

    def test_encrypted_key_is_base64_string(self):
        """Test that encrypted key is a string (base64-like)."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        encrypted = tm.encrypt_private_key(private_pem)

        assert isinstance(encrypted, str)
        # Fernet tokens are base64-encoded
        assert len(encrypted) > 100


class TestAccessToken:
    """Tests for Ed25519-signed access tokens."""

    def test_create_access_token(self):
        """Test creating an access token."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        token, expires_at = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=["user-pii", "session-tokens"],
            private_key_pem=private_pem,
        )

        assert token is not None
        assert "." in token  # JWT format
        assert expires_at > datetime.now(timezone.utc)

    def test_access_token_contains_claims(self):
        """Test that access token contains expected claims."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="production",
            contexts=["user-pii"],
            private_key_pem=private_pem,
        )

        # Decode without verification to check claims
        payload = jwt.decode(token, options={"verify_signature": False})

        assert payload["sub"] == "app_test_123"
        assert payload["name"] == "Test App"
        assert payload["team"] == "backend"
        assert payload["env"] == "production"
        assert payload["contexts"] == ["user-pii"]
        assert payload["type"] == "access"
        assert payload["iss"] == "cryptoserve"
        assert payload["aud"] == "cryptoserve-api"

    def test_access_token_expires_in_1_hour(self):
        """Test that access token expires in approximately 1 hour."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        token, expires_at = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=[],
            private_key_pem=private_pem,
        )

        now = datetime.now(timezone.utc)
        delta = (expires_at - now).total_seconds()

        # Should be approximately ACCESS_TOKEN_LIFETIME_SECONDS
        assert ACCESS_TOKEN_LIFETIME_SECONDS - 5 <= delta <= ACCESS_TOKEN_LIFETIME_SECONDS + 5

    def test_verify_access_token_valid(self):
        """Test verifying a valid access token."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=["user-pii"],
            private_key_pem=private_pem,
        )

        payload = tm.verify_access_token(token, public_pem)

        assert payload is not None
        assert payload["sub"] == "app_test_123"
        assert payload["type"] == "access"

    def test_verify_access_token_wrong_key(self):
        """Test that verification fails with wrong public key."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()
        _, wrong_public = tm.generate_keypair()  # Different key

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=[],
            private_key_pem=private_pem,
        )

        payload = tm.verify_access_token(token, wrong_public)

        assert payload is None

    def test_verify_access_token_tampered(self):
        """Test that verification fails for tampered token."""
        tm = TokenManager()
        private_pem, public_pem = tm.generate_keypair()

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=[],
            private_key_pem=private_pem,
        )

        # Tamper with the token
        parts = token.split(".")
        parts[1] = parts[1][:-4] + "XXXX"  # Modify payload
        tampered = ".".join(parts)

        payload = tm.verify_access_token(tampered, public_pem)

        assert payload is None


class TestRefreshToken:
    """Tests for refresh tokens."""

    def test_create_refresh_token(self):
        """Test creating a refresh token."""
        tm = TokenManager()

        token, token_hash, expires_at = tm.create_refresh_token("app_test_123")

        assert token is not None
        assert "." in token  # JWT format
        assert len(token_hash) == 64  # SHA-256 hex
        assert expires_at > datetime.now(timezone.utc)

    def test_refresh_token_contains_claims(self):
        """Test that refresh token contains expected claims."""
        tm = TokenManager()

        token, _, _ = tm.create_refresh_token("app_test_123")

        # Decode without verification to check claims
        payload = jwt.decode(token, options={"verify_signature": False})

        assert payload["sub"] == "app_test_123"
        assert payload["type"] == "refresh"
        assert payload["iss"] == "cryptoserve"
        assert payload["aud"] == "cryptoserve-refresh"
        assert "jti" in payload  # Unique token ID

    def test_refresh_token_expires_in_30_days(self):
        """Test that refresh token expires in approximately 30 days."""
        tm = TokenManager()

        _, _, expires_at = tm.create_refresh_token("app_test_123")

        now = datetime.now(timezone.utc)
        delta = (expires_at - now).total_seconds()
        expected = REFRESH_TOKEN_LIFETIME_DAYS * 24 * 3600

        # Should be approximately 30 days
        assert expected - 60 <= delta <= expected + 60

    def test_refresh_token_hash_is_unique(self):
        """Test that each refresh token has unique hash."""
        tm = TokenManager()

        _, hash1, _ = tm.create_refresh_token("app_test_123")
        _, hash2, _ = tm.create_refresh_token("app_test_123")

        assert hash1 != hash2

    def test_verify_refresh_token_valid(self):
        """Test verifying a valid refresh token."""
        tm = TokenManager()

        token, token_hash, _ = tm.create_refresh_token("app_test_123")

        payload = tm.verify_refresh_token(token, token_hash)

        assert payload is not None
        assert payload["sub"] == "app_test_123"
        assert payload["type"] == "refresh"

    def test_verify_refresh_token_wrong_hash(self):
        """Test that verification fails with wrong hash."""
        tm = TokenManager()

        token, _, _ = tm.create_refresh_token("app_test_123")
        wrong_hash = "a" * 64  # Wrong hash

        payload = tm.verify_refresh_token(token, wrong_hash)

        assert payload is None

    def test_verify_refresh_token_rotated(self):
        """Test that old token fails after rotation."""
        tm = TokenManager()

        # Create first token
        old_token, old_hash, _ = tm.create_refresh_token("app_test_123")

        # "Rotate" by creating new token (simulates DB update)
        _, new_hash, _ = tm.create_refresh_token("app_test_123")

        # Old token should fail with new hash
        payload = tm.verify_refresh_token(old_token, new_hash)

        assert payload is None


class TestTokenUtilities:
    """Tests for token utility functions."""

    def test_decode_token_unverified(self):
        """Test decoding token without verification."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=["user-pii"],
            private_key_pem=private_pem,
        )

        payload = tm.decode_token_unverified(token)

        assert payload is not None
        assert payload["sub"] == "app_test_123"

    def test_decode_token_unverified_invalid(self):
        """Test decoding invalid token returns None."""
        tm = TokenManager()

        payload = tm.decode_token_unverified("not-a-valid-token")

        assert payload is None

    def test_hash_token(self):
        """Test token hashing."""
        tm = TokenManager()

        hash1 = tm.hash_token("token123")
        hash2 = tm.hash_token("token123")
        hash3 = tm.hash_token("token456")

        assert len(hash1) == 64  # SHA-256 hex
        assert hash1 == hash2  # Same token = same hash
        assert hash1 != hash3  # Different token = different hash


class TestSingletonInstance:
    """Tests for singleton token_manager instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert token_manager is not None

    def test_singleton_is_token_manager(self):
        """Test that singleton is a TokenManager instance."""
        assert isinstance(token_manager, TokenManager)

    def test_singleton_generates_keys(self):
        """Test that singleton can generate keys."""
        private_pem, public_pem = token_manager.generate_keypair()

        assert private_pem is not None
        assert public_pem is not None


class TestEdDSAAlgorithm:
    """Tests to verify Ed25519/EdDSA algorithm is used correctly."""

    def test_access_token_uses_eddsa(self):
        """Test that access token uses EdDSA algorithm."""
        tm = TokenManager()
        private_pem, _ = tm.generate_keypair()

        token, _ = tm.create_access_token(
            app_id="app_test_123",
            app_name="Test App",
            team="backend",
            environment="development",
            contexts=[],
            private_key_pem=private_pem,
        )

        # Check header for algorithm
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "EdDSA"

    def test_refresh_token_uses_hs256(self):
        """Test that refresh token uses HS256 algorithm."""
        tm = TokenManager()

        token, _, _ = tm.create_refresh_token("app_test_123")

        # Check header for algorithm
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256"
