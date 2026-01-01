"""Ed25519-based token management with refresh support.

This module provides production-grade token management:
- Ed25519 asymmetric signing for access tokens (per-application keypairs)
- Short-lived access tokens (1 hour) with auto-refresh support
- Long-lived refresh tokens (30 days) stored as hashes
- Immediate revocation capability
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings

settings = get_settings()


# Token lifetimes
ACCESS_TOKEN_LIFETIME_SECONDS = 3600  # 1 hour
REFRESH_TOKEN_LIFETIME_DAYS = 30


class TokenManager:
    """Ed25519-based token management with refresh support."""

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate Ed25519 keypair for new application.

        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def encrypt_private_key(self, private_key_pem: bytes) -> str:
        """Encrypt private key for storage using master key.

        Uses AES-256-GCM via Fernet-like approach with master key derivation.
        For simplicity, we use base64 encoding with HMAC for now.
        In production, use proper envelope encryption with KMS.
        """
        from cryptography.fernet import Fernet
        import base64

        # Derive Fernet key from master key (must be 32 bytes, base64-encoded)
        key_bytes = hashlib.sha256(settings.cryptoserve_master_key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)

        fernet = Fernet(fernet_key)
        encrypted = fernet.encrypt(private_key_pem)

        return encrypted.decode('utf-8')

    def decrypt_private_key(self, encrypted_key: str) -> bytes:
        """Decrypt private key from storage."""
        from cryptography.fernet import Fernet
        import base64

        key_bytes = hashlib.sha256(settings.cryptoserve_master_key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)

        fernet = Fernet(fernet_key)
        decrypted = fernet.decrypt(encrypted_key.encode('utf-8'))

        return decrypted

    def create_access_token(
        self,
        app_id: str,
        app_name: str,
        team: str,
        environment: str,
        contexts: list[str],
        private_key_pem: bytes,
    ) -> tuple[str, datetime]:
        """Create short-lived access token (1 hour), Ed25519 signed.

        Args:
            app_id: Application ID (e.g., "app_backend_abc123")
            app_name: Human-readable name
            team: Team name
            environment: Environment (production, staging, development)
            contexts: Allowed encryption contexts
            private_key_pem: PEM-encoded Ed25519 private key

        Returns:
            Tuple of (token_string, expiry_datetime)
        """
        now = int(time.time())
        expires_at = datetime.fromtimestamp(now + ACCESS_TOKEN_LIFETIME_SECONDS, tz=timezone.utc)

        payload = {
            "iss": "cryptoserve",
            "sub": app_id,
            "aud": "cryptoserve-api",
            "iat": now,
            "exp": now + ACCESS_TOKEN_LIFETIME_SECONDS,
            "type": "access",
            "name": app_name,
            "team": team,
            "env": environment,
            "contexts": contexts,
        }

        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )

        token = jwt.encode(
            payload,
            private_key,
            algorithm="EdDSA",
        )

        return token, expires_at

    def verify_access_token(self, token: str, public_key_pem: bytes) -> dict | None:
        """Verify Ed25519 signature and claims.

        Args:
            token: JWT token string
            public_key_pem: PEM-encoded Ed25519 public key

        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                audience="cryptoserve-api",
            )

            # Verify it's an access token
            if payload.get("type") != "access":
                return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def create_refresh_token(self, app_id: str) -> tuple[str, str, datetime]:
        """Create long-lived refresh token (30 days).

        The refresh token is signed with the master key (HS256) since it needs
        to be verified without looking up the application first.

        Args:
            app_id: Application ID

        Returns:
            Tuple of (token_string, token_hash, expiry_datetime)
        """
        now = int(time.time())
        expires_at = datetime.fromtimestamp(
            now + (REFRESH_TOKEN_LIFETIME_DAYS * 24 * 3600),
            tz=timezone.utc
        )

        # Generate unique token ID for revocation
        jti = secrets.token_urlsafe(32)

        payload = {
            "iss": "cryptoserve",
            "sub": app_id,
            "aud": "cryptoserve-refresh",
            "iat": now,
            "exp": now + (REFRESH_TOKEN_LIFETIME_DAYS * 24 * 3600),
            "type": "refresh",
            "jti": jti,
        }

        token = jwt.encode(
            payload,
            settings.cryptoserve_master_key,
            algorithm="HS256",
        )

        # Store hash for verification (not the token itself)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        return token, token_hash, expires_at

    def verify_refresh_token(self, token: str, stored_hash: str) -> dict | None:
        """Verify refresh token against stored hash.

        Args:
            token: Refresh token string
            stored_hash: SHA-256 hash stored in database

        Returns:
            Decoded payload if valid, None otherwise
        """
        # First verify the hash matches
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if not secrets.compare_digest(token_hash, stored_hash):
            return None

        try:
            payload = jwt.decode(
                token,
                settings.cryptoserve_master_key,
                algorithms=["HS256"],
                audience="cryptoserve-refresh",
            )

            # Verify it's a refresh token
            if payload.get("type") != "refresh":
                return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def decode_token_unverified(self, token: str) -> dict | None:
        """Decode token without verification to extract app_id.

        Used to look up the public key before verification.
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None

    def hash_token(self, token: str) -> str:
        """Generate SHA-256 hash of token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()


# Singleton instance
token_manager = TokenManager()
