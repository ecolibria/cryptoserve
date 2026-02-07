"""Tests for cryptoserve_core JWT tokens module."""

import json
import time

import pytest

from cryptoserve_core.tokens import (
    create_token,
    verify_token,
    decode_token,
    TokenError,
    TokenExpiredError,
    TokenVerificationError,
    TokenDecodeError,
)


# Test key (32 bytes = 256 bits)
TEST_KEY = b"super-secret-key-for-testing!!"  # 30 bytes, > 16 min


class TestCreateToken:
    """Tests for create_token()."""

    def test_basic_create(self):
        """Create a token with basic payload."""
        token = create_token({"user": 1}, TEST_KEY)
        assert isinstance(token, str)
        parts = token.split(".")
        assert len(parts) == 3

    def test_auto_adds_iat(self):
        """iat claim is auto-added."""
        token = create_token({"sub": "test"}, TEST_KEY)
        payload = decode_token(token)
        assert "iat" in payload
        assert abs(payload["iat"] - int(time.time())) <= 2

    def test_auto_adds_exp(self):
        """exp claim is auto-added with default 1 hour."""
        token = create_token({"sub": "test"}, TEST_KEY)
        payload = decode_token(token)
        assert "exp" in payload
        expected = int(time.time()) + 3600
        assert abs(payload["exp"] - expected) <= 2

    def test_custom_expires_in(self):
        """Custom expires_in sets correct exp."""
        token = create_token({"sub": "test"}, TEST_KEY, expires_in=60)
        payload = decode_token(token)
        expected = int(time.time()) + 60
        assert abs(payload["exp"] - expected) <= 2

    def test_no_auto_exp_when_zero(self):
        """expires_in=0 skips auto-adding exp."""
        token = create_token({"sub": "test"}, TEST_KEY, expires_in=0)
        payload = decode_token(token)
        assert "exp" not in payload

    def test_preserves_existing_iat(self):
        """Existing iat is preserved."""
        token = create_token({"iat": 12345}, TEST_KEY)
        payload = decode_token(token)
        assert payload["iat"] == 12345

    def test_preserves_existing_exp(self):
        """Existing exp is preserved."""
        future = int(time.time()) + 9999
        token = create_token({"exp": future}, TEST_KEY)
        payload = decode_token(token)
        assert payload["exp"] == future

    def test_key_too_short(self):
        """Key shorter than 16 bytes raises TokenError."""
        with pytest.raises(TokenError, match="at least 16 bytes"):
            create_token({"sub": "test"}, b"short")

    def test_payload_passed_through(self):
        """All payload claims are preserved."""
        payload = {"sub": "user-42", "role": "admin", "custom": [1, 2, 3]}
        token = create_token(payload, TEST_KEY)
        decoded = decode_token(token)
        assert decoded["sub"] == "user-42"
        assert decoded["role"] == "admin"
        assert decoded["custom"] == [1, 2, 3]


class TestVerifyToken:
    """Tests for verify_token()."""

    def test_valid_token(self):
        """Valid token verifies and returns payload."""
        token = create_token({"user": 1}, TEST_KEY)
        payload = verify_token(token, TEST_KEY)
        assert payload["user"] == 1

    def test_wrong_key(self):
        """Wrong key raises TokenVerificationError."""
        token = create_token({"user": 1}, TEST_KEY)
        with pytest.raises(TokenVerificationError, match="Invalid token signature"):
            verify_token(token, b"different-key-not-same!!!")

    def test_expired_token(self):
        """Expired token raises TokenExpiredError."""
        token = create_token({"user": 1}, TEST_KEY, expires_in=1)
        # Manually create an already-expired token
        expired_token = create_token(
            {"user": 1, "exp": int(time.time()) - 10},
            TEST_KEY,
        )
        with pytest.raises(TokenExpiredError, match="expired"):
            verify_token(expired_token, TEST_KEY)

    def test_expired_with_leeway(self):
        """Leeway allows recently expired tokens."""
        expired_token = create_token(
            {"user": 1, "exp": int(time.time()) - 5},
            TEST_KEY,
        )
        # Without leeway: should fail
        with pytest.raises(TokenExpiredError):
            verify_token(expired_token, TEST_KEY)
        # With leeway: should succeed
        payload = verify_token(expired_token, TEST_KEY, leeway=10)
        assert payload["user"] == 1

    def test_malformed_token(self):
        """Malformed token raises TokenDecodeError."""
        with pytest.raises(TokenDecodeError, match="expected 3 parts"):
            verify_token("not.a.valid.token.at.all", TEST_KEY)

        with pytest.raises(TokenDecodeError, match="expected 3 parts"):
            verify_token("only-one-part", TEST_KEY)

    def test_tampered_payload(self):
        """Tampered payload is detected."""
        import base64

        token = create_token({"user": 1, "role": "user"}, TEST_KEY)
        header_b64, payload_b64, sig_b64 = token.split(".")

        # Tamper with payload
        tampered = {"user": 1, "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}
        tampered_b64 = base64.urlsafe_b64encode(
            json.dumps(tampered, separators=(",", ":")).encode()
        ).rstrip(b"=").decode("ascii")

        tampered_token = f"{header_b64}.{tampered_b64}.{sig_b64}"
        with pytest.raises(TokenVerificationError, match="Invalid token signature"):
            verify_token(tampered_token, TEST_KEY)

    def test_no_exp_token_verifies(self):
        """Token without exp claim verifies successfully."""
        token = create_token({"user": 1}, TEST_KEY, expires_in=0)
        payload = verify_token(token, TEST_KEY)
        assert payload["user"] == 1
        assert "exp" not in payload


class TestDecodeToken:
    """Tests for decode_token()."""

    def test_decode_without_verification(self):
        """Decode returns payload without checking signature."""
        token = create_token({"user": 1, "data": "test"}, TEST_KEY)
        payload = decode_token(token)
        assert payload["user"] == 1
        assert payload["data"] == "test"

    def test_decode_with_wrong_key_still_works(self):
        """Decode works even if we don't have the right key."""
        token = create_token({"secret": "value"}, TEST_KEY)
        payload = decode_token(token)
        assert payload["secret"] == "value"

    def test_decode_malformed(self):
        """Malformed token raises TokenDecodeError."""
        with pytest.raises(TokenDecodeError):
            decode_token("not-a-token")

    def test_decode_invalid_base64_payload(self):
        """Invalid base64 in payload raises TokenDecodeError."""
        with pytest.raises(TokenDecodeError):
            decode_token("header.!!!invalid!!!.signature")
