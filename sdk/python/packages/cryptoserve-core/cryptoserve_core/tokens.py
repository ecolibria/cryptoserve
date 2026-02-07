"""
Minimal JWT implementation for CryptoServe Core.

Supports HS256 (HMAC-SHA256) only. Uses Python stdlib exclusively.
No pyjwt or other JWT library dependencies.
"""

import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    """Base exception for token operations."""
    pass


class TokenExpiredError(TokenError):
    """Token has expired."""
    pass


class TokenVerificationError(TokenError):
    """Token signature verification failed."""
    pass


class TokenDecodeError(TokenError):
    """Token could not be decoded."""
    pass


# HS256 header (constant - never changes)
_HEADER = {"alg": "HS256", "typ": "JWT"}
_HEADER_B64 = base64.urlsafe_b64encode(
    json.dumps(_HEADER, separators=(",", ":")).encode()
).rstrip(b"=").decode("ascii")

_MIN_KEY_LENGTH = 16  # 128 bits minimum for HS256


def create_token(
    payload: dict,
    key: bytes,
    expires_in: int = 3600,
) -> str:
    """
    Create a JWT token (HS256).

    Automatically adds 'iat' (issued at) and 'exp' (expiry) claims
    if not already present in the payload.

    Args:
        payload: Claims dictionary. Standard claims (sub, iss, aud, etc.)
                 are passed through as-is.
        key: Secret key for HMAC-SHA256 (minimum 16 bytes).
        expires_in: Seconds until expiry (default: 3600 = 1 hour).
                    Set to 0 to skip auto-adding exp.

    Returns:
        JWT string (header.payload.signature).

    Raises:
        TokenError: If key is too short or payload is invalid.
    """
    if len(key) < _MIN_KEY_LENGTH:
        raise TokenError(
            f"Key must be at least {_MIN_KEY_LENGTH} bytes, got {len(key)}"
        )

    # Build payload with auto claims
    claims = dict(payload)
    now = int(time.time())

    if "iat" not in claims:
        claims["iat"] = now

    if "exp" not in claims and expires_in > 0:
        claims["exp"] = now + expires_in

    # Encode payload
    payload_bytes = json.dumps(claims, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")

    # Sign
    signing_input = f"{_HEADER_B64}.{payload_b64}".encode()
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    return f"{_HEADER_B64}.{payload_b64}.{signature_b64}"


def verify_token(
    token: str,
    key: bytes,
    leeway: int = 0,
) -> dict:
    """
    Verify a JWT token and return the payload.

    Checks HMAC-SHA256 signature and expiry (if present).

    Args:
        token: JWT string to verify.
        key: Secret key used to create the token.
        leeway: Seconds of clock skew tolerance for expiry (default: 0).

    Returns:
        Verified payload dictionary.

    Raises:
        TokenVerificationError: If signature is invalid.
        TokenExpiredError: If token has expired.
        TokenDecodeError: If token format is invalid.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenDecodeError(f"Invalid token format: expected 3 parts, got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts

    # Verify header
    try:
        header = json.loads(_b64decode(header_b64))
    except Exception as e:
        raise TokenDecodeError(f"Invalid token header: {e}") from e

    if header.get("alg") != "HS256":
        raise TokenVerificationError(
            f"Unsupported algorithm: {header.get('alg')}. Only HS256 is supported."
        )

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    actual_sig = _b64decode(signature_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise TokenVerificationError("Invalid token signature")

    # Decode payload
    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception as e:
        raise TokenDecodeError(f"Invalid token payload: {e}") from e

    # Check expiry
    if "exp" in payload:
        now = int(time.time())
        if now > payload["exp"] + leeway:
            raise TokenExpiredError("Token has expired")

    return payload


def decode_token(token: str) -> dict:
    """
    Decode a JWT token without verification.

    Useful for inspecting token contents (e.g., checking claims
    before deciding which key to use for verification).

    Args:
        token: JWT string to decode.

    Returns:
        Payload dictionary (unverified).

    Raises:
        TokenDecodeError: If token format is invalid.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenDecodeError(f"Invalid token format: expected 3 parts, got {len(parts)}")

    try:
        payload = json.loads(_b64decode(parts[1]))
    except Exception as e:
        raise TokenDecodeError(f"Invalid token payload: {e}") from e

    return payload


def _b64decode(s: str) -> bytes:
    """Decode URL-safe base64 with padding tolerance."""
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
