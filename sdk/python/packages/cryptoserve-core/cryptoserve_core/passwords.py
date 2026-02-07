"""
Password hashing and strength checking for CryptoServe Core.

Uses stdlib hashlib.scrypt and hashlib.pbkdf2_hmac.
No additional dependencies beyond Python stdlib.

Hash format follows PHC (Password Hashing Competition) string format:
    $algorithm$params$salt_b64$hash_b64
"""

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field


class PasswordHashError(Exception):
    """Exception for password hashing operations."""
    pass


# Scrypt defaults (N=2^14 is the standard interactive login recommendation)
_SCRYPT_N = 2**14  # 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT_SIZE = 16

# PBKDF2 defaults
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_DKLEN = 32
_PBKDF2_SALT_SIZE = 16

# Common weak passwords (subset for basic detection)
_COMMON_PASSWORDS = frozenset({
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "master", "iloveyou", "admin", "welcome",
    "login", "princess", "passw0rd", "shadow", "123456789",
    "password1", "password123",
})

# Common keyboard patterns
_KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1234", "abcd",
]


def hash_password(password: str, algorithm: str = "scrypt") -> str:
    """
    Hash a password using a secure algorithm.

    Args:
        password: Password to hash.
        algorithm: Algorithm to use ("scrypt" or "pbkdf2").

    Returns:
        PHC-format hash string (safe for database storage).

    Raises:
        PasswordHashError: If hashing fails.
        ValueError: If algorithm is unsupported.
    """
    if algorithm == "scrypt":
        return _hash_scrypt(password)
    elif algorithm == "pbkdf2":
        return _hash_pbkdf2(password)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'scrypt' or 'pbkdf2'.")


def verify_password(password: str, hash_string: str) -> bool:
    """
    Verify a password against a PHC-format hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        password: Password to verify.
        hash_string: PHC-format hash from hash_password().

    Returns:
        True if password matches, False otherwise.

    Raises:
        PasswordHashError: If hash format is invalid.
    """
    if hash_string.startswith("$scrypt$"):
        return _verify_scrypt(password, hash_string)
    elif hash_string.startswith("$pbkdf2-sha256$"):
        return _verify_pbkdf2(password, hash_string)
    else:
        raise PasswordHashError(
            f"Unrecognized hash format. Expected $scrypt$ or $pbkdf2-sha256$ prefix."
        )


@dataclass
class PasswordStrength:
    """Result of password strength analysis."""
    score: int  # 0-4
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    feedback: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Human-readable strength label."""
        labels = {
            0: "very weak",
            1: "weak",
            2: "fair",
            3: "strong",
            4: "very strong",
        }
        return labels.get(self.score, "unknown")


def check_strength(password: str) -> PasswordStrength:
    """
    Analyze password strength.

    Scores from 0 (very weak) to 4 (very strong) based on:
    - Length (8+ chars recommended, 12+ ideal)
    - Character diversity (upper, lower, digit, special)
    - Common password detection
    - Keyboard pattern detection

    Args:
        password: Password to analyze.

    Returns:
        PasswordStrength with score, details, and feedback.
    """
    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    score = 0
    feedback = []

    # Empty or trivial
    if length == 0:
        return PasswordStrength(
            score=0, length=0,
            has_upper=False, has_lower=False,
            has_digit=False, has_special=False,
            feedback=["Password is empty."],
        )

    # Common password check
    if password.lower() in _COMMON_PASSWORDS:
        return PasswordStrength(
            score=0, length=length,
            has_upper=has_upper, has_lower=has_lower,
            has_digit=has_digit, has_special=has_special,
            feedback=["This is a commonly used password."],
        )

    # Keyboard pattern check
    lower_pw = password.lower()
    for pattern in _KEYBOARD_PATTERNS:
        if pattern in lower_pw:
            feedback.append(f"Contains keyboard pattern '{pattern}'.")
            break

    # Length scoring
    if length < 8:
        feedback.append("Use at least 8 characters.")
    elif length < 12:
        score += 1
        feedback.append("Consider using 12+ characters.")
    else:
        score += 2

    # Character diversity
    diversity = sum([has_upper, has_lower, has_digit, has_special])
    if diversity <= 1:
        feedback.append("Add uppercase, digits, or special characters.")
    elif diversity == 2:
        score += 1
    elif diversity >= 3:
        score += 2

    # Cap at 4
    score = min(score, 4)

    if not feedback:
        feedback.append("Password meets strength requirements.")

    return PasswordStrength(
        score=score,
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        feedback=feedback,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64encode_nopad(data: bytes) -> str:
    """Base64 encode without padding (PHC convention)."""
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode_nopad(s: str) -> bytes:
    """Base64 decode with missing padding tolerance."""
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _hash_scrypt(password: str) -> str:
    """Hash with scrypt, return PHC format."""
    salt = os.urandom(_SCRYPT_SALT_SIZE)
    try:
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
        )
    except Exception as e:
        raise PasswordHashError(f"scrypt hashing failed: {e}") from e

    salt_b64 = _b64encode_nopad(salt)
    hash_b64 = _b64encode_nopad(dk)
    return f"$scrypt$n={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}${salt_b64}${hash_b64}"


def _verify_scrypt(password: str, hash_string: str) -> bool:
    """Verify password against scrypt PHC hash."""
    # Parse: $scrypt$n=131072,r=8,p=1$<salt>$<hash>
    parts = hash_string.split("$")
    if len(parts) != 5 or parts[1] != "scrypt":
        raise PasswordHashError("Invalid scrypt hash format")

    params_str = parts[2]
    salt_b64 = parts[3]
    hash_b64 = parts[4]

    # Parse params
    params = {}
    for param in params_str.split(","):
        k, v = param.split("=")
        params[k] = int(v)

    salt = _b64decode_nopad(salt_b64)
    expected = _b64decode_nopad(hash_b64)

    try:
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=params["n"],
            r=params["r"],
            p=params["p"],
            dklen=len(expected),
        )
    except Exception as e:
        raise PasswordHashError(f"scrypt verification failed: {e}") from e

    return hmac.compare_digest(dk, expected)


def _hash_pbkdf2(password: str) -> str:
    """Hash with PBKDF2-SHA256, return PHC format."""
    salt = os.urandom(_PBKDF2_SALT_SIZE)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_PBKDF2_DKLEN,
    )
    salt_b64 = _b64encode_nopad(salt)
    hash_b64 = _b64encode_nopad(dk)
    return f"$pbkdf2-sha256$i={_PBKDF2_ITERATIONS}${salt_b64}${hash_b64}"


def _verify_pbkdf2(password: str, hash_string: str) -> bool:
    """Verify password against PBKDF2 PHC hash."""
    # Parse: $pbkdf2-sha256$i=600000$<salt>$<hash>
    parts = hash_string.split("$")
    if len(parts) != 5 or parts[1] != "pbkdf2-sha256":
        raise PasswordHashError("Invalid PBKDF2 hash format")

    params_str = parts[2]
    salt_b64 = parts[3]
    hash_b64 = parts[4]

    # Parse iterations
    if not params_str.startswith("i="):
        raise PasswordHashError("Invalid PBKDF2 params: missing iterations")
    iterations = int(params_str[2:])

    salt = _b64decode_nopad(salt_b64)
    expected = _b64decode_nopad(hash_b64)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(dk, expected)
