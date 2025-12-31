"""Password Hashing Engine.

Provides secure password hashing with modern algorithms:
- Argon2id: Recommended for new applications (memory-hard)
- bcrypt: Widely deployed, proven security
- scrypt: Memory-hard, IETF standard
- PBKDF2-SHA256: FIPS-compliant, legacy support

Default parameters follow OWASP 2024 recommendations.
"""

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# Argon2 support via argon2-cffi
try:
    import argon2
    from argon2 import PasswordHasher, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# bcrypt support
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

# cryptography for PBKDF2 and scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes


class PasswordAlgorithm(str, Enum):
    """Supported password hashing algorithms."""
    ARGON2ID = "argon2id"  # Recommended
    ARGON2I = "argon2i"  # For side-channel resistance
    ARGON2D = "argon2d"  # For GPU resistance
    BCRYPT = "bcrypt"  # Widely deployed
    SCRYPT = "scrypt"  # Memory-hard
    PBKDF2_SHA256 = "pbkdf2-sha256"  # FIPS compliant


@dataclass
class Argon2Params:
    """Argon2 parameters (OWASP 2024 recommendations)."""
    time_cost: int = 3  # Iterations
    memory_cost: int = 65536  # 64 MiB in KiB
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16
    type: str = "id"  # argon2id


@dataclass
class BcryptParams:
    """bcrypt parameters."""
    rounds: int = 12  # 2^12 iterations


@dataclass
class ScryptParams:
    """scrypt parameters (OWASP recommendations)."""
    n: int = 2**17  # CPU/memory cost (128 MiB)
    r: int = 8  # Block size
    p: int = 1  # Parallelism
    key_length: int = 32
    salt_length: int = 16


@dataclass
class PBKDF2Params:
    """PBKDF2 parameters (OWASP 2024)."""
    iterations: int = 600_000  # For SHA-256
    hash_algorithm: str = "sha256"
    key_length: int = 32
    salt_length: int = 16


@dataclass
class PasswordHashResult:
    """Result of password hashing."""
    hash: str  # PHC string format or algorithm-specific
    algorithm: PasswordAlgorithm
    params: dict
    created_at: datetime


@dataclass
class PasswordVerifyResult:
    """Result of password verification."""
    valid: bool
    needs_rehash: bool  # True if params are outdated
    algorithm: PasswordAlgorithm


class PasswordHashError(Exception):
    """Password hashing failed."""
    pass


class PasswordVerifyError(Exception):
    """Password verification failed."""
    pass


class UnsupportedAlgorithmError(Exception):
    """Algorithm not available."""
    pass


class PasswordEngine:
    """Handles password hashing and verification."""

    # Default parameters per algorithm
    DEFAULT_PARAMS = {
        PasswordAlgorithm.ARGON2ID: Argon2Params(),
        PasswordAlgorithm.ARGON2I: Argon2Params(type="i"),
        PasswordAlgorithm.ARGON2D: Argon2Params(type="d"),
        PasswordAlgorithm.BCRYPT: BcryptParams(),
        PasswordAlgorithm.SCRYPT: ScryptParams(),
        PasswordAlgorithm.PBKDF2_SHA256: PBKDF2Params(),
    }

    def hash_password(
        self,
        password: str,
        algorithm: PasswordAlgorithm = PasswordAlgorithm.ARGON2ID,
        params: Argon2Params | BcryptParams | ScryptParams | PBKDF2Params | None = None,
    ) -> PasswordHashResult:
        """Hash a password using the specified algorithm.

        Args:
            password: The password to hash
            algorithm: Hashing algorithm to use
            params: Custom parameters (uses defaults if None)

        Returns:
            PasswordHashResult with hash string
        """
        if params is None:
            params = self.DEFAULT_PARAMS[algorithm]

        if algorithm in [PasswordAlgorithm.ARGON2ID, PasswordAlgorithm.ARGON2I, PasswordAlgorithm.ARGON2D]:
            hash_str = self._hash_argon2(password, params)
        elif algorithm == PasswordAlgorithm.BCRYPT:
            hash_str = self._hash_bcrypt(password, params)
        elif algorithm == PasswordAlgorithm.SCRYPT:
            hash_str = self._hash_scrypt(password, params)
        elif algorithm == PasswordAlgorithm.PBKDF2_SHA256:
            hash_str = self._hash_pbkdf2(password, params)
        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

        return PasswordHashResult(
            hash=hash_str,
            algorithm=algorithm,
            params=self._params_to_dict(params),
            created_at=datetime.now(timezone.utc),
        )

    def verify_password(
        self,
        password: str,
        hash_string: str,
        algorithm: PasswordAlgorithm | None = None,
    ) -> PasswordVerifyResult:
        """Verify a password against a hash.

        Args:
            password: The password to verify
            hash_string: The hash to verify against
            algorithm: Algorithm hint (auto-detected if None)

        Returns:
            PasswordVerifyResult with validity and rehash recommendation
        """
        # Auto-detect algorithm from hash format
        if algorithm is None:
            algorithm = self._detect_algorithm(hash_string)

        if algorithm in [PasswordAlgorithm.ARGON2ID, PasswordAlgorithm.ARGON2I, PasswordAlgorithm.ARGON2D]:
            valid, needs_rehash = self._verify_argon2(password, hash_string)
        elif algorithm == PasswordAlgorithm.BCRYPT:
            valid, needs_rehash = self._verify_bcrypt(password, hash_string)
        elif algorithm == PasswordAlgorithm.SCRYPT:
            valid, needs_rehash = self._verify_scrypt(password, hash_string)
        elif algorithm == PasswordAlgorithm.PBKDF2_SHA256:
            valid, needs_rehash = self._verify_pbkdf2(password, hash_string)
        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

        return PasswordVerifyResult(
            valid=valid,
            needs_rehash=needs_rehash,
            algorithm=algorithm,
        )

    def check_strength(self, password: str) -> dict:
        """Check password strength.

        Returns:
            Dictionary with strength assessment
        """
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        char_sets = sum([has_lower, has_upper, has_digit, has_special])

        # Calculate entropy estimate
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        import math
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        # Score: 0-100
        score = min(100, int(
            (min(length, 16) / 16) * 40 +  # Length (up to 40 points)
            (char_sets / 4) * 30 +  # Character diversity (up to 30 points)
            (min(entropy, 60) / 60) * 30  # Entropy (up to 30 points)
        ))

        if score >= 80:
            strength = "strong"
        elif score >= 60:
            strength = "good"
        elif score >= 40:
            strength = "fair"
        else:
            strength = "weak"

        return {
            "score": score,
            "strength": strength,
            "entropy_bits": round(entropy, 1),
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special": has_special,
            "recommendations": self._get_recommendations(
                length, has_lower, has_upper, has_digit, has_special
            ),
        }

    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_special: bool = True,
        exclude_ambiguous: bool = True,
    ) -> str:
        """Generate a secure random password.

        Args:
            length: Password length (minimum 8)
            include_uppercase: Include A-Z
            include_lowercase: Include a-z
            include_digits: Include 0-9
            include_special: Include special characters
            exclude_ambiguous: Exclude ambiguous chars (0O, 1lI, etc.)

        Returns:
            Generated password
        """
        if length < 8:
            raise ValueError("Password length must be at least 8")

        charset = ""
        required = []

        if include_lowercase:
            chars = "abcdefghjkmnpqrstuvwxyz" if exclude_ambiguous else "abcdefghijklmnopqrstuvwxyz"
            charset += chars
            required.append(secrets.choice(chars))

        if include_uppercase:
            chars = "ABCDEFGHJKMNPQRSTUVWXYZ" if exclude_ambiguous else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            charset += chars
            required.append(secrets.choice(chars))

        if include_digits:
            chars = "23456789" if exclude_ambiguous else "0123456789"
            charset += chars
            required.append(secrets.choice(chars))

        if include_special:
            chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            charset += chars
            required.append(secrets.choice(chars))

        if not charset:
            raise ValueError("At least one character set must be included")

        # Fill remaining length
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]

        # Shuffle
        password_list = list(password_chars)
        secrets.SystemRandom().shuffle(password_list)

        return "".join(password_list)

    # ==================== Algorithm Implementations ====================

    def _hash_argon2(self, password: str, params: Argon2Params) -> str:
        """Hash with Argon2."""
        if not ARGON2_AVAILABLE:
            raise UnsupportedAlgorithmError(
                "argon2-cffi is not installed. Install with: pip install argon2-cffi"
            )

        type_map = {
            "id": Type.ID,
            "i": Type.I,
            "d": Type.D,
        }

        hasher = PasswordHasher(
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            salt_len=params.salt_len,
            type=type_map.get(params.type, Type.ID),
        )

        return hasher.hash(password)

    def _verify_argon2(self, password: str, hash_string: str) -> tuple[bool, bool]:
        """Verify Argon2 hash."""
        if not ARGON2_AVAILABLE:
            raise UnsupportedAlgorithmError("argon2-cffi is not installed")

        hasher = PasswordHasher(
            time_cost=self.DEFAULT_PARAMS[PasswordAlgorithm.ARGON2ID].time_cost,
            memory_cost=self.DEFAULT_PARAMS[PasswordAlgorithm.ARGON2ID].memory_cost,
            parallelism=self.DEFAULT_PARAMS[PasswordAlgorithm.ARGON2ID].parallelism,
        )

        try:
            hasher.verify(hash_string, password)
            needs_rehash = hasher.check_needs_rehash(hash_string)
            return True, needs_rehash
        except argon2.exceptions.VerifyMismatchError:
            return False, False
        except argon2.exceptions.InvalidHash:
            raise PasswordVerifyError("Invalid Argon2 hash format")

    def _hash_bcrypt(self, password: str, params: BcryptParams) -> str:
        """Hash with bcrypt."""
        if not BCRYPT_AVAILABLE:
            raise UnsupportedAlgorithmError(
                "bcrypt is not installed. Install with: pip install bcrypt"
            )

        salt = bcrypt.gensalt(rounds=params.rounds)
        hash_bytes = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hash_bytes.decode("utf-8")

    def _verify_bcrypt(self, password: str, hash_string: str) -> tuple[bool, bool]:
        """Verify bcrypt hash."""
        if not BCRYPT_AVAILABLE:
            raise UnsupportedAlgorithmError("bcrypt is not installed")

        try:
            valid = bcrypt.checkpw(password.encode("utf-8"), hash_string.encode("utf-8"))

            # Check if rounds are outdated
            # bcrypt format: $2b$rounds$salt+hash
            parts = hash_string.split("$")
            if len(parts) >= 3:
                rounds = int(parts[2])
                needs_rehash = rounds < self.DEFAULT_PARAMS[PasswordAlgorithm.BCRYPT].rounds
            else:
                needs_rehash = False

            return valid, needs_rehash
        except Exception as e:
            raise PasswordVerifyError(f"bcrypt verification failed: {e}")

    def _hash_scrypt(self, password: str, params: ScryptParams) -> str:
        """Hash with scrypt.

        Output format: $scrypt$n=N,r=R,p=P$salt$hash
        """
        salt = os.urandom(params.salt_length)

        kdf = Scrypt(
            salt=salt,
            length=params.key_length,
            n=params.n,
            r=params.r,
            p=params.p,
        )

        key = kdf.derive(password.encode("utf-8"))

        # PHC-like format
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(key).decode("ascii")

        return f"$scrypt$n={params.n},r={params.r},p={params.p}${salt_b64}${hash_b64}"

    def _verify_scrypt(self, password: str, hash_string: str) -> tuple[bool, bool]:
        """Verify scrypt hash."""
        try:
            # Parse format: $scrypt$n=N,r=R,p=P$salt$hash
            parts = hash_string.split("$")
            if len(parts) != 5 or parts[1] != "scrypt":
                raise PasswordVerifyError("Invalid scrypt hash format")

            # Parse parameters
            param_str = parts[2]
            params = {}
            for p in param_str.split(","):
                k, v = p.split("=")
                params[k] = int(v)

            salt = base64.b64decode(parts[3])
            expected_hash = base64.b64decode(parts[4])

            kdf = Scrypt(
                salt=salt,
                length=len(expected_hash),
                n=params["n"],
                r=params["r"],
                p=params["p"],
            )

            try:
                kdf.verify(password.encode("utf-8"), expected_hash)
                valid = True
            except Exception:
                valid = False

            # Check if parameters are outdated
            default_params = self.DEFAULT_PARAMS[PasswordAlgorithm.SCRYPT]
            needs_rehash = params["n"] < default_params.n

            return valid, needs_rehash

        except PasswordVerifyError:
            raise
        except Exception as e:
            raise PasswordVerifyError(f"scrypt verification failed: {e}")

    def _hash_pbkdf2(self, password: str, params: PBKDF2Params) -> str:
        """Hash with PBKDF2.

        Output format: $pbkdf2-sha256$iterations$salt$hash
        """
        salt = os.urandom(params.salt_length)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=params.key_length,
            salt=salt,
            iterations=params.iterations,
        )

        key = kdf.derive(password.encode("utf-8"))

        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(key).decode("ascii")

        return f"$pbkdf2-sha256${params.iterations}${salt_b64}${hash_b64}"

    def _verify_pbkdf2(self, password: str, hash_string: str) -> tuple[bool, bool]:
        """Verify PBKDF2 hash."""
        try:
            # Parse format: $pbkdf2-sha256$iterations$salt$hash
            parts = hash_string.split("$")
            if len(parts) != 5 or not parts[1].startswith("pbkdf2"):
                raise PasswordVerifyError("Invalid PBKDF2 hash format")

            iterations = int(parts[2])
            salt = base64.b64decode(parts[3])
            expected_hash = base64.b64decode(parts[4])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=len(expected_hash),
                salt=salt,
                iterations=iterations,
            )

            try:
                kdf.verify(password.encode("utf-8"), expected_hash)
                valid = True
            except Exception:
                valid = False

            # Check if iterations are outdated
            default_params = self.DEFAULT_PARAMS[PasswordAlgorithm.PBKDF2_SHA256]
            needs_rehash = iterations < default_params.iterations

            return valid, needs_rehash

        except PasswordVerifyError:
            raise
        except Exception as e:
            raise PasswordVerifyError(f"PBKDF2 verification failed: {e}")

    # ==================== Helper Methods ====================

    def _detect_algorithm(self, hash_string: str) -> PasswordAlgorithm:
        """Detect algorithm from hash format."""
        if hash_string.startswith("$argon2id$"):
            return PasswordAlgorithm.ARGON2ID
        elif hash_string.startswith("$argon2i$"):
            return PasswordAlgorithm.ARGON2I
        elif hash_string.startswith("$argon2d$"):
            return PasswordAlgorithm.ARGON2D
        elif hash_string.startswith("$2") and len(hash_string) == 60:
            return PasswordAlgorithm.BCRYPT
        elif hash_string.startswith("$scrypt$"):
            return PasswordAlgorithm.SCRYPT
        elif hash_string.startswith("$pbkdf2"):
            return PasswordAlgorithm.PBKDF2_SHA256
        else:
            raise PasswordVerifyError(f"Could not detect algorithm from hash: {hash_string[:20]}...")

    def _params_to_dict(self, params: Any) -> dict:
        """Convert params dataclass to dictionary."""
        if hasattr(params, "__dataclass_fields__"):
            return {k: v for k, v in params.__dict__.items()}
        return {}

    def _get_recommendations(
        self,
        length: int,
        has_lower: bool,
        has_upper: bool,
        has_digit: bool,
        has_special: bool,
    ) -> list[str]:
        """Get password improvement recommendations."""
        recommendations = []

        if length < 12:
            recommendations.append("Use at least 12 characters")
        if not has_lower:
            recommendations.append("Add lowercase letters (a-z)")
        if not has_upper:
            recommendations.append("Add uppercase letters (A-Z)")
        if not has_digit:
            recommendations.append("Add numbers (0-9)")
        if not has_special:
            recommendations.append("Add special characters (!@#$%)")

        if not recommendations:
            recommendations.append("Password meets all recommendations")

        return recommendations

    def get_available_algorithms(self) -> list[dict]:
        """Get list of available algorithms and their status."""
        return [
            {
                "algorithm": PasswordAlgorithm.ARGON2ID.value,
                "available": ARGON2_AVAILABLE,
                "recommended": True,
                "description": "Memory-hard, resistant to GPU/ASIC attacks",
            },
            {
                "algorithm": PasswordAlgorithm.BCRYPT.value,
                "available": BCRYPT_AVAILABLE,
                "recommended": False,
                "description": "Proven, widely deployed",
            },
            {
                "algorithm": PasswordAlgorithm.SCRYPT.value,
                "available": True,
                "recommended": False,
                "description": "Memory-hard, IETF standard",
            },
            {
                "algorithm": PasswordAlgorithm.PBKDF2_SHA256.value,
                "available": True,
                "recommended": False,
                "description": "FIPS-compliant, legacy support",
            },
        ]


# Singleton instance
password_engine = PasswordEngine()
