"""Tests for cryptoserve_core password hashing module."""

import pytest

from cryptoserve_core.passwords import (
    hash_password,
    verify_password,
    check_strength,
    PasswordStrength,
    PasswordHashError,
)


class TestHashPassword:
    """Tests for hash_password()."""

    def test_scrypt_phc_format(self):
        """scrypt hash follows PHC format."""
        h = hash_password("test123", algorithm="scrypt")
        assert h.startswith("$scrypt$n=")
        parts = h.split("$")
        assert len(parts) == 5
        assert parts[1] == "scrypt"

    def test_pbkdf2_phc_format(self):
        """PBKDF2 hash follows PHC format."""
        h = hash_password("test123", algorithm="pbkdf2")
        assert h.startswith("$pbkdf2-sha256$i=")
        parts = h.split("$")
        assert len(parts) == 5
        assert parts[1] == "pbkdf2-sha256"

    def test_default_algorithm_is_scrypt(self):
        """Default algorithm is scrypt."""
        h = hash_password("test123")
        assert h.startswith("$scrypt$")

    def test_different_hashes_same_password(self):
        """Same password produces different hashes (random salt)."""
        h1 = hash_password("password123", algorithm="pbkdf2")
        h2 = hash_password("password123", algorithm="pbkdf2")
        assert h1 != h2

    def test_unsupported_algorithm(self):
        """Unsupported algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_password("test", algorithm="bcrypt")


class TestVerifyPassword:
    """Tests for verify_password()."""

    def test_verify_correct_scrypt(self):
        """Correct password verifies against scrypt hash."""
        h = hash_password("correct-horse-battery-staple", algorithm="scrypt")
        assert verify_password("correct-horse-battery-staple", h) is True

    def test_verify_wrong_scrypt(self):
        """Wrong password fails verification against scrypt hash."""
        h = hash_password("correct-password", algorithm="scrypt")
        assert verify_password("wrong-password", h) is False

    def test_verify_correct_pbkdf2(self):
        """Correct password verifies against PBKDF2 hash."""
        h = hash_password("my-secure-pass", algorithm="pbkdf2")
        assert verify_password("my-secure-pass", h) is True

    def test_verify_wrong_pbkdf2(self):
        """Wrong password fails verification against PBKDF2 hash."""
        h = hash_password("correct", algorithm="pbkdf2")
        assert verify_password("incorrect", h) is False

    def test_invalid_hash_format(self):
        """Invalid hash format raises PasswordHashError."""
        with pytest.raises(PasswordHashError):
            verify_password("test", "$unknown$params$salt$hash")

    def test_empty_password_hashes_and_verifies(self):
        """Empty string password can be hashed and verified."""
        h = hash_password("", algorithm="pbkdf2")
        assert verify_password("", h) is True
        assert verify_password("not-empty", h) is False


class TestCheckStrength:
    """Tests for check_strength()."""

    def test_empty_password(self):
        """Empty password scores 0."""
        result = check_strength("")
        assert result.score == 0
        assert result.label == "very weak"
        assert result.length == 0

    def test_common_password(self):
        """Common passwords score 0."""
        result = check_strength("password")
        assert result.score == 0
        assert result.label == "very weak"
        assert "commonly used" in result.feedback[0]

    def test_common_password_case_insensitive(self):
        """Common password detection is case-insensitive."""
        result = check_strength("PASSWORD")
        assert result.score == 0

    def test_short_password(self):
        """Short passwords get low scores."""
        result = check_strength("Ab1!")
        assert result.score <= 2
        assert result.length == 4

    def test_strong_password(self):
        """Strong password with good length and diversity scores high."""
        result = check_strength("MyStr0ng!Pass#2026")
        assert result.score >= 3
        assert result.has_upper is True
        assert result.has_lower is True
        assert result.has_digit is True
        assert result.has_special is True

    def test_only_lowercase(self):
        """Only lowercase chars get low diversity score."""
        result = check_strength("onlylowercase")
        assert result.has_upper is False
        assert result.has_digit is False
        assert result.has_special is False

    def test_keyboard_pattern_detection(self):
        """Keyboard patterns are detected."""
        result = check_strength("qwertyuiop123")
        has_pattern_feedback = any("keyboard pattern" in f for f in result.feedback)
        assert has_pattern_feedback

    def test_strength_labels(self):
        """All score values map to labels."""
        for score in range(5):
            ps = PasswordStrength(
                score=score, length=10,
                has_upper=True, has_lower=True,
                has_digit=True, has_special=True,
            )
            assert ps.label in ("very weak", "weak", "fair", "strong", "very strong")

    def test_medium_password(self):
        """Medium-length password with some diversity."""
        result = check_strength("Hello123")
        assert result.score >= 1
        assert result.has_upper is True
        assert result.has_lower is True
        assert result.has_digit is True
