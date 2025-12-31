"""Tests for the password hashing engine."""

import pytest

from app.core.password_engine import (
    password_engine,
    PasswordEngine,
    PasswordAlgorithm,
    Argon2Params,
    BcryptParams,
    ScryptParams,
    PBKDF2Params,
    PasswordHashError,
    PasswordVerifyError,
    UnsupportedAlgorithmError,
    ARGON2_AVAILABLE,
    BCRYPT_AVAILABLE,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh password engine for each test."""
    return PasswordEngine()


class TestArgon2Hashing:
    """Tests for Argon2 password hashing."""

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_hash_with_argon2id(self, fresh_engine):
        """Test Argon2id password hashing."""
        result = fresh_engine.hash_password(
            "my-secret-password",
            algorithm=PasswordAlgorithm.ARGON2ID,
        )

        assert result.algorithm == PasswordAlgorithm.ARGON2ID
        assert result.hash.startswith("$argon2id$")
        assert result.params["time_cost"] == 3
        assert result.params["memory_cost"] == 65536
        assert result.created_at is not None

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_verify_argon2id_password(self, fresh_engine):
        """Test Argon2id password verification."""
        password = "correct-password"
        result = fresh_engine.hash_password(password, PasswordAlgorithm.ARGON2ID)

        # Verify correct password
        verification = fresh_engine.verify_password(password, result.hash)
        assert verification.valid
        assert verification.algorithm == PasswordAlgorithm.ARGON2ID

        # Verify incorrect password
        wrong_verification = fresh_engine.verify_password("wrong-password", result.hash)
        assert not wrong_verification.valid

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_argon2_with_custom_params(self, fresh_engine):
        """Test Argon2 with custom parameters."""
        custom_params = Argon2Params(
            time_cost=2,
            memory_cost=32768,
            parallelism=2,
            hash_len=32,
            salt_len=16,
        )

        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.ARGON2ID,
            params=custom_params,
        )

        assert result.params["time_cost"] == 2
        assert result.params["memory_cost"] == 32768

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_argon2_needs_rehash_detection(self, fresh_engine):
        """Test detection of outdated Argon2 parameters."""
        # Hash with minimal params
        minimal_params = Argon2Params(
            time_cost=1,
            memory_cost=16384,
            parallelism=1,
        )
        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.ARGON2ID,
            params=minimal_params,
        )

        # Verify - should indicate needs_rehash
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.valid
        assert verification.needs_rehash  # Params are below defaults

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_argon2_variants(self, fresh_engine):
        """Test all Argon2 variants."""
        for algo in [PasswordAlgorithm.ARGON2ID, PasswordAlgorithm.ARGON2I, PasswordAlgorithm.ARGON2D]:
            result = fresh_engine.hash_password("password", algorithm=algo)
            verification = fresh_engine.verify_password("password", result.hash)
            assert verification.valid


class TestBcryptHashing:
    """Tests for bcrypt password hashing."""

    @pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
    def test_hash_with_bcrypt(self, fresh_engine):
        """Test bcrypt password hashing."""
        result = fresh_engine.hash_password(
            "my-secret-password",
            algorithm=PasswordAlgorithm.BCRYPT,
        )

        assert result.algorithm == PasswordAlgorithm.BCRYPT
        assert result.hash.startswith("$2")
        assert len(result.hash) == 60

    @pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
    def test_verify_bcrypt_password(self, fresh_engine):
        """Test bcrypt password verification."""
        password = "correct-password"
        result = fresh_engine.hash_password(password, PasswordAlgorithm.BCRYPT)

        verification = fresh_engine.verify_password(password, result.hash)
        assert verification.valid

        wrong_verification = fresh_engine.verify_password("wrong", result.hash)
        assert not wrong_verification.valid

    @pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
    def test_bcrypt_custom_rounds(self, fresh_engine):
        """Test bcrypt with custom rounds."""
        custom_params = BcryptParams(rounds=10)
        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.BCRYPT,
            params=custom_params,
        )

        # Verify the hash works
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.valid

    @pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
    def test_bcrypt_needs_rehash(self, fresh_engine):
        """Test bcrypt needs_rehash detection."""
        # Use low rounds
        low_rounds = BcryptParams(rounds=4)
        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.BCRYPT,
            params=low_rounds,
        )

        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.valid
        assert verification.needs_rehash  # Rounds are below default (12)


class TestScryptHashing:
    """Tests for scrypt password hashing."""

    def test_hash_with_scrypt(self, fresh_engine):
        """Test scrypt password hashing."""
        # Use lower params for faster testing
        params = ScryptParams(n=2**14, r=8, p=1)
        result = fresh_engine.hash_password(
            "my-secret-password",
            algorithm=PasswordAlgorithm.SCRYPT,
            params=params,
        )

        assert result.algorithm == PasswordAlgorithm.SCRYPT
        assert result.hash.startswith("$scrypt$")
        assert "n=" in result.hash
        assert "r=" in result.hash
        assert "p=" in result.hash

    def test_verify_scrypt_password(self, fresh_engine):
        """Test scrypt password verification."""
        params = ScryptParams(n=2**14, r=8, p=1)
        password = "correct-password"
        result = fresh_engine.hash_password(
            password,
            algorithm=PasswordAlgorithm.SCRYPT,
            params=params,
        )

        verification = fresh_engine.verify_password(password, result.hash)
        assert verification.valid
        assert verification.algorithm == PasswordAlgorithm.SCRYPT

        wrong_verification = fresh_engine.verify_password("wrong", result.hash)
        assert not wrong_verification.valid

    def test_scrypt_needs_rehash(self, fresh_engine):
        """Test scrypt needs_rehash detection."""
        # Use low N value
        low_params = ScryptParams(n=2**10, r=8, p=1)
        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.SCRYPT,
            params=low_params,
        )

        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.valid
        assert verification.needs_rehash


class TestPBKDF2Hashing:
    """Tests for PBKDF2 password hashing."""

    def test_hash_with_pbkdf2(self, fresh_engine):
        """Test PBKDF2-SHA256 password hashing."""
        # Use lower iterations for faster testing
        params = PBKDF2Params(iterations=10000)
        result = fresh_engine.hash_password(
            "my-secret-password",
            algorithm=PasswordAlgorithm.PBKDF2_SHA256,
            params=params,
        )

        assert result.algorithm == PasswordAlgorithm.PBKDF2_SHA256
        assert result.hash.startswith("$pbkdf2-sha256$")

    def test_verify_pbkdf2_password(self, fresh_engine):
        """Test PBKDF2 password verification."""
        params = PBKDF2Params(iterations=10000)
        password = "correct-password"
        result = fresh_engine.hash_password(
            password,
            algorithm=PasswordAlgorithm.PBKDF2_SHA256,
            params=params,
        )

        verification = fresh_engine.verify_password(password, result.hash)
        assert verification.valid
        assert verification.algorithm == PasswordAlgorithm.PBKDF2_SHA256

        wrong_verification = fresh_engine.verify_password("wrong", result.hash)
        assert not wrong_verification.valid

    def test_pbkdf2_needs_rehash(self, fresh_engine):
        """Test PBKDF2 needs_rehash detection."""
        # Use low iterations
        low_params = PBKDF2Params(iterations=1000)
        result = fresh_engine.hash_password(
            "password",
            algorithm=PasswordAlgorithm.PBKDF2_SHA256,
            params=low_params,
        )

        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.valid
        assert verification.needs_rehash


class TestAlgorithmDetection:
    """Tests for algorithm auto-detection."""

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
    def test_detect_argon2id(self, fresh_engine):
        """Test auto-detecting Argon2id hash."""
        result = fresh_engine.hash_password("password", PasswordAlgorithm.ARGON2ID)
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.algorithm == PasswordAlgorithm.ARGON2ID

    @pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
    def test_detect_bcrypt(self, fresh_engine):
        """Test auto-detecting bcrypt hash."""
        result = fresh_engine.hash_password("password", PasswordAlgorithm.BCRYPT)
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.algorithm == PasswordAlgorithm.BCRYPT

    def test_detect_scrypt(self, fresh_engine):
        """Test auto-detecting scrypt hash."""
        params = ScryptParams(n=2**14, r=8, p=1)
        result = fresh_engine.hash_password(
            "password",
            PasswordAlgorithm.SCRYPT,
            params=params,
        )
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.algorithm == PasswordAlgorithm.SCRYPT

    def test_detect_pbkdf2(self, fresh_engine):
        """Test auto-detecting PBKDF2 hash."""
        params = PBKDF2Params(iterations=10000)
        result = fresh_engine.hash_password(
            "password",
            PasswordAlgorithm.PBKDF2_SHA256,
            params=params,
        )
        verification = fresh_engine.verify_password("password", result.hash)
        assert verification.algorithm == PasswordAlgorithm.PBKDF2_SHA256

    def test_detect_unknown_format(self, fresh_engine):
        """Test error on unknown hash format."""
        with pytest.raises(PasswordVerifyError):
            fresh_engine.verify_password("password", "unknown-hash-format")


class TestPasswordStrength:
    """Tests for password strength checking."""

    def test_strong_password(self, fresh_engine):
        """Test strength of a strong password."""
        result = fresh_engine.check_strength("P@ssw0rd!Strong123")

        assert result["strength"] in ["strong", "good"]
        assert result["score"] >= 60
        assert result["has_lowercase"]
        assert result["has_uppercase"]
        assert result["has_digits"]
        assert result["has_special"]
        assert result["entropy_bits"] > 0

    def test_weak_password(self, fresh_engine):
        """Test strength of a weak password."""
        result = fresh_engine.check_strength("pass")

        assert result["strength"] == "weak"
        assert result["score"] < 40
        assert len(result["recommendations"]) > 1

    def test_recommendations(self, fresh_engine):
        """Test password recommendations."""
        # Missing uppercase
        result = fresh_engine.check_strength("password123!")
        assert any("uppercase" in r.lower() for r in result["recommendations"])

        # Short password
        result = fresh_engine.check_strength("Ab1!")
        assert any("12" in r for r in result["recommendations"])

    def test_entropy_calculation(self, fresh_engine):
        """Test entropy calculation."""
        # Simple lowercase only
        result1 = fresh_engine.check_strength("abcdefgh")
        # Complex mixed
        result2 = fresh_engine.check_strength("Ab1!Ab1!")

        # Mixed should have higher entropy
        assert result2["entropy_bits"] > result1["entropy_bits"]


class TestPasswordGeneration:
    """Tests for password generation."""

    def test_generate_default_password(self, fresh_engine):
        """Test generating a default password."""
        password = fresh_engine.generate_password()

        assert len(password) == 16
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)

    def test_generate_custom_length(self, fresh_engine):
        """Test generating password with custom length."""
        password = fresh_engine.generate_password(length=24)
        assert len(password) == 24

    def test_generate_minimum_length(self, fresh_engine):
        """Test minimum password length enforcement."""
        with pytest.raises(ValueError):
            fresh_engine.generate_password(length=4)

    def test_generate_no_special(self, fresh_engine):
        """Test generating password without special characters."""
        password = fresh_engine.generate_password(
            include_special=False,
            length=20,
        )

        assert all(c.isalnum() for c in password)

    def test_generate_no_digits(self, fresh_engine):
        """Test generating password without digits."""
        password = fresh_engine.generate_password(
            include_digits=False,
            length=20,
        )

        assert not any(c.isdigit() for c in password)

    def test_generate_unique(self, fresh_engine):
        """Test that generated passwords are unique."""
        passwords = {fresh_engine.generate_password() for _ in range(100)}
        assert len(passwords) == 100

    def test_exclude_ambiguous(self, fresh_engine):
        """Test excluding ambiguous characters."""
        # Generate many passwords and check
        for _ in range(20):
            password = fresh_engine.generate_password(
                length=50,
                exclude_ambiguous=True,
            )
            # 0, O, l, I are ambiguous
            assert "0" not in password
            assert "O" not in password
            assert "l" not in password
            assert "I" not in password


class TestAvailableAlgorithms:
    """Tests for algorithm availability."""

    def test_get_available_algorithms(self, fresh_engine):
        """Test getting list of available algorithms."""
        algorithms = fresh_engine.get_available_algorithms()

        assert len(algorithms) >= 4
        assert all("algorithm" in a for a in algorithms)
        assert all("available" in a for a in algorithms)
        assert all("description" in a for a in algorithms)

        # Argon2 should be recommended
        argon2 = next(a for a in algorithms if a["algorithm"] == "argon2id")
        assert argon2["recommended"]

    def test_scrypt_always_available(self, fresh_engine):
        """Test that scrypt is always available."""
        algorithms = fresh_engine.get_available_algorithms()
        scrypt = next(a for a in algorithms if a["algorithm"] == "scrypt")
        assert scrypt["available"]

    def test_pbkdf2_always_available(self, fresh_engine):
        """Test that PBKDF2 is always available."""
        algorithms = fresh_engine.get_available_algorithms()
        pbkdf2 = next(a for a in algorithms if a["algorithm"] == "pbkdf2-sha256")
        assert pbkdf2["available"]


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_password(self, fresh_engine):
        """Test hashing empty password."""
        params = ScryptParams(n=2**14, r=8, p=1)
        result = fresh_engine.hash_password(
            "",
            algorithm=PasswordAlgorithm.SCRYPT,
            params=params,
        )

        verification = fresh_engine.verify_password("", result.hash)
        assert verification.valid

    def test_unicode_password(self, fresh_engine):
        """Test hashing unicode password."""
        params = ScryptParams(n=2**14, r=8, p=1)
        unicode_password = "пароль密码🔐"
        result = fresh_engine.hash_password(
            unicode_password,
            algorithm=PasswordAlgorithm.SCRYPT,
            params=params,
        )

        verification = fresh_engine.verify_password(unicode_password, result.hash)
        assert verification.valid

    def test_long_password(self, fresh_engine):
        """Test hashing very long password."""
        params = ScryptParams(n=2**14, r=8, p=1)
        long_password = "a" * 1000
        result = fresh_engine.hash_password(
            long_password,
            algorithm=PasswordAlgorithm.SCRYPT,
            params=params,
        )

        verification = fresh_engine.verify_password(long_password, result.hash)
        assert verification.valid

    def test_invalid_hash_format(self, fresh_engine):
        """Test verification with invalid hash format."""
        with pytest.raises(PasswordVerifyError):
            fresh_engine.verify_password(
                "password",
                "$scrypt$invalid$format",
                PasswordAlgorithm.SCRYPT,
            )

    def test_require_at_least_one_charset(self, fresh_engine):
        """Test that at least one charset is required."""
        with pytest.raises(ValueError):
            fresh_engine.generate_password(
                include_lowercase=False,
                include_uppercase=False,
                include_digits=False,
                include_special=False,
            )
