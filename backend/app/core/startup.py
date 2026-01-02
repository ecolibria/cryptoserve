"""Startup validation and initialization.

Validates critical configuration and secrets before the application starts.
Prevents running with insecure defaults or missing configuration.

Validation levels:
- STRICT: All checks must pass (production)
- WARN: Log warnings but continue (development)
- SKIP: Skip validation (testing)
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from app.config import get_settings

logger = logging.getLogger(__name__)


class ValidationLevel(str, Enum):
    """Validation strictness levels."""
    STRICT = "strict"  # Fail if any check fails
    WARN = "warn"      # Log warnings, continue
    SKIP = "skip"      # Skip all validation


@dataclass
class ValidationResult:
    """Result of a validation check."""
    name: str
    passed: bool
    message: str
    critical: bool = True  # If critical, failure blocks startup in STRICT mode


class StartupValidator:
    """Validates configuration and secrets on startup."""

    def __init__(self, level: ValidationLevel = ValidationLevel.STRICT):
        self.level = level
        self.results: list[ValidationResult] = []

    def _check(
        self,
        name: str,
        condition: bool,
        message: str,
        critical: bool = True,
    ) -> ValidationResult:
        """Run a validation check."""
        result = ValidationResult(
            name=name,
            passed=condition,
            message=message,
            critical=critical,
        )
        self.results.append(result)
        return result

    def validate_master_key(self, settings) -> ValidationResult:
        """Validate CRYPTOSERVE_MASTER_KEY."""
        key = settings.cryptoserve_master_key

        if not key:
            return self._check(
                "master_key",
                False,
                "CRYPTOSERVE_MASTER_KEY is not set",
                critical=True,
            )

        if len(key) < 32:
            return self._check(
                "master_key",
                False,
                f"CRYPTOSERVE_MASTER_KEY is too short ({len(key)} chars, need 32+)",
                critical=True,
            )

        if "change-in-production" in key.lower():
            return self._check(
                "master_key",
                False,
                "Using default development master key - set a secure key for production",
                critical=True,
            )

        # Check entropy (basic check)
        unique_chars = len(set(key))
        if unique_chars < 10:
            return self._check(
                "master_key",
                False,
                f"CRYPTOSERVE_MASTER_KEY has low entropy ({unique_chars} unique chars)",
                critical=True,
            )

        return self._check(
            "master_key",
            True,
            "Master key is properly configured",
            critical=True,
        )

    def validate_jwt_secret(self, settings) -> ValidationResult:
        """Validate JWT_SECRET_KEY."""
        secret = settings.jwt_secret_key

        if not secret:
            return self._check(
                "jwt_secret",
                False,
                "JWT_SECRET_KEY is not set",
                critical=True,
            )

        if "change-in-production" in secret.lower():
            return self._check(
                "jwt_secret",
                False,
                "Using default JWT secret - set a secure JWT_SECRET_KEY for production",
                critical=True,
            )

        if len(secret) < 32:
            return self._check(
                "jwt_secret",
                False,
                f"JWT_SECRET_KEY is too short ({len(secret)} chars, need 32+)",
                critical=False,  # Not as critical as master key
            )

        return self._check(
            "jwt_secret",
            True,
            "JWT secret is properly configured",
            critical=True,
        )

    def validate_hkdf_salt(self, settings) -> ValidationResult:
        """Validate CRYPTOSERVE_HKDF_SALT."""
        salt = settings.hkdf_salt

        if not salt:
            return self._check(
                "hkdf_salt",
                False,
                "CRYPTOSERVE_HKDF_SALT is not set (using default)",
                critical=False,
            )

        if len(salt) < 16:
            return self._check(
                "hkdf_salt",
                False,
                f"CRYPTOSERVE_HKDF_SALT is too short ({len(salt)} chars)",
                critical=False,
            )

        return self._check(
            "hkdf_salt",
            True,
            "HKDF salt is properly configured",
            critical=False,
        )

    def validate_oauth(self, settings) -> ValidationResult:
        """Validate GitHub OAuth configuration."""
        client_id = settings.github_client_id
        client_secret = settings.github_client_secret

        if not client_id and not client_secret:
            return self._check(
                "oauth",
                True,
                "GitHub OAuth not configured (optional)",
                critical=False,
            )

        if client_id and not client_secret:
            return self._check(
                "oauth",
                False,
                "GITHUB_CLIENT_ID set but GITHUB_CLIENT_SECRET missing",
                critical=False,
            )

        if not client_id and client_secret:
            return self._check(
                "oauth",
                False,
                "GITHUB_CLIENT_SECRET set but GITHUB_CLIENT_ID missing",
                critical=False,
            )

        return self._check(
            "oauth",
            True,
            "GitHub OAuth is properly configured",
            critical=False,
        )

    def validate_database(self, settings) -> ValidationResult:
        """Validate database configuration."""
        db_url = settings.database_url

        if not db_url:
            return self._check(
                "database",
                False,
                "DATABASE_URL is not set",
                critical=True,
            )

        if "sqlite" in db_url and ":memory:" in db_url:
            return self._check(
                "database",
                False,
                "Using in-memory SQLite - data will be lost on restart",
                critical=False,
            )

        return self._check(
            "database",
            True,
            "Database is configured",
            critical=True,
        )

    def validate_kms_backend(self, settings) -> ValidationResult:
        """Validate KMS backend configuration."""
        backend = os.environ.get("KMS_BACKEND", "local").lower()

        if backend == "local":
            return self._check(
                "kms_backend",
                True,
                "Using local KMS - not HSM-backed (development mode)",
                critical=False,
            )

        if backend == "aws_kms":
            key_id = os.environ.get("KMS_MASTER_KEY_ID")
            if not key_id:
                return self._check(
                    "kms_backend",
                    False,
                    "AWS KMS selected but KMS_MASTER_KEY_ID not set",
                    critical=True,
                )
            return self._check(
                "kms_backend",
                True,
                f"Using AWS KMS with key: {key_id[:20]}...",
                critical=True,
            )

        return self._check(
            "kms_backend",
            True,
            f"Using KMS backend: {backend}",
            critical=True,
        )

    def validate_fips_mode(self, settings) -> ValidationResult:
        """Validate FIPS 140-2/140-3 configuration."""
        from app.core.fips import get_fips_status, FIPSMode

        status = get_fips_status()

        if status.mode == FIPSMode.DISABLED:
            return self._check(
                "fips_mode",
                True,
                f"FIPS mode disabled (OpenSSL: {status.openssl_version})",
                critical=False,
            )

        if status.mode == FIPSMode.ENABLED:
            if status.compliant:
                return self._check(
                    "fips_mode",
                    True,
                    f"FIPS mode enabled and compliant (OpenSSL: {status.openssl_version})",
                    critical=True,
                )
            else:
                return self._check(
                    "fips_mode",
                    False,
                    f"FIPS mode enabled but not compliant: {status.message}",
                    critical=True,
                )

        # PREFERRED mode
        if status.openssl_fips_available:
            return self._check(
                "fips_mode",
                True,
                f"FIPS mode preferred and available (OpenSSL: {status.openssl_version})",
                critical=False,
            )
        else:
            return self._check(
                "fips_mode",
                True,
                f"FIPS mode preferred but not available - using standard crypto",
                critical=False,
            )

    def run_all(self) -> list[ValidationResult]:
        """Run all validation checks."""
        settings = get_settings()

        # Core secrets
        self.validate_master_key(settings)
        self.validate_jwt_secret(settings)
        self.validate_hkdf_salt(settings)

        # External services
        self.validate_database(settings)
        self.validate_oauth(settings)
        self.validate_kms_backend(settings)

        # Compliance
        self.validate_fips_mode(settings)

        return self.results

    def report(self) -> bool:
        """Report validation results and return success status."""
        if not self.results:
            self.run_all()

        passed = []
        warnings = []
        failed = []

        for result in self.results:
            if result.passed:
                passed.append(result)
            elif result.critical:
                failed.append(result)
            else:
                warnings.append(result)

        # Log results
        logger.info(f"Startup validation: {len(passed)} passed, {len(warnings)} warnings, {len(failed)} failed")

        for result in passed:
            logger.debug(f"  [PASS] {result.name}: {result.message}")

        for result in warnings:
            logger.warning(f"  [WARN] {result.name}: {result.message}")

        for result in failed:
            logger.error(f"  [FAIL] {result.name}: {result.message}")

        # Determine success based on level
        if self.level == ValidationLevel.SKIP:
            return True

        if self.level == ValidationLevel.WARN:
            return True

        # STRICT mode: fail if any critical check failed
        return len(failed) == 0


def validate_startup(level: ValidationLevel | None = None) -> bool:
    """Validate startup configuration.

    Args:
        level: Validation level (default: from STARTUP_VALIDATION_LEVEL env var)

    Returns:
        True if validation passed, False otherwise

    Raises:
        RuntimeError: If STRICT mode and validation failed
    """
    if level is None:
        env_level = os.environ.get("STARTUP_VALIDATION_LEVEL", "warn").lower()
        try:
            level = ValidationLevel(env_level)
        except ValueError:
            level = ValidationLevel.WARN

    if level == ValidationLevel.SKIP:
        logger.info("Startup validation skipped (STARTUP_VALIDATION_LEVEL=skip)")
        return True

    validator = StartupValidator(level)
    success = validator.report()

    if not success and level == ValidationLevel.STRICT:
        raise RuntimeError(
            "Startup validation failed in STRICT mode. "
            "Fix configuration issues or set STARTUP_VALIDATION_LEVEL=warn to continue."
        )

    return success
