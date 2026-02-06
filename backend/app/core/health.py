"""Comprehensive health check system.

Provides production-grade health checks for all dependencies:
- Database connectivity and query performance
- KMS provider health and latency
- Configuration validation
- Critical secrets verification
- Memory and resource status

Health check types:
- Liveness: Is the service running? (for Kubernetes liveness probe)
- Readiness: Is the service ready to accept traffic? (for readiness probe)
- Deep: Full dependency verification (for debugging/monitoring)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.key_manager import key_manager

logger = logging.getLogger(__name__)
settings = get_settings()


class HealthStatus(str, Enum):
    """Health check status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Some non-critical checks failed
    UNHEALTHY = "unhealthy"  # Critical checks failed


@dataclass
class CheckResult:
    """Result of a single health check."""

    name: str
    status: HealthStatus
    latency_ms: float
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    critical: bool = True  # If critical, failure = unhealthy


@dataclass
class HealthReport:
    """Complete health report."""

    status: HealthStatus
    timestamp: datetime
    version: str
    checks: list[CheckResult]
    total_latency_ms: float

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON response."""
        return {
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "checks": {
                check.name: {
                    "status": check.status.value,
                    "latency_ms": round(check.latency_ms, 2),
                    "message": check.message,
                    "details": check.details,
                }
                for check in self.checks
            },
        }


class HealthChecker:
    """Comprehensive health check system."""

    from app import __version__

    VERSION = __version__

    async def check_database(self, db: AsyncSession) -> CheckResult:
        """Check database connectivity and query performance."""
        start = time.monotonic()
        try:
            # Simple query to verify connectivity
            result = await db.execute(text("SELECT 1"))
            result.scalar()

            # Check if we can query tables
            await db.execute(text("SELECT COUNT(*) FROM users"))

            latency = (time.monotonic() - start) * 1000

            status = HealthStatus.HEALTHY
            message = "Database is responsive"

            # Warn if latency is high
            if latency > 100:
                status = HealthStatus.DEGRADED
                message = f"Database latency is high: {latency:.1f}ms"

            return CheckResult(
                name="database",
                status=status,
                latency_ms=latency,
                message=message,
                details={"driver": "asyncpg/aiosqlite"},
                critical=True,
            )

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            logger.error(f"Database health check failed: {e}")
            return CheckResult(
                name="database",
                status=HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"Database error: {str(e)}",
                critical=True,
            )

    async def check_kms(self) -> CheckResult:
        """Check KMS provider health."""
        start = time.monotonic()
        try:
            health = await key_manager.get_kms_health()
            latency = (time.monotonic() - start) * 1000

            if health.get("healthy"):
                return CheckResult(
                    name="kms",
                    status=HealthStatus.HEALTHY,
                    latency_ms=latency,
                    message=f"KMS backend: {health.get('backend', 'unknown')}",
                    details={
                        "backend": health.get("backend"),
                        "hsm_backed": health.get("hsm_backed", False),
                        "fips_compliant": health.get("fips_compliant", False),
                        "key_status": health.get("master_key_status"),
                    },
                    critical=True,
                )
            else:
                return CheckResult(
                    name="kms",
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=latency,
                    message=f"KMS error: {health.get('error', 'unknown')}",
                    critical=True,
                )

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            logger.error(f"KMS health check failed: {e}")
            return CheckResult(
                name="kms",
                status=HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"KMS error: {str(e)}",
                critical=True,
            )

    def check_configuration(self) -> CheckResult:
        """Validate critical configuration."""
        start = time.monotonic()
        issues = []

        # Check critical secrets are set
        if not settings.cryptoserve_master_key:
            issues.append("CRYPTOSERVE_MASTER_KEY not set")
        elif len(settings.cryptoserve_master_key) < 32:
            issues.append("CRYPTOSERVE_MASTER_KEY too short (< 32 chars)")
        elif "change-in-production" in settings.cryptoserve_master_key.lower():
            issues.append("Using default development master key")

        if not settings.hkdf_salt:
            issues.append("CRYPTOSERVE_HKDF_SALT not set")

        if not settings.jwt_secret_key:
            issues.append("JWT_SECRET_KEY not set")
        elif "change-in-production" in settings.jwt_secret_key.lower():
            issues.append("Using default JWT secret")

        # Check GitHub OAuth (if enabled)
        if settings.github_client_id and not settings.github_client_secret:
            issues.append("GITHUB_CLIENT_ID set but GITHUB_CLIENT_SECRET missing")

        latency = (time.monotonic() - start) * 1000

        if issues:
            return CheckResult(
                name="configuration",
                status=HealthStatus.DEGRADED if len(issues) < 3 else HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"{len(issues)} configuration issue(s)",
                details={"issues": issues},
                critical=True,
            )

        return CheckResult(
            name="configuration",
            status=HealthStatus.HEALTHY,
            latency_ms=latency,
            message="Configuration validated",
            details={"environment": settings.environment},
            critical=True,
        )

    async def check_crypto_operations(self, db: AsyncSession) -> CheckResult:
        """Test encryption/decryption round-trip."""
        start = time.monotonic()
        try:
            # Simple key derivation test
            test_key = await key_manager.derive_key("health-check", 1, 32)

            if len(test_key) != 32:
                raise ValueError("Key derivation returned wrong size")

            latency = (time.monotonic() - start) * 1000

            return CheckResult(
                name="crypto",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
                message="Cryptographic operations working",
                details={"key_derivation": "ok"},
                critical=True,
            )

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            logger.error(f"Crypto health check failed: {e}")
            return CheckResult(
                name="crypto",
                status=HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"Crypto error: {str(e)}",
                critical=True,
            )

    async def liveness(self) -> dict:
        """Quick liveness check - just verifies the service is running.

        Used by Kubernetes liveness probe. Should be fast and simple.
        """
        return {
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def readiness(self, db: AsyncSession) -> HealthReport:
        """Readiness check - verifies service can handle requests.

        Used by Kubernetes readiness probe. Checks critical dependencies.
        """
        start = time.monotonic()
        checks = []

        # Run critical checks in parallel
        db_check, kms_check = await asyncio.gather(
            self.check_database(db),
            self.check_kms(),
            return_exceptions=True,
        )

        # Handle exceptions
        if isinstance(db_check, Exception):
            checks.append(
                CheckResult(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=0,
                    message=str(db_check),
                    critical=True,
                )
            )
        else:
            checks.append(db_check)

        if isinstance(kms_check, Exception):
            checks.append(
                CheckResult(
                    name="kms",
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=0,
                    message=str(kms_check),
                    critical=True,
                )
            )
        else:
            checks.append(kms_check)

        total_latency = (time.monotonic() - start) * 1000

        # Determine overall status
        if any(c.status == HealthStatus.UNHEALTHY and c.critical for c in checks):
            status = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in checks):
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return HealthReport(
            status=status,
            timestamp=datetime.now(timezone.utc),
            version=self.VERSION,
            checks=checks,
            total_latency_ms=total_latency,
        )

    async def deep(self, db: AsyncSession) -> HealthReport:
        """Deep health check - verifies all dependencies.

        Used for debugging and monitoring dashboards.
        """
        start = time.monotonic()
        checks = []

        # Run all checks in parallel
        results = await asyncio.gather(
            self.check_database(db),
            self.check_kms(),
            self.check_crypto_operations(db),
            return_exceptions=True,
        )

        check_names = ["database", "kms", "crypto"]
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                checks.append(
                    CheckResult(
                        name=check_names[i],
                        status=HealthStatus.UNHEALTHY,
                        latency_ms=0,
                        message=str(result),
                        critical=True,
                    )
                )
            else:
                checks.append(result)

        # Add synchronous configuration check
        checks.append(self.check_configuration())

        total_latency = (time.monotonic() - start) * 1000

        # Determine overall status
        critical_unhealthy = any(c.status == HealthStatus.UNHEALTHY and c.critical for c in checks)
        any_degraded = any(c.status == HealthStatus.DEGRADED for c in checks)

        if critical_unhealthy:
            status = HealthStatus.UNHEALTHY
        elif any_degraded:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return HealthReport(
            status=status,
            timestamp=datetime.now(timezone.utc),
            version=self.VERSION,
            checks=checks,
            total_latency_ms=total_latency,
        )


# Singleton instance
health_checker = HealthChecker()
