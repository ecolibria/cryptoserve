"""CryptoServe Backend - Main FastAPI Application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import select

# Initialize structured logging early
from app.core.logging import setup_logging, RequestLoggingMiddleware, get_logger
setup_logging(json_output=False, level="INFO")  # Set json_output=True in production

# Rate limiting (optional - graceful fallback if not installed)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_ENABLED = True
except ImportError:
    RATE_LIMITING_ENABLED = False
    Limiter = None

from app.config import get_settings
from app.database import init_db, close_db, get_session_maker, get_db
from app.auth import github_oauth_router
from app.api import (
    identities_router,
    applications_router,
    auth_router,
    contexts_router,
    crypto_router,
    users_router,
    audit_router,
    policies_router,
    signatures_router,
    hashing_router,
    passwords_router,
    jose_router,
    asymmetric_router,
    secrets_router,
    discovery_router,
    code_analysis_router,
    certificates_router,
    dependencies_router,
    inventory_router,
    cbom_router,
    dashboard_router,
    promotion_router,
)
from app.api.sdk import router as sdk_router
from app.api.admin import router as admin_router
from app.api.algorithms import router as algorithms_router
from app.api.public import router as public_router
from app.models import Context
from app.schemas.context import (
    ContextConfig,
    DataIdentity,
    RegulatoryMapping,
    ThreatModel,
    AccessPatterns,
    RetentionPolicy,
    Sensitivity,
    DataCategory,
    Adversary,
    AccessFrequency,
)
from app.core.algorithm_resolver import resolve_algorithm

settings = get_settings()

# Rate limiter (only if slowapi is available)
if RATE_LIMITING_ENABLED:
    limiter = Limiter(key_func=get_remote_address)
else:
    limiter = None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Only add HSTS in production with HTTPS
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy for API responses
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        return response


def build_default_contexts() -> list[dict]:
    """Build default contexts with full 5-layer configuration."""
    contexts = []

    # 1. User PII Context
    user_pii_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.PERSONAL_IDENTIFIER,
            sensitivity=Sensitivity.CRITICAL,
            pii=True,
            notification_required=True,
            examples=["email", "phone", "SSN", "address", "date of birth", "full name"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["GDPR", "CCPA"],
            retention=RetentionPolicy(
                maximum_days=2555,
                deletion_method="crypto_shred",
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.ORGANIZED_CRIME, Adversary.NATION_STATE],
            protection_lifetime_years=20,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.HIGH,
            latency_requirement_ms=50,
        ),
    )
    user_pii_derived = resolve_algorithm(user_pii_config)
    contexts.append({
        "name": "user-pii",
        "display_name": "User Personal Data",
        "description": "Personally identifiable information that can identify an individual",
        "config": user_pii_config.model_dump(),
        "derived": user_pii_derived.model_dump(),
        "algorithm": user_pii_derived.resolved_algorithm,
        "data_examples": user_pii_config.data_identity.examples,
        "compliance_tags": user_pii_config.regulatory.frameworks,
    })

    # 2. Payment Data Context
    payment_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.FINANCIAL,
            subcategory="payment_card",
            sensitivity=Sensitivity.CRITICAL,
            pci=True,
            notification_required=True,
            examples=["credit card number", "bank account", "CVV", "billing address"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["PCI-DSS"],
            retention=RetentionPolicy(
                minimum_days=365,
                maximum_days=2555,
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.ORGANIZED_CRIME, Adversary.INSIDER],
            protection_lifetime_years=7,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.HIGH,
            operations_per_second=5000,
            latency_requirement_ms=10,
        ),
    )
    payment_derived = resolve_algorithm(payment_config)
    contexts.append({
        "name": "payment-data",
        "display_name": "Payment & Financial",
        "description": "Payment card data and financial account information",
        "config": payment_config.model_dump(),
        "derived": payment_derived.model_dump(),
        "algorithm": payment_derived.resolved_algorithm,
        "data_examples": payment_config.data_identity.examples,
        "compliance_tags": payment_config.regulatory.frameworks,
    })

    # 3. Session Tokens Context
    session_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.AUTHENTICATION,
            sensitivity=Sensitivity.MEDIUM,
            pii=False,
            notification_required=False,
            examples=["JWT tokens", "session IDs", "refresh tokens", "API keys"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["OWASP"],
            retention=RetentionPolicy(
                maximum_days=1,
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.OPPORTUNISTIC],
            protection_lifetime_years=0.01,  # Hours
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.HIGH,
            operations_per_second=10000,
            latency_requirement_ms=5,
        ),
    )
    session_derived = resolve_algorithm(session_config)
    contexts.append({
        "name": "session-tokens",
        "display_name": "Session & Auth Tokens",
        "description": "Temporary authentication and session data",
        "config": session_config.model_dump(),
        "derived": session_derived.model_dump(),
        "algorithm": session_derived.resolved_algorithm,
        "data_examples": session_config.data_identity.examples,
        "compliance_tags": session_config.regulatory.frameworks,
    })

    # 4. Health Data Context (HIPAA)
    health_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.HEALTH,
            sensitivity=Sensitivity.CRITICAL,
            phi=True,
            notification_required=True,
            examples=["diagnosis", "prescriptions", "medical history", "insurance ID"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["HIPAA"],
            retention=RetentionPolicy(
                minimum_days=2555,  # 7 years for HIPAA
                maximum_days=3650,
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.ORGANIZED_CRIME, Adversary.NATION_STATE],
            protection_lifetime_years=25,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.MEDIUM,
            latency_requirement_ms=100,
        ),
    )
    health_derived = resolve_algorithm(health_config)
    contexts.append({
        "name": "health-data",
        "display_name": "Health Information",
        "description": "Protected health information and medical records",
        "config": health_config.model_dump(),
        "derived": health_derived.model_dump(),
        "algorithm": health_derived.resolved_algorithm,
        "data_examples": health_config.data_identity.examples,
        "compliance_tags": health_config.regulatory.frameworks,
    })

    # 5. General Purpose Context
    general_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.GENERAL,
            sensitivity=Sensitivity.MEDIUM,
            examples=["internal IDs", "configuration secrets", "API responses"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=[],
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.OPPORTUNISTIC],
            protection_lifetime_years=5,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.MEDIUM,
        ),
    )
    general_derived = resolve_algorithm(general_config)
    contexts.append({
        "name": "general",
        "display_name": "General Purpose",
        "description": "General purpose encryption for miscellaneous sensitive data",
        "config": general_config.model_dump(),
        "derived": general_derived.model_dump(),
        "algorithm": general_derived.resolved_algorithm,
        "data_examples": general_config.data_identity.examples,
        "compliance_tags": general_config.regulatory.frameworks,
    })

    # 6. Internal Logs Context (SOC2)
    logs_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.GENERAL,
            subcategory="audit_logs",
            sensitivity=Sensitivity.MEDIUM,
            pii=False,
            notification_required=False,
            examples=["error logs", "access logs", "audit trails", "metrics", "debug logs"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["SOC2"],
            retention=RetentionPolicy(
                minimum_days=365,  # 1 year for SOC2
                maximum_days=730,
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.INSIDER, Adversary.OPPORTUNISTIC],
            protection_lifetime_years=2,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.HIGH,
            operations_per_second=10000,
            latency_requirement_ms=5,
            batch_operations=True,
        ),
    )
    logs_derived = resolve_algorithm(logs_config)
    contexts.append({
        "name": "internal-logs",
        "display_name": "Application Logs",
        "description": "System logs, audit trails, and application metrics",
        "config": logs_config.model_dump(),
        "derived": logs_derived.model_dump(),
        "algorithm": logs_derived.resolved_algorithm,
        "data_examples": logs_config.data_identity.examples,
        "compliance_tags": logs_config.regulatory.frameworks,
    })

    # 7. API Secrets Context
    api_secrets_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.AUTHENTICATION,
            subcategory="service_credentials",
            sensitivity=Sensitivity.CRITICAL,
            pii=False,
            notification_required=True,
            examples=["API keys", "service tokens", "database credentials", "webhook secrets", "OAuth client secrets"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["SOC2", "OWASP"],
            retention=RetentionPolicy(
                maximum_days=365,
                deletion_method="crypto_shred",
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.NATION_STATE, Adversary.ORGANIZED_CRIME, Adversary.INSIDER],
            protection_lifetime_years=1,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.LOW,
            latency_requirement_ms=100,
        ),
    )
    api_secrets_derived = resolve_algorithm(api_secrets_config)
    contexts.append({
        "name": "api-secrets",
        "display_name": "API & Service Secrets",
        "description": "API keys, service credentials, and integration secrets",
        "config": api_secrets_config.model_dump(),
        "derived": api_secrets_derived.model_dump(),
        "algorithm": api_secrets_derived.resolved_algorithm,
        "data_examples": api_secrets_config.data_identity.examples,
        "compliance_tags": api_secrets_config.regulatory.frameworks,
    })

    # 8. Business Documents Context
    business_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.BUSINESS_CONFIDENTIAL,
            sensitivity=Sensitivity.HIGH,
            pii=False,
            notification_required=False,
            examples=["contracts", "financial reports", "HR documents", "IP", "board materials", "M&A documents"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["SOX", "SOC2"],
            retention=RetentionPolicy(
                minimum_days=2555,  # 7 years for SOX
                maximum_days=3650,
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.ORGANIZED_CRIME, Adversary.INSIDER, Adversary.NATION_STATE],
            protection_lifetime_years=10,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.LOW,
            latency_requirement_ms=200,
        ),
    )
    business_derived = resolve_algorithm(business_config)
    contexts.append({
        "name": "business-documents",
        "display_name": "Business Confidential",
        "description": "Contracts, reports, IP, and other business-sensitive documents",
        "config": business_config.model_dump(),
        "derived": business_derived.model_dump(),
        "algorithm": business_derived.resolved_algorithm,
        "data_examples": business_config.data_identity.examples,
        "compliance_tags": business_config.regulatory.frameworks,
    })

    # 9. Backup Data Context
    backup_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.GENERAL,
            subcategory="backup_archive",
            sensitivity=Sensitivity.HIGH,
            pii=True,  # Backups may contain PII
            phi=True,  # Backups may contain PHI
            pci=True,  # Backups may contain PCI
            notification_required=True,
            examples=["database backups", "file archives", "disaster recovery", "snapshots"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["GDPR", "HIPAA", "PCI-DSS", "SOC2"],
            retention=RetentionPolicy(
                minimum_days=30,
                maximum_days=2555,  # 7 years
                deletion_method="crypto_shred",
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.NATION_STATE, Adversary.ORGANIZED_CRIME],
            attack_vectors=["offline_attack", "media_theft"],
            protection_lifetime_years=10,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.RARE,
            batch_operations=True,
            latency_requirement_ms=1000,  # Backups can be slower
        ),
    )
    backup_derived = resolve_algorithm(backup_config)
    contexts.append({
        "name": "backup-data",
        "display_name": "Backup & Archives",
        "description": "Database backups, file archives, and disaster recovery data",
        "config": backup_config.model_dump(),
        "derived": backup_derived.model_dump(),
        "algorithm": backup_derived.resolved_algorithm,
        "data_examples": backup_config.data_identity.examples,
        "compliance_tags": backup_config.regulatory.frameworks,
    })

    # 10. Quantum-Ready Context
    quantum_config = ContextConfig(
        data_identity=DataIdentity(
            category=DataCategory.BUSINESS_CONFIDENTIAL,
            subcategory="long_term_secrets",
            sensitivity=Sensitivity.CRITICAL,
            notification_required=True,
            examples=["trade secrets", "cryptographic keys", "classified documents"],
        ),
        regulatory=RegulatoryMapping(
            frameworks=["SOX", "NIST"],
            retention=RetentionPolicy(
                minimum_days=3650,  # 10 years
                maximum_days=10950,  # 30 years
            ),
        ),
        threat_model=ThreatModel(
            adversaries=[Adversary.NATION_STATE, Adversary.QUANTUM],
            attack_vectors=["harvest_now_decrypt_later"],
            protection_lifetime_years=30,
        ),
        access_patterns=AccessPatterns(
            frequency=AccessFrequency.LOW,
            latency_requirement_ms=500,  # Can tolerate higher latency
        ),
    )
    quantum_derived = resolve_algorithm(quantum_config)
    contexts.append({
        "name": "quantum-ready",
        "display_name": "Quantum-Ready Secrets",
        "description": "Long-term secrets requiring post-quantum cryptography protection",
        "config": quantum_config.model_dump(),
        "derived": quantum_derived.model_dump(),
        "algorithm": quantum_derived.resolved_algorithm,
        "data_examples": quantum_config.data_identity.examples,
        "compliance_tags": quantum_config.regulatory.frameworks,
    })

    return contexts


async def seed_default_contexts():
    """Seed default contexts if they don't exist."""
    default_contexts = build_default_contexts()

    async with get_session_maker()() as db:
        for ctx_data in default_contexts:
            result = await db.execute(
                select(Context).where(Context.name == ctx_data["name"])
            )
            existing = result.scalar_one_or_none()

            if not existing:
                context = Context(**ctx_data)
                db.add(context)

        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events.

    Handles graceful startup and shutdown for horizontal scaling:
    - Startup: Initialize DB, seed defaults, log readiness
    - Shutdown: Close DB connections, cleanup rate limiter
    """
    import signal
    import os

    # Validate startup configuration
    from app.core.startup import validate_startup
    validate_startup()  # Raises RuntimeError in STRICT mode if validation fails

    # Initialize database
    await init_db()
    await seed_default_contexts()

    logger = get_logger("cryptoserve")
    instance_id = os.getenv("HOSTNAME", os.getenv("INSTANCE_ID", "unknown"))
    logger.info(
        "CryptoServe started",
        version="0.1.0",
        instance_id=instance_id,
        pid=os.getpid(),
    )

    yield

    # Graceful shutdown
    logger.info("CryptoServe shutting down gracefully", instance_id=instance_id)

    # Close database connections
    await close_db()
    logger.info("Database connections closed")

    # Note: In-flight requests are handled by Uvicorn's graceful shutdown
    # Default timeout is 30 seconds (configurable via --timeout-graceful-shutdown)
    logger.info("Shutdown complete")


app = FastAPI(
    title="CryptoServe",
    description="Cryptographic operations server with personalized SDK distribution",
    version="0.1.0",
    lifespan=lifespan,
)

# Add rate limiter to app state (if available)
if RATE_LIMITING_ENABLED and limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS middleware - restricted methods and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Request-ID", "X-Correlation-ID"],
)

# Request logging middleware with correlation IDs
app.add_middleware(RequestLoggingMiddleware)

# Include routers
app.include_router(github_oauth_router)
app.include_router(users_router)
app.include_router(identities_router)
app.include_router(applications_router)
app.include_router(auth_router)
app.include_router(contexts_router)
app.include_router(crypto_router)
app.include_router(audit_router)
app.include_router(policies_router)
app.include_router(signatures_router)
app.include_router(hashing_router)
app.include_router(passwords_router)
app.include_router(jose_router)
app.include_router(asymmetric_router)
app.include_router(secrets_router)
app.include_router(discovery_router)
app.include_router(code_analysis_router)
app.include_router(certificates_router)
app.include_router(dependencies_router)
app.include_router(inventory_router)
app.include_router(cbom_router)
app.include_router(dashboard_router)
app.include_router(promotion_router)
app.include_router(sdk_router)
app.include_router(algorithms_router)
app.include_router(admin_router)
app.include_router(public_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "CryptoServe",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Basic health check - backwards compatible."""
    return {"status": "healthy"}


@app.get("/health/live")
async def health_liveness():
    """Liveness probe for Kubernetes.

    Quick check that the service is running.
    """
    from app.core.health import health_checker
    return await health_checker.liveness()


@app.get("/health/ready")
async def health_readiness(db: AsyncSession = Depends(get_db)):
    """Readiness probe for Kubernetes.

    Checks critical dependencies (database, KMS).
    Returns 503 if not ready to accept traffic.
    """
    from app.core.health import health_checker, HealthStatus
    from fastapi.responses import JSONResponse

    report = await health_checker.readiness(db)
    status_code = 200 if report.status != HealthStatus.UNHEALTHY else 503

    return JSONResponse(
        content=report.to_dict(),
        status_code=status_code,
    )


@app.get("/health/deep")
async def health_deep(db: AsyncSession = Depends(get_db)):
    """Deep health check for debugging and monitoring.

    Checks all dependencies including:
    - Database connectivity
    - KMS provider health
    - Cryptographic operations
    - Configuration validation
    - FIPS compliance status
    """
    from app.core.health import health_checker, HealthStatus
    from app.core.fips import get_fips_status
    from fastapi.responses import JSONResponse

    report = await health_checker.deep(db)

    # Add FIPS status to the report
    fips_status = get_fips_status()
    report_dict = report.to_dict()
    report_dict["fips"] = fips_status.to_dict()

    status_code = 200 if report.status != HealthStatus.UNHEALTHY else 503

    return JSONResponse(
        content=report_dict,
        status_code=status_code,
    )


@app.get("/health/fips")
async def health_fips():
    """FIPS 140-2/140-3 compliance status.

    Returns current FIPS mode and compliance information.
    """
    from app.core.fips import get_fips_status, get_fips_approved_algorithms

    status = get_fips_status()
    return {
        "status": status.to_dict(),
        "approved_algorithms": get_fips_approved_algorithms(),
    }
