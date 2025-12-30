"""CryptoServe Backend - Main FastAPI Application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import get_settings
from app.database import init_db, close_db, get_session_maker
from app.auth import github_oauth_router
from app.api import (
    identities_router,
    contexts_router,
    crypto_router,
    users_router,
    audit_router,
    policies_router,
)
from app.api.sdk import router as sdk_router
from app.api.admin import router as admin_router
from app.api.algorithms import router as algorithms_router
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

    # 6. Quantum-Ready Context (new!)
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
    """Application lifespan events."""
    # Startup
    await init_db()
    await seed_default_contexts()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="CryptoServe",
    description="Cryptographic operations server with personalized SDK distribution",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(github_oauth_router)
app.include_router(users_router)
app.include_router(identities_router)
app.include_router(contexts_router)
app.include_router(crypto_router)
app.include_router(audit_router)
app.include_router(policies_router)
app.include_router(sdk_router)
app.include_router(algorithms_router)
app.include_router(admin_router)


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
    """Health check endpoint."""
    return {"status": "healthy"}
