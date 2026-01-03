"""API routes."""

from app.api.identities import router as identities_router
from app.api.applications import router as applications_router
from app.api.auth import router as auth_router
from app.api.contexts import router as contexts_router
from app.api.crypto import router as crypto_router
from app.api.users import router as users_router
from app.api.audit import router as audit_router
from app.api.policies import router as policies_router
from app.api.signatures import router as signatures_router
from app.api.hashing import router as hashing_router
from app.api.passwords import router as passwords_router
from app.api.jose import router as jose_router
from app.api.asymmetric import router as asymmetric_router
from app.api.secrets import router as secrets_router
from app.api.discovery import router as discovery_router
from app.api.code_analysis import router as code_analysis_router
from app.api.certificates import router as certificates_router
from app.api.dependencies import router as dependencies_router
from app.api.inventory import router as inventory_router, cbom_router
from app.api.dashboard import router as dashboard_router
from app.api.promotion import router as promotion_router
from app.api.compliance import router as compliance_router

__all__ = [
    "identities_router",
    "applications_router",
    "auth_router",
    "contexts_router",
    "crypto_router",
    "users_router",
    "audit_router",
    "policies_router",
    "signatures_router",
    "hashing_router",
    "passwords_router",
    "jose_router",
    "asymmetric_router",
    "secrets_router",
    "discovery_router",
    "code_analysis_router",
    "certificates_router",
    "dependencies_router",
    "inventory_router",
    "cbom_router",
    "dashboard_router",
    "promotion_router",
    "compliance_router",
]
