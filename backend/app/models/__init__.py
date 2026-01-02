"""Database models."""

from app.models.tenant import Tenant, DEFAULT_TENANT_ID, DEFAULT_TENANT_SLUG
from app.models.user import User
from app.models.organization import OrganizationSettings  # Legacy, kept for migration
from app.models.identity import Identity, IdentityType, IdentityStatus
from app.models.application import Application, ApplicationStatus
from app.models.context import Context
from app.models.key import Key, KeyStatus, KeyType, PQCKey
from app.models.audit import AuditLog
from app.models.policy import Policy, PolicyViolationLog
from app.models.crypto_inventory import (
    CryptoInventoryReport,
    CryptoLibraryUsage,
    QuantumRisk,
    EnforcementAction,
    ScanSource,
)

__all__ = [
    # Multi-tenancy
    "Tenant",
    "DEFAULT_TENANT_ID",
    "DEFAULT_TENANT_SLUG",
    # Users
    "User",
    "OrganizationSettings",  # Legacy, kept for migration
    # Legacy Identity (keeping for backward compatibility)
    "Identity",
    "IdentityType",
    "IdentityStatus",
    # New Application model
    "Application",
    "ApplicationStatus",
    "Context",
    "Key",
    "KeyStatus",
    "KeyType",
    "PQCKey",
    "AuditLog",
    "Policy",
    "PolicyViolationLog",
    "CryptoInventoryReport",
    "CryptoLibraryUsage",
    "QuantumRisk",
    "EnforcementAction",
    "ScanSource",
]
