"""Database models."""

from app.models.tenant import Tenant, DEFAULT_TENANT_ID, DEFAULT_TENANT_SLUG
from app.models.user import User
from app.models.team import Team, TeamSource, user_teams
from app.models.organization import OrganizationSettings  # Legacy, kept for migration
from app.models.invitation import UserInvitation, InvitationStatus
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
from app.models.security_scan import (
    SecurityScan,
    SecurityFinding,
    CertificateInventory,
    ScanType,
    SeverityLevel,
    FindingStatus,
)
from app.models.approval import (
    ExpeditedApprovalRequest,
    ApprovalStatus,
    ApprovalPriority,
)
from app.models.migration_history import MigrationHistory

__all__ = [
    # Multi-tenancy
    "Tenant",
    "DEFAULT_TENANT_ID",
    "DEFAULT_TENANT_SLUG",
    # Users
    "User",
    "OrganizationSettings",  # Legacy, kept for migration
    # Invitations
    "UserInvitation",
    "InvitationStatus",
    # Teams
    "Team",
    "TeamSource",
    "user_teams",
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
    # Security Scanning
    "SecurityScan",
    "SecurityFinding",
    "CertificateInventory",
    "ScanType",
    "SeverityLevel",
    "FindingStatus",
    # Approval Workflow
    "ExpeditedApprovalRequest",
    "ApprovalStatus",
    "ApprovalPriority",
    # Migration History
    "MigrationHistory",
]
