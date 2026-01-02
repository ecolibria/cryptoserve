"""Role-Based Access Control (RBAC) System.

Implements enterprise-grade RBAC with:
- Predefined roles with hierarchical permissions
- Resource-based access control
- Tenant-scoped roles
- Permission inheritance

Roles (from most to least privileged):
- OWNER: Full control, can manage billing and delete tenant
- ADMIN: Full control except billing and tenant deletion
- DEVELOPER: Create/manage contexts, keys, applications
- VIEWER: Read-only access to all resources
- SERVICE_ACCOUNT: API-only access with scoped permissions

Resources:
- contexts: Encryption contexts
- keys: Cryptographic keys
- applications: Registered applications
- policies: Security policies
- audit: Audit logs
- users: User management
- tenants: Tenant management
- compliance: Compliance reports
- ceremony: Key ceremony operations
- backups: Backup/restore operations
"""

from enum import Enum
from dataclasses import dataclass, field
from functools import wraps
from typing import Callable

from fastapi import HTTPException, status


class Permission(str, Enum):
    """Fine-grained permissions for resources."""

    # Context permissions
    CONTEXTS_READ = "contexts:read"
    CONTEXTS_CREATE = "contexts:create"
    CONTEXTS_UPDATE = "contexts:update"
    CONTEXTS_DELETE = "contexts:delete"

    # Key permissions
    KEYS_READ = "keys:read"
    KEYS_CREATE = "keys:create"
    KEYS_ROTATE = "keys:rotate"
    KEYS_DELETE = "keys:delete"

    # Application permissions
    APPS_READ = "apps:read"
    APPS_CREATE = "apps:create"
    APPS_UPDATE = "apps:update"
    APPS_DELETE = "apps:delete"

    # Policy permissions
    POLICIES_READ = "policies:read"
    POLICIES_CREATE = "policies:create"
    POLICIES_UPDATE = "policies:update"
    POLICIES_DELETE = "policies:delete"

    # Audit permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # User management
    USERS_READ = "users:read"
    USERS_INVITE = "users:invite"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    USERS_MANAGE_ROLES = "users:manage_roles"

    # Tenant management
    TENANTS_READ = "tenants:read"
    TENANTS_UPDATE = "tenants:update"
    TENANTS_DELETE = "tenants:delete"
    TENANTS_BILLING = "tenants:billing"

    # Compliance
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_EXPORT = "compliance:export"

    # Key ceremony
    CEREMONY_READ = "ceremony:read"
    CEREMONY_INITIALIZE = "ceremony:initialize"
    CEREMONY_SEAL = "ceremony:seal"
    CEREMONY_UNSEAL = "ceremony:unseal"

    # Backups
    BACKUPS_CREATE = "backups:create"
    BACKUPS_RESTORE = "backups:restore"
    BACKUPS_DELETE = "backups:delete"

    # Crypto operations
    CRYPTO_ENCRYPT = "crypto:encrypt"
    CRYPTO_DECRYPT = "crypto:decrypt"
    CRYPTO_SIGN = "crypto:sign"
    CRYPTO_VERIFY = "crypto:verify"

    # Secrets
    SECRETS_SPLIT = "secrets:split"
    SECRETS_COMBINE = "secrets:combine"


class Role(str, Enum):
    """Predefined roles with permission sets."""

    OWNER = "owner"
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"


# Permission sets for each role
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.OWNER: set(Permission),  # All permissions

    Role.ADMIN: {
        # All except billing and tenant deletion
        Permission.CONTEXTS_READ, Permission.CONTEXTS_CREATE,
        Permission.CONTEXTS_UPDATE, Permission.CONTEXTS_DELETE,
        Permission.KEYS_READ, Permission.KEYS_CREATE,
        Permission.KEYS_ROTATE, Permission.KEYS_DELETE,
        Permission.APPS_READ, Permission.APPS_CREATE,
        Permission.APPS_UPDATE, Permission.APPS_DELETE,
        Permission.POLICIES_READ, Permission.POLICIES_CREATE,
        Permission.POLICIES_UPDATE, Permission.POLICIES_DELETE,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        Permission.USERS_READ, Permission.USERS_INVITE,
        Permission.USERS_UPDATE, Permission.USERS_DELETE,
        Permission.USERS_MANAGE_ROLES,
        Permission.TENANTS_READ, Permission.TENANTS_UPDATE,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_EXPORT,
        Permission.CEREMONY_READ, Permission.CEREMONY_INITIALIZE,
        Permission.CEREMONY_SEAL, Permission.CEREMONY_UNSEAL,
        Permission.BACKUPS_CREATE, Permission.BACKUPS_RESTORE,
        Permission.BACKUPS_DELETE,
        Permission.CRYPTO_ENCRYPT, Permission.CRYPTO_DECRYPT,
        Permission.CRYPTO_SIGN, Permission.CRYPTO_VERIFY,
        Permission.SECRETS_SPLIT, Permission.SECRETS_COMBINE,
    },

    Role.DEVELOPER: {
        Permission.CONTEXTS_READ, Permission.CONTEXTS_CREATE,
        Permission.CONTEXTS_UPDATE,
        Permission.KEYS_READ, Permission.KEYS_CREATE,
        Permission.KEYS_ROTATE,
        Permission.APPS_READ, Permission.APPS_CREATE,
        Permission.APPS_UPDATE, Permission.APPS_DELETE,
        Permission.POLICIES_READ,
        Permission.AUDIT_READ,
        Permission.USERS_READ,
        Permission.TENANTS_READ,
        Permission.COMPLIANCE_READ,
        Permission.CEREMONY_READ,
        Permission.CRYPTO_ENCRYPT, Permission.CRYPTO_DECRYPT,
        Permission.CRYPTO_SIGN, Permission.CRYPTO_VERIFY,
        Permission.SECRETS_SPLIT, Permission.SECRETS_COMBINE,
    },

    Role.VIEWER: {
        Permission.CONTEXTS_READ,
        Permission.KEYS_READ,
        Permission.APPS_READ,
        Permission.POLICIES_READ,
        Permission.AUDIT_READ,
        Permission.USERS_READ,
        Permission.TENANTS_READ,
        Permission.COMPLIANCE_READ,
        Permission.CEREMONY_READ,
    },

    Role.SERVICE_ACCOUNT: {
        # Minimal permissions for API access
        Permission.CONTEXTS_READ,
        Permission.CRYPTO_ENCRYPT, Permission.CRYPTO_DECRYPT,
        Permission.CRYPTO_SIGN, Permission.CRYPTO_VERIFY,
    },
}


@dataclass
class UserPermissions:
    """User's effective permissions."""

    user_id: str
    role: Role
    permissions: set[Permission] = field(default_factory=set)
    custom_permissions: set[Permission] = field(default_factory=set)
    denied_permissions: set[Permission] = field(default_factory=set)

    @property
    def effective_permissions(self) -> set[Permission]:
        """Calculate effective permissions (role + custom - denied)."""
        base = ROLE_PERMISSIONS.get(self.role, set())
        return (base | self.custom_permissions) - self.denied_permissions

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        return permission in self.effective_permissions

    def has_any_permission(self, permissions: list[Permission]) -> bool:
        """Check if user has any of the listed permissions."""
        return bool(self.effective_permissions & set(permissions))

    def has_all_permissions(self, permissions: list[Permission]) -> bool:
        """Check if user has all listed permissions."""
        return set(permissions) <= self.effective_permissions


def get_user_role(user) -> Role:
    """Get the role for a user.

    Maps the simple is_admin boolean to role, with support
    for the role field when added.
    """
    # Check for explicit role field first (future-proofing)
    if hasattr(user, 'role') and user.role:
        try:
            return Role(user.role)
        except ValueError:
            pass

    # Fall back to is_admin boolean
    if user.is_admin:
        return Role.ADMIN

    return Role.DEVELOPER  # Default role for authenticated users


def get_user_permissions(user) -> UserPermissions:
    """Get complete permissions for a user."""
    role = get_user_role(user)

    # Check for custom permissions (stored as JSON in user record)
    custom = set()
    denied = set()

    if hasattr(user, 'custom_permissions') and user.custom_permissions:
        for p in user.custom_permissions:
            try:
                custom.add(Permission(p))
            except ValueError:
                pass

    if hasattr(user, 'denied_permissions') and user.denied_permissions:
        for p in user.denied_permissions:
            try:
                denied.add(Permission(p))
            except ValueError:
                pass

    return UserPermissions(
        user_id=str(user.id),
        role=role,
        custom_permissions=custom,
        denied_permissions=denied,
    )


def check_permission(user, permission: Permission) -> bool:
    """Check if user has a specific permission."""
    perms = get_user_permissions(user)
    return perms.has_permission(permission)


def require_permission(permission: Permission):
    """Decorator to require a specific permission for an endpoint.

    Usage:
        @router.get("/contexts")
        @require_permission(Permission.CONTEXTS_READ)
        async def list_contexts(user: User = Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the user in kwargs (injected by Depends)
            user = kwargs.get('current_user') or kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            if not check_permission(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission.value}",
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(*permissions: Permission):
    """Decorator to require any of the listed permissions."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get('current_user') or kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            perms = get_user_permissions(user)
            if not perms.has_any_permission(list(permissions)):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: requires one of {[p.value for p in permissions]}",
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_all_permissions(*permissions: Permission):
    """Decorator to require all listed permissions."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get('current_user') or kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            perms = get_user_permissions(user)
            if not perms.has_all_permissions(list(permissions)):
                missing = set(permissions) - perms.effective_permissions
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permissions: {[p.value for p in missing]}",
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


# FastAPI dependency for permission checking
class PermissionChecker:
    """FastAPI dependency for permission checking.

    Usage:
        @router.get("/contexts")
        async def list_contexts(
            _: None = Depends(PermissionChecker(Permission.CONTEXTS_READ)),
            user: User = Depends(get_current_user),
        ):
            ...
    """

    def __init__(self, *permissions: Permission, require_all: bool = False):
        self.permissions = permissions
        self.require_all = require_all

    async def __call__(self, current_user=None):
        from app.auth.jwt import get_current_user
        from fastapi import Depends

        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        perms = get_user_permissions(current_user)

        if self.require_all:
            if not perms.has_all_permissions(list(self.permissions)):
                missing = set(self.permissions) - perms.effective_permissions
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permissions: {[p.value for p in missing]}",
                )
        else:
            if not perms.has_any_permission(list(self.permissions)):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: requires one of {[p.value for p in self.permissions]}",
                )


# Role hierarchy for display
ROLE_HIERARCHY = [
    Role.OWNER,
    Role.ADMIN,
    Role.DEVELOPER,
    Role.VIEWER,
    Role.SERVICE_ACCOUNT,
]


def get_role_display_name(role: Role) -> str:
    """Get human-readable role name."""
    return {
        Role.OWNER: "Owner",
        Role.ADMIN: "Administrator",
        Role.DEVELOPER: "Developer",
        Role.VIEWER: "Viewer",
        Role.SERVICE_ACCOUNT: "Service Account",
    }.get(role, role.value)


def get_role_description(role: Role) -> str:
    """Get role description."""
    return {
        Role.OWNER: "Full control including billing and tenant deletion",
        Role.ADMIN: "Full control except billing and tenant deletion",
        Role.DEVELOPER: "Create and manage contexts, keys, and applications",
        Role.VIEWER: "Read-only access to all resources",
        Role.SERVICE_ACCOUNT: "API-only access for automated systems",
    }.get(role, "")


def list_roles() -> list[dict]:
    """List all available roles with descriptions."""
    return [
        {
            "role": role.value,
            "display_name": get_role_display_name(role),
            "description": get_role_description(role),
            "permissions_count": len(ROLE_PERMISSIONS.get(role, set())),
        }
        for role in ROLE_HIERARCHY
    ]


def list_permissions() -> list[dict]:
    """List all available permissions grouped by resource."""
    resources = {}
    for perm in Permission:
        resource = perm.value.split(":")[0]
        action = perm.value.split(":")[1]
        if resource not in resources:
            resources[resource] = []
        resources[resource].append({
            "permission": perm.value,
            "action": action,
        })

    return [
        {"resource": resource, "actions": actions}
        for resource, actions in sorted(resources.items())
    ]
