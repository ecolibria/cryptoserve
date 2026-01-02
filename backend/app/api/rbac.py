"""RBAC Management API.

Provides endpoints for role and permission management.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User
from app.core.rbac import (
    Role,
    Permission,
    get_user_permissions,
    get_user_role,
    get_role_display_name,
    get_role_description,
    list_roles,
    list_permissions,
    ROLE_PERMISSIONS,
    check_permission,
)

router = APIRouter(prefix="/api/rbac", tags=["rbac"])


# =============================================================================
# Request/Response Models
# =============================================================================

class RoleInfo(BaseModel):
    """Role information."""
    role: str
    display_name: str
    description: str
    permissions_count: int


class PermissionInfo(BaseModel):
    """Permission information."""
    permission: str
    action: str


class ResourcePermissions(BaseModel):
    """Permissions grouped by resource."""
    resource: str
    actions: list[PermissionInfo]


class UserPermissionsResponse(BaseModel):
    """User's effective permissions."""
    user_id: str
    role: str
    role_display_name: str
    effective_permissions: list[str]
    custom_permissions: list[str]
    denied_permissions: list[str]


class UpdateRoleRequest(BaseModel):
    """Request to update a user's role."""
    role: str = Field(..., description="New role: owner, admin, developer, viewer, service_account")


class UpdatePermissionsRequest(BaseModel):
    """Request to update custom permissions."""
    add_permissions: list[str] = Field(default_factory=list)
    remove_permissions: list[str] = Field(default_factory=list)
    deny_permissions: list[str] = Field(default_factory=list)
    allow_permissions: list[str] = Field(default_factory=list)  # Remove from denied


class CheckPermissionRequest(BaseModel):
    """Request to check a permission."""
    permission: str


class CheckPermissionResponse(BaseModel):
    """Permission check result."""
    permission: str
    allowed: bool
    reason: str


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/roles", response_model=list[RoleInfo])
async def get_available_roles(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """List all available roles with descriptions."""
    return list_roles()


@router.get("/permissions")
async def get_available_permissions(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """List all available permissions grouped by resource."""
    return list_permissions()


@router.get("/roles/{role}/permissions")
async def get_role_permissions(
    role: str,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get all permissions for a specific role."""
    try:
        role_enum = Role(role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {role}",
        )

    permissions = ROLE_PERMISSIONS.get(role_enum, set())

    return {
        "role": role,
        "display_name": get_role_display_name(role_enum),
        "description": get_role_description(role_enum),
        "permissions": sorted([p.value for p in permissions]),
    }


@router.get("/me/permissions", response_model=UserPermissionsResponse)
async def get_my_permissions(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get current user's effective permissions."""
    perms = get_user_permissions(current_user)

    return UserPermissionsResponse(
        user_id=str(current_user.id),
        role=perms.role.value,
        role_display_name=get_role_display_name(perms.role),
        effective_permissions=sorted([p.value for p in perms.effective_permissions]),
        custom_permissions=sorted([p.value for p in perms.custom_permissions]),
        denied_permissions=sorted([p.value for p in perms.denied_permissions]),
    )


@router.post("/me/check", response_model=CheckPermissionResponse)
async def check_my_permission(
    request: CheckPermissionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if current user has a specific permission."""
    try:
        perm = Permission(request.permission)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission: {request.permission}",
        )

    allowed = check_permission(current_user, perm)
    perms = get_user_permissions(current_user)

    if allowed:
        if perm in perms.custom_permissions:
            reason = "Granted via custom permission"
        else:
            reason = f"Granted via {perms.role.value} role"
    else:
        if perm in perms.denied_permissions:
            reason = "Explicitly denied"
        else:
            reason = f"Not included in {perms.role.value} role"

    return CheckPermissionResponse(
        permission=request.permission,
        allowed=allowed,
        reason=reason,
    )


@router.get("/users/{user_id}/permissions", response_model=UserPermissionsResponse)
async def get_user_permissions_endpoint(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get another user's permissions (requires admin)."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to view other users' permissions",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    perms = get_user_permissions(user)

    return UserPermissionsResponse(
        user_id=str(user.id),
        role=perms.role.value,
        role_display_name=get_role_display_name(perms.role),
        effective_permissions=sorted([p.value for p in perms.effective_permissions]),
        custom_permissions=sorted([p.value for p in perms.custom_permissions]),
        denied_permissions=sorted([p.value for p in perms.denied_permissions]),
    )


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    request: UpdateRoleRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Update a user's role (requires admin or owner)."""
    # Check permission
    if not check_permission(current_user, Permission.USERS_MANAGE_ROLES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users:manage_roles required",
        )

    # Validate role
    try:
        new_role = Role(request.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {request.role}. Valid roles: {[r.value for r in Role]}",
        )

    # Only owners can create other owners
    if new_role == Role.OWNER and get_user_role(current_user) != Role.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can assign the owner role",
        )

    # Get target user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Can't change own role (prevent lock-out)
    if str(user.id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role",
        )

    # Update role
    user.role = new_role.value

    # Sync is_admin flag
    user.is_admin = new_role in (Role.OWNER, Role.ADMIN)

    await db.commit()

    return {
        "success": True,
        "user_id": user_id,
        "new_role": new_role.value,
        "display_name": get_role_display_name(new_role),
    }


@router.patch("/users/{user_id}/permissions")
async def update_user_permissions(
    user_id: str,
    request: UpdatePermissionsRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Update a user's custom permissions (requires admin)."""
    if not check_permission(current_user, Permission.USERS_MANAGE_ROLES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users:manage_roles required",
        )

    # Validate all permissions
    for perm_str in (request.add_permissions + request.remove_permissions +
                     request.deny_permissions + request.allow_permissions):
        try:
            Permission(perm_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permission: {perm_str}",
            )

    # Get target user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update custom permissions
    custom = set(user.custom_permissions or [])
    custom.update(request.add_permissions)
    custom -= set(request.remove_permissions)
    user.custom_permissions = list(custom) if custom else None

    # Update denied permissions
    denied = set(user.denied_permissions or [])
    denied.update(request.deny_permissions)
    denied -= set(request.allow_permissions)
    user.denied_permissions = list(denied) if denied else None

    await db.commit()

    # Get updated permissions
    perms = get_user_permissions(user)

    return {
        "success": True,
        "user_id": user_id,
        "custom_permissions": sorted([p.value for p in perms.custom_permissions]),
        "denied_permissions": sorted([p.value for p in perms.denied_permissions]),
        "effective_permissions_count": len(perms.effective_permissions),
    }


@router.get("/summary")
async def get_rbac_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get RBAC system summary (requires admin)."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    # Count users by role
    result = await db.execute(select(User))
    users = result.scalars().all()

    role_counts = {}
    for user in users:
        role = get_user_role(user)
        role_counts[role.value] = role_counts.get(role.value, 0) + 1

    return {
        "total_users": len(users),
        "users_by_role": role_counts,
        "available_roles": len(Role),
        "total_permissions": len(Permission),
        "roles": list_roles(),
    }
