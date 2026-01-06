"""Onboarding API routes for user provisioning and invitations.

Provides endpoints for:
- Setup wizard state management
- Email invitations
- Provisioning configuration
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User
from app.core.onboarding_service import onboarding_service
from app.core.rbac import Permission, check_permission

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


# --- Dependency Functions ---

async def require_invite_permission(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require users:invite permission."""
    if not check_permission(user, Permission.USERS_INVITE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: {Permission.USERS_INVITE.value}",
        )
    return user


# --- Request/Response Schemas ---

class SetupStatusResponse(BaseModel):
    """Setup wizard status response."""
    setupCompleted: bool
    setupCompletedAt: str | None = None
    hasAdmin: bool
    userCount: int
    provisioningMode: str
    allowedDomains: list[str]
    allowedGithubOrgs: list[str]
    defaultRole: str
    organizationName: str | None = None


class CompleteSetupRequest(BaseModel):
    """Request to complete setup wizard."""
    organizationName: str | None = Field(None, max_length=255)
    allowedDomains: list[str] | None = None
    allowedGithubOrgs: list[str] | None = None
    provisioningMode: str = Field(default="domain")
    defaultRole: str = Field(default="developer")


class CreateInvitationRequest(BaseModel):
    """Request to create a user invitation."""
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[^@]+@[^@]+\.[^@]+$")
    role: str = Field(default="developer")
    expiresDays: int = Field(default=7, ge=1, le=30)


class InvitationResponse(BaseModel):
    """User invitation response."""
    id: str
    email: str
    role: str
    status: str
    token: str
    createdAt: datetime
    expiresAt: datetime
    acceptedAt: datetime | None = None
    invitedBy: str


class InvitationValidationResponse(BaseModel):
    """Invitation validation response."""
    valid: bool
    error: str | None = None
    email: str | None = None
    role: str | None = None
    expiresAt: datetime | None = None


class ProvisioningConfigRequest(BaseModel):
    """Request to update provisioning configuration."""
    provisioningMode: str | None = None
    defaultRole: str | None = None
    allowedDomains: list[str] | None = None
    allowedGithubOrgs: list[str] | None = None


class ProvisioningConfigResponse(BaseModel):
    """Provisioning configuration response."""
    provisioningMode: str
    defaultRole: str
    allowedDomains: list[str]
    allowedGithubOrgs: list[str]


class AddGithubOrgRequest(BaseModel):
    """Request to add a GitHub organization."""
    organization: str = Field(..., min_length=1, max_length=100)


# --- Setup Wizard Endpoints ---

@router.get("/setup/status", response_model=SetupStatusResponse)
async def get_setup_status(
    db: AsyncSession = Depends(get_db),
):
    """Get setup wizard status.

    This endpoint is public to allow redirecting to setup wizard
    before authentication.
    """
    status_data = await onboarding_service.get_setup_status(db)
    return SetupStatusResponse(**status_data)


@router.post("/setup/complete", response_model=SetupStatusResponse)
async def complete_setup(
    data: CompleteSetupRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Complete the initial setup wizard.

    Only admins can complete setup.
    """
    # Verify user is admin
    if not user.is_admin and user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can complete setup"
        )

    await onboarding_service.complete_setup(
        db=db,
        user_id=user.id,
        organization_name=data.organizationName,
        allowed_domains=data.allowedDomains,
        allowed_github_orgs=data.allowedGithubOrgs,
        provisioning_mode=data.provisioningMode,
        default_role=data.defaultRole,
    )

    # Return updated status
    status_data = await onboarding_service.get_setup_status(db)
    return SetupStatusResponse(**status_data)


# --- Invitation Endpoints ---

@router.post("/invitations", response_model=InvitationResponse)
async def create_invitation(
    data: CreateInvitationRequest,
    user: Annotated[User, Depends(require_invite_permission)],
    db: AsyncSession = Depends(get_db),
):
    """Create a new user invitation.

    Requires users:invite permission.
    """
    try:
        invitation = await onboarding_service.create_invitation(
            db=db,
            tenant_id=user.tenant_id,
            email=data.email,
            invited_by_id=user.id,
            role=data.role,
            expires_days=data.expiresDays,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    return InvitationResponse(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        status=invitation.status,
        token=invitation.token,
        createdAt=invitation.created_at,
        expiresAt=invitation.expires_at,
        acceptedAt=invitation.accepted_at,
        invitedBy=user.github_username,
    )


@router.get("/invitations", response_model=list[InvitationResponse])
async def list_invitations(
    user: Annotated[User, Depends(require_invite_permission)],
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
):
    """List invitations for the tenant.

    Requires users:invite permission.

    Args:
        status_filter: Filter by status (pending, accepted, expired, revoked)
    """
    invitations = await onboarding_service.list_invitations(
        db=db,
        tenant_id=user.tenant_id,
        status_filter=status_filter,
    )

    return [
        InvitationResponse(
            id=inv.id,
            email=inv.email,
            role=inv.role,
            status=inv.status,
            token=inv.token,
            createdAt=inv.created_at,
            expiresAt=inv.expires_at,
            acceptedAt=inv.accepted_at,
            invitedBy=inv.invited_by.github_username if inv.invited_by else "Unknown",
        )
        for inv in invitations
    ]


@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: str,
    user: Annotated[User, Depends(require_invite_permission)],
    db: AsyncSession = Depends(get_db),
):
    """Revoke a pending invitation.

    Requires users:invite permission.
    """
    success = await onboarding_service.revoke_invitation(db, invitation_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found or already used"
        )

    return {"message": "Invitation revoked"}


@router.get("/invitations/validate/{token}", response_model=InvitationValidationResponse)
async def validate_invitation_token(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Validate an invitation token.

    This endpoint is public to allow validation before login.
    """
    is_valid, error, invitation = await onboarding_service.validate_invitation(db, token)

    if not is_valid:
        return InvitationValidationResponse(
            valid=False,
            error=error,
        )

    return InvitationValidationResponse(
        valid=True,
        email=invitation.email,
        role=invitation.role,
        expiresAt=invitation.expires_at,
    )


# --- Provisioning Configuration Endpoints ---

@router.get("/config/provisioning", response_model=ProvisioningConfigResponse)
async def get_provisioning_config(
    user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get current provisioning configuration.

    Requires authentication.
    """
    settings = await onboarding_service.get_org_settings(db)

    return ProvisioningConfigResponse(
        provisioningMode=settings.provisioning_mode,
        defaultRole=settings.default_role,
        allowedDomains=settings.allowed_domains,
        allowedGithubOrgs=settings.allowed_github_orgs,
    )


@router.put("/config/provisioning", response_model=ProvisioningConfigResponse)
async def update_provisioning_config(
    data: ProvisioningConfigRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Update provisioning configuration.

    Only admins can update configuration.
    """
    # Verify user is admin
    if not user.is_admin and user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update provisioning configuration"
        )

    try:
        settings = await onboarding_service.update_provisioning_config(
            db=db,
            provisioning_mode=data.provisioningMode,
            default_role=data.defaultRole,
            allowed_domains=data.allowedDomains,
            allowed_github_orgs=data.allowedGithubOrgs,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    return ProvisioningConfigResponse(
        provisioningMode=settings.provisioning_mode,
        defaultRole=settings.default_role,
        allowedDomains=settings.allowed_domains,
        allowedGithubOrgs=settings.allowed_github_orgs,
    )


@router.post("/config/github-orgs")
async def add_github_org(
    data: AddGithubOrgRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Add a GitHub organization to the allowed list.

    Only admins can add organizations.
    """
    if not user.is_admin and user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can add GitHub organizations"
        )

    try:
        settings = await onboarding_service.add_allowed_github_org(db, data.organization)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    return {"allowedGithubOrgs": settings.allowed_github_orgs}


@router.delete("/config/github-orgs/{org}")
async def remove_github_org(
    org: str,
    user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Remove a GitHub organization from the allowed list.

    Only admins can remove organizations.
    """
    if not user.is_admin and user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can remove GitHub organizations"
        )

    settings = await onboarding_service.remove_allowed_github_org(db, org)
    return {"allowedGithubOrgs": settings.allowed_github_orgs}
