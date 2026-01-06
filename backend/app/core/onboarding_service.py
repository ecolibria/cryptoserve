"""User onboarding and invitation service.

Handles enterprise user onboarding workflows including:
- Email invitations with secure tokens
- Domain-based auto-provisioning
- GitHub organization auto-provisioning
- First admin setup wizard
- Provisioning mode management
"""

import secrets
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, OrganizationSettings
from app.models.invitation import UserInvitation, InvitationStatus
from app.core.rbac import Role


class OnboardingService:
    """Service for managing user onboarding and invitations."""

    # Token length for invitation URLs (256 bits of entropy)
    TOKEN_LENGTH = 64
    DEFAULT_INVITATION_DAYS = 7

    @staticmethod
    def generate_invitation_token() -> str:
        """Generate a secure random token for invitation URLs."""
        return secrets.token_urlsafe(OnboardingService.TOKEN_LENGTH)

    async def get_org_settings(self, db: AsyncSession) -> OrganizationSettings:
        """Get organization settings (creates if not exists)."""
        result = await db.execute(select(OrganizationSettings).limit(1))
        settings = result.scalar_one_or_none()

        if settings is None:
            settings = OrganizationSettings()
            db.add(settings)
            await db.commit()
            await db.refresh(settings)

        return settings

    # --- Setup Wizard Methods ---

    async def is_setup_complete(self, db: AsyncSession) -> bool:
        """Check if initial setup has been completed."""
        settings = await self.get_org_settings(db)
        return settings.setup_completed

    async def get_setup_status(self, db: AsyncSession) -> dict:
        """Get comprehensive setup status for the wizard.

        Returns:
            Dictionary with setup state and configuration
        """
        settings = await self.get_org_settings(db)

        # Count users
        user_count = await db.scalar(select(func.count()).select_from(User))

        # Check if there's an admin
        admin_count = await db.scalar(
            select(func.count()).select_from(User).where(
                (User.role == Role.ADMIN.value) | (User.role == Role.OWNER.value)
            )
        )

        return {
            "setupCompleted": settings.setup_completed,
            "setupCompletedAt": settings.setup_completed_at.isoformat() if settings.setup_completed_at else None,
            "hasAdmin": admin_count > 0,
            "userCount": user_count,
            "provisioningMode": settings.provisioning_mode,
            "allowedDomains": settings.allowed_domains,
            "allowedGithubOrgs": settings.allowed_github_orgs,
            "defaultRole": settings.default_role,
            "organizationName": settings.organization_name,
        }

    async def complete_setup(
        self,
        db: AsyncSession,
        user_id: str,
        organization_name: str | None = None,
        allowed_domains: list[str] | None = None,
        allowed_github_orgs: list[str] | None = None,
        provisioning_mode: str = "domain",
        default_role: str = "developer",
    ) -> OrganizationSettings:
        """Complete the initial setup wizard.

        Args:
            db: Database session
            user_id: ID of admin completing setup
            organization_name: Optional organization name
            allowed_domains: Email domains for auto-provisioning
            allowed_github_orgs: GitHub orgs for auto-provisioning
            provisioning_mode: How users are provisioned
            default_role: Default role for auto-provisioned users

        Returns:
            Updated OrganizationSettings
        """
        settings = await self.get_org_settings(db)

        if organization_name is not None:
            settings.organization_name = organization_name

        if allowed_domains is not None:
            settings.allowed_domains = [d.lower().strip() for d in allowed_domains if d.strip()]

        if allowed_github_orgs is not None:
            settings.allowed_github_orgs = [org.strip() for org in allowed_github_orgs if org.strip()]

        settings.provisioning_mode = provisioning_mode
        settings.default_role = default_role
        settings.setup_completed = True
        settings.setup_completed_at = datetime.now(timezone.utc)
        settings.setup_completed_by_id = user_id

        await db.commit()
        await db.refresh(settings)
        return settings

    # --- Invitation Methods ---

    async def create_invitation(
        self,
        db: AsyncSession,
        tenant_id: str,
        email: str,
        invited_by_id: str,
        role: str = "developer",
        expires_days: int | None = None,
    ) -> UserInvitation:
        """Create a new user invitation.

        Args:
            db: Database session
            tenant_id: Tenant ID
            email: Email to invite
            invited_by_id: ID of user creating invitation
            role: Role to assign on acceptance
            expires_days: Days until expiration (default: 7)

        Returns:
            Created UserInvitation

        Raises:
            ValueError: If email is invalid or already has pending invitation
        """
        email = email.lower().strip()
        if not email or "@" not in email:
            raise ValueError("Invalid email address")

        # Check for existing pending invitation
        existing = await db.execute(
            select(UserInvitation).where(
                UserInvitation.email == email,
                UserInvitation.status == InvitationStatus.PENDING.value,
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Pending invitation already exists for {email}")

        # Check if user already exists
        existing_user = await db.execute(
            select(User).where(User.email == email)
        )
        if existing_user.scalar_one_or_none():
            raise ValueError(f"User with email {email} already exists")

        expires = expires_days or self.DEFAULT_INVITATION_DAYS
        invitation = UserInvitation(
            tenant_id=tenant_id,
            email=email,
            role=role,
            token=self.generate_invitation_token(),
            invited_by_id=invited_by_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires),
        )

        db.add(invitation)
        await db.commit()
        await db.refresh(invitation)
        return invitation

    async def get_invitation_by_token(
        self,
        db: AsyncSession,
        token: str,
    ) -> UserInvitation | None:
        """Get invitation by its token.

        Args:
            db: Database session
            token: Invitation token

        Returns:
            UserInvitation or None if not found
        """
        result = await db.execute(
            select(UserInvitation).where(UserInvitation.token == token)
        )
        return result.scalar_one_or_none()

    async def validate_invitation(
        self,
        db: AsyncSession,
        token: str,
    ) -> tuple[bool, str | None, UserInvitation | None]:
        """Validate an invitation token.

        Args:
            db: Database session
            token: Invitation token to validate

        Returns:
            Tuple of (is_valid, error_message, invitation)
        """
        invitation = await self.get_invitation_by_token(db, token)

        if not invitation:
            return False, "Invitation not found", None

        if invitation.status == InvitationStatus.REVOKED.value:
            return False, "Invitation has been revoked", invitation

        if invitation.status == InvitationStatus.ACCEPTED.value:
            return False, "Invitation has already been used", invitation

        if invitation.is_expired:
            # Update status if expired
            invitation.status = InvitationStatus.EXPIRED.value
            await db.commit()
            return False, "Invitation has expired", invitation

        return True, None, invitation

    async def accept_invitation(
        self,
        db: AsyncSession,
        invitation: UserInvitation,
        user: User,
    ) -> None:
        """Accept an invitation and link it to a user.

        Args:
            db: Database session
            invitation: The invitation to accept
            user: The user accepting the invitation
        """
        invitation.status = InvitationStatus.ACCEPTED.value
        invitation.accepted_at = datetime.now(timezone.utc)
        invitation.accepted_by_user_id = user.id

        # Link user to invitation
        user.invitation_id = invitation.id
        user.provisioning_source = "invitation"

        await db.commit()

    async def revoke_invitation(
        self,
        db: AsyncSession,
        invitation_id: str,
    ) -> bool:
        """Revoke a pending invitation.

        Args:
            db: Database session
            invitation_id: ID of invitation to revoke

        Returns:
            True if revoked, False if not found or already used
        """
        result = await db.execute(
            select(UserInvitation).where(UserInvitation.id == invitation_id)
        )
        invitation = result.scalar_one_or_none()

        if not invitation:
            return False

        if invitation.status != InvitationStatus.PENDING.value:
            return False

        invitation.status = InvitationStatus.REVOKED.value
        await db.commit()
        return True

    async def list_invitations(
        self,
        db: AsyncSession,
        tenant_id: str,
        status_filter: str | None = None,
    ) -> list[UserInvitation]:
        """List invitations for a tenant.

        Args:
            db: Database session
            tenant_id: Tenant ID
            status_filter: Optional status filter (pending, accepted, expired, revoked)

        Returns:
            List of UserInvitation objects
        """
        query = select(UserInvitation).where(
            UserInvitation.tenant_id == tenant_id
        )

        if status_filter:
            query = query.where(UserInvitation.status == status_filter)

        query = query.order_by(UserInvitation.created_at.desc())

        result = await db.execute(query)
        return list(result.scalars().all())

    # --- Auto-Provisioning Methods ---

    async def check_auto_provisioning(
        self,
        db: AsyncSession,
        email: str | None,
        github_orgs: list[str] | None = None,
    ) -> tuple[bool, str, str]:
        """Check if a user should be auto-provisioned.

        Args:
            db: Database session
            email: User's email address
            github_orgs: User's GitHub organization memberships

        Returns:
            Tuple of (should_provision, role, source)
            source can be: "first_user", "domain", "github_org", "invitation"
        """
        settings = await self.get_org_settings(db)

        # First, check if this is the first user
        user_count = await db.scalar(select(func.count()).select_from(User))
        if user_count == 0:
            return True, Role.ADMIN.value, "first_user"

        # Check for pending invitation
        if email:
            invitation_result = await db.execute(
                select(UserInvitation).where(
                    UserInvitation.email == email.lower(),
                    UserInvitation.status == InvitationStatus.PENDING.value,
                )
            )
            invitation = invitation_result.scalar_one_or_none()
            if invitation and invitation.is_valid:
                return True, invitation.role, "invitation"

        # Check provisioning mode
        mode = settings.provisioning_mode

        if mode == "open":
            # Anyone can join
            return True, settings.default_role, "open"

        if mode == "invitation_only":
            # Must have invitation (checked above)
            return False, "", ""

        # Domain check
        domain_match = False
        if email and settings.allowed_domains:
            email_domain = email.split("@")[-1].lower() if "@" in email else ""
            domain_match = email_domain in [d.lower() for d in settings.allowed_domains]

        # GitHub org check
        github_match = False
        if github_orgs and settings.allowed_github_orgs:
            github_match = any(
                org.lower() in [ao.lower() for ao in settings.allowed_github_orgs]
                for org in github_orgs
            )

        if mode == "domain" and domain_match:
            return True, settings.default_role, "domain"

        if mode == "github_org" and github_match:
            return True, settings.default_role, "github_org"

        if mode == "domain_and_github" and (domain_match or github_match):
            source = "domain" if domain_match else "github_org"
            return True, settings.default_role, source

        return False, "", ""

    # --- Provisioning Config Methods ---

    async def update_provisioning_config(
        self,
        db: AsyncSession,
        provisioning_mode: str | None = None,
        default_role: str | None = None,
        allowed_domains: list[str] | None = None,
        allowed_github_orgs: list[str] | None = None,
    ) -> OrganizationSettings:
        """Update provisioning configuration.

        Args:
            db: Database session
            provisioning_mode: New provisioning mode
            default_role: New default role
            allowed_domains: New allowed domains
            allowed_github_orgs: New allowed GitHub orgs

        Returns:
            Updated OrganizationSettings
        """
        settings = await self.get_org_settings(db)

        if provisioning_mode is not None:
            valid_modes = ["domain", "github_org", "invitation_only", "open", "domain_and_github"]
            if provisioning_mode not in valid_modes:
                raise ValueError(f"Invalid provisioning mode. Must be one of: {valid_modes}")
            settings.provisioning_mode = provisioning_mode

        if default_role is not None:
            valid_roles = [r.value for r in Role]
            if default_role not in valid_roles:
                raise ValueError(f"Invalid role. Must be one of: {valid_roles}")
            settings.default_role = default_role

        if allowed_domains is not None:
            settings.allowed_domains = [d.lower().strip() for d in allowed_domains if d.strip()]

        if allowed_github_orgs is not None:
            settings.allowed_github_orgs = [org.strip() for org in allowed_github_orgs if org.strip()]

        await db.commit()
        await db.refresh(settings)
        return settings

    async def add_allowed_github_org(
        self,
        db: AsyncSession,
        org: str,
    ) -> OrganizationSettings:
        """Add a GitHub organization to the allowed list.

        Args:
            db: Database session
            org: GitHub organization name

        Returns:
            Updated OrganizationSettings
        """
        org = org.strip()
        if not org:
            raise ValueError("Organization name cannot be empty")

        settings = await self.get_org_settings(db)

        if org.lower() not in [o.lower() for o in settings.allowed_github_orgs]:
            settings.allowed_github_orgs = [*settings.allowed_github_orgs, org]
            await db.commit()
            await db.refresh(settings)

        return settings

    async def remove_allowed_github_org(
        self,
        db: AsyncSession,
        org: str,
    ) -> OrganizationSettings:
        """Remove a GitHub organization from the allowed list.

        Args:
            db: Database session
            org: GitHub organization name

        Returns:
            Updated OrganizationSettings
        """
        settings = await self.get_org_settings(db)

        settings.allowed_github_orgs = [
            o for o in settings.allowed_github_orgs
            if o.lower() != org.lower()
        ]
        await db.commit()
        await db.refresh(settings)
        return settings


# Singleton instance
onboarding_service = OnboardingService()
