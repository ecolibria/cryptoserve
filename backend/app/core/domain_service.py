"""Domain-based access control service."""

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import OrganizationSettings, User


class DomainService:
    """Service for managing allowed email domains and access control."""

    @staticmethod
    def extract_domain(email: str) -> str | None:
        """Extract domain from email address.

        Args:
            email: Email address (e.g., "user@example.com")

        Returns:
            Domain part (e.g., "example.com") or None if invalid
        """
        if not email or "@" not in email:
            return None
        return email.split("@")[-1].lower()

    async def get_org_settings(self, db: AsyncSession) -> OrganizationSettings:
        """Get or create organization settings.

        Returns the singleton OrganizationSettings record, creating it if needed.
        """
        result = await db.execute(select(OrganizationSettings).limit(1))
        settings = result.scalar_one_or_none()

        if settings is None:
            # Create default settings from environment
            env_settings = get_settings()
            env_domains = []
            if env_settings.allowed_domains:
                env_domains = [
                    d.strip().lower()
                    for d in env_settings.allowed_domains.split(",")
                    if d.strip()
                ]

            settings = OrganizationSettings(
                allowed_domains=env_domains,
                admin_email=env_settings.admin_email or None,
                require_domain_match=env_settings.require_domain_verification,
                allow_any_github_user=not env_settings.require_domain_verification,
            )
            db.add(settings)
            await db.commit()
            await db.refresh(settings)

        return settings

    async def get_allowed_domains(self, db: AsyncSession) -> list[str]:
        """Get list of allowed email domains.

        Combines domains from database with any additional domains from env.
        Database takes precedence.
        """
        org_settings = await self.get_org_settings(db)

        if org_settings.allowed_domains:
            return org_settings.allowed_domains

        # Fall back to env var if database is empty
        env_settings = get_settings()
        if env_settings.allowed_domains:
            return [
                d.strip().lower()
                for d in env_settings.allowed_domains.split(",")
                if d.strip()
            ]

        return []

    async def is_domain_allowed(
        self,
        email: str,
        db: AsyncSession,
    ) -> bool:
        """Check if email domain is in allowed list.

        Args:
            email: The email address to check
            db: Database session

        Returns:
            True if the domain is allowed or domain checking is disabled
        """
        org_settings = await self.get_org_settings(db)

        # If any GitHub user is allowed, bypass domain check
        if org_settings.allow_any_github_user:
            return True

        # If domain matching not required, allow
        if not org_settings.require_domain_match:
            return True

        # Get allowed domains
        allowed_domains = await self.get_allowed_domains(db)

        # If no domains configured, allow all (open access)
        if not allowed_domains:
            return True

        # Extract domain from email
        domain = self.extract_domain(email)
        if not domain:
            return False

        # Check if domain matches (case-insensitive)
        return domain in [d.lower() for d in allowed_domains]

    async def add_domain(self, domain: str, db: AsyncSession) -> None:
        """Add a new allowed email domain.

        Args:
            domain: Domain to add (e.g., "example.com")
            db: Database session
        """
        domain = domain.strip().lower()
        if not domain:
            raise ValueError("Domain cannot be empty")

        # Basic validation
        if "." not in domain or len(domain) < 4:
            raise ValueError("Invalid domain format")

        org_settings = await self.get_org_settings(db)

        # Avoid duplicates
        if domain not in org_settings.allowed_domains:
            org_settings.allowed_domains = [
                *org_settings.allowed_domains,
                domain
            ]
            await db.commit()

    async def remove_domain(self, domain: str, db: AsyncSession) -> None:
        """Remove an allowed email domain.

        Args:
            domain: Domain to remove (e.g., "example.com")
            db: Database session
        """
        domain = domain.strip().lower()
        org_settings = await self.get_org_settings(db)

        org_settings.allowed_domains = [
            d for d in org_settings.allowed_domains
            if d.lower() != domain
        ]
        await db.commit()

    async def should_be_admin(
        self,
        user_email: str | None,
        db: AsyncSession,
    ) -> bool:
        """Determine if user should be granted admin role.

        A user should be admin if:
        1. Their email matches ADMIN_EMAIL env var
        2. They are the first user to register

        Args:
            user_email: The user's email address
            db: Database session

        Returns:
            True if user should be admin
        """
        env_settings = get_settings()

        # Check if ADMIN_EMAIL matches
        if env_settings.admin_email and user_email:
            if user_email.lower() == env_settings.admin_email.lower():
                return True

        # Check if this is the first user
        user_count = await db.scalar(
            select(func.count()).select_from(User)
        )
        if user_count == 0:
            return True

        return False

    async def update_settings(
        self,
        db: AsyncSession,
        *,
        require_domain_match: bool | None = None,
        allow_any_github_user: bool | None = None,
        organization_name: str | None = None,
    ) -> OrganizationSettings:
        """Update organization settings.

        Args:
            db: Database session
            require_domain_match: Whether to require email domain matching
            allow_any_github_user: Whether to allow any GitHub user
            organization_name: Organization name for branding

        Returns:
            Updated OrganizationSettings
        """
        org_settings = await self.get_org_settings(db)

        if require_domain_match is not None:
            org_settings.require_domain_match = require_domain_match

        if allow_any_github_user is not None:
            org_settings.allow_any_github_user = allow_any_github_user

        if organization_name is not None:
            org_settings.organization_name = organization_name

        await db.commit()
        await db.refresh(org_settings)
        return org_settings


# Singleton instance
domain_service = DomainService()
