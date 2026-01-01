"""Application creation and management with Ed25519 tokens."""

import secrets
from datetime import datetime, timedelta, timezone

from slugify import slugify
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.application import Application, ApplicationStatus
from app.models import User
from app.core.token_manager import token_manager

settings = get_settings()


class ApplicationManager:
    """Manages SDK applications with Ed25519 tokens."""

    def generate_application_id(self, name: str) -> str:
        """Generate unique application ID."""
        name_slug = slugify(name, max_length=20, word_boundary=True)
        suffix = secrets.token_hex(4)
        return f"app_{name_slug}_{suffix}"

    async def create_application(
        self,
        db: AsyncSession,
        user: User,
        name: str,
        team: str,
        environment: str,
        allowed_contexts: list[str],
        description: str | None = None,
        expires_in_days: int | None = None,
    ) -> tuple[Application, str, str]:
        """Create a new application with Ed25519 keypair.

        Args:
            db: Database session
            user: Owner user
            name: Application name
            team: Team name
            environment: Environment (production, staging, development)
            allowed_contexts: List of allowed encryption contexts
            description: Optional description
            expires_in_days: Days until application expires

        Returns:
            Tuple of (application, access_token, refresh_token)
        """
        if expires_in_days is None:
            expires_in_days = settings.default_identity_expiration_days

        app_id = self.generate_application_id(name)
        now = datetime.now(timezone.utc)

        # Generate Ed25519 keypair
        private_key_pem, public_key_pem = token_manager.generate_keypair()

        # Encrypt private key for storage
        private_key_encrypted = token_manager.encrypt_private_key(private_key_pem)

        # Create refresh token
        refresh_token, refresh_token_hash, refresh_expires = token_manager.create_refresh_token(app_id)

        # Create application record
        application = Application(
            id=app_id,
            user_id=user.id,
            name=name,
            description=description,
            team=team,
            environment=environment,
            allowed_contexts=allowed_contexts,
            status=ApplicationStatus.ACTIVE.value,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
            public_key=public_key_pem.decode('utf-8'),
            private_key_encrypted=private_key_encrypted,
            key_created_at=now,
            refresh_token_hash=refresh_token_hash,
            refresh_token_expires_at=refresh_expires,
        )

        db.add(application)
        await db.commit()
        await db.refresh(application)

        # Create access token
        access_token, _ = token_manager.create_access_token(
            app_id=app_id,
            app_name=name,
            team=team,
            environment=environment,
            contexts=allowed_contexts,
            private_key_pem=private_key_pem,
        )

        return application, access_token, refresh_token

    async def refresh_access_token(
        self,
        db: AsyncSession,
        refresh_token: str,
    ) -> tuple[str, datetime] | None:
        """Exchange refresh token for new access token.

        Args:
            db: Database session
            refresh_token: Current refresh token

        Returns:
            Tuple of (new_access_token, expires_at) or None if invalid
        """
        # Decode to get app_id (unverified)
        payload = token_manager.decode_token_unverified(refresh_token)
        if not payload:
            return None

        app_id = payload.get("sub")
        if not app_id:
            return None

        # Look up application
        result = await db.execute(
            select(Application).where(Application.id == app_id)
        )
        application = result.scalar_one_or_none()

        if not application:
            return None

        if not application.is_active:
            return None

        if not application.refresh_token_hash:
            return None

        # Verify refresh token
        verified = token_manager.verify_refresh_token(
            refresh_token,
            application.refresh_token_hash,
        )
        if not verified:
            return None

        # Decrypt private key
        private_key_pem = token_manager.decrypt_private_key(
            application.private_key_encrypted
        )

        # Create new access token
        access_token, expires_at = token_manager.create_access_token(
            app_id=application.id,
            app_name=application.name,
            team=application.team,
            environment=application.environment,
            contexts=application.allowed_contexts,
            private_key_pem=private_key_pem,
        )

        # Update last used
        application.last_used_at = datetime.now(timezone.utc)
        await db.commit()

        return access_token, expires_at

    async def rotate_refresh_token(
        self,
        db: AsyncSession,
        application: Application,
    ) -> str:
        """Issue new refresh token, invalidate old.

        Args:
            db: Database session
            application: Application to rotate token for

        Returns:
            New refresh token
        """
        now = datetime.now(timezone.utc)

        # Generate new refresh token
        refresh_token, refresh_token_hash, refresh_expires = token_manager.create_refresh_token(
            application.id
        )

        # Update application
        application.refresh_token_hash = refresh_token_hash
        application.refresh_token_expires_at = refresh_expires
        application.refresh_token_rotated_at = now

        await db.commit()

        return refresh_token

    async def revoke_tokens(
        self,
        db: AsyncSession,
        application: Application,
    ) -> None:
        """Immediately revoke all tokens for application.

        Args:
            db: Database session
            application: Application to revoke tokens for
        """
        now = datetime.now(timezone.utc)

        # Clear refresh token (invalidates immediately)
        application.refresh_token_hash = None
        application.refresh_token_expires_at = None
        application.refresh_token_rotated_at = now

        await db.commit()

    async def get_application_by_access_token(
        self,
        db: AsyncSession,
        access_token: str,
    ) -> Application | None:
        """Get application from access token, validating signature.

        Args:
            db: Database session
            access_token: JWT access token

        Returns:
            Application if valid, None otherwise
        """
        # First decode without verification to get app_id
        payload = token_manager.decode_token_unverified(access_token)
        if not payload:
            return None

        app_id = payload.get("sub")
        if not app_id:
            return None

        # Look up application
        result = await db.execute(
            select(Application).where(Application.id == app_id)
        )
        application = result.scalar_one_or_none()

        if not application:
            return None

        if not application.is_active:
            return None

        # Verify token with application's public key
        verified = token_manager.verify_access_token(
            access_token,
            application.public_key.encode('utf-8'),
        )
        if not verified:
            return None

        # Update last used
        application.last_used_at = datetime.now(timezone.utc)
        await db.commit()

        return application

    async def revoke_application(
        self,
        db: AsyncSession,
        app_id: str,
        user: User,
    ) -> bool:
        """Revoke an application owned by the user.

        Args:
            db: Database session
            app_id: Application ID
            user: Owner user

        Returns:
            True if revoked, False if not found
        """
        result = await db.execute(
            select(Application)
            .where(Application.id == app_id)
            .where(Application.user_id == user.id)
        )
        application = result.scalar_one_or_none()

        if not application:
            return False

        application.status = ApplicationStatus.REVOKED.value
        application.refresh_token_hash = None  # Immediate revocation
        await db.commit()

        return True

    async def update_application(
        self,
        db: AsyncSession,
        application: Application,
        name: str | None = None,
        description: str | None = None,
        allowed_contexts: list[str] | None = None,
    ) -> Application:
        """Update application metadata.

        Args:
            db: Database session
            application: Application to update
            name: New name (optional)
            description: New description (optional)
            allowed_contexts: New contexts (optional)

        Returns:
            Updated application
        """
        if name is not None:
            application.name = name
        if description is not None:
            application.description = description
        if allowed_contexts is not None:
            application.allowed_contexts = allowed_contexts

        await db.commit()
        await db.refresh(application)

        return application


# Singleton instance
application_manager = ApplicationManager()

# Backward compatibility
identity_manager = application_manager
