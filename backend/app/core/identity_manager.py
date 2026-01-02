"""Identity creation and management."""

import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from slugify import slugify
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import Identity, IdentityType, IdentityStatus, User

settings = get_settings()


class IdentityManager:
    """Manages SDK identities."""

    def generate_identity_id(self, identity_type: IdentityType, name: str) -> str:
        """Generate unique identity ID."""
        prefix = "dev" if identity_type == IdentityType.DEVELOPER else "svc"
        name_slug = slugify(name, max_length=20, word_boundary=True)
        suffix = secrets.token_hex(4)
        return f"{prefix}_{name_slug}_{suffix}"

    def create_identity_token(self, identity: Identity) -> str:
        """Create signed JWT token for SDK identity."""
        # Use time.time() for accurate timestamps (not affected by timezone)
        now = int(time.time())
        # Calculate expiry in seconds from now
        expiry_delta = (identity.expires_at.replace(tzinfo=None) - identity.created_at.replace(tzinfo=None)).total_seconds()
        exp = now + int(expiry_delta)

        payload = {
            "iss": settings.backend_url,
            "sub": identity.id,
            "aud": "cryptoserve-sdk",
            "iat": now,
            "exp": exp,
            "type": identity.type.value,
            "name": identity.name,
            "team": identity.team,
            "env": identity.environment,
            "contexts": identity.allowed_contexts,
        }

        return jwt.encode(
            payload,
            settings.cryptoserve_master_key,
            algorithm="HS256",
        )

    def verify_identity_token(self, token: str) -> dict | None:
        """Verify and decode identity token."""
        try:
            payload = jwt.decode(
                token,
                settings.cryptoserve_master_key,
                algorithms=["HS256"],
                audience="cryptoserve-sdk",
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def create_identity(
        self,
        db: AsyncSession,
        user: User,
        name: str,
        identity_type: IdentityType,
        team: str,
        environment: str,
        allowed_contexts: list[str],
        expires_in_days: int | None = None,
    ) -> tuple[Identity, str]:
        """Create a new identity and return it with its token."""
        if expires_in_days is None:
            expires_in_days = settings.default_identity_expiration_days

        identity_id = self.generate_identity_id(identity_type, name)

        now = datetime.now(timezone.utc)
        identity = Identity(
            id=identity_id,
            tenant_id=user.tenant_id,
            user_id=user.id,
            type=identity_type,
            name=name,
            team=team,
            environment=environment,
            allowed_contexts=allowed_contexts,
            status=IdentityStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
        )

        db.add(identity)
        await db.commit()
        await db.refresh(identity)

        token = self.create_identity_token(identity)

        return identity, token

    async def get_identity_by_token(
        self,
        db: AsyncSession,
        token: str,
    ) -> Identity | None:
        """Get identity from token, validating status."""
        payload = self.verify_identity_token(token)
        if not payload:
            return None

        identity_id = payload.get("sub")
        if not identity_id:
            return None

        result = await db.execute(
            select(Identity).where(Identity.id == identity_id)
        )
        identity = result.scalar_one_or_none()

        if not identity:
            return None

        if not identity.is_active:
            return None

        return identity

    async def revoke_identity(
        self,
        db: AsyncSession,
        identity_id: str,
        user: User,
    ) -> bool:
        """Revoke an identity owned by the user."""
        result = await db.execute(
            select(Identity)
            .where(Identity.id == identity_id)
            .where(Identity.user_id == user.id)
        )
        identity = result.scalar_one_or_none()

        if not identity:
            return False

        identity.status = IdentityStatus.REVOKED
        await db.commit()

        return True


# Singleton instance
identity_manager = IdentityManager()
