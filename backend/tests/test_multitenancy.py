"""Tests for multi-tenancy isolation.

These tests verify that data is properly isolated between tenants.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Tenant,
    User,
    Context,
    Identity,
    IdentityType,
    IdentityStatus,
    AuditLog,
    Policy,
)


# --- Fixtures ---

@pytest.fixture
async def tenant_a(db_session: AsyncSession) -> Tenant:
    """Create tenant A for testing."""
    tenant = Tenant(
        id=str(uuid4()),
        slug="tenant-a",
        name="Tenant A",
        organization_name="Acme Corp",
        primary_domain="acme.com",
        allowed_domains=["acme.com"],
        require_domain_match=True,
        allow_any_github_user=False,
        is_active=True,
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest.fixture
async def tenant_b(db_session: AsyncSession) -> Tenant:
    """Create tenant B for testing."""
    tenant = Tenant(
        id=str(uuid4()),
        slug="tenant-b",
        name="Tenant B",
        organization_name="Beta Inc",
        primary_domain="beta.io",
        allowed_domains=["beta.io"],
        require_domain_match=True,
        allow_any_github_user=False,
        is_active=True,
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest.fixture
async def user_tenant_a(db_session: AsyncSession, tenant_a: Tenant) -> User:
    """Create a user in tenant A."""
    user = User(
        tenant_id=tenant_a.id,
        github_id=11111,
        github_username="user_a",
        email="user@acme.com",
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def user_tenant_b(db_session: AsyncSession, tenant_b: Tenant) -> User:
    """Create a user in tenant B."""
    user = User(
        tenant_id=tenant_b.id,
        github_id=22222,
        github_username="user_b",
        email="user@beta.io",
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def context_tenant_a(db_session: AsyncSession, tenant_a: Tenant) -> Context:
    """Create a context in tenant A."""
    context = Context(
        tenant_id=tenant_a.id,
        name="tenant-a-context",
        display_name="Tenant A Context",
        description="Context for tenant A only",
        algorithm="AES-256-GCM",
    )
    db_session.add(context)
    await db_session.commit()
    await db_session.refresh(context)
    return context


@pytest.fixture
async def context_tenant_b(db_session: AsyncSession, tenant_b: Tenant) -> Context:
    """Create a context in tenant B."""
    context = Context(
        tenant_id=tenant_b.id,
        name="tenant-b-context",
        display_name="Tenant B Context",
        description="Context for tenant B only",
        algorithm="AES-256-GCM",
    )
    db_session.add(context)
    await db_session.commit()
    await db_session.refresh(context)
    return context


# --- Tenant Model Tests ---

class TestTenantModel:
    """Tests for the Tenant model."""

    @pytest.mark.asyncio
    async def test_tenant_creation(self, db_session: AsyncSession):
        """Test creating a tenant."""
        tenant = Tenant(
            id=str(uuid4()),
            slug="test-tenant",
            name="Test Tenant",
            organization_name="Test Org",
            primary_domain="test.com",
            allowed_domains=["test.com", "*.test.com"],
            is_active=True,
        )
        db_session.add(tenant)
        await db_session.commit()

        # Verify it was created
        result = await db_session.execute(
            select(Tenant).where(Tenant.slug == "test-tenant")
        )
        saved = result.scalar_one_or_none()
        assert saved is not None
        assert saved.name == "Test Tenant"
        assert saved.organization_name == "Test Org"

    @pytest.mark.asyncio
    async def test_tenant_slug_uniqueness(self, db_session: AsyncSession, tenant_a: Tenant):
        """Test that tenant slugs must be unique."""
        duplicate = Tenant(
            id=str(uuid4()),
            slug=tenant_a.slug,  # Same slug
            name="Duplicate Tenant",
            is_active=True,
        )
        db_session.add(duplicate)

        with pytest.raises(Exception):  # IntegrityError
            await db_session.commit()

    @pytest.mark.asyncio
    async def test_email_domain_matching(self, tenant_a: Tenant):
        """Test email domain matching logic."""
        # Exact match
        assert tenant_a.matches_email_domain("user@acme.com") is True

        # No match
        assert tenant_a.matches_email_domain("user@other.com") is False

        # Invalid email
        assert tenant_a.matches_email_domain("invalid") is False
        assert tenant_a.matches_email_domain("") is False

    @pytest.mark.asyncio
    async def test_wildcard_domain_matching(self, db_session: AsyncSession):
        """Test wildcard domain matching."""
        tenant = Tenant(
            id=str(uuid4()),
            slug="wildcard-tenant",
            name="Wildcard Tenant",
            allowed_domains=["*.company.com"],
            is_active=True,
        )
        db_session.add(tenant)
        await db_session.commit()

        # Subdomain should match
        assert tenant.matches_email_domain("user@eng.company.com") is True
        assert tenant.matches_email_domain("user@sales.company.com") is True

        # Base domain should match
        assert tenant.matches_email_domain("user@company.com") is True

        # Different domain should not match
        assert tenant.matches_email_domain("user@other.com") is False


# --- User Tenant Isolation Tests ---

class TestUserTenantIsolation:
    """Tests for user tenant isolation."""

    @pytest.mark.asyncio
    async def test_user_belongs_to_single_tenant(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        tenant_a: Tenant,
    ):
        """Test that a user belongs to exactly one tenant."""
        assert user_tenant_a.tenant_id == tenant_a.id

    @pytest.mark.asyncio
    async def test_users_isolated_by_tenant(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        user_tenant_b: User,
        tenant_a: Tenant,
        tenant_b: Tenant,
    ):
        """Test that users are isolated by tenant."""
        # Query users for tenant A
        result_a = await db_session.execute(
            select(User).where(User.tenant_id == tenant_a.id)
        )
        users_a = result_a.scalars().all()

        # Query users for tenant B
        result_b = await db_session.execute(
            select(User).where(User.tenant_id == tenant_b.id)
        )
        users_b = result_b.scalars().all()

        # Each tenant should only see their own users
        assert len(users_a) == 1
        assert len(users_b) == 1
        assert users_a[0].id == user_tenant_a.id
        assert users_b[0].id == user_tenant_b.id


# --- Context Tenant Isolation Tests ---

class TestContextTenantIsolation:
    """Tests for context tenant isolation."""

    @pytest.mark.asyncio
    async def test_context_belongs_to_tenant(
        self,
        context_tenant_a: Context,
        tenant_a: Tenant,
    ):
        """Test that contexts belong to their tenant."""
        assert context_tenant_a.tenant_id == tenant_a.id

    @pytest.mark.asyncio
    async def test_contexts_isolated_by_tenant(
        self,
        db_session: AsyncSession,
        context_tenant_a: Context,
        context_tenant_b: Context,
        tenant_a: Tenant,
        tenant_b: Tenant,
    ):
        """Test that contexts are isolated by tenant."""
        # Query contexts for tenant A
        result_a = await db_session.execute(
            select(Context).where(Context.tenant_id == tenant_a.id)
        )
        contexts_a = result_a.scalars().all()

        # Query contexts for tenant B
        result_b = await db_session.execute(
            select(Context).where(Context.tenant_id == tenant_b.id)
        )
        contexts_b = result_b.scalars().all()

        # Each tenant should only see their own contexts
        assert len(contexts_a) == 1
        assert len(contexts_b) == 1
        assert contexts_a[0].name == "tenant-a-context"
        assert contexts_b[0].name == "tenant-b-context"

    @pytest.mark.asyncio
    async def test_context_uniqueness_within_tenant(
        self,
        db_session: AsyncSession,
        tenant_a: Tenant,
    ):
        """Test that context names must be unique within a tenant."""
        # Create first context
        context_1 = Context(
            tenant_id=tenant_a.id,
            name="unique-test-context",
            display_name="Context 1",
            description="First context",
            algorithm="AES-256-GCM",
        )
        db_session.add(context_1)
        await db_session.commit()

        # Try to create duplicate in same tenant
        context_2 = Context(
            tenant_id=tenant_a.id,
            name="unique-test-context",  # Same name
            display_name="Context 2",
            description="Duplicate context",
            algorithm="ChaCha20-Poly1305",
        )
        db_session.add(context_2)

        # Should fail due to unique constraint
        with pytest.raises(Exception):  # IntegrityError
            await db_session.commit()


# --- Identity Tenant Isolation Tests ---

class TestIdentityTenantIsolation:
    """Tests for identity tenant isolation."""

    @pytest.mark.asyncio
    async def test_identity_belongs_to_tenant(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        tenant_a: Tenant,
    ):
        """Test that identities are created with tenant_id."""
        identity = Identity(
            id="dev_test_123",
            tenant_id=tenant_a.id,
            user_id=user_tenant_a.id,
            type=IdentityType.DEVELOPER,
            name="Test Identity",
            team="engineering",
            environment="development",
            allowed_contexts=["general"],
            status=IdentityStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )
        db_session.add(identity)
        await db_session.commit()

        assert identity.tenant_id == tenant_a.id

    @pytest.mark.asyncio
    async def test_identities_isolated_by_tenant(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        user_tenant_b: User,
        tenant_a: Tenant,
        tenant_b: Tenant,
    ):
        """Test that identities are isolated by tenant."""
        # Create identity for tenant A
        identity_a = Identity(
            id="dev_a_123",
            tenant_id=tenant_a.id,
            user_id=user_tenant_a.id,
            type=IdentityType.DEVELOPER,
            name="Identity A",
            team="eng-a",
            environment="development",
            allowed_contexts=["general"],
            status=IdentityStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )

        # Create identity for tenant B
        identity_b = Identity(
            id="dev_b_456",
            tenant_id=tenant_b.id,
            user_id=user_tenant_b.id,
            type=IdentityType.DEVELOPER,
            name="Identity B",
            team="eng-b",
            environment="development",
            allowed_contexts=["general"],
            status=IdentityStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )

        db_session.add(identity_a)
        db_session.add(identity_b)
        await db_session.commit()

        # Query identities for tenant A
        result_a = await db_session.execute(
            select(Identity).where(Identity.tenant_id == tenant_a.id)
        )
        identities_a = result_a.scalars().all()

        # Query identities for tenant B
        result_b = await db_session.execute(
            select(Identity).where(Identity.tenant_id == tenant_b.id)
        )
        identities_b = result_b.scalars().all()

        # Each tenant should only see their own identities
        assert len(identities_a) == 1
        assert len(identities_b) == 1
        assert identities_a[0].name == "Identity A"
        assert identities_b[0].name == "Identity B"


# --- Audit Log Tenant Isolation Tests ---

class TestAuditLogTenantIsolation:
    """Tests for audit log tenant isolation."""

    @pytest.mark.asyncio
    async def test_audit_log_belongs_to_tenant(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        tenant_a: Tenant,
    ):
        """Test that audit logs are created with tenant_id."""
        audit = AuditLog(
            tenant_id=tenant_a.id,
            identity_id="dev_test_123",
            operation="encrypt",
            context="test-context",
            input_size_bytes=100,
            success=True,
            latency_ms=5,
        )
        db_session.add(audit)
        await db_session.commit()

        assert audit.tenant_id == tenant_a.id

    @pytest.mark.asyncio
    async def test_audit_logs_isolated_by_tenant(
        self,
        db_session: AsyncSession,
        tenant_a: Tenant,
        tenant_b: Tenant,
    ):
        """Test that audit logs are isolated by tenant."""
        # Create audit logs for both tenants
        for i in range(3):
            audit_a = AuditLog(
                tenant_id=tenant_a.id,
                identity_id="dev_a_123",
                operation="encrypt",
                context="tenant-a-context",
                input_size_bytes=100,
                success=True,
                latency_ms=5,
            )
            db_session.add(audit_a)

        for i in range(5):
            audit_b = AuditLog(
                tenant_id=tenant_b.id,
                identity_id="dev_b_456",
                operation="decrypt",
                context="tenant-b-context",
                input_size_bytes=200,
                success=True,
                latency_ms=3,
            )
            db_session.add(audit_b)

        await db_session.commit()

        # Query logs for tenant A
        result_a = await db_session.execute(
            select(AuditLog).where(AuditLog.tenant_id == tenant_a.id)
        )
        logs_a = result_a.scalars().all()

        # Query logs for tenant B
        result_b = await db_session.execute(
            select(AuditLog).where(AuditLog.tenant_id == tenant_b.id)
        )
        logs_b = result_b.scalars().all()

        # Each tenant should only see their own logs
        assert len(logs_a) == 3
        assert len(logs_b) == 5
        assert all(log.context == "tenant-a-context" for log in logs_a)
        assert all(log.context == "tenant-b-context" for log in logs_b)


# --- Policy Tenant Isolation Tests ---

class TestPolicyTenantIsolation:
    """Tests for policy tenant isolation."""

    @pytest.mark.asyncio
    async def test_policy_belongs_to_tenant(
        self,
        db_session: AsyncSession,
        context_tenant_a: Context,
        tenant_a: Tenant,
    ):
        """Test that policies are created with tenant_id."""
        policy = Policy(
            tenant_id=tenant_a.id,
            name="test-policy",
            description="Test policy",
            rule="true",
            severity="info",
            message="Test message",
            enabled=True,
            linked_context=context_tenant_a.name,
        )
        db_session.add(policy)
        await db_session.commit()

        assert policy.tenant_id == tenant_a.id

    @pytest.mark.asyncio
    async def test_policies_isolated_by_tenant(
        self,
        db_session: AsyncSession,
        context_tenant_a: Context,
        context_tenant_b: Context,
        tenant_a: Tenant,
        tenant_b: Tenant,
    ):
        """Test that policies are isolated by tenant."""
        # Create policies for both tenants
        policy_a = Policy(
            tenant_id=tenant_a.id,
            name="policy-a",
            description="Policy A",
            rule="true",
            severity="info",
            message="Policy A message",
            enabled=True,
            linked_context=context_tenant_a.name,
        )
        policy_b = Policy(
            tenant_id=tenant_b.id,
            name="policy-b",
            description="Policy B",
            rule="true",
            severity="info",
            message="Policy B message",
            enabled=True,
            linked_context=context_tenant_b.name,
        )

        db_session.add(policy_a)
        db_session.add(policy_b)
        await db_session.commit()

        # Query policies for tenant A
        result_a = await db_session.execute(
            select(Policy).where(Policy.tenant_id == tenant_a.id)
        )
        policies_a = result_a.scalars().all()

        # Query policies for tenant B
        result_b = await db_session.execute(
            select(Policy).where(Policy.tenant_id == tenant_b.id)
        )
        policies_b = result_b.scalars().all()

        # Each tenant should only see their own policies
        assert len(policies_a) == 1
        assert len(policies_b) == 1
        assert policies_a[0].name == "policy-a"
        assert policies_b[0].name == "policy-b"


# --- Cross-Tenant Access Prevention Tests ---

class TestCrossTenantPrevention:
    """Tests to verify cross-tenant access is prevented."""

    @pytest.mark.asyncio
    async def test_user_cannot_see_other_tenant_contexts(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        context_tenant_b: Context,
        tenant_a: Tenant,
    ):
        """Verify that querying with tenant filter excludes other tenant's data."""
        # User A tries to query contexts with tenant A filter
        result = await db_session.execute(
            select(Context).where(
                Context.tenant_id == tenant_a.id,
                Context.name == context_tenant_b.name  # Trying to access B's context
            )
        )
        context = result.scalar_one_or_none()

        # Should not find tenant B's context
        assert context is None

    @pytest.mark.asyncio
    async def test_user_cannot_see_other_tenant_users(
        self,
        db_session: AsyncSession,
        user_tenant_a: User,
        user_tenant_b: User,
        tenant_a: Tenant,
    ):
        """Verify that querying with tenant filter excludes other tenant's users."""
        # Query users with tenant A filter trying to find user B
        result = await db_session.execute(
            select(User).where(
                User.tenant_id == tenant_a.id,
                User.id == user_tenant_b.id  # Trying to access B's user
            )
        )
        user = result.scalar_one_or_none()

        # Should not find tenant B's user
        assert user is None

    @pytest.mark.asyncio
    async def test_tenant_filter_is_required_pattern(
        self,
        db_session: AsyncSession,
        context_tenant_a: Context,
        context_tenant_b: Context,
    ):
        """Demonstrate the importance of tenant filtering."""
        # WITHOUT tenant filter - sees ALL contexts (BAD)
        result_all = await db_session.execute(select(Context))
        all_contexts = result_all.scalars().all()

        # WITH tenant filter - sees only own contexts (GOOD)
        result_a = await db_session.execute(
            select(Context).where(Context.tenant_id == context_tenant_a.tenant_id)
        )
        tenant_a_contexts = result_a.scalars().all()

        # Without filter, we see both; with filter, we see only one
        assert len(all_contexts) >= 2
        assert len(tenant_a_contexts) == 1
