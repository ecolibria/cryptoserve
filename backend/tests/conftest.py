"""Test configuration and fixtures."""

import asyncio
import os
import pytest
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Set up test environment variables BEFORE importing app modules
os.environ.setdefault("CRYPTOSERVE_MASTER_KEY", "test-master-key-for-testing-only-32chars")
os.environ.setdefault("CRYPTOSERVE_HKDF_SALT", "test-hkdf-salt-for-tests")
os.environ.setdefault("KMS_BACKEND", "local")

from app.database import Base
from app.models import User, Context, Tenant


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def reset_kms_provider():
    """Reset KMS provider between tests to ensure clean state."""
    from app.core.kms.factory import reset_kms_provider
    from app.core.key_manager import key_manager

    reset_kms_provider()
    key_manager._initialized = False
    key_manager._kms = None
    yield
    reset_kms_provider()
    key_manager._initialized = False
    key_manager._kms = None


@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def test_tenant(db_session: AsyncSession) -> Tenant:
    """Create a test tenant."""
    tenant = Tenant(
        slug="test-tenant",
        name="Test Tenant",
        organization_name="Test Organization",
        primary_domain="example.com",
        allowed_domains=["example.com", "test.com"],
        require_domain_match=False,
        allow_any_github_user=True,
        is_active=True,
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest.fixture
async def test_user(db_session: AsyncSession, test_tenant: Tenant) -> User:
    """Create a test user."""
    user = User(
        tenant_id=test_tenant.id,
        github_id=12345,
        github_username="testuser",
        email="test@example.com",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_context(db_session: AsyncSession, test_tenant: Tenant) -> Context:
    """Create a test context."""
    context = Context(
        tenant_id=test_tenant.id,
        name="test-context",
        display_name="Test Context",
        description="A test context for unit tests",
        data_examples=["test data"],
        compliance_tags=["TEST"],
        algorithm="AES-256-GCM",
    )
    db_session.add(context)
    await db_session.commit()
    await db_session.refresh(context)
    return context


@pytest.fixture
async def user_pii_context(db_session: AsyncSession, test_tenant: Tenant) -> Context:
    """Create a user-pii context for hybrid encryption tests."""
    context = Context(
        tenant_id=test_tenant.id,
        name="user-pii",
        display_name="User PII",
        description="Personal identifiable information",
        data_examples=["email", "SSN", "phone"],
        compliance_tags=["GDPR", "SOC2"],
        algorithm="AES-256-GCM",
    )
    db_session.add(context)
    await db_session.commit()
    await db_session.refresh(context)
    return context
