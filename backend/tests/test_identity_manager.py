"""Tests for the identity manager."""

import pytest
from datetime import datetime, timedelta

from app.core.identity_manager import identity_manager
from app.models import Identity, IdentityType, IdentityStatus, User, Tenant


@pytest.mark.asyncio
async def test_create_identity(db_session, test_user):
    """Test creating an identity."""
    identity, token = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Test Identity",
        identity_type=IdentityType.DEVELOPER,
        team="engineering",
        environment="development",
        allowed_contexts=["user-pii", "general"],
        expires_in_days=90,
    )

    assert identity.id.startswith("dev_")
    assert identity.name == "Test Identity"
    assert identity.team == "engineering"
    assert identity.environment == "development"
    assert identity.allowed_contexts == ["user-pii", "general"]
    assert identity.status == IdentityStatus.ACTIVE
    assert token is not None


@pytest.mark.asyncio
async def test_create_service_identity(db_session, test_user):
    """Test creating a service identity."""
    identity, token = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Checkout Service",
        identity_type=IdentityType.SERVICE,
        team="payments",
        environment="production",
        allowed_contexts=["payment-data"],
        expires_in_days=365,
    )

    assert identity.id.startswith("svc_")
    assert identity.type == IdentityType.SERVICE


@pytest.mark.asyncio
async def test_identity_token_roundtrip(db_session, test_user):
    """Test creating and validating an identity token."""
    identity, token = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Token Test",
        identity_type=IdentityType.DEVELOPER,
        team="test",
        environment="development",
        allowed_contexts=["general"],
    )

    # Verify token
    payload = identity_manager.verify_identity_token(token)
    assert payload is not None
    assert payload["sub"] == identity.id
    assert payload["name"] == "Token Test"
    assert payload["team"] == "test"
    assert payload["contexts"] == ["general"]


@pytest.mark.asyncio
async def test_get_identity_by_token(db_session, test_user):
    """Test retrieving identity by token."""
    identity, token = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Retrieve Test",
        identity_type=IdentityType.DEVELOPER,
        team="test",
        environment="development",
        allowed_contexts=["general"],
    )

    retrieved = await identity_manager.get_identity_by_token(db_session, token)
    assert retrieved is not None
    assert retrieved.id == identity.id


@pytest.mark.asyncio
async def test_get_identity_invalid_token(db_session):
    """Test retrieving identity with invalid token."""
    retrieved = await identity_manager.get_identity_by_token(
        db_session,
        "invalid-token"
    )
    assert retrieved is None


@pytest.mark.asyncio
async def test_revoke_identity(db_session, test_user):
    """Test revoking an identity."""
    identity, token = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Revoke Test",
        identity_type=IdentityType.DEVELOPER,
        team="test",
        environment="development",
        allowed_contexts=["general"],
    )

    # Revoke
    success = await identity_manager.revoke_identity(
        db_session,
        identity.id,
        test_user
    )
    assert success

    # Refresh and check status
    await db_session.refresh(identity)
    assert identity.status == IdentityStatus.REVOKED

    # Should not be able to retrieve revoked identity
    retrieved = await identity_manager.get_identity_by_token(db_session, token)
    assert retrieved is None


@pytest.mark.asyncio
async def test_revoke_other_users_identity(db_session, test_user, test_tenant):
    """Test that users cannot revoke other users' identities."""
    identity, _ = await identity_manager.create_identity(
        db=db_session,
        user=test_user,
        name="Other User Identity",
        identity_type=IdentityType.DEVELOPER,
        team="test",
        environment="development",
        allowed_contexts=["general"],
    )

    # Create another user in the same tenant
    other_user = User(
        tenant_id=test_tenant.id,
        github_id=99999,
        github_username="otheruser",
        email="other@example.com",
    )
    db_session.add(other_user)
    await db_session.commit()

    # Try to revoke with other user
    success = await identity_manager.revoke_identity(
        db_session,
        identity.id,
        other_user
    )
    assert not success


@pytest.mark.asyncio
async def test_identity_id_format():
    """Test identity ID generation format."""
    dev_id = identity_manager.generate_identity_id(
        IdentityType.DEVELOPER,
        "Alice Smith"
    )
    svc_id = identity_manager.generate_identity_id(
        IdentityType.SERVICE,
        "Checkout Service"
    )

    assert dev_id.startswith("dev_")
    assert svc_id.startswith("svc_")
    assert "alice" in dev_id.lower()
    assert "checkout" in svc_id.lower()
