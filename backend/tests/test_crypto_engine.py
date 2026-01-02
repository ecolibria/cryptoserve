"""Tests for the crypto engine."""

import pytest
from datetime import datetime, timedelta, timezone

from app.core.crypto_engine import crypto_engine, CryptoError, ContextNotFoundError, AuthorizationError
from app.core.key_manager import key_manager
from app.models import Identity, IdentityType, IdentityStatus, User, Context, Tenant


@pytest.mark.asyncio
async def test_key_derivation():
    """Test that key derivation is deterministic."""
    key1 = await key_manager.derive_key("test-context", 1)
    key2 = await key_manager.derive_key("test-context", 1)
    key3 = await key_manager.derive_key("test-context", 2)
    key4 = await key_manager.derive_key("other-context", 1)

    assert key1 == key2  # Same context and version = same key
    assert key1 != key3  # Different version = different key
    assert key1 != key4  # Different context = different key
    assert len(key1) == 32  # 256 bits


@pytest.mark.asyncio
async def test_encrypt_decrypt_roundtrip(db_session, test_user, test_context, test_tenant):
    """Test basic encrypt/decrypt roundtrip."""
    # Create identity with access to test context
    identity = Identity(
        id="test_identity_abc123",
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        type=IdentityType.DEVELOPER,
        name="Test Identity",
        team="test",
        environment="development",
        allowed_contexts=["test-context"],
        status=IdentityStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db_session.add(identity)
    await db_session.commit()

    # Encrypt
    plaintext = b"Hello, World!"
    result = await crypto_engine.encrypt(
        db=db_session,
        plaintext=plaintext,
        context_name="test-context",
        identity=identity,
    )

    assert result.ciphertext != plaintext
    assert len(result.ciphertext) > len(plaintext)  # Ciphertext includes header

    # Decrypt
    decrypted = await crypto_engine.decrypt(
        db=db_session,
        packed_ciphertext=result.ciphertext,
        context_name="test-context",
        identity=identity,
    )

    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_encrypt_unknown_context(db_session, test_user, test_tenant):
    """Test encryption with unknown context fails."""
    identity = Identity(
        id="test_identity_xyz789",
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        type=IdentityType.DEVELOPER,
        name="Test Identity",
        team="test",
        environment="development",
        allowed_contexts=["unknown-context"],
        status=IdentityStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db_session.add(identity)
    await db_session.commit()

    with pytest.raises(ContextNotFoundError):
        await crypto_engine.encrypt(
            db=db_session,
            plaintext=b"test",
            context_name="unknown-context",
            identity=identity,
        )


@pytest.mark.asyncio
async def test_encrypt_unauthorized_context(db_session, test_user, test_context, test_tenant):
    """Test encryption with unauthorized context fails."""
    # Identity without access to test-context
    identity = Identity(
        id="test_identity_noauth",
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        type=IdentityType.DEVELOPER,
        name="Test Identity",
        team="test",
        environment="development",
        allowed_contexts=["other-context"],  # Different context
        status=IdentityStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db_session.add(identity)
    await db_session.commit()

    with pytest.raises(AuthorizationError):
        await crypto_engine.encrypt(
            db=db_session,
            plaintext=b"test",
            context_name="test-context",
            identity=identity,
        )


@pytest.mark.asyncio
async def test_different_contexts_different_keys(db_session, test_user, test_tenant):
    """Test that different contexts produce different ciphertext."""
    # Create two contexts
    ctx1 = Context(
        tenant_id=test_tenant.id,
        name="context-1",
        display_name="Context 1",
        description="First context",
        algorithm="AES-256-GCM",
    )
    ctx2 = Context(
        tenant_id=test_tenant.id,
        name="context-2",
        display_name="Context 2",
        description="Second context",
        algorithm="AES-256-GCM",
    )
    db_session.add_all([ctx1, ctx2])
    await db_session.commit()

    identity = Identity(
        id="test_identity_multi",
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        type=IdentityType.DEVELOPER,
        name="Test Identity",
        team="test",
        environment="development",
        allowed_contexts=["context-1", "context-2"],
        status=IdentityStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db_session.add(identity)
    await db_session.commit()

    plaintext = b"same plaintext"

    ciphertext1 = await crypto_engine.encrypt(
        db=db_session,
        plaintext=plaintext,
        context_name="context-1",
        identity=identity,
    )

    ciphertext2 = await crypto_engine.encrypt(
        db=db_session,
        plaintext=plaintext,
        context_name="context-2",
        identity=identity,
    )

    # Different contexts should produce different ciphertext
    # (different keys, different nonces)
    assert ciphertext1 != ciphertext2
