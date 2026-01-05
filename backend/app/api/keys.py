"""Key bundle API routes.

Provides endpoints for viewing and managing key bundles per context.
Key bundles contain encryption, MAC, and optionally signing keys.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated
from uuid import uuid4
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Context, Key, AuditLog
from app.models.key import KeyStatus as ModelKeyStatus
from app.schemas.keys import (
    KeyStatus,
    KeyType,
    KeyInfo,
    KeyBundle,
    KeyHistoryEntry,
    RotateKeyRequest,
    RotateKeyResponse,
    UpdateKeyScheduleRequest,
    UpdateKeyScheduleResponse,
)

router = APIRouter(prefix="/api/v1/contexts", tags=["keys"])


# =============================================================================
# Helper Functions
# =============================================================================

def generate_key_id(context_name: str, key_type: str, version: int) -> str:
    """Generate a deterministic key ID."""
    data = f"{context_name}:{key_type}:{version}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def get_rotation_days(context: Context) -> int:
    """Get key rotation period from context config or default."""
    if context.derived and "key_rotation_days" in context.derived:
        return context.derived["key_rotation_days"]
    if context.config and "threat_model" in context.config:
        # Shorter rotation for higher sensitivity
        sensitivity = context.config.get("data_identity", {}).get("sensitivity", "medium")
        if sensitivity == "critical":
            return 30
        elif sensitivity == "high":
            return 60
        elif sensitivity == "medium":
            return 90
    return 90  # Default


def build_key_info(
    key: Key | None,
    context: Context,
    key_type: KeyType,
    algorithm: str,
) -> KeyInfo:
    """Build KeyInfo from a Key model or create synthetic one."""
    now = datetime.now(timezone.utc)
    rotation_days = get_rotation_days(context)

    if key:
        created_at = key.created_at
        version = key.version
        key_id = key.id
        key_status = KeyStatus.ACTIVE if key.status == ModelKeyStatus.ACTIVE else KeyStatus.RETIRED
    else:
        # Create synthetic key info for contexts without explicit keys
        created_at = context.created_at
        version = 1
        key_id = generate_key_id(context.name, key_type.value, version)
        key_status = KeyStatus.ACTIVE

    expires_at = created_at + timedelta(days=rotation_days)
    last_rotated_at = created_at

    return KeyInfo(
        id=key_id,
        algorithm=algorithm,
        version=version,
        status=key_status,
        created_at=created_at,
        expires_at=expires_at,
        rotation_schedule_days=rotation_days,
        last_rotated_at=last_rotated_at,
    )


def get_algorithm_for_key_type(context: Context, key_type: KeyType) -> str:
    """Get the algorithm for a specific key type from context."""
    if key_type == KeyType.ENCRYPTION:
        return context.algorithm or "AES-256-GCM"
    elif key_type == KeyType.MAC:
        # Derive MAC algorithm from encryption algorithm
        if "256" in (context.algorithm or ""):
            return "HMAC-SHA256"
        return "HMAC-SHA256"
    elif key_type == KeyType.SIGNING:
        # Check if quantum-safe signing needed
        if context.quantum_resistant:
            return "ML-DSA-65"
        return "ECDSA-P256"
    return "AES-256-GCM"


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/{name}/keys", response_model=KeyBundle)
async def get_key_bundle(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the key bundle for a context.

    Returns information about the encryption, MAC, and signing keys
    for the specified context. Key material is never exposed.
    """
    # Get the context
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    # Get existing keys for this context
    keys_result = await db.execute(
        select(Key).where(
            Key.context == name,
            Key.tenant_id == user.tenant_id,
            Key.status == ModelKeyStatus.ACTIVE
        ).order_by(Key.version.desc())
    )
    keys = {k.id: k for k in keys_result.scalars().all()}

    # Build key bundle
    now = datetime.now(timezone.utc)
    rotation_days = get_rotation_days(context)

    # Find or create key info for each type
    encryption_key = build_key_info(
        None,  # Keys are derived from master key, no explicit storage
        context,
        KeyType.ENCRYPTION,
        get_algorithm_for_key_type(context, KeyType.ENCRYPTION),
    )

    mac_key = build_key_info(
        None,
        context,
        KeyType.MAC,
        get_algorithm_for_key_type(context, KeyType.MAC),
    )

    # Signing key is optional - check if context needs signatures
    signing_key = None
    if context.config:
        sensitivity = context.config.get("data_identity", {}).get("sensitivity", "medium")
        if sensitivity in ["critical", "high"]:
            signing_key = build_key_info(
                None,
                context,
                KeyType.SIGNING,
                get_algorithm_for_key_type(context, KeyType.SIGNING),
            )

    bundle_id = generate_key_id(name, "bundle", 1)

    return KeyBundle(
        id=bundle_id,
        context_id=name,
        version=1,
        status=KeyStatus.ACTIVE,
        created_at=context.created_at,
        encryption_key=encryption_key,
        mac_key=mac_key,
        signing_key=signing_key,
    )


@router.get("/{name}/keys/history", response_model=list[KeyHistoryEntry])
async def get_key_history(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
):
    """Get the key rotation history for a context.

    Returns historical key rotation events for audit purposes.
    """
    # Verify context exists and user has access
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    # Get all keys for this context (including retired)
    keys_result = await db.execute(
        select(Key).where(
            Key.context == name,
            Key.tenant_id == user.tenant_id
        ).order_by(Key.version.desc()).limit(limit)
    )
    keys = keys_result.scalars().all()

    # Build history entries
    history = []

    # If no keys in DB, create synthetic history entry for initial key
    if not keys:
        history.append(KeyHistoryEntry(
            id=str(uuid4()),
            context_id=name,
            key_type=KeyType.ENCRYPTION,
            version=1,
            algorithm=context.algorithm or "AES-256-GCM",
            created_at=context.created_at,
            retired_at=None,
            status=KeyStatus.ACTIVE,
            rotation_reason="initial",
            rotated_by="system",
        ))
    else:
        for key in keys:
            key_status = KeyStatus.ACTIVE if key.status == ModelKeyStatus.ACTIVE else KeyStatus.RETIRED
            history.append(KeyHistoryEntry(
                id=key.id,
                context_id=name,
                key_type=KeyType.ENCRYPTION,  # Keys model doesn't track type yet
                version=key.version,
                algorithm=context.algorithm or "AES-256-GCM",
                created_at=key.created_at,
                retired_at=None if key.status == ModelKeyStatus.ACTIVE else key.created_at,
                status=key_status,
                rotation_reason="scheduled",
                rotated_by="system",
            ))

    return history


@router.post("/{name}/keys/rotate", response_model=RotateKeyResponse)
async def rotate_key(
    name: str,
    request: RotateKeyRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Rotate a key in a context.

    Creates a new key version and marks the old one as retiring.
    For encryption keys, optionally re-encrypts existing data.
    """
    # Verify context exists and user has access
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    # Get current version
    version_result = await db.execute(
        select(func.max(Key.version)).where(
            Key.context == name,
            Key.tenant_id == user.tenant_id
        )
    )
    current_version = version_result.scalar() or 0
    new_version = current_version + 1

    # Mark old keys as rotated
    await db.execute(
        select(Key).where(
            Key.context == name,
            Key.tenant_id == user.tenant_id,
            Key.status == ModelKeyStatus.ACTIVE
        )
    )
    old_keys = (await db.execute(
        select(Key).where(
            Key.context == name,
            Key.tenant_id == user.tenant_id,
            Key.status == ModelKeyStatus.ACTIVE
        )
    )).scalars().all()

    for old_key in old_keys:
        old_key.status = ModelKeyStatus.ROTATED

    # Create new key record
    new_key_id = generate_key_id(name, request.key_type.value, new_version)
    new_key = Key(
        id=new_key_id,
        tenant_id=user.tenant_id,
        context=name,
        version=new_version,
        status=ModelKeyStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_key)

    # Log the rotation
    audit_log = AuditLog(
        tenant_id=user.tenant_id,
        operation="key_rotate",
        context=name,
        success=True,
        identity_id=user.github_id,
        identity_name=user.github_username,
        algorithm=context.algorithm,
    )
    db.add(audit_log)

    await db.commit()

    # Build response with updated key bundle
    rotation_days = get_rotation_days(context)
    now = datetime.now(timezone.utc)

    encryption_key = KeyInfo(
        id=new_key_id if request.key_type == KeyType.ENCRYPTION else generate_key_id(name, "ENCRYPTION", new_version),
        algorithm=get_algorithm_for_key_type(context, KeyType.ENCRYPTION),
        version=new_version,
        status=KeyStatus.ACTIVE,
        created_at=now,
        expires_at=now + timedelta(days=rotation_days),
        rotation_schedule_days=rotation_days,
        last_rotated_at=now,
    )

    mac_key = KeyInfo(
        id=new_key_id if request.key_type == KeyType.MAC else generate_key_id(name, "MAC", new_version),
        algorithm=get_algorithm_for_key_type(context, KeyType.MAC),
        version=new_version,
        status=KeyStatus.ACTIVE,
        created_at=now,
        expires_at=now + timedelta(days=rotation_days),
        rotation_schedule_days=rotation_days,
        last_rotated_at=now,
    )

    signing_key = None
    if context.config:
        sensitivity = context.config.get("data_identity", {}).get("sensitivity", "medium")
        if sensitivity in ["critical", "high"]:
            signing_key = KeyInfo(
                id=new_key_id if request.key_type == KeyType.SIGNING else generate_key_id(name, "SIGNING", new_version),
                algorithm=get_algorithm_for_key_type(context, KeyType.SIGNING),
                version=new_version,
                status=KeyStatus.ACTIVE,
                created_at=now,
                expires_at=now + timedelta(days=rotation_days),
                rotation_schedule_days=rotation_days,
                last_rotated_at=now,
            )

    bundle = KeyBundle(
        id=generate_key_id(name, "bundle", new_version),
        context_id=name,
        version=new_version,
        status=KeyStatus.ACTIVE,
        created_at=now,
        encryption_key=encryption_key,
        mac_key=mac_key,
        signing_key=signing_key,
    )

    return RotateKeyResponse(
        success=True,
        message=f"Successfully rotated {request.key_type.value} key for context {name}",
        old_version=current_version,
        new_version=new_version,
        key_bundle=bundle,
    )


@router.put("/{name}/keys/{key_type}/schedule", response_model=UpdateKeyScheduleResponse)
async def update_key_schedule(
    name: str,
    key_type: KeyType,
    request: UpdateKeyScheduleRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update the rotation schedule for a key type in a context.

    Changes how frequently the specified key type should be rotated.
    Valid range is 1-3650 days.
    """
    # Verify context exists and user has access
    result = await db.execute(
        select(Context).where(
            Context.name == name,
            Context.tenant_id == user.tenant_id
        )
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    # Get current rotation schedule
    old_schedule_days = get_rotation_days(context)
    new_schedule_days = request.rotation_schedule_days

    # Update context derived config with new rotation schedule
    if not context.derived:
        context.derived = {}

    # Store per-key-type schedule if needed, or use global for now
    context.derived["key_rotation_days"] = new_schedule_days

    # Calculate next rotation date
    now = datetime.now(timezone.utc)
    next_rotation_at = now + timedelta(days=new_schedule_days)

    # Log the schedule update
    audit_log = AuditLog(
        tenant_id=user.tenant_id,
        operation="key_schedule_update",
        context=name,
        success=True,
        identity_id=user.github_id,
        identity_name=user.github_username,
        algorithm=context.algorithm,
    )
    db.add(audit_log)

    await db.commit()

    return UpdateKeyScheduleResponse(
        success=True,
        message=f"Updated {key_type.value} key rotation schedule from {old_schedule_days} to {new_schedule_days} days",
        key_type=key_type,
        old_schedule_days=old_schedule_days,
        new_schedule_days=new_schedule_days,
        next_rotation_at=next_rotation_at,
    )
