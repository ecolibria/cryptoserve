"""Key bundle and rotation schemas.

Supports the unified key bundle model where each context has:
- Encryption key (AES/ChaCha20)
- MAC key (HMAC-SHA256/HMAC-SHA512)
- Signing key (optional, for contexts requiring signatures)
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def to_camel(string: str) -> str:
    """Convert snake_case to camelCase."""
    components = string.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


class KeyStatus(str, Enum):
    """Status of a cryptographic key."""
    ACTIVE = "ACTIVE"
    RETIRING = "RETIRING"
    RETIRED = "RETIRED"


class KeyType(str, Enum):
    """Type of cryptographic key in a bundle."""
    ENCRYPTION = "ENCRYPTION"
    MAC = "MAC"
    SIGNING = "SIGNING"


class KeyInfo(BaseModel):
    """Information about an individual key in a bundle."""
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    id: str = Field(description="Unique key identifier")
    algorithm: str = Field(description="Algorithm (e.g., AES-256-GCM, HMAC-SHA256)")
    version: int = Field(description="Key version number")
    status: KeyStatus = Field(description="Current key status")
    created_at: datetime = Field(description="When the key was created")
    expires_at: datetime = Field(description="When the key expires")
    rotation_schedule_days: int = Field(description="Days between rotations")
    last_rotated_at: datetime = Field(description="Last rotation timestamp")


class KeyBundle(BaseModel):
    """A complete key bundle for a context.

    Contains encryption, MAC, and optionally signing keys.
    """
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    id: str = Field(description="Bundle identifier")
    context_id: str = Field(description="Associated context name")
    version: int = Field(description="Bundle version")
    status: KeyStatus = Field(description="Bundle status")
    created_at: datetime = Field(description="Bundle creation time")
    encryption_key: KeyInfo = Field(description="Encryption key info")
    mac_key: KeyInfo = Field(description="MAC key info")
    signing_key: KeyInfo | None = Field(
        default=None,
        description="Signing key info (optional)"
    )


class KeyHistoryEntry(BaseModel):
    """A historical key rotation event."""
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    id: str = Field(description="History entry ID")
    context_id: str = Field(description="Context name")
    key_type: KeyType = Field(description="Type of key rotated")
    version: int = Field(description="New key version after rotation")
    algorithm: str = Field(description="Algorithm used")
    created_at: datetime = Field(description="When this version was created")
    retired_at: datetime | None = Field(
        default=None,
        description="When this version was retired"
    )
    status: KeyStatus = Field(description="Current status")
    rotation_reason: str | None = Field(
        default=None,
        description="Reason for rotation"
    )
    rotated_by: str | None = Field(
        default=None,
        description="User who initiated rotation"
    )


class RotateKeyRequest(BaseModel):
    """Request to rotate a key in a context."""
    key_type: KeyType = Field(description="Which key to rotate")
    reason: str = Field(
        default="scheduled",
        description="Reason for rotation (scheduled, security, compliance, manual)"
    )
    re_encrypt_data: bool = Field(
        default=False,
        description="Whether to re-encrypt existing data (encryption key only)"
    )


class RotateKeyResponse(BaseModel):
    """Response after key rotation."""
    success: bool
    message: str
    old_version: int
    new_version: int
    key_bundle: KeyBundle


class UpdateKeyScheduleRequest(BaseModel):
    """Request to update key rotation schedule."""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )

    rotation_schedule_days: int = Field(
        ge=1,
        le=3650,
        description="Days between key rotations (1-3650)"
    )


class UpdateKeyScheduleResponse(BaseModel):
    """Response after updating key schedule."""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )

    success: bool
    message: str
    key_type: KeyType
    old_schedule_days: int
    new_schedule_days: int
    next_rotation_at: datetime
