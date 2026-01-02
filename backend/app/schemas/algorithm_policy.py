"""Algorithm policy schemas for classification-level defaults.

Defines default algorithm settings per data classification level.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def to_camel(string: str) -> str:
    """Convert snake_case to camelCase."""
    components = string.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


class DataClassification(str, Enum):
    """Data classification levels."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    CRITICAL = "CRITICAL"


class ClassificationAlgorithmPolicy(BaseModel):
    """Algorithm policy defaults for a classification level.

    Admins can set organization-wide defaults per classification,
    which contexts inherit unless explicitly overridden.
    """
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    classification: DataClassification = Field(
        description="Data classification level"
    )
    default_encryption_algorithm: str = Field(
        description="Default encryption algorithm (e.g., AES-256-GCM)"
    )
    default_mac_algorithm: str = Field(
        description="Default MAC algorithm (e.g., HMAC-SHA256)"
    )
    default_signing_algorithm: str | None = Field(
        default=None,
        description="Default signing algorithm (e.g., ECDSA-P256)"
    )
    min_key_bits: int = Field(
        default=128,
        ge=128,
        le=512,
        description="Minimum key size in bits"
    )
    key_rotation_days: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Default key rotation period in days"
    )
    require_quantum_safe: bool = Field(
        default=False,
        description="Require quantum-safe algorithms"
    )
    allowed_ciphers: list[str] = Field(
        default_factory=lambda: ["AES", "ChaCha20"],
        description="Allowed cipher families"
    )
    allowed_modes: list[str] = Field(
        default_factory=lambda: ["gcm", "gcm-siv", "ccm"],
        description="Allowed cipher modes"
    )
    updated_at: datetime | None = Field(
        default=None,
        description="Last update timestamp"
    )
    updated_by: str | None = Field(
        default=None,
        description="User who last updated"
    )


class UpdateClassificationPolicyRequest(BaseModel):
    """Request to update a classification's algorithm policy."""
    default_encryption_algorithm: str | None = Field(
        default=None,
        description="New default encryption algorithm"
    )
    default_mac_algorithm: str | None = Field(
        default=None,
        description="New default MAC algorithm"
    )
    default_signing_algorithm: str | None = Field(
        default=None,
        description="New default signing algorithm"
    )
    min_key_bits: int | None = Field(
        default=None,
        ge=128,
        le=512,
        description="New minimum key size"
    )
    key_rotation_days: int | None = Field(
        default=None,
        ge=1,
        le=365,
        description="New rotation period"
    )
    require_quantum_safe: bool | None = Field(
        default=None,
        description="Require quantum-safe algorithms"
    )
    allowed_ciphers: list[str] | None = Field(
        default=None,
        description="New allowed ciphers list"
    )
    allowed_modes: list[str] | None = Field(
        default=None,
        description="New allowed modes list"
    )


class AlgorithmPoliciesResponse(BaseModel):
    """Response containing all classification policies."""
    policies: list[ClassificationAlgorithmPolicy] = Field(
        description="Policies for all classification levels"
    )
