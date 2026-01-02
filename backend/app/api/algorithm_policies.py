"""Algorithm policy API routes.

Provides endpoints for viewing and managing organization-wide
algorithm policies per data classification level.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.jwt import get_current_user
from app.models import User
from app.schemas.algorithm_policy import (
    DataClassification,
    ClassificationAlgorithmPolicy,
    UpdateClassificationPolicyRequest,
    AlgorithmPoliciesResponse,
)

router = APIRouter(prefix="/api/v1/admin", tags=["algorithm-policies"])


# =============================================================================
# Default Policies (can be overridden per tenant)
# =============================================================================

# In-memory storage for policies (would be in DB for production)
# Key: (tenant_id, classification)
_policy_overrides: dict[tuple[str, DataClassification], ClassificationAlgorithmPolicy] = {}


def get_default_policies() -> dict[DataClassification, ClassificationAlgorithmPolicy]:
    """Get default algorithm policies per classification."""
    return {
        DataClassification.PUBLIC: ClassificationAlgorithmPolicy(
            classification=DataClassification.PUBLIC,
            default_encryption_algorithm="AES-128-GCM",
            default_mac_algorithm="HMAC-SHA256",
            default_signing_algorithm=None,
            min_key_bits=128,
            key_rotation_days=180,
            require_quantum_safe=False,
            allowed_ciphers=["AES", "ChaCha20"],
            allowed_modes=["gcm", "ctr"],
        ),
        DataClassification.INTERNAL: ClassificationAlgorithmPolicy(
            classification=DataClassification.INTERNAL,
            default_encryption_algorithm="AES-256-GCM",
            default_mac_algorithm="HMAC-SHA256",
            default_signing_algorithm=None,
            min_key_bits=128,
            key_rotation_days=90,
            require_quantum_safe=False,
            allowed_ciphers=["AES", "ChaCha20"],
            allowed_modes=["gcm", "gcm-siv", "ccm"],
        ),
        DataClassification.SENSITIVE: ClassificationAlgorithmPolicy(
            classification=DataClassification.SENSITIVE,
            default_encryption_algorithm="AES-256-GCM",
            default_mac_algorithm="HMAC-SHA512",
            default_signing_algorithm="ECDSA-P256",
            min_key_bits=256,
            key_rotation_days=60,
            require_quantum_safe=False,
            allowed_ciphers=["AES"],
            allowed_modes=["gcm", "gcm-siv"],
        ),
        DataClassification.CRITICAL: ClassificationAlgorithmPolicy(
            classification=DataClassification.CRITICAL,
            default_encryption_algorithm="AES-256-GCM+ML-KEM-768",
            default_mac_algorithm="HMAC-SHA512",
            default_signing_algorithm="ML-DSA-65",
            min_key_bits=256,
            key_rotation_days=30,
            require_quantum_safe=True,
            allowed_ciphers=["AES"],
            allowed_modes=["gcm", "gcm-siv"],
        ),
    }


def get_policy_for_tenant(
    tenant_id: str,
    classification: DataClassification
) -> ClassificationAlgorithmPolicy:
    """Get policy for a tenant and classification, with overrides."""
    # Check for tenant-specific override
    key = (tenant_id, classification)
    if key in _policy_overrides:
        return _policy_overrides[key]

    # Return default
    defaults = get_default_policies()
    return defaults[classification]


# =============================================================================
# Admin Check
# =============================================================================

async def require_admin(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Ensure the current user is an admin."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/algorithm-policies", response_model=AlgorithmPoliciesResponse)
async def get_algorithm_policies(
    admin: Annotated[User, Depends(require_admin)],
):
    """Get all algorithm policies for each classification level.

    Returns the default or tenant-specific policies for:
    - PUBLIC
    - INTERNAL
    - SENSITIVE
    - CRITICAL

    Admin access required.
    """
    policies = []
    for classification in DataClassification:
        policy = get_policy_for_tenant(admin.tenant_id, classification)
        policies.append(policy)

    return AlgorithmPoliciesResponse(policies=policies)


@router.get(
    "/algorithm-policies/{classification}",
    response_model=ClassificationAlgorithmPolicy
)
async def get_algorithm_policy(
    classification: DataClassification,
    admin: Annotated[User, Depends(require_admin)],
):
    """Get the algorithm policy for a specific classification level.

    Admin access required.
    """
    return get_policy_for_tenant(admin.tenant_id, classification)


@router.put(
    "/algorithm-policies/{classification}",
    response_model=ClassificationAlgorithmPolicy
)
async def update_algorithm_policy(
    classification: DataClassification,
    request: UpdateClassificationPolicyRequest,
    admin: Annotated[User, Depends(require_admin)],
):
    """Update the algorithm policy for a classification level.

    Only provided fields are updated; others retain their current values.

    Admin access required.
    """
    # Get current policy (default or existing override)
    current = get_policy_for_tenant(admin.tenant_id, classification)

    # Build updated policy
    updated = ClassificationAlgorithmPolicy(
        classification=classification,
        default_encryption_algorithm=(
            request.default_encryption_algorithm
            if request.default_encryption_algorithm is not None
            else current.default_encryption_algorithm
        ),
        default_mac_algorithm=(
            request.default_mac_algorithm
            if request.default_mac_algorithm is not None
            else current.default_mac_algorithm
        ),
        default_signing_algorithm=(
            request.default_signing_algorithm
            if request.default_signing_algorithm is not None
            else current.default_signing_algorithm
        ),
        min_key_bits=(
            request.min_key_bits
            if request.min_key_bits is not None
            else current.min_key_bits
        ),
        key_rotation_days=(
            request.key_rotation_days
            if request.key_rotation_days is not None
            else current.key_rotation_days
        ),
        require_quantum_safe=(
            request.require_quantum_safe
            if request.require_quantum_safe is not None
            else current.require_quantum_safe
        ),
        allowed_ciphers=(
            request.allowed_ciphers
            if request.allowed_ciphers is not None
            else current.allowed_ciphers
        ),
        allowed_modes=(
            request.allowed_modes
            if request.allowed_modes is not None
            else current.allowed_modes
        ),
        updated_at=datetime.now(timezone.utc),
        updated_by=admin.github_username,
    )

    # Store the override
    key = (admin.tenant_id, classification)
    _policy_overrides[key] = updated

    return updated


@router.delete("/algorithm-policies/{classification}")
async def reset_algorithm_policy(
    classification: DataClassification,
    admin: Annotated[User, Depends(require_admin)],
):
    """Reset a classification's policy to defaults.

    Removes any tenant-specific overrides.

    Admin access required.
    """
    key = (admin.tenant_id, classification)
    if key in _policy_overrides:
        del _policy_overrides[key]

    return {
        "message": f"Policy for {classification.value} reset to defaults",
        "classification": classification.value,
    }
