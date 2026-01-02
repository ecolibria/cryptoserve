"""Key Ceremony API routes.

Provides endpoints for master key initialization, sealing, and unsealing.
Implements the Vault-style seal/unseal pattern for enterprise key management.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User
from app.core.key_ceremony import (
    key_ceremony_service,
    CeremonyError,
    AlreadyInitializedError,
    NotInitializedError,
    AlreadySealedError,
    AlreadyUnsealedError,
    InvalidShareError,
)

router = APIRouter(prefix="/api/admin/ceremony", tags=["ceremony"])


# Dependency to require admin access
async def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require admin user for ceremony operations."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for key ceremony operations",
        )
    return current_user


# =============================================================================
# Request/Response Models
# =============================================================================

class InitializeRequest(BaseModel):
    """Request to initialize the master key."""
    threshold: int = Field(
        ...,
        ge=2,
        le=10,
        description="Minimum shares needed to unseal (2-10)"
    )
    total_shares: int = Field(
        ...,
        ge=2,
        le=20,
        description="Total shares to generate (2-20)"
    )
    custodian_emails: list[str] | None = Field(
        default=None,
        description="Optional list of custodian emails"
    )


class InitializeResponse(BaseModel):
    """Response from initialization."""
    success: bool
    message: str
    recovery_shares: list[str] = Field(
        ...,
        description="Hex-encoded recovery shares - distribute to custodians"
    )
    root_token: str = Field(
        ...,
        description="Root token for initial setup - store securely"
    )
    threshold: int
    total_shares: int
    share_fingerprints: list[str] = Field(
        ...,
        description="SHA-256 fingerprints for share verification"
    )


class UnsealRequest(BaseModel):
    """Request to provide an unseal share."""
    share: str = Field(..., description="Hex-encoded recovery share")


class UnsealResponse(BaseModel):
    """Response from unseal operation."""
    success: bool
    message: str
    shares_provided: int
    shares_required: int
    is_sealed: bool
    progress_percent: float


class StatusResponse(BaseModel):
    """Key ceremony status."""
    state: str
    is_initialized: bool
    is_sealed: bool
    threshold: int
    total_shares: int
    custodians: int
    unseal_progress: dict | None = None


class VerifyShareRequest(BaseModel):
    """Request to verify a share."""
    share: str = Field(..., description="Hex-encoded share to verify")


class VerifyShareResponse(BaseModel):
    """Share verification result."""
    valid: bool
    share_index: int | None = None
    fingerprint: str | None = None
    params_match: bool | None = None
    fingerprint_valid: bool | None = None
    error: str | None = None


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/status", response_model=StatusResponse)
async def get_ceremony_status(
    admin: User = Depends(require_admin),
):
    """Get current key ceremony status.

    Returns the state of the key ceremony:
    - uninitialized: No master key exists
    - sealed: Master key exists but locked
    - unsealing: Collecting shares to unseal
    - unsealed: Service is operational
    """
    status = key_ceremony_service.get_status()
    return StatusResponse(**status)


@router.post("/initialize", response_model=InitializeResponse)
async def initialize_master_key(
    request: InitializeRequest,
    admin: User = Depends(require_admin),
):
    """Initialize the master key and generate recovery shares.

    **IMPORTANT: This should only be called once during initial deployment.**

    This creates a new master key and splits it into recovery shares
    using Shamir's Secret Sharing. Each share should be securely
    distributed to a different key custodian.

    Example: With threshold=3 and total_shares=5:
    - 5 shares are generated
    - Any 3 shares can reconstruct the master key
    - 2 or fewer shares reveal nothing about the master key

    The recovery shares are returned ONCE. Store them securely!
    """
    try:
        result = key_ceremony_service.initialize(
            threshold=request.threshold,
            total_shares=request.total_shares,
            custodian_emails=request.custodian_emails,
            actor=admin.email or admin.github_username,
        )

        return InitializeResponse(
            success=True,
            message=(
                f"Master key initialized with {result.threshold}-of-{result.total_shares} "
                f"threshold scheme. Distribute the recovery shares to custodians securely."
            ),
            recovery_shares=result.recovery_shares,
            root_token=result.root_token,
            threshold=result.threshold,
            total_shares=result.total_shares,
            share_fingerprints=result.share_fingerprints,
        )

    except AlreadyInitializedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except CeremonyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/seal")
async def seal_service(
    admin: User = Depends(require_admin),
):
    """Seal the service.

    Clears the master key from memory and requires unsealing
    to resume operations. Use this when:
    - Performing maintenance
    - Responding to a security incident
    - Before system shutdown
    """
    try:
        key_ceremony_service.seal(
            actor=admin.email or admin.github_username
        )
        return {
            "success": True,
            "message": "Service sealed. Unseal required to resume operations.",
        }
    except AlreadySealedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except NotInitializedError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/unseal", response_model=UnsealResponse)
async def unseal_service(
    request: UnsealRequest,
    admin: User = Depends(require_admin),
):
    """Provide a share to unseal the service.

    Call this repeatedly with different recovery shares until
    the threshold is reached. Each share should come from a
    different custodian.

    When the threshold is reached, the service becomes unsealed
    and operational.
    """
    try:
        progress = key_ceremony_service.unseal(
            share_hex=request.share,
            actor=admin.email or admin.github_username,
        )

        if not progress.is_sealed:
            message = "Service successfully unsealed!"
        else:
            message = f"Share accepted. {progress.shares_provided}/{progress.shares_required} shares provided."

        return UnsealResponse(
            success=True,
            message=message,
            shares_provided=progress.shares_provided,
            shares_required=progress.shares_required,
            is_sealed=progress.is_sealed,
            progress_percent=progress.progress_percent,
        )

    except AlreadyUnsealedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except InvalidShareError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except NotInitializedError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/reset-unseal")
async def reset_unseal_progress(
    admin: User = Depends(require_admin),
):
    """Reset unseal progress.

    Clears any pending shares. Use this if incorrect shares
    were provided and you need to start over.
    """
    key_ceremony_service.reset_unseal_progress(
        actor=admin.email or admin.github_username
    )
    return {
        "success": True,
        "message": "Unseal progress reset. Start over with correct shares.",
    }


@router.post("/verify-share", response_model=VerifyShareResponse)
async def verify_share(
    request: VerifyShareRequest,
    admin: User = Depends(require_admin),
):
    """Verify a share without using it.

    Useful for custodians to confirm their share is valid
    before a ceremony, without actually unsealing.
    """
    result = key_ceremony_service.verify_share(request.share)
    return VerifyShareResponse(**result)


@router.get("/custodians")
async def list_custodians(
    admin: User = Depends(require_admin),
):
    """List registered key custodians.

    Returns custodian metadata (not their shares).
    """
    custodians = key_ceremony_service.get_custodians()
    return {
        "custodians": custodians,
        "total": len(custodians),
    }


@router.get("/audit")
async def get_ceremony_audit(
    limit: int = 100,
    admin: User = Depends(require_admin),
):
    """Get key ceremony audit log.

    Returns recent ceremony events including:
    - Initialization
    - Seal/unseal operations
    - Share verification
    """
    events = key_ceremony_service.get_audit_log(limit=limit)
    return {
        "events": events,
        "total": len(events),
    }
