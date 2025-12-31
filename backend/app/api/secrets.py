"""Secrets Management API routes.

Provides Shamir Secret Sharing, Threshold Cryptography, and Lease Management.
These are advanced features for high-security scenarios.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.secret_sharing_engine import (
    SecretSharingEngine,
    SecretSharingError,
)
from app.core.threshold_engine import (
    ThresholdEngine,
    ThresholdError,
)
from app.core.lease_engine import (
    LeaseEngine,
    LeaseError,
    LeaseNotFoundError,
    LeaseExpiredError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/v1/secrets", tags=["secrets"])

# Singleton engines
secret_sharing_engine = SecretSharingEngine()
threshold_engine = ThresholdEngine()
lease_engine = LeaseEngine()


# ============================================================================
# Shamir Secret Sharing
# ============================================================================

class ShamirSplitRequest(BaseModel):
    """Shamir split request."""
    secret: str = Field(..., description="Secret to split (base64 encoded)")
    threshold: int = Field(..., ge=2, le=255, description="Minimum shares needed to reconstruct")
    total_shares: int = Field(..., ge=2, le=255, description="Total shares to generate")


class ShamirShare(BaseModel):
    """A single Shamir share."""
    index: int
    value: str = Field(..., description="Share value (base64 encoded)")


class ShamirSplitResponse(BaseModel):
    """Shamir split response."""
    shares: list[ShamirShare]
    threshold: int
    total_shares: int


class ShamirCombineRequest(BaseModel):
    """Shamir combine request."""
    shares: list[ShamirShare]


class ShamirCombineResponse(BaseModel):
    """Shamir combine response."""
    secret: str = Field(..., description="Reconstructed secret (base64 encoded)")


@router.post("/shamir/split", response_model=ShamirSplitResponse)
async def shamir_split(
    data: ShamirSplitRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Split a secret using Shamir's Secret Sharing.

    Divides a secret into N shares where any K (threshold) shares
    can reconstruct the secret, but K-1 shares reveal nothing.

    Use cases:
    - Key escrow with multiple custodians
    - Disaster recovery requiring multiple approvals
    - Multi-party key management

    Example: Split into 5 shares with threshold 3 means any 3 shares
    can reconstruct, but 2 shares reveal nothing about the secret.
    """
    if data.threshold > data.total_shares:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threshold cannot exceed total shares",
        )

    try:
        secret = base64.b64decode(data.secret)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 secret",
        )

    try:
        shares = secret_sharing_engine.split(
            secret=secret,
            threshold=data.threshold,
            num_shares=data.total_shares,
        )
    except SecretSharingError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ShamirSplitResponse(
        shares=[
            ShamirShare(index=i, value=base64.b64encode(s).decode("ascii"))
            for i, s in shares
        ],
        threshold=data.threshold,
        total_shares=data.total_shares,
    )


@router.post("/shamir/combine", response_model=ShamirCombineResponse)
async def shamir_combine(
    data: ShamirCombineRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Reconstruct a secret from Shamir shares.

    Requires at least threshold shares to reconstruct.
    Extra shares are ignored but can help verify correctness.
    """
    try:
        shares = [
            (s.index, base64.b64decode(s.value))
            for s in data.shares
        ]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid share format",
        )

    try:
        secret = secret_sharing_engine.combine(shares)
    except SecretSharingError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ShamirCombineResponse(
        secret=base64.b64encode(secret).decode("ascii"),
    )


# ============================================================================
# Threshold Cryptography
# ============================================================================

class ThresholdKeyGenRequest(BaseModel):
    """Threshold key generation request."""
    threshold: int = Field(..., ge=2, description="Signing threshold")
    total_parties: int = Field(..., ge=2, description="Total parties")
    curve: str = Field(default="secp256k1", description="Curve: secp256k1, p256")


class ThresholdKeyShare(BaseModel):
    """A threshold key share."""
    party_id: int
    private_share: str = Field(..., description="Private key share (base64)")
    public_share: str = Field(..., description="Public key share (base64)")
    verification_key: str = Field(..., description="Verification key (base64)")


class ThresholdKeyGenResponse(BaseModel):
    """Threshold key generation response."""
    shares: list[ThresholdKeyShare]
    group_public_key: str = Field(..., description="Combined public key (base64)")
    threshold: int
    total_parties: int


class ThresholdSignRequest(BaseModel):
    """Threshold signing request."""
    message: str = Field(..., description="Message to sign (base64)")
    party_shares: list[dict] = Field(..., description="Participating party shares")
    group_public_key: str = Field(..., description="Group public key (base64)")


class ThresholdSignResponse(BaseModel):
    """Threshold signing response."""
    signature: str = Field(..., description="Combined signature (base64)")
    signers: list[int] = Field(..., description="Party IDs that contributed")


@router.post("/threshold/keygen", response_model=ThresholdKeyGenResponse)
async def threshold_key_generation(
    data: ThresholdKeyGenRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate threshold key shares using Distributed Key Generation.

    Creates key shares for N parties where any T (threshold) parties
    can cooperatively sign without revealing the private key.

    Features:
    - Verifiable Secret Sharing (Feldman's VSS)
    - No dealer - distributed generation
    - Supports key refresh without changing public key
    """
    if data.threshold > data.total_parties:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threshold cannot exceed total parties",
        )

    try:
        result = threshold_engine.distributed_key_generation(
            threshold=data.threshold,
            num_parties=data.total_parties,
            curve=data.curve,
        )
    except ThresholdError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ThresholdKeyGenResponse(
        shares=[
            ThresholdKeyShare(
                party_id=s.party_id,
                private_share=base64.b64encode(s.private_share).decode("ascii"),
                public_share=base64.b64encode(s.public_share).decode("ascii"),
                verification_key=base64.b64encode(s.verification_key).decode("ascii"),
            )
            for s in result.shares
        ],
        group_public_key=base64.b64encode(result.group_public_key).decode("ascii"),
        threshold=data.threshold,
        total_parties=data.total_parties,
    )


@router.post("/threshold/sign", response_model=ThresholdSignResponse)
async def threshold_sign(
    data: ThresholdSignRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Create a threshold signature.

    Combines partial signatures from T parties to produce a valid
    signature that verifies against the group public key.
    """
    try:
        message = base64.b64decode(data.message)
        group_public_key = base64.b64decode(data.group_public_key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        result = threshold_engine.threshold_sign(
            message=message,
            party_shares=data.party_shares,
            group_public_key=group_public_key,
        )
    except ThresholdError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ThresholdSignResponse(
        signature=base64.b64encode(result.signature).decode("ascii"),
        signers=result.signers,
    )


# ============================================================================
# Lease Management (Time-Limited Secrets)
# ============================================================================

class LeaseCreateRequest(BaseModel):
    """Lease creation request."""
    secret: str = Field(..., description="Secret data (base64)")
    ttl_seconds: int = Field(default=3600, description="Time to live in seconds")
    max_ttl_seconds: int | None = Field(default=None, description="Maximum TTL (limits renewals)")
    renewable: bool = Field(default=True, description="Allow lease renewal")
    metadata: dict | None = Field(default=None, description="Optional metadata")


class LeaseResponse(BaseModel):
    """Lease response."""
    lease_id: str
    secret: str = Field(..., description="Secret data (base64)")
    ttl_seconds: int
    expires_at: str
    renewable: bool
    metadata: dict | None = None


class LeaseRenewRequest(BaseModel):
    """Lease renewal request."""
    lease_id: str
    increment_seconds: int = Field(default=3600, description="TTL extension")


class LeaseRevokeRequest(BaseModel):
    """Lease revocation request."""
    lease_id: str


@router.post("/lease/create", response_model=LeaseResponse)
async def create_lease(
    data: LeaseCreateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Create a time-limited lease for a secret.

    Leases provide:
    - Automatic expiration
    - Optional renewal with max TTL cap
    - Audit trail of access
    - Revocation capability

    Use for:
    - Temporary credentials
    - Time-boxed access tokens
    - Secrets that should auto-expire
    """
    try:
        secret = base64.b64decode(data.secret)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 secret",
        )

    try:
        lease = lease_engine.create_lease(
            secret=secret,
            ttl=data.ttl_seconds,
            max_ttl=data.max_ttl_seconds,
            renewable=data.renewable,
            metadata=data.metadata,
            identity_id=str(identity.id),
        )
    except LeaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return LeaseResponse(
        lease_id=lease.lease_id,
        secret=base64.b64encode(lease.secret).decode("ascii"),
        ttl_seconds=lease.ttl,
        expires_at=lease.expires_at.isoformat(),
        renewable=lease.renewable,
        metadata=lease.metadata,
    )


@router.get("/lease/{lease_id}", response_model=LeaseResponse)
async def get_lease(
    lease_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Retrieve a secret by lease ID.

    Returns the secret if the lease is still valid.
    Automatically tracks access for auditing.
    """
    try:
        lease = lease_engine.get_lease(lease_id)
    except LeaseNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
    except LeaseExpiredError:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Lease expired")
    except LeaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return LeaseResponse(
        lease_id=lease.lease_id,
        secret=base64.b64encode(lease.secret).decode("ascii"),
        ttl_seconds=lease.ttl,
        expires_at=lease.expires_at.isoformat(),
        renewable=lease.renewable,
        metadata=lease.metadata,
    )


@router.post("/lease/renew", response_model=LeaseResponse)
async def renew_lease(
    data: LeaseRenewRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Renew a lease to extend its TTL.

    The new TTL cannot exceed max_ttl if one was set.
    Non-renewable leases cannot be renewed.
    """
    try:
        lease = lease_engine.renew_lease(
            lease_id=data.lease_id,
            increment=data.increment_seconds,
        )
    except LeaseNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
    except LeaseExpiredError:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Lease expired")
    except LeaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return LeaseResponse(
        lease_id=lease.lease_id,
        secret=base64.b64encode(lease.secret).decode("ascii"),
        ttl_seconds=lease.ttl,
        expires_at=lease.expires_at.isoformat(),
        renewable=lease.renewable,
        metadata=lease.metadata,
    )


@router.post("/lease/revoke")
async def revoke_lease(
    data: LeaseRevokeRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Revoke a lease immediately.

    The secret becomes inaccessible and the lease cannot be renewed.
    This action is irreversible.
    """
    try:
        lease_engine.revoke_lease(data.lease_id)
    except LeaseNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
    except LeaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {"status": "revoked", "lease_id": data.lease_id}


@router.get("/lease/{lease_id}/audit")
async def get_lease_audit(
    lease_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Get audit trail for a lease.

    Shows all access events, renewals, and revocations.
    """
    try:
        audit = lease_engine.get_lease_audit(lease_id)
    except LeaseNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
    except LeaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return audit
