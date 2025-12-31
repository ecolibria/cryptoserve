"""Hash and MAC API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.hash_engine import (
    hash_engine,
    mac_engine,
    HashAlgorithm,
    MACAlgorithm,
    HashError,
    MACError,
    UnsupportedAlgorithmError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/api/v1/crypto", tags=["hashing"])


# ============================================================================
# Hash Operations
# ============================================================================

class HashRequest(BaseModel):
    """Hash request schema."""
    data: str = Field(..., description="Data to hash (base64 encoded)")
    algorithm: str = Field(
        default="sha256",
        description="Hash algorithm (sha256, sha384, sha512, sha3-256, sha3-512, blake2b, blake2s, blake3)"
    )
    output_length: int | None = Field(
        default=None,
        description="Output length in bytes (for XOF algorithms like SHAKE, BLAKE)"
    )


class HashResponse(BaseModel):
    """Hash response schema."""
    digest: str = Field(..., description="Hash digest (base64 encoded)")
    hex: str = Field(..., description="Hash digest (hex encoded)")
    algorithm: str
    length_bits: int


class HashVerifyRequest(BaseModel):
    """Hash verification request schema."""
    data: str = Field(..., description="Data to verify (base64 encoded)")
    expected_digest: str = Field(..., description="Expected digest (hex or base64 encoded)")
    algorithm: str = Field(default="sha256")


class HashVerifyResponse(BaseModel):
    """Hash verification response schema."""
    valid: bool


@router.post("/hash", response_model=HashResponse)
async def compute_hash(
    data: HashRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Compute cryptographic hash of data.

    Supports SHA-2, SHA-3, BLAKE2, and BLAKE3 family of hash functions.
    For XOF (extendable output function) algorithms like SHAKE, you can
    specify a custom output length.
    """
    try:
        raw_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        algorithm = HashAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown hash algorithm: {data.algorithm}. Supported: {[a.value for a in HashAlgorithm]}",
        )

    try:
        result = hash_engine.hash(raw_data, algorithm, data.output_length)
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except HashError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return HashResponse(
        digest=result.base64,
        hex=result.hex,
        algorithm=algorithm.value,
        length_bits=result.length,
    )


@router.post("/hash/verify", response_model=HashVerifyResponse)
async def verify_hash(
    data: HashVerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a hash matches expected value.

    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        raw_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    # Try to decode expected as hex first, then base64
    try:
        expected = bytes.fromhex(data.expected_digest)
    except ValueError:
        try:
            expected = base64.b64decode(data.expected_digest)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid expected_digest format (must be hex or base64)",
            )

    try:
        algorithm = HashAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown hash algorithm: {data.algorithm}",
        )

    valid = hash_engine.verify(raw_data, expected, algorithm)

    return HashVerifyResponse(valid=valid)


# ============================================================================
# MAC Operations
# ============================================================================

class MACRequest(BaseModel):
    """MAC request schema."""
    data: str = Field(..., description="Data to authenticate (base64 encoded)")
    key: str = Field(..., description="MAC key (base64 encoded)")
    algorithm: str = Field(
        default="hmac-sha256",
        description="MAC algorithm (hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha3-256, kmac128, kmac256)"
    )
    customization: str | None = Field(
        default=None,
        description="Customization string for KMAC (base64 encoded)"
    )
    output_length: int | None = Field(
        default=None,
        description="Output length in bytes for KMAC"
    )


class MACResponse(BaseModel):
    """MAC response schema."""
    tag: str = Field(..., description="MAC tag (base64 encoded)")
    hex: str = Field(..., description="MAC tag (hex encoded)")
    algorithm: str
    length_bits: int


class MACVerifyRequest(BaseModel):
    """MAC verification request schema."""
    data: str = Field(..., description="Data to verify (base64 encoded)")
    key: str = Field(..., description="MAC key (base64 encoded)")
    expected_tag: str = Field(..., description="Expected tag (hex or base64 encoded)")
    algorithm: str = Field(default="hmac-sha256")
    customization: str | None = Field(default=None)


class MACVerifyResponse(BaseModel):
    """MAC verification response schema."""
    valid: bool


class MACKeyGenerateRequest(BaseModel):
    """MAC key generation request schema."""
    algorithm: str = Field(
        default="hmac-sha256",
        description="MAC algorithm to generate key for"
    )


class MACKeyGenerateResponse(BaseModel):
    """MAC key generation response schema."""
    key: str = Field(..., description="Generated key (base64 encoded)")
    algorithm: str
    length_bytes: int


@router.post("/mac", response_model=MACResponse)
async def compute_mac(
    data: MACRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Compute message authentication code.

    Supports HMAC (SHA-2, SHA-3, BLAKE2b) and KMAC (NIST SP 800-185).
    For KMAC, you can optionally provide a customization string.
    """
    try:
        raw_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        key = base64.b64decode(data.key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 key",
        )

    customization = b""
    if data.customization:
        try:
            customization = base64.b64decode(data.customization)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 customization",
            )

    try:
        algorithm = MACAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown MAC algorithm: {data.algorithm}. Supported: {[a.value for a in MACAlgorithm]}",
        )

    try:
        result = mac_engine.mac(
            raw_data, key, algorithm, customization, data.output_length
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except MACError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return MACResponse(
        tag=result.base64,
        hex=result.hex,
        algorithm=algorithm.value,
        length_bits=result.length,
    )


@router.post("/mac/verify", response_model=MACVerifyResponse)
async def verify_mac(
    data: MACVerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a MAC tag.

    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        raw_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        key = base64.b64decode(data.key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 key",
        )

    # Try to decode expected as hex first, then base64
    try:
        expected = bytes.fromhex(data.expected_tag)
    except ValueError:
        try:
            expected = base64.b64decode(data.expected_tag)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid expected_tag format (must be hex or base64)",
            )

    customization = b""
    if data.customization:
        try:
            customization = base64.b64decode(data.customization)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 customization",
            )

    try:
        algorithm = MACAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown MAC algorithm: {data.algorithm}",
        )

    valid = mac_engine.verify(raw_data, key, expected, algorithm, customization)

    return MACVerifyResponse(valid=valid)


@router.post("/mac/generate-key", response_model=MACKeyGenerateResponse)
async def generate_mac_key(
    data: MACKeyGenerateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a random MAC key.

    Generates a cryptographically secure random key of appropriate size
    for the specified MAC algorithm.
    """
    try:
        algorithm = MACAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown MAC algorithm: {data.algorithm}",
        )

    key = mac_engine.generate_key(algorithm)

    return MACKeyGenerateResponse(
        key=base64.b64encode(key).decode("ascii"),
        algorithm=algorithm.value,
        length_bytes=len(key),
    )
