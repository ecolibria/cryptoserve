"""Password Hashing API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.password_engine import (
    PasswordEngine,
    PasswordAlgorithm,
    PasswordHashError,
    PasswordVerifyError,
    UnsupportedAlgorithmError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/v1/crypto/password", tags=["passwords"])

# Singleton password engine
password_engine = PasswordEngine()


class PasswordHashRequest(BaseModel):
    """Password hash request schema."""
    password: str = Field(..., description="Password to hash", min_length=1)
    algorithm: str = Field(
        default="argon2id",
        description="Algorithm: argon2id (recommended), bcrypt, scrypt, pbkdf2-sha256"
    )


class PasswordHashResponse(BaseModel):
    """Password hash response schema."""
    hash: str = Field(..., description="Password hash in PHC string format")
    algorithm: str
    params: dict = Field(..., description="Parameters used for hashing")


class PasswordVerifyRequest(BaseModel):
    """Password verification request schema."""
    password: str = Field(..., description="Password to verify")
    hash: str = Field(..., description="Hash to verify against (PHC format)")


class PasswordVerifyResponse(BaseModel):
    """Password verification response schema."""
    valid: bool
    needs_rehash: bool = Field(
        ...,
        description="True if parameters are outdated and password should be rehashed"
    )
    algorithm: str


class PasswordStrengthRequest(BaseModel):
    """Password strength check request schema."""
    password: str = Field(..., description="Password to analyze")


class PasswordStrengthResponse(BaseModel):
    """Password strength response schema."""
    score: int = Field(..., description="Strength score 0-100")
    strength: str = Field(..., description="Strength level: weak, fair, good, strong")
    length: int
    entropy_bits: float
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    suggestions: list[str] = Field(default_factory=list)


@router.post("/hash", response_model=PasswordHashResponse)
async def hash_password(
    data: PasswordHashRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Hash a password using a secure algorithm.

    Supports:
    - argon2id (recommended): Memory-hard, resistant to GPU/ASIC attacks
    - bcrypt: Widely deployed, proven security
    - scrypt: Memory-hard, IETF standard
    - pbkdf2-sha256: FIPS-compliant, for legacy/compliance requirements

    Returns the hash in PHC (Password Hashing Competition) string format
    which includes algorithm, parameters, salt, and hash.
    """
    try:
        algorithm = PasswordAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Supported: {[a.value for a in PasswordAlgorithm]}",
        )

    try:
        result = password_engine.hash_password(data.password, algorithm)
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except PasswordHashError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return PasswordHashResponse(
        hash=result.hash,
        algorithm=result.algorithm.value,
        params=result.params,
    )


@router.post("/verify", response_model=PasswordVerifyResponse)
async def verify_password(
    data: PasswordVerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a password against a hash.

    Uses constant-time comparison to prevent timing attacks.
    Auto-detects algorithm from the hash format.

    Returns whether the password is valid and whether the hash
    should be regenerated with updated parameters (needs_rehash).
    """
    try:
        result = password_engine.verify_password(data.password, data.hash)
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except PasswordVerifyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return PasswordVerifyResponse(
        valid=result.valid,
        needs_rehash=result.needs_rehash,
        algorithm=result.algorithm.value,
    )


@router.post("/strength", response_model=PasswordStrengthResponse)
async def check_password_strength(
    data: PasswordStrengthRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Check password strength.

    Analyzes password for:
    - Length
    - Character diversity (lowercase, uppercase, digits, special)
    - Entropy estimation

    Returns a score (0-100) and strength level with suggestions
    for improvement.
    """
    result = password_engine.check_strength(data.password)

    suggestions = []
    if result["length"] < 12:
        suggestions.append("Use at least 12 characters")
    if not result["has_lowercase"]:
        suggestions.append("Add lowercase letters")
    if not result["has_uppercase"]:
        suggestions.append("Add uppercase letters")
    if not result["has_digits"]:
        suggestions.append("Add numbers")
    if not result["has_special"]:
        suggestions.append("Add special characters (!@#$%^&*)")
    if result["strength"] in ["weak", "fair"]:
        suggestions.append("Consider using a passphrase (multiple random words)")

    return PasswordStrengthResponse(
        score=result["score"],
        strength=result["strength"],
        length=result["length"],
        entropy_bits=result["entropy_bits"],
        has_lowercase=result["has_lowercase"],
        has_uppercase=result["has_uppercase"],
        has_digits=result["has_digits"],
        has_special=result["has_special"],
        suggestions=suggestions,
    )
