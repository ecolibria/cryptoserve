"""Hybrid Key Exchange API routes.

Provides endpoints for X25519 + ML-KEM hybrid key exchange operations.
This implements hybrid key exchange per NIST recommendations for the
post-quantum transition period.
"""

import base64
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.identity_manager import identity_manager
from app.core.hybrid_crypto import is_pqc_available, PQCError
from app.core.hybrid_kex import (
    HybridKeyExchange,
    HybridKEXMode,
    HybridKEXKeyPair,
    get_hybrid_kex_info,
)

router = APIRouter(prefix="/api/v1/kex", tags=["key-exchange"])
security = HTTPBearer()


# =============================================================================
# In-memory key storage (production should use HSM/secure storage)
# =============================================================================

_kex_key_store: dict[str, dict] = {}


# =============================================================================
# Request/Response Models
# =============================================================================


class ModeInfo(BaseModel):
    """Information about a hybrid KEX mode."""

    name: str
    classicalAlgorithm: str = Field(description="Classical algorithm (X25519)")
    pqcAlgorithm: str = Field(description="Post-quantum algorithm (ML-KEM)")
    classicalSecurityBits: int
    quantumSecurityBits: int
    nistPqcLevel: int
    x25519PublicKeyBytes: int
    mlkemPublicKeyBytes: int
    mlkemCiphertextBytes: int
    sharedSecretBytes: int


class ListModesResponse(BaseModel):
    """Response with available modes."""

    available: bool
    modes: list[ModeInfo]


class GenerateKEXKeyRequest(BaseModel):
    """Request to generate a hybrid KEX key pair."""

    mode: str = Field(
        default="X25519+ML-KEM-768",
        description="Hybrid KEX mode: X25519+ML-KEM-768 or X25519+ML-KEM-1024",
    )


class GenerateKEXKeyResponse(BaseModel):
    """Response with generated key pair information."""

    keyId: str
    mode: str
    x25519PublicKey: str = Field(description="Base64-encoded X25519 public key (32 bytes)")
    mlkemPublicKey: str = Field(description="Base64-encoded ML-KEM public key")
    x25519PublicKeyBytes: int
    mlkemPublicKeyBytes: int
    createdAt: str


class EncapsulateRequest(BaseModel):
    """Request to encapsulate (create shared secret)."""

    x25519PublicKey: str = Field(description="Base64-encoded recipient X25519 public key")
    mlkemPublicKey: str = Field(description="Base64-encoded recipient ML-KEM public key")
    mode: str = Field(default="X25519+ML-KEM-768", description="Hybrid KEX mode")


class EncapsulateResponse(BaseModel):
    """Response with encapsulation and shared secret."""

    encapsulation: str = Field(description="Base64-encoded encapsulation data (send to recipient)")
    sharedSecret: str = Field(description="Base64-encoded shared secret (32 bytes)")
    mode: str


class DecapsulateRequest(BaseModel):
    """Request to decapsulate (recover shared secret)."""

    encapsulation: str = Field(description="Base64-encoded encapsulation data from sender")
    keyId: str = Field(description="ID of the recipient's KEX key pair")


class DecapsulateResponse(BaseModel):
    """Response with recovered shared secret."""

    sharedSecret: str = Field(description="Base64-encoded shared secret (32 bytes)")
    keyId: str
    mode: str


class GetKEXKeyResponse(BaseModel):
    """Response with public keys."""

    keyId: str
    mode: str
    x25519PublicKey: str = Field(description="Base64-encoded X25519 public key")
    mlkemPublicKey: str = Field(description="Base64-encoded ML-KEM public key")
    createdAt: str


class KEXKeyInfo(BaseModel):
    """Information about a KEX key pair."""

    keyId: str
    mode: str
    x25519PublicKeyBytes: int
    mlkemPublicKeyBytes: int
    createdAt: str


class ListKEXKeysResponse(BaseModel):
    """Response with list of KEX keys."""

    keys: list[KEXKeyInfo]


class DeleteKEXKeyResponse(BaseModel):
    """Response for key deletion."""

    deleted: bool
    keyId: str


# =============================================================================
# Authentication
# =============================================================================


async def get_sdk_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Identity:
    """Get identity from SDK token."""
    token = credentials.credentials
    identity = await identity_manager.get_identity_by_token(db, token)

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired identity token",
        )

    return identity


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/modes", response_model=ListModesResponse)
async def list_modes():
    """List available hybrid key exchange modes.

    Returns information about all supported hybrid KEX modes
    combining X25519 with ML-KEM variants.
    """
    available = is_pqc_available()
    modes = []

    if available:
        for mode in HybridKEXMode:
            info = get_hybrid_kex_info(mode)
            modes.append(
                ModeInfo(
                    name=mode.value,
                    classicalAlgorithm=info["classical_algorithm"],
                    pqcAlgorithm=info["pqc_algorithm"],
                    classicalSecurityBits=info["classical_security_bits"],
                    quantumSecurityBits=info["quantum_security_bits"],
                    nistPqcLevel=info["nist_pqc_level"],
                    x25519PublicKeyBytes=info["x25519_public_key_bytes"],
                    mlkemPublicKeyBytes=info["mlkem_public_key_bytes"],
                    mlkemCiphertextBytes=info["mlkem_ciphertext_bytes"],
                    sharedSecretBytes=info["shared_secret_bytes"],
                )
            )

    return ListModesResponse(available=available, modes=modes)


@router.post("/keys/generate", response_model=GenerateKEXKeyResponse)
async def generate_kex_key(
    request: Request,
    data: GenerateKEXKeyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a new hybrid KEX key pair.

    Creates a new hybrid key exchange key pair combining X25519 and ML-KEM.
    Share the public keys with the sender who will use them to create
    a shared secret via encapsulation.
    """
    if not is_pqc_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PQC not available. liboqs library is not installed.",
        )

    try:
        mode = HybridKEXMode(data.mode)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode: {data.mode}. Valid modes: {[m.value for m in HybridKEXMode]}",
        )

    try:
        kex = HybridKeyExchange(mode)
        keypair = kex.generate_keypair()

        # Store key pair
        now = datetime.now(timezone.utc)
        _kex_key_store[keypair.key_id] = {
            "mode": mode.value,
            "x25519_private": keypair.x25519_private,
            "x25519_public": keypair.x25519_public,
            "mlkem_private": keypair.mlkem_private,
            "mlkem_public": keypair.mlkem_public,
            "created_at": now.isoformat(),
        }

        return GenerateKEXKeyResponse(
            keyId=keypair.key_id,
            mode=mode.value,
            x25519PublicKey=base64.b64encode(keypair.x25519_public).decode("ascii"),
            mlkemPublicKey=base64.b64encode(keypair.mlkem_public).decode("ascii"),
            x25519PublicKeyBytes=len(keypair.x25519_public),
            mlkemPublicKeyBytes=len(keypair.mlkem_public),
            createdAt=now.isoformat(),
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key generation failed: {str(e)}",
        )


@router.post("/encapsulate", response_model=EncapsulateResponse)
async def encapsulate(
    request: Request,
    data: EncapsulateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encapsulate to create a shared secret.

    Performs hybrid key encapsulation using the recipient's public keys.
    Returns the encapsulation data (send to recipient) and the shared secret.

    The recipient uses decapsulate with their private key to recover
    the same shared secret.
    """
    if not is_pqc_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PQC not available. liboqs library is not installed.",
        )

    try:
        mode = HybridKEXMode(data.mode)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode: {data.mode}",
        )

    try:
        x25519_public = base64.b64decode(data.x25519PublicKey)
        mlkem_public = base64.b64decode(data.mlkemPublicKey)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 public key",
        )

    try:
        kex = HybridKeyExchange(mode)
        encap, shared_secret = kex.encapsulate(x25519_public, mlkem_public)

        return EncapsulateResponse(
            encapsulation=base64.b64encode(kex.serialize_encapsulation(encap)).decode("ascii"),
            sharedSecret=base64.b64encode(shared_secret).decode("ascii"),
            mode=mode.value,
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encapsulation failed: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid public key: {str(e)}",
        )


@router.post("/decapsulate", response_model=DecapsulateResponse)
async def decapsulate(
    request: Request,
    data: DecapsulateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decapsulate to recover the shared secret.

    Uses your private key to recover the shared secret from the
    encapsulation data sent by the other party.

    The resulting shared secret will match what the sender computed
    during encapsulation.
    """
    if not is_pqc_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PQC not available. liboqs library is not installed.",
        )

    # Get key pair
    if data.keyId not in _kex_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {data.keyId}",
        )

    key_info = _kex_key_store[data.keyId]

    try:
        encap_bytes = base64.b64decode(data.encapsulation)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 encapsulation",
        )

    try:
        mode = HybridKEXMode(key_info["mode"])
        kex = HybridKeyExchange(mode)

        # Deserialize encapsulation
        encap = HybridKeyExchange.deserialize_encapsulation(encap_bytes)

        # Reconstruct keypair
        keypair = HybridKEXKeyPair(
            x25519_private=key_info["x25519_private"],
            x25519_public=key_info["x25519_public"],
            mlkem_private=key_info["mlkem_private"],
            mlkem_public=key_info["mlkem_public"],
            mode=mode,
            key_id=data.keyId,
        )

        # Decapsulate
        shared_secret = kex.decapsulate(encap, keypair)

        return DecapsulateResponse(
            sharedSecret=base64.b64encode(shared_secret).decode("ascii"),
            keyId=data.keyId,
            mode=mode.value,
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decapsulation failed: {str(e)}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid encapsulation: {str(e)}",
        )


@router.get("/keys/{key_id}", response_model=GetKEXKeyResponse)
async def get_kex_key(
    request: Request,
    key_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Get the public keys for a KEX key pair.

    Returns the public keys in base64 format. The private keys
    are never exposed through the API.
    """
    if key_id not in _kex_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {key_id}",
        )

    key_info = _kex_key_store[key_id]

    return GetKEXKeyResponse(
        keyId=key_id,
        mode=key_info["mode"],
        x25519PublicKey=base64.b64encode(key_info["x25519_public"]).decode("ascii"),
        mlkemPublicKey=base64.b64encode(key_info["mlkem_public"]).decode("ascii"),
        createdAt=key_info["created_at"],
    )


@router.get("/keys", response_model=ListKEXKeysResponse)
async def list_kex_keys(
    request: Request,
    mode: str | None = None,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """List all hybrid KEX key pairs.

    Returns metadata about all KEX key pairs, optionally filtered by mode.
    Private key material is never exposed.
    """
    keys = []
    for key_id, info in _kex_key_store.items():
        # Apply filter
        if mode and info["mode"] != mode:
            continue

        keys.append(
            KEXKeyInfo(
                keyId=key_id,
                mode=info["mode"],
                x25519PublicKeyBytes=len(info["x25519_public"]),
                mlkemPublicKeyBytes=len(info["mlkem_public"]),
                createdAt=info["created_at"],
            )
        )

    return ListKEXKeysResponse(keys=keys)


@router.delete("/keys/{key_id}", response_model=DeleteKEXKeyResponse)
async def delete_kex_key(
    request: Request,
    key_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Delete a KEX key pair.

    Permanently deletes the key pair. This action cannot be undone.
    Any shared secrets derived using these keys remain valid.
    """
    if key_id not in _kex_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {key_id}",
        )

    del _kex_key_store[key_id]

    return DeleteKEXKeyResponse(
        deleted=True,
        keyId=key_id,
    )
