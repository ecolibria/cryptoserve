"""Post-Quantum Cryptography Signature API routes.

Provides endpoints for NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
post-quantum digital signature operations.
"""

import base64
import secrets
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.identity_manager import identity_manager
from app.core.hybrid_crypto import (
    MLDSA,
    SLHDSA,
    PQCError,
    is_pqc_available,
    get_mldsa,
    get_slhdsa,
)

router = APIRouter(prefix="/api/v1/pqc", tags=["pqc-signatures"])
security = HTTPBearer()


# =============================================================================
# In-memory key storage (production should use HSM/secure storage)
# =============================================================================

_pqc_key_store: dict[str, dict] = {}


# =============================================================================
# Request/Response Models
# =============================================================================


class AlgorithmInfo(BaseModel):
    """Information about a PQC algorithm."""

    name: str
    nistLevel: int = Field(description="NIST security level (1, 3, or 5)")
    publicKeyBytes: int
    secretKeyBytes: int
    signatureBytes: int
    standard: str
    variant: str | None = None
    securityBasis: str | None = None


class ListAlgorithmsResponse(BaseModel):
    """Response with available algorithms."""

    available: bool
    mldsa: list[AlgorithmInfo]
    slhdsa: list[AlgorithmInfo]


class GenerateKeyRequest(BaseModel):
    """Request to generate a PQC signing key pair."""

    algorithm: str = Field(
        default="ML-DSA-65",
        description="Algorithm: ML-DSA-44/65/87 or SLH-DSA-SHA2-128f/128s/192f/192s/256f/256s",
    )
    context: str = Field(
        description="Context identifier for the key",
        min_length=1,
        max_length=64,
    )


class GenerateKeyResponse(BaseModel):
    """Response with generated key information."""

    keyId: str
    algorithm: str
    context: str
    publicKey: str = Field(description="Base64-encoded public key")
    publicKeyBytes: int
    signatureBytes: int
    nistLevel: int
    createdAt: str


class SignRequest(BaseModel):
    """Request to sign a message with PQC."""

    message: str = Field(description="Base64-encoded message to sign")
    keyId: str = Field(description="ID of the PQC signing key")


class SignResponse(BaseModel):
    """Response with signature."""

    signature: str = Field(description="Base64-encoded signature")
    algorithm: str
    keyId: str
    signatureBytes: int


class VerifyRequest(BaseModel):
    """Request to verify a PQC signature."""

    message: str = Field(description="Base64-encoded original message")
    signature: str = Field(description="Base64-encoded signature")
    keyId: str = Field(description="ID of the signing key")


class VerifyResponse(BaseModel):
    """Response with verification result."""

    valid: bool
    algorithm: str
    keyId: str
    message: str


class GetPublicKeyResponse(BaseModel):
    """Response with public key."""

    keyId: str
    algorithm: str
    publicKey: str = Field(description="Base64-encoded public key")
    context: str
    nistLevel: int
    createdAt: str


class KeyInfo(BaseModel):
    """Information about a PQC key."""

    keyId: str
    algorithm: str
    context: str
    nistLevel: int
    publicKeyBytes: int
    signatureBytes: int
    createdAt: str


class ListKeysResponse(BaseModel):
    """Response with list of keys."""

    keys: list[KeyInfo]


class DeleteKeyResponse(BaseModel):
    """Response for key deletion."""

    deleted: bool
    keyId: str


class ImportPublicKeyRequest(BaseModel):
    """Request to import a public key."""

    publicKey: str = Field(description="Base64-encoded public key")
    algorithm: str = Field(description="Algorithm name (e.g., ML-DSA-65, SLH-DSA-SHA2-128f)")
    context: str = Field(default="imported", description="Context identifier")


# =============================================================================
# Authentication
# =============================================================================


async def get_sdk_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Identity:
    """Get identity from SDK token (supports both identity and application tokens)."""
    token = credentials.credentials

    # First, try legacy identity token
    identity = await identity_manager.get_identity_by_token(db, token)
    if identity:
        return identity

    # Try application token (new Ed25519-signed tokens)
    from app.core.token_manager import token_manager
    from app.models.application import Application
    from sqlalchemy import select

    payload = token_manager.decode_token_unverified(token)
    if payload and payload.get("type") == "access":
        app_id = payload.get("sub")
        if app_id:
            result = await db.execute(select(Application).where(Application.id == app_id))
            app = result.scalar_one_or_none()

            if app and app.is_active:
                # Verify the token signature (public key may be string or bytes)
                try:
                    public_key = app.public_key
                    if isinstance(public_key, str):
                        public_key = public_key.encode("utf-8")
                    verified_payload = token_manager.verify_access_token(token, public_key)
                    if verified_payload:
                        # Return a "virtual" Identity object from the Application
                        # We create a duck-typed object that has the same interface
                        from app.models.identity import IdentityType, IdentityStatus

                        class ApplicationIdentity:
                            """Wrapper to make Application look like Identity for PQC endpoints."""

                            def __init__(self, app: Application):
                                self.id = app.id
                                self.tenant_id = app.tenant_id
                                self.user_id = app.user_id
                                self.type = IdentityType.SERVICE
                                self.name = app.name
                                self.team = app.team
                                self.environment = app.environment
                                self.allowed_contexts = app.allowed_contexts
                                self.status = IdentityStatus.ACTIVE
                                self.created_at = app.created_at
                                self.expires_at = app.expires_at
                                self.last_used_at = app.last_used_at
                                self._app = app

                            @property
                            def is_active(self):
                                return self._app.is_active

                        return ApplicationIdentity(app)
                except Exception as e:
                    import logging

                    logging.getLogger(__name__).debug("Application token verification failed: %s", e)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired identity token",
    )


# =============================================================================
# Helper Functions
# =============================================================================


def _get_algorithm_class(algorithm: str) -> tuple[type, dict]:
    """Get the algorithm class and params for a given algorithm name."""
    if algorithm in MLDSA.PARAMS:
        return MLDSA, MLDSA.PARAMS[algorithm]
    elif algorithm in SLHDSA.PARAMS:
        return SLHDSA, SLHDSA.PARAMS[algorithm]
    else:
        raise ValueError(
            f"Unknown algorithm: {algorithm}. " f"Valid: {list(MLDSA.PARAMS.keys()) + list(SLHDSA.PARAMS.keys())}"
        )


def _get_signer(algorithm: str, private_key: bytes = None):
    """Get a signer instance for the given algorithm."""
    if algorithm in MLDSA.PARAMS:
        signer = get_mldsa(algorithm)
    elif algorithm in SLHDSA.PARAMS:
        signer = get_slhdsa(algorithm)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    return signer


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/algorithms", response_model=ListAlgorithmsResponse)
async def list_algorithms():
    """List available PQC signature algorithms.

    Returns information about all supported post-quantum signature
    algorithms including ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
    """
    available = is_pqc_available()

    mldsa_algos = []
    slhdsa_algos = []

    if available:
        # ML-DSA algorithms
        for name, params in MLDSA.PARAMS.items():
            mldsa_algos.append(
                AlgorithmInfo(
                    name=name,
                    nistLevel=params["level"],
                    publicKeyBytes=params["pk_len"],
                    secretKeyBytes=params["sk_len"],
                    signatureBytes=params["sig_len"],
                    standard="NIST FIPS 204",
                    securityBasis="lattice-based",
                )
            )

        # SLH-DSA algorithms
        for name, params in SLHDSA.PARAMS.items():
            slhdsa_algos.append(
                AlgorithmInfo(
                    name=name,
                    nistLevel=params["level"],
                    publicKeyBytes=params["pk_len"],
                    secretKeyBytes=params["sk_len"],
                    signatureBytes=params["sig_len"],
                    standard="NIST FIPS 205",
                    variant=params["variant"],
                    securityBasis="hash-based (conservative)",
                )
            )

    return ListAlgorithmsResponse(
        available=available,
        mldsa=mldsa_algos,
        slhdsa=slhdsa_algos,
    )


@router.post("/keys/generate", response_model=GenerateKeyResponse)
async def generate_pqc_key(
    request: Request,
    data: GenerateKeyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a new PQC signing key pair.

    Creates a new post-quantum key pair for digital signatures.
    Supports both ML-DSA (lattice-based) and SLH-DSA (hash-based).

    ML-DSA: Faster operations, moderate key/signature sizes
    SLH-DSA: Conservative security (hash-based), tiny keys but large signatures
    """
    if not is_pqc_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PQC not available. liboqs library is not installed.",
        )

    try:
        algo_class, params = _get_algorithm_class(data.algorithm)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    try:
        # Create signer and generate keys
        signer = _get_signer(data.algorithm)
        public_key = signer.generate_keypair()
        private_key = signer.private_key

        # Generate key ID
        key_id = f"pqc-{secrets.token_hex(16)}"

        # Store key (in production, use HSM/secure storage)
        now = datetime.now(timezone.utc)
        _pqc_key_store[key_id] = {
            "algorithm": data.algorithm,
            "context": data.context,
            "public_key": public_key,
            "private_key": private_key,
            "params": params,
            "created_at": now.isoformat(),
            "standard": "FIPS 205" if "SLH" in data.algorithm else "FIPS 204",
        }

        return GenerateKeyResponse(
            keyId=key_id,
            algorithm=data.algorithm,
            context=data.context,
            publicKey=base64.b64encode(public_key).decode("ascii"),
            publicKeyBytes=len(public_key),
            signatureBytes=params["sig_len"],
            nistLevel=params["level"],
            createdAt=now.isoformat(),
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PQC operation failed: {str(e)}",
        )


@router.post("/sign", response_model=SignResponse)
async def sign_message(
    request: Request,
    data: SignRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Sign a message using PQC.

    Signs the provided message using the specified post-quantum signing key.
    Note: SLH-DSA signatures are large (8-50 KB) but have conservative security.
    """
    # Decode message
    try:
        message = base64.b64decode(data.message)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 message",
        )

    # Get key
    if data.keyId not in _pqc_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {data.keyId}",
        )

    key_info = _pqc_key_store[data.keyId]
    algorithm = key_info["algorithm"]

    try:
        # Create signer with stored key
        signer = _get_signer(algorithm)
        signer.set_keypair(key_info["public_key"], key_info["private_key"])

        # Sign
        signature = signer.sign(message)

        return SignResponse(
            signature=base64.b64encode(signature).decode("ascii"),
            algorithm=algorithm,
            keyId=data.keyId,
            signatureBytes=len(signature),
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signing failed: {str(e)}",
        )


@router.post("/verify", response_model=VerifyResponse)
async def verify_signature(
    request: Request,
    data: VerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a PQC signature.

    Verifies that the signature was created by the signing key
    for the given message using post-quantum algorithms.
    """
    # Decode message
    try:
        message = base64.b64decode(data.message)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 message",
        )

    # Decode signature
    try:
        signature = base64.b64decode(data.signature)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 signature",
        )

    # Get key
    if data.keyId not in _pqc_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {data.keyId}",
        )

    key_info = _pqc_key_store[data.keyId]
    algorithm = key_info["algorithm"]

    try:
        # Create verifier
        signer = _get_signer(algorithm)

        # Verify
        valid = signer.verify(message, signature, key_info["public_key"])

        return VerifyResponse(
            valid=valid,
            algorithm=algorithm,
            keyId=data.keyId,
            message="Signature valid" if valid else "Signature invalid",
        )

    except PQCError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}",
        )


@router.get("/keys/{key_id}", response_model=GetPublicKeyResponse)
async def get_public_key(
    request: Request,
    key_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Get the public key for a PQC signing key.

    Returns the public key in base64 format. The private key
    is never exposed through the API.
    """
    if key_id not in _pqc_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {key_id}",
        )

    key_info = _pqc_key_store[key_id]

    return GetPublicKeyResponse(
        keyId=key_id,
        algorithm=key_info["algorithm"],
        publicKey=base64.b64encode(key_info["public_key"]).decode("ascii"),
        context=key_info["context"],
        nistLevel=key_info["params"]["level"],
        createdAt=key_info["created_at"],
    )


@router.get("/keys", response_model=ListKeysResponse)
async def list_keys(
    request: Request,
    context: str | None = None,
    algorithm: str | None = None,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """List all PQC signing keys.

    Returns metadata about all PQC signing keys, optionally filtered
    by context or algorithm. Private key material is never exposed.
    """
    keys = []
    for key_id, info in _pqc_key_store.items():
        # Apply filters
        if context and info["context"] != context:
            continue
        if algorithm and info["algorithm"] != algorithm:
            continue

        keys.append(
            KeyInfo(
                keyId=key_id,
                algorithm=info["algorithm"],
                context=info["context"],
                nistLevel=info["params"]["level"],
                publicKeyBytes=info["params"]["pk_len"],
                signatureBytes=info["params"]["sig_len"],
                createdAt=info["created_at"],
            )
        )

    return ListKeysResponse(keys=keys)


@router.delete("/keys/{key_id}", response_model=DeleteKeyResponse)
async def delete_key(
    request: Request,
    key_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Delete a PQC signing key.

    Permanently deletes the signing key pair. This action cannot be undone.
    Any signatures created with this key can still be verified if the
    public key was distributed externally.
    """
    if key_id not in _pqc_key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {key_id}",
        )

    del _pqc_key_store[key_id]

    return DeleteKeyResponse(
        deleted=True,
        keyId=key_id,
    )


@router.post("/keys/import", response_model=GetPublicKeyResponse)
async def import_public_key(
    request: Request,
    data: ImportPublicKeyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Import a public key for verification.

    Imports an external public key so it can be used to verify signatures.
    Only public keys can be imported; private keys are never accepted.
    """
    try:
        algo_class, params = _get_algorithm_class(data.algorithm)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    try:
        pk_bytes = base64.b64decode(data.publicKey)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 public key",
        )

    # Validate key length
    if len(pk_bytes) != params["pk_len"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid public key length. Expected {params['pk_len']} bytes, got {len(pk_bytes)}",
        )

    # Generate key ID
    key_id = f"pqc-import-{secrets.token_hex(16)}"

    now = datetime.now(timezone.utc)
    _pqc_key_store[key_id] = {
        "algorithm": data.algorithm,
        "context": data.context,
        "public_key": pk_bytes,
        "private_key": None,  # No private key for imported public keys
        "params": params,
        "created_at": now.isoformat(),
        "standard": "FIPS 205" if "SLH" in data.algorithm else "FIPS 204",
    }

    return GetPublicKeyResponse(
        keyId=key_id,
        algorithm=data.algorithm,
        publicKey=data.publicKey,
        context=data.context,
        nistLevel=params["level"],
        createdAt=now.isoformat(),
    )
