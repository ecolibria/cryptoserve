"""Digital Signature API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.signature_engine import (
    signature_engine,
    SignatureAlgorithm,
    SignatureFormat,
    KeyNotFoundError,
    UnsupportedAlgorithmError,
)
from app.core.identity_manager import identity_manager

router = APIRouter(prefix="/api/v1/signatures", tags=["signatures"])
security = HTTPBearer()


# Request/Response models


class GenerateKeyRequest(BaseModel):
    """Request to generate a signing key pair."""

    algorithm: SignatureAlgorithm = Field(
        default=SignatureAlgorithm.ED25519,
        description="Signature algorithm (Ed25519 recommended)",
    )
    context: str = Field(
        description="Context identifier for the key",
        min_length=1,
        max_length=64,
    )


class PublicKeyJWK(BaseModel):
    """JWK representation of a public key."""

    kty: str
    crv: str | None = None
    x: str
    y: str | None = None
    kid: str
    use: str = "sig"
    alg: str | None = None


class GenerateKeyResponse(BaseModel):
    """Response with generated key information."""

    key_id: str
    algorithm: str
    context: str
    public_key_jwk: PublicKeyJWK
    public_key_pem: str
    created_at: str


class SignRequest(BaseModel):
    """Request to sign a message."""

    message: str = Field(
        description="Base64-encoded message to sign",
    )
    key_id: str = Field(
        description="ID of the signing key to use",
    )
    output_format: SignatureFormat = Field(
        default=SignatureFormat.BASE64,
        description="Output format for signature",
    )


class SignResponse(BaseModel):
    """Response with signature."""

    signature: str = Field(description="Signature in requested format")
    algorithm: str
    key_id: str
    format: str


class VerifyRequest(BaseModel):
    """Request to verify a signature."""

    message: str = Field(
        description="Base64-encoded original message",
    )
    signature: str = Field(
        description="Signature to verify (format specified by signature_format)",
    )
    key_id: str = Field(
        description="ID of the signing key (public key used)",
    )
    signature_format: SignatureFormat = Field(
        default=SignatureFormat.BASE64,
        description="Format of the signature",
    )


class VerifyResponse(BaseModel):
    """Response with verification result."""

    valid: bool
    algorithm: str
    key_id: str
    message: str


class GetPublicKeyResponse(BaseModel):
    """Response with public key."""

    key_id: str
    algorithm: str
    public_key: str | dict = Field(
        description="Public key in requested format",
    )
    format: str


class ImportPublicKeyRequest(BaseModel):
    """Request to import a public key."""

    public_key: str | dict = Field(
        description="Public key data (PEM string or JWK object)",
    )
    format: str = Field(
        default="pem",
        description="Format of public key: 'pem' or 'jwk'",
    )
    key_id: str | None = Field(
        default=None,
        description="Optional key ID (generated if not provided)",
    )


class ImportPublicKeyResponse(BaseModel):
    """Response with imported key ID."""

    key_id: str
    algorithm: str


class KeyInfo(BaseModel):
    """Information about a signing key."""

    key_id: str
    algorithm: str
    context: str
    created_at: str
    public_key_jwk: PublicKeyJWK


class ListKeysResponse(BaseModel):
    """Response with list of keys."""

    keys: list[KeyInfo]


class DeleteKeyResponse(BaseModel):
    """Response for key deletion."""

    deleted: bool
    key_id: str


# Authentication dependency


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
                            """Wrapper to make Application look like Identity for signature endpoints."""

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


# Endpoints


@router.post("/keys/generate", response_model=GenerateKeyResponse)
async def generate_signing_key(
    request: Request,
    data: GenerateKeyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a new signing key pair.

    Creates a new asymmetric key pair for digital signatures.
    The private key is stored securely; the public key is returned for distribution.
    """
    try:
        key_pair = signature_engine.generate_key_pair(
            algorithm=data.algorithm,
            context=data.context,
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return GenerateKeyResponse(
        key_id=key_pair.key_id,
        algorithm=key_pair.algorithm.value,
        context=key_pair.context,
        public_key_jwk=PublicKeyJWK(**key_pair.public_key_jwk),
        public_key_pem=key_pair.public_key_pem.decode("utf-8"),
        created_at=key_pair.created_at.isoformat(),
    )


@router.post("/sign", response_model=SignResponse)
async def sign_message(
    request: Request,
    data: SignRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Sign a message.

    Signs the provided message using the specified signing key.
    Returns the signature in the requested format.
    """
    try:
        message = base64.b64decode(data.message)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 message",
        )

    try:
        result = signature_engine.sign(
            message=message,
            key_id=data.key_id,
            output_format=data.output_format,
        )
    except KeyNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Encode signature if raw bytes
    if isinstance(result.signature, bytes) and data.output_format == SignatureFormat.RAW:
        signature_str = base64.b64encode(result.signature).decode("ascii")
    elif isinstance(result.signature, bytes):
        signature_str = result.signature.decode("ascii")
    else:
        signature_str = result.signature

    return SignResponse(
        signature=signature_str,
        algorithm=result.algorithm.value,
        key_id=result.key_id,
        format=result.format.value,
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify_signature(
    request: Request,
    data: VerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a signature.

    Verifies that the signature was created by the signing key
    for the given message.
    """
    try:
        message = base64.b64decode(data.message)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 message",
        )

    try:
        if data.signature_format == SignatureFormat.BASE64:
            signature = base64.b64decode(data.signature)
        else:
            signature = data.signature.encode("latin-1")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature encoding",
        )

    try:
        result = signature_engine.verify(
            message=message,
            signature=signature,
            key_id=data.key_id,
            signature_format=SignatureFormat.RAW,  # We decoded above
        )
    except KeyNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return VerifyResponse(
        valid=result.valid,
        algorithm=result.algorithm.value,
        key_id=result.key_id,
        message=result.message,
    )


@router.get("/keys/{key_id}/public", response_model=GetPublicKeyResponse)
async def get_public_key(
    request: Request,
    key_id: str,
    format: str = "jwk",
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Get the public key for a signing key.

    Returns the public key in the requested format (jwk, pem, or raw).
    """
    if format not in ["jwk", "pem", "raw"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format must be 'jwk', 'pem', or 'raw'",
        )

    try:
        public_key = signature_engine.get_public_key(key_id, format=format)
    except KeyNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    # Format output
    if format == "pem" and isinstance(public_key, bytes):
        public_key_out = public_key.decode("utf-8")
    elif format == "raw" and isinstance(public_key, bytes):
        public_key_out = base64.b64encode(public_key).decode("ascii")
    else:
        public_key_out = public_key

    # Get algorithm from key store
    key_info = signature_engine.list_keys()
    algorithm = next((k["algorithm"] for k in key_info if k["key_id"] == key_id), "unknown")

    return GetPublicKeyResponse(
        key_id=key_id,
        algorithm=algorithm,
        public_key=public_key_out,
        format=format,
    )


@router.post("/keys/import", response_model=ImportPublicKeyResponse)
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
        if data.format == "jwk":
            public_key_data = data.public_key if isinstance(data.public_key, dict) else None
            if public_key_data is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="JWK format requires a JSON object",
                )
        elif data.format == "pem":
            public_key_data = data.public_key if isinstance(data.public_key, str) else None
            if public_key_data is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PEM format requires a string",
                )
            public_key_data = public_key_data.encode("utf-8")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format must be 'jwk' or 'pem'",
            )

        key_id = signature_engine.import_public_key(
            public_key_data=public_key_data,
            key_id=data.key_id,
            format=data.format,
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to import public key: {str(e)}",
        )

    # Get algorithm from key store
    key_info = signature_engine.list_keys()
    algorithm = next((k["algorithm"] for k in key_info if k["key_id"] == key_id), "unknown")

    return ImportPublicKeyResponse(
        key_id=key_id,
        algorithm=algorithm,
    )


@router.get("/keys", response_model=ListKeysResponse)
async def list_signing_keys(
    request: Request,
    context: str | None = None,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """List all signing keys.

    Returns metadata about all signing keys, optionally filtered by context.
    Private key material is never exposed.
    """
    keys = signature_engine.list_keys(context=context)

    return ListKeysResponse(
        keys=[
            KeyInfo(
                key_id=k["key_id"],
                algorithm=k["algorithm"],
                context=k["context"],
                created_at=k["created_at"],
                public_key_jwk=PublicKeyJWK(**k["public_key_jwk"]),
            )
            for k in keys
        ]
    )


@router.delete("/keys/{key_id}", response_model=DeleteKeyResponse)
async def delete_signing_key(
    request: Request,
    key_id: str,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Delete a signing key.

    Permanently deletes the signing key pair. This action cannot be undone.
    Any signatures created with this key can still be verified if the
    public key was distributed externally.
    """
    deleted = signature_engine.delete_key(key_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signing key not found: {key_id}",
        )

    return DeleteKeyResponse(
        deleted=True,
        key_id=key_id,
    )
