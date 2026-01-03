"""Crypto operations API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.crypto_engine import (
    crypto_engine,
    CryptoError,
    ContextNotFoundError,
    AuthorizationError,
    DecryptionError,
    UnsupportedModeError,
)
from app.core.identity_manager import identity_manager
from app.core.rate_limiter import (
    get_rate_limiter,
    RateLimitResult,
    RateLimitExceeded,
)
from app.schemas.context import AlgorithmOverride, CipherMode

router = APIRouter(prefix="/api/v1/crypto", tags=["crypto"])
security = HTTPBearer()


class EncryptRequest(BaseModel):
    """Encryption request schema."""
    plaintext: str  # Base64 encoded
    context: str
    algorithm_override: AlgorithmOverride | None = Field(
        default=None,
        description="Optional: Override automatic algorithm selection"
    )
    associated_data: str | None = Field(
        default=None,
        description="Optional: Additional authenticated data (AAD) - base64 encoded. "
                    "AAD is authenticated but not encrypted. Supported by AEAD modes "
                    "(GCM, CCM, ChaCha20-Poly1305). Must provide same AAD for decryption."
    )


class AlgorithmInfo(BaseModel):
    """Information about the algorithm used."""
    name: str
    mode: str
    key_bits: int
    description: str | None = None


class EncryptResponse(BaseModel):
    """Encryption response schema."""
    ciphertext: str  # Base64 encoded
    algorithm: AlgorithmInfo | None = Field(
        default=None,
        description="Algorithm used for encryption"
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Any warnings about the encryption (e.g., deprecation)"
    )


class DecryptRequest(BaseModel):
    """Decryption request schema."""
    ciphertext: str  # Base64 encoded
    context: str
    associated_data: str | None = Field(
        default=None,
        description="Optional: Additional authenticated data (AAD) - base64 encoded. "
                    "Must match AAD used during encryption if AAD was used."
    )


class DecryptResponse(BaseModel):
    """Decryption response schema."""
    plaintext: str  # Base64 encoded


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
            result = await db.execute(
                select(Application).where(Application.id == app_id)
            )
            app = result.scalar_one_or_none()

            if app and app.is_active:
                # Verify the token signature (public key may be string or bytes)
                try:
                    public_key = app.public_key
                    if isinstance(public_key, str):
                        public_key = public_key.encode('utf-8')
                    verified_payload = token_manager.verify_access_token(token, public_key)
                    if verified_payload:
                        # Return a "virtual" Identity object from the Application
                        # We create a duck-typed object that has the same interface
                        from app.models.identity import IdentityType, IdentityStatus

                        class ApplicationIdentity:
                            """Wrapper to make Application look like Identity for crypto endpoints."""
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
                except Exception:
                    pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired identity token",
    )


async def check_rate_limit(
    request: Request,
    identity: Identity,
    context_name: str | None = None,
) -> RateLimitResult:
    """Check rate limits and raise exception if exceeded.

    Args:
        request: FastAPI request for client IP
        identity: Authenticated identity
        context_name: Optional context being accessed

    Returns:
        RateLimitResult with headers to add to response

    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    limiter = get_rate_limiter()
    ip_address = request.client.host if request.client else "unknown"

    # Check all applicable rate limits
    result = await limiter.check_all(
        ip_address=ip_address,
        identity_id=str(identity.id),
        context_name=context_name,
    )

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {result.retry_after} seconds.",
            headers=result.headers,
        )

    return result


def add_rate_limit_headers(response: Response, result: RateLimitResult) -> None:
    """Add rate limit headers to response."""
    for key, value in result.headers.items():
        if value:  # Skip empty values
            response.headers[key] = value


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt(
    request: Request,
    response: Response,
    data: EncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Encrypt data.

    Encrypts the provided plaintext using the specified context's algorithm.
    Optionally accepts an algorithm_override to explicitly select cipher,
    mode, and key size.

    Rate limits apply per identity and per context.
    """
    # Check rate limits before expensive crypto operation
    rate_result = await check_rate_limit(request, identity, data.context)
    add_rate_limit_headers(response, rate_result)

    try:
        plaintext = base64.b64decode(data.plaintext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 plaintext",
        )

    # Parse optional AAD
    associated_data = None
    if data.associated_data:
        try:
            associated_data = base64.b64decode(data.associated_data)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 associated_data",
            )

    try:
        result = await crypto_engine.encrypt(
            db=db,
            plaintext=plaintext,
            context_name=data.context,
            identity=identity,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            algorithm_override=data.algorithm_override,
            associated_data=associated_data,
        )
    except ContextNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except (CryptoError, UnsupportedModeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Build algorithm info for response
    algorithm_info = AlgorithmInfo(
        name=result.algorithm,
        mode=result.mode.value if hasattr(result.mode, 'value') else str(result.mode),
        key_bits=result.key_bits,
        description=result.description,
    )

    return EncryptResponse(
        ciphertext=base64.b64encode(result.ciphertext).decode("ascii"),
        algorithm=algorithm_info,
        warnings=result.warnings,
    )


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(
    request: Request,
    response: Response,
    data: DecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Decrypt data.

    Decrypts the provided ciphertext using the context's key.
    If the ciphertext was encrypted with AAD, the same AAD must be provided.

    Rate limits apply per identity and per context.
    """
    # Check rate limits before expensive crypto operation
    rate_result = await check_rate_limit(request, identity, data.context)
    add_rate_limit_headers(response, rate_result)

    try:
        ciphertext = base64.b64decode(data.ciphertext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 ciphertext",
        )

    # Parse optional AAD
    associated_data = None
    if data.associated_data:
        try:
            associated_data = base64.b64decode(data.associated_data)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 associated_data",
            )

    try:
        plaintext = await crypto_engine.decrypt(
            db=db,
            packed_ciphertext=ciphertext,
            context_name=data.context,
            identity=identity,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            associated_data=associated_data,
        )
    except ContextNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except DecryptionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return DecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )


# ============================================================================
# Key Bundle Endpoint (for SDK local caching)
# ============================================================================


class KeyBundleRequest(BaseModel):
    """Request for encryption key bundle."""
    context: str = Field(..., description="Encryption context name")


class KeyBundleResponse(BaseModel):
    """Response containing encryption key for local caching."""
    key: str = Field(..., description="Base64-encoded encryption key")
    key_id: str = Field(..., description="Key identifier")
    algorithm: str = Field(..., description="Algorithm name (e.g., AES-256-GCM)")
    version: int = Field(..., description="Key version")
    ttl: int = Field(default=300, description="Recommended cache TTL in seconds")


def _get_key_size_from_algorithm(algorithm: str | None) -> int:
    """Extract key size in bytes from algorithm name."""
    if not algorithm:
        return 32  # Default AES-256
    if "128" in algorithm:
        return 16
    if "192" in algorithm:
        return 24
    return 32  # Default AES-256


@router.post("/key-bundle", response_model=KeyBundleResponse)
async def get_key_bundle(
    request: Request,
    response: Response,
    data: KeyBundleRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get encryption key bundle for local caching.

    Returns the current active key for a context, enabling SDK clients
    to perform local encryption/decryption without server round-trips.

    This dramatically reduces latency from ~5-50ms (server round-trip)
    to ~0.1-0.5ms (local crypto with cached key).

    Rate limits apply per identity and per context.
    """
    # Check rate limits
    rate_result = await check_rate_limit(request, identity, data.context)
    add_rate_limit_headers(response, rate_result)

    # Import here to avoid circular imports
    from sqlalchemy import select
    from app.models.context import Context
    from app.models.key import Key
    from app.core.key_manager import key_manager

    # 1. Get context and validate it exists
    result = await db.execute(
        select(Context).where(Context.name == data.context)
    )
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown context: {data.context}",
        )

    # 2. Check identity authorization
    if data.context not in identity.allowed_contexts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity not authorized for context: {data.context}",
        )

    # 3. Get or create active key
    key_size = _get_key_size_from_algorithm(context.algorithm)
    key_material, key_id = await key_manager.get_or_create_key(
        db=db,
        context=data.context,
        tenant_id=str(identity.tenant_id),
        key_size=key_size,
    )

    # 4. Get key record for version info
    key_result = await db.execute(select(Key).where(Key.id == key_id))
    key_record = key_result.scalar_one_or_none()
    version = key_record.version if key_record else 1

    # 5. Return key bundle
    return KeyBundleResponse(
        key=base64.b64encode(key_material).decode("ascii"),
        key_id=key_id,
        algorithm=context.algorithm or "AES-256-GCM",
        version=version,
        ttl=300,  # 5 minutes
    )
