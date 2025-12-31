"""JOSE (JWS, JWE, JWK) API routes."""

import base64
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.jose_engine import (
    JOSEEngine,
    JWSAlgorithm,
    JWEAlgorithm,
    JWEEncryption,
    JOSEError,
    InvalidJWSError,
    InvalidJWEError,
    UnsupportedAlgorithmError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/api/v1/jose", tags=["jose"])

# Singleton JOSE engine
jose_engine = JOSEEngine()


# ============================================================================
# JWS (JSON Web Signature) - RFC 7515
# ============================================================================

class JWSCreateRequest(BaseModel):
    """JWS creation request schema."""
    payload: str = Field(..., description="Payload to sign (base64 encoded)")
    key: str = Field(..., description="Signing key (JWK JSON or base64 symmetric key)")
    algorithm: str = Field(
        default="EdDSA",
        description="JWS algorithm: EdDSA (recommended), ES256, ES384, HS256, HS384, HS512"
    )
    additional_headers: dict | None = Field(
        default=None,
        description="Additional protected header claims"
    )


class JWSCreateResponse(BaseModel):
    """JWS creation response schema."""
    jws: str = Field(..., description="JWS compact serialization (header.payload.signature)")
    header: dict
    algorithm: str


class JWSVerifyRequest(BaseModel):
    """JWS verification request schema."""
    jws: str = Field(..., description="JWS compact serialization to verify")
    key: str = Field(..., description="Verification key (JWK JSON or base64 symmetric key)")
    algorithms: list[str] | None = Field(
        default=None,
        description="Allowed algorithms (for algorithm confusion prevention)"
    )


class JWSVerifyResponse(BaseModel):
    """JWS verification response schema."""
    valid: bool
    payload: str = Field(..., description="Verified payload (base64 encoded)")
    header: dict
    algorithm: str


@router.post("/sign", response_model=JWSCreateResponse)
async def create_jws(
    data: JWSCreateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Create a JSON Web Signature (JWS).

    Signs the payload using the specified algorithm and returns
    the JWS in compact serialization format (header.payload.signature).

    Supported algorithms:
    - EdDSA (Ed25519): Recommended for new applications
    - ES256: ECDSA with P-256 curve
    - ES384: ECDSA with P-384 curve
    - HS256/HS384/HS512: HMAC for symmetric signing
    """
    try:
        payload = base64.b64decode(data.payload)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 payload",
        )

    try:
        algorithm = JWSAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Supported: {[a.value for a in JWSAlgorithm]}",
        )

    # Parse key
    key = _parse_key(data.key)

    try:
        result = jose_engine.sign_jws(
            payload=payload,
            key=key,
            algorithm=algorithm,
            additional_headers=data.additional_headers,
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return JWSCreateResponse(
        jws=result.compact,
        header=result.header,
        algorithm=algorithm.value,
    )


@router.post("/verify", response_model=JWSVerifyResponse)
async def verify_jws(
    data: JWSVerifyRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Verify a JSON Web Signature (JWS).

    Verifies the signature and returns the payload if valid.
    Use the `algorithms` parameter to prevent algorithm confusion attacks.
    """
    key = _parse_key(data.key)

    # Parse allowed algorithms
    allowed_algorithms = None
    if data.algorithms:
        try:
            allowed_algorithms = [JWSAlgorithm(a) for a in data.algorithms]
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid algorithm in allowlist: {e}",
            )

    try:
        payload, header = jose_engine.verify_jws(
            jws=data.jws,
            key=key,
            allowed_algorithms=allowed_algorithms,
        )
    except InvalidJWSError as e:
        return JWSVerifyResponse(
            valid=False,
            payload="",
            header={},
            algorithm="",
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return JWSVerifyResponse(
        valid=True,
        payload=base64.b64encode(payload).decode("ascii"),
        header=header,
        algorithm=header.get("alg", ""),
    )


# ============================================================================
# JWE (JSON Web Encryption) - RFC 7516
# ============================================================================

class JWECreateRequest(BaseModel):
    """JWE creation request schema."""
    plaintext: str = Field(..., description="Data to encrypt (base64 encoded)")
    key: str = Field(..., description="Encryption key (JWK JSON or base64 symmetric key)")
    algorithm: str = Field(
        default="dir",
        description="Key management algorithm: dir, A128KW, A256KW, ECDH-ES"
    )
    encryption: str = Field(
        default="A256GCM",
        description="Content encryption: A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512"
    )
    aad: str | None = Field(
        default=None,
        description="Additional authenticated data (base64 encoded)"
    )


class JWECreateResponse(BaseModel):
    """JWE creation response schema."""
    jwe: str = Field(..., description="JWE compact serialization")
    header: dict
    algorithm: str
    encryption: str


class JWEDecryptRequest(BaseModel):
    """JWE decryption request schema."""
    jwe: str = Field(..., description="JWE compact serialization to decrypt")
    key: str = Field(..., description="Decryption key")


class JWEDecryptResponse(BaseModel):
    """JWE decryption response schema."""
    plaintext: str = Field(..., description="Decrypted plaintext (base64 encoded)")
    header: dict
    algorithm: str
    encryption: str


@router.post("/encrypt", response_model=JWECreateResponse)
async def create_jwe(
    data: JWECreateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Create a JSON Web Encryption (JWE).

    Encrypts the plaintext and returns the JWE in compact serialization format.

    Key management algorithms:
    - dir: Direct encryption with symmetric key
    - A128KW, A256KW: AES Key Wrap
    - ECDH-ES: Elliptic Curve Diffie-Hellman

    Content encryption:
    - A128GCM, A256GCM: AES-GCM (recommended)
    - A128CBC-HS256, A256CBC-HS512: AES-CBC with HMAC
    """
    try:
        plaintext = base64.b64decode(data.plaintext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 plaintext",
        )

    try:
        algorithm = JWEAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Supported: {[a.value for a in JWEAlgorithm]}",
        )

    try:
        encryption = JWEEncryption(data.encryption)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown encryption: {data.encryption}. Supported: {[e.value for e in JWEEncryption]}",
        )

    key = _parse_key(data.key)

    aad = None
    if data.aad:
        try:
            aad = base64.b64decode(data.aad)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 aad",
            )

    try:
        result = jose_engine.encrypt_jwe(
            plaintext=plaintext,
            key=key,
            algorithm=algorithm,
            encryption=encryption,
            aad=aad,
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return JWECreateResponse(
        jwe=result.compact,
        header=result.header,
        algorithm=algorithm.value,
        encryption=encryption.value,
    )


@router.post("/decrypt", response_model=JWEDecryptResponse)
async def decrypt_jwe(
    data: JWEDecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt a JSON Web Encryption (JWE).

    Decrypts the JWE and returns the plaintext.
    """
    key = _parse_key(data.key)

    try:
        plaintext, header = jose_engine.decrypt_jwe(
            jwe=data.jwe,
            key=key,
        )
    except InvalidJWEError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {e}",
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return JWEDecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
        header=header,
        algorithm=header.get("alg", ""),
        encryption=header.get("enc", ""),
    )


# ============================================================================
# JWK (JSON Web Key) - RFC 7517
# ============================================================================

class JWKGenerateRequest(BaseModel):
    """JWK generation request schema."""
    key_type: str = Field(
        ...,
        description="Key type: EC (P-256, P-384), OKP (Ed25519, X25519), oct (symmetric)"
    )
    curve: str | None = Field(
        default=None,
        description="Curve for EC/OKP keys: P-256, P-384, Ed25519, X25519"
    )
    size: int | None = Field(
        default=None,
        description="Key size in bits for symmetric keys (128, 256)"
    )
    use: str | None = Field(
        default=None,
        description="Key use: sig (signature) or enc (encryption)"
    )
    kid: str | None = Field(
        default=None,
        description="Key ID"
    )


class JWKGenerateResponse(BaseModel):
    """JWK generation response schema."""
    private_jwk: dict = Field(..., description="Private JWK (keep secret)")
    public_jwk: dict | None = Field(None, description="Public JWK (for asymmetric keys)")


class JWKConvertRequest(BaseModel):
    """JWK conversion request schema."""
    key: str = Field(..., description="Key in PEM, DER, or raw format (base64 encoded)")
    format: str = Field(
        default="pem",
        description="Input format: pem, der, raw"
    )
    key_type: str | None = Field(
        default=None,
        description="Key type hint for raw keys"
    )


class JWKConvertResponse(BaseModel):
    """JWK conversion response schema."""
    jwk: dict


@router.post("/jwk/generate", response_model=JWKGenerateResponse)
async def generate_jwk(
    data: JWKGenerateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate a JSON Web Key (JWK).

    Supports:
    - EC keys: P-256, P-384 curves
    - OKP keys: Ed25519 (signing), X25519 (key exchange)
    - Symmetric (oct): 128-bit or 256-bit keys
    """
    try:
        private_jwk, public_jwk = jose_engine.generate_jwk(
            key_type=data.key_type,
            curve=data.curve,
            size=data.size,
            use=data.use,
            kid=data.kid,
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return JWKGenerateResponse(
        private_jwk=private_jwk,
        public_jwk=public_jwk,
    )


@router.post("/jwk/thumbprint")
async def get_jwk_thumbprint(
    jwk: dict,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
) -> dict:
    """Compute JWK thumbprint (RFC 7638).

    Returns the SHA-256 thumbprint of the JWK, which can be used
    as a key identifier.
    """
    try:
        thumbprint = jose_engine.compute_thumbprint(jwk)
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return {"thumbprint": thumbprint}


# ============================================================================
# Helpers
# ============================================================================

def _parse_key(key_str: str) -> bytes | dict:
    """Parse a key from string (JWK JSON or base64 bytes)."""
    # Try parsing as JWK JSON first
    try:
        import json
        key_dict = json.loads(key_str)
        if isinstance(key_dict, dict) and "kty" in key_dict:
            return key_dict
    except (json.JSONDecodeError, TypeError):
        pass

    # Try parsing as base64
    try:
        return base64.b64decode(key_str)
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid key format. Provide JWK JSON or base64-encoded key bytes.",
    )
