"""Asymmetric Encryption and Key Exchange API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.asymmetric_engine import (
    AsymmetricEngine,
    KeyExchangeAlgorithm,
    AsymmetricAlgorithm,
    AsymmetricError,
    UnsupportedAlgorithmError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/api/v1/crypto", tags=["asymmetric"])

# Singleton engine
asymmetric_engine = AsymmetricEngine()


# ============================================================================
# Key Exchange
# ============================================================================

class KeyExchangeGenerateRequest(BaseModel):
    """Key exchange key generation request."""
    algorithm: str = Field(
        default="x25519",
        description="Algorithm: x25519 (recommended), ecdh-p256, ecdh-p384"
    )


class KeyExchangeGenerateResponse(BaseModel):
    """Key exchange key generation response."""
    private_key: str = Field(..., description="Private key (base64)")
    public_key: str = Field(..., description="Public key (base64)")
    algorithm: str


class KeyExchangeDeriveRequest(BaseModel):
    """Key exchange derivation request."""
    private_key: str = Field(..., description="Your private key (base64)")
    peer_public_key: str = Field(..., description="Peer's public key (base64)")
    algorithm: str = Field(default="x25519")
    key_length: int = Field(default=32, description="Derived key length in bytes")
    info: str | None = Field(default=None, description="Context info for HKDF (base64)")


class KeyExchangeDeriveResponse(BaseModel):
    """Key exchange derivation response."""
    shared_secret: str = Field(..., description="Derived shared secret (base64)")
    algorithm: str
    length_bytes: int


@router.post("/key-exchange/generate", response_model=KeyExchangeGenerateResponse)
async def generate_key_exchange_keys(
    data: KeyExchangeGenerateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate key exchange key pair.

    Generates an ephemeral key pair for Diffie-Hellman key exchange.

    Algorithms:
    - x25519: Modern, fast, recommended
    - ecdh-p256: NIST P-256 curve
    - ecdh-p384: NIST P-384 curve for higher security
    """
    try:
        algorithm = KeyExchangeAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Supported: {[a.value for a in KeyExchangeAlgorithm]}",
        )

    try:
        from cryptography.hazmat.primitives import serialization

        # Map key exchange algorithm to asymmetric algorithm
        algo_map = {
            KeyExchangeAlgorithm.X25519: AsymmetricAlgorithm.X25519_AESGCM,
            KeyExchangeAlgorithm.ECDH_P256: AsymmetricAlgorithm.ECIES_P256,
            KeyExchangeAlgorithm.ECDH_P384: AsymmetricAlgorithm.ECIES_P384,
        }
        asymmetric_algo = algo_map.get(algorithm)
        if not asymmetric_algo:
            raise UnsupportedAlgorithmError(f"Unsupported key exchange algorithm: {algorithm}")

        key_pair = asymmetric_engine.generate_key_pair(
            algorithm=asymmetric_algo,
            context="key-exchange",
        )

        # Serialize keys to raw bytes
        if algorithm == KeyExchangeAlgorithm.X25519:
            private_bytes = key_pair.private_key.private_bytes_raw()
            public_bytes = key_pair.public_key.public_bytes_raw()
        else:
            # ECDH uses X.509 format
            private_bytes = key_pair.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_bytes = key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return KeyExchangeGenerateResponse(
        private_key=base64.b64encode(private_bytes).decode("ascii"),
        public_key=base64.b64encode(public_bytes).decode("ascii"),
        algorithm=algorithm.value,
    )


@router.post("/key-exchange/derive", response_model=KeyExchangeDeriveResponse)
async def derive_shared_secret(
    data: KeyExchangeDeriveRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Derive shared secret from key exchange.

    Performs Diffie-Hellman key exchange to derive a shared secret
    that can be used for symmetric encryption.
    """
    try:
        private_key = base64.b64decode(data.private_key)
        peer_public_key = base64.b64decode(data.peer_public_key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 key",
        )

    try:
        algorithm = KeyExchangeAlgorithm(data.algorithm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}",
        )

    info = None
    if data.info:
        try:
            info = base64.b64decode(data.info)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 info",
            )

    try:
        shared_secret = asymmetric_engine.derive_shared_secret(
            private_key=private_key,
            peer_public_key=peer_public_key,
            algorithm=algorithm,
            key_length=data.key_length,
            info=info,
        )
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return KeyExchangeDeriveResponse(
        shared_secret=base64.b64encode(shared_secret).decode("ascii"),
        algorithm=algorithm.value,
        length_bytes=len(shared_secret),
    )


# ============================================================================
# Hybrid Encryption (ECIES-style)
# ============================================================================

class HybridEncryptRequest(BaseModel):
    """Hybrid encryption request."""
    plaintext: str = Field(..., description="Data to encrypt (base64)")
    recipient_public_key: str = Field(..., description="Recipient's public key (base64)")
    algorithm: str = Field(
        default="x25519-aes256gcm",
        description="Algorithm: x25519-aes256gcm (recommended), ecies-p256"
    )
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HybridEncryptResponse(BaseModel):
    """Hybrid encryption response."""
    ciphertext: str = Field(..., description="Encrypted data with ephemeral public key (base64)")
    algorithm: str


class HybridDecryptRequest(BaseModel):
    """Hybrid decryption request."""
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    private_key: str = Field(..., description="Your private key (base64)")
    algorithm: str = Field(default="x25519-aes256gcm")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HybridDecryptResponse(BaseModel):
    """Hybrid decryption response."""
    plaintext: str = Field(..., description="Decrypted data (base64)")


@router.post("/hybrid/encrypt", response_model=HybridEncryptResponse)
async def hybrid_encrypt(
    data: HybridEncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encrypt data using hybrid encryption (ECIES-style).

    Combines asymmetric key exchange with symmetric encryption:
    1. Generate ephemeral key pair
    2. Derive shared secret with recipient's public key
    3. Encrypt data with derived symmetric key
    4. Return ephemeral public key + ciphertext

    This allows encrypting to a recipient's public key without
    needing a pre-shared symmetric key.
    """
    try:
        plaintext = base64.b64decode(data.plaintext)
        recipient_public_key = base64.b64decode(data.recipient_public_key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

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
        ciphertext = asymmetric_engine.hybrid_encrypt(
            plaintext=plaintext,
            recipient_public_key=recipient_public_key,
            algorithm=data.algorithm,
            aad=aad,
        )
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return HybridEncryptResponse(
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        algorithm=data.algorithm,
    )


@router.post("/hybrid/decrypt", response_model=HybridDecryptResponse)
async def hybrid_decrypt(
    data: HybridDecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt data encrypted with hybrid encryption.

    Extracts the ephemeral public key from the ciphertext,
    derives the shared secret, and decrypts the data.
    """
    try:
        ciphertext = base64.b64decode(data.ciphertext)
        private_key = base64.b64decode(data.private_key)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

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
        plaintext = asymmetric_engine.hybrid_decrypt(
            ciphertext=ciphertext,
            private_key=private_key,
            algorithm=data.algorithm,
            aad=aad,
        )
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return HybridDecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )


# ============================================================================
# RSA Operations
# ============================================================================

class RSAGenerateRequest(BaseModel):
    """RSA key generation request."""
    key_size: int = Field(default=2048, description="Key size in bits (2048, 3072, 4096)")


class RSAGenerateResponse(BaseModel):
    """RSA key generation response."""
    private_key_pem: str = Field(..., description="Private key in PEM format")
    public_key_pem: str = Field(..., description="Public key in PEM format")
    key_size: int


class RSAEncryptRequest(BaseModel):
    """RSA encryption request (OAEP)."""
    plaintext: str = Field(..., description="Data to encrypt (base64)")
    public_key_pem: str = Field(..., description="RSA public key in PEM format")
    hash_algorithm: str = Field(default="sha256", description="Hash: sha256, sha384, sha512")


class RSAEncryptResponse(BaseModel):
    """RSA encryption response."""
    ciphertext: str = Field(..., description="Encrypted data (base64)")


class RSADecryptRequest(BaseModel):
    """RSA decryption request."""
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    private_key_pem: str = Field(..., description="RSA private key in PEM format")
    hash_algorithm: str = Field(default="sha256")


class RSADecryptResponse(BaseModel):
    """RSA decryption response."""
    plaintext: str = Field(..., description="Decrypted data (base64)")


@router.post("/rsa/generate", response_model=RSAGenerateResponse)
async def generate_rsa_keys(
    data: RSAGenerateRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate RSA key pair.

    Generates an RSA key pair for encryption (OAEP) or signing (PSS).
    Minimum recommended key size is 2048 bits.
    """
    if data.key_size < 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key size must be at least 2048 bits",
        )

    try:
        from cryptography.hazmat.primitives import serialization

        key_pair = asymmetric_engine.generate_key_pair(
            algorithm=AsymmetricAlgorithm.RSA_OAEP_SHA256,
            context="rsa-generation",
            rsa_key_size=data.key_size,
        )

        # Serialize to PEM format
        private_pem = key_pair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = key_pair.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return RSAGenerateResponse(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        key_size=data.key_size,
    )


@router.post("/rsa/encrypt", response_model=RSAEncryptResponse)
async def rsa_encrypt(
    data: RSAEncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encrypt data using RSA-OAEP.

    Uses Optimal Asymmetric Encryption Padding (OAEP) for security.
    Note: RSA encryption is limited by key size. For larger data,
    use hybrid encryption.
    """
    try:
        plaintext = base64.b64decode(data.plaintext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 plaintext",
        )

    try:
        ciphertext = asymmetric_engine.rsa_encrypt(
            plaintext=plaintext,
            public_key_pem=data.public_key_pem,
            hash_algorithm=data.hash_algorithm,
        )
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return RSAEncryptResponse(
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
    )


@router.post("/rsa/decrypt", response_model=RSADecryptResponse)
async def rsa_decrypt(
    data: RSADecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt RSA-OAEP encrypted data."""
    try:
        ciphertext = base64.b64decode(data.ciphertext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 ciphertext",
        )

    try:
        plaintext = asymmetric_engine.rsa_decrypt(
            ciphertext=ciphertext,
            private_key_pem=data.private_key_pem,
            hash_algorithm=data.hash_algorithm,
        )
    except AsymmetricError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return RSADecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )
