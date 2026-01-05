"""HPKE (Hybrid Public Key Encryption) API routes.

Implements RFC 9180 HPKE REST API for modern hybrid encryption.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.models import Identity
from app.core.hpke_engine import (
    HPKEEngine,
    HPKECipherSuite,
    HPKEMode,
    HPKEEncryptedMessage,
    HPKEError,
    hpke_available,
    get_hpke_engine,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/api/v1/crypto/hpke", tags=["hpke"])


# ============================================================================
# Request/Response Models
# ============================================================================

class HPKEKeyPairRequest(BaseModel):
    """HPKE key pair generation request."""
    suite: str = Field(
        default="x25519-sha256-aes128gcm",
        description="Cipher suite: x25519-sha256-aes128gcm (recommended), p256-sha256-aes128gcm, p384-sha384-aes256gcm"
    )


class HPKEKeyPairResponse(BaseModel):
    """HPKE key pair generation response."""
    private_key: str = Field(..., description="Private key (base64)")
    public_key: str = Field(..., description="Public key (base64)")
    suite: str


class HPKEEncryptRequest(BaseModel):
    """HPKE encryption request (Base mode)."""
    plaintext: str = Field(..., description="Data to encrypt (base64)")
    recipient_public_key: str = Field(..., description="Recipient's public key (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info for key derivation (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKEEncryptResponse(BaseModel):
    """HPKE encryption response."""
    enc: str = Field(..., description="Encapsulated key (base64)")
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    suite: str
    mode: str


class HPKEDecryptRequest(BaseModel):
    """HPKE decryption request (Base mode)."""
    enc: str = Field(..., description="Encapsulated key (base64)")
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    recipient_private_key: str = Field(..., description="Recipient's private key (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKEDecryptResponse(BaseModel):
    """HPKE decryption response."""
    plaintext: str = Field(..., description="Decrypted data (base64)")


class HPKEAuthEncryptRequest(BaseModel):
    """HPKE authenticated encryption request (Auth mode)."""
    plaintext: str = Field(..., description="Data to encrypt (base64)")
    sender_private_key: str = Field(..., description="Sender's private key for authentication (base64)")
    recipient_public_key: str = Field(..., description="Recipient's public key (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKEAuthDecryptRequest(BaseModel):
    """HPKE authenticated decryption request (Auth mode)."""
    enc: str = Field(..., description="Encapsulated key (base64)")
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    recipient_private_key: str = Field(..., description="Recipient's private key (base64)")
    sender_public_key: str = Field(..., description="Sender's public key for verification (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKEPSKEncryptRequest(BaseModel):
    """HPKE PSK encryption request."""
    plaintext: str = Field(..., description="Data to encrypt (base64)")
    recipient_public_key: str = Field(..., description="Recipient's public key (base64)")
    psk: str = Field(..., description="Pre-shared key (base64)")
    psk_id: str = Field(..., description="PSK identifier (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKEPSKDecryptRequest(BaseModel):
    """HPKE PSK decryption request."""
    enc: str = Field(..., description="Encapsulated key (base64)")
    ciphertext: str = Field(..., description="Encrypted data (base64)")
    recipient_private_key: str = Field(..., description="Recipient's private key (base64)")
    psk: str = Field(..., description="Pre-shared key (base64)")
    psk_id: str = Field(..., description="PSK identifier (base64)")
    suite: str = Field(default="x25519-sha256-aes128gcm")
    info: str | None = Field(default=None, description="Context info (base64)")
    aad: str | None = Field(default=None, description="Additional authenticated data (base64)")


class HPKESuiteInfo(BaseModel):
    """HPKE cipher suite information."""
    suite: str
    name: str
    kem: str
    kdf: str
    aead: str
    security_level: int
    nist_approved: bool
    recommended: bool


# ============================================================================
# Helper Functions
# ============================================================================

def _get_engine() -> HPKEEngine:
    """Get HPKE engine, checking availability."""
    if not hpke_available():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="HPKE not available. Install pyhpke: pip install pyhpke"
        )
    return get_hpke_engine()


def _parse_suite(suite_str: str) -> HPKECipherSuite:
    """Parse cipher suite string to enum."""
    try:
        return HPKECipherSuite(suite_str)
    except ValueError:
        valid_suites = [s.value for s in HPKECipherSuite]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown cipher suite: {suite_str}. Valid: {valid_suites}"
        )


def _decode_b64(data: str | None, field_name: str) -> bytes | None:
    """Decode base64 or return None."""
    if data is None:
        return None
    try:
        return base64.b64decode(data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 in {field_name}"
        )


def _decode_b64_required(data: str, field_name: str) -> bytes:
    """Decode required base64 field."""
    try:
        return base64.b64decode(data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 in {field_name}"
        )


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/suites", response_model=list[HPKESuiteInfo])
async def list_cipher_suites(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """List all supported HPKE cipher suites.

    Returns information about each suite including the KEM, KDF, and AEAD
    algorithms, security level, and NIST approval status.
    """
    engine = _get_engine()
    return engine.list_cipher_suites()


@router.post("/keypair", response_model=HPKEKeyPairResponse)
async def generate_keypair(
    data: HPKEKeyPairRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Generate an HPKE key pair.

    The key pair can be used for receiving encrypted messages.
    Keep the private key secure and share the public key with senders.

    Supported cipher suites:
    - x25519-sha256-aes128gcm (recommended): Fast, modern, secure
    - x25519-sha256-chacha20poly1305: Alternative AEAD
    - p256-sha256-aes128gcm: NIST P-256 curve
    - p384-sha384-aes256gcm: Higher security level
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    try:
        key_pair = engine.generate_keypair(suite)
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return HPKEKeyPairResponse(
        private_key=base64.b64encode(key_pair.private_key).decode("ascii"),
        public_key=base64.b64encode(key_pair.public_key).decode("ascii"),
        suite=suite.value,
    )


@router.post("/encrypt", response_model=HPKEEncryptResponse)
async def encrypt(
    data: HPKEEncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encrypt data using HPKE (Base mode).

    This is the simplest HPKE mode with no sender authentication.
    The sender generates an ephemeral key pair, derives a shared secret
    with the recipient's public key, and encrypts the data.

    The response includes:
    - enc: Encapsulated key (must be sent with ciphertext)
    - ciphertext: Encrypted data

    Both enc and ciphertext are needed for decryption.
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    plaintext = _decode_b64_required(data.plaintext, "plaintext")
    recipient_public_key = _decode_b64_required(data.recipient_public_key, "recipient_public_key")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    try:
        result = engine.encrypt(
            recipient_public_key=recipient_public_key,
            plaintext=plaintext,
            suite=suite,
            info=info,
            aad=aad,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Encryption failed: {e}")

    return HPKEEncryptResponse(
        enc=base64.b64encode(result.enc).decode("ascii"),
        ciphertext=base64.b64encode(result.ciphertext).decode("ascii"),
        suite=result.suite.value,
        mode=result.mode.value,
    )


@router.post("/decrypt", response_model=HPKEDecryptResponse)
async def decrypt(
    data: HPKEDecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt HPKE encrypted data (Base mode).

    Requires:
    - enc: Encapsulated key from encryption
    - ciphertext: Encrypted data
    - recipient_private_key: Your private key

    If info or aad were used during encryption, they must match exactly.
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    enc = _decode_b64_required(data.enc, "enc")
    ciphertext = _decode_b64_required(data.ciphertext, "ciphertext")
    recipient_private_key = _decode_b64_required(data.recipient_private_key, "recipient_private_key")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    encrypted_message = HPKEEncryptedMessage(
        enc=enc,
        ciphertext=ciphertext,
        suite=suite,
        mode=HPKEMode.BASE,
        info=info,
        aad=aad,
    )

    try:
        plaintext = engine.decrypt(
            recipient_private_key=recipient_private_key,
            encrypted_message=encrypted_message,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Decryption failed: {e}")

    return HPKEDecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )


@router.post("/encrypt/auth", response_model=HPKEEncryptResponse)
async def encrypt_authenticated(
    data: HPKEAuthEncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encrypt with sender authentication (Auth mode).

    The sender's identity is cryptographically bound to the message,
    allowing the recipient to verify who encrypted it.

    This provides:
    - Confidentiality: Only recipient can decrypt
    - Sender authentication: Recipient can verify sender's identity
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    plaintext = _decode_b64_required(data.plaintext, "plaintext")
    sender_private_key = _decode_b64_required(data.sender_private_key, "sender_private_key")
    recipient_public_key = _decode_b64_required(data.recipient_public_key, "recipient_public_key")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    try:
        result = engine.encrypt_with_auth(
            sender_private_key=sender_private_key,
            recipient_public_key=recipient_public_key,
            plaintext=plaintext,
            suite=suite,
            info=info,
            aad=aad,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Encryption failed: {e}")

    return HPKEEncryptResponse(
        enc=base64.b64encode(result.enc).decode("ascii"),
        ciphertext=base64.b64encode(result.ciphertext).decode("ascii"),
        suite=result.suite.value,
        mode=result.mode.value,
    )


@router.post("/decrypt/auth", response_model=HPKEDecryptResponse)
async def decrypt_authenticated(
    data: HPKEAuthDecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt with sender authentication verification (Auth mode).

    Verifies that the message was encrypted by the holder of the
    sender's private key. Decryption will fail if the sender's
    public key doesn't match.
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    enc = _decode_b64_required(data.enc, "enc")
    ciphertext = _decode_b64_required(data.ciphertext, "ciphertext")
    recipient_private_key = _decode_b64_required(data.recipient_private_key, "recipient_private_key")
    sender_public_key = _decode_b64_required(data.sender_public_key, "sender_public_key")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    encrypted_message = HPKEEncryptedMessage(
        enc=enc,
        ciphertext=ciphertext,
        suite=suite,
        mode=HPKEMode.AUTH,
        info=info,
        aad=aad,
    )

    try:
        plaintext = engine.decrypt_with_auth(
            recipient_private_key=recipient_private_key,
            sender_public_key=sender_public_key,
            encrypted_message=encrypted_message,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Authentication/decryption failed: {e}")

    return HPKEDecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )


@router.post("/encrypt/psk", response_model=HPKEEncryptResponse)
async def encrypt_psk(
    data: HPKEPSKEncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Encrypt with pre-shared key authentication (PSK mode).

    Combines asymmetric encryption with a pre-shared key for
    additional authentication. Both parties must know the PSK
    and PSK ID for successful encryption/decryption.

    This provides:
    - Confidentiality: Only recipient can decrypt
    - PSK authentication: Both parties verified by shared secret
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    plaintext = _decode_b64_required(data.plaintext, "plaintext")
    recipient_public_key = _decode_b64_required(data.recipient_public_key, "recipient_public_key")
    psk = _decode_b64_required(data.psk, "psk")
    psk_id = _decode_b64_required(data.psk_id, "psk_id")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    try:
        result = engine.encrypt_with_psk(
            recipient_public_key=recipient_public_key,
            plaintext=plaintext,
            psk=psk,
            psk_id=psk_id,
            suite=suite,
            info=info,
            aad=aad,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Encryption failed: {e}")

    return HPKEEncryptResponse(
        enc=base64.b64encode(result.enc).decode("ascii"),
        ciphertext=base64.b64encode(result.ciphertext).decode("ascii"),
        suite=result.suite.value,
        mode=result.mode.value,
    )


@router.post("/decrypt/psk", response_model=HPKEDecryptResponse)
async def decrypt_psk(
    data: HPKEPSKDecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Decrypt with pre-shared key (PSK mode).

    The PSK and PSK ID must match exactly what was used during encryption.
    """
    engine = _get_engine()
    suite = _parse_suite(data.suite)

    enc = _decode_b64_required(data.enc, "enc")
    ciphertext = _decode_b64_required(data.ciphertext, "ciphertext")
    recipient_private_key = _decode_b64_required(data.recipient_private_key, "recipient_private_key")
    psk = _decode_b64_required(data.psk, "psk")
    psk_id = _decode_b64_required(data.psk_id, "psk_id")
    info = _decode_b64(data.info, "info") or b""
    aad = _decode_b64(data.aad, "aad") or b""

    encrypted_message = HPKEEncryptedMessage(
        enc=enc,
        ciphertext=ciphertext,
        suite=suite,
        mode=HPKEMode.PSK,
        info=info,
        aad=aad,
    )

    try:
        plaintext = engine.decrypt_with_psk(
            recipient_private_key=recipient_private_key,
            encrypted_message=encrypted_message,
            psk=psk,
            psk_id=psk_id,
        )
    except HPKEError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Decryption failed: {e}")

    return HPKEDecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )
