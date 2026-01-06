# CryptoServe PQC Enhancement Implementation Plan

This plan covers 3 features to complete the post-quantum cryptography story for the OSS MVP.

## Overview

| Feature | Priority | Complexity | Files Affected |
|---------|----------|------------|----------------|
| AES-XTS for disk encryption | High | Medium | 3-4 files |
| All ML-DSA sizes (44/65/87) | High | Low | 2-3 files |
| X25519 + ML-KEM hybrid key exchange | High | High | 4-5 files |

---

## Feature 1: AES-XTS for `usage="disk"`

### Background
AES-XTS (IEEE 1619) is the standard for disk/storage encryption. Currently, CryptoServe throws `UnsupportedModeError` for XTS mode because XTS is sector-based and doesn't provide authentication like GCM.

For the `usage="disk"` hint, we should implement XTS properly with an HMAC wrapper for integrity.

### Implementation Steps

#### 1.1 Update algorithm_resolver.py
**File:** `backend/app/core/algorithm_resolver.py`

Add XTS to the usage context mappings:
```python
USAGE_CONTEXT_ALGORITHM_MAP = {
    # ... existing mappings ...
    EncryptionUsageContext.DISK: "AES-256-XTS",
}

USAGE_CONTEXT_MODE_MAP = {
    # ... existing mappings ...
    EncryptionUsageContext.DISK: CipherMode.XTS,
}
```

Add XTS to ALGORITHMS registry:
```python
ALGORITHMS = {
    # ... existing ...
    "AES-256-XTS": {
        "key_bits": 512,  # XTS uses two 256-bit keys
        "description": "AES-256 in XTS mode for disk/storage encryption (IEEE 1619)",
        "use_cases": ["disk encryption", "storage", "full-disk encryption"],
        "quantum_safe": False,
    },
    "AES-128-XTS": {
        "key_bits": 256,  # Two 128-bit keys
        "description": "AES-128 in XTS mode for disk/storage encryption",
        "use_cases": ["disk encryption", "storage"],
        "quantum_safe": False,
        "legacy": True,
        "replacement": "AES-256-XTS",
    },
}
```

#### 1.2 Update schemas/context.py
**File:** `backend/app/schemas/context.py`

Add DISK to EncryptionUsageContext enum if not present:
```python
class EncryptionUsageContext(str, Enum):
    AT_REST = "at_rest"
    IN_TRANSIT = "in_transit"
    IN_USE = "in_use"
    STREAMING = "streaming"
    DISK = "disk"  # Add this
```

#### 1.3 Implement XTS in CipherFactory
**File:** `backend/app/core/crypto_engine.py`

Add XTS encryption/decryption methods to `CipherFactory`:

```python
@staticmethod
def encrypt_xts(key: bytes, plaintext: bytes, tweak: bytes) -> bytes:
    """Encrypt using AES-XTS with HMAC for integrity.

    XTS is designed for sector-based encryption and doesn't provide
    authentication. We add HMAC for integrity verification.

    Args:
        key: 64-byte key (two 256-bit keys: encryption + tweak)
        plaintext: Data to encrypt (should be >= 16 bytes)
        tweak: 16-byte tweak value (like sector number)

    Returns:
        ciphertext + hmac
    """
    if len(key) != 64:
        raise CryptoError("XTS requires 64-byte key (two 256-bit keys)")
    if len(tweak) != 16:
        raise CryptoError("XTS requires 16-byte tweak")
    if len(plaintext) < 16:
        raise CryptoError("XTS requires plaintext >= 16 bytes")

    # Split key into encryption key and tweak key
    enc_key = key[:32]
    tweak_key = key[32:]

    # XTS encryption
    cipher = Cipher(
        algorithms.AES(enc_key),
        modes.XTS(tweak_key),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Add HMAC for integrity (XTS doesn't provide authentication)
    mac_key = CipherFactory.derive_enc_mac_keys(key[:32])[1]
    mac = hmac.new(mac_key, tweak + ciphertext, hashlib.sha256).digest()

    return ciphertext + mac

@staticmethod
def decrypt_xts(key: bytes, data: bytes, tweak: bytes) -> bytes:
    """Decrypt AES-XTS with HMAC verification."""
    if len(key) != 64:
        raise CryptoError("XTS requires 64-byte key (two 256-bit keys)")

    ciphertext = data[:-32]
    mac = data[-32:]

    # Verify HMAC first
    mac_key = CipherFactory.derive_enc_mac_keys(key[:32])[1]
    expected_mac = hmac.new(mac_key, tweak + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise DecryptionError("HMAC verification failed")

    # Split key
    enc_key = key[:32]
    tweak_key = key[32:]

    # XTS decryption
    cipher = Cipher(
        algorithms.AES(enc_key),
        modes.XTS(tweak_key),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
```

#### 1.4 Update _encrypt_with_mode and _decrypt_with_mode
**File:** `backend/app/core/crypto_engine.py`

Remove the `UnsupportedModeError` for XTS and add proper handling:

```python
elif mode == CipherMode.XTS:
    # XTS uses 16-byte tweak (we use nonce as tweak)
    if len(nonce) != 16:
        nonce = nonce[:16] if len(nonce) > 16 else nonce + b'\x00' * (16 - len(nonce))
    return CipherFactory.encrypt_xts(key, plaintext, nonce)
```

#### 1.5 Add Tests
**File:** `backend/tests/test_xts_encryption.py` (new file)

```python
"""Tests for AES-XTS disk encryption mode."""
import pytest
from app.core.crypto_engine import CipherFactory, CryptoError, DecryptionError

class TestAESXTS:
    def test_xts_encrypt_decrypt_roundtrip(self):
        key = os.urandom(64)  # Two 256-bit keys
        tweak = os.urandom(16)
        plaintext = b"This is test data for XTS mode!" * 10

        ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak)
        decrypted = CipherFactory.decrypt_xts(key, ciphertext, tweak)

        assert decrypted == plaintext

    def test_xts_requires_64_byte_key(self):
        with pytest.raises(CryptoError, match="64-byte key"):
            CipherFactory.encrypt_xts(b"short", b"x" * 16, b"t" * 16)

    def test_xts_requires_16_byte_tweak(self):
        with pytest.raises(CryptoError, match="16-byte tweak"):
            CipherFactory.encrypt_xts(os.urandom(64), b"x" * 16, b"short")

    def test_xts_minimum_plaintext_size(self):
        with pytest.raises(CryptoError, match=">= 16 bytes"):
            CipherFactory.encrypt_xts(os.urandom(64), b"short", b"t" * 16)

    def test_xts_hmac_integrity(self):
        key = os.urandom(64)
        tweak = os.urandom(16)
        plaintext = b"Sensitive disk sector data" * 5

        ciphertext = CipherFactory.encrypt_xts(key, plaintext, tweak)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[10] ^= 0xFF

        with pytest.raises(DecryptionError, match="HMAC"):
            CipherFactory.decrypt_xts(key, bytes(tampered), tweak)
```

---

## Feature 2: All ML-DSA Sizes (44/65/87)

### Background
ML-DSA (FIPS 204, formerly Dilithium) has three security levels:
- ML-DSA-44: NIST Level 2 (128-bit security)
- ML-DSA-65: NIST Level 3 (192-bit security)
- ML-DSA-87: NIST Level 5 (256-bit security)

Currently only ML-DSA-65 and ML-DSA-87 may be fully implemented.

### Implementation Steps

#### 2.1 Verify/Update hybrid_crypto.py
**File:** `backend/app/core/hybrid_crypto.py`

Ensure all three sizes are in SignatureAlgorithm enum:
```python
class SignatureAlgorithm(str, Enum):
    """Supported PQC signature algorithms."""
    ML_DSA_44 = "ML-DSA-44"  # NIST Level 2
    ML_DSA_65 = "ML-DSA-65"  # NIST Level 3
    ML_DSA_87 = "ML-DSA-87"  # NIST Level 5
    # ... SLH-DSA variants ...
```

Update `get_mldsa()` function to support all sizes:
```python
def get_mldsa(variant: str = "ML-DSA-65") -> Any:
    """Get ML-DSA signer for specified security level.

    Args:
        variant: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"

    Returns:
        liboqs Signature object
    """
    if not LIBOQS_AVAILABLE:
        raise PQCError("liboqs not available")

    # Map to liboqs algorithm names
    algo_map = {
        "ML-DSA-44": "ML-DSA-44",
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-87": "ML-DSA-87",
        # Legacy names for compatibility
        "Dilithium2": "ML-DSA-44",
        "Dilithium3": "ML-DSA-65",
        "Dilithium5": "ML-DSA-87",
    }

    algo_name = algo_map.get(variant)
    if not algo_name:
        raise PQCError(f"Unknown ML-DSA variant: {variant}")

    return oqs.Signature(algo_name)
```

#### 2.2 Update PQCSignatureEngine
**File:** `backend/app/core/hybrid_crypto.py`

Ensure PQCSignatureEngine handles all ML-DSA sizes:
```python
class PQCSignatureEngine:
    """Post-quantum signature engine supporting all ML-DSA sizes."""

    SUPPORTED_ALGORITHMS = {
        SignatureAlgorithm.ML_DSA_44: "ML-DSA-44",
        SignatureAlgorithm.ML_DSA_65: "ML-DSA-65",
        SignatureAlgorithm.ML_DSA_87: "ML-DSA-87",
    }

    def __init__(self, algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise PQCError(f"Unsupported algorithm: {algorithm}")
        self.algorithm = algorithm
        self._algo_name = self.SUPPORTED_ALGORITHMS[algorithm]
```

#### 2.3 Add Comprehensive Tests
**File:** `backend/tests/test_mldsa_all_sizes.py` (new file)

```python
"""Tests for all ML-DSA security levels."""
import pytest
from app.core.hybrid_crypto import (
    is_pqc_available,
    get_mldsa,
    PQCSignatureEngine,
    SignatureAlgorithm,
    pqc_sign,
    pqc_verify,
)

pytestmark = pytest.mark.skipif(not is_pqc_available(), reason="liboqs not installed")


class TestMLDSAAllSizes:
    """Test all three ML-DSA security levels."""

    @pytest.mark.parametrize("variant,expected_level", [
        ("ML-DSA-44", 2),
        ("ML-DSA-65", 3),
        ("ML-DSA-87", 5),
    ])
    def test_mldsa_keygen(self, variant, expected_level):
        """Test key generation for all ML-DSA variants."""
        signer = get_mldsa(variant)
        public_key = signer.generate_keypair()

        assert public_key is not None
        assert len(public_key) > 0

    @pytest.mark.parametrize("variant", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_mldsa_sign_verify(self, variant):
        """Test sign/verify roundtrip for all variants."""
        signer = get_mldsa(variant)
        public_key = signer.generate_keypair()

        message = b"Test message for ML-DSA signing"
        signature = signer.sign(message)

        assert signer.verify(message, signature, public_key)

    @pytest.mark.parametrize("variant", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_mldsa_invalid_signature(self, variant):
        """Test that invalid signatures are rejected."""
        signer = get_mldsa(variant)
        public_key = signer.generate_keypair()

        message = b"Original message"
        signature = signer.sign(message)

        # Verify with different message should fail
        assert not signer.verify(b"Different message", signature, public_key)

    @pytest.mark.parametrize("algorithm", [
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    ])
    def test_pqc_signature_engine(self, algorithm):
        """Test PQCSignatureEngine with all ML-DSA sizes."""
        engine = PQCSignatureEngine(algorithm)
        keypair = engine.generate_keypair()

        message = b"Test message"
        signature = engine.sign(message, keypair.private_key)

        assert engine.verify(message, signature, keypair.public_key)

    def test_mldsa_size_comparison(self):
        """Verify key/signature sizes increase with security level."""
        sizes = {}
        for variant in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            signer = get_mldsa(variant)
            public_key = signer.generate_keypair()
            signature = signer.sign(b"test")
            sizes[variant] = {
                "public_key": len(public_key),
                "signature": len(signature),
            }

        # Higher security levels should have larger keys/signatures
        assert sizes["ML-DSA-44"]["public_key"] < sizes["ML-DSA-65"]["public_key"]
        assert sizes["ML-DSA-65"]["public_key"] < sizes["ML-DSA-87"]["public_key"]
```

#### 2.4 Update API Endpoints
**File:** `backend/app/api/v1/signatures.py`

Ensure the signatures API accepts all ML-DSA variants:
```python
class SignRequest(BaseModel):
    message: str  # Base64 encoded
    algorithm: str = "ML-DSA-65"  # Default to Level 3

    @validator("algorithm")
    def validate_algorithm(cls, v):
        valid = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-128s", "SLH-DSA-128f"]
        if v not in valid:
            raise ValueError(f"Algorithm must be one of: {valid}")
        return v
```

---

## Feature 3: X25519 + ML-KEM Hybrid Key Exchange

### Background
True hybrid PQC key exchange combines classical ECDH (X25519) with ML-KEM to provide security against both classical and quantum attacks. The shared secret is derived from both exchanges.

### Implementation Steps

#### 3.1 Create Hybrid Key Exchange Module
**File:** `backend/app/core/hybrid_kex.py` (new file)

```python
"""Hybrid Key Exchange combining X25519 and ML-KEM.

This module implements hybrid key exchange per NIST recommendations for
the post-quantum transition period. The shared secret is derived from
both a classical X25519 exchange and a post-quantum ML-KEM encapsulation.

Security: If either algorithm remains secure, the combined scheme is secure.
"""

import os
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.core.hybrid_crypto import is_pqc_available, get_mlkem, PQCError

import logging
logger = logging.getLogger(__name__)


class HybridKEXMode(str, Enum):
    """Supported hybrid key exchange modes."""
    X25519_MLKEM_768 = "X25519+ML-KEM-768"
    X25519_MLKEM_1024 = "X25519+ML-KEM-1024"


@dataclass
class HybridKEXKeyPair:
    """Hybrid key exchange key pair."""
    x25519_private: bytes
    x25519_public: bytes
    mlkem_private: bytes
    mlkem_public: bytes
    mode: HybridKEXMode
    key_id: str


@dataclass
class HybridKEXEncapsulation:
    """Result of hybrid key encapsulation."""
    x25519_public: bytes  # Ephemeral X25519 public key
    mlkem_ciphertext: bytes  # ML-KEM ciphertext
    mode: HybridKEXMode


class HybridKeyExchange:
    """Hybrid key exchange combining X25519 and ML-KEM.

    Usage:
        # Key generation (recipient)
        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        # Encapsulation (sender) - creates shared secret
        encap, shared_secret_sender = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)

        # Decapsulation (recipient) - recovers shared secret
        shared_secret_recipient = kex.decapsulate(encap, keypair)

        assert shared_secret_sender == shared_secret_recipient
    """

    MLKEM_VARIANTS = {
        HybridKEXMode.X25519_MLKEM_768: "ML-KEM-768",
        HybridKEXMode.X25519_MLKEM_1024: "ML-KEM-1024",
    }

    def __init__(self, mode: HybridKEXMode = HybridKEXMode.X25519_MLKEM_768):
        if not is_pqc_available():
            raise PQCError("liboqs required for hybrid key exchange")
        self.mode = mode
        self._mlkem_variant = self.MLKEM_VARIANTS[mode]

    def generate_keypair(self) -> HybridKEXKeyPair:
        """Generate hybrid key pair (X25519 + ML-KEM)."""
        import secrets

        # Generate X25519 key pair
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()

        x25519_private_bytes = x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        x25519_public_bytes = x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Generate ML-KEM key pair
        kem = get_mlkem(self._mlkem_variant)
        mlkem_public = kem.generate_keypair()
        mlkem_private = kem.export_secret_key()

        key_id = secrets.token_hex(16)

        return HybridKEXKeyPair(
            x25519_private=x25519_private_bytes,
            x25519_public=x25519_public_bytes,
            mlkem_private=mlkem_private,
            mlkem_public=mlkem_public,
            mode=self.mode,
            key_id=key_id,
        )

    def encapsulate(
        self,
        recipient_x25519_public: bytes,
        recipient_mlkem_public: bytes,
    ) -> Tuple[HybridKEXEncapsulation, bytes]:
        """Encapsulate to create shared secret.

        Args:
            recipient_x25519_public: Recipient's X25519 public key (32 bytes)
            recipient_mlkem_public: Recipient's ML-KEM public key

        Returns:
            Tuple of (encapsulation data, shared_secret)
        """
        # X25519 key exchange
        ephemeral_x25519 = X25519PrivateKey.generate()
        ephemeral_x25519_public = ephemeral_x25519.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        recipient_x25519 = X25519PublicKey.from_public_bytes(recipient_x25519_public)
        x25519_shared = ephemeral_x25519.exchange(recipient_x25519)

        # ML-KEM encapsulation
        kem = get_mlkem(self._mlkem_variant)
        mlkem_ciphertext, mlkem_shared = kem.encap_secret(recipient_mlkem_public)

        # Combine shared secrets using HKDF
        combined = x25519_shared + mlkem_shared
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid-kex-v1",
            info=self.mode.value.encode(),
        ).derive(combined)

        encap = HybridKEXEncapsulation(
            x25519_public=ephemeral_x25519_public,
            mlkem_ciphertext=mlkem_ciphertext,
            mode=self.mode,
        )

        return encap, shared_secret

    def decapsulate(
        self,
        encapsulation: HybridKEXEncapsulation,
        keypair: HybridKEXKeyPair,
    ) -> bytes:
        """Decapsulate to recover shared secret.

        Args:
            encapsulation: Encapsulation data from sender
            keypair: Recipient's key pair

        Returns:
            Shared secret (32 bytes)
        """
        if encapsulation.mode != keypair.mode:
            raise PQCError(f"Mode mismatch: {encapsulation.mode} vs {keypair.mode}")

        # X25519 key exchange
        x25519_private = X25519PrivateKey.from_private_bytes(keypair.x25519_private)
        sender_x25519_public = X25519PublicKey.from_public_bytes(encapsulation.x25519_public)
        x25519_shared = x25519_private.exchange(sender_x25519_public)

        # ML-KEM decapsulation
        kem = get_mlkem(self._mlkem_variant)
        # Need to set secret key for decapsulation
        kem_with_sk = get_mlkem(self._mlkem_variant)
        # liboqs requires generating keypair then we use our stored secret key
        _ = kem_with_sk.generate_keypair()
        mlkem_shared = kem.decap_secret(encapsulation.mlkem_ciphertext)

        # Combine shared secrets using HKDF
        combined = x25519_shared + mlkem_shared
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid-kex-v1",
            info=self.mode.value.encode(),
        ).derive(combined)

        return shared_secret

    def serialize_encapsulation(self, encap: HybridKEXEncapsulation) -> bytes:
        """Serialize encapsulation for transmission."""
        import json
        header = {
            "mode": encap.mode.value,
            "x25519_len": len(encap.x25519_public),
            "mlkem_len": len(encap.mlkem_ciphertext),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(2, "big")

        return header_len + header_json + encap.x25519_public + encap.mlkem_ciphertext

    @staticmethod
    def deserialize_encapsulation(data: bytes) -> HybridKEXEncapsulation:
        """Deserialize encapsulation from bytes."""
        import json

        header_len = int.from_bytes(data[:2], "big")
        header = json.loads(data[2:2 + header_len].decode())

        offset = 2 + header_len
        x25519_public = data[offset:offset + header["x25519_len"]]
        offset += header["x25519_len"]
        mlkem_ciphertext = data[offset:offset + header["mlkem_len"]]

        return HybridKEXEncapsulation(
            x25519_public=x25519_public,
            mlkem_ciphertext=mlkem_ciphertext,
            mode=HybridKEXMode(header["mode"]),
        )


# Convenience functions
def hybrid_key_exchange(
    mode: HybridKEXMode = HybridKEXMode.X25519_MLKEM_768
) -> HybridKeyExchange:
    """Create a hybrid key exchange instance."""
    return HybridKeyExchange(mode)
```

#### 3.2 Add API Endpoint
**File:** `backend/app/api/v1/key_exchange.py` (new file)

```python
"""Hybrid key exchange API endpoints."""
import base64
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.hybrid_kex import (
    HybridKeyExchange,
    HybridKEXMode,
    HybridKEXKeyPair,
)
from app.core.hybrid_crypto import is_pqc_available
from app.db.session import get_db

router = APIRouter(prefix="/key-exchange", tags=["key-exchange"])


class GenerateKeyPairRequest(BaseModel):
    mode: str = "X25519+ML-KEM-768"


class GenerateKeyPairResponse(BaseModel):
    key_id: str
    x25519_public: str  # Base64
    mlkem_public: str  # Base64
    mode: str


class EncapsulateRequest(BaseModel):
    x25519_public: str  # Base64
    mlkem_public: str  # Base64
    mode: str = "X25519+ML-KEM-768"


class EncapsulateResponse(BaseModel):
    encapsulation: str  # Base64 serialized
    shared_secret: str  # Base64 (for demo - in production, use directly)


@router.post("/generate-keypair", response_model=GenerateKeyPairResponse)
async def generate_keypair(
    request: GenerateKeyPairRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate a hybrid key exchange key pair."""
    if not is_pqc_available():
        raise HTTPException(503, "PQC not available - liboqs required")

    try:
        mode = HybridKEXMode(request.mode)
    except ValueError:
        raise HTTPException(400, f"Invalid mode: {request.mode}")

    kex = HybridKeyExchange(mode)
    keypair = kex.generate_keypair()

    # TODO: Store private key securely for later decapsulation

    return GenerateKeyPairResponse(
        key_id=keypair.key_id,
        x25519_public=base64.b64encode(keypair.x25519_public).decode(),
        mlkem_public=base64.b64encode(keypair.mlkem_public).decode(),
        mode=mode.value,
    )


@router.post("/encapsulate", response_model=EncapsulateResponse)
async def encapsulate(
    request: EncapsulateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Encapsulate to create shared secret."""
    if not is_pqc_available():
        raise HTTPException(503, "PQC not available - liboqs required")

    try:
        mode = HybridKEXMode(request.mode)
    except ValueError:
        raise HTTPException(400, f"Invalid mode: {request.mode}")

    kex = HybridKeyExchange(mode)

    x25519_public = base64.b64decode(request.x25519_public)
    mlkem_public = base64.b64decode(request.mlkem_public)

    encap, shared_secret = kex.encapsulate(x25519_public, mlkem_public)

    return EncapsulateResponse(
        encapsulation=base64.b64encode(kex.serialize_encapsulation(encap)).decode(),
        shared_secret=base64.b64encode(shared_secret).decode(),
    )
```

#### 3.3 Register Router
**File:** `backend/app/api/v1/__init__.py`

Add the new router:
```python
from app.api.v1.key_exchange import router as key_exchange_router

# In router registration
api_router.include_router(key_exchange_router)
```

#### 3.4 Add Tests
**File:** `backend/tests/test_hybrid_kex.py` (new file)

```python
"""Tests for hybrid X25519 + ML-KEM key exchange."""
import pytest
from app.core.hybrid_crypto import is_pqc_available
from app.core.hybrid_kex import (
    HybridKeyExchange,
    HybridKEXMode,
    HybridKEXKeyPair,
    HybridKEXEncapsulation,
)

pytestmark = pytest.mark.skipif(not is_pqc_available(), reason="liboqs not installed")


class TestHybridKeyExchange:
    """Test hybrid key exchange."""

    @pytest.mark.parametrize("mode", [
        HybridKEXMode.X25519_MLKEM_768,
        HybridKEXMode.X25519_MLKEM_1024,
    ])
    def test_full_key_exchange(self, mode):
        """Test complete key exchange flow."""
        kex = HybridKeyExchange(mode)

        # Recipient generates key pair
        keypair = kex.generate_keypair()
        assert keypair.mode == mode
        assert len(keypair.x25519_public) == 32
        assert len(keypair.mlkem_public) > 0

        # Sender encapsulates
        encap, sender_secret = kex.encapsulate(
            keypair.x25519_public,
            keypair.mlkem_public,
        )

        # Recipient decapsulates
        recipient_secret = kex.decapsulate(encap, keypair)

        # Both should have same shared secret
        assert sender_secret == recipient_secret
        assert len(sender_secret) == 32

    def test_serialization_roundtrip(self):
        """Test encapsulation serialization."""
        kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        keypair = kex.generate_keypair()

        encap, _ = kex.encapsulate(keypair.x25519_public, keypair.mlkem_public)

        # Serialize and deserialize
        serialized = kex.serialize_encapsulation(encap)
        deserialized = HybridKeyExchange.deserialize_encapsulation(serialized)

        assert deserialized.mode == encap.mode
        assert deserialized.x25519_public == encap.x25519_public
        assert deserialized.mlkem_ciphertext == encap.mlkem_ciphertext

    def test_different_keypairs_different_secrets(self):
        """Test that different key pairs produce different secrets."""
        kex = HybridKeyExchange()

        keypair1 = kex.generate_keypair()
        keypair2 = kex.generate_keypair()

        _, secret1 = kex.encapsulate(keypair1.x25519_public, keypair1.mlkem_public)
        _, secret2 = kex.encapsulate(keypair2.x25519_public, keypair2.mlkem_public)

        assert secret1 != secret2

    def test_mode_mismatch_fails(self):
        """Test that mode mismatch is detected."""
        kex_768 = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
        kex_1024 = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_1024)

        keypair_768 = kex_768.generate_keypair()

        # Try to use 1024 encapsulation with 768 keypair
        encap_1024, _ = kex_1024.encapsulate(
            keypair_768.x25519_public,
            keypair_768.mlkem_public,  # This won't work properly
        )

        # The mode check should catch this
        from app.core.hybrid_crypto import PQCError
        with pytest.raises(PQCError, match="Mode mismatch"):
            kex_768.decapsulate(encap_1024, keypair_768)
```

#### 3.5 Update SDK
**File:** `sdk/python/cryptoserve/key_exchange.py` (new file)

```python
"""Hybrid key exchange SDK functions."""
from typing import Tuple, Optional
import base64

from .client import CryptoServeClient


def generate_hybrid_keypair(
    client: CryptoServeClient,
    mode: str = "X25519+ML-KEM-768",
) -> dict:
    """Generate a hybrid key exchange key pair.

    Args:
        client: CryptoServe client
        mode: Key exchange mode ("X25519+ML-KEM-768" or "X25519+ML-KEM-1024")

    Returns:
        Dict with key_id, x25519_public, mlkem_public, mode
    """
    return client.post("/v1/key-exchange/generate-keypair", json={"mode": mode})


def encapsulate(
    client: CryptoServeClient,
    x25519_public: bytes,
    mlkem_public: bytes,
    mode: str = "X25519+ML-KEM-768",
) -> Tuple[bytes, bytes]:
    """Encapsulate to create shared secret.

    Args:
        client: CryptoServe client
        x25519_public: Recipient's X25519 public key
        mlkem_public: Recipient's ML-KEM public key
        mode: Key exchange mode

    Returns:
        Tuple of (encapsulation, shared_secret)
    """
    response = client.post("/v1/key-exchange/encapsulate", json={
        "x25519_public": base64.b64encode(x25519_public).decode(),
        "mlkem_public": base64.b64encode(mlkem_public).decode(),
        "mode": mode,
    })

    return (
        base64.b64decode(response["encapsulation"]),
        base64.b64decode(response["shared_secret"]),
    )
```

---

## Testing Checklist

After implementation, run these tests:

```bash
# Run all tests
cd backend && pytest -v

# Run specific test files
pytest tests/test_xts_encryption.py -v
pytest tests/test_mldsa_all_sizes.py -v
pytest tests/test_hybrid_kex.py -v

# Run with coverage
pytest --cov=app --cov-report=term-missing
```

## Documentation Updates

After implementation, update these docs:
1. `README.md` - Add XTS and hybrid KEX to features list
2. `docs/algorithms.md` - Document AES-XTS usage
3. `docs/pqc.md` - Document all ML-DSA sizes and hybrid KEX
4. Website `/docs/sdk/key-exchange/` page

---

## Implementation Order

1. **Feature 2: ML-DSA sizes** (smallest change, low risk)
2. **Feature 1: AES-XTS** (medium complexity)
3. **Feature 3: Hybrid KEX** (most complex, depends on existing PQC infra)

Each feature should be a separate commit/PR for clean history.
