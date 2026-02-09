# Cryptographic Technical Reference

**Version:** 1.1
**Date:** January 2026
**Classification:** Public
**Intended Audience:** Security auditors, cryptographic assessors, compliance teams

This document provides complete technical transparency for cryptographic assessments and security audits. It contains all implementation details, algorithm specifications, and security considerations needed to evaluate CryptoServe's cryptographic architecture.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Key Management](#4-key-management)
5. [Post-Quantum Cryptography](#5-post-quantum-cryptography)
6. [Authentication and Authorization](#6-authentication-and-authorization)
7. [Protocol Design](#7-protocol-design)
8. [Security Model and Threat Analysis](#8-security-model-and-threat-analysis)
9. [Implementation Security](#9-implementation-security)
10. [Compliance and Standards](#10-compliance-and-standards)
11. [Known Limitations](#11-known-limitations)
12. [Security Considerations for Researchers](#12-security-considerations-for-researchers)
13. [SDK Security](#13-sdk-security)
14. [Community Dashboard Security](#14-community-dashboard-security)

---

## 1. Executive Summary

CryptoServe is a cryptography-as-a-service platform providing symmetric encryption, asymmetric encryption, post-quantum cryptography, and key management capabilities via a REST API. This document provides complete transparency into the cryptographic design decisions, implementation details, and security considerations.

### Design Principles

1. **Defense in Depth**: Multiple layers of security controls
2. **Fail Secure**: Errors default to denying access
3. **Least Privilege**: Identities are scoped to specific contexts
4. **Cryptographic Agility**: Support algorithm migration without breaking changes
5. **Auditability**: Complete audit trail of all cryptographic operations

### Libraries and Dependencies

| Library | Version | Purpose | Audit Status |
|---------|---------|---------|--------------|
| `cryptography` | ≥42.0.0 | Core primitives (OpenSSL bindings) | Audited by Trail of Bits |
| `liboqs-python` | ≥0.10.0 | NIST PQC (ML-KEM, ML-DSA) | NIST-validated algorithms |
| `PyJWT` | ≥2.8.0 | JWT operations | Widely audited |
| `argon2-cffi` | - | Password hashing | PHC winner |

---

## 2. Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Layer                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  /encrypt    │  │  /decrypt    │  │  /sign       │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Layer                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Ed25519 JWT Verification  │  OAuth 2.0/OIDC Providers   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Policy Engine                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Context Authorization  │  Algorithm Policy Enforcement  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Crypto Engine                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Symmetric   │  │  Asymmetric  │  │  Hybrid PQC  │          │
│  │  AES-GCM     │  │  X25519      │  │  ML-KEM-768  │          │
│  │  ChaCha20    │  │  ECIES       │  │  ML-DSA-65   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Key Management                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Local HKDF Derivation  │  KMS Integration (AWS/GCP)     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Tenancy Isolation

- Each tenant has isolated encryption contexts
- Keys are derived per-tenant using HKDF with tenant-specific info
- Database queries always include tenant_id filter
- Cross-tenant access is cryptographically impossible (different derived keys)

---

## 3. Cryptographic Primitives

### 3.1 Symmetric Encryption

#### Primary: AES-256-GCM

```
Algorithm:     AES-256-GCM (NIST SP 800-38D)
Key Size:      256 bits
Nonce:         96 bits (12 bytes), randomly generated per encryption
Auth Tag:      128 bits
Max Message:   64 GiB (per NIST recommendation)
```

**Implementation Notes:**
- Uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- Nonce generated via `os.urandom(12)` - CSPRNG backed by OS entropy
- Key commitment computed and stored to prevent multi-key attacks

**Code Path:** `app/core/crypto_engine.py:CipherFactory.encrypt_gcm()`

#### Secondary: ChaCha20-Poly1305

```
Algorithm:     ChaCha20-Poly1305 (RFC 8439)
Key Size:      256 bits
Nonce:         96 bits (12 bytes)
Auth Tag:      128 bits (Poly1305)
```

**Use Case:** Systems without AES-NI hardware acceleration

**Note:** Not FIPS-approved. Blocked when FIPS mode is enabled.

#### Legacy: AES-CBC with HMAC

```
Algorithm:     AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)
Key Size:      256 bits (encryption) + 256 bits (MAC)
IV:            128 bits, randomly generated
Padding:       PKCS#7
MAC:           HMAC-SHA256 over (IV || ciphertext)
```

**Security Properties:**
- Separate keys derived via HKDF for encryption and authentication
- Encrypt-then-MAC construction (authenticated before decrypted)
- Constant-time MAC comparison via `hmac.compare_digest()`

**Code Path:** `app/core/crypto_engine.py:CipherFactory.encrypt_cbc()`

### 3.2 Key Commitment

To prevent multi-key/partitioning attacks on AES-GCM (the "Invisible Salamanders" attack class), we implement key commitment:

```python
def compute_key_commitment(key: bytes) -> bytes:
    """HMAC-SHA256(key, "key-commitment-v1")"""
    return hmac.new(key, b"key-commitment-v1", hashlib.sha256).digest()
```

The 32-byte commitment is stored in the ciphertext header and verified during decryption. If an attacker attempts to decrypt with a different key that happens to produce valid plaintext, the commitment will not match.

**Reference:** Albertini et al., "How to Abuse and Fix Authenticated Encryption Without Key Commitment" (2020)

### 3.3 Ciphertext Format

Self-describing format enables algorithm agility:

```
┌─────────────────────────────────────────────────────────────┐
│  Header Length (2 bytes, big-endian)                        │
├─────────────────────────────────────────────────────────────┤
│  Header (JSON)                                              │
│  {                                                          │
│    "v": 3,                    // Format version             │
│    "ctx": "user-pii",         // Context name               │
│    "kid": "key_user-pii_a1b2",// Key identifier             │
│    "alg": "AES-256-GCM",      // Algorithm                  │
│    "mode": "gcm",             // Cipher mode                │
│    "nonce": "base64...",      // 12-byte nonce              │
│    "kc": "base64...",         // Key commitment (32 bytes)  │
│    "aad": false               // AAD flag                   │
│  }                                                          │
├─────────────────────────────────────────────────────────────┤
│  Ciphertext + Auth Tag                                      │
└─────────────────────────────────────────────────────────────┘
```

**Backward Compatibility:** Versions 1, 2, and 3 are all supported for decryption.

### 3.4 Nonce Generation

All nonces are generated using `os.urandom()`:

```python
nonce = os.urandom(12)  # For GCM, CCM, ChaCha20
iv = os.urandom(16)     # For CBC, CTR
```

**Entropy Source:**
- Linux: `/dev/urandom` (getrandom syscall when available)
- macOS: `getentropy()` syscall
- Windows: `CryptGenRandom()`

**Collision Analysis:**
- 96-bit nonce space: 2^96 possible values
- Birthday bound: ~2^48 encryptions before 50% collision probability
- Rate limiting and key rotation ensure we stay well below this

---

## 4. Key Management

### 4.1 Key Hierarchy

```
Master Key (KEK)
    │
    │  [HKDF-SHA256]
    │  salt = "crypto-serve-v1"
    │  info = "{context}:{version}:{key_size}"
    │
    ▼
Data Encryption Keys (DEKs) per context
```

### 4.2 Key Derivation (Development Mode)

```python
def derive_key(context: str, version: int, key_size: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=b"crypto-serve-v1",
        info=f"{context}:{version}:{key_size}".encode(),
    )
    return hkdf.derive(master_key)
```

**Security Note:** Deterministic derivation allows consistent keys across restarts without storing DEKs. The security of all DEKs depends entirely on the master key secrecy.

### 4.3 KMS Integration (Production Mode)

For production deployments, the platform supports external KMS:

| Provider | Status | Envelope Encryption |
|----------|--------|---------------------|
| AWS KMS | Supported | Yes |
| GCP KMS | Planned | Yes |
| Azure Key Vault | Planned | Yes |
| HashiCorp Vault | Planned | Yes |

In KMS mode:
1. Master key never leaves the HSM
2. DEKs are generated by KMS and encrypted (envelope encryption)
3. Encrypted DEKs can be stored with ciphertext for per-message keys

### 4.4 Key Rotation

```python
async def rotate_key(context: str, tenant_id: str) -> tuple[bytes, str]:
    # 1. Mark current key as ROTATED
    current_key.status = KeyStatus.ROTATED

    # 2. Create new key with incremented version
    new_key = Key(
        version=current_version + 1,
        status=KeyStatus.ACTIVE
    )

    # 3. Derive new key material
    return derive_key(context, new_version, key_size)
```

**Important:** Key rotation does NOT re-encrypt existing data. Old keys remain available (status=ROTATED) for decryption. Re-encryption must be performed separately if required.

### 4.5 PQC Key Storage

Post-quantum keys cannot be deterministically derived and must be stored:

```python
# Storage: Private key encrypted with AES-256-GCM
nonce = secrets.token_bytes(12)
aesgcm = AESGCM(encryption_key)
encrypted_private_key = aesgcm.encrypt(
    nonce,
    private_key,
    associated_data=f"{context}:{key_id}:{algorithm}".encode()
)
```

The encryption key is derived from the context's master key, binding the PQC key to its context.

---

## 5. Post-Quantum Cryptography

### 5.1 Implementation

CryptoServe uses **liboqs** (Open Quantum Safe) for post-quantum algorithms:

```python
import oqs
kem = oqs.KeyEncapsulation("ML-KEM-768")
```

liboqs provides production-ready implementations of NIST-standardized algorithms.

### 5.2 Supported Algorithms

#### ML-KEM (FIPS 203) - Key Encapsulation

| Variant | Security Level | Public Key | Ciphertext | Shared Secret |
|---------|----------------|------------|------------|---------------|
| ML-KEM-512 | NIST Level 1 (128-bit) | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | NIST Level 3 (192-bit) | 1,184 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | NIST Level 5 (256-bit) | 1,568 bytes | 1,568 bytes | 32 bytes |

#### ML-DSA (FIPS 204) - Digital Signatures

| Variant | Security Level | Public Key | Signature |
|---------|----------------|------------|-----------|
| ML-DSA-44 | NIST Level 2 (~128-bit) | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | NIST Level 3 (~192-bit) | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | NIST Level 5 (~256-bit) | 2,592 bytes | 4,627 bytes |

### 5.3 Hybrid Encryption

We implement hybrid encryption combining classical and post-quantum algorithms:

```
Hybrid Mode: AES-256-GCM + ML-KEM-768 (Recommended)

Encryption:
1. KEM Encapsulation: (kem_ciphertext, shared_secret) = ML-KEM.Encap(public_key)
2. Key Derivation:    symmetric_key = HKDF-SHA256(shared_secret, info="cryptoserve-hybrid-v1")
3. AEAD Encryption:   ciphertext = AES-GCM.Encrypt(symmetric_key, plaintext, nonce)
4. Output:            kem_ciphertext || ciphertext

Decryption:
1. KEM Decapsulation: shared_secret = ML-KEM.Decap(kem_ciphertext, private_key)
2. Key Derivation:    symmetric_key = HKDF-SHA256(shared_secret, info="cryptoserve-hybrid-v1")
3. AEAD Decryption:   plaintext = AES-GCM.Decrypt(symmetric_key, ciphertext, nonce)
```

**Security Rationale:** Hybrid mode provides security if EITHER algorithm remains secure. This is the recommended approach during the PQC transition period per NIST guidance.

### 5.4 Hybrid Ciphertext Format

```
┌─────────────────────────────────────────────────────────────┐
│  Header Length (2 bytes)                                    │
├─────────────────────────────────────────────────────────────┤
│  Header (JSON)                                              │
│  {                                                          │
│    "v": 1,                                                  │
│    "mode": "AES-256-GCM+ML-KEM-768",                        │
│    "kid": "pqc_key_abc123",                                 │
│    "nonce": "base64...",                                    │
│    "kem_ct_len": 1088                                       │
│  }                                                          │
├─────────────────────────────────────────────────────────────┤
│  KEM Ciphertext (1088 bytes for ML-KEM-768)                 │
├─────────────────────────────────────────────────────────────┤
│  AEAD Ciphertext + Auth Tag                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Authentication and Authorization

### 6.1 Token Architecture

CryptoServe uses a dual-token system:

#### Access Tokens (Short-lived)

```
Algorithm:     EdDSA (Ed25519)
Lifetime:      1 hour
Signing Key:   Per-application Ed25519 private key
Audience:      "cryptoserve-api"
```

**JWT Claims:**
```json
{
  "iss": "cryptoserve",
  "sub": "app_backend_abc123",
  "aud": "cryptoserve-api",
  "iat": 1704067200,
  "exp": 1704070800,
  "type": "access",
  "name": "Backend Service",
  "team": "platform",
  "env": "production",
  "contexts": ["user-pii", "payment-data"]
}
```

#### Refresh Tokens (Long-lived)

```
Algorithm:     HS256 (HMAC-SHA256)
Lifetime:      30 days
Signing Key:   Master key
Storage:       SHA-256 hash only (not the token itself)
```

**Security Properties:**
- Refresh token hash stored, not the token → Database compromise doesn't expose tokens
- `jti` claim enables revocation
- Constant-time comparison: `secrets.compare_digest()`

### 6.2 Application Keypair Management

Each application gets a unique Ed25519 keypair:

```python
private_key = Ed25519PrivateKey.generate()  # 32 bytes entropy from CSPRNG
```

**Private Key Storage:**
```python
# Encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
fernet_key = base64.urlsafe_b64encode(
    hashlib.sha256(master_key.encode()).digest()
)
encrypted = Fernet(fernet_key).encrypt(private_key_pem)
```

**Note:** This uses SHA-256 truncated to 256 bits for the Fernet key. While Fernet internally uses AES-128, the key derivation provides 256 bits of entropy.

### 6.3 Context-Based Authorization

Identities are authorized for specific encryption contexts:

```python
# During encryption
if context_name not in identity.allowed_contexts:
    raise AuthorizationError(
        f"Identity not authorized for context: {context_name}"
    )
```

### 6.4 OAuth 2.0 / OIDC Integration

Supported identity providers:
- GitHub OAuth
- Google OIDC
- Azure AD
- Okta
- Generic OIDC

All OAuth flows use:
- PKCE (Proof Key for Code Exchange) where supported
- State parameter for CSRF protection
- Secure token storage

---

## 7. Protocol Design

### 7.1 Encrypt Request Flow

```
1. Client sends: POST /api/v1/crypto/encrypt
   {
     "plaintext": "base64...",
     "context": "user-pii",
     "associated_data": "base64..." (optional)
   }

2. Server validates:
   - JWT signature (Ed25519)
   - JWT not expired
   - Identity authorized for context
   - Context exists and is active

3. Policy evaluation:
   - Check algorithm policy enforcement
   - Check custom policies (CEL expressions)

4. Key retrieval:
   - Get or create key for context
   - Derive key material via HKDF

5. Encryption:
   - Generate random nonce (12 bytes)
   - Compute key commitment
   - Encrypt with AES-GCM
   - Pack into self-describing format

6. Audit logging:
   - Log operation, context, identity, timing
   - Log algorithm details (cipher, mode, key_bits)

7. Return:
   {
     "ciphertext": "base64...",
     "algorithm": "AES-256-GCM",
     "key_id": "key_user-pii_a1b2",
     "warnings": []
   }
```

### 7.2 Decrypt Request Flow

```
1. Client sends: POST /api/v1/crypto/decrypt
   {
     "ciphertext": "base64...",
     "context": "user-pii",
     "associated_data": "base64..." (optional, must match encryption)
   }

2. Parse ciphertext header:
   - Validate format version (1, 2, or 3)
   - Extract: context, key_id, algorithm, mode, nonce, key_commitment

3. Validate:
   - Context matches request
   - Identity authorized for context
   - Key exists and is not revoked

4. Key commitment verification:
   - Compute expected commitment from retrieved key
   - Compare with stored commitment (constant-time)
   - Reject if mismatch

5. Decryption:
   - Decrypt with appropriate mode
   - AEAD tag verification (implicit in decrypt call)

6. Return plaintext
```

### 7.3 Error Handling

**Important:** Error messages are designed to not leak sensitive information:

```python
# BAD: Leaks whether key exists
raise DecryptionError(f"Key {key_id} not found")

# GOOD: Generic message
raise DecryptionError("Decryption failed")
```

However, for debugging purposes in non-production environments, detailed errors may be enabled. The ciphertext context mismatch IS reported to help developers identify configuration issues.

---

## 8. Security Model and Threat Analysis

### 8.1 Trust Model

**Trusted:**
- The platform operator (has access to master key)
- The underlying infrastructure (OS, database, network)
- The cryptographic libraries (cryptography, liboqs)

**Untrusted:**
- End users (applications using the API)
- Network between client and server (TLS required)
- Stored data at rest (encrypted)

### 8.2 Threat Analysis

#### T1: Master Key Compromise

**Impact:** Complete compromise of all encrypted data

**Mitigations:**
- Production: Store master key in HSM (AWS KMS, etc.)
- Key rotation capability (changes derivation context)
- Audit logging of all key operations

#### T2: Database Compromise

**Impact:** Access to encrypted data, key metadata, audit logs

**Mitigations:**
- DEKs are derived, not stored (development mode)
- PQC private keys encrypted at rest
- Refresh tokens stored as SHA-256 hashes only
- Database encryption at rest (recommended)

#### T3: Nonce Reuse (AES-GCM)

**Impact:** Loss of authenticity, potential plaintext recovery

**Mitigations:**
- Nonces generated via `os.urandom()` (96-bit random)
- Key rotation after ~2^32 operations (configurable)
- Audit logging enables detection

**Analysis:** With 96-bit random nonces and 2^32 messages per key, collision probability is ~2^-32 (negligible).

#### T4: Timing Attacks

**Impact:** Key recovery, authentication bypass

**Mitigations:**
- `hmac.compare_digest()` for all MAC comparisons
- `secrets.compare_digest()` for token hash comparison
- Ed25519 signatures are deterministic (no timing on nonce generation)

#### T5: Ciphertext Malleability

**Impact:** Modified ciphertext decrypts to attacker-controlled plaintext

**Mitigations:**
- AEAD modes (GCM, CCM, ChaCha20-Poly1305) provide authentication
- CBC mode uses Encrypt-then-MAC construction
- Key commitment prevents partition attacks

#### T6: Algorithm Downgrade

**Impact:** Weaker encryption than intended

**Mitigations:**
- Algorithm policy enforcement per context
- Policy enforcement modes: none, warn, enforce
- Ciphertext includes algorithm in authenticated header

#### T7: Quantum Computer Attacks (Future)

**Impact:** Decryption of data encrypted with classical algorithms

**Mitigations:**
- Hybrid PQC modes available (ML-KEM + AES-GCM)
- Algorithm agility allows migration
- Self-describing ciphertext format supports versioning

### 8.3 Out of Scope

The following are NOT protected against:

1. **Compromised client application:** If the application itself is compromised, it has legitimate access to decrypt data
2. **Side-channel attacks on the server:** We rely on library implementations for side-channel resistance
3. **Memory forensics on running server:** Keys exist in memory during operations
4. **Malicious platform operator:** The operator can access the master key

---

## 9. Implementation Security

### 9.1 Memory Handling

Secure memory zeroization for sensitive data:

```python
def secure_zero(data: bytearray) -> None:
    """Overwrite memory with zeros using ctypes.memset."""
    buffer_type = ctypes.c_char * len(data)
    buffer = buffer_type.from_buffer(data)
    ctypes.memset(ctypes.addressof(buffer), 0, len(data))
```

**SecureBytes context manager:**
```python
with SecureBytes(key_material) as secure_key:
    result = encrypt(secure_key.data, plaintext)
# Key automatically zeroed on exit
```

**Limitations:**
- Python's garbage collector may leave copies in memory
- Compiler optimizations might eliminate zeroization
- This is best-effort, not guaranteed secure erasure

### 9.2 Constant-Time Operations

All security-critical comparisons use constant-time functions:

```python
# MAC verification
if not hmac.compare_digest(expected_mac, computed_mac):
    raise DecryptionError("Authentication failed")

# Token hash verification
if not secrets.compare_digest(token_hash, stored_hash):
    return None
```

### 9.3 Input Validation

- Maximum plaintext sizes enforced (64 GiB for GCM, 64 KiB for CCM)
- Context names validated against allowlist
- JWT claims validated with strict type checking
- Base64 decoding errors caught and handled

### 9.4 Error Messages

Error messages are designed to:
1. Help legitimate developers debug issues
2. Not leak information useful to attackers

```python
# Decryption errors are generic
raise DecryptionError("Decryption failed")

# But context mismatch is reported (helps debugging, not security-sensitive)
raise DecryptionError(f"Context mismatch: expected {expected}, got {actual}")
```

---

## 10. Compliance and Standards

### 10.1 FIPS 140-2/140-3

FIPS mode can be enabled via configuration:

```
FIPS_MODE=enabled    # Strict enforcement
FIPS_MODE=preferred  # Use FIPS if available, warn otherwise
FIPS_MODE=disabled   # No restrictions (default)
```

**FIPS-Approved Algorithms:**
- Symmetric: AES (128, 192, 256) in GCM, CBC, CTR, CCM modes
- Hash: SHA-256, SHA-384, SHA-512, SHA3-*
- MAC: HMAC with approved hash functions
- KDF: HKDF, PBKDF2, KBKDF
- Asymmetric: RSA (2048+), ECDSA (P-256, P-384), EdDSA
- PQC: ML-KEM (FIPS 203), ML-DSA (FIPS 204)

**Blocked in FIPS Mode:**
- ChaCha20-Poly1305 (RFC, not NIST)
- AES-GCM-SIV (RFC, not NIST)
- Argon2, bcrypt (not NIST-approved)

### 10.2 NIST Standards Compliance

| Standard | Description | Status |
|----------|-------------|--------|
| SP 800-38D | AES-GCM | Compliant |
| SP 800-38C | AES-CCM | Compliant |
| SP 800-38A | AES-CBC, CTR | Compliant |
| SP 800-56C | Key Derivation | Compliant (HKDF) |
| SP 800-108 | KDF in Counter Mode | Compliant (KBKDF) |
| SP 800-132 | Password-Based Key Derivation | Compliant (PBKDF2) |
| FIPS 186-4 | Digital Signatures | Compliant (ECDSA) |
| FIPS 203 | ML-KEM | Compliant |
| FIPS 204 | ML-DSA | Compliant |

### 10.3 Industry Standards

| Standard | Relevance | Implementation |
|----------|-----------|----------------|
| PCI-DSS | Payment data encryption | Supported via payment-data context |
| HIPAA | Health data encryption | Supported via health-records context |
| GDPR | Data protection | Encryption + audit logging |
| SOC 2 | Security controls | Audit logging, access controls |

---

## 11. Known Limitations

### 11.1 Cryptographic Limitations

1. **No Forward Secrecy for Symmetric Encryption**
   - Key compromise exposes all data encrypted with that key
   - Mitigation: Key rotation, per-message keys (with KMS)

2. **Deterministic Key Derivation**
   - In development mode, DEKs can be rederived if master key is known
   - Mitigation: Use KMS in production for true envelope encryption

3. **Python Memory Model**
   - Sensitive data may persist in memory due to garbage collection
   - Mitigation: SecureBytes helper (best-effort)

4. **AES-GCM Nonce Size**
   - 96-bit nonces limit safe usage to ~2^32 messages per key
   - Mitigation: Key rotation, monitoring via audit logs

5. **No Key Escrow/Recovery**
   - Lost keys mean lost data
   - Mitigation: Backup procedures, key export capabilities

### 11.2 Operational Limitations

1. **Single Master Key**
   - All tenant keys derived from one master key
   - Mitigation: Per-tenant KMS keys in production

2. **No Hardware Security Module by Default**
   - Development mode uses software key storage
   - Mitigation: KMS integration for production

3. **Audit Log Storage**
   - Logs stored in same database as application data
   - Mitigation: External log shipping, immutable storage

### 11.3 API Limitations

1. **No Streaming Encryption**
   - Entire plaintext must fit in memory
   - Future: Chunked encryption support

2. **No Client-Side Encryption**
   - All encryption happens server-side
   - Future: Client SDK with local encryption option

---

## 12. Security Considerations for Researchers

### 12.1 Areas for Review

We invite security researchers to examine:

1. **Nonce handling in `crypto_engine.py`**
   - Is `os.urandom()` properly used?
   - Any possibility of nonce reuse?

2. **Key derivation in `key_manager.py`**
   - Is HKDF correctly applied?
   - Is the info parameter sufficient for domain separation?

3. **Token management in `token_manager.py`**
   - Is the refresh token hash scheme secure?
   - Any timing leaks in verification?

4. **Hybrid PQC in `hybrid_crypto.py`**
   - Is the combiner (HKDF) correctly applied?
   - Any issues with the serialization format?

5. **CBC/CTR HMAC in `CipherFactory`**
   - Is Encrypt-then-MAC correctly implemented?
   - Is the key separation sufficient?

### 12.2 Reporting Vulnerabilities

Please report security vulnerabilities via:
- Email: security@cryptoserve.dev (if applicable)
- GitHub Security Advisories

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### 12.3 Bug Bounty

[Details of bug bounty program if applicable]

---

## 13. SDK Security

The CryptoServe Python SDK provides a zero-configuration interface for applications to access cryptographic services. This section documents the security architecture of the SDK.

### 13.1 Authentication Flow

The SDK uses a two-phase authentication approach:

```
Phase 1: Developer Authentication (one-time)
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Developer      │──────│  cryptoserve    │──────│  GitHub OAuth   │
│                 │      │  login          │      │                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘
        │                        │
        │                        ▼
        │                ~/.cryptoserve/credentials.json
        │                        │
        │                        ▼
Phase 2: Application Auto-Registration
        │                ┌─────────────────┐
        └───────────────│  CryptoServe()  │
                        │  constructor    │
                        └─────────────────┘
                                │
                                ▼
                        POST /api/v1/applications/sdk/register
                                │
                                ▼
                        Application tokens stored in
                        ~/.cryptoserve/apps/{app_id}.json
```

### 13.2 Credential Storage

All credentials are stored in `~/.cryptoserve/` with restricted permissions:

```
~/.cryptoserve/
├── credentials.json     # Session token (chmod 600)
└── apps/
    └── {app_id}.json    # Per-app credentials (chmod 600)
```

**Security Properties:**
- Directory created with mode 0700 (owner-only access)
- Files created with mode 0600 (owner read/write only)
- Tokens never logged or printed in full
- Session tokens are JWT with 7-day expiry

### 13.3 Application Token Architecture

Each registered application receives:

| Token Type | Algorithm | Lifetime | Storage |
|------------|-----------|----------|---------|
| Access Token | Ed25519 (EdDSA) | 1 hour | Memory only |
| Refresh Token | HS256 | 30 days | SHA-256 hash in DB |

**Ed25519 Keypair:**
- Generated per-application at registration
- Private key encrypted with Fernet (AES-128-CBC + HMAC)
- Public key stored in application record
- Enables JWT signature verification without master key

### 13.4 Auto-Registration Security

The SDK's auto-registration feature (`CryptoServe()` constructor):

```python
crypto = CryptoServe(
    app_name="my-service",
    team="platform",
    environment="development",
    contexts=["user-pii"]
)
```

**Security Controls:**
1. Requires valid session token from `cryptoserve login`
2. Application name + environment must be unique per user
3. Existing apps return new tokens (idempotent)
4. Contexts default to `["default"]` if not specified
5. Rate limited to prevent abuse

### 13.5 Token Refresh

The SDK implements automatic token refresh:

```python
# Transparent to application code
if self._should_refresh():  # <5 minutes remaining
    with self._refresh_lock:
        self._do_refresh()
```

**Security Properties:**
- Thread-safe refresh with mutex lock
- Refresh occurs before token expiry (5-minute buffer)
- Failed refresh raises `TokenRefreshError`
- Refresh token rotation on each use

### 13.6 Local Cryptographic Operations

Hash and MAC operations execute locally without server calls:

```python
# These never leave the client
hash_hex = crypto.hash(data, algorithm="sha256")
mac_hex = crypto.mac(data, key, algorithm="hmac-sha256")
```

**Supported Algorithms:**
- Hash: SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b
- MAC: HMAC-SHA256, HMAC-SHA512

---

## 14. Community Dashboard Security

The web dashboard provides administrative access to CryptoServe. This section documents its security architecture.

### 14.1 Authentication

**Primary:** GitHub OAuth 2.0
- PKCE enabled for authorization code flow
- State parameter for CSRF protection
- Tokens stored in HTTP-only, Secure cookies

**Development Mode:**
- `DEV_MODE=true` enables username/password login
- Intended only for local development
- Disabled by default in production builds

### 14.2 Session Management

```
Cookie: access_token=<JWT>
  ├── Algorithm: HS256
  ├── Expiry: 7 days
  ├── HttpOnly: true
  ├── Secure: true (production)
  ├── SameSite: Lax
  └── Path: /
```

### 14.3 Multi-Tenant Isolation

All database queries are scoped by `tenant_id`:

```python
# Every query includes tenant filter
result = await db.execute(
    select(Context)
    .where(Context.tenant_id == user.tenant_id)
    .where(Context.name == context_name)
)
```

**Isolation Guarantees:**
- Users cannot see other tenants' applications
- Users cannot access other tenants' contexts
- Users cannot view other tenants' audit logs
- Key derivation includes tenant ID (cryptographic isolation)

### 14.4 Role-Based Access Control (RBAC)

| Role | Capabilities |
|------|--------------|
| Viewer | View applications, contexts, usage stats |
| Developer | Create/manage own applications |
| Admin | Manage all tenant resources, contexts, policies |
| Owner | Full control including billing, team management |

### 14.5 Dashboard API Security

All dashboard API endpoints:

1. **Authentication Required:** `get_current_user` dependency
2. **Tenant Scoping:** Queries filtered by `user.tenant_id`
3. **Input Validation:** Pydantic models with strict types
4. **Rate Limiting:** Per-user and per-IP limits
5. **Audit Logging:** All mutations logged

### 14.6 Sensitive Operations

Operations requiring additional verification:

| Operation | Additional Control |
|-----------|-------------------|
| Delete application | Confirmation required |
| Rotate tokens | Old tokens immediately invalidated |
| Change algorithm policy | Enforcement mode warning |
| Export keys | Not supported (by design) |
| View private keys | Never exposed via API |

### 14.7 Audit Logging

All dashboard operations are logged:

```json
{
  "timestamp": "2026-01-02T12:00:00Z",
  "user_id": "user_abc123",
  "tenant_id": "tenant_xyz789",
  "action": "application.create",
  "resource_type": "application",
  "resource_id": "app_my-service_a1b2",
  "details": {
    "name": "my-service",
    "team": "platform",
    "contexts": ["user-pii"]
  },
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

**Log Retention:** 90 days by default (configurable)

### 14.8 Content Security Policy

The dashboard implements strict CSP headers:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.github.com;
  frame-ancestors 'none';
```

---

## Appendix A: Algorithm Reference

### Symmetric Encryption

| Algorithm | Key Size | Nonce/IV | Auth Tag | Max Message | FIPS |
|-----------|----------|----------|----------|-------------|------|
| AES-128-GCM | 128 bits | 96 bits | 128 bits | 64 GiB | Yes |
| AES-256-GCM | 256 bits | 96 bits | 128 bits | 64 GiB | Yes |
| AES-256-CBC | 256 bits | 128 bits | HMAC-256 | Unlimited | Yes |
| AES-256-CTR | 256 bits | 96 bits | HMAC-256 | Unlimited | Yes |
| AES-256-CCM | 256 bits | 96 bits | 128 bits | 64 KiB | Yes |
| ChaCha20-Poly1305 | 256 bits | 96 bits | 128 bits | Unlimited | No |

### Hash Functions

| Algorithm | Output | Block Size | FIPS |
|-----------|--------|------------|------|
| SHA-256 | 256 bits | 512 bits | Yes |
| SHA-384 | 384 bits | 1024 bits | Yes |
| SHA-512 | 512 bits | 1024 bits | Yes |
| SHA3-256 | 256 bits | 1088 bits | Yes |
| BLAKE2b | 512 bits | 1024 bits | No |

### Key Derivation

| Algorithm | Standard | FIPS |
|-----------|----------|------|
| HKDF-SHA256 | RFC 5869 | Yes |
| PBKDF2-SHA256 | NIST SP 800-132 | Yes |
| KBKDF-HMAC-SHA256 | NIST SP 800-108 | Yes |
| Argon2id | RFC 9106 | No |
| scrypt | RFC 7914 | No* |

*scrypt is NIST-approved but not FIPS-validated

---

## Appendix B: Ciphertext Format Versions

### Version 1 (Legacy)
```json
{"v":1,"ctx":"...","kid":"...","alg":"...","nonce":"..."}
```

### Version 2 (Added mode)
```json
{"v":2,"ctx":"...","kid":"...","alg":"...","mode":"...","nonce":"..."}
```

### Version 3 (Current - Key commitment + AAD)
```json
{"v":3,"ctx":"...","kid":"...","alg":"...","mode":"...","nonce":"...","kc":"...","aad":false}
```

---

## Appendix C: Cryptographic Library Versions

| Library | Minimum Version | Recommended | Notes |
|---------|-----------------|-------------|-------|
| cryptography | 42.0.0 | Latest | OpenSSL bindings |
| liboqs-python | 0.10.0 | Latest | NIST PQC |
| PyJWT | 2.8.0 | Latest | JWT handling |
| argon2-cffi | 21.0.0 | Latest | Password hashing |

---

**Document History:**
- v1.1 (January 2026): Added SDK Security and Dashboard Security sections
- v1.0 (January 2026): Initial public release

**Contact:**
- Technical questions: engineering@cryptoserve.dev
- Security issues: security@cryptoserve.dev
