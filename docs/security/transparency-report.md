# CryptoServe Security Transparency Report

**Version**: 1.0.0
**Date**: February 2026
**Classification**: Public
**Intended Audience**: Enterprise security teams, government auditors, compliance officers

---

## Executive Summary

CryptoServe is an open-source cryptographic services platform providing encryption, key management, digital signatures, and post-quantum cryptography through a unified API. This transparency report documents the platform's security architecture, controls, audit history, and known limitations to support independent evaluation by enterprise and government security teams.

**Key Security Properties:**
- NIST-approved cryptographic primitives (AES-256-GCM, SHA-256/384/512, HKDF, ECDSA, RSA)
- Post-quantum cryptography support (ML-KEM FIPS 203, ML-DSA FIPS 204)
- FIPS 140-2/140-3 configurable compliance mode
- Multi-tenant cryptographic isolation with per-tenant key derivation
- Database-backed token revocation with in-memory caching
- AEAD-only encryption by default (no unauthenticated modes)
- Full audit logging with HMAC-SHA256 integrity verification

---

## 1. Cryptographic Architecture

### 1.1 Symmetric Encryption

| Algorithm | Mode | Key Size | Nonce | Status |
|-----------|------|----------|-------|--------|
| AES-256-GCM | AEAD | 256-bit | 96-bit random | Primary (recommended) |
| ChaCha20-Poly1305 | AEAD | 256-bit | 96-bit random | Secondary (non-AES-NI) |
| AES-256-CBC + HMAC-SHA256 | Encrypt-then-MAC | 256-bit | 128-bit random | Legacy compatibility |
| AES-256-CCM | AEAD | 256-bit | Variable | Supported |

**Design Decisions:**
- All encryption modes are authenticated (AEAD or Encrypt-then-MAC)
- Unauthenticated modes (ECB, bare CBC, bare CTR) are not exposed
- Key commitment is enforced in the ciphertext header to prevent multi-key attacks
- Nonces are generated using `secrets.token_bytes()` (OS CSPRNG)
- 96-bit GCM nonces provide a birthday bound of ~2^48 encryptions per key

### 1.2 Key Management

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key derivation | HKDF-SHA256 | NIST SP 800-56C Rev. 2 |
| Master key storage | Platform KMS or config | Per deployment |
| Per-tenant isolation | HKDF with tenant-scoped salt | Custom |
| Key rotation | Versioned derivation | Custom |
| PQC key storage | AES-256-GCM encryption at rest | Custom |

**Key Hierarchy:**
```
Master Secret (from KMS or configuration)
  |
  +-- HKDF(salt="{platform_salt}:{tenant_id}", info="{context}:{version}:{key_size}")
        |
        +-- Data Encryption Key (per context, per tenant)
```

**Tenant Isolation:** Each tenant derives unique keys through:
1. Tenant ID incorporated into HKDF salt material
2. Context name qualified with tenant ID in async KMS derivation
3. Database-level tenant_id filtering on all key records

### 1.3 Post-Quantum Cryptography

| Algorithm | Standard | Security Level | Status |
|-----------|----------|----------------|--------|
| ML-KEM-512 | FIPS 203 | Level 1 (128-bit) | Supported |
| ML-KEM-768 | FIPS 203 | Level 3 (192-bit) | Recommended |
| ML-KEM-1024 | FIPS 203 | Level 5 (256-bit) | Supported |
| ML-DSA-44 | FIPS 204 | Level 2 | Supported |
| ML-DSA-65 | FIPS 204 | Level 3 | Recommended |
| ML-DSA-87 | FIPS 204 | Level 5 | Supported |

**Hybrid Mode:** ML-KEM-768 + AES-256-GCM for data protection during the quantum transition period.

### 1.4 Hashing and MACs

| Function | Output Size | Usage |
|----------|-------------|-------|
| SHA-256 | 256-bit | General-purpose hashing, HMAC |
| SHA-384 | 384-bit | Extended hashing |
| SHA-512 | 512-bit | High-security hashing |
| SHA3-256 | 256-bit | Post-quantum hash |
| BLAKE2b | Variable | Performance-optimized hashing |
| HMAC-SHA256 | 256-bit | Message authentication, audit integrity |

### 1.5 Digital Signatures

| Algorithm | Key Size | Standard |
|-----------|----------|----------|
| ECDSA (P-256) | 256-bit | FIPS 186-4 |
| ECDSA (P-384) | 384-bit | FIPS 186-4 |
| RSA-PSS | 2048/3072/4096-bit | PKCS#1 v2.1 |
| Ed25519 | 256-bit | RFC 8032 |
| ML-DSA | Variable | FIPS 204 |

---

## 2. Authentication and Authorization

### 2.1 User Authentication

| Method | Token Type | Lifetime | Storage |
|--------|-----------|----------|---------|
| OAuth 2.0 (GitHub, Google, Azure AD, Okta) | JWT (HS256) | 1 day | HttpOnly cookie (SameSite=Strict) |
| SDK Bearer Token | Application keypair | Configurable | Client-side credential file (0600) |

**JWT Security Controls:**
- Unique `jti` claim (128-bit random) on every token
- Database-backed token revocation (persistent across restarts)
- In-memory revocation cache for sub-millisecond validation
- Automatic cleanup of expired revocation records on startup
- User ownership verification on revocation requests

### 2.2 OAuth CSRF Protection

- HMAC-SHA256 signed state parameter (128-bit signature)
- 5-minute state expiration
- Per-provider nonce to prevent cross-provider replay
- Constant-time signature comparison (`hmac.compare_digest`)

### 2.3 Role-Based Access Control

| Role | Permissions |
|------|-------------|
| Viewer | Read-only access to contexts and audit logs |
| Developer | Encrypt/decrypt, manage own identities |
| Admin | Create contexts, manage policies, view all audit logs |
| Owner | Full platform administration, team management |

### 2.4 Rate Limiting

| Endpoint Category | Limit |
|-------------------|-------|
| Authentication (login, callback) | 10 requests/minute |
| Dev login | 5 requests/minute |
| Token refresh | 10 requests/minute |
| Token verification | 30 requests/minute |
| Token revocation | 10 requests/minute |
| Crypto operations | Configurable per deployment |

---

## 3. Data Protection Controls

### 3.1 Transport Security

- TLS 1.2+ required (TLS 1.3 recommended)
- HSTS with `includeSubDomains` and `preload` directives
- HTTP requests upgraded to HTTPS

### 3.2 HTTP Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload | Force HTTPS |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-Frame-Options | DENY | Prevent clickjacking |
| X-XSS-Protection | 0 | Defer to CSP (browser-native XSS filter unreliable) |
| Content-Security-Policy | default-src 'self' | Restrict resource loading |
| Referrer-Policy | no-referrer | Prevent referrer leakage |
| Cache-Control | no-store | Prevent caching of sensitive responses |
| Permissions-Policy | camera=(), microphone=(), geolocation=() | Restrict browser APIs |

### 3.3 Cookie Security

| Attribute | Value |
|-----------|-------|
| HttpOnly | true |
| Secure | true (enforced in production) |
| SameSite | Strict |
| Path | / |

### 3.4 Input Validation

| Input | Validation |
|-------|-----------|
| Plaintext/ciphertext | Max 10MB (base64-encoded) |
| Context names | Max 64 chars, regex: `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` |
| Associated data (AAD) | Max 1MB (base64-encoded) |
| Batch operations | Max 100 items per request |
| File uploads | Max 10MB |
| Batch item IDs | Max 128 chars |

### 3.5 Memory Protection

- `SecureBytes` context manager for key material zeroization
- `secure_zero()` applied to all intermediate key material in encrypt/decrypt paths
- `bytearray` used instead of `bytes` for mutable zeroization
- `try/finally` blocks ensure cleanup on exceptions
- SDK cipher classes provide `close()` for explicit cleanup

**Known Limitation:** Python's garbage collector may copy objects during compaction. Memory zeroization is best-effort; for environments requiring guaranteed memory clearing, deploy behind a hardware security module.

---

## 4. Audit and Logging

### 4.1 Audit Log Fields

Every cryptographic operation produces an audit record containing:

| Field | Description |
|-------|-------------|
| timestamp | UTC timestamp of operation |
| operation | encrypt, decrypt, sign, verify, hash |
| context | Encryption context name |
| identity_id | Authenticated identity performing the operation |
| success | Boolean result |
| algorithm | Algorithm used (e.g., AES-256-GCM) |
| key_id | Key identifier used |
| quantum_safe | Whether PQC algorithm was used |
| policy_violation | Whether policy was violated |
| input_size_bytes | Size of input data |
| output_size_bytes | Size of output data |
| latency_ms | Operation latency |
| ip_address | Client IP address |
| integrity_hash | HMAC-SHA256 over key audit fields |

### 4.2 Audit Integrity

Each audit record includes an HMAC-SHA256 integrity hash computed over:
```
HMAC-SHA256(key, "{timestamp}|{identity_id}|{operation}|{context}|{success}")
```

This allows detection of unauthorized modification of audit records.

### 4.3 Dev Login Monitoring

All development-mode login events are logged with:
- Client IP address
- User identity
- Warning-level severity for visibility in log aggregators

---

## 5. Compliance Standards Mapping

### 5.1 FIPS 140-2/140-3

CryptoServe provides three FIPS compliance modes:

| Mode | Behavior |
|------|----------|
| Disabled | All algorithms available |
| Preferred | FIPS-approved algorithms preferred, others available |
| Enabled | Only FIPS-approved algorithms permitted |

**FIPS-Approved Algorithms:** AES (128/192/256), SHA-2 family, HMAC-SHA2, HKDF-SHA256, ECDSA (P-256/P-384), RSA (2048+)

**Blocked in FIPS Mode:** ChaCha20-Poly1305, Argon2, bcrypt, AES-GCM-SIV, BLAKE2

### 5.2 Standards Compliance Matrix

| Standard | Coverage | Notes |
|----------|----------|-------|
| NIST SP 800-38D | AES-GCM implementation | Primary encryption mode |
| NIST SP 800-56C | Key derivation (HKDF) | Key hierarchy |
| NIST SP 800-108 | KDF in counter mode | Supported via kdf_engine |
| NIST FIPS 203 | ML-KEM (Kyber) | Post-quantum key encapsulation |
| NIST FIPS 204 | ML-DSA (Dilithium) | Post-quantum signatures |
| FIPS 186-4 | Digital signatures | ECDSA, RSA |
| PCI-DSS | Encryption, key management, audit | Sections 3, 4, 10 |
| HIPAA | Access control, audit, integrity | Technical safeguards |
| GDPR | Privacy by design, security measures | Article 25, 32 |
| SOC 2 | Encryption, access, monitoring | Trust Service Criteria |

---

## 6. Supply Chain Security

### 6.1 Dependency Management

- All production dependencies pinned to exact versions
- Separate production (`requirements.txt`) and development (`requirements-dev.txt`) dependency files
- CI pipeline includes `pip-audit` for known vulnerability scanning
- CI pipeline includes `bandit` for static security analysis

### 6.2 CI/CD Security

| Control | Implementation |
|---------|----------------|
| Action pinning | All GitHub Actions pinned to SHA hashes |
| PyPI publishing | OIDC Trusted Publishers (no stored API tokens) |
| Static analysis | Bandit with medium+ severity threshold |
| Dependency audit | pip-audit against known vulnerability databases |
| Test gate | All 1,380+ tests must pass before publish |
| Package verification | twine check on all built artifacts |
| Release provenance | `SHA256SUMS.txt` and SLSA provenance on each CLI release from `js-v0.4.0`; no Python release has attestations or a checksum file that verifies ([Verifying releases](../../README.md#verifying-releases)) |

### 6.3 Container Security

- Multi-stage Docker build (build dependencies not in runtime image)
- Non-root user (`cryptoserve`) in runtime container
- `.dockerignore` excludes sensitive files (.env, .git, tests, *.db, *.pem, *.key)
- Production Docker Compose with resource limits and health checks
- No source code volume mounts in production configuration

---

## 7. Security Audit History

### 7.1 Internal Platform Audit (February 2026)

**Scope:** Full platform security review covering authentication, cryptography, authorization, API security, configuration, and CI/CD.

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 4 | 4 | 0 |
| High | 7 | 7 | 0 |
| Medium | 7 | 7 | 0 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **23** | **0** |

**Critical Findings (all resolved):**
1. Hardcoded default secrets in production configuration
2. Config validator accepted weak sentinel values
3. Cross-tenant key retrieval without tenant filtering
4. HKDF key derivation lacked per-tenant isolation

**High Findings (all resolved):**
1. JWT tokens lacked unique identifiers (jti claim)
2. Token revocation allowed cross-user revocation
3. SameSite cookie attribute set to Lax instead of Strict
4. No rate limiting on authentication endpoints
5. Bare exception handlers swallowing security errors
6. CI security scanning failures silently ignored
7. GitHub Actions not pinned to SHA hashes

### 7.2 Deep Penetration Test Review (February 2026)

**Scope:** Adversarial review of authentication flows, cryptographic implementation, multi-tenant isolation, and API security.

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 2 | 2 | 0 |
| High | 3 | 3 | 0 |
| Medium | 6 | 4 | 2 (accepted risk) |
| Low | 2 | 2 | 0 |
| **Total** | **13** | **11** | **2** |

**Accepted Risks:**
- **GCM nonce birthday bound (2^48 operations/key):** Mitigated by key rotation; standard 96-bit nonce as recommended by NIST SP 800-38D
- **Policy engine DotDict attribute access:** Safe by design - only dict keys exposed as attributes, no arbitrary object access

### 7.3 Remediation Commits

All security fixes are publicly auditable in the git history:

| Commit | Description |
|--------|-------------|
| `606466b` | Fix all critical and high findings from platform audit |
| `49f8734` | Fix medium and low findings from platform audit |
| `8146a48` | Fix all pentest findings from deep security review |

---

## 8. Test Coverage

### 8.1 Test Suite

| Category | Tests | Coverage Focus |
|----------|-------|----------------|
| Crypto engine | ~200 | Encrypt/decrypt, key derivation, algorithm selection |
| AEAD modes | ~80 | GCM, CCM, ChaCha20-Poly1305, nonce handling |
| Key management | ~60 | Derivation, rotation, tenant isolation |
| Authentication | ~100 | JWT, OAuth, token revocation, rate limiting |
| Policy engine | ~80 | Algorithm policies, enforcement, violations |
| PQC operations | ~60 | ML-KEM, ML-DSA, hybrid encryption |
| API endpoints | ~200 | Request validation, error handling, auth checks |
| Multi-tenancy | ~50 | Tenant isolation, cross-tenant prevention |
| Code scanning | ~40 | AST analysis, dependency scanning |
| Certificates | ~30 | CSR, signing, chain verification |
| Other modules | ~380 | Backup, migration, CBOM, metrics, health |
| **Total** | **1,380+** | |

### 8.2 Security-Specific Tests

- Unauthenticated request rejection on all protected endpoints
- Cross-tenant data isolation verification
- Policy violation detection and enforcement
- Nonce uniqueness verification
- Key material zeroization verification
- FIPS mode algorithm blocking
- Rate limit enforcement
- Input validation boundary testing

---

## 9. Known Limitations

This section documents security properties that CryptoServe does **not** provide. Transparency about limitations is essential for accurate risk assessment.

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No forward secrecy for symmetric encryption | Compromise of a key exposes all data encrypted under it | Key rotation, short key lifetimes |
| Python memory model | GC may copy key material before zeroization | SecureBytes best-effort; HSM for high-assurance |
| Single master key per deployment | Master key compromise affects all tenants | Use platform KMS (AWS/GCP/Azure) for per-tenant master keys |
| No hardware security module by default | Software key storage | HSM integration available via KMS providers |
| No streaming encryption | Large files must fit in memory | Planned for future release |
| No client-side encryption | Data is encrypted server-side | SDK provides local crypto primitives via cryptoserve-core |
| In-memory revocation cache | New server instances need DB sync | Cache populated from persistent DB on startup |
| AES-GCM 2^48 message limit per key | Theoretical nonce collision risk at scale | Key rotation enforced before limit |

---

## 10. Deployment Security Checklist

For production deployments, verify the following:

- [ ] `ENVIRONMENT=production` is set
- [ ] `STARTUP_VALIDATION_LEVEL=strict` enforced
- [ ] `DEV_MODE=false` (blocks dev login endpoint)
- [ ] All secrets generated with `openssl rand -base64 32` (no defaults)
- [ ] `COOKIE_SECURE=true` enforced
- [ ] TLS termination configured (load balancer or reverse proxy)
- [ ] Database credentials use unique, randomly generated passwords
- [ ] OAuth state secret is unique per deployment
- [ ] HKDF salt is unique per deployment
- [ ] JWT secret key is unique per deployment
- [ ] Docker container runs as non-root user
- [ ] No source code volume mounts
- [ ] Database backups configured and encrypted
- [ ] Log aggregation configured (structured JSON logging auto-enabled in production)
- [ ] Rate limiting verified active
- [ ] Health endpoints accessible for monitoring

---

## 11. Independent Verification

### 11.1 Source Code

The complete source code is available for audit at:
`https://github.com/ecolibria/cryptoserve`

### 11.2 Key Files for Security Review

| File | Purpose |
|------|---------|
| `backend/app/core/crypto_engine.py` | Symmetric encryption implementation |
| `backend/app/core/key_manager.py` | Key derivation and tenant isolation |
| `backend/app/core/hybrid_crypto.py` | Post-quantum hybrid encryption |
| `backend/app/auth/jwt.py` | JWT token creation, validation, revocation |
| `backend/app/auth/oauth.py` | OAuth 2.0 flows and CSRF protection |
| `backend/app/core/secure_memory.py` | Memory zeroization utilities |
| `backend/app/core/policy_engine.py` | Cryptographic policy enforcement |
| `backend/app/core/fips.py` | FIPS compliance mode |
| `backend/app/config.py` | Configuration with production validation |
| `backend/app/core/startup.py` | Startup security validation |
| `backend/app/main.py` | Security middleware and headers |

### 11.3 Reproducible Builds

```bash
# Clone and verify
git clone https://github.com/ecolibria/cryptoserve.git
cd crypto-serve/backend

# Install dependencies
pip install -r requirements-dev.txt

# Run full test suite
DEV_MODE=true STARTUP_VALIDATION_LEVEL=skip pytest -v

# Run security scans
bandit -r app -ll -ii
pip-audit -r requirements.txt
```

### 11.4 CBOM Generation

CryptoServe can generate a Cryptographic Bill of Materials (CBOM) for its own deployment, providing a machine-readable inventory of all cryptographic algorithms in use. Export formats: CycloneDX 1.5, SPDX 2.3, and native JSON.

---

## 12. Contact

**Security Issues:** See [SECURITY.md](../../SECURITY.md) for vulnerability reporting procedures.
**Repository:** https://github.com/ecolibria/cryptoserve
**License:** Apache 2.0
