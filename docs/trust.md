# Why Trust CryptoServe

This document is for engineering leaders, security teams, and procurement officers evaluating CryptoServe for use in regulated or high-risk environments. It provides verifiable evidence for each claim rather than asking you to take our word for it.

---

## Open Source, Fully Auditable

CryptoServe is Apache 2.0 licensed. Every line of cryptographic code is publicly available for inspection. There is no "enterprise edition" with hidden security logic — the open-source version is the production version.

**Verify:** `git clone https://github.com/ecolibria/crypto-serve.git`

---

## What CryptoServe Does

CryptoServe provides cryptographic operations as a service: encryption, key management, digital signatures, hashing, and post-quantum cryptography through a REST API and Python SDK.

### Encryption

Encrypt and decrypt data using authenticated encryption (AES-256-GCM by default). The platform manages key derivation, nonce generation, and algorithm selection. You send plaintext and a context name; you get back ciphertext. No cryptographic decisions required by your application code.

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="payments", team="backend")
ciphertext = crypto.encrypt(b"4111-1111-1111-1111", context="card-data")
plaintext = crypto.decrypt(ciphertext, context="card-data")
```

**Algorithms available:** AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, AES-256-CBC+HMAC, AES-256-CCM, AES-256-XTS

### Key Management

Keys are derived using HKDF-SHA256, not stored directly. Each tenant and context gets unique key material. Key rotation is zero-downtime: new data uses the new key, old data decrypts with the old key until re-encrypted.

**Verify:** See `backend/app/core/key_manager.py` — key derivation uses HKDF per NIST SP 800-56C with per-tenant salt isolation.

### Post-Quantum Cryptography

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are available today, including hybrid mode that combines classical and post-quantum algorithms for defense-in-depth during the transition period.

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| ML-KEM-768 | FIPS 203 | Key encapsulation (recommended) |
| ML-KEM-512/1024 | FIPS 203 | Key encapsulation (Level 1/5) |
| ML-DSA-65 | FIPS 204 | Digital signatures (recommended) |
| ML-DSA-44/87 | FIPS 204 | Digital signatures (Level 2/5) |
| X25519 + ML-KEM | Hybrid | Quantum-safe key exchange |

**Verify:** See `backend/app/core/hybrid_crypto.py` and `backend/tests/test_hybrid_crypto.py`.

### Policy Engine

Define organizational rules for cryptographic usage. Enforce minimum key sizes, restrict algorithms, require quantum-safe modes for specific data classes. Violations are logged and optionally blocked.

**Verify:** See `backend/app/core/policy_engine.py` and `backend/tests/test_policy_engine.py`.

### Multi-Tenant Isolation

Each tenant derives unique key material through tenant-scoped HKDF salt. Database queries are filtered by tenant ID. A tenant cannot access another tenant's keys, contexts, or audit logs through the API.

**Verify:** See `backend/tests/test_multitenancy.py` — tests specifically verify cross-tenant access is blocked.

### Audit Logging

Every cryptographic operation produces a tamper-evident audit record containing: timestamp, operation, identity, algorithm, key ID, success/failure, input/output sizes, latency, and an HMAC-SHA256 integrity hash. These records support compliance evidence for PCI-DSS, HIPAA, and SOC 2.

**Verify:** See `backend/app/models/audit.py` and `backend/app/core/crypto_engine.py` (search for `integrity_hash`).

### Cryptographic Bill of Materials (CBOM)

Generate machine-readable inventories of all cryptographic algorithms in use across your deployment. Export as CycloneDX 1.5 or SPDX 2.3 format for integration with existing SBOM workflows.

**Verify:** See `backend/app/core/cbom.py` and `backend/tests/test_cbom.py`.

### Code and Dependency Scanning

AST-based scanner identifies cryptographic usage in source code (Python, JavaScript, Java, Go, Rust, C/C++). Dependency scanner audits npm, PyPI, and Cargo packages for known cryptographic vulnerabilities.

**Verify:** See `backend/app/core/code_scanner.py` and `backend/tests/test_code_scanner.py`.

---

## Security Controls

These are the specific controls protecting the platform itself.

### Authentication

- OAuth 2.0 with GitHub, Google, Azure AD, and Okta
- JWT tokens with unique `jti` claims and 1-day expiration
- Database-backed token revocation (persistent across restarts)
- Token ownership verification (users can only revoke their own tokens)
- Rate limiting on all authentication endpoints

### Transport and Session

- HSTS with preload directive
- HttpOnly, Secure, SameSite=Strict cookies
- Cache-Control: no-store on all responses
- Content-Security-Policy, X-Content-Type-Options, X-Frame-Options headers
- No sensitive data in URL parameters

### Input Validation

- Payload size limits on all API endpoints (10MB max for crypto operations)
- Context names restricted to alphanumeric characters plus dots, hyphens, underscores
- Batch operations capped at 100 items per request
- Pydantic v2 model validation on all request bodies

### Memory Protection

- Key material stored in mutable `bytearray` (not immutable `bytes`)
- `try/finally` blocks ensure zeroization on exceptions
- `SecureBytes` context manager for scoped key lifetime
- SDK cipher classes provide explicit `close()` for cleanup

**Honest limitation:** Python's garbage collector may copy objects during compaction. Memory zeroization is best-effort. For environments requiring guaranteed memory clearing, use a hardware security module.

### Configuration Safety

- No hardcoded secrets — production mode requires externally-provided secrets
- Startup validation blocks launch if dev-mode defaults are detected in production
- Dev login endpoint disabled when `DEV_MODE=false`
- Cookie secure flag enforced when `ENVIRONMENT=production`

---

## Compliance Readiness

### FIPS 140-2/140-3

Three modes: disabled (all algorithms), preferred (FIPS algorithms prioritized), and enabled (only FIPS-approved algorithms permitted). In FIPS-enabled mode, ChaCha20-Poly1305, Argon2, bcrypt, and other non-approved algorithms are blocked at the API level.

**Verify:** See `backend/app/core/fips.py` and `docs/fips-compliance.md`.

### Standards Coverage

| Standard | What CryptoServe Provides |
|----------|---------------------------|
| NIST SP 800-38D | AES-GCM implementation (primary encryption mode) |
| NIST SP 800-56C | HKDF key derivation |
| NIST FIPS 203/204 | ML-KEM and ML-DSA post-quantum algorithms |
| PCI-DSS (Sections 3, 4, 10) | AES-256 encryption, key management, audit logging |
| HIPAA Technical Safeguards | Access control, audit controls, integrity, transmission security |
| GDPR (Articles 25, 32) | Encryption by design, security of processing |
| SOC 2 Trust Criteria | Encryption, access controls, monitoring |

CryptoServe does not claim certification against these standards. It provides the cryptographic controls that support your organization's compliance posture.

---

## Testing

### Test Suite

1,380+ automated tests covering every cryptographic module, API endpoint, and security control.

```bash
# Run the full suite yourself
cd backend
pip install -r requirements-dev.txt
DEV_MODE=true STARTUP_VALIDATION_LEVEL=skip pytest -v
```

### What's Tested

- Encrypt/decrypt round-trip for all algorithms and modes
- Key derivation correctness and tenant isolation
- Cross-tenant access prevention
- Policy enforcement and violation detection
- Authentication flows (JWT, OAuth, token revocation)
- Input validation boundary cases
- Rate limiting enforcement
- FIPS mode algorithm blocking
- Nonce uniqueness
- Ciphertext format versioning and backward compatibility

---

## Security Audit Results

### Internal Platform Audit (February 2026)

23 findings identified across the full platform. All 23 resolved.

| Severity | Found | Fixed |
|----------|-------|-------|
| Critical | 4 | 4 |
| High | 7 | 7 |
| Medium | 7 | 7 |
| Low | 5 | 5 |

### Deep Penetration Test Review (February 2026)

13 additional findings from adversarial review. 11 resolved, 2 accepted as standard engineering tradeoffs.

| Severity | Found | Fixed | Accepted Risk |
|----------|-------|-------|---------------|
| Critical | 2 | 2 | 0 |
| High | 3 | 3 | 0 |
| Medium | 6 | 4 | 2 |
| Low | 2 | 2 | 0 |

**Accepted risks:**
- AES-GCM 96-bit nonce birthday bound at 2^48 operations per key (NIST SP 800-38D standard recommendation; mitigated by key rotation)
- Policy engine DotDict attribute access (safe by design — only dictionary keys exposed, no arbitrary object traversal)

**Verify:** All remediation commits are public: `606466b`, `49f8734`, `8146a48`. Full finding details in [Security Transparency Report](security/transparency-report.md).

---

## Supply Chain Security

| Control | How |
|---------|-----|
| Dependency pinning | All production packages pinned to exact versions |
| Vulnerability scanning | `pip-audit` in CI pipeline against advisory databases |
| Static analysis | `bandit` in CI with medium+ severity threshold |
| Action pinning | All GitHub Actions pinned to SHA commit hashes |
| Package publishing | PyPI OIDC Trusted Publishers (no stored API tokens) |
| Release artifacts | SHA-256 checksums on all published packages |
| Container security | Multi-stage Docker build, non-root runtime user |

---

## What CryptoServe Does Not Do

Transparency about boundaries is as important as capabilities.

- **Not a certificate authority.** CryptoServe generates and parses certificates but is not a production CA.
- **Not a secrets manager.** Use HashiCorp Vault, AWS Secrets Manager, or similar for application secrets. CryptoServe manages encryption keys.
- **Not a TLS terminator.** Deploy behind a reverse proxy or load balancer for TLS.
- **No forward secrecy for symmetric encryption.** If a key is compromised, data encrypted under that key is exposed. Mitigate with key rotation and short key lifetimes.
- **No guaranteed memory clearing.** Python's garbage collector limits what can be guaranteed. For highest assurance, pair with a hardware security module.
- **No FIPS 140-2 certification.** CryptoServe supports FIPS-approved algorithms and can operate in FIPS mode, but the platform itself is not FIPS certified. Certification is deployment-specific.

---

## Production Deployment

CryptoServe ships with a production-ready Docker Compose configuration that enforces:

- Strict startup validation (blocks launch with dev defaults)
- Non-root container user
- No source code volume mounts
- Health checks on all services
- Resource limits
- Structured JSON logging

```bash
# Production deployment
cp .env.example .env
# Edit .env with production secrets (openssl rand -base64 32 for each)
docker compose -f docker-compose.production.yml up -d
```

Full deployment guide: [Production Deployment](guides/production-deployment.md)

---

## How to Evaluate Independently

1. **Read the code.** The cryptographic implementation is in `backend/app/core/`. Start with `crypto_engine.py` (symmetric encryption), `key_manager.py` (key derivation), and `hybrid_crypto.py` (PQC).

2. **Run the tests.** Clone the repo, install dependencies, run `pytest -v`. All 1,380+ tests should pass.

3. **Run security scans.** `bandit -r backend/app -ll -ii` and `pip-audit -r backend/requirements.txt` against the production dependencies.

4. **Read the audit trail.** Security remediation commits are public: `git log --grep="security:"`.

5. **Deploy and test.** `docker compose up -d`, then hit `http://localhost:8003/health/deep` for a full system health check. Use the SDK to encrypt and decrypt data end-to-end.

6. **Generate a CBOM.** Use the `/api/v1/cbom/generate` endpoint to produce a machine-readable inventory of all cryptographic algorithms in your deployment.

---

## Documentation Map

| Document | Audience | Content |
|----------|----------|---------|
| [README](../README.md) | Developers | Quick start, SDK reference, API examples |
| [Security Transparency Report](security/transparency-report.md) | Auditors | Detailed findings, controls, compliance mapping |
| [Technical Reference](security/technical-reference.md) | Cryptographers | Algorithm details, threat model, protocol design |
| [FIPS Compliance Guide](fips-compliance.md) | Compliance officers | FIPS mode configuration and verification |
| [Production Deployment](guides/production-deployment.md) | Operations teams | Deployment checklist and configuration |
| **This document** | Decision makers | Trust evaluation and independent verification |
| [SECURITY.md](../SECURITY.md) | Security researchers | Vulnerability reporting and response SLAs |
