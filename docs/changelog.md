# Changelog

All notable changes to CryptoServe are documented here.

This project follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

---

## [1.3.7] - 2026-01-06

### Added
- **AES-256-XTS Disk Encryption**: Full IEEE 1619 compliant disk encryption with HMAC integrity
  - `CipherFactory.encrypt_xts()` and `decrypt_xts()` methods
  - Support for sector-based encryption with 16-byte tweaks
  - HMAC verification for tamper detection
- **Hybrid Key Exchange (X25519 + ML-KEM)**: Quantum-safe key agreement
  - New `HybridKeyExchange` class combining classical X25519 with post-quantum ML-KEM
  - Support for ML-KEM-768 (Level 3) and ML-KEM-1024 (Level 5)
  - Complete API endpoints at `/api/v1/kex/*`
  - Serialization support for encapsulation data and keypairs
- **All ML-DSA Sizes**: Complete FIPS 204 support
  - ML-DSA-44 (NIST Level 2, 128-bit)
  - ML-DSA-65 (NIST Level 3, 192-bit)
  - ML-DSA-87 (NIST Level 5, 256-bit)
- **Full Algorithm Suite Resolution**: Complete cryptographic profile per context
  - Automatic resolution of symmetric, signing, hash, and KDF algorithms
  - Sensitivity-based algorithm selection (CRITICAL→SHA-384/ECDSA-P384, etc.)
  - Quantum-resistant signing (ML-DSA) when quantum threat detected
  - New `AlgorithmSuite` schema with full algorithm details

### UI Enhancements
- **Expandable Algorithm Suite Display**: Context cards now show full crypto profile
  - Click chevron to expand/collapse algorithm details
  - Shows symmetric, signing, hash, and KDF algorithms with icons
  - Lazy-loads algorithm suite on first expansion

### API Endpoints
- `GET /api/v1/kex/modes` - List available hybrid KEX modes
- `POST /api/v1/kex/keys/generate` - Generate X25519+ML-KEM keypair
- `GET /api/v1/kex/keys` - List hybrid KEX keys
- `GET /api/v1/kex/keys/{key_id}` - Get hybrid KEX key details
- `DELETE /api/v1/kex/keys/{key_id}` - Delete hybrid KEX key
- `POST /api/v1/kex/encapsulate` - Create shared secret (sender)
- `POST /api/v1/kex/decapsulate` - Recover shared secret (recipient)

### Documentation
- Updated README with hybrid key exchange and AES-XTS examples
- New sections in post-quantum.md for hybrid KEX, SLH-DSA, and XTS
- API reference updated with new endpoints

### Testing
- 34 new tests for PQC enhancements
- All ML-DSA sizes tested with FIPS 204 compliance
- AES-XTS HMAC integrity verification tests
- Hybrid KEX encapsulation/decapsulation roundtrip tests

---

## [1.3.6] - 2026-01-04

### Added
- Comprehensive examples directory with 11 working code samples
  - `01_basic_encryption.py` - Fundamental encrypt/decrypt operations
  - `02_string_and_json.py` - String and JSON encryption patterns
  - `03_signing.py` - Digital signatures with verification
  - `04_hashing.py` - Cryptographic hashing and MAC operations
  - `05_password_hashing.py` - Secure password storage with Argon2id
  - `06_file_encryption.py` - File encryption with metadata preservation
  - `09_post_quantum.py` - ML-KEM and ML-DSA operations (FIPS 203/204)
  - `fastapi_integration.py` - FastAPI web service with field-level encryption
  - `sqlalchemy_integration.py` - Transparent ORM field encryption
  - `error_handling.py` - Comprehensive error handling patterns
- PQC Migration Guide (`docs/guides/pqc-migration.md`)
  - Step-by-step migration strategy (Assessment → Hybrid → Pure PQC)
  - Algorithm selection guide for ML-KEM, ML-DSA, SLH-DSA
  - Performance and bandwidth considerations
  - Compliance mapping (FIPS, HIPAA, PCI-DSS, GDPR)

### Documentation
- Enhanced README with complete feature matrix and architecture diagram
- Post-quantum cryptography section with algorithm tables
- 5-layer context model explanation
- API reference tables for all endpoints
- Updated guides index with PQC and platform migration links

---

## [1.3.5] - 2026-01-04

### Fixed
- P0: Trust score now dynamically calculated instead of hardcoded to 1.0
- `check_promotion_readiness()` now accepts user_id and tenant_id parameters
- Trust score reflects user history (approvals, rejections, policy violations)

### Security
- Promotion readiness now properly gates based on developer trust metrics

---

## [1.3.2] - 2026-01-04

### Added
- Comprehensive production deployment documentation
- Critical secrets configuration section with generation commands
- Kubernetes secrets YAML example
- Health check verification steps for configuration validation

### Documentation
- Updated `docs/guides/production.md` with secrets management best practices
- All pre-release gap assessment items completed

---

## [1.3.1] - 2026-01-04

### Fixed
- `/health/ready` endpoint now returns 503 with error details instead of 500 on failures
- `/health/deep` endpoint now returns 503 with error details instead of 500 on failures
- FIPS status check wrapped in try/except to prevent cascading failures

### Improved
- Graceful degradation for all health check endpoints
- Better error messages when health checks fail unexpectedly

---

## [1.3.0] - 2026-01-04

### Added
- SDK integration test suite with 69 tests
  - `test_client.py` - CryptoClient low-level API tests
  - `test_cryptoserve.py` - CryptoServe high-level API tests
  - `test_init_cbom_pqc.py` - Init, CBOM, and PQC recommendation tests
  - `conftest.py` - Shared test fixtures

### Fixed
- Lease engine tests updated to match actual API (`secret` bytes instead of `secret_id` string)
- Compliance test fixed to remove broken `get_current_user` patch
- Revocation callback signature corrected to `(lease_id)` only

### Testing
- Total test count: 1,235 tests passing

---

## [1.2.0] - 2026-01-04

### Added
- `GET /api/v1/code/recommendations` endpoint for cryptographic best practices
- Empty plaintext validation in encrypt endpoint (returns 400)

### Fixed
- Weak password test uses truly weak passwords
- Hybrid encryption includes required `recipient_public_key`
- ML-DSA-65 test includes required `context` field
- CBOM endpoint corrected to `/api/v1/code/cbom`
- Policy evaluate includes required `algorithm` field
- Shamir shares include threshold for proper validation
- CBOM upload includes `tenant_id`

### Testing
- Feature test coverage: 103/103 (100%)
- PQC (ML-DSA, ML-KEM) fully validated
- API authentication consolidated to SDK identity auth

---

## [1.1.2] - 2026-01-04

### Fixed
- Standardize frontend port to 3000 (Next.js default)
- Standardize backend port to 8000 (FastAPI default)
- OAuth redirect mismatch (was redirecting to port 3003)

---

## [1.1.1] - 2026-01-04

### Fixed
- Migration history API 500 error by creating dedicated `MigrationHistory` table
- URL normalization for CT monitoring (accepts full URLs like `https://example.com`)
- Frontend domain normalization for CT search

---

## [1.1.0] - 2026-01-03

### Added

#### Certificate Revocation Checking
- OCSP (Online Certificate Status Protocol) support for real-time revocation checking
- CRL (Certificate Revocation List) support with automatic URL extraction
- Combined revocation check with OCSP-to-CRL fallback
- New methods: `get_ocsp_url()`, `get_crl_urls()`, `check_ocsp()`, `check_crl()`, `check_revocation()`

#### Batch Encryption API
- `POST /v1/crypto/batch/encrypt` - Encrypt up to 100 items per request
- `POST /v1/crypto/batch/decrypt` - Decrypt up to 100 items per request
- Client-provided IDs for tracking individual items
- `fail_fast` mode (stop on first error) or continue mode
- AAD (Additional Authenticated Data) support per item

#### SDK Key Bundle Caching
- `GET /v1/crypto/key-bundle` endpoint for SDK local caching
- Enables offline encryption/decryption operations
- Measured 95%+ cache hit rate in production workloads

#### Documentation
- Comprehensive migration guide for AWS KMS, HashiCorp Vault, and crypto libraries
- Cryptographic assessment report documenting NIST compliance

### Fixed
- Dynamic version retrieval in backup metadata (was hardcoded)

### Security
- Certificate revocation checking prevents use of compromised certificates
- Batch API enforces same authorization as single-item operations

---

## [1.0.0] - 2025-01-03

### Added

#### 5-Layer Context Model
- Data Identity layer: sensitivity classification (low/medium/high/critical), PII/PHI/PCI flags
- Regulatory layer: compliance framework support (HIPAA, GDPR, PCI-DSS, SOC2)
- Threat Model layer: quantum resistance requirements, protection lifetime
- Access Patterns layer: frequency-based optimization, latency requirements
- Technical layer: hardware acceleration, key size requirements
- Automatic algorithm selection based on all 5 layers

#### Policy Engine
- Customizable cryptographic policy rules
- Three severity levels: block, warn, info
- Default policies for common security requirements
- Policy evaluation API for testing before deployment
- Context-specific policy scoping
- CI/CD integration support via `/api/policies/check` endpoint

#### Admin Dashboard
- Overview with KPI cards (users, identities, operations, success rate)
- User management with search and pagination
- Global identity management with filtering
- Audit log viewer with export (CSV/JSON)
- Context management with key rotation
- Usage analytics with charts
- System health monitoring

#### Post-Quantum Cryptography
- ML-KEM-512/768/1024 (FIPS 203) key encapsulation
- ML-DSA-44/65/87 (FIPS 204) digital signatures
- Hybrid Ed25519+ML-DSA for signatures
- Hybrid X25519+ML-KEM for key exchange
- liboqs integration

#### Threshold Cryptography
- FROST signatures for distributed signing
- Distributed Key Generation (DKG)
- Threshold decryption with participant management

#### Secret Sharing
- Shamir's Secret Sharing (GF(256) implementation)
- Configurable threshold (k-of-n)

#### Key Ceremony
- Vault-style seal/unseal mechanism
- Shamir-based master key protection
- Multi-custodian support
- Recovery process

#### SIEM Integration
- CEF (Common Event Format)
- LEEF (IBM QRadar)
- JSON (Splunk/ELK)
- RFC 5424 Syslog
- Event categorization

### Security
- AES-256-GCM encryption by default
- HKDF-SHA256 key derivation
- JWT-based identity tokens
- Full audit logging
- Policy enforcement at runtime
- FIPS 140-2/140-3 compliance mode

### Infrastructure
- Docker Compose deployment
- GitHub OAuth integration
- CI/CD integration documentation

---

## [0.3.0] - 2024-01-15

### Added
- **Post-Quantum Cryptography**: ML-KEM-768 and ML-DSA-65 support
- **Hybrid Encryption**: Combined classical + PQC for defense in depth
- **Key Commitment**: Protection against invisible salamanders attack
- **FIPS Mode**: FIPS 140-2 compliant operation mode
- **Batch Operations**: Efficient bulk encrypt/decrypt APIs

### Changed
- Key hierarchy now supports PQC algorithms
- Context model extended to 5 layers
- Improved audit logging granularity

### Security
- Added key commitment scheme to prevent ciphertext malleability
- Implemented constant-time comparison for all sensitive operations

---

## [0.2.0] - 2023-10-01

### Added
- **Policy Engine**: Declarative cryptographic policies
- **KMS Integration**: AWS KMS and Google Cloud KMS support
- **Key Rotation**: Automatic and manual key rotation
- **Python SDK**: Full-featured Python client library
- **Identity Management**: Service identity authentication

### Changed
- Migrated from Flask to FastAPI
- Database schema refactored for multi-tenancy
- API versioning (v1 prefix)

### Fixed
- Memory leak in long-running encryption jobs
- Race condition in concurrent key access

---

## [0.1.0] - 2023-07-01

### Added
- Initial release
- **Core Encryption**: AES-256-GCM encryption/decryption
- **Context System**: Logical grouping for encryption keys
- **REST API**: Full CRUD operations
- **SQLite/PostgreSQL**: Database support
- **Docker**: Containerized deployment
- **Basic Authentication**: API key authentication

### Security
- All cryptographic operations use secure defaults
- No plaintext key storage

---

## Versioning Policy

- **Major (X.0.0)**: Breaking API changes
- **Minor (0.X.0)**: New features, backwards compatible
- **Patch (0.0.X)**: Bug fixes, security patches

## Deprecation Policy

- Deprecated features are marked in release notes
- Minimum 2 minor versions before removal
- Security fixes may bypass deprecation period

---

[1.3.7]: https://github.com/ecolibria/crypto-serve/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/ecolibria/crypto-serve/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/ecolibria/crypto-serve/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/ecolibria/crypto-serve/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/ecolibria/crypto-serve/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/ecolibria/crypto-serve/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/ecolibria/crypto-serve/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/ecolibria/crypto-serve/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ecolibria/crypto-serve/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/ecolibria/crypto-serve/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/ecolibria/crypto-serve/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/ecolibria/crypto-serve/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ecolibria/crypto-serve/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/ecolibria/crypto-serve/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ecolibria/crypto-serve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ecolibria/crypto-serve/releases/tag/v0.1.0
