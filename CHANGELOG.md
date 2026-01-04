# Changelog

All notable changes to CryptoServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

#### Frontend Improvements
- Policies page with interactive policy evaluator
- Dashboard navigation with policies link
- Mobile-responsive layout improvements

#### Backend Features
- PostgreSQL-based context configuration storage
- Context-derived cryptographic requirements
- Algorithm recommendation engine
- Admin API endpoints with role-based access

### Security
- AES-256-GCM encryption by default
- HKDF-SHA256 key derivation
- JWT-based identity tokens
- Full audit logging
- Policy enforcement at runtime

### Infrastructure
- Docker Compose deployment
- GitHub OAuth integration
- CI/CD integration documentation

## [0.1.0] - 2024-12-01

### Added
- Initial release
- Basic encrypt/decrypt operations
- Context-based key management
- Identity management
- Personalized SDK generation
- GitHub OAuth authentication
- Audit logging
