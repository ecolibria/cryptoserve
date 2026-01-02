# FIPS 140-2/140-3 Compliance Guide

This guide explains how to configure and operate CryptoServe in FIPS-compliant mode.

## Overview

FIPS 140-2 and FIPS 140-3 are U.S. government security standards for cryptographic modules. Many organizations (federal agencies, healthcare, financial services) require FIPS-validated cryptography.

CryptoServe supports three FIPS modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `disabled` | No FIPS enforcement | Development, testing |
| `preferred` | Use FIPS if available, warn if not | Transitional deployments |
| `enabled` | Strict FIPS enforcement, fail if unavailable | Production compliance |

## Quick Start

```bash
# Enable FIPS mode
export FIPS_MODE=enabled

# Start CryptoServe
uvicorn app.main:app
```

## Configuration

Set via environment variable:

```bash
# Options: disabled, preferred, enabled
FIPS_MODE=enabled
```

Or in `.env` file:

```ini
FIPS_MODE=enabled
```

## FIPS-Approved Algorithms

When FIPS mode is `enabled` or `preferred`, only these algorithms are allowed:

### Symmetric Encryption

| Cipher | Modes | Key Sizes | Standard |
|--------|-------|-----------|----------|
| AES | GCM, CBC, CTR, CCM | 128, 192, 256 bits | FIPS 197 |

### Hash Functions

| Algorithm | Standard |
|-----------|----------|
| SHA-256 | FIPS 180-4 |
| SHA-384 | FIPS 180-4 |
| SHA-512 | FIPS 180-4 |
| SHA3-256 | FIPS 202 |
| SHA3-384 | FIPS 202 |
| SHA3-512 | FIPS 202 |

### Post-Quantum Cryptography

| Algorithm | Standard | Security Level |
|-----------|----------|----------------|
| ML-KEM-512 | FIPS 203 | Level 1 |
| ML-KEM-768 | FIPS 203 | Level 3 |
| ML-KEM-1024 | FIPS 203 | Level 5 |
| ML-DSA-44 | FIPS 204 | Level 2 |
| ML-DSA-65 | FIPS 204 | Level 3 |
| ML-DSA-87 | FIPS 204 | Level 5 |
| SLH-DSA-128f | FIPS 205 | Level 1 |
| SLH-DSA-192f | FIPS 205 | Level 3 |
| SLH-DSA-256f | FIPS 205 | Level 5 |

### Password Hashing

| Algorithm | Standard |
|-----------|----------|
| PBKDF2-SHA256 | NIST SP 800-132 |

## Blocked Algorithms (Non-FIPS)

The following algorithms are blocked in FIPS mode:

| Algorithm | Reason |
|-----------|--------|
| ChaCha20-Poly1305 | RFC 8439, not NIST |
| AES-GCM-SIV | RFC 8452, not NIST |
| Argon2 | Not NIST approved |
| Bcrypt | Not NIST approved |

## OpenSSL FIPS Provider

For full FIPS compliance, CryptoServe requires OpenSSL with FIPS provider:

### Check Current Status

```bash
# Via API
curl http://localhost:8003/health/fips

# Response
{
  "status": {
    "mode": "enabled",
    "openssl_fips_available": true,
    "openssl_version": "OpenSSL 3.0.12 24 Oct 2023",
    "fips_provider_loaded": true,
    "compliant": true,
    "message": "FIPS mode enabled with validated OpenSSL FIPS provider"
  },
  "approved_algorithms": {...}
}
```

### Installing OpenSSL FIPS Provider

#### Ubuntu/Debian

```bash
# OpenSSL 3.x with FIPS support
sudo apt-get install openssl libssl3

# Configure FIPS provider
sudo openssl fipsinstall -out /etc/ssl/fipsmodule.cnf -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
```

#### Docker (FIPS-enabled image)

```dockerfile
FROM python:3.12-slim

# Install OpenSSL 3.x with FIPS
RUN apt-get update && apt-get install -y \
    openssl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Enable FIPS provider
ENV OPENSSL_CONF=/etc/ssl/openssl-fips.cnf
COPY openssl-fips.cnf /etc/ssl/openssl-fips.cnf
```

#### AWS/Cloud

Use FIPS-enabled AMIs or container images:
- AWS: Amazon Linux 2 FIPS, Ubuntu Pro FIPS
- Azure: FIPS-enabled Ubuntu images
- GCP: FIPS-enabled OS images

## Startup Validation

CryptoServe validates FIPS configuration at startup:

```
INFO: Startup validation: 7 passed, 0 warnings, 0 failed
INFO: FIPS status mode=enabled openssl_version=OpenSSL 3.0.12 fips_available=True compliant=True
INFO: FIPS 140-2/140-3 mode is active
```

### Strict Mode Failure

If `FIPS_MODE=enabled` but FIPS provider is not available:

```
ERROR: [FAIL] fips_mode: FIPS mode enabled but not compliant: OpenSSL FIPS provider not available
RuntimeError: Startup validation failed in STRICT mode.
```

## Runtime Enforcement

When FIPS mode is enabled, non-compliant algorithm requests are rejected:

```python
# This will fail in FIPS mode
crypto.encrypt(
    plaintext,
    context="user-pii",
    algorithm_override={"cipher": "ChaCha20", "mode": "poly1305", "key_bits": 256}
)

# Error: FIPSViolationError: Cipher 'ChaCha20' is not FIPS-approved
```

## Health Monitoring

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health/fips` | FIPS status and approved algorithms |
| `/health/deep` | Full health check including FIPS |

### Prometheus Metrics (Future)

```
cryptoserve_fips_mode{mode="enabled"} 1
cryptoserve_fips_compliant 1
cryptoserve_fips_violations_total 0
```

## Compliance Audit

### Audit Log Fields

All crypto operations log FIPS-relevant fields:

```json
{
  "operation": "encrypt",
  "algorithm": "AES-256-GCM",
  "cipher": "AES",
  "mode": "gcm",
  "key_bits": 256,
  "fips_compliant": true,
  "context": "user-pii"
}
```

### Generating Compliance Report

```bash
# List all algorithms used in last 30 days
curl http://localhost:8003/api/admin/metrics/algorithms

# Check for any non-FIPS usage
curl http://localhost:8003/api/admin/audit?fips_compliant=false
```

## Best Practices

1. **Always test FIPS mode before production**
   ```bash
   FIPS_MODE=enabled python -m pytest tests/
   ```

2. **Use FIPS-validated KMS in production**
   - AWS KMS is FIPS 140-2 validated
   - Azure Key Vault supports FIPS 140-2
   - HashiCorp Vault Enterprise has FIPS support

3. **Monitor FIPS violations**
   - Set up alerts for any `fips_compliant=false` audit entries
   - Review `/health/fips` in monitoring dashboards

4. **Document your FIPS boundary**
   - CryptoServe handles data-at-rest encryption
   - TLS (data-in-transit) requires separate FIPS configuration
   - Client applications may need their own FIPS validation

## Limitations

1. **OpenSSL Dependency**: FIPS mode requires OpenSSL 3.x with FIPS provider. The provider must be properly installed and configured at the OS level.

2. **Post-Quantum**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) are newly standardized. FIPS validation for liboqs implementations is pending.

3. **Password Hashing**: Argon2 (preferred for password hashing) is not FIPS-approved. In FIPS mode, PBKDF2-SHA256 is used instead.

## References

- [NIST FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [NIST Cryptographic Module Validation Program](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [OpenSSL FIPS Provider](https://www.openssl.org/docs/man3.0/man7/fips_module.html)
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
