# Compliance

CryptoServe is designed to help organizations meet their compliance requirements for data encryption.

## Supported Standards

### FIPS 140-2/140-3

Federal Information Processing Standard for cryptographic modules.

**Status**: Configurable compliance mode

**Configuration**:

```bash
# Strict FIPS enforcement
FIPS_MODE=enabled

# Prefer FIPS, warn on non-FIPS
FIPS_MODE=preferred

# No restrictions (default)
FIPS_MODE=disabled
```

**FIPS-Approved Algorithms**:

| Category | Algorithms |
|----------|------------|
| Symmetric | AES (128, 192, 256) in GCM, CBC, CTR, CCM |
| Hash | SHA-256, SHA-384, SHA-512, SHA3-* |
| MAC | HMAC with approved hash |
| KDF | HKDF, PBKDF2, KBKDF |
| Asymmetric | RSA (2048+), ECDSA (P-256, P-384), EdDSA |
| PQC | ML-KEM (FIPS 203), ML-DSA (FIPS 204) |

**Blocked in FIPS Mode**:

- ChaCha20-Poly1305
- Argon2
- bcrypt
- AES-GCM-SIV

---

### NIST Standards

| Standard | Description | CryptoServe Support |
|----------|-------------|---------------------|
| SP 800-38D | AES-GCM | Full compliance |
| SP 800-38C | AES-CCM | Full compliance |
| SP 800-38A | AES-CBC, CTR | Full compliance |
| SP 800-56C | Key Derivation | HKDF-SHA256 |
| SP 800-108 | KDF Counter Mode | KBKDF supported |
| SP 800-132 | Password-Based KDF | PBKDF2 supported |
| FIPS 186-4 | Digital Signatures | ECDSA, EdDSA |
| FIPS 203 | ML-KEM | Full compliance |
| FIPS 204 | ML-DSA | Full compliance |

---

### PCI-DSS

Payment Card Industry Data Security Standard.

**Relevant Requirements**:

| Requirement | CryptoServe Support |
|-------------|---------------------|
| 3.4 - Render PAN unreadable | AES-256 encryption |
| 3.5 - Protect cryptographic keys | HKDF derivation, KMS integration |
| 3.6 - Key management procedures | Key rotation, audit logging |
| 10.2 - Audit trails | Complete operation logging |

**Example Context Configuration**:

```json
{
  "name": "payment-data",
  "config": {
    "data_identity": {
      "sensitivity": "critical",
      "classification": "pci"
    },
    "regulatory": {
      "frameworks": ["pci-dss"],
      "audit_requirements": "detailed"
    }
  }
}
```

**Policy Example**:

```json
{
  "name": "pci-dss-encryption",
  "rule": {
    "require_algorithms": ["AES-256-GCM"],
    "min_key_bits": 256,
    "require_audit": true
  },
  "severity": "block",
  "applies_to": ["payment-data"]
}
```

---

### HIPAA

Health Insurance Portability and Accountability Act.

**Technical Safeguards**:

| Safeguard | CryptoServe Support |
|-----------|---------------------|
| Access Control | Identity-based authorization |
| Audit Controls | Complete operation logging |
| Integrity Controls | AEAD authentication |
| Transmission Security | TLS + encryption |

**Example Context Configuration**:

```json
{
  "name": "health-data",
  "config": {
    "data_identity": {
      "sensitivity": "critical",
      "classification": "phi"
    },
    "regulatory": {
      "frameworks": ["hipaa"],
      "audit_requirements": "detailed"
    }
  }
}
```

---

### GDPR

General Data Protection Regulation (EU).

**Relevant Articles**:

| Article | CryptoServe Support |
|---------|---------------------|
| Art. 25 - Privacy by Design | Default encryption |
| Art. 32 - Security of Processing | Strong encryption, access controls |
| Art. 33/34 - Breach Notification | Audit logs for investigation |

**Features Supporting GDPR**:

- Encryption at rest and in transit
- Access logging for accountability
- Key management for data deletion (key destruction)
- Multi-tenancy isolation

---

### SOC 2

Service Organization Control 2.

**Trust Service Criteria**:

| Criterion | CryptoServe Support |
|-----------|---------------------|
| Security | Encryption, authentication, authorization |
| Availability | Health monitoring, redundancy support |
| Confidentiality | Encryption, access controls |
| Processing Integrity | AEAD authentication |

**Audit Features**:

- Complete operation audit trail
- Exportable logs (JSON, CSV)
- Metrics and monitoring endpoints
- Admin dashboard for oversight

---

## Compliance Configuration

### Enable FIPS Mode

```bash
# Environment variable
FIPS_MODE=enabled
```

Or via API:

```bash
curl -X PUT http://localhost:8003/api/admin/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"fips_mode": "enabled"}'
```

### Create Compliance Policy

```bash
curl -X POST http://localhost:8003/api/policies \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "compliance-encryption",
    "type": "compliance",
    "rule": {
      "require_algorithms": ["AES-256-GCM"],
      "require_audit": true,
      "require_key_rotation_days": 365
    },
    "severity": "block"
  }'
```

### Configure Compliant Context

```bash
curl -X POST http://localhost:8003/api/contexts \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "regulated-data",
    "config": {
      "data_identity": {"sensitivity": "critical"},
      "regulatory": {
        "frameworks": ["hipaa", "pci-dss"],
        "audit_requirements": "detailed"
      },
      "technical": {"fips_required": true}
    }
  }'
```

---

## Audit Reports

### Export Audit Logs

```bash
# JSON format
curl "http://localhost:8003/api/admin/audit/export?format=json&start=2024-01-01&end=2024-01-31" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o audit-january.json

# CSV format
curl "http://localhost:8003/api/admin/audit/export?format=csv&start=2024-01-01&end=2024-01-31" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o audit-january.csv
```

### Audit Log Contents

Each audit record includes:

| Field | Description |
|-------|-------------|
| `timestamp` | UTC timestamp of operation |
| `operation` | encrypt, decrypt, sign, verify |
| `identity_id` | Identity that performed operation |
| `context` | Encryption context used |
| `algorithm` | Algorithm used |
| `success` | Operation success/failure |
| `error_message` | Error details if failed |
| `latency_ms` | Operation duration |
| `input_size_bytes` | Size of input data |

---

## Compliance Checklist

### Pre-Production

- [ ] Configure FIPS mode if required
- [ ] Create compliance policies for each regulation
- [ ] Set up contexts for sensitive data types
- [ ] Enable audit logging
- [ ] Configure log export/retention
- [ ] Set up KMS integration
- [ ] Document key management procedures
- [ ] Test disaster recovery

### Ongoing

- [ ] Regular key rotation (annual minimum)
- [ ] Audit log review (per policy)
- [ ] Access review (quarterly)
- [ ] Security patching
- [ ] Penetration testing (annual)
- [ ] Compliance audit documentation
