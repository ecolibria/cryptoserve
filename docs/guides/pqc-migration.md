# Post-Quantum Cryptography Migration Guide

A comprehensive guide to migrating your applications to quantum-resistant cryptography with CryptoServe.

---

## Overview

### Why Migrate to PQC?

Quantum computers pose an existential threat to current public-key cryptography:

| Algorithm | Threat Level | Timeline |
|-----------|--------------|----------|
| RSA-2048 | Critical | Broken by 2030-2035 |
| ECDSA P-256 | Critical | Broken by 2030-2035 |
| Ed25519 | Critical | Broken by 2030-2035 |
| AES-256 | Low | Requires doubling key size |
| SHA-256 | Low | Security reduced to 128-bit |

**"Harvest Now, Decrypt Later"** - Adversaries are already collecting encrypted data to decrypt once quantum computers become available. Data that must remain confidential for 10+ years should use PQC today.

### NIST Standards

CryptoServe implements the finalized NIST post-quantum standards:

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| **FIPS 203** | ML-KEM (Kyber) | Key encapsulation |
| **FIPS 204** | ML-DSA (Dilithium) | Digital signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based signatures |

---

## Migration Strategy

### Phase 1: Assessment (Week 1-2)

#### Step 1: Inventory Cryptographic Assets

Use CryptoServe's CBOM (Cryptographic Bill of Materials) scanner:

```bash
# Scan your codebase
cryptoserve scan ./src --output cbom.json

# View results in dashboard
open http://localhost:3000/cbom
```

The scanner identifies:
- RSA key usage (key exchange, encryption, signing)
- Elliptic curve usage (ECDSA, ECDH, Ed25519)
- Hash function usage
- TLS/SSL configuration

#### Step 2: Classify Data Sensitivity

Categorize your data by protection lifetime:

| Category | Examples | Required Protection |
|----------|----------|---------------------|
| **Short-term** (<5 years) | Session tokens, OTPs | Classical encryption OK |
| **Medium-term** (5-15 years) | Business documents | Hybrid recommended |
| **Long-term** (15+ years) | Health records, legal docs | PQC required |
| **Permanent** | Government secrets | PQC required now |

#### Step 3: Risk Assessment

```python
from cryptoserve import CryptoServe, get_pqc_recommendations

crypto = CryptoServe(app_name="my-app", team="platform")

# Get personalized recommendations
recommendations = crypto.get_pqc_recommendations()

for rec in recommendations:
    print(f"Context: {rec.context}")
    print(f"Current: {rec.current_algorithm}")
    print(f"Recommended: {rec.recommended_algorithm}")
    print(f"Risk: {rec.quantum_risk_level}")
    print(f"Migration Priority: {rec.priority}")
    print()
```

### Phase 2: Hybrid Migration (Week 3-6)

Hybrid cryptography combines classical and post-quantum algorithms for defense-in-depth.

#### Why Hybrid?

1. **Safety net** - If PQC algorithms have undiscovered weaknesses, classical provides backup
2. **Compliance** - Many standards still require classical algorithms
3. **Performance testing** - Gradual rollout lets you monitor impact

#### Enable Hybrid Mode

```python
# Configure context for hybrid encryption
crypto.configure_context(
    name="sensitive-data",
    encryption={
        "algorithm": "hybrid",
        "classical": "x25519",
        "pqc": "ml-kem-768"
    },
    signature={
        "algorithm": "hybrid",
        "classical": "ed25519",
        "pqc": "ml-dsa-65"
    }
)

# Usage is identical - hybrid is transparent
ciphertext = crypto.encrypt(data, context="sensitive-data")
signature = crypto.sign(document, context="sensitive-data")
```

#### Hybrid Key Exchange

```python
# X25519 + ML-KEM-768 hybrid
result = crypto.key_exchange(
    algorithm="hybrid-x25519-mlkem768",
    peer_public_key=peer_key
)

# Both parties derive the same shared secret
# Secret is secure if EITHER algorithm is secure
shared_secret = result["shared_secret"]
```

#### Hybrid Signatures

```python
# Ed25519 + ML-DSA-65 hybrid
signature = crypto.sign(
    document,
    algorithm="hybrid-ed25519-mldsa65"
)

# Verification requires both signatures to be valid
is_valid = crypto.verify(document, signature)
```

### Phase 3: Pure PQC (Week 7+)

Once confident in PQC stability, migrate to pure post-quantum:

```python
# Pure ML-KEM encryption
crypto.configure_context(
    name="quantum-safe",
    encryption={
        "algorithm": "ml-kem-1024"  # Pure PQC
    },
    signature={
        "algorithm": "ml-dsa-87"    # Pure PQC
    }
)
```

---

## Algorithm Selection Guide

### Key Encapsulation (ML-KEM)

| Variant | Security | Public Key | Ciphertext | Shared Secret | Use Case |
|---------|----------|------------|------------|---------------|----------|
| ML-KEM-512 | 128-bit | 800 B | 768 B | 32 B | IoT, embedded |
| ML-KEM-768 | 192-bit | 1,184 B | 1,088 B | 32 B | **General purpose** |
| ML-KEM-1024 | 256-bit | 1,568 B | 1,568 B | 32 B | High security |

**Recommendation**: Use ML-KEM-768 for most applications. Use ML-KEM-1024 for classified or long-term secrets.

### Digital Signatures (ML-DSA)

| Variant | Security | Public Key | Signature | Use Case |
|---------|----------|------------|-----------|----------|
| ML-DSA-44 | 128-bit | 1,312 B | 2,420 B | High-volume signing |
| ML-DSA-65 | 192-bit | 1,952 B | 3,293 B | **General purpose** |
| ML-DSA-87 | 256-bit | 2,592 B | 4,595 B | Critical documents |

**Recommendation**: Use ML-DSA-65 for most applications. Use ML-DSA-87 for legal documents and certificates.

### Hash-Based Signatures (SLH-DSA)

| Variant | Security | Public Key | Signature | Use Case |
|---------|----------|------------|-----------|----------|
| SLH-DSA-128f | 128-bit | 32 B | 17 KB | Fast signing |
| SLH-DSA-128s | 128-bit | 32 B | 7.8 KB | **Small signatures** |
| SLH-DSA-192f | 192-bit | 48 B | 35 KB | Fast, high security |
| SLH-DSA-256f | 256-bit | 64 B | 50 KB | Maximum security |

**Recommendation**: Use SLH-DSA for code signing or where signature size is less critical than trust assumptions (hash-only security).

---

## Code Examples

### Basic Migration: RSA to ML-KEM

**Before (RSA):**
```python
# Traditional RSA key exchange
from cryptography.hazmat.primitives.asymmetric import rsa, padding

private_key = rsa.generate_private_key(65537, 2048)
public_key = private_key.public_key()

# Encrypt session key
session_key = os.urandom(32)
encrypted_key = public_key.encrypt(session_key, padding.OAEP(...))
```

**After (ML-KEM via CryptoServe):**
```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Generate ML-KEM keypair
keypair = crypto.generate_keypair(algorithm="ml-kem-768")

# Encapsulate (replaces encrypt)
result = crypto.encapsulate(
    public_key=keypair["public_key"],
    algorithm="ml-kem-768"
)
shared_secret = result["shared_secret"]  # Use as session key
ciphertext = result["ciphertext"]        # Send to recipient

# Decapsulate (replaces decrypt)
shared_secret = crypto.decapsulate(
    ciphertext=ciphertext,
    private_key=keypair["private_key"],
    algorithm="ml-kem-768"
)
```

### Basic Migration: ECDSA to ML-DSA

**Before (ECDSA):**
```python
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
```

**After (ML-DSA via CryptoServe):**
```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Generate ML-DSA keypair
keypair = crypto.generate_keypair(algorithm="ml-dsa-65")

# Sign
signature = crypto.sign_pqc(
    message=data,
    private_key=keypair["private_key"],
    algorithm="ml-dsa-65"
)

# Verify
is_valid = crypto.verify_pqc(
    message=data,
    signature=signature,
    public_key=keypair["public_key"],
    algorithm="ml-dsa-65"
)
```

### TLS Migration Path

For TLS/mTLS connections, CryptoServe supports hybrid certificates:

```python
# Generate hybrid certificate
cert = crypto.generate_certificate(
    common_name="api.example.com",
    algorithm="hybrid-ed25519-mldsa65",
    validity_days=365
)

# Use in your web server configuration
# The certificate contains both classical and PQC signatures
```

---

## Performance Considerations

### Latency Impact

| Operation | RSA-2048 | ECDSA P-256 | ML-KEM-768 | ML-DSA-65 |
|-----------|----------|-------------|------------|-----------|
| Key Gen | 50ms | 0.1ms | 0.1ms | 0.3ms |
| Encrypt/Encap | 0.1ms | 0.2ms | 0.1ms | N/A |
| Decrypt/Decap | 2ms | 0.2ms | 0.1ms | N/A |
| Sign | 2ms | 0.1ms | N/A | 1ms |
| Verify | 0.1ms | 0.2ms | N/A | 0.5ms |

**Key insight**: ML-KEM and ML-DSA are often *faster* than RSA.

### Bandwidth Impact

| Algorithm | Public Key | Ciphertext/Signature |
|-----------|------------|---------------------|
| RSA-2048 | 256 B | 256 B |
| ECDSA P-256 | 64 B | 64 B |
| ML-KEM-768 | 1,184 B | 1,088 B |
| ML-DSA-65 | 1,952 B | 3,293 B |

**Key insight**: PQC has larger keys and signatures. Plan for:
- Increased certificate sizes
- Larger TLS handshakes
- More storage for signatures

### Optimization Tips

1. **Cache public keys** - PQC keys are larger but don't change often
2. **Use hybrid selectively** - Only for data requiring long-term protection
3. **Batch operations** - Amortize key generation costs
4. **Pre-compute** - Generate keypairs ahead of time

---

## Compliance Mapping

### NIST Recommendations

| Protection Level | Symmetric | Hash | PQC KEM | PQC Signature |
|------------------|-----------|------|---------|---------------|
| 128-bit | AES-128 | SHA-256 | ML-KEM-512 | ML-DSA-44 |
| 192-bit | AES-192 | SHA-384 | ML-KEM-768 | ML-DSA-65 |
| 256-bit | AES-256 | SHA-512 | ML-KEM-1024 | ML-DSA-87 |

### Framework Alignment

| Framework | PQC Requirement |
|-----------|-----------------|
| **FIPS 140-3** | ML-KEM, ML-DSA approved |
| **PCI-DSS 4.0** | Recommends PQC evaluation |
| **HIPAA** | Requires encryption; PQC for long-term data |
| **GDPR** | "Appropriate" security; PQC for personal data |
| **FedRAMP** | Following NIST guidelines |

---

## Monitoring and Verification

### Dashboard Metrics

Track migration progress in the CryptoServe dashboard:

- **Algorithm Distribution** - Percentage of operations by algorithm
- **PQC Adoption** - Trend of PQC vs classical usage
- **Quantum Risk Score** - Overall exposure to quantum threats
- **Migration Progress** - Contexts migrated vs remaining

### Alerts

Configure alerts for:

```python
# Alert if classical-only encryption is still used
crypto.configure_alert(
    name="classical-encryption-usage",
    condition="algorithm NOT LIKE 'ml-%' AND algorithm NOT LIKE 'hybrid-%'",
    severity="warning"
)
```

### Audit Log Analysis

```python
# Query audit logs for quantum-vulnerable operations
logs = crypto.query_audit_logs(
    filters={
        "algorithm": {"$in": ["rsa", "ecdsa", "ed25519"]},
        "timestamp": {"$gte": "2024-01-01"}
    }
)

for log in logs:
    print(f"{log.timestamp}: {log.operation} using {log.algorithm}")
```

---

## Rollback Plan

If issues arise during migration:

### Quick Rollback

```python
# Temporarily disable PQC for a context
crypto.configure_context(
    name="sensitive-data",
    encryption={
        "algorithm": "aes-256-gcm",  # Fall back to classical
        "pqc_enabled": False
    }
)
```

### Data Re-encryption

```python
# Re-encrypt data with different algorithm
from cryptoserve import re_encrypt

result = crypto.re_encrypt(
    ciphertext=old_ciphertext,
    from_context="hybrid-context",
    to_context="classical-context"
)
```

### Key Recovery

Hybrid encryption ensures data remains accessible:
- If PQC key is compromised → Classical key still protects
- If classical key is compromised → PQC key still protects
- Both must be compromised for data exposure

---

## Timeline Recommendations

| Data Type | Recommended Action | Target Date |
|-----------|-------------------|-------------|
| Government/Military | Pure PQC | Now |
| Financial (10+ year) | Hybrid | 2025 |
| Healthcare (PHI) | Hybrid | 2025 |
| Enterprise PII | Hybrid | 2026 |
| General Business | Evaluate | 2027 |

---

## Next Steps

1. **Run CBOM scan** on your codebase
2. **Identify high-priority** contexts (long-term data)
3. **Enable hybrid mode** for priority contexts
4. **Monitor performance** and adjust as needed
5. **Plan pure PQC** migration for 2026-2027

## Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CISA Post-Quantum Guidance](https://www.cisa.gov/quantum)
- [CryptoServe PQC API Reference](../api-reference/crypto.md)
- [Example: Post-Quantum Operations](https://github.com/keytum/crypto-serve/blob/main/examples/09_post_quantum.py)
