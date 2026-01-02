# Algorithm Policy API

Configure allowed cryptographic algorithms and enforce compliance standards.

## Endpoints

### Get Algorithm Policy

```http
GET /api/v1/algorithm-policy
```

Get the current algorithm policy configuration.

**Response:**

```json
{
  "fipsMode": "preferred",
  "minimumKeySize": 256,
  "allowedSymmetric": [
    "AES-256-GCM",
    "AES-128-GCM",
    "ChaCha20-Poly1305"
  ],
  "allowedHash": [
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256"
  ],
  "allowedPqc": [
    "ML-KEM-768",
    "ML-KEM-1024",
    "ML-DSA-65",
    "ML-DSA-87"
  ],
  "deprecatedAlgorithms": [
    "AES-128-CBC",
    "SHA-1"
  ],
  "defaultSymmetric": "AES-256-GCM",
  "defaultHash": "SHA-256",
  "requirePqcForLongTerm": false,
  "updatedAt": "2026-01-02T10:00:00Z",
  "updatedBy": "admin@example.com"
}
```

---

### Update Algorithm Policy

```http
PUT /api/v1/algorithm-policy
```

Update the algorithm policy. Requires admin privileges.

**Request Body:**

```json
{
  "fipsMode": "enabled",
  "minimumKeySize": 256,
  "allowedSymmetric": ["AES-256-GCM", "AES-128-GCM"],
  "deprecatedAlgorithms": ["ChaCha20-Poly1305"],
  "requirePqcForLongTerm": true
}
```

**Response:**

```json
{
  "status": "updated",
  "warnings": [
    "ChaCha20-Poly1305 marked as deprecated - 3 contexts currently use this algorithm"
  ]
}
```

---

### Validate Algorithm

```http
POST /api/v1/algorithm-policy/validate
```

Check if an algorithm is allowed under current policy.

**Request Body:**

```json
{
  "algorithm": "AES-256-GCM",
  "keySize": 256,
  "operation": "encrypt"
}
```

**Response:**

```json
{
  "allowed": true,
  "fipsCompliant": true,
  "warnings": [],
  "recommendation": null
}
```

---

### Get FIPS Status

```http
GET /api/v1/algorithm-policy/fips-status
```

Get FIPS compliance status for all contexts.

**Response:**

```json
{
  "fipsMode": "preferred",
  "compliantContexts": 3,
  "nonCompliantContexts": 1,
  "contexts": [
    {
      "context": "user-pii",
      "algorithm": "AES-256-GCM",
      "fipsCompliant": true
    },
    {
      "context": "session-tokens",
      "algorithm": "ChaCha20-Poly1305",
      "fipsCompliant": false,
      "recommendation": "Switch to AES-256-GCM for FIPS compliance"
    }
  ]
}
```

---

## FIPS Mode

| Mode | Description |
|------|-------------|
| `disabled` | No FIPS restrictions (default) |
| `preferred` | Prefer FIPS algorithms, warn on non-FIPS |
| `enabled` | Block non-FIPS algorithms |

## FIPS-Approved Algorithms

### Symmetric Encryption
- AES-128-GCM, AES-256-GCM
- AES-128-CBC, AES-256-CBC
- AES-128-CTR, AES-256-CTR

### Hash Functions
- SHA-256, SHA-384, SHA-512
- SHA3-256, SHA3-384, SHA3-512

### Post-Quantum (FIPS 203/204)
- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA-44, ML-DSA-65, ML-DSA-87

### NOT FIPS-Approved
- ChaCha20-Poly1305
- BLAKE2b
- Argon2

## Policy Enforcement

When algorithm policy is updated:

1. **Existing data** - Can still be decrypted with deprecated algorithms
2. **New encryptions** - Must use allowed algorithms
3. **Warnings** - Logged when deprecated algorithms are used for decryption
4. **Blocking** - Non-allowed algorithms blocked for new operations

## Best Practices

1. **Start Permissive** - Begin with `fipsMode: disabled`, audit usage
2. **Identify Non-Compliant** - Use FIPS status endpoint to find issues
3. **Migrate Gradually** - Move contexts to compliant algorithms
4. **Enable FIPS** - Switch to `enabled` once all contexts are compliant
