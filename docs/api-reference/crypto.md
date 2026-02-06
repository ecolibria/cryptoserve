# Crypto Operations API

Core cryptographic operations: encryption, decryption, signing, and verification.

## Encrypt

Encrypt data using a specified context.

```
POST /v1/crypto/encrypt
```

### Request

```json
{
  "plaintext": "base64-encoded-data",
  "context": "user-pii",
  "associated_data": "base64-encoded-aad",  // optional
  "algorithm": "AES-256-GCM"  // optional, uses context default
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `plaintext` | string | Yes | Base64-encoded data to encrypt |
| `context` | string | Yes | Encryption context name |
| `associated_data` | string | No | Base64-encoded AAD (authenticated but not encrypted) |
| `algorithm` | string | No | Override context's default algorithm |

### Response

```json
{
  "ciphertext": "AQAAAFd7InYiOjMsImN0eCI6...",
  "algorithm": "AES-256-GCM",
  "key_id": "key_user-pii_v1_abc123",
  "warnings": []
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | string | Base64-encoded ciphertext |
| `algorithm` | string | Algorithm used |
| `key_id` | string | Key identifier (for audit) |
| `warnings` | array | Policy warnings (if any) |

### Example

=== "cURL"

    ```bash
    curl -X POST http://localhost:8003/v1/crypto/encrypt \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "plaintext": "SGVsbG8gV29ybGQh",
        "context": "user-pii"
      }'
    ```

=== "Python"

    ```python
    import requests
    import base64

    response = requests.post(
        "http://localhost:8003/v1/crypto/encrypt",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "plaintext": base64.b64encode(b"Hello World!").decode(),
            "context": "user-pii"
        }
    )
    ciphertext = response.json()["ciphertext"]
    ```

### Errors

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_plaintext` | Plaintext is not valid base64 |
| 403 | `context_not_authorized` | Identity cannot access this context |
| 404 | `context_not_found` | Context does not exist |
| 403 | `policy_violation` | Operation blocked by policy |

---

## Decrypt

Decrypt previously encrypted data.

```
POST /v1/crypto/decrypt
```

### Request

```json
{
  "ciphertext": "AQAAAFd7InYiOjMsImN0eCI6...",
  "context": "user-pii",  // optional, extracted from ciphertext
  "associated_data": "base64-encoded-aad"  // optional, must match encryption
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ciphertext` | string | Yes | Base64-encoded ciphertext from encrypt |
| `context` | string | No | Context name (verified against ciphertext) |
| `associated_data` | string | No | Must match AAD used during encryption |

### Response

```json
{
  "plaintext": "SGVsbG8gV29ybGQh",
  "context": "user-pii",
  "algorithm": "AES-256-GCM",
  "key_id": "key_user-pii_v1_abc123"
}
```

### Example

=== "cURL"

    ```bash
    curl -X POST http://localhost:8003/v1/crypto/decrypt \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "ciphertext": "AQAAAFd7InYiOjMsImN0eCI6..."
      }'
    ```

=== "Python"

    ```python
    response = requests.post(
        "http://localhost:8003/v1/crypto/decrypt",
        headers={"Authorization": f"Bearer {token}"},
        json={"ciphertext": ciphertext}
    )
    plaintext = base64.b64decode(response.json()["plaintext"])
    ```

### Errors

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_ciphertext` | Ciphertext is malformed |
| 400 | `decryption_failed` | Authentication tag verification failed |
| 400 | `context_mismatch` | Provided context doesn't match ciphertext |
| 403 | `context_not_authorized` | Identity cannot access this context |
| 404 | `key_not_found` | Key version no longer available |

---

## Encrypt String

Convenience endpoint for string data.

```
POST /v1/crypto/encrypt-string
```

### Request

```json
{
  "plaintext": "Hello World!",
  "context": "user-pii"
}
```

### Response

```json
{
  "ciphertext": "AQAAAFd7InYiOjMsImN0eCI6...",
  "algorithm": "AES-256-GCM"
}
```

---

## Decrypt String

Convenience endpoint returning string data.

```
POST /v1/crypto/decrypt-string
```

### Request

```json
{
  "ciphertext": "AQAAAFd7InYiOjMsImN0eCI6..."
}
```

### Response

```json
{
  "plaintext": "Hello World!",
  "context": "user-pii"
}
```

---

## Batch Encrypt

Encrypt multiple items in a single request.

```
POST /v1/crypto/batch/encrypt
```

### Request

```json
{
  "items": [
    {"plaintext": "SGVsbG8=", "context": "user-pii"},
    {"plaintext": "V29ybGQ=", "context": "user-pii"}
  ]
}
```

### Response

```json
{
  "results": [
    {"ciphertext": "...", "success": true},
    {"ciphertext": "...", "success": true}
  ],
  "success_count": 2,
  "error_count": 0
}
```

---

## Sign

Create a digital signature.

```
POST /v1/crypto/sign
```

### Request

```json
{
  "message": "base64-encoded-message",
  "context": "signing-context",
  "algorithm": "Ed25519"  // or ML-DSA-65
}
```

### Response

```json
{
  "signature": "base64-encoded-signature",
  "algorithm": "Ed25519",
  "key_id": "sign_key_abc123"
}
```

---

## Verify

Verify a digital signature.

```
POST /v1/crypto/verify
```

### Request

```json
{
  "message": "base64-encoded-message",
  "signature": "base64-encoded-signature",
  "context": "signing-context"
}
```

### Response

```json
{
  "valid": true,
  "algorithm": "Ed25519",
  "key_id": "sign_key_abc123"
}
```

---

## Algorithms

Get available encryption algorithms.

```
GET /v1/crypto/algorithms
```

### Response

```json
{
  "symmetric": [
    {
      "name": "AES-256-GCM",
      "key_bits": 256,
      "nonce_bits": 96,
      "tag_bits": 128,
      "fips_approved": true
    },
    {
      "name": "ChaCha20-Poly1305",
      "key_bits": 256,
      "nonce_bits": 96,
      "tag_bits": 128,
      "fips_approved": false
    }
  ],
  "hybrid": [
    {
      "name": "AES-256-GCM+ML-KEM-768",
      "classical": "AES-256-GCM",
      "pqc": "ML-KEM-768",
      "quantum_resistant": true
    }
  ],
  "signing": [
    {
      "name": "Ed25519",
      "key_bits": 256,
      "signature_bits": 512,
      "fips_approved": true
    },
    {
      "name": "ML-DSA-65",
      "key_bits": 1952,
      "signature_bits": 26472,
      "quantum_resistant": true
    }
  ]
}
```

---

## Health Check

Check crypto subsystem health.

```
GET /v1/crypto/health
```

### Response

```json
{
  "status": "healthy",
  "components": {
    "aes": "ok",
    "hkdf": "ok",
    "pqc": "ok"
  },
  "fips_mode": "disabled"
}
```
