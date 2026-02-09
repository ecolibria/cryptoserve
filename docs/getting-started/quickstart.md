# Quick Start

Get up and running with CryptoServe in 5 minutes.

## Prerequisites

- CryptoServe server running (see [Installation](installation.md))
- GitHub account for authentication
- Python 3.9+

---

## Step 1: Install the SDK

```bash
pip install cryptoserve
```

---

## Step 2: Login (One-Time Setup)

Authenticate your machine with CryptoServe:

```bash
cryptoserve login
```

This opens your browser for GitHub OAuth. After authorizing, your credentials are stored locally in `~/.cryptoserve/`.

> **Tip:** You only need to run `cryptoserve login` once per machine. All your applications will use these credentials for auto-registration.

---

## Step 3: Encrypt Your First Data

Create a Python file and try the SDK:

```python
# test_crypto.py
from cryptoserve import CryptoServe

# Initialize - auto-registers your app on first use
crypto = CryptoServe(
    app_name="my-first-app",
    team="engineering",
    environment="development"
)

# Encrypt data
secret = b"My sensitive data: SSN 123-45-6789"
encrypted = crypto.encrypt(secret, context="user-pii")
print(f"Encrypted: {encrypted[:50]}...")

# Decrypt it back
decrypted = crypto.decrypt(encrypted, context="user-pii")
print(f"Decrypted: {decrypted}")

# Verify it matches
assert decrypted == secret
print("Success! Data encrypted and decrypted correctly.")
```

Run it:

```bash
python test_crypto.py
```

Expected output:

```
[CryptoServe] Registered new app: my-first-app (development)
Encrypted: b'\x01\x00\x00\x00W{"v":3,"ctx":"user-pii"...
Decrypted: b'My sensitive data: SSN 123-45-6789'
Success! Data encrypted and decrypted correctly.
```

---

## Step 4: Try More Operations

```python
# crypto_operations.py
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-first-app")

# Sign and verify
document = b"Important contract document"
signature = crypto.sign(document, key_id="contract-signing")
is_valid = crypto.verify_signature(document, signature, key_id="contract-signing")
print(f"Signature valid: {is_valid}")

# Compute hash
hash_hex = crypto.hash(b"data to hash", algorithm="sha256")
print(f"SHA-256: {hash_hex}")

# Health check
if crypto.health_check():
    print("SDK connected successfully!")
```

---

## Step 5: Try File Encryption

CryptoServe handles binary data like files:

```python
# encrypt_file.py
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-first-app")

# Encrypt a file
with open("document.pdf", "rb") as f:
    original = f.read()

encrypted = crypto.encrypt(original, context="user-pii")

# Save encrypted file
with open("document.pdf.enc", "wb") as f:
    f.write(encrypted)

# Decrypt
decrypted = crypto.decrypt(encrypted, context="user-pii")
assert decrypted == original
print(f"Encrypted {len(original)} bytes successfully")
```

---

## Step 6: View in Community Dashboard

Open the dashboard (default: `http://localhost:3003`) to see:

- **Your Applications** — View auto-registered apps
- **Usage Analytics** — Monitor encryption/decryption operations
- **Contexts** — See which contexts you're using
- **Audit Logs** — Complete audit trail of all operations

| Timestamp | Operation | Context | App | Status |
|-----------|-----------|---------|-----|--------|
| 2026-01-02 10:30:45 | encrypt | user-pii | my-first-app | Success |
| 2026-01-02 10:30:46 | decrypt | user-pii | my-first-app | Success |

---

## What's in the Ciphertext?

CryptoServe uses a self-describing format:

```python
import json
import base64

# The ciphertext contains metadata
header_len = int.from_bytes(base64.b64decode(encrypted)[:2], 'big')
header = json.loads(base64.b64decode(encrypted)[2:2+header_len])

print(json.dumps(header, indent=2))
```

```json
{
  "v": 3,
  "ctx": "user-pii",
  "kid": "key_user-pii_v1_abc123",
  "alg": "AES-256-GCM",
  "mode": "gcm",
  "nonce": "base64...",
  "kc": "base64..."
}
```

This means:

- **v**: Format version (enables future upgrades)
- **ctx**: Context used for encryption
- **kid**: Key identifier (for rotation)
- **alg/mode**: Algorithm used
- **nonce**: Random nonce (prevents replay)
- **kc**: Key commitment (prevents multi-key attacks)

---

## Common Patterns

### Encrypt JSON

```python
import json
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

user_data = {
    "name": "John Doe",
    "ssn": "123-45-6789",
    "email": "john@example.com"
}

# Encrypt the entire object
encrypted = crypto.encrypt_string(
    json.dumps(user_data),
    context="user-pii"
)

# Store encrypted in database
# ...

# Later, decrypt and parse
decrypted = json.loads(crypto.decrypt_string(encrypted, context="user-pii"))
```

### Encrypt with Associated Data

```python
# Associated data is authenticated but not encrypted
# Use for metadata that must match on decryption

encrypted = crypto.encrypt_string(
    "sensitive data",
    context="user-pii",
    associated_data=b"user_id:12345"
)

# Decryption will fail if associated_data doesn't match
decrypted = crypto.decrypt_string(
    encrypted,
    context="user-pii",
    associated_data=b"user_id:12345"
)
```

### Error Handling

```python
from cryptoserve import CryptoServe
from cryptoserve import (
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError
)

crypto = CryptoServe(app_name="my-app", team="platform")

try:
    decrypted = crypto.decrypt_string(ciphertext, context="user-pii")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except AuthorizationError as e:
    print(f"Not authorized for this context: {e}")
except ContextNotFoundError as e:
    print(f"Context doesn't exist: {e}")
```

---

## Next Steps

| Resource | Description |
|----------|-------------|
| **[Concepts](../concepts/index.md)** | Understand the architecture and context model |
| **[API Reference](../api-reference/index.md)** | Complete API documentation |
| **[Security](../security/technical-reference.md)** | Read the technical reference |
| **[Production](../guides/production.md)** | Deploy to production |
