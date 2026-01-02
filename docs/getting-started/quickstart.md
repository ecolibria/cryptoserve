# Quick Start

Get up and running with CryptoServe in 5 minutes.

## Prerequisites

- CryptoServe server running (see [Installation](installation.md))
- GitHub account for authentication

---

## Step 1: Sign In

Open the dashboard at [http://localhost:3001](http://localhost:3001) and click **Sign in with GitHub**.

!!! note "Dashboard Login"
    The login page displays OAuth providers configured for your instance. Click your preferred provider to authenticate. After authorizing, you'll be redirected to the main dashboard.

After authorizing, you'll see the dashboard with your identities and recent activity.

---

## Step 2: Create an Identity

Identities represent applications or services that use CryptoServe.

1. Click **Create New Identity**
2. Fill in the details:

| Field | Example | Description |
|-------|---------|-------------|
| Name | `backend-api` | Unique identifier |
| Team | `platform` | Your team or department |
| Environment | `development` | dev, staging, production |
| Contexts | `user-pii`, `session-tokens` | What data can be encrypted |

3. Click **Create Identity**

---

## Step 3: Download the SDK

After creating an identity, you'll see an install command:

```bash
pip install http://localhost:8001/sdk/download/YOUR_TOKEN/python
```

!!! tip "Token Security"
    The download token is single-use and expires after download. Your identity credentials are embedded in the SDK package itself.

Run the command to install your personalized SDK:

```bash
pip install http://localhost:8001/sdk/download/eyJhbGc.../python
```

---

## Step 4: Encrypt Your First Data

Create a Python file and try encryption:

```python title="test_crypto.py"
from cryptoserve import crypto

# Encrypt a string
secret = "My sensitive data: SSN 123-45-6789"
encrypted = crypto.encrypt_string(secret, context="user-pii")

print(f"Encrypted: {encrypted[:50]}...")

# Decrypt it back
decrypted = crypto.decrypt_string(encrypted)
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
Encrypted: AQAAAFd7InYiOjMsImN0eCI6InVzZXItcGlpIiwia2lkI...
Decrypted: My sensitive data: SSN 123-45-6789
Success! Data encrypted and decrypted correctly.
```

---

## Step 5: Try Binary Data

CryptoServe handles binary data too:

```python title="test_binary.py"
from cryptoserve import crypto

# Encrypt binary data (e.g., a file)
with open("document.pdf", "rb") as f:
    original = f.read()

encrypted = crypto.encrypt(original, context="user-pii")

# Decrypt
decrypted = crypto.decrypt(encrypted)

assert decrypted == original
print(f"Encrypted {len(original)} bytes successfully")
```

---

## Step 6: View Audit Logs

Every operation is logged. Check the dashboard's **Audit Logs** section:

| Timestamp | Operation | Context | Status |
|-----------|-----------|---------|--------|
| 2024-01-15 10:30:45 | encrypt | user-pii | Success |
| 2024-01-15 10:30:46 | decrypt | user-pii | Success |

Or query via API:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/audit
```

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
from cryptoserve import crypto

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
decrypted = json.loads(crypto.decrypt_string(encrypted))
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
    associated_data=b"user_id:12345"
)
```

### Error Handling

```python
from cryptoserve import crypto
from cryptoserve.exceptions import (
    DecryptionError,
    AuthorizationError,
    ContextNotFoundError
)

try:
    decrypted = crypto.decrypt_string(ciphertext)
except DecryptionError as e:
    print(f"Decryption failed: {e}")
except AuthorizationError as e:
    print(f"Not authorized for this context: {e}")
except ContextNotFoundError as e:
    print(f"Context doesn't exist: {e}")
```

---

## Next Steps

<div class="grid cards" markdown>

-   :material-book-open:{ .lg .middle } **Learn the Concepts**

    ---

    Understand the architecture and context model

    [:octicons-arrow-right-24: Concepts](../concepts/index.md)

-   :material-api:{ .lg .middle } **API Reference**

    ---

    Complete API documentation

    [:octicons-arrow-right-24: API Reference](../api-reference/index.md)

-   :material-shield-lock:{ .lg .middle } **Security**

    ---

    Read the security whitepaper

    [:octicons-arrow-right-24: Security](../security/whitepaper.md)

-   :material-rocket-launch:{ .lg .middle } **Production**

    ---

    Deploy to production

    [:octicons-arrow-right-24: Production Guide](../guides/production.md)

</div>
