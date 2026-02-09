# Python SDK

The official Python SDK for CryptoServe with zero-configuration setup.

## Installation

```bash
pip install cryptoserve
```

Individual packages are also available:

```bash
pip install cryptoserve-core    # Pure crypto primitives only
pip install cryptoserve-client  # API client only
pip install cryptoserve-auto    # Auto-protect third-party libraries
```

After installing, run a one-time login:

```bash
cryptoserve login
```

## Requirements

- Python 3.9+
- `requests`, `cryptography`, `pyyaml` (installed automatically)

---

## Quick Start

The `CryptoServe` class provides auto-registration - your app is automatically registered on first use:

```python
from cryptoserve import CryptoServe

# One-time login (run once per machine)
# $ cryptoserve login

# Initialize - app auto-registers if needed
crypto = CryptoServe(
    app_name="my-service",
    team="platform",
    environment="development"
)

# Encrypt/Decrypt
encrypted = crypto.encrypt(b"Hello World!", context="user-pii")
decrypted = crypto.decrypt(encrypted, context="user-pii")

# Sign/Verify
signature = crypto.sign(b"document", key_id="signing-key")
is_valid = crypto.verify_signature(b"document", signature, key_id="signing-key")

# Hash and MAC
hash_hex = crypto.hash(b"data", algorithm="sha256")
mac_hex = crypto.mac(b"message", key=secret_key)

print(decrypted)  # b"Hello World!"
```

---

## CryptoServe Class Reference

### Initialization

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(
    app_name="my-service",      # Required: unique app identifier
    team="platform",            # Optional: team/department (default: "default")
    environment="production",   # Optional: environment (default: "development")
    contexts=["user-pii"],      # Optional: encryption contexts to request
    description="Backend API",  # Optional: app description
    auto_register=True          # Optional: auto-register on init (default: True)
)
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `app_id` | `str` | The registered application ID |
| `client` | `CryptoClient` | Underlying API client |

---

## Local Mode (No Server Required)

Local mode runs entirely offline — no server, no API keys, no network calls. Keys are derived from a master password using PBKDF2 (600K iterations) and per-context keys via HKDF-SHA256.

```python
from cryptoserve import CryptoServe

# Initialize with a password
crypto = CryptoServe.local(password="my-secret")

# Or with an explicit 256-bit master key
import os
crypto = CryptoServe.local(master_key=os.urandom(32))

# Encrypt/Decrypt with context-derived keys
ct = crypto.encrypt(b"sensitive data", context="user-pii")
pt = crypto.decrypt(ct, context="user-pii")

# String and JSON helpers
enc = crypto.encrypt_string("hello", context="default")
crypto.decrypt_string(enc, context="default")  # "hello"

obj = crypto.encrypt_json({"ssn": "123-45-6789"}, context="pii")
crypto.decrypt_json(obj, context="pii")

# Hash and MAC
crypto.hash(b"data")  # SHA-256 hex
crypto.hash(b"data", algorithm="sha512")  # SHA-512 hex
crypto.mac(b"message", key=b"secret-key", algorithm="hmac-sha256")
```

### Local Mode Limitations

- **No signing**: `sign()` and `verify_signature()` require server-managed keys
- **No key rotation**: Keys are deterministic from the password
- **No audit logging**: Operations are not logged

### Migrating from Easy API to Local Mode

```python
import cryptoserve_core as core
from cryptoserve import CryptoServe

# Decrypt existing easy blob
easy_blob = core.encrypt(b"data", "old-password")

# Migrate to local mode
local = CryptoServe.local(password="new-master")
migrated = CryptoServe.migrate_from_easy(
    easy_blob, password="old-password",
    target=local, context="migrated"
)
local.decrypt(migrated, context="migrated")  # b"data"
```

---

## CLI Tools

The SDK provides offline CLI commands. No server required.

```bash
# Encrypt a string (outputs base64)
cryptoserve encrypt "secret message" --password my-pw

# Decrypt
cryptoserve decrypt "base64-ciphertext" --password my-pw

# Encrypt/decrypt files
cryptoserve encrypt --file input.txt --output encrypted.bin --password my-pw
cryptoserve decrypt --file encrypted.bin --output output.txt --password my-pw

# Hash a password (prompts for input)
cryptoserve hash-password
cryptoserve hash-password "my-password" --algo pbkdf2

# Create a JWT token
cryptoserve token --key my-secret-key --payload '{"sub": "user-1"}' --expires 3600
```

Run `cryptoserve help` to see all available commands.

---

## Cryptographic Operations

### `encrypt(plaintext, context, usage=None)`

Encrypt binary data. Optionally pass a `usage` hint to let the platform select the optimal algorithm.

```python
encrypted = crypto.encrypt(b"sensitive data", context="user-pii")

# With usage hint for automatic algorithm selection
from cryptoserve import Usage
encrypted = crypto.encrypt(b"sensitive data", context="user-pii", usage=Usage.AT_REST)
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `plaintext` | `bytes` | Yes | Data to encrypt |
| `context` | `str` | Yes | Encryption context name |
| `associated_data` | `bytes` | No | Authenticated but unencrypted data |
| `usage` | `Usage \| str` | No | Runtime usage hint: `at_rest`, `in_transit`, `in_use`, `streaming`, `disk` |

**Returns:** `bytes` - Ciphertext

### `decrypt(ciphertext, context)`

Decrypt binary data.

```python
decrypted = crypto.decrypt(encrypted, context="user-pii")
```

**Returns:** `bytes` - Plaintext

### `sign(data, key_id)`

Create a digital signature.

```python
signature = crypto.sign(b"document to sign", key_id="my-signing-key")
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `data` | `bytes` | Yes | Data to sign |
| `key_id` | `str` | Yes | Signing key identifier |

**Returns:** `bytes` - Signature

### `verify_signature(data, signature, key_id, public_key)`

Verify a digital signature.

```python
is_valid = crypto.verify_signature(
    b"document",
    signature,
    key_id="my-signing-key"  # OR public_key="-----BEGIN PUBLIC KEY-----..."
)
```

**Returns:** `bool` - True if valid

### `hash(data, algorithm)`

Compute a cryptographic hash.

```python
hash_hex = crypto.hash(b"data to hash", algorithm="sha256")
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `data` | `bytes` | Yes | Data to hash |
| `algorithm` | `str` | No | Hash algorithm (default: "sha256") |

**Supported algorithms:** `sha256`, `sha384`, `sha512`, `sha3-256`, `blake2b`

**Returns:** `str` - Hash as hex string

### `mac(data, key, algorithm)`

Compute a Message Authentication Code.

```python
mac_hex = crypto.mac(b"message", key=secret_key, algorithm="hmac-sha256")
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `data` | `bytes` | Yes | Data to authenticate |
| `key` | `bytes` | Yes | Secret key |
| `algorithm` | `str` | No | MAC algorithm (default: "hmac-sha256") |

**Returns:** `str` - MAC as hex string

### `health_check()`

Verify the SDK connection is working.

```python
if crypto.health_check():
    print("Connected!")
```

**Returns:** `bool` - True if connection successful

---

## API Reference

### Encryption

#### `encrypt(data, context, **kwargs)`

Encrypt binary data.

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt bytes
data = b"binary data here"
encrypted = crypto.encrypt(data, context="user-pii")

# With associated data
encrypted = crypto.encrypt(
    data,
    context="user-pii",
    associated_data=b"metadata"
)
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `data` | bytes | Yes | Data to encrypt |
| `context` | str | Yes | Encryption context name |
| `associated_data` | bytes | No | Authenticated but not encrypted |
| `algorithm` | str | No | Override default algorithm |

**Returns:** `bytes` - Ciphertext

#### `encrypt_string(text, context, **kwargs)`

Encrypt a string (UTF-8 encoded).

```python
# Using the crypto instance from above
encrypted = crypto.encrypt_string("sensitive text", context="user-pii")
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `text` | str | Yes | String to encrypt |
| `context` | str | Yes | Encryption context name |

**Returns:** `str` - Base64-encoded ciphertext

#### `encrypt_json(obj, context, **kwargs)`

Encrypt a JSON-serializable object.

```python
# Using the crypto instance from above
user = {"name": "John", "ssn": "123-45-6789"}
encrypted = crypto.encrypt_json(user, context="user-pii")
```

**Returns:** `str` - Base64-encoded ciphertext

---

### Decryption

#### `decrypt(ciphertext, context, **kwargs)`

Decrypt binary data.

```python
plaintext = crypto.decrypt(encrypted_bytes, context="user-pii")

# With associated data
plaintext = crypto.decrypt(
    encrypted_bytes,
    context="user-pii",
    associated_data=b"metadata"  # Must match encryption
)
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `ciphertext` | bytes | Yes | Ciphertext to decrypt |
| `context` | str | Yes | Encryption context name |
| `associated_data` | bytes | No | Must match encryption AAD |

**Returns:** `bytes` - Plaintext

#### `decrypt_string(ciphertext, context, **kwargs)`

Decrypt to a string.

```python
text = crypto.decrypt_string(encrypted_string, context="user-pii")
```

**Returns:** `str` - Decrypted string

#### `decrypt_json(ciphertext, context, **kwargs)`

Decrypt to a JSON object.

```python
user = crypto.decrypt_json(encrypted_string, context="user-pii")
print(user["name"])  # "John"
```

**Returns:** `dict | list` - Parsed JSON

---

### Signing

#### `sign(message, context, **kwargs)`

Create a digital signature.

```python
signature = crypto.sign(b"message to sign", context="signing-context")
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `message` | bytes | Yes | Message to sign |
| `context` | str | Yes | Signing context |
| `algorithm` | str | No | `Ed25519` or `ML-DSA-65` |

**Returns:** `bytes` - Signature

#### `verify(message, signature, context, **kwargs)`

Verify a digital signature.

```python
is_valid = crypto.verify(message, signature, context="signing-context")
```

**Returns:** `bool` - True if valid

---

### Batch Operations

#### `batch_encrypt(items)`

Encrypt multiple items efficiently.

```python
items = [
    {"data": b"item1", "context": "user-pii"},
    {"data": b"item2", "context": "user-pii"},
]
results = crypto.batch_encrypt(items)

for result in results:
    if result.success:
        print(result.ciphertext)
    else:
        print(f"Error: {result.error}")
```

#### `batch_decrypt(items)`

Decrypt multiple items efficiently.

```python
items = [
    {"ciphertext": ct1},
    {"ciphertext": ct2},
]
results = crypto.batch_decrypt(items)
```

---

### Configuration

#### `configure(**kwargs)`

Configure SDK behavior.

```python
crypto.configure(
    server_url="https://your-server",  # Override server
    timeout=30,           # Request timeout in seconds
    max_retries=3,        # Retry count
    verify_ssl=True,      # SSL verification
    debug=False           # Enable debug logging
)
```

#### `get_identity_info()`

Get information about the current identity.

```python
info = crypto.get_identity_info()
print(info)
# {
#     "identity_id": "id_abc123",
#     "name": "backend-api",
#     "team": "platform",
#     "environment": "production",
#     "contexts": ["user-pii", "session-tokens"]
# }
```

#### `get_contexts()`

List available contexts for this identity.

```python
contexts = crypto.get_contexts()
for ctx in contexts:
    print(f"{ctx.name}: {ctx.algorithm}")
```

---

### Async Support

The SDK provides async versions of all methods:

```python
from cryptoserve import async_crypto

async def main():
    encrypted = await async_crypto.encrypt_string(
        "Hello World!",
        context="user-pii"
    )
    decrypted = await async_crypto.decrypt_string(encrypted)
    print(decrypted)

import asyncio
asyncio.run(main())
```

---

## Error Handling

```python
from cryptoserve import CryptoServe
from cryptoserve import (
    CryptoServeError,      # Base exception
    AuthenticationError,   # Authentication failed
    AuthorizationError,    # Not authorized for context
    ContextNotFoundError,  # Context doesn't exist
    TokenRefreshError      # Token refresh failed
)

crypto = CryptoServe(app_name="my-app", team="platform")

try:
    decrypted = crypto.decrypt_string(ciphertext, context="user-pii")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except AuthorizationError as e:
    print(f"Not authorized: {e}")
except ContextNotFoundError as e:
    print(f"Context not found: {e}")
except CryptoServeError as e:
    print(f"General error: {e}")
```

---

## Type Hints

Full type annotations for IDE support:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

def encrypt_user_data(user: dict) -> str:
    """Encrypt user data and return ciphertext."""
    return crypto.encrypt_json(user, context="user-pii")
```

---

## Examples

### Django Integration

```python
# models.py
from django.db import models
from cryptoserve import CryptoServe

# Initialize once at module level
crypto = CryptoServe(app_name="my-django-app", team="platform")

class User(models.Model):
    email = models.EmailField()
    _ssn_encrypted = models.TextField()

    @property
    def ssn(self):
        return crypto.decrypt_string(self._ssn_encrypted, context="user-pii")

    @ssn.setter
    def ssn(self, value):
        self._ssn_encrypted = crypto.encrypt_string(
            value, context="user-pii"
        )
```

### FastAPI Integration

```python
from fastapi import FastAPI
from cryptoserve import CryptoServe
from cryptoserve.fastapi import configure

app = FastAPI()

# Initialize CryptoServe at startup
crypto = CryptoServe(app_name="my-fastapi-app", team="platform")
configure(crypto)  # Configure FastAPI integration

@app.post("/users")
async def create_user(ssn: str):
    encrypted_ssn = crypto.encrypt_string(ssn, context="user-pii")
    # Store encrypted_ssn in database
    return {"status": "created"}

@app.get("/users/{user_id}/ssn")
async def get_ssn(user_id: str):
    # Fetch encrypted_ssn from database
    return {"ssn": crypto.decrypt_string(encrypted_ssn, context="user-pii")}
```

### SQLAlchemy Integration

```python
from sqlalchemy import Column, String
from sqlalchemy.ext.hybrid import hybrid_property
from cryptoserve import CryptoServe

# Initialize once at module level
crypto = CryptoServe(app_name="my-app", team="platform")

class User(Base):
    __tablename__ = 'users'

    id = Column(String, primary_key=True)
    _ssn = Column("ssn", String)

    @hybrid_property
    def ssn(self):
        if self._ssn:
            return crypto.decrypt_string(self._ssn, context="user-pii")
        return None

    @ssn.setter
    def ssn(self, value):
        if value:
            self._ssn = crypto.encrypt_string(value, context="user-pii")
        else:
            self._ssn = None
```

### File Encryption

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

def encrypt_file(input_path: str, output_path: str, context: str):
    """Encrypt a file."""
    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = crypto.encrypt(plaintext, context=context)

    with open(output_path, "wb") as f:
        f.write(ciphertext)

def decrypt_file(input_path: str, output_path: str, context: str):
    """Decrypt a file."""
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    plaintext = crypto.decrypt(ciphertext, context=context)

    with open(output_path, "wb") as f:
        f.write(plaintext)
```

---

## Testing

### Local Mode (Recommended for Tests)

The simplest way to test without a server is local mode:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe.local(password="test-password")

# Real encryption — no mocks needed
ct = crypto.encrypt(b"test data", context="test")
assert crypto.decrypt(ct, context="test") == b"test data"
```

### Mock Mode

For testing without a server, use environment variables or mock the CryptoServe class:

```python
from unittest.mock import Mock, patch
from cryptoserve import CryptoServe

# Option 1: Mock the entire class
@patch('mymodule.CryptoServe')
def test_encryption(mock_crypto_class):
    mock_instance = Mock()
    mock_crypto_class.return_value = mock_instance
    mock_instance.encrypt_string.return_value = "encrypted"
    mock_instance.decrypt_string.return_value = "decrypted"

    # Your test code here

# Option 2: Use a test server
crypto = CryptoServe(
    app_name="test-app",
    team="test",
    server_url="http://localhost:8003"  # Test server
)
```

### Pytest Fixture

```python
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def mock_crypto():
    with patch('mymodule.CryptoServe') as mock:
        instance = Mock()
        mock.return_value = instance
        instance.encrypt_string.side_effect = lambda x, **kw: f"ENC:{x}"
        instance.decrypt_string.side_effect = lambda x, **kw: x.replace("ENC:", "")
        yield instance

def test_encryption(mock_crypto):
    encrypted = mock_crypto.encrypt_string("test", context="user-pii")
    assert "test" in mock_crypto.decrypt_string(encrypted, context="user-pii")
```
