# CryptoServe SDK

![Security Audit](https://github.com/ecolibria/crypto-serve/actions/workflows/security.yml/badge.svg)

Zero-config cryptographic operations with managed keys and auto-registration.

## Installation

```bash
pip install cryptoserve
```

## Quick Start (Recommended)

```bash
# One-time login (stores credentials locally)
cryptoserve login
```

```python
from cryptoserve import CryptoServe

# Initialize - auto-registers your app on first use
crypto = CryptoServe(
    app_name="my-service",
    team="platform",
    environment="development"
)

# Encrypt/Decrypt
encrypted = crypto.encrypt(b"sensitive data", context="user-pii")
decrypted = crypto.decrypt(encrypted, context="user-pii")

# Sign/Verify
signature = crypto.sign(b"document", key_id="signing-key")
is_valid = crypto.verify_signature(b"document", signature, key_id="signing-key")

# Hash and MAC
hash_hex = crypto.hash(b"data", algorithm="sha256")
mac_hex = crypto.mac(b"message", key=secret_key, algorithm="hmac-sha256")
```

## Local Mode (No Server)

Run the full SDK API without a server. All operations happen locally using a password or master key.

```python
from cryptoserve import CryptoServe

# Initialize with a password (deterministic key derivation)
crypto = CryptoServe.local(password="my-secret-password")

# Same API as server mode
encrypted = crypto.encrypt(b"sensitive data", context="user-pii")
decrypted = crypto.decrypt(encrypted, context="user-pii")

# String helpers
encoded = crypto.encrypt_string("PII data", context="user-pii")
text = crypto.decrypt_string(encoded, context="user-pii")

# JSON
crypto.encrypt_json({"email": "user@example.com"}, context="user-pii")

# Hash and MAC work locally too
hash_hex = crypto.hash(b"data")
```

Two instances with the same password can decrypt each other's data. Different contexts derive different keys, providing isolation.

## CryptoServe Class

The `CryptoServe` class provides:

| Method | Description |
|--------|-------------|
| `encrypt(plaintext, context)` | Encrypt binary data |
| `decrypt(ciphertext, context)` | Decrypt binary data |
| `encrypt_string(text, context)` | Encrypt string (returns base64) |
| `decrypt_string(ciphertext, context)` | Decrypt to string |
| `encrypt_json(obj, context)` | Encrypt JSON object |
| `decrypt_json(ciphertext, context)` | Decrypt to JSON |
| `sign(data, key_id)` | Create digital signature |
| `verify_signature(data, signature, key_id)` | Verify signature |
| `hash(data, algorithm)` | Compute cryptographic hash |
| `mac(data, key, algorithm)` | Compute MAC |
| `health_check()` | Verify connection |
| `cache_stats()` | Get cache performance stats |
| `invalidate_cache(context)` | Clear cached keys |
| `local(password=..., master_key=...)` | Create local-mode instance (class method) |
| `migrate_from_easy(ciphertext, password, target, context)` | Migrate easy-blob data (static method) |

## Performance Features

CryptoServe SDK includes built-in performance optimizations:

### Local Key Caching

Keys are cached locally to reduce network round-trips:

| Metric | Value |
|--------|-------|
| Server round-trip | ~90ms |
| Cached operation | ~0.3ms avg |
| Min latency | 0.009ms |
| **Speedup** | **~250x** |
| Cache hit rate | 90%+ (after warmup) |

```python
from cryptoserve import CryptoServe

# Enable caching (default: enabled)
crypto = CryptoServe(
    app_name="my-service",
    team="platform",
    enable_cache=True,   # Default: True
    cache_ttl=300.0,     # 5 minutes (default)
    cache_size=100,      # Max cached keys (default)
)

# First call fetches key from server and caches it
encrypted = crypto.encrypt(b"data", context="user-pii")  # ~90ms

# Subsequent calls use cached key (local AES-256-GCM)
encrypted = crypto.encrypt(b"more data", context="user-pii")  # ~0.3ms
```

### Cache Statistics

Monitor cache performance:

```python
stats = crypto.cache_stats()
print(f"Hit rate: {stats['hit_rate']:.1%}")
print(f"Hits: {stats['hits']}, Misses: {stats['misses']}")
print(f"Cache size: {stats['size']}")
```

### Cache Invalidation

Invalidate cached keys (e.g., after key rotation):

```python
# Invalidate specific context
crypto.invalidate_cache("user-pii")

# Invalidate all cached keys
crypto.invalidate_cache()
```

## Health Check

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-service")

if crypto.health_check():
    print("Connected!")
else:
    print("Connection failed")
```

## FastAPI Integration

```python
from cryptoserve import CryptoServe
from cryptoserve.fastapi import configure, EncryptedStr
from pydantic import BaseModel

# Configure once at startup
crypto = CryptoServe(app_name="my-api", team="platform")
configure(crypto)

class User(BaseModel):
    name: str
    email: EncryptedStr["user-pii"]  # Automatically encrypted
```

## SQLAlchemy Integration

```python
from cryptoserve import CryptoServe
from cryptoserve.fastapi import configure, EncryptedString
from sqlalchemy import Column, Integer

# Configure once at startup
crypto = CryptoServe(app_name="my-api", team="platform")
configure(crypto)

class User(Base):
    id = Column(Integer, primary_key=True)
    email = Column(EncryptedString(context="user-pii"))
```

## Auto-Protect (Third-Party Libraries)

```python
from cryptoserve import auto_protect

auto_protect(encryption_key=key)

# Now all outbound requests are automatically protected
import requests
requests.post(url, json={"email": "user@example.com"})  # Auto-encrypted
```

## CLI

```bash
# Interactive context wizard
cryptoserve wizard

# Verify SDK health
cryptoserve verify

# Show identity info
cryptoserve info

# List encryption contexts
cryptoserve contexts
```

### Offline Tools (No Server Required)

```bash
# Encrypt/decrypt strings
cryptoserve encrypt "sensitive data" --password my-secret
cryptoserve decrypt "<base64>" --password my-secret

# Encrypt/decrypt files
cryptoserve encrypt --file report.pdf --output report.enc --password my-secret
cryptoserve decrypt --file report.enc --output report.pdf --password my-secret

# Hash a password (prompts for input if no argument)
cryptoserve hash-password
cryptoserve hash-password "my-password" --algo pbkdf2

# Create a JWT token
cryptoserve token --key my-secret-key-1234 --payload '{"sub":"user-1"}' --expires 3600
```

## Package Architecture

CryptoServe uses a modular architecture for flexibility:

| Package | Purpose | Install |
|---------|---------|---------|
| `cryptoserve` | Full SDK with managed keys | `pip install cryptoserve` |
| `cryptoserve-core` | Pure crypto primitives | `pip install cryptoserve-core` |
| `cryptoserve-client` | API client only | `pip install cryptoserve-client` |
| `cryptoserve-auto` | Auto-protect libraries | `pip install cryptoserve-auto` |

**Use cases:**
- **Most users**: Install `cryptoserve` for the full experience
- **Bring your own keys**: Install `cryptoserve-core` only
- **Custom integration**: Install `cryptoserve-client` for API access
- **Dependency protection**: Add `cryptoserve-auto` for automatic protection

## Error Handling

```python
from cryptoserve import (
    CryptoServe,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
)

crypto = CryptoServe(app_name="my-app", team="platform")

try:
    ciphertext = crypto.encrypt(data, context="user-pii")
except AuthenticationError:
    # Token expired or invalid
    pass
except AuthorizationError:
    # Not allowed to use this context
    pass
except ContextNotFoundError:
    # Context doesn't exist
    pass
```

## License

Apache 2.0
