# CryptoServe SDK

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

## Performance Features

CryptoServe SDK includes built-in performance optimizations:

### Local Key Caching

Keys are cached locally to reduce network round-trips:

- **First operation**: ~5-50ms (fetches key from server)
- **Subsequent operations**: ~0.1-0.5ms (local crypto with cached key)

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

# First call fetches key from server
encrypted = crypto.encrypt(b"data", context="user-pii")  # ~10ms

# Subsequent calls use cached key
encrypted = crypto.encrypt(b"more data", context="user-pii")  # ~0.2ms
```

### Cache Statistics

Monitor cache performance:

```python
stats = crypto.cache_stats()
print(f"Hit rate: {stats['hit_rate']:.1%}")
print(f"Cached contexts: {stats['contexts']}")
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
python -m cryptoserve wizard

# Verify SDK health
python -m cryptoserve verify

# Show identity info
python -m cryptoserve info
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
