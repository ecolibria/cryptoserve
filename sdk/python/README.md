# CryptoServe SDK

Zero-config cryptographic operations with managed keys.

## Installation

```bash
# Full SDK (recommended)
pip install cryptoserve

# With framework integrations
pip install cryptoserve[fastapi]
pip install cryptoserve[sqlalchemy]
pip install cryptoserve[all]

# With auto-protect for third-party libraries
pip install cryptoserve[auto]
```

## Quick Start

```python
from cryptoserve import crypto

# Encrypt data
ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

# Decrypt data
plaintext = crypto.decrypt(ciphertext, context="user-pii")

# String helpers
encrypted = crypto.encrypt_string("my secret", context="user-pii")
decrypted = crypto.decrypt_string(encrypted, context="user-pii")
```

## Verify SDK

```python
from cryptoserve import crypto

result = crypto.verify()
if result:
    print(f"SDK healthy! Identity: {result.identity_name}")
else:
    print(f"Error: {result.error}")
```

## Mock Mode (Development)

```python
from cryptoserve import crypto

crypto.enable_mock_mode()

# Now works without a server
encrypted = crypto.encrypt(b"test", context="any-context")
```

## FastAPI Integration

```python
from pydantic import BaseModel
from cryptoserve.fastapi import EncryptedStr

class User(BaseModel):
    name: str
    email: EncryptedStr["user-pii"]  # Automatically encrypted
```

## SQLAlchemy Integration

```python
from sqlalchemy import Column, Integer
from cryptoserve.fastapi import EncryptedString

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
    crypto,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
)

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
