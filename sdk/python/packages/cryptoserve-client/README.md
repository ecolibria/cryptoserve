# cryptoserve-client

API client for communicating with CryptoServe server.

## Installation

```bash
pip install cryptoserve-client
```

## Usage

```python
from cryptoserve_client import CryptoClient

# Initialize client
client = CryptoClient(
    server_url="https://api.cryptoserve.dev",
    token="your-identity-token",
)

# Encrypt data
ciphertext = client.encrypt(b"sensitive data", context="user-pii")

# Decrypt data
plaintext = client.decrypt(ciphertext, context="user-pii")

# Check health
info = client.get_identity_info()
print(f"Identity: {info['name']}")
print(f"Contexts: {info['allowed_contexts']}")
```

## Async Support

```bash
pip install cryptoserve-client[async]
```

```python
from cryptoserve_client import AsyncCryptoClient

async def main():
    async with AsyncCryptoClient(server_url, token) as client:
        ciphertext = await client.encrypt(b"data", context="user-pii")
```

## Error Handling

```python
from cryptoserve_client import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
)

try:
    client.encrypt(data, context="unknown")
except AuthorizationError:
    print("Not authorized for this context")
except ContextNotFoundError:
    print("Context doesn't exist")
```

## License

Apache 2.0
