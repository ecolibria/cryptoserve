# cryptoserve-core

Pure cryptographic primitives for CryptoServe. Zero network dependencies.

## Installation

```bash
pip install cryptoserve-core
```

## Usage

```python
from cryptoserve_core import AESGCMCipher, ChaCha20Cipher, KeyDerivation

# Generate a key
key = KeyDerivation.generate_key(256)

# AES-256-GCM encryption
cipher = AESGCMCipher(key)
ciphertext, nonce = cipher.encrypt(b"sensitive data")
plaintext = cipher.decrypt(ciphertext, nonce)

# ChaCha20-Poly1305 encryption
cipher = ChaCha20Cipher(key)
ciphertext, nonce = cipher.encrypt(b"sensitive data")
plaintext = cipher.decrypt(ciphertext, nonce)
```

## Supported Algorithms

| Algorithm | Security | Use Case |
|-----------|----------|----------|
| AES-256-GCM | 256-bit | General purpose, hardware accelerated |
| ChaCha20-Poly1305 | 256-bit | Mobile, real-time applications |

## Why cryptoserve-core?

- **Zero network dependencies** - Works entirely offline
- **Pure Python + cryptography** - No custom C extensions
- **Auditable** - Small, focused codebase
- **Standards compliant** - NIST-approved algorithms

## License

Apache 2.0
