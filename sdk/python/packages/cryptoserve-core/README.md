# cryptoserve-core

![Security Audit](https://github.com/ecolibria/crypto-serve/actions/workflows/security.yml/badge.svg)

Pure cryptographic primitives for Python. Zero network dependencies, one `pip install`, production-ready defaults.

## Installation

```bash
pip install cryptoserve-core
```

## Quick Start

```python
import cryptoserve_core as crypto

# Encrypt a string with a password
encrypted = crypto.encrypt_string("sensitive data", password="my-secret")
decrypted = crypto.decrypt_string(encrypted, password="my-secret")

# Hash a password (scrypt, PHC format)
hashed = crypto.hash_password("user-password")
assert crypto.verify_password("user-password", hashed)

# Create a JWT token
token = crypto.create_token({"sub": "user-123"}, key=b"my-secret-key-1234567890")
claims = crypto.verify_token(token, key=b"my-secret-key-1234567890")
```

## Easy Encryption

Password-based encryption using PBKDF2 (600K iterations) + AES-256-GCM. Each call generates a fresh random salt and nonce.

```python
from cryptoserve_core import encrypt, decrypt, encrypt_string, decrypt_string

# Bytes
ciphertext = encrypt(b"secret bytes", password="my-password")
plaintext = decrypt(ciphertext, password="my-password")

# Strings (returns URL-safe base64)
encoded = encrypt_string("secret text", password="my-password")
text = decrypt_string(encoded, password="my-password")
```

### File Encryption

Files under 64KB use a single encrypted blob. Larger files use chunked encryption for memory efficiency.

```python
from cryptoserve_core import encrypt_file, decrypt_file

encrypt_file("report.pdf", "report.pdf.enc", password="file-password")
decrypt_file("report.pdf.enc", "report.pdf", password="file-password")
```

## Password Hashing

Secure password hashing with scrypt or PBKDF2. Output follows the PHC (Password Hashing Competition) string format for safe database storage.

```python
from cryptoserve_core import hash_password, verify_password, check_strength

# Hash (default: scrypt)
hashed = hash_password("user-password")
# Output: $scrypt$n=16384,r=8,p=1$<salt>$<hash>

# Hash with PBKDF2
hashed = hash_password("user-password", algorithm="pbkdf2")
# Output: $pbkdf2-sha256$i=600000$<salt>$<hash>

# Verify (constant-time comparison)
assert verify_password("user-password", hashed)

# Strength check (0-4 score)
result = check_strength("P@ssw0rd!2026")
print(f"Score: {result.score}/4 ({result.label})")
print(f"Feedback: {result.feedback}")
```

## JWT Tokens

Minimal JWT implementation using HS256 (HMAC-SHA256). No pyjwt dependency.

```python
from cryptoserve_core import create_token, verify_token, decode_token

key = b"my-secret-key-minimum-16-bytes"

# Create with automatic iat/exp claims
token = create_token({"sub": "user-123", "role": "admin"}, key=key, expires_in=3600)

# Verify signature and expiry
claims = verify_token(token, key=key)

# Decode without verification (inspect claims)
claims = decode_token(token)
```

## Low-Level API

For custom key management and direct cipher access:

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

# Key derivation from password
key, salt = KeyDerivation.from_password("my-password", bits=256, iterations=600_000)
```

## Supported Algorithms

| Algorithm | Security | Use Case |
|-----------|----------|----------|
| AES-256-GCM | 256-bit | General purpose, hardware accelerated |
| ChaCha20-Poly1305 | 256-bit | Mobile, real-time applications |
| scrypt | N=16384, r=8, p=1 | Password hashing (interactive) |
| PBKDF2-SHA256 | 600K iterations | Password hashing (compatibility) |
| HS256 | HMAC-SHA256 | JWT token signing |

## Why cryptoserve-core?

- **Zero config** - Production-safe defaults for every algorithm
- **No server required** - Works entirely offline
- **One dependency** - Only `cryptography` (no pyjwt, bcrypt, argon2-cffi)
- **Auditable** - Small, focused codebase with continuous security validation
- **Standards compliant** - NIST-approved algorithms, PHC hash format

## License

Apache 2.0
