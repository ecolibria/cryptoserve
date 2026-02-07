# CryptoServe Ciphertext Formats

This document describes the four ciphertext formats used across the CryptoServe SDK and how to migrate between them.

## Format Overview

| Format | Used by | Purpose | Key source |
|--------|---------|---------|------------|
| Easy blob (v1/v2) | `cryptoserve_core.encrypt()` | Password-based standalone encryption | PBKDF2 from password |
| Core encoding | `encode_ciphertext()` | Raw cipher output wrapper | User-provided key |
| Local mode | `CryptoServe.local()` | Context-aware SDK API (offline) | HKDF from master key |
| Server/cached (v4) | `CryptoServe()` | Server-managed keys | Server key bundle |

## Easy Blob Format

Used by `cryptoserve_core.encrypt()`, `encrypt_string()`, `encrypt_file()`.

### Version 1 (single blob)

```
[version:1 byte][salt:16 bytes][nonce:12 bytes][ciphertext + AES-GCM tag]
```

- **version**: `0x01`
- **salt**: Random 16-byte salt for PBKDF2 key derivation
- **nonce**: Random 12-byte nonce for AES-256-GCM
- **ciphertext**: AES-256-GCM encrypted data with 16-byte auth tag appended

Key derivation: PBKDF2-SHA256, 600,000 iterations, 256-bit key.

### Version 2 (chunked file)

Used for files larger than 64KB.

```
[version:1 byte][salt:16 bytes][chunk_count:4 bytes (big-endian)]
Per chunk:
  [nonce:12 bytes][chunk_len:4 bytes (big-endian)][ciphertext + tag]
```

- **version**: `0x02`
- **chunk_count**: Number of 64KB chunks
- Each chunk encrypted independently with a fresh nonce

## Core Encoding Format

Used by `cryptoserve_core.encode_ciphertext()`. Wraps raw cipher output with metadata.

```
[algorithm_id:1 byte][key_id_len:2 bytes][key_id][nonce][ciphertext + tag]
```

Algorithm IDs:
- `0x01`: AES-256-GCM
- `0x02`: ChaCha20-Poly1305

## Local Mode Format

Used by `CryptoServe.local()` encrypt/decrypt operations.

```
[context_len:2 bytes (big-endian)][context:UTF-8 string][nonce:12 bytes][ciphertext + tag]
```

- **context_len**: Length of the embedded context string
- **context**: The encryption context (e.g., "user-pii"), embedded for validation
- **nonce**: Random 12-byte nonce for AES-256-GCM
- **ciphertext**: AES-256-GCM encrypted data with 16-byte auth tag

Key derivation: Master key derived from password (PBKDF2 600K iterations with deterministic salt), then per-context key via HKDF-SHA256 with info `cryptoserve-local-{context}`.

## Server/Cached Format (v4)

Used by `CryptoServe()` in server mode with local caching.

```
[version:1 byte][key_id_len:2 bytes][key_id][algorithm:1 byte][nonce][ciphertext + tag]
```

- **version**: `0x04`
- **key_id**: Server-assigned key identifier
- **algorithm**: Server-selected algorithm based on context policy and usage hint

Keys are fetched from the server and cached locally for performance.

## Migration Paths

### Easy blob -> Local mode

Decrypt the easy blob with the original password, then re-encrypt under a CryptoServe local instance with a context.

```python
import cryptoserve_core as core
from cryptoserve import CryptoServe

# Decrypt the easy blob
plaintext = core.decrypt(easy_ciphertext, password="old-password")

# Re-encrypt under local mode
local = CryptoServe.local(password="new-master-password")
new_ciphertext = local.encrypt(plaintext, context="user-pii")
```

Or use the migration helper:

```python
local = CryptoServe.local(password="new-master-password")
new_ciphertext = CryptoServe.migrate_from_easy(
    easy_ciphertext, password="old-password",
    target=local, context="user-pii"
)
```

### Easy blob -> Server mode

```python
import cryptoserve_core as core
from cryptoserve import CryptoServe

plaintext = core.decrypt(easy_ciphertext, password="old-password")

server = CryptoServe(app_name="my-app", team="platform")
new_ciphertext = server.encrypt(plaintext, context="user-pii")
```

### Local mode -> Server mode

```python
from cryptoserve import CryptoServe

local = CryptoServe.local(password="master-password")
server = CryptoServe(app_name="my-app", team="platform")

plaintext = local.decrypt(local_ciphertext, context="user-pii")
new_ciphertext = server.encrypt(plaintext, context="user-pii")
```
