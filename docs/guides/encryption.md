# Encryption & Decryption Guide

This guide covers common encryption patterns and best practices.

## Basic Encryption

### String Data

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt
encrypted = crypto.encrypt_string("sensitive data", context="user-pii")

# Decrypt
decrypted = crypto.decrypt_string(encrypted, context="user-pii")
```

### Binary Data

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt bytes
data = b"binary data"
encrypted = crypto.encrypt(data, context="user-pii")

# Decrypt
decrypted = crypto.decrypt(encrypted, context="user-pii")
```

### JSON Objects

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

user = {"name": "John", "ssn": "123-45-6789"}
encrypted = crypto.encrypt_json(user, context="user-pii")
decrypted = crypto.decrypt_json(encrypted, context="user-pii")
```

---

## Using Associated Data

Associated Data (AAD) is authenticated but not encrypted. Use it to bind ciphertext to specific metadata.

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt with AAD
encrypted = crypto.encrypt_string(
    "sensitive data",
    context="user-pii",
    associated_data=b"user_id:12345"
)

# Decrypt - AAD must match exactly
decrypted = crypto.decrypt_string(
    encrypted,
    context="user-pii",
    associated_data=b"user_id:12345"
)
```

**Use cases for AAD:**

- Bind ciphertext to a specific user ID
- Include metadata in authentication
- Version or timestamp binding

---

## Choosing Contexts

Select the appropriate context for your data:

| Data Type | Recommended Context | Algorithm |
|-----------|-------------------|-----------|
| User PII (SSN, email) | `user-pii` | AES-256-GCM |
| Payment cards | `payment-data` | AES-256-GCM |
| Medical records | `health-data` | AES-256-GCM |
| Session tokens | `session-tokens` | AES-256-GCM |
| Long-term secrets | Custom (PQC) | Hybrid |

---

## Field-Level Encryption

Encrypt specific fields in a database:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

class User:
    def __init__(self, email, ssn):
        self.email = email
        self._ssn_encrypted = crypto.encrypt_string(ssn, context="user-pii")

    @property
    def ssn(self):
        return crypto.decrypt_string(self._ssn_encrypted, context="user-pii")
```

---

## Batch Operations

Process multiple items efficiently:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt multiple items
items = [
    {"data": b"item1", "context": "user-pii"},
    {"data": b"item2", "context": "user-pii"},
]
results = crypto.batch_encrypt(items)

# Check results
for result in results:
    if result.success:
        print(f"Encrypted: {len(result.ciphertext)} bytes")
    else:
        print(f"Error: {result.error}")
```

---

## Error Handling

```python
from cryptoserve import CryptoServe
from cryptoserve import (
    CryptoServeError,
    AuthorizationError,
    ContextNotFoundError
)

crypto = CryptoServe(app_name="my-app", team="platform")

try:
    decrypted = crypto.decrypt_string(ciphertext, context="user-pii")
except CryptoServeError:
    # Ciphertext corrupted or wrong key
    log.error("Decryption failed")
except AuthorizationError:
    # Identity not authorized
    log.error("Not authorized for this context")
except ContextNotFoundError:
    # Context doesn't exist
    log.error("Invalid context")
```

---

## Best Practices

1. **Use appropriate contexts**: Don't mix data types in one context
2. **Handle errors gracefully**: Never expose decryption failures to users
3. **Use AAD when applicable**: Bind ciphertext to specific metadata
4. **Log operations**: Enable audit logging for compliance
5. **Test with mock mode**: Use mock crypto in tests
