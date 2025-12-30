# cryptoserve-auto

Automatic encryption for data flowing through third-party libraries.

## The Problem

Your application uses hundreds of dependencies. Each may send sensitive data
to external services. When quantum computing breaks classical encryption,
these dependencies become attack vectors.

## The Solution

One line of code automatically protects all outbound sensitive data:

```python
import cryptoserve_auto
cryptoserve_auto.protect()

# Now all outbound requests are automatically protected
import requests
requests.post("https://api.vendor.com/users", json={
    "name": "John Doe",
    "email": "john@example.com",  # Auto-encrypted
    "ssn": "123-45-6789",         # Auto-encrypted
})
```

## Installation

```bash
pip install cryptoserve-auto
```

## How It Works

1. **Intercepts** outbound calls from popular libraries (requests, httpx, boto3)
2. **Detects** sensitive fields using patterns and field names
3. **Encrypts** data with quantum-ready algorithms before transmission
4. **Logs** all protected data flows for audit visibility

## Configuration

```python
import cryptoserve_auto

cryptoserve_auto.protect(
    # What to protect
    libraries=["requests", "httpx"],  # Default: all supported
    patterns=["pii", "financial"],     # Default: all patterns

    # How to protect
    encryption_key=key,                # Required: your encryption key
    mode="encrypt",                    # "encrypt" | "tokenize" | "log_only"

    # Behavior
    fail_open=True,                    # On error: pass through (True) or block (False)
    async_logging=True,                # Non-blocking audit logging
)
```

## Supported Libraries

| Library | What's Protected |
|---------|------------------|
| `requests` | POST/PUT/PATCH body data |
| `httpx` | POST/PUT/PATCH body data |
| `urllib3` | Request bodies |

More coming: boto3, stripe, psycopg2, sqlalchemy, redis

## Sensitive Field Detection

**Automatic patterns:**
- SSN: `XXX-XX-XXXX`
- Credit cards: `XXXX-XXXX-XXXX-XXXX`
- Emails: `user@domain.com`
- Phone numbers

**Field name detection:**
- `ssn`, `social_security`, `tax_id`
- `email`, `phone`, `address`
- `password`, `secret`, `api_key`
- `credit_card`, `card_number`

**Custom patterns:**
```python
cryptoserve_auto.protect(
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
    },
    custom_fields=["internal_id"],
)
```

## Escape Hatch

```python
# Temporarily disable protection
with cryptoserve_auto.unprotected():
    requests.post(url, json=data)  # Not intercepted
```

## Audit Logging

All protected data flows are logged:

```json
{
  "timestamp": "2025-12-29T10:30:00Z",
  "library": "requests",
  "destination": "api.vendor.com",
  "fields_protected": ["email", "ssn"],
  "algorithm": "AES-256-GCM"
}
```

## Performance

| Operation | Overhead |
|-----------|----------|
| Field detection | ~5μs per field |
| Encryption | ~50μs per KB |
| Total request overhead | <1ms |

## License

Apache 2.0
