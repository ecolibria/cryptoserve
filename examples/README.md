# CryptoServe Examples

This directory contains comprehensive examples for using CryptoServe in various scenarios.

## Quick Start

Before running these examples, ensure:

1. CryptoServe server is running (`docker compose up -d`)
2. SDK is installed (`pip install cryptoserve`)
3. You've authenticated (`cryptoserve login`)

## Examples

### Basic Operations

| Example | Description |
|---------|-------------|
| [01_basic_encryption.py](01_basic_encryption.py) | Encrypt and decrypt data |
| [02_string_and_json.py](02_string_and_json.py) | Work with strings and JSON |
| [03_signing.py](03_signing.py) | Digital signatures |
| [04_hashing.py](04_hashing.py) | Cryptographic hashing |
| [05_password_hashing.py](05_password_hashing.py) | Secure password storage |

### Advanced Operations

| Example | Description |
|---------|-------------|
| [06_file_encryption.py](06_file_encryption.py) | Encrypt and decrypt files |
| [07_batch_operations.py](07_batch_operations.py) | Process multiple items efficiently |
| [08_associated_data.py](08_associated_data.py) | Bind ciphertext to context with AAD |
| [09_post_quantum.py](09_post_quantum.py) | Post-quantum cryptography (ML-KEM, ML-DSA) |
| [10_hybrid_encryption.py](10_hybrid_encryption.py) | Classical + PQC hybrid mode |

### Framework Integrations

| Example | Description |
|---------|-------------|
| [fastapi_integration.py](fastapi_integration.py) | FastAPI web service |
| [django_integration.py](django_integration.py) | Django model encryption |
| [sqlalchemy_integration.py](sqlalchemy_integration.py) | SQLAlchemy transparent encryption |
| [flask_integration.py](flask_integration.py) | Flask web application |

### Production Patterns

| Example | Description |
|---------|-------------|
| [error_handling.py](error_handling.py) | Comprehensive error handling |
| [key_rotation.py](key_rotation.py) | Handle key rotation |
| [multi_context.py](multi_context.py) | Work with multiple contexts |
| [audit_logging.py](audit_logging.py) | Access audit logs |

## Running Examples

```bash
# Run a single example
python examples/01_basic_encryption.py

# Run all examples (requires pytest)
pytest examples/ -v
```

## Environment Variables

Some examples may require environment variables:

```bash
export CRYPTOSERVE_URL=http://localhost:8003
export CRYPTOSERVE_APP_NAME=example-app
export CRYPTOSERVE_TEAM=examples
```
