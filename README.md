<p align="center">
  <img src="docs/assets/logo.svg" alt="CryptoServe" width="120" height="120">
</p>

<h1 align="center">CryptoServe</h1>

<p align="center">
  <strong>Cryptography-as-a-Service Platform</strong><br>
  Production-grade encryption, signing, and hashing with zero configuration.<br>
  Post-quantum ready. FIPS compliant. Open source.
</p>

<p align="center">
  <a href="https://github.com/keytum/crypto-serve/actions"><img src="https://img.shields.io/github/actions/workflow/status/keytum/crypto-serve/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="https://github.com/keytum/crypto-serve/releases"><img src="https://img.shields.io/github/v/release/keytum/crypto-serve?style=flat-square" alt="Release"></a>
  <a href="https://github.com/keytum/crypto-serve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square" alt="Python 3.10+"></a>
  <a href="https://keytum.github.io/crypto-serve/"><img src="https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat-square" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#sdk-reference">SDK</a> •
  <a href="#post-quantum-cryptography">Post-Quantum</a> •
  <a href="docs/security/technical-reference.md">Security</a> •
  <a href="docs/api-reference/">API</a> •
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Why CryptoServe?

Cryptography is hard. Key management is harder. CryptoServe eliminates the complexity:

| Challenge | Without CryptoServe | With CryptoServe |
|-----------|---------------------|------------------|
| **Key Management** | Generate, store, rotate, backup keys manually | Automatic key lifecycle management |
| **Algorithm Selection** | Research NIST recommendations, implement correctly | Pre-configured secure defaults |
| **Compliance** | Build audit trails, prove FIPS compliance | Built-in audit logging and FIPS modes |
| **Post-Quantum** | Wait for standards, plan migration | ML-KEM and ML-DSA ready today |
| **Multi-tenant** | Build isolation from scratch | Tenant isolation built-in |

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+
- GitHub account (for authentication)

### 1. Start the Server

```bash
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve
cp .env.example .env
docker compose up -d
```

Server: `http://localhost:8000` | Dashboard: `http://localhost:3000`

### 2. Install SDK and Login

```bash
pip install -e sdk/python/
cryptoserve login  # Opens browser for GitHub auth
```

### 3. Encrypt Data

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="engineering")

# Encrypt
ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

# Decrypt
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

That's it. Your app auto-registers and is ready for production.

---

## Features

### Cryptographic Operations

| Operation | Algorithms | Use Case |
|-----------|------------|----------|
| **Symmetric Encryption** | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 | Data at rest, field-level encryption |
| **Asymmetric Encryption** | RSA-OAEP, ECIES (P-256, P-384), X25519 | Key exchange, hybrid encryption |
| **Digital Signatures** | Ed25519, ECDSA, RSA-PSS, ML-DSA | Document signing, authentication |
| **Hashing** | SHA-256/384/512, SHA-3, BLAKE2b/3 | Integrity verification |
| **Password Hashing** | Argon2id, bcrypt, scrypt, PBKDF2 | User authentication |
| **Key Derivation** | HKDF-SHA256, PBKDF2, scrypt | Deriving keys from passwords |
| **Post-Quantum** | ML-KEM-768/1024, ML-DSA-65/87, SLH-DSA | Quantum-resistant encryption |

### Platform Capabilities

| Capability | Description |
|------------|-------------|
| **5-Layer Context Model** | Automatic algorithm selection based on sensitivity, compliance, threats, access patterns, and technical requirements |
| **Policy Engine** | Declarative rules for algorithm restrictions, key sizes, and compliance enforcement |
| **Key Rotation** | Zero-downtime automatic and manual key rotation with versioning |
| **Audit Logging** | Complete cryptographic operation audit trail with SIEM integration |
| **Multi-Tenant** | Full tenant isolation with per-tenant keys and policies |
| **FIPS Compliance** | FIPS 140-2/140-3 compliant operation modes |
| **Threshold Crypto** | FROST signatures, Shamir secret sharing, distributed key generation |

---

## SDK Reference

### Installation

**Option 1: CLI Install (Recommended)**

```bash
pip install -e sdk/python/
cryptoserve login  # Opens browser for GitHub auth
```

Your app auto-registers on first use - no manual setup needed.

**Option 2: Dashboard Download**

1. Go to **Applications** in the dashboard (`http://localhost:3000/applications`)
2. Create or select an application
3. Click **Download SDK**
4. Install the downloaded wheel:

```bash
pip install cryptoserve-*.whl
```

This embeds your credentials directly in the SDK package.

### Initialization

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(
    app_name="my-service",       # Required: unique app identifier
    team="platform",             # Optional: team name (default: "default")
    environment="production",    # Optional: dev/staging/production
    contexts=["user-pii"],       # Optional: contexts to request access to
)
```

### Encrypt and Decrypt

```python
# Binary data
ciphertext = crypto.encrypt(b"sensitive bytes", context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")

# Strings
encrypted = crypto.encrypt_string("sensitive text", context="user-pii")
decrypted = crypto.decrypt_string(encrypted, context="user-pii")

# JSON objects
user = {"name": "John", "ssn": "123-45-6789"}
encrypted = crypto.encrypt_json(user, context="user-pii")
decrypted = crypto.decrypt_json(encrypted, context="user-pii")
```

### Sign and Verify

```python
# Create signature
signature = crypto.sign(b"document content", key_id="signing-key")

# Verify signature
is_valid = crypto.verify_signature(b"document content", signature, key_id="signing-key")
```

### Hash and MAC

```python
# Cryptographic hash (SHA-256 default)
hash_hex = crypto.hash(b"data to hash")
hash_hex = crypto.hash(b"data", algorithm="sha3-256")

# Message Authentication Code
mac_hex = crypto.mac(b"message", key=secret_key)
```

### Health Check

```python
if crypto.health_check():
    print("Connected to CryptoServe")
```

---

## Post-Quantum Cryptography

CryptoServe implements NIST FIPS 203, 204, and 205 standards for post-quantum cryptography:

### Supported Algorithms

| Algorithm | Standard | Type | Security Level |
|-----------|----------|------|----------------|
| **ML-KEM-512** | FIPS 203 | Key Encapsulation | 128-bit |
| **ML-KEM-768** | FIPS 203 | Key Encapsulation | 192-bit |
| **ML-KEM-1024** | FIPS 203 | Key Encapsulation | 256-bit |
| **ML-DSA-44** | FIPS 204 | Digital Signature | 128-bit |
| **ML-DSA-65** | FIPS 204 | Digital Signature | 192-bit |
| **ML-DSA-87** | FIPS 204 | Digital Signature | 256-bit |
| **SLH-DSA-128** | FIPS 205 | Digital Signature | 128-bit |
| **SLH-DSA-192** | FIPS 205 | Digital Signature | 192-bit |
| **SLH-DSA-256** | FIPS 205 | Digital Signature | 256-bit |

### Hybrid Encryption

Combine classical and post-quantum for defense-in-depth:

```python
# Hybrid encryption: X25519 + ML-KEM-768
ciphertext = crypto.encrypt(
    plaintext,
    context="quantum-ready",
    algorithm="hybrid-x25519-mlkem768"
)

# Hybrid signatures: Ed25519 + ML-DSA-65
signature = crypto.sign(
    message,
    key_id="hybrid-signing-key",
    algorithm="hybrid-ed25519-mldsa65"
)
```

### Migration Path

1. **Assess**: Run `cryptoserve scan` to identify quantum-vulnerable algorithms
2. **Plan**: Use the context model to flag sensitive data for PQC
3. **Migrate**: Enable hybrid mode for gradual transition
4. **Verify**: Monitor with the dashboard and CBOM reports

---

## Context Model

The 5-layer context model automatically selects appropriate algorithms:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Data Identity                                       │
│   Sensitivity: low | medium | high | critical                │
│   Data Types: PII, PHI, PCI, financial, secrets              │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Regulatory                                          │
│   Frameworks: HIPAA, GDPR, PCI-DSS, SOC2, FedRAMP           │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Threat Model                                        │
│   Adversary: script-kiddie | criminal | nation-state        │
│   Quantum Timeline: none | 5yr | 10yr | 15yr+               │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Access Patterns                                     │
│   Frequency: rare | occasional | frequent | continuous       │
│   Latency: strict (<10ms) | normal | relaxed                │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Technical                                           │
│   Hardware: HSM, TPM, software-only                         │
│   Key Size: minimum bits required                            │
└─────────────────────────────────────────────────────────────┘
```

### Example Context Configurations

```python
# User PII - automatically uses AES-256-GCM with strict audit
crypto.encrypt(data, context="user-pii")

# Payment data - PCI-DSS compliant encryption
crypto.encrypt(card_number, context="payment-data")

# Healthcare - HIPAA compliant with extended retention
crypto.encrypt(diagnosis, context="health-data")

# Quantum-ready - Hybrid classical + PQC encryption
crypto.encrypt(classified, context="quantum-ready")
```

---

## Examples

### Database Integration (SQLAlchemy)

```python
from sqlalchemy import Column, String
from sqlalchemy.ext.hybrid import hybrid_property
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

class User(Base):
    __tablename__ = 'users'

    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    _ssn = Column("ssn_encrypted", String)

    @hybrid_property
    def ssn(self):
        if self._ssn:
            return crypto.decrypt_string(self._ssn, context="user-pii")
        return None

    @ssn.setter
    def ssn(self, value):
        if value:
            self._ssn = crypto.encrypt_string(value, context="user-pii")

# Usage - encryption is automatic
user = User(id="user_123", email="john@example.com", ssn="123-45-6789")
session.add(user)
session.commit()
```

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptoserve import CryptoServe

app = FastAPI()
crypto = CryptoServe(app_name="my-api", team="platform")

class CreateUserRequest(BaseModel):
    email: str
    ssn: str

@app.post("/users")
async def create_user(request: CreateUserRequest):
    encrypted_ssn = crypto.encrypt_string(request.ssn, context="user-pii")
    # Store encrypted_ssn in database
    return {"id": "user_123", "email": request.email}
```

### File Encryption

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="file-service", team="platform")

def encrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = crypto.encrypt(plaintext, context="documents")

    with open(output_path, "wb") as f:
        f.write(ciphertext)

def decrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    plaintext = crypto.decrypt(ciphertext, context="documents")

    with open(output_path, "wb") as f:
        f.write(plaintext)
```

### Batch Operations

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="batch-processor", team="platform")

# Encrypt multiple items
records = [
    {"id": "1", "ssn": "111-11-1111"},
    {"id": "2", "ssn": "222-22-2222"},
    {"id": "3", "ssn": "333-33-3333"},
]

for record in records:
    record["ssn_encrypted"] = crypto.encrypt_string(
        record["ssn"], context="user-pii"
    )
    del record["ssn"]  # Remove plaintext
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                       │
│       Python SDK  |  TypeScript (Soon)  |  REST API         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     CryptoServe Server                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Auth Layer  │  │   Policy    │  │   Crypto Engines    │  │
│  │ JWT / OAuth │  │   Engine    │  │ AES | PQC | Hybrid  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Key Management Layer                        ││
│  │         HKDF | KMS Integration | Key Rotation           ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │                 Audit & Compliance                       ││
│  │        SIEM Export | CBOM | Compliance Reports          ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgreSQL / SQLite / MySQL                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Self-Hosting

### Docker Compose (Recommended)

```bash
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve
cp .env.example .env
```

Edit `.env`:

```bash
# Required: GitHub OAuth (create at https://github.com/settings/developers)
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret

# Required: Security keys (generate with: openssl rand -hex 32)
CRYPTOSERVE_MASTER_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)

# Optional: Database (defaults to SQLite)
DATABASE_URL=postgresql://user:pass@localhost/cryptoserve

# Optional: FIPS mode
FIPS_MODE=disabled  # or "enabled" for FIPS compliance
```

Start services:

```bash
docker compose up -d
```

### Production Configuration

For production deployments, see the [Production Guide](https://keytum.github.io/crypto-serve/guides/production/).

Key requirements:
- Generate unique secrets (never use defaults)
- Use PostgreSQL for production
- Enable TLS termination
- Configure backup and recovery
- Set up monitoring and alerting

---

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/crypto/encrypt` | POST | Encrypt data |
| `/api/v1/crypto/decrypt` | POST | Decrypt data |
| `/api/v1/crypto/batch/encrypt` | POST | Batch encrypt (up to 100 items) |
| `/api/v1/crypto/batch/decrypt` | POST | Batch decrypt (up to 100 items) |
| `/api/v1/signatures/sign` | POST | Create digital signature |
| `/api/v1/signatures/verify` | POST | Verify digital signature |
| `/api/v1/hash` | POST | Compute cryptographic hash |
| `/api/v1/passwords/hash` | POST | Hash password (Argon2id) |
| `/api/v1/passwords/verify` | POST | Verify password hash |

### Context Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/contexts` | GET | List available contexts |
| `/api/v1/contexts/{name}` | GET | Get context details |
| `/api/v1/contexts` | POST | Create new context |
| `/api/v1/contexts/{name}/rotate` | POST | Rotate context keys |

### Post-Quantum

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/asymmetric/ml-kem/keygen` | POST | Generate ML-KEM keypair |
| `/api/v1/asymmetric/ml-kem/encapsulate` | POST | Encapsulate shared secret |
| `/api/v1/asymmetric/ml-kem/decapsulate` | POST | Decapsulate shared secret |
| `/api/v1/signatures/ml-dsa/keygen` | POST | Generate ML-DSA keypair |
| `/api/v1/signatures/ml-dsa/sign` | POST | Sign with ML-DSA |
| `/api/v1/signatures/ml-dsa/verify` | POST | Verify ML-DSA signature |

### Health & Monitoring

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Basic health check |
| `/health/ready` | GET | Readiness probe |
| `/health/deep` | GET | Deep health check (all dependencies) |

Full API documentation: [API Reference](https://keytum.github.io/crypto-serve/api-reference/)

---

## Dashboard

Access the web dashboard at `http://localhost:3000`:

- **Overview**: KPIs, operation counts, success rates
- **Applications**: View and manage registered apps
- **Contexts**: Configure encryption contexts
- **Audit Logs**: Search and export operation logs
- **Analytics**: Usage trends and algorithm distribution
- **CBOM**: Cryptographic Bill of Materials scanner

---

## Testing

```bash
cd backend

# Run all tests (1,235 tests)
pytest -v

# Run with coverage
pytest --cov=app --cov-report=term-missing

# Run specific test categories
pytest tests/test_crypto/          # Crypto engine tests
pytest tests/test_pqc/             # Post-quantum tests
pytest tests/test_api/             # API endpoint tests
```

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Quick Start](https://keytum.github.io/crypto-serve/getting-started/quickstart/) | Get running in 5 minutes |
| [Concepts](https://keytum.github.io/crypto-serve/concepts/) | Architecture, context model, key management |
| [SDK Reference](https://keytum.github.io/crypto-serve/sdk/python/) | Complete Python SDK documentation |
| [API Reference](https://keytum.github.io/crypto-serve/api-reference/) | REST API documentation |
| [Technical Reference](docs/security/technical-reference.md) | Cryptographic design and threat model |
| [Migration Guide](https://keytum.github.io/crypto-serve/guides/migration/) | Migrate from AWS KMS, Vault, or crypto libraries |
| [Production Guide](https://keytum.github.io/crypto-serve/guides/production/) | Production deployment best practices |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Run tests
pytest -v

# Code formatting
black app/ tests/
ruff check app/ tests/
```

---

## Security

**Report vulnerabilities** to security@cryptoserve.io or via [GitHub Security Advisories](https://github.com/keytum/crypto-serve/security/advisories).

See [SECURITY.md](SECURITY.md) and [Technical Reference](docs/security/technical-reference.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built for developers who need cryptography done right.</sub>
</p>
