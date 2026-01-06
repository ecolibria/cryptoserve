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
  <a href="https://github.com/ecolibria/crypto-serve/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ecolibria/crypto-serve/ci.yml?branch=main&style=flat-square&label=build" alt="Build Status"></a>
  <a href="https://github.com/ecolibria/crypto-serve/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-1,346%20passed-brightgreen.svg?style=flat-square" alt="Tests"></a>
  <a href="https://github.com/ecolibria/crypto-serve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square" alt="Python 3.10+"></a>
  <a href="https://cryptoserve.dev/docs/"><img src="https://img.shields.io/badge/docs-cryptoserve.dev-brightgreen.svg?style=flat-square" alt="Documentation"></a>
</p>

<p align="center">
  <a href="https://cryptoserve.dev">Website</a> •
  <a href="https://cryptoserve.dev/docs/">Documentation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#sdk-reference">SDK</a> •
  <a href="#runtime-usage-hints-intelligent-algorithm-selection">Runtime Usage</a> •
  <a href="#post-quantum-cryptography">Post-Quantum</a> •
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
git clone https://github.com/ecolibria/crypto-serve.git
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
| **Post-Quantum** | ML-KEM-768/1024, ML-DSA-44/65/87, SLH-DSA | Quantum-resistant encryption |
| **Hybrid Key Exchange** | X25519 + ML-KEM-768/1024 | Quantum-safe key agreement |
| **Disk Encryption** | AES-256-XTS | Full-disk/sector encryption |

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
| **SLH-DSA-128f/s** | FIPS 205 | Digital Signature | 128-bit |
| **SLH-DSA-192f/s** | FIPS 205 | Digital Signature | 192-bit |
| **SLH-DSA-256f/s** | FIPS 205 | Digital Signature | 256-bit |

### Hybrid Key Exchange (X25519 + ML-KEM)

Quantum-safe key agreement combining classical X25519 with ML-KEM:

```python
# Generate hybrid key pair
from app.core.hybrid_kex import HybridKeyExchange, HybridKEXMode

kex = HybridKeyExchange(HybridKEXMode.X25519_MLKEM_768)
keypair = kex.generate_keypair()

# Sender: encapsulate to create shared secret
encap, shared_secret = kex.encapsulate(
    keypair.x25519_public, keypair.mlkem_public
)

# Recipient: decapsulate to recover shared secret
shared_secret = kex.decapsulate(encap, keypair)
```

**API Endpoints:**
- `GET /api/v1/kex/modes` - List available hybrid KEX modes
- `POST /api/v1/kex/keys/generate` - Generate hybrid key pair
- `POST /api/v1/kex/encapsulate` - Create shared secret (sender)
- `POST /api/v1/kex/decapsulate` - Recover shared secret (recipient)

### Hybrid Encryption

Combine classical and post-quantum for defense-in-depth:

```python
# Hybrid encryption: AES-GCM + ML-KEM-768
ciphertext = crypto.encrypt(
    plaintext,
    context="quantum-ready",
    algorithm="hybrid-aes-mlkem768"
)

# Hybrid signatures: Ed25519 + ML-DSA-65
signature = crypto.sign(
    message,
    key_id="hybrid-signing-key",
    algorithm="hybrid-ed25519-mldsa65"
)
```

### AES-XTS Disk Encryption

Full-disk encryption with HMAC integrity protection:

```python
from app.core.crypto_engine import CipherFactory

# 64-byte key (two 256-bit keys for XTS)
key = os.urandom(64)
tweak = sector_number.to_bytes(16, 'little')

# Encrypt sector
ciphertext = CipherFactory.encrypt_xts(key, sector_data, tweak)

# Decrypt sector
plaintext = CipherFactory.decrypt_xts(key, ciphertext, tweak)
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
│ Layer 1: Data Identity                                      │
│   Sensitivity: low | medium | high | critical               │
│   Data Types: PII, PHI, PCI, financial, secrets             │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Regulatory                                         │
│   Frameworks: HIPAA, GDPR, PCI-DSS, SOC2, FedRAMP           │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Threat Model                                       │
│   Adversary: script-kiddie | criminal | nation-state        │
│   Quantum Timeline: none | 5yr | 10yr | 15yr+               │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Access Patterns                                    │
│   Frequency: rare | occasional | frequent | continuous      │
│   Latency: strict (<10ms) | normal | relaxed                │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Technical                                          │
│   Hardware: HSM, TPM, software-only                         │
│   Key Size: minimum bits required                           │
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

## Runtime Usage Hints (Intelligent Algorithm Selection)

CryptoServe's key differentiator: **automatic algorithm selection** that combines admin-configured **context policies** (WHAT the data is) with developer-provided **runtime usage hints** (HOW the data is being used).

This solves the enterprise problem where:
- Admins can't know at configuration time whether PII will be stored in a database vs sent over an API
- Developers don't want to learn cryptographic details
- The same data type needs different optimal algorithms for different use cases

### Runtime Usage Hints

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Same context ("customer-pii"), different usage = different optimal algorithms!

# "at_rest" - Data being stored (databases, files, backups)
# Platform selects: AES-256-GCM (optimized for storage)
db_record = crypto.encrypt(
    ssn.encode(),
    context="customer-pii",
    usage="at_rest"
)

# "in_transit" - Data being transmitted (API calls, network)
# Platform selects: AES-256-GCM (optimized for network)
api_response = crypto.encrypt(
    ssn.encode(),
    context="customer-pii",
    usage="in_transit"
)

# "in_use" - Data in active memory/processing
# Platform selects: AES-256-GCM-SIV (nonce-misuse resistant)
memory_data = crypto.encrypt(
    ssn.encode(),
    context="customer-pii",
    usage="in_use"
)

# "streaming" - Real-time data streams
# Platform selects: ChaCha20-Poly1305 (optimized for streams)
stream_chunk = crypto.encrypt(
    video_chunk,
    context="media-content",
    usage="streaming"
)

# "disk" - Volume/disk encryption
# Platform selects: Based on context policy (XTS mode)
disk_sector = crypto.encrypt(
    sector_data,
    context="disk-encryption",
    usage="disk"
)
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  Admin configures CONTEXT (via dashboard):                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  customer-pii:                                               │   │
│  │    sensitivity: critical                                     │   │
│  │    compliance: [HIPAA, GDPR]                                 │   │
│  │    min_key_bits: 256                                         │   │
│  │    quantum_resistant: false                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Developer provides USAGE at runtime:                               │
│                                                                     │
│    crypto.encrypt(data, context="customer-pii", usage="at_rest")    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CryptoServe combines CONTEXT + USAGE → Optimal Algorithm           │
│                                                                     │
│    customer-pii + "at_rest"    → AES-256-GCM                        │
│    customer-pii + "in_transit" → AES-256-GCM                        │
│    customer-pii + "in_use"     → AES-256-GCM-SIV (nonce-resistant)  │
│    customer-pii + "streaming"  → ChaCha20-Poly1305                  │
│                                                                     │
│    If context requires quantum_resistant:                           │
│    customer-pii + "at_rest"    → AES-256-GCM + ML-KEM-768 (hybrid)  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Usage Reference

| Usage | Description | Default Algorithm |
|-------|-------------|-------------------|
| `"at_rest"` | Database storage, file encryption | AES-256-GCM |
| `"in_transit"` | Network transmission, API payloads | AES-256-GCM |
| `"in_use"` | Memory encryption, active processing | AES-256-GCM-SIV |
| `"streaming"` | Real-time data streams | ChaCha20-Poly1305 |
| `"disk"` | Volume/disk encryption | Per context policy |

### Admin Analytics

Admins can see how developers are using each context in the audit logs:

```sql
-- See usage patterns for customer-pii context
SELECT usage, COUNT(*) as ops, DATE(timestamp) as date
FROM audit_log
WHERE context = 'customer-pii'
GROUP BY usage, DATE(timestamp)
ORDER BY date DESC;

-- Results:
-- usage       | ops  | date
-- at_rest     | 1542 | 2024-01-06
-- in_transit  | 3291 | 2024-01-06
-- streaming   |   47 | 2024-01-06
```

This helps admins understand actual data flow and adjust context policies accordingly.

### Real-World Example

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="healthcare-api", team="platform")

class PatientService:
    """Healthcare service showing usage-based encryption."""

    def save_to_database(self, patient_record: dict) -> str:
        """Store patient data in database."""
        encrypted = crypto.encrypt_json(
            patient_record,
            context="patient-phi",
            usage="at_rest"  # Database storage
        )
        db.save(encrypted)
        return encrypted

    def send_to_api(self, patient_record: dict) -> bytes:
        """Send patient data to external API."""
        return crypto.encrypt_json(
            patient_record,
            context="patient-phi",
            usage="in_transit"  # Network transmission
        )

    def process_in_memory(self, patient_record: dict) -> bytes:
        """Process patient data in secure memory."""
        return crypto.encrypt_json(
            patient_record,
            context="patient-phi",
            usage="in_use"  # Memory-safe encryption
        )

    def stream_to_archive(self, records_stream):
        """Stream patient records to archive."""
        for record in records_stream:
            yield crypto.encrypt_json(
                record,
                context="patient-phi",
                usage="streaming"  # Optimized for streams
            )
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
│       Python SDK  |  TypeScript (Soon)  |  REST API         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     CryptoServe Server                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Auth Layer  │  │   Policy    │  │   Crypto Engines    │  │
│  │ JWT / OAuth │  │   Engine    │  │ AES | PQC | Hybrid  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Key Management Layer                       ││
│  │         HKDF | KMS Integration | Key Rotation           ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │                 Audit & Compliance                      ││
│  │        SIEM Export | CBOM | Compliance Reports          ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgreSQL / SQLite / MySQL                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Self-Hosting

### Docker Compose (Recommended)

```bash
git clone https://github.com/ecolibria/crypto-serve.git
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

For production deployments, see the [Production Guide](https://cryptoserve.dev/docs/configuration/).

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
| `/api/v1/pqc/keys/generate` | POST | Generate PQC signing keypair (ML-DSA/SLH-DSA) |
| `/api/v1/pqc/sign` | POST | Sign with PQC algorithm |
| `/api/v1/pqc/verify` | POST | Verify PQC signature |

### Hybrid Key Exchange

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/kex/modes` | GET | List available hybrid KEX modes |
| `/api/v1/kex/keys/generate` | POST | Generate X25519+ML-KEM keypair |
| `/api/v1/kex/keys` | GET | List hybrid KEX keys |
| `/api/v1/kex/keys/{key_id}` | GET | Get hybrid KEX key details |
| `/api/v1/kex/keys/{key_id}` | DELETE | Delete hybrid KEX key |
| `/api/v1/kex/encapsulate` | POST | Create shared secret (sender) |
| `/api/v1/kex/decapsulate` | POST | Recover shared secret (recipient) |

### Health & Monitoring

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Basic health check |
| `/health/ready` | GET | Readiness probe |
| `/health/deep` | GET | Deep health check (all dependencies) |

Full API documentation: [API Reference](https://cryptoserve.dev/docs/api-reference/)

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
| [Quick Start](https://cryptoserve.dev/docs/getting-started/) | Get running in 5 minutes |
| [Architecture](https://cryptoserve.dev/docs/architecture/) | Architecture and context model |
| [SDK Reference](https://cryptoserve.dev/docs/sdk/) | Complete Python SDK documentation |
| [API Reference](https://cryptoserve.dev/docs/api-reference/) | REST API documentation |
| [Security](https://cryptoserve.dev/docs/security/fips/) | FIPS compliance and post-quantum cryptography |
| [Examples](https://cryptoserve.dev/docs/examples/) | Real-world integration patterns |
| [Technical Reference](docs/security/technical-reference.md) | Cryptographic design and threat model |

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

**Report vulnerabilities** to [info@cryptoserve.dev](mailto:info@cryptoserve.dev) or via [GitHub Security Advisories](https://github.com/ecolibria/crypto-serve/security/advisories).

See [SECURITY.md](SECURITY.md) and [Technical Reference](docs/security/technical-reference.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Contact

- **Website:** [https://cryptoserve.dev](https://cryptoserve.dev)
- **Email:** [info@cryptoserve.dev](mailto:info@cryptoserve.dev)
- **GitHub:** [ecolibria/crypto-serve](https://github.com/ecolibria/crypto-serve)

---

<p align="center">
  <sub>Built for developers who need cryptography done right.</sub>
</p>
