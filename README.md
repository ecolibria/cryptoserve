<p align="center">
  <img src="docs/assets/logo.svg" alt="CryptoServe" width="120" height="120">
</p>

<h1 align="center">CryptoServe</h1>

<p align="center">
  <strong>Cryptography-as-a-Service Platform</strong><br>
  Encrypt, sign, and hash data with zero configuration. Post-quantum ready.
</p>

<p align="center">
  <a href="https://github.com/keytum/crypto-serve/actions"><img src="https://img.shields.io/github/actions/workflow/status/keytum/crypto-serve/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="https://github.com/keytum/crypto-serve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square" alt="Python 3.10+"></a>
  <a href="https://keytum.github.io/crypto-serve/"><img src="https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat-square" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#get-started-in-60-seconds">Get Started</a> •
  <a href="https://keytum.github.io/crypto-serve/">Documentation</a> •
  <a href="https://keytum.github.io/crypto-serve/api-reference/">API Reference</a> •
  <a href="https://keytum.github.io/crypto-serve/security/whitepaper/">Security Whitepaper</a>
</p>

---

## Get Started in 60 Seconds

### Prerequisites

- Docker and Docker Compose
- Python 3.10+
- A GitHub account

### Step 1: Clone and Start the Server

```bash
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve
cp .env.example .env
docker compose up -d
```

The server is now running at `http://localhost:8001` and the dashboard at `http://localhost:3001`.

### Step 2: Install the SDK and Login

```bash
pip install cryptoserve
cryptoserve login
```

This opens your browser for GitHub authentication. Your credentials are stored securely in `~/.cryptoserve/`.

### Step 3: Start Encrypting

Create a file called `example.py`:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="engineering")

# Encrypt
plaintext = b"Hello, World!"
ciphertext = crypto.encrypt(plaintext, context="default")

# Decrypt
decrypted = crypto.decrypt(ciphertext, context="default")

print(decrypted)  # b"Hello, World!"
```

Run it:

```bash
python example.py
```

That's it. Your app is automatically registered and ready to use.

---

## Why CryptoServe?

| Without CryptoServe | With CryptoServe |
|---------------------|------------------|
| Configure cryptographic libraries | `pip install cryptoserve` |
| Generate and store encryption keys | Keys managed automatically |
| Implement key rotation logic | Automatic key rotation |
| Build compliance audit trails | Full audit logging built-in |
| Plan for post-quantum migration | PQC algorithms ready to use |

---

## SDK Reference

### Installation

```bash
pip install cryptoserve
```

### Initialization

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(
    app_name="my-service",       # Required: unique identifier for your app
    team="platform",             # Optional: team name (default: "default")
    environment="production",    # Optional: environment (default: "development")
    contexts=["user-pii"],       # Optional: encryption contexts to use
)
```

### Encrypt and Decrypt

```python
# Encrypt bytes
ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

# Decrypt bytes
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

### Sign and Verify

```python
# Sign data
signature = crypto.sign(b"document content", key_id="signing-key")

# Verify signature
is_valid = crypto.verify_signature(b"document content", signature, key_id="signing-key")
```

### Hash

```python
# SHA-256 (default)
hash_hex = crypto.hash(b"data to hash")

# Other algorithms: sha384, sha512, sha3-256, blake2b
hash_hex = crypto.hash(b"data", algorithm="sha512")
```

### MAC (Message Authentication Code)

```python
secret_key = b"my-secret-key-32-bytes-long!!!!!"
mac_hex = crypto.mac(b"message", key=secret_key)
```

### Health Check

```python
if crypto.health_check():
    print("Connected to CryptoServe")
```

---

## Features

### Supported Algorithms

| Category | Algorithms |
|----------|------------|
| Symmetric Encryption | AES-256-GCM (default), AES-128-GCM, ChaCha20-Poly1305 |
| Hash Functions | SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b |
| Post-Quantum | ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87 |
| Hybrid Modes | AES-256-GCM + ML-KEM-768 |

### Community Dashboard

Access the web dashboard at `http://localhost:3001` to:

- View registered applications
- Monitor encryption/decryption usage
- Manage encryption contexts
- Configure algorithm policies
- Review audit logs
- Scan for cryptographic vulnerabilities (CBOM)

### Enterprise Features

- **FIPS 140-2/140-3 compliance modes**
- **Multi-tenant isolation**
- **Key rotation with zero downtime**
- **Complete audit trail**
- **Policy engine for compliance enforcement**

---

## Self-Hosting

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve
cp .env.example .env
```

Edit `.env` with your configuration:

```bash
# Required: GitHub OAuth (create at https://github.com/settings/developers)
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret

# Required: Security keys (generate with: openssl rand -hex 32)
CRYPTOSERVE_MASTER_KEY=your-32-byte-hex-key
JWT_SECRET_KEY=your-jwt-secret-key

# Optional
DATABASE_URL=sqlite:///./cryptoserve.db
FIPS_MODE=disabled
```

Start the services:

```bash
docker compose up -d
```

### Manual Installation

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8001

# Frontend (separate terminal)
cd frontend
npm install
npm run build
npm start
```

---

## GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Fill in:
   - **Application name:** CryptoServe
   - **Homepage URL:** `http://localhost:3001`
   - **Authorization callback URL:** `http://localhost:8001/auth/github/callback`
4. Click **Register application**
5. Copy **Client ID** and generate a **Client Secret**
6. Add to your `.env` file

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                       │
│                      (Python SDK)                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     CryptoServe Server                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Auth Layer  │  │ Policy      │  │ Crypto Engine       │  │
│  │ (JWT/OAuth) │  │ Engine      │  │ (AES, PQC, Hybrid)  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Key Management (HKDF / KMS)                ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  PostgreSQL / SQLite                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Quick Start](https://keytum.github.io/crypto-serve/getting-started/quickstart/) | Get running in 5 minutes |
| [SDK Reference](https://keytum.github.io/crypto-serve/sdk/python/) | Complete Python SDK documentation |
| [API Reference](https://keytum.github.io/crypto-serve/api-reference/) | REST API documentation |
| [Security Whitepaper](https://keytum.github.io/crypto-serve/security/whitepaper/) | Cryptographic design and threat model |
| [Concepts](https://keytum.github.io/crypto-serve/concepts/) | Architecture and key management |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run tests
cd backend
pytest -v

# Run with coverage
pytest --cov=app --cov-report=term-missing
```

---

## Security

Report security vulnerabilities to **security@cryptoserve.io** or via [GitHub Security Advisories](https://github.com/keytum/crypto-serve/security/advisories).

See our [Security Policy](SECURITY.md) and [Security Whitepaper](https://keytum.github.io/crypto-serve/security/whitepaper/) for details.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built for developers who need encryption done right.</sub>
</p>
