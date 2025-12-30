# CryptoServe

Zero-config cryptographic operations server with personalized SDK distribution.

## What is CryptoServe?

CryptoServe lets developers use encryption without hardcoding cryptography. Download a personalized SDK with your identity baked in, then just import and use:

```python
from cryptoserve import crypto

# That's it. No config needed.
ciphertext = crypto.encrypt(data, context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

## Features

- **Zero Configuration** — SDK works immediately after import
- **Personalized SDKs** — Identity embedded in the package
- **5-Layer Context Model** — Intelligent algorithm selection based on data sensitivity, compliance, and threat model
- **Policy Engine** — Customizable rules to enforce cryptographic standards
- **Full Audit Trail** — Every operation logged with identity
- **Admin Dashboard** — User management, analytics, and compliance reporting
- **Self-Service Dashboard** — Sign in with GitHub, create identities, download SDKs

## Quick Start

### 1. Start the server

```bash
# Clone the repo
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve

# Copy environment file
cp .env.example .env
# Edit .env with your GitHub OAuth credentials

# Start with Docker Compose
docker compose up -d
```

### 2. Create an identity

1. Open http://localhost:3001
2. Sign in with GitHub
3. Click "Create New Identity"
4. Select your team, environment, and contexts
5. Copy the install command

### 3. Install and use the SDK

```bash
pip install http://localhost:8001/sdk/download/YOUR_TOKEN/python
```

```python
from cryptoserve import crypto

# Encrypt
encrypted = crypto.encrypt_string("sensitive data", context="user-pii")

# Decrypt
decrypted = crypto.decrypt_string(encrypted, context="user-pii")
```

## Configuration

### Environment Variables

Create a `.env` file with:

```bash
# GitHub OAuth (required)
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret

# Security (generate for production)
CRYPTOSERVE_MASTER_KEY=your-master-key
JWT_SECRET_KEY=your-jwt-secret

# URLs
FRONTEND_URL=http://localhost:3001
BACKEND_URL=http://localhost:8001
```

### GitHub OAuth Setup

1. Go to https://github.com/settings/developers
2. Create a new OAuth App
3. Set Homepage URL to `http://localhost:3001`
4. Set Callback URL to `http://localhost:8001/auth/github/callback`
5. Copy Client ID and Secret to `.env`

## 5-Layer Context Model

Each context in CryptoServe uses a 5-layer model to automatically select the optimal cryptographic algorithm:

| Layer | Purpose | Example |
|-------|---------|---------|
| **Data Identity** | Sensitivity and data classification | PII, PHI, PCI |
| **Regulatory** | Compliance frameworks | HIPAA, GDPR, PCI-DSS |
| **Threat Model** | Attack vectors and protection duration | Quantum threats, protection lifetime |
| **Access Patterns** | Usage characteristics | Frequency, latency requirements |
| **Technical** | Infrastructure constraints | Hardware acceleration, key sizes |

The system evaluates all 5 layers and automatically selects the best algorithm:

```python
# AES-256-GCM for high-sensitivity PII
crypto.encrypt(data, context="user-pii")

# ChaCha20-Poly1305 for high-frequency session data
crypto.encrypt(data, context="session-tokens")
```

## Policy Engine

CryptoServe includes a policy engine that enforces cryptographic standards at runtime:

```python
# Example policies
- "Require 256-bit encryption for critical data"
- "Block deprecated algorithms (DES, 3DES, RC4)"
- "Warn about non-quantum-resistant algorithms for long-term data"
- "Enforce HIPAA-compliant encryption for health data"
```

Policies support three severity levels:
- **block** — Reject the operation
- **warn** — Allow but log a warning
- **info** — Informational only

Test policies in the web dashboard before deployment.

## Available Contexts

Contexts define encryption policies. Default contexts:

| Context | Description | Compliance |
|---------|-------------|------------|
| `user-pii` | Personal identifiable information | GDPR, CCPA |
| `payment-data` | Payment card data | PCI-DSS |
| `session-tokens` | Auth tokens and sessions | - |
| `health-data` | Medical records | HIPAA |
| `general` | General purpose | - |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Frontend                           │
│              (Next.js 14 + shadcn/ui)                  │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                      Backend                            │
│                     (FastAPI)                           │
│                                                         │
│  • GitHub OAuth    • Crypto Engine   • SDK Generator   │
│  • Identity API    • Audit Logging   • Key Management  │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    PostgreSQL                           │
└─────────────────────────────────────────────────────────┘
```

## Development

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### SDK

```bash
cd sdk/python
pip install -e .
```

## API Reference

### Crypto Operations

```
POST /v1/crypto/encrypt
POST /v1/crypto/decrypt
```

### Identity Management

```
GET    /api/identities       # List identities
POST   /api/identities       # Create identity
DELETE /api/identities/{id}  # Revoke identity
```

### Contexts

```
GET  /api/contexts       # List contexts
POST /api/contexts       # Create context
```

### Policies

```
GET  /api/policies           # List policies
GET  /api/policies/defaults  # Get default policies
POST /api/policies/evaluate  # Test policy evaluation
```

### Admin (requires admin role)

```
GET  /api/admin/dashboard         # Dashboard stats
GET  /api/admin/users             # List all users
GET  /api/admin/identities        # List all identities
GET  /api/admin/audit/global      # Global audit logs
GET  /api/admin/audit/export      # Export audit logs
GET  /api/admin/contexts          # Contexts with stats
POST /api/admin/contexts/{name}/rotate-key  # Rotate encryption key
GET  /api/admin/analytics/trends  # Usage trends
GET  /api/admin/analytics/teams   # Team usage breakdown
GET  /api/admin/health            # System health
```

### SDK Download

```
GET /sdk/download/{token}/python  # Download Python SDK
```

## Security

- All crypto operations use AES-256-GCM
- Keys derived from master key using HKDF-SHA256
- Identity tokens are signed JWTs
- All operations logged for audit

## License

Apache License 2.0
