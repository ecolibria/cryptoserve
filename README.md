<p align="center">
  <img src="docs/assets/logo.svg" alt="CryptoServe" width="120" height="120">
</p>

<h1 align="center">CryptoServe</h1>

<p align="center">
  <strong>Cryptography-as-a-Service Platform</strong><br>
  Production-grade encryption, scanning, and key management. Post-quantum ready.
</p>

<p align="center">
  <a href="https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ecolibria/cryptoserve/ci.yml?branch=main&style=flat-square&label=build" alt="Build Status"></a>
  <a href="https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-1,380%20passed-brightgreen.svg?style=flat-square" alt="Tests"></a>
  <a href="https://github.com/ecolibria/cryptoserve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://pypi.org/project/cryptoserve/"><img src="https://img.shields.io/pypi/v/cryptoserve.svg?style=flat-square" alt="PyPI"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=flat-square" alt="Python 3.9+"></a>
  <a href="https://cryptoserve.dev/docs/"><img src="https://img.shields.io/badge/docs-cryptoserve.dev-brightgreen.svg?style=flat-square" alt="Documentation"></a>
  <a href="https://ghcr.io/ecolibria/crypto-serve-backend"><img src="https://img.shields.io/badge/ghcr.io-backend-blue.svg?style=flat-square" alt="Backend Image"></a>
  <a href="https://ghcr.io/ecolibria/crypto-serve-frontend"><img src="https://img.shields.io/badge/ghcr.io-frontend-blue.svg?style=flat-square" alt="Frontend Image"></a>
</p>

---

## What is CryptoServe?

CryptoServe is an open-source cryptography platform that provides encryption, signing, hashing, and key management through an SDK, CLI, and REST API. It scans codebases for cryptographic usage, generates Cryptographic Bills of Materials (CBOM), and supports post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA). A 5-layer context model selects algorithms automatically based on data sensitivity, compliance requirements, and threat profile.

## Quick Start

### Install

```bash
pip install cryptoserve
```

### Scan Your Codebase

```bash
cryptoserve scan .                                    # 90+ cryptographic patterns
cryptoserve cbom --format cyclonedx --output cbom.json # Generate CBOM
cryptoserve pqc                                        # PQC readiness assessment
```

### Encrypt Data

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="engineering")
ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

### Offline Encrypt (no server)

```bash
cryptoserve encrypt "secret message" --password mypassword
cryptoserve decrypt "<output>" --password mypassword
```

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Scanning** | 90+ cryptographic patterns, CBOM generation (CycloneDX, SPDX), dependency analysis, SARIF output |
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305, AES-XTS, ECIES, RSA-OAEP |
| **Signing** | Ed25519, ECDSA, RSA-PSS, ML-DSA |
| **Hashing** | SHA-2, SHA-3, BLAKE2b/3, Argon2id, bcrypt, scrypt |
| **Post-Quantum** | ML-KEM-768/1024, ML-DSA-44/65/87, SLH-DSA (FIPS 203/204/205) |
| **Key Management** | Automatic rotation, versioning, HKDF derivation, Shamir secret sharing |
| **Context Model** | 5-layer automatic algorithm selection (sensitivity, compliance, threats, access, technical) |
| **Policy Engine** | Declarative rules, CI/CD gate checks, compliance enforcement |
| **Compliance** | FIPS 140-2/140-3 modes, audit logging, SIEM integration |
| **Multi-Tenant** | Tenant isolation with per-tenant keys and policies |

---

## CLI Tools

The CLI includes offline scanning and crypto tools that work without a server. See the [full CLI reference](docs/cli.md) for all commands and flags.

### Scan and CBOM

```bash
cryptoserve scan .                                    # Scan for crypto patterns
cryptoserve deps .                                     # Dependency crypto analysis
cryptoserve cbom --format cyclonedx -o cbom.json       # Generate CBOM
cryptoserve push cbom.json                             # Upload to dashboard
```

### CI/CD Gate

```bash
cryptoserve gate . --policy strict --format sarif      # Policy enforcement
cryptoserve gate . --staged                            # Pre-commit check
```

### Offline Crypto

```bash
cryptoserve encrypt "data" -p secret                   # Encrypt string
cryptoserve encrypt --file doc.pdf -p secret -o doc.enc # Encrypt file
cryptoserve hash-password "mypassword"                 # scrypt hash
cryptoserve token --key mysecret --payload '{"sub":"u1"}' # JWT
```

### Certificates

```bash
cryptoserve certs generate-csr --cn "example.com"
cryptoserve certs self-signed --cn "localhost" --days 365
cryptoserve certs parse server.pem
```

---

## SDK Usage

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt / Decrypt
ciphertext = crypto.encrypt(b"data", context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")

# Sign / Verify
signature = crypto.sign(b"document", key_id="signing-key")
valid = crypto.verify_signature(b"document", signature, key_id="signing-key")

# Hash
digest = crypto.hash(b"data", algorithm="sha3-256")
```

Runtime usage hints let the platform select optimal algorithms per use case:

```python
crypto.encrypt(data, context="customer-pii", usage="at_rest")    # AES-256-GCM
crypto.encrypt(data, context="customer-pii", usage="streaming")  # ChaCha20-Poly1305
```

See the [Python SDK docs](https://cryptoserve.dev/docs/sdk/) for the full API.

---

## Self-Hosting

### Docker (recommended)

Pre-built images are published to GitHub Container Registry. No clone required.

```bash
# Download the production compose file and example env
curl -O https://raw.githubusercontent.com/ecolibria/crypto-serve/main/docker-compose.production.yml
curl -O https://raw.githubusercontent.com/ecolibria/crypto-serve/main/.env.example
cp .env.example .env
# Edit .env with your secrets (see comments in .env.example)
docker compose -f docker-compose.production.yml up -d
```

Server: `http://localhost:8003` | Dashboard: `http://localhost:3003`

### Build from source

```bash
git clone https://github.com/ecolibria/crypto-serve.git
cd crypto-serve
cp .env.example .env
docker compose up -d
```

The default `.env` runs in dev mode (`DEV_MODE=true`), which bypasses GitHub OAuth for local development. See the [production deployment guide](docs/guides/production-deployment.md) for hardened configuration.

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Getting Started](https://cryptoserve.dev/docs/getting-started/) | Installation and quickstart |
| [CLI Reference](docs/cli.md) | All CLI commands, flags, and examples |
| [Python SDK](https://cryptoserve.dev/docs/sdk/) | SDK reference and examples |
| [API Reference](https://cryptoserve.dev/docs/api-reference/) | REST API documentation |
| [Architecture](https://cryptoserve.dev/docs/concepts/architecture/) | Context model, policy engine, key management |
| [Post-Quantum](https://cryptoserve.dev/docs/concepts/post-quantum/) | ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange |
| [Security](https://cryptoserve.dev/docs/security/) | FIPS compliance, threat model, technical reference |
| [Guides](https://cryptoserve.dev/docs/guides/) | Encryption, key rotation, compliance, PQC migration |

---

## Security

Report vulnerabilities to [info@cryptoserve.dev](mailto:info@cryptoserve.dev) or via [GitHub Security Advisories](https://github.com/ecolibria/cryptoserve/security/advisories).

See [SECURITY.md](SECURITY.md) and [Technical Reference](docs/security/technical-reference.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
