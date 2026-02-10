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
  <a href="https://www.npmjs.com/package/cryptoserve"><img src="https://img.shields.io/npm/v/cryptoserve.svg?style=flat-square" alt="npm"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-18+-blue.svg?style=flat-square" alt="Node.js 18+"></a>
  <a href="https://cryptoserve.dev/docs/"><img src="https://img.shields.io/badge/docs-cryptoserve.dev-brightgreen.svg?style=flat-square" alt="Documentation"></a>
  <a href="https://ghcr.io/ecolibria/crypto-serve"><img src="https://img.shields.io/badge/ghcr.io-all--in--one-blue.svg?style=flat-square" alt="All-in-One Image"></a>
  <a href="https://ghcr.io/ecolibria/crypto-serve-backend"><img src="https://img.shields.io/badge/ghcr.io-backend-blue.svg?style=flat-square" alt="Backend Image"></a>
  <a href="https://ghcr.io/ecolibria/crypto-serve-frontend"><img src="https://img.shields.io/badge/ghcr.io-frontend-blue.svg?style=flat-square" alt="Frontend Image"></a>
</p>

---

## What is CryptoServe?

**CLI and SDK** — available as `npx cryptoserve` (Node.js, zero dependencies) or `pip install cryptoserve` (Python). Standalone toolchain for cryptographic scanning across 6 languages, CBOM generation (CycloneDX, SPDX), 80+ algorithm database with quantum risk classification, offline encryption/decryption, password hashing, certificate management, and CI/CD policy gates. No server required. Supports post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA).

**Platform** — the self-hosted server adds centralized key management with automatic rotation and HSM/KMS backends, a 5-layer context model for automatic algorithm selection, a declarative policy engine, multi-tenant isolation, audit logging with SIEM integration, FIPS 140-2/3 compliance modes, and a dashboard for security posture and quantum readiness.

## Quick Start

### Install

```bash
# Node.js (zero dependencies, requires Node 18+)
npx cryptoserve help
npm install -g cryptoserve

# Python
pip install cryptoserve
```

### Scan Your Codebase

```bash
cryptoserve scan .                                     # 6 languages, 80+ algorithms
cryptoserve scan . --binary                            # Include binary signature detection
cryptoserve cbom --format cyclonedx --output cbom.json # Generate CBOM
cryptoserve pqc                                        # PQC readiness assessment
cryptoserve gate . --fail-on-weak                      # CI/CD quality gate
```

### Supported Languages

| Language | Manifest | Source Detection |
|----------|----------|-----------------|
| JavaScript/TypeScript | `package.json` | Imports, algorithm literals, weak patterns |
| Go | `go.mod` | `crypto/*` stdlib, `x/crypto`, `circl` |
| Python | `requirements.txt`, `pyproject.toml` | `hashlib`, `cryptography`, `PyCryptodome` |
| Java/Kotlin | `pom.xml` | `Cipher.getInstance`, `MessageDigest`, `KeyPairGenerator` |
| Rust | `Cargo.toml` | `aes-gcm`, `ring`, `ed25519-dalek`, `pqcrypto` |
| C/C++ | — | OpenSSL `EVP_*`, `RSA_*`, `SHA*_Init` |

### Offline Crypto (no server)

```bash
cryptoserve encrypt "secret message" --password mypassword
cryptoserve decrypt "<output>" --password mypassword
cryptoserve hash-password "mypassword"                 # scrypt hash
```

---

## CLI Reference

All CLI commands work offline. No server required. See the [full CLI reference](docs/cli.md) for all flags and examples.

| Command | Description |
|---------|-------------|
| `scan` | Scan for crypto libraries, algorithms, secrets, and TLS configs |
| `deps` | Dependency crypto analysis |
| `cbom` | Generate CBOM (CycloneDX, SPDX) |
| `pqc` | Post-quantum readiness assessment |
| `gate` | CI/CD policy enforcement (`--max-risk`, `--min-score`, `--fail-on-weak`) |
| `push` | Upload CBOM to dashboard |
| `encrypt` / `decrypt` | Password-based encryption (strings and files) |
| `hash-password` | scrypt / PBKDF2 password hashing |
| `token` | Generate JWT tokens |
| `certs` | CSR generation, self-signed certs, certificate parsing |

---

## SDK Usage

### Node.js SDK

Zero-dependency ES module SDK. All modules importable directly:

```javascript
import { scanProject } from 'cryptoserve/lib/scanner.mjs';
import { analyzeOffline } from 'cryptoserve/lib/pqc-engine.mjs';
import { generateCbom, toCycloneDx, toSpdx } from 'cryptoserve/lib/cbom.mjs';
import { encrypt, decrypt } from 'cryptoserve/lib/local-crypto.mjs';
import { ALGORITHM_DB, lookupAlgorithm } from 'cryptoserve/lib/algorithm-db.mjs';
```

See the [Node.js SDK README](sdk/javascript/README.md) for the full API.

### Python SDK

The Python SDK connects to a running CryptoServe server for managed keys and context-aware algorithm selection.

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

See the [Python SDK docs](docs/sdk/python.md) for the full API.

---

## Platform

The self-hosted server extends the CLI with centralized management, policy enforcement, and compliance features.

| Feature | Description |
|---------|-------------|
| **Key Management** | Automatic rotation, versioning, HKDF derivation, Shamir secret sharing, HSM/KMS backends |
| **Context Model** | 5-layer algorithm selection based on sensitivity, compliance, threats, access patterns, and technical constraints |
| **Policy Engine** | Declarative rules, CI/CD gate checks, compliance enforcement |
| **Multi-Tenancy** | Per-tenant isolation with separate keys and policies |
| **Audit & Compliance** | Operation logging, SIEM integration, FIPS 140-2/3 modes |
| **Dashboard** | Security posture overview, quantum readiness, migration advisor |
| **Identity & RBAC** | OAuth (GitHub/Google/Azure/Okta), role-based access, SDK token management |
| **Algorithms** | AES-256-GCM, ChaCha20-Poly1305, AES-XTS, ECIES, RSA-OAEP, Ed25519, ECDSA, RSA-PSS, ML-DSA, SHA-2/3, BLAKE2b/3, Argon2id, bcrypt, ML-KEM-768/1024, ML-DSA-44/65/87, SLH-DSA |

---

## Self-Hosting

### Docker (single container)

```bash
docker run -d -p 8003:8003 -p 3000:3000 -v cryptoserve-data:/data ghcr.io/ecolibria/crypto-serve
```

API: `http://localhost:8003` | Dashboard: `http://localhost:3000`

Uses SQLite and dev mode for zero-config startup. Mount `/data` to persist the database across restarts. For production deployments with PostgreSQL, use the multi-container setup below.

### Quickstart script (multi-container)

```bash
curl -fsSL https://raw.githubusercontent.com/ecolibria/crypto-serve/main/scripts/quickstart.sh | sh
```

This downloads the compose file, generates random secrets, pulls pre-built images from GHCR, and starts the stack (PostgreSQL + backend + frontend). No clone required.

API: `http://localhost:8003` | Dashboard: `http://localhost:3003`

Configuration is in `cryptoserve/.env`. Edit it to add GitHub OAuth, switch to production mode, or change ports.

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
| [Getting Started](docs/getting-started/index.md) | Installation and quickstart |
| [CLI Reference](docs/cli.md) | All CLI commands, flags, and examples |
| [Python SDK](docs/sdk/index.md) | SDK reference and examples |
| [API Reference](docs/api-reference/index.md) | REST API documentation |
| [Architecture](docs/concepts/architecture.md) | Context model, policy engine, key management |
| [Post-Quantum](docs/concepts/post-quantum.md) | ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange |
| [Security](docs/security/index.md) | FIPS compliance, threat model, technical reference |
| [Guides](docs/guides/index.md) | Encryption, key rotation, compliance, PQC migration |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ecolibria/cryptoserve/security/advisories).

See [SECURITY.md](SECURITY.md) and [Technical Reference](docs/security/technical-reference.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
