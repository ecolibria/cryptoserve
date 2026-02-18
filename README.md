<p align="center">
  <img src="docs/assets/logo.svg" alt="CryptoServe" width="120" height="120">
</p>

<h1 align="center">CryptoServe</h1>

<p align="center">
  <strong>Scan your code for cryptographic risk. Get quantum-ready.</strong>
</p>

<p align="center">
  <a href="https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ecolibria/cryptoserve/ci.yml?branch=main&style=flat-square&label=build" alt="Build Status"></a>
  <a href="https://github.com/ecolibria/cryptoserve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://pypi.org/project/cryptoserve/"><img src="https://img.shields.io/pypi/v/cryptoserve.svg?style=flat-square" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/cryptoserve"><img src="https://img.shields.io/npm/v/cryptoserve.svg?style=flat-square" alt="npm"></a>
</p>

---

## Try It Now

```bash
npx cryptoserve scan .
```

That's it. Scans your project for cryptographic libraries, algorithms, weak patterns, and hardcoded secrets across 6 languages. No config, no server, no dependencies.

```
Found 4 crypto libraries, 3 source algorithms, 1 weak pattern
Quantum readiness: 40/100 (2 quantum-vulnerable algorithms)
```

## Install

```bash
# Node.js (zero dependencies, Node 18+)
npm install -g cryptoserve

# Python
pip install cryptoserve
```

## What It Does

**Scan** -- Find every cryptographic dependency, algorithm, weak pattern, and hardcoded secret in your codebase. Supports JavaScript/TypeScript, Go, Python, Java/Kotlin, Rust, and C/C++.

**Assess** -- Get a quantum readiness score with SNDL (Store Now, Decrypt Later) risk analysis and migration recommendations based on NIST FIPS 203/204/205 standards.

**Generate** -- Export a Cryptographic Bill of Materials (CBOM) in CycloneDX or SPDX format for supply chain compliance.

**Enforce** -- Add `cryptoserve gate` to your CI pipeline to block builds that use weak algorithms or fail quantum readiness thresholds.

## Common Commands

```bash
cryptoserve scan .                          # Scan project (6 languages, 80+ algorithms)
cryptoserve scan . --binary                 # Include binary signature detection
cryptoserve pqc                             # Post-quantum readiness assessment
cryptoserve cbom --format cyclonedx         # Generate CBOM
cryptoserve gate . --fail-on-weak           # CI/CD quality gate
cryptoserve encrypt "secret" -p mypassword  # Offline encryption
cryptoserve hash-password "mypassword"      # Password hashing (scrypt)
```

See the [full CLI reference](docs/cli.md) for all commands and flags.

## Supported Languages

| Language | Manifest | Source Detection |
|----------|----------|-----------------|
| JavaScript/TypeScript | `package.json` | Imports, algorithm literals, weak patterns |
| Go | `go.mod` | `crypto/*` stdlib, `x/crypto`, `circl` |
| Python | `requirements.txt`, `pyproject.toml` | `hashlib`, `cryptography`, `PyCryptodome` |
| Java/Kotlin | `pom.xml` | `Cipher.getInstance`, `MessageDigest`, `KeyPairGenerator` |
| Rust | `Cargo.toml` | `aes-gcm`, `ring`, `ed25519-dalek`, `pqcrypto` |
| C/C++ | -- | OpenSSL `EVP_*`, `RSA_*`, `SHA*_Init` |

## CI/CD Integration

Add to any CI pipeline:

```yaml
- name: Crypto gate
  run: npx cryptoserve gate . --fail-on-weak --max-risk medium --format sarif
```

The `gate` command exits non-zero when violations are found. Use `--format sarif` to upload results to GitHub's Security tab.

---

## SDK Usage

### Node.js

Zero-dependency ES module SDK. Import individual modules:

```javascript
import { scanProject } from 'cryptoserve/lib/scanner.mjs';
import { analyzeOffline } from 'cryptoserve/lib/pqc-engine.mjs';
import { generateCbom, toCycloneDx } from 'cryptoserve/lib/cbom.mjs';
import { encrypt, decrypt } from 'cryptoserve/lib/local-crypto.mjs';
```

See the [Node.js SDK README](sdk/javascript/README.md).

### Python

The Python SDK adds managed key management and context-aware algorithm selection when connected to a CryptoServe server:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

ciphertext = crypto.encrypt(b"data", context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

See the [Python SDK docs](docs/sdk/python.md).

---

## Self-Hosted Platform

The optional server adds centralized key management, policy enforcement, and a dashboard. The CLI works fully standalone without it.

### Quick start

```bash
docker run -d -p 8003:8003 -p 3000:3000 -v cryptoserve-data:/data ghcr.io/ecolibria/crypto-serve
```

API: `http://localhost:8003` | Dashboard: `http://localhost:3000`

### Multi-container (production)

```bash
curl -fsSL https://raw.githubusercontent.com/ecolibria/crypto-serve/main/scripts/quickstart.sh | sh
```

Downloads the compose file, generates secrets, and starts PostgreSQL + backend + frontend. See the [production deployment guide](docs/guides/production-deployment.md).

### Platform features

| Feature | Description |
|---------|-------------|
| **Key Management** | Automatic rotation, versioning, HKDF derivation, Shamir secret sharing, HSM/KMS backends |
| **Context Model** | 5-layer algorithm selection: sensitivity, compliance, threats, access patterns, constraints |
| **Policy Engine** | Declarative rules with CI/CD gate enforcement |
| **Multi-Tenancy** | Per-tenant isolation with separate keys and policies |
| **Audit & Compliance** | SIEM integration, FIPS 140-2/3 modes |
| **Identity** | OAuth (GitHub/Google/Azure/Okta), RBAC, SDK token management |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Getting Started](docs/getting-started/index.md) | Installation and quickstart |
| [CLI Reference](docs/cli.md) | All commands, flags, and examples |
| [Python SDK](docs/sdk/index.md) | SDK reference |
| [API Reference](docs/api-reference/index.md) | REST API |
| [Architecture](docs/concepts/architecture.md) | Context model, policy engine, key management |
| [Post-Quantum](docs/concepts/post-quantum.md) | ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange |
| [Security](docs/security/index.md) | FIPS compliance, threat model |

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ecolibria/cryptoserve/security/advisories). See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
