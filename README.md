<img src="docs/assets/logo.svg" alt="" width="64" height="64" align="left">

# cryptoserve

Cryptographic toolchain for codebases. Scans for weak crypto, generates CBOMs, enforces CI gates, encrypts files, and assesses post-quantum readiness. Works offline. Apache 2.0.

[![Build](https://img.shields.io/github/actions/workflow/status/ecolibria/cryptoserve/ci.yml?branch=main&label=build)](https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/cryptoserve.svg?label=npm)](https://www.npmjs.com/package/cryptoserve)
[![PyPI](https://img.shields.io/pypi/v/cryptoserve.svg?label=pypi)](https://pypi.org/project/cryptoserve/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Website](https://cryptoserve.dev) · [Crypto Census](https://census.cryptoserve.dev) · [Docs](https://cryptoserve.dev/docs/) · [SDK](#sdks) · [Self-host](#self-host-optional)

## Quick start

```bash
npx cryptoserve scan .
```

```
  CryptoServe scan: .

  Found
  ---------------------------------------------------
  Crypto libraries        4
  Source algorithms       3   (1 weak: MD5)
  Hardcoded secrets       1
  ---------------------------------------------------
  Quantum readiness    40 / 100   (2 quantum-vulnerable)

  Next: cryptoserve pqc            (migration plan)
        cryptoserve cbom           (export CBOM)
        cryptoserve gate .         (block weak crypto in CI)
```

Scans 6 languages (JavaScript/TypeScript, Go, Python, Java/Kotlin, Rust, C/C++) against a database of 131 algorithms. Zero npm dependencies. Works offline.

## Install

```bash
npx cryptoserve scan .          # run once, no install
npm install -g cryptoserve      # install globally (Node 18+)
pip install cryptoserve         # Python SDK + CLI alias
```

### From source

```bash
git clone https://github.com/ecolibria/cryptoserve.git
cd cryptoserve
node sdk/javascript/bin/cryptoserve.mjs scan .   # JS CLI, no build step
```

The Python SDK lives under `sdk/python/` (editable install via `pip install -e sdk/python`).

## Verifying releases

Every published tag carries a `SHA256SUMS.txt` attached to the GitHub Release. Wheels and tarballs match those hashes; npm tarballs match `dist.shasum` from the registry.

```bash
# Python wheel
gh release download v1.4.3 -p SHA256SUMS.txt -R ecolibria/cryptoserve
sha256sum -c SHA256SUMS.txt

# npm tarball
npm view cryptoserve@0.3.4 dist.shasum dist.tarball
```

The npm and PyPI publish workflows run from a fixed-tag trigger with `id-token: write` and `--provenance`. SLSA provenance attestations and Sigstore signatures are scaffolded in the workflows but not yet propagated to released artifacts; until that ships, verify via `SHA256SUMS.txt`.

## Which command do I want

| You want to... | Command |
|---|---|
| See what crypto is in this project | `cryptoserve scan .` |
| Score post-quantum readiness and get a migration plan | `cryptoserve pqc` |
| Generate a Cryptographic Bill of Materials | `cryptoserve cbom --format cyclonedx` |
| Block weak crypto in CI | `cryptoserve gate . --fail-on-weak` |
| Encrypt a file or string offline | `cryptoserve encrypt --file data.csv --password $SECRET` |
| Hash a password (scrypt / pbkdf2 / argon2) | `cryptoserve hash-password --algorithm argon2` |
| Store secrets in an encrypted local vault | `cryptoserve vault set API_KEY <value>` |
| See what cryptography the open-source ecosystem uses | `cryptoserve census` |

Run `cryptoserve help` or `cryptoserve <command> --help` for full flags.

## Commands

### Assess

| Command | What it does |
|---|---|
| `cryptoserve scan [path]` | Find every crypto library, algorithm, weak pattern, and hardcoded secret in the tree. JSON or table output. |
| `cryptoserve pqc` | Quantum-readiness score with SNDL (Store Now, Decrypt Later) analysis and NIST-aligned migration guidance. |
| `cryptoserve cbom [path] --format <fmt>` | Export a CBOM in CycloneDX or SPDX. |
| `cryptoserve gate [path]` | CI/CD quality gate. Non-zero exit on weak algorithms or thresholds failing. SARIF for the GitHub Security tab. |
| `cryptoserve census` | Global crypto adoption across 11 package ecosystems plus NVD. Live dashboard at [census.cryptoserve.dev](https://census.cryptoserve.dev). |

### Encrypt

| Command | What it does |
|---|---|
| `cryptoserve encrypt "text"` | Context-aware encryption. `--context <name>` picks an algorithm per the policy model; `--password` does pure-password mode. |
| `cryptoserve encrypt --file F --output O` | Encrypt a file in place or to a new path. |
| `cryptoserve decrypt ...` | Inverse of `encrypt`. Same flags. |
| `cryptoserve hash-password` | scrypt by default; `--algorithm argon2` if `cryptoserve[password]` is installed. Non-interactive `--password` for CI. |
| `cryptoserve context list` | Available encryption contexts and the algorithm each resolves to. |

### Vault

| Command | What it does |
|---|---|
| `cryptoserve vault init` | Create an encrypted local secret store. |
| `cryptoserve vault set/get/list/delete` | CRUD against the vault. |
| `cryptoserve vault run -- <cmd>` | Run a subprocess with vault entries injected as env vars. |
| `cryptoserve vault import .env` | Import an existing `.env` file. |

### Operate

| Command | What it does |
|---|---|
| `cryptoserve init` | One-shot setup: master key, default vault, AI-tool integration. |
| `cryptoserve login [--server URL]` | Authenticate against a self-hosted CryptoServe server. |
| `cryptoserve status` | Configuration, server reachability, vault state. |
| `cryptoserve version` | Build version. |

Full reference: [docs/cli.md](docs/cli.md).

## CI/CD

```yaml
- name: Crypto gate
  run: npx cryptoserve gate . --fail-on-weak --max-risk medium --format sarif --output crypto.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: crypto.sarif
```

Exit codes: `0` clean / gate passed, `1` failures found or invalid input.

## SDKs

### Node.js (offline, zero dependencies)

```javascript
import { scanProject } from 'cryptoserve/lib/scanner.mjs';
import { analyzeOffline } from 'cryptoserve/lib/pqc-engine.mjs';
import { generateCbom, toCycloneDx } from 'cryptoserve/lib/cbom.mjs';
import { encrypt, decrypt } from 'cryptoserve/lib/local-crypto.mjs';
```

Full reference: [sdk/javascript/README.md](sdk/javascript/README.md).

### Python (server-connected, local fallback)

```bash
pip install cryptoserve              # core + client
pip install cryptoserve[password]    # adds argon2
```

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")
ciphertext = crypto.encrypt(b"data", context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")
```

Local mode works without a server. Full reference: [docs/sdk/python.md](docs/sdk/python.md).

## Self-host (optional)

The CLI and SDKs work fully offline. The self-hosted server adds centralized key management, policy enforcement, audit logging, and a dashboard.

```bash
docker run -d -p 8003:8003 -p 3000:3000 -v cryptoserve-data:/data ghcr.io/ecolibria/crypto-serve
```

API on `:8003`, dashboard on `:3000`. For production (Postgres + frontend + backend, generated secrets), see [docs/guides/production-deployment.md](docs/guides/production-deployment.md). Don't pipe `curl | sh`; download `scripts/quickstart.sh`, compare `shasum` against release notes, then execute.

Capabilities: automatic key rotation and versioning, HKDF derivation, Shamir secret sharing, HSM/KMS backends, 5-layer context model, declarative policies, OAuth (GitHub/Google/Azure/Okta), RBAC, FIPS 140-2/3 modes, SIEM forwarding.

## Documentation

| Resource | What's there |
|---|---|
| [Getting started](docs/getting-started/index.md) | Install and first scan. |
| [CLI reference](docs/cli.md) | Every command and flag. |
| [Architecture](docs/concepts/architecture.md) | Context model, policy engine, key management. |
| [Post-quantum](docs/concepts/post-quantum.md) | ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange. |
| [Python SDK](docs/sdk/index.md) | API and examples. |
| [REST API](docs/api-reference/index.md) | Server endpoints. |
| [Security](docs/security/index.md) | Threat model, FIPS compliance, transparency. |

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ecolibria/cryptoserve/security/advisories). See [SECURITY.md](SECURITY.md).

## Contributing

Apache 2.0. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, test conventions, and pre-push review gates.

```bash
git clone https://github.com/ecolibria/cryptoserve.git
cd cryptoserve && npm test
```

## License

Apache 2.0. See [LICENSE](LICENSE).
