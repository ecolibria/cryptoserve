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
CRYPTOSERVE > scan

  Directory            /work/payments-api
  Source files         2
  Files examined       3

Crypto Libraries
  Library                Version    Risk       Algorithms
  ---------------------- ---------- ---------- ------------------------------
  jsonwebtoken           9.0.0      high       RS256, HS256, ES256
  bcrypt                 5.1.0      none       bcrypt
  cryptography           builtin    high       rsa
  node:crypto            builtin    critical   md5, 3des, aes-gcm, csprng

Weak Crypto Patterns
  x RSA-1024: 1024-bit key is below the 2048-bit minimum (CWE-326)
    src/keys.py:4
    *  Fix: Generate keys at 3072 bits or move to ML-KEM / ML-DSA
  x MD5: Collision attacks (CWE-328)
    src/tokens.js:4
    *  Fix: Replace with SHA-256
  !  3DES: Deprecated, Sweet32 attack (CWE-327)
    src/tokens.js:8
    *  Fix: Replace with AES-256-GCM

Source Code Crypto
  Algorithm          Category      Language    Risk      Location
  ------------------ ------------- ----------- --------- ------------------------------
  rsa                encryption    python      high      src/keys.py:4
  rsa-1024           encryption    python      critical  src/keys.py:4
  md5                hashing       javascript  critical  src/tokens.js:4
  3des               encryption    javascript  low       src/tokens.js:8
  aes-gcm            encryption    javascript  none      src/tokens.js:12
  csprng             random        javascript  none      src/tokens.js:12

Summary
  Libraries            4
  Source algorithms    6
  Languages            python, javascript
  Manifests            package.json
  Secrets found        + 0
  Weak patterns        !  3
  Cert/key files       0
```

Scans 6 languages (JavaScript/TypeScript, Go, Python, Java/Kotlin, Rust, C/C++)
against a database of 133 algorithms, 22 of them flagged weak with a named
replacement. Every finding carries `file:line`. Zero npm dependencies. Works
offline.

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

Every published tag attaches a `SHA256SUMS.txt` to its GitHub Release, covering
every wheel, sdist and npm tarball uploaded with it. Entries use bare filenames,
so verification works in whatever directory you download into.

```bash
# Python SDK
gh release download v1.4.3 -R ecolibria/cryptoserve
sha256sum -c SHA256SUMS.txt

# CLI (npm)
gh release download js-v0.4.0 -R ecolibria/cryptoserve
sha256sum -c SHA256SUMS.txt
```

Both publish workflows are triggered by a tag push and refuse to publish when
the tag disagrees with the package version in the tree. npm publishes through
npm Trusted Publishing and PyPI through PyPI Trusted Publishing, both over
OIDC; no registry token exists in either workflow.

Releases from `js-v0.4.0` onward also carry SLSA provenance, and the workflow
fails the release if the published version has no attestation:

```bash
npm view cryptoserve@0.4.0 dist.attestations --json
```

Versions at or before `0.3.4` were published under the previous token-based
workflow and carry no attestations. Verify those with `SHA256SUMS.txt` only.

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
| `cryptoserve census` | Global crypto adoption across 11 package ecosystems plus NVD. Renders the published snapshot from [census.cryptoserve.dev](https://census.cryptoserve.dev), which is a dated measurement rather than a live feed, and shows the collection date. Cached for a day; `--no-cache` re-fetches. |

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
  run: npx cryptoserve gate . --max-risk medium --max-severity low --format sarif --output crypto.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: crypto.sarif
```

Each SARIF result carries the `file:line` that produced it, so findings land on
the right line in the GitHub Security tab and in pull request annotations.

The gate's SARIF describes the gate's decision: the violations that failed this
run at these thresholds, each naming the threshold it breached. A passing gate
uploads no alerts. For every finding in the tree regardless of any threshold,
upload `cryptoserve scan --format sarif` instead.

`--max-risk` bounds quantum risk; `--max-severity` bounds the security severity
`scan` reports. They are separate questions: SHA-256 is quantum `low` and good
practice, unauthenticated CBC has no quantum problem and is a `medium` security
finding. See [docs/cli.md](docs/cli.md#the-two-thresholds-are-different-questions).

Exit codes: `0` gate passed, `1` violations found, `2` the gate could not run
(missing path, unreadable tree, a threshold it cannot enforce). A typo in the
scanned path exits 2 rather than scoring a clean pass.

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

## Configuration

State (master key, vault, cached census data) lives in `~/.cryptoserve` by
default. Two environment variables move it, which is what makes the CLI usable
in CI and in containers without writing into the invoking user's home:

| Variable | Effect |
|---|---|
| `CRYPTOSERVE_HOME` | Absolute path to the state directory. Wins outright. |
| `XDG_CONFIG_HOME` | Uses `$XDG_CONFIG_HOME/cryptoserve` when `CRYPTOSERVE_HOME` is unset. |

```bash
CRYPTOSERVE_HOME=/run/cryptoserve cryptoserve vault init --password "$VAULT_PW"
```

Scanner limits and skip lists come from an optional `.cryptoserve.json` in the
scanned directory. See [docs/cli.md](docs/cli.md).

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
