# CryptoServe CLI (Node.js)

Zero-dependency CLI for cryptographic scanning, post-quantum readiness analysis, CBOM generation, CI/CD gating, encryption, and local key management.

```bash
npx cryptoserve pqc
```

## Installation

```bash
# Run without installing
npx cryptoserve help

# Or install globally
npm install -g cryptoserve
```

Requires Node.js 18 or later. No dependencies — uses only Node.js built-in modules (`node:crypto`, `node:fs`, `node:https`).

## Commands

| Command | Description |
|---------|-------------|
| `scan [path]` | Scan project for crypto libraries, hardcoded secrets, and weak patterns |
| `pqc` | Post-quantum readiness analysis with SNDL risk assessment |
| `cbom [path]` | Generate Cryptographic Bill of Materials (CycloneDX, SPDX, JSON) |
| `gate [path]` | CI/CD quality gate with configurable thresholds |
| `encrypt` / `decrypt` | Password-based encryption (strings and files) |
| `context list` / `show` | List and inspect context-aware algorithm presets |
| `hash-password` | scrypt / PBKDF2 password hashing |
| `vault` | Encrypted local secret storage with env injection |
| `init` | Set up master key + AI tool protection |
| `login` / `status` | Connect to a CryptoServe server |

## Scan

Detect crypto libraries, algorithm usage, hardcoded secrets, and certificate files across multiple languages and ecosystems.

```bash
cryptoserve scan .
cryptoserve scan ./src --format json
cryptoserve scan . --binary          # Include binary crypto detection
```

### Supported Languages

| Language | Extensions | Detection |
|----------|-----------|-----------|
| JavaScript/TypeScript | `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx` | Imports, algorithm literals, weak patterns |
| Go | `.go` | `crypto/*` stdlib, `x/crypto`, `circl` |
| Python | `.py` | `hashlib`, `cryptography`, `PyCryptodome`, `bcrypt` |
| Java/Kotlin | `.java`, `.kt`, `.scala` | `Cipher.getInstance`, `MessageDigest`, `KeyPairGenerator` |
| Rust | `.rs` | `aes-gcm`, `ring`, `ed25519-dalek`, `pqcrypto` |
| C/C++ | `.c`, `.h`, `.cpp`, `.hpp`, `.cc` | OpenSSL `EVP_*`, `RSA_*`, `SHA*_Init` |

### Supported Manifests

| Manifest | Ecosystem |
|----------|-----------|
| `package.json` | npm |
| `go.mod` | Go modules |
| `requirements.txt` | PyPI |
| `pyproject.toml` | PyPI (PEP 621 + Poetry) |
| `Cargo.toml` | Cargo (Rust) |
| `pom.xml` | Maven (Java) |

### Additional Detection

- **TLS/SSL versions** — nginx, Apache, Node.js, Go, Java configs
- **Binary signatures** — AES S-box, DES tables, SHA constants, ChaCha20 sigma (with `--binary`)
- **80+ algorithms** classified by quantum risk, weakness, and category
- **Hardcoded secrets** — AWS, OpenAI, Anthropic, GitHub, Stripe, and more

## PQC Analysis

Offline post-quantum readiness assessment with confidence indicators.

```bash
cryptoserve pqc
cryptoserve pqc --profile healthcare
cryptoserve pqc --profile national_security --verbose
cryptoserve pqc --format json
```

**Profiles:** `general`, `national_security`, `healthcare`, `financial`, `intellectual_property`, `legal`, `authentication`, `session_tokens`, `ephemeral`

Output includes:
- Quantum readiness score (0-100) with confidence level
- Risk breakdown (critical/high/medium/low/safe)
- Migration urgency (immediate/high/medium/low/none)
- SNDL risk assessment
- KEM/signature recommendations (ML-KEM, ML-DSA, SLH-DSA)
- Migration plan with compliance references (CNSA 2.0, NIST SP 800-208, BSI, ANSSI)

## CBOM Generation

Generate a Cryptographic Bill of Materials in industry-standard formats.

```bash
# CycloneDX 1.5 format
cryptoserve cbom . --format cyclonedx --output cbom.json

# SPDX 2.3 format
cryptoserve cbom . --format spdx --output cbom-spdx.json

# Native JSON with quantum readiness data
cryptoserve cbom . --format json --output cbom-native.json

# Print to stdout
cryptoserve cbom .
```

Each CBOM includes:
- All detected crypto components with Package URLs (purls)
- Quantum readiness score and risk assessment
- Git metadata (commit, branch, remote)
- Content hash for integrity verification

## CI/CD Gate

Enforce cryptographic policies in your CI/CD pipeline.

```bash
# Default: fail if quantum risk > high or score < 50
cryptoserve gate .

# Strict: fail on any high-risk algorithm
cryptoserve gate . --max-risk medium

# Fail on weak/deprecated algorithms (MD5, DES, RC4, etc.)
cryptoserve gate . --fail-on-weak

# Custom score threshold
cryptoserve gate . --min-score 70

# JSON output for CI parsing
cryptoserve gate . --format json
```

**Exit codes:** `0` = pass, `1` = fail, `2` = error

**Example GitHub Actions step:**

```yaml
- name: Crypto gate
  run: npx cryptoserve gate . --max-risk high --min-score 50 --fail-on-weak
```

## Encrypt / Decrypt

AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305 encryption with password-based key derivation (scrypt).

```bash
# Text
cryptoserve encrypt "sensitive data" --password mypassword
cryptoserve decrypt "<base64 output>" --password mypassword

# Files
cryptoserve encrypt --file report.pdf --output report.enc --password mypassword
cryptoserve decrypt --file report.enc --output report.pdf --password mypassword

# Choose algorithm
cryptoserve encrypt "data" --algorithm ChaCha20-Poly1305 --password mypassword

# Context-aware (auto-selects algorithm based on data sensitivity)
cryptoserve encrypt "SSN: 123-45-6789" --context user-pii --password mypassword
```

### Cross-SDK Compatibility

The encrypted blob format is byte-identical between the Python and Node.js SDKs. Data encrypted by one can be decrypted by the other:

```
[header_len: 2 bytes][JSON header][ciphertext + auth tag]
```

## Context-Aware Encryption

A 5-layer algorithm resolver selects the optimal encryption algorithm based on data sensitivity, compliance requirements, threat model, and access patterns.

```bash
cryptoserve context list
cryptoserve context show user-pii --verbose
cryptoserve encrypt "patient diagnosis" --context health-data --password mypassword
```

### Built-in Contexts

| Context | Sensitivity | Algorithm | Compliance |
|---------|------------|-----------|------------|
| `user-pii` | High | AES-256-GCM | GDPR |
| `payment-data` | Critical | AES-256-GCM | PCI-DSS |
| `session-tokens` | Medium | AES-128-GCM | OWASP |
| `health-data` | Critical | AES-256-GCM | HIPAA |
| `general` | Medium | AES-128-GCM | — |

### Custom Contexts

Add project-specific contexts in `.cryptoserve.json`:

```json
{
  "contexts": {
    "audit-logs": {
      "displayName": "Audit Logs",
      "sensitivity": "high",
      "compliance": ["SOX"],
      "adversaries": ["insider"],
      "protectionYears": 7,
      "usage": "at_rest",
      "frequency": "high"
    }
  }
}
```

## Password Hashing

```bash
cryptoserve hash-password
cryptoserve hash-password --algorithm pbkdf2
```

Outputs `$scrypt$...` or `$pbkdf2-sha256$...` format strings.

## Vault

Encrypted local secret storage using AES-256-GCM. Secrets are stored at `~/.cryptoserve/vault.enc`.

```bash
cryptoserve vault init
cryptoserve vault set DATABASE_URL "postgres://..."
cryptoserve vault set API_KEY "sk-..."
cryptoserve vault get DATABASE_URL
cryptoserve vault list

# Run a command with secrets injected as environment variables
cryptoserve vault run -- node server.js

# Import from .env file
cryptoserve vault import .env
```

## Init

Set up master key storage and AI tool protection in one command.

```bash
cryptoserve init
```

This generates a master key (stored in OS keychain on macOS/Linux, encrypted file fallback), detects AI coding tools (Claude Code, Cursor, Copilot, Windsurf, Cline, Aider), and configures deny rules to prevent them from reading `.env`, `.pem`, `.key`, and other sensitive files.

## Programmatic Usage

All modules are importable as ES modules:

```javascript
import { encrypt, decrypt, encryptString, decryptString } from 'cryptoserve/lib/local-crypto.mjs';
import { analyzeOffline } from 'cryptoserve/lib/pqc-engine.mjs';
import { scanProject } from 'cryptoserve/lib/scanner.mjs';
import { resolveContext } from 'cryptoserve/lib/context-resolver.mjs';
import { generateCbom, toCycloneDx, toSpdx } from 'cryptoserve/lib/cbom.mjs';
import { ALGORITHM_DB, lookupAlgorithm } from 'cryptoserve/lib/algorithm-db.mjs';
```

## License

Apache-2.0
