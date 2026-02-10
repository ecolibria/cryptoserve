# CryptoServe CLI (Node.js)

Zero-dependency CLI for cryptographic scanning, post-quantum readiness analysis, encryption, and local key management.

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
| `encrypt` / `decrypt` | Password-based encryption (strings and files) |
| `context list` / `show` | List and inspect context-aware algorithm presets |
| `hash-password` | scrypt / PBKDF2 password hashing |
| `vault` | Encrypted local secret storage with env injection |
| `init` | Set up master key + AI tool protection |
| `login` / `status` | Connect to a CryptoServe server |

## Scan

Detect crypto libraries, algorithm usage, hardcoded secrets, and certificate files in JavaScript/TypeScript projects.

```bash
cryptoserve scan .
cryptoserve scan ./src --format json
```

Detects 20+ crypto packages (`jsonwebtoken`, `node-forge`, `@noble/curves`, etc.), `node:crypto` API usage, algorithm string literals, weak patterns (MD5, DES, ECB, `createCipher`), and hardcoded API keys (AWS, OpenAI, Anthropic, GitHub, Stripe, and more).

## PQC Analysis

Offline post-quantum readiness assessment. Evaluates your project's cryptographic posture against quantum threat timelines.

```bash
cryptoserve pqc
cryptoserve pqc --profile healthcare
cryptoserve pqc --profile national_security --verbose
cryptoserve pqc --format json
```

**Profiles:** `general`, `national_security`, `healthcare`, `financial`, `intellectual_property`, `legal`, `authentication`, `session_tokens`, `ephemeral`

Output includes quantum readiness score (0-100), SNDL risk assessment, KEM/signature recommendations (ML-KEM, ML-DSA, SLH-DSA), migration plan, and compliance references (CNSA 2.0, NIST SP 800-208, BSI, ANSSI).

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
# List available contexts
cryptoserve context list

# Show full resolution rationale
cryptoserve context show user-pii --verbose

# Encrypt with automatic algorithm selection
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
```

## License

Apache-2.0
