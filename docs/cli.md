# CLI Reference

CryptoServe ships a single `cryptoserve` CLI with scanning, encryption, and secret management commands. All commands work offline with no server required (except `login`).

## Installation

```bash
# Node.js (zero dependencies, Node 18+)
npm install -g cryptoserve

# Python
pip install cryptoserve
```

---

## Scanning Tools

### `scan` — Cryptographic Scanner

Scans files and directories for 130+ cryptographic patterns across 6 languages.

```bash
cryptoserve scan .                          # Scan current directory
cryptoserve scan . --format sarif           # SARIF output for CI/IDE
cryptoserve scan . --binary                 # Include binary signature detection
cryptoserve scan . --verbose                # Detailed output
```

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `text` (default), `json`, `sarif` |
| `--binary` | Include binary file scanning (ELF, PE, Mach-O, .class, .NET) |
| `--verbose` | Show detailed progress and findings |

### `cbom` — CBOM Generation

Generates a Cryptographic Bill of Materials in multiple formats.

```bash
cryptoserve cbom                            # Default JSON output
cryptoserve cbom --format cyclonedx -o cbom.json  # CycloneDX format
cryptoserve cbom --format spdx              # SPDX format
```

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `json` (default), `cyclonedx`, `spdx` |
| `--output <file>` / `-o` | Write output to file |

### `pqc` — PQC Migration Recommendations

Analyzes cryptographic exposure and provides post-quantum readiness assessment.

```bash
cryptoserve pqc                             # General profile
cryptoserve pqc --profile healthcare        # HIPAA-focused
cryptoserve pqc --profile financial         # PCI-DSS-focused
cryptoserve pqc --verbose                   # Detailed breakdown
```

| Flag | Description |
|------|-------------|
| `--profile <p>` | Sensitivity profile: `general` (default), `healthcare`, `financial`, `national_security`, `short_lived` |
| `--format <fmt>` | Output format: `text` (default), `json` |
| `--verbose` | Show detailed analysis |

### `gate` — CI/CD Policy Gate

Enforces cryptographic policy compliance in CI/CD pipelines. Exits non-zero when violations are found.

```bash
cryptoserve gate .                          # Check current directory
cryptoserve gate . --fail-on-weak           # Fail on weak algorithms (MD5, DES, RC4)
cryptoserve gate . --min-score 70           # Require minimum quantum readiness score
cryptoserve gate . --max-risk medium        # Fail on algorithms above medium risk
cryptoserve gate . --format sarif           # SARIF output
```

| Flag | Description |
|------|-------------|
| `--max-risk <level>` | Maximum allowed risk level: `none`, `low`, `medium`, `high` (default), `critical` |
| `--min-score <n>` | Minimum quantum readiness score (default: `50`) |
| `--fail-on-weak` | Fail on weak algorithms (MD5, DES, RC4, ECB) |
| `--format <fmt>` | Output format: `text` (default), `json`, `sarif` |
| `--verbose` | Show detailed violations |

### `census` — Ecosystem Census

Analyze cryptographic library adoption across package ecosystems.

```bash
cryptoserve census                          # Offline census from bundled data
cryptoserve census --live                   # Fetch real-time data from registries
cryptoserve census --live --ecosystems npm  # Query only npm
cryptoserve census --format json -o out.json  # JSON output
```

| Flag | Description |
|------|-------------|
| `--live` | Fetch real-time download counts from package registries (npm, PyPI, crates.io) |
| `--ecosystems <list>` | Comma-separated list: `npm`, `pypi`, `crates` (default: all three) |
| `--format <fmt>` | Output format: `text` (default), `json`, `html` |
| `--output <file>` | Write output to a file |
| `--no-cache` | Skip cached data |
| `--verbose` | Show detailed progress |

---

## Crypto Tools

### `encrypt` — Encrypt String or File

Password-based authenticated encryption (AES-256-GCM with PBKDF2 key derivation).

```bash
cryptoserve encrypt "hello world" --password secret
cryptoserve encrypt --file secret.txt -p secret -o secret.enc
```

| Flag | Description |
|------|-------------|
| `--password <pw>` / `-p` | Encryption password (prompted if omitted) |
| `--algorithm <alg>` | Encryption algorithm (default: AES-256-GCM) |
| `--context <ctx>` | Encryption context for server-managed keys |
| `--file <path>` | File to encrypt |
| `--output <path>` / `-o` | Output file path |

### `decrypt` — Decrypt String or File

```bash
cryptoserve decrypt "<base64>" --password secret
cryptoserve decrypt --file secret.enc -p secret -o decrypted.txt
```

| Flag | Description |
|------|-------------|
| `--password <pw>` / `-p` | Decryption password (prompted if omitted) |
| `--file <path>` | Encrypted file to decrypt |
| `--output <path>` / `-o` | Output file path |

### `hash-password` — Password Hashing

Generates password hashes using scrypt (default) or PBKDF2.

```bash
cryptoserve hash-password                   # Interactive prompt
cryptoserve hash-password "mypassword"      # Positional argument
cryptoserve hash-password --password mypass  # Non-interactive (CI/scripts)
cryptoserve hash-password "mypassword" --algorithm pbkdf2
```

| Flag | Description |
|------|-------------|
| `--password <pw>` | Password to hash (prompted if omitted) |
| `--algorithm <alg>` | Algorithm: `scrypt` (default), `pbkdf2` |

### `vault` — Encrypted Secret Storage

Stores secrets in an encrypted vault at `~/.cryptoserve/vault.enc`. All vault commands accept `--password P` for non-interactive/CI usage.

```bash
cryptoserve vault init                      # Create new vault (prompts for password)
cryptoserve vault init --password mysecret  # Non-interactive
cryptoserve vault set API_KEY sk-abc123     # Store a secret
cryptoserve vault get API_KEY               # Retrieve a secret
cryptoserve vault list                      # List stored secrets
cryptoserve vault delete API_KEY            # Remove a secret
cryptoserve vault run -- node server.js     # Run command with secrets as env vars
cryptoserve vault import .env               # Import .env file into vault
cryptoserve vault export                    # Export encrypted bundle
cryptoserve vault reset                     # Delete vault
```

| Flag | Description |
|------|-------------|
| `--password <pw>` | Vault password (prompted if omitted) |

---

## Setup Commands

### `init` — Initialize Project

Sets up CryptoServe in a project: generates a master key and configures AI tool protection.

```bash
cryptoserve init                            # Interactive setup
cryptoserve init --insecure-storage         # Skip keychain (not recommended)
```

### `login` — Authenticate with Server

```bash
cryptoserve login                           # Login to default server
cryptoserve login --server https://crypto.company.com  # Custom server
```

| Flag | Description |
|------|-------------|
| `--server <url>` / `-s` | Server URL (default: `http://localhost:8003`) |

### `context` — List Encryption Contexts

```bash
cryptoserve context                         # List all contexts
cryptoserve context --verbose               # Show key versions and rotation info
cryptoserve context --format json           # JSON output
```

| Flag | Description |
|------|-------------|
| `--verbose` | Show key version details |
| `--format <fmt>` | Output format: `text` (default), `json` |

### `status` — Show Configuration

```bash
cryptoserve status
```

Displays SDK configuration, identity, and server connection status.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (scan clean, gate passed) |
| `1` | Failure (gate failed, crypto issues found, invalid input) |

---

## Built-in Help

```bash
cryptoserve help              # All commands and flags
cryptoserve scan --help       # Scan-specific options
cryptoserve --version         # Current version
```

Every command supports `--help` for detailed usage.

---

## Python CLI Only

The following commands are available via `pip install cryptoserve` (`python -m cryptoserve`) but not yet in the Node.js CLI (`npx cryptoserve`):

### Scanning & Analysis
- **`deps`** — Dedicated dependency analysis with binary downloaders
- **`push`** — Upload scan results or CBOM to CryptoServe dashboard

### Crypto Tools
- **`token`** — JWT token creation/verification
- **`certs`** — Certificate management (generate-csr, self-signed, parse, verify)

### Server Commands (requires login)
- **`logout`** — Clear credentials
- **`configure`** — Set SDK configuration (token, server URL)
- **`verify`** — Server health check
- **`info`** — Display identity information
- **`contexts`** — List and search encryption contexts
- **`promote`** — Promote application to production
- **`wizard`** — Interactive context selection wizard

### Admin Commands
- **`backup`** / **`restore`** / **`backups`** — Encrypted backup and restore
- **`ceremony`** — Enterprise key ceremony (Shamir's Secret Sharing)
