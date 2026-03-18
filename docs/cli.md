# CLI Reference

CryptoServe ships a single `cryptoserve` CLI with scanning, encryption, certificate, and server management commands. Many commands work offline with no server required.

## Installation

```bash
# Node.js (zero dependencies, Node 18+)
npm install -g cryptoserve

# Python
pip install cryptoserve
```

---

## Scanning Tools (no server required)

Scanner binaries are downloaded automatically on first use and cached in `~/.cryptoserve/bin/`.

### `scan` — Cryptographic Scanner

Scans files and directories for 90+ cryptographic patterns. Generates output in text, JSON, SARIF, or CycloneDX CBOM format.

```bash
cryptoserve scan .                                    # Scan current directory
cryptoserve scan ./src --format sarif -o results.sarif # SARIF output
cryptoserve scan . --push                              # Scan + upload to dashboard
cryptoserve scan . --python-only                       # Built-in lightweight scanner
cryptoserve scan . --update                            # Force binary re-download
```

Example output:

```
CRYPTOSERVE > scan

  Directory            /path/to/project
  Files scanned        55

Crypto Libraries
  Library                Version    Risk       Algorithms
  node:crypto            builtin    high       AES, ChaCha20, SHA-256, RS256

Hardcoded Secrets
  x [CRIT] AWS Access Key
         src/config.js
         *  Use $AWS_ACCESS_KEY_ID instead

Weak Crypto Patterns
  !  MD5 is cryptographically broken
    lib/hash.js
  x DES has 56-bit keys (use AES)
    lib/legacy.js
```

| Flag | Description |
|------|-------------|
| `--push` | Upload results to CryptoServe dashboard |
| `--python-only` | Use built-in Python scanner instead of CryptoScan binary |
| `--update` | Force re-download of CryptoScan binary |
| `--format <fmt>` / `-f` | Output format: `json`, `sarif`, `cyclonedx` |
| `--output <file>` / `-o` | Write output to file |

Any unrecognized flags are passed through to the CryptoScan binary.

### `deps` — Dependency Analysis

Analyzes the dependency tree for cryptographic usage. Supports CBOM generation and reachability analysis.

```bash
cryptoserve deps .                                    # Analyze dependencies
cryptoserve deps . --push                              # Analyze + upload
cryptoserve deps . --format json -o deps.json          # JSON output
cryptoserve deps . --update                            # Force binary re-download
```

| Flag | Description |
|------|-------------|
| `--push` | Upload results to CryptoServe dashboard |
| `--update` | Force re-download of CryptoDeps binary |
| `--format <fmt>` / `-f` | Output format: `json`, `sarif`, `cyclonedx` |
| `--output <file>` / `-o` | Write output to file |

Any unrecognized flags are passed through to the CryptoDeps binary.

### `push` — Upload Results

Uploads JSON results from CryptoScan, CryptoDeps, or CycloneDX CBOM to the dashboard.

```bash
cryptoserve push scan-results.json
cryptoserve push cbom.json
```

---

## Security Tools

### `cbom` — CBOM Generation

Generates a Cryptographic Bill of Materials in multiple formats.

```bash
cryptoserve cbom                                      # Default JSON output
cryptoserve cbom --format cyclonedx -o cbom.json       # CycloneDX format
cryptoserve cbom --format spdx -o sbom.spdx            # SPDX format
cryptoserve cbom --local-only                          # Skip upload
```

| Flag | Description |
|------|-------------|
| `--format <fmt>` / `-f` | Output format: `json`, `cyclonedx`, `spdx` |
| `--output <file>` / `-o` | Write output to file |
| `--name <name>` / `-n` | Scan name for platform upload |
| `--local-only` | Generate without uploading |
| `--no-upload` | Disable automatic upload |

### `pqc` — PQC Migration Recommendations

Analyzes cryptographic exposure and provides post-quantum readiness assessment.

```bash
cryptoserve pqc                                       # General profile
cryptoserve pqc --profile healthcare                   # HIPAA-focused
cryptoserve pqc --profile financial                    # PCI-DSS-focused
```

Example output:

```
CRYPTOSERVE > pqc

Data Profile
  Profile              Personal Data / General
  Protection needed    10 years
  Urgency              MEDIUM

Quantum Readiness
  40/100 (high confidence -- 14 algorithms found)
  Migration urgency    IMMEDIATE
  Risk breakdown       x 3 critical / !  7 high / 1 low / + 3 safe

SNDL Risk Assessment
  Risk level           critical
  Risk window          3 years

KEM Recommendations
  Algorithm            FIPS         Level          Score
  ML-KEM-768           FIPS 203     NIST Level 3   100%
```

| Flag | Description |
|------|-------------|
| `--profile <p>` / `-p` | Sensitivity profile: `general` (default), `healthcare`, `financial`, `national_security`, `short_lived` |

### `gate` — CI/CD Policy Gate

Enforces cryptographic policy compliance in CI/CD pipelines. Returns pass/fail with violation details.

```bash
cryptoserve gate .                                    # Check current directory
cryptoserve gate . --fail-on-weak                      # Fail on weak algorithms (MD5, DES, RC4)
cryptoserve gate . --min-score 70                      # Require minimum quantum readiness score
cryptoserve gate . --max-risk medium                   # Fail on algorithms above medium risk
cryptoserve gate . --format json                       # JSON output for CI parsing
```

Example output:

```
CRYPTOSERVE > gate

  Status               x FAIL
  Score                40/100 (min: 50)
  Max risk             high

  Violations:
  x [CRITICAL] MD5 -- node:crypto@builtin
  x [CRITICAL] DES -- node:crypto@builtin
  x [CRITICAL] RC4 -- node:crypto@builtin

  x Score 40 is below minimum 50
```

| Flag | Description |
|------|-------------|
| `--max-risk <level>` | Maximum allowed risk level: `none`, `low`, `medium`, `high` (default), `critical` |
| `--min-score <n>` | Minimum quantum readiness score (default: `50`) |
| `--fail-on-weak` | Fail on weak algorithms (MD5, DES, RC4, ECB) |
| `--format <fmt>` / `-f` | Output format: `text` (default), `json`, `sarif` |

### `census` -- Ecosystem Census

Analyze cryptographic library adoption across package ecosystems.

```bash
cryptoserve census                            # Run ecosystem census (cached/offline data)
cryptoserve census --live                     # Fetch real-time data from npm, PyPI, crates.io
cryptoserve census --live --ecosystems npm    # Query only npm
cryptoserve census --live --format json       # Machine-readable JSON output
```

| Flag | Description |
|------|-------------|
| `--live` | Fetch real-time download counts from package registries (npm, PyPI, crates.io) |
| `--ecosystems <list>` | Comma-separated list of ecosystems to query: `npm`, `pypi`, `crates` (default: all three) |
| `--format <fmt>` | Output format: `text` (default), `json`, `html` |
| `--output <file>` | Write output to a file |
| `--no-cache` | Skip cached data |
| `--verbose` | Show detailed progress |

---

## Offline Crypto Tools (no server required)

### `encrypt` — Encrypt String or File

Password-based authenticated encryption.

```bash
cryptoserve encrypt "hello world" --password secret
cryptoserve encrypt --file secret.txt -p secret -o secret.enc
```

| Flag | Description |
|------|-------------|
| `--password <pw>` / `-p` | Encryption password (prompted if omitted) |
| `--file <path>` / `-f` | File to encrypt |
| `--output <path>` / `-o` | Output file path |

### `decrypt` — Decrypt String or File

```bash
cryptoserve decrypt "<base64>" --password secret
cryptoserve decrypt --file secret.enc -p secret -o decrypted.txt
```

| Flag | Description |
|------|-------------|
| `--password <pw>` / `-p` | Decryption password (prompted if omitted) |
| `--file <path>` / `-f` | Encrypted file to decrypt |
| `--output <path>` / `-o` | Output file path |

### `hash-password` — Password Hashing

Generates password hashes using scrypt (default) or PBKDF2.

```bash
cryptoserve hash-password                              # Interactive prompt
cryptoserve hash-password --password mypass             # Non-interactive (CI/scripts)
cryptoserve hash-password "mypassword"
cryptoserve hash-password "mypassword" --algorithm pbkdf2
```

| Flag | Description |
|------|-------------|
| `--password <pw>` | Password to hash (prompted if omitted) |
| `--algorithm <alg>` | Algorithm: `scrypt` (default), `pbkdf2` |

### `token` — JWT Token Creation

Creates HS256 JWT tokens with custom payload and expiration.

```bash
cryptoserve token --key mysecret
cryptoserve token --key mysecret --payload '{"sub":"user1"}' --expires 7200
```

| Flag | Description |
|------|-------------|
| `--key <secret>` / `-k` | Signing key (required) |
| `--payload <json>` | JSON payload (default: `{}`) |
| `--expires <sec>` / `-e` | Expiration in seconds (default: 3600) |

### `vault` — Encrypted Secret Storage

Stores secrets in an encrypted vault at `~/.cryptoserve/vault.enc`. All vault commands accept `--password P` for non-interactive/CI usage.

```bash
cryptoserve vault init                                  # Create new vault (prompts for password)
cryptoserve vault init --password mysecret              # Non-interactive
cryptoserve vault set API_KEY sk-abc123                 # Store a secret
cryptoserve vault get API_KEY                           # Retrieve a secret
cryptoserve vault list                                  # List stored secrets
cryptoserve vault delete API_KEY                        # Remove a secret
cryptoserve vault run -- node server.js                 # Run command with secrets as env vars
cryptoserve vault import .env                           # Import .env file into vault
cryptoserve vault export                                # Export encrypted bundle
cryptoserve vault reset                                 # Delete vault
```

| Flag | Description |
|------|-------------|
| `--password <pw>` | Vault password (prompted if omitted) |

---

## Certificate Operations

### `certs generate-csr` — Generate CSR

```bash
cryptoserve certs generate-csr --cn "example.com" --org "Example Inc"
cryptoserve certs generate-csr --cn "example.com" --san "*.example.com" --key-type rsa --key-size 4096
```

| Flag | Description |
|------|-------------|
| `--cn <name>` | Common Name (required) |
| `--org <org>` | Organization |
| `--country <code>` | Country code (2 letters) |
| `--key-type <type>` | `ec` (default), `rsa` |
| `--key-size <bits>` | Key size (256 for EC, 2048 for RSA) |
| `--san <domain>` | Subject Alternative Name (repeatable) |
| `--output <prefix>` | Output file prefix |

### `certs self-signed` — Generate Self-Signed Certificate

```bash
cryptoserve certs self-signed --cn "localhost"
cryptoserve certs self-signed --cn "example.com" --days 730 --ca
```

| Flag | Description |
|------|-------------|
| `--cn <name>` | Common Name (required) |
| `--org <org>` | Organization |
| `--days <n>` | Validity period (default: 365) |
| `--ca` | Create as CA certificate |
| `--san <domain>` | Subject Alternative Name (repeatable) |
| `--output <prefix>` | Output file prefix |

### `certs parse` — Parse Certificate

```bash
cryptoserve certs parse server.pem
```

Displays subject, issuer, expiry, extensions, and key info.

### `certs verify` — Verify Certificate

```bash
cryptoserve certs verify server.pem --issuer ca.pem
```

| Flag | Description |
|------|-------------|
| `--issuer <ca.pem>` | CA certificate for chain verification |

---

## Server Commands (requires login)

### `login` — Authenticate

```bash
cryptoserve login                                     # Opens browser for OAuth
cryptoserve login --server https://your-server  # Custom server
cryptoserve login --dev                                # Dev mode (no OAuth)
cryptoserve login --cookie <jwt>                       # Manual session token
```

| Flag | Description |
|------|-------------|
| `--server <url>` / `-s` | Server URL (default: `http://localhost:8003`) |
| `--dev` | Force dev mode login |
| `--cookie <jwt>` | Set session manually |

### `logout` — Clear Credentials

```bash
cryptoserve logout
```

### `configure` — Set SDK Configuration

```bash
cryptoserve configure --token <token>
cryptoserve configure --server https://your-server
cryptoserve configure --refresh-token <token>
```

| Flag | Description |
|------|-------------|
| `--token <t>` / `-t` | API token |
| `--refresh-token <t>` / `-r` | Refresh token |
| `--server <url>` / `-s` | Server URL |

Also reads from environment variables: `CRYPTOSERVE_TOKEN`, `CRYPTOSERVE_REFRESH_TOKEN`, `CRYPTOSERVE_SERVER_URL`.

### `status` — Show Configuration

```bash
cryptoserve status
```

Displays SDK configuration, identity, and server connection status.

### `verify` — Health Check

```bash
cryptoserve verify
```

Checks server connectivity and reports latency.

### `info` — Identity Information

```bash
cryptoserve info
```

Displays current identity, app name, tenants, and roles.

### `contexts` — List Encryption Contexts

```bash
cryptoserve contexts                                  # List all
cryptoserve contexts "pii"                             # Search by keyword
cryptoserve contexts -e user-pii                       # Show usage example
```

| Flag | Description |
|------|-------------|
| `--example <name>` / `-e` | Show usage example for a context |

### `promote` — Promote Application

```bash
cryptoserve promote my-app                             # Check readiness
cryptoserve promote my-app --confirm                   # Promote
cryptoserve promote my-app --to staging                # Target environment
cryptoserve promote my-app --expedite                  # Expedited approval
```

| Flag | Description |
|------|-------------|
| `--to <env>` / `-t` | Target environment (default: `production`) |
| `--confirm` | Proceed with promotion |
| `--expedite` / `-e` | Request expedited approval |

### `wizard` — Interactive Context Wizard

```bash
cryptoserve wizard
```

Guided walkthrough for selecting encryption contexts for your application.

---

## Backup & Restore (requires admin)

### `backup` — Create Encrypted Backup

```bash
cryptoserve backup -o backup.enc
cryptoserve backup -o backup.enc --audit-logs
cryptoserve backup -o backup.enc --tenant-only
```

| Flag | Description |
|------|-------------|
| `--output <file>` / `-o` | Output file path |
| `--audit-logs` | Include audit logs |
| `--tenant-only` | Backup current tenant only |

### `restore` — Restore from Backup

```bash
cryptoserve restore --backup backup.enc --dry-run      # Preview
cryptoserve restore --backup backup.enc --execute       # Restore
```

| Flag | Description |
|------|-------------|
| `--backup <file>` / `-b` | Backup file (required) |
| `--dry-run` | Preview what would be restored (default) |
| `--execute` | Perform the restore |

### `backups` — List Backups

```bash
cryptoserve backups
```

---

## Key Ceremony (requires admin)

Enterprise master key management using Shamir's Secret Sharing.

### `ceremony status`

```bash
cryptoserve ceremony status
```

Shows current state: uninitialized, sealed, or unsealed.

### `ceremony initialize`

```bash
cryptoserve ceremony initialize --threshold 3 --shares 5
```

Creates master key and generates recovery shares.

| Flag | Description |
|------|-------------|
| `--threshold <n>` | Shares required to unseal |
| `--shares <n>` | Total shares to generate |

### `ceremony seal`

```bash
cryptoserve ceremony seal
```

Clears master key from memory. Service must be unsealed to resume operation.

### `ceremony unseal`

```bash
cryptoserve ceremony unseal --share <hex>
cryptoserve ceremony unseal --interactive
```

| Flag | Description |
|------|-------------|
| `--share <hex>` | Recovery share (hex-encoded) |
| `--interactive` | Prompt for share input |

### `ceremony verify`

```bash
cryptoserve ceremony verify --share <hex>
```

Validates a recovery share without using it.

### `ceremony audit`

```bash
cryptoserve ceremony audit
```

Displays audit log of ceremony operations.

---

## Binary Management

The `scan` and `deps` commands use Go binaries (CryptoScan, CryptoDeps) that are managed automatically:

- **Cache location**: `~/.cryptoserve/bin/`
- **Auto-download**: Binaries are fetched on first use
- **Integrity**: SHA-256 checksum verification on download
- **Update**: Use `--update` to force re-download
- **Platforms**: macOS (arm64, amd64), Linux (arm64, amd64), Windows (amd64)

The `--python-only` flag on `scan` bypasses the binary and uses a built-in Python scanner with fewer patterns.
