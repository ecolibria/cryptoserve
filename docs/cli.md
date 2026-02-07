# CLI Reference

CryptoServe ships a single `cryptoserve` CLI with scanning, encryption, certificate, and server management commands. Many commands work offline with no server required.

## Installation

```bash
pip install cryptoserve
```

---

## Scanning Tools (no server required)

These commands delegate to Go binaries (CryptoScan, CryptoDeps) that are downloaded automatically on first use and cached in `~/.cryptoserve/bin/`.

### `scan` — Cryptographic Scanner

Scans files and directories for 90+ cryptographic patterns. Generates output in text, JSON, SARIF, or CycloneDX CBOM format.

```bash
cryptoserve scan .                                    # Scan current directory
cryptoserve scan ./src --format sarif -o results.sarif # SARIF output
cryptoserve scan . --push                              # Scan + upload to dashboard
cryptoserve scan . --python-only                       # Built-in lightweight scanner
cryptoserve scan . --update                            # Force binary re-download
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

| Flag | Description |
|------|-------------|
| `--profile <p>` / `-p` | Sensitivity profile: `general` (default), `healthcare`, `financial`, `national_security`, `short_lived` |

### `gate` — CI/CD Policy Gate

Enforces cryptographic policy compliance in CI/CD pipelines. Returns pass/fail with violation details.

```bash
cryptoserve gate .                                    # Check current directory
cryptoserve gate . --policy strict                     # Strict policy
cryptoserve gate . --staged                            # Git staged files only
cryptoserve gate . --format json --fail-on warnings    # JSON, fail on warnings
```

| Flag | Description |
|------|-------------|
| `--policy <p>` / `-p` | Policy level: `standard` (default), `strict`, `permissive` |
| `--format <fmt>` / `-f` | Output format: `text` (default), `json`, `sarif` |
| `--fail-on <level>` | Fail on: `violations` (default), `warnings`, `any` |
| `--staged` | Scan only git staged files |
| `--include-deps` | Include dependency analysis |

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
cryptoserve hash-password                              # Prompted input
cryptoserve hash-password "mypassword"
cryptoserve hash-password "mypassword" --algo pbkdf2
```

| Flag | Description |
|------|-------------|
| `--algo <alg>` / `-a` | Algorithm: `scrypt` (default), `pbkdf2` |

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
cryptoserve login --server https://api.cryptoserve.io  # Custom server
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
cryptoserve configure --server https://api.cryptoserve.io
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
