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

### `scan`: Cryptographic Scanner

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

Hardcoded secrets are detected in source files AND in config files, including
`.env`, `.env.local` and `.env.production`. Before 0.5.0 only source files were
searched, so an AWS key committed in `.env` reported `Secrets found: 0` while the
same literal in a `.js` file was found. Committed templates (`.env.example`,
`.env.sample`, `.env.template`, `.env.dist`) hold placeholders and are not
treated as value-bearing.

The report counts source files and config files separately, because
`Secrets found: 0` means something different when no `.env` was read than when
one was read and was clean.

### `cbom`: CBOM Generation

Generates a Cryptographic Bill of Materials in multiple formats.

```bash
cryptoserve cbom                            # Default JSON output, current directory
cryptoserve cbom ./services/api             # A specific directory
cryptoserve cbom --format cyclonedx -o cbom.json  # CycloneDX format
cryptoserve cbom --format spdx              # SPDX format
```

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `json` (default), `cyclonedx`, `spdx` |
| `--output <file>` / `-o` | Write output to file |

The document goes to stdout; how much was read goes to stderr, so a piped CBOM
stays clean while the file and component counts stay visible. A path that does
not exist exits `2`. Before 0.5.0 it produced a CBOM asserting
`quantumReadiness.score: 100, riskLevel: none` and exited `0`, so a typo
certified a tree nobody had read.

### `pqc`: PQC Migration Recommendations

Analyzes cryptographic exposure and provides post-quantum readiness assessment.

```bash
cryptoserve pqc                             # Current directory, general profile
cryptoserve pqc ./services/api              # A specific directory
cryptoserve pqc --profile healthcare        # HIPAA-focused
cryptoserve pqc --profile financial         # PCI-DSS-focused
cryptoserve pqc --verbose                   # Detailed breakdown
```

| Flag | Description |
|------|-------------|
| `--profile <p>` | Sensitivity profile: `general` (default), `healthcare`, `financial`, `national_security`, `short_lived` |
| `--format <fmt>` | Output format: `text` (default), `json` |
| `--verbose` | Show detailed analysis |

An unknown `--profile` exits `2`. It used to fall back to `general` with the
warning suppressed in JSON mode, so `--profile helthcare` returned a confident
"not vulnerable / medium" instead of the HIPAA assessment that was asked for.

The report names the directory it analyzed and how many files it read, in both
formats (`scannedPath` and `filesScanned` in JSON). Before 0.5.0 the path
argument was accepted and then discarded: `pqc ./services/api` scored the current
directory instead, exit `0`, no warning.

### `gate`: CI/CD Policy Gate

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
| `--allow-secrets` | Do not fail on hardcoded secrets or committed private keys (both still reported) |
| `--format <fmt>` | Output format: `text` (default), `json`, `sarif` |
| `--verbose` | Show detailed violations |

`--min-score` must be a number from 0 to 100 and `--max-risk` one of the five
levels; anything else exits `2` rather than running. This matters because an
unenforceable threshold is not a lax gate but an absent one. Before 0.5.0
`--min-score abc` parsed to `NaN`, `score < NaN` was false, and a gate failing on
score printed `min: NaN` and exited `0`.

The report shows the directory and the file count, so a gate that passed because
it scanned nothing is distinguishable from one that passed on a clean tree. A
gate that read no files at all exits `2` rather than reporting `100/100`.

Hardcoded secrets and committed private keys fail the gate. Before 0.5.0 `scan`
reported `[CRIT] AWS Access Key .env:1` while `gate` on the same tree returned
`PASS 100/100`, so the highest-severity findings the scanner produces had no path
into CI. A public certificate does not fail the gate; the private key that signs
it does. `--allow-secrets` waives both explicitly and still reports the count.

An unknown flag exits `2` rather than warning and continuing, because
`gate . --min-scoree 95` used to fall back to the default threshold and pass.

### `census`: Ecosystem Census

Analyze cryptographic library adoption across package ecosystems.

Renders the published census from census.cryptoserve.dev: 11 ecosystems, NVD and
GitHub advisories, carrying the date the snapshot was collected. The snapshot is
cached for a day.

This command reports the published measurement and does not collect its own, so
its figures match the site exactly rather than approximately.

```bash
cryptoserve census                            # Render the published snapshot
cryptoserve census --no-cache                 # Re-fetch rather than use the day-old cache
cryptoserve census --format json -o out.json  # JSON output
```

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `text` (default), `json`, `html` |
| `--output <file>` | Write output to a file |
| `--no-cache` | Re-fetch the snapshot instead of using the cached copy |
| `--verbose` | Show detailed progress |

`--live` was removed in 0.5.0. It collected three of the eleven ecosystems from
its own copy of the fetch logic while the help text advertised all eleven, and
it recorded a rate-limited request as zero downloads -- so `cryptography`, which
really exceeds a billion downloads a month, could print as none, and two runs
hours apart disagreed by hundreds of millions. Running it now explains this and
exits non-zero.

---

## Crypto Tools

### `encrypt`: Encrypt String or File

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

### `decrypt`: Decrypt String or File

```bash
cryptoserve decrypt "<base64>" --password secret
cryptoserve decrypt --file secret.enc -p secret -o decrypted.txt
```

| Flag | Description |
|------|-------------|
| `--password <pw>` / `-p` | Decryption password (prompted if omitted) |
| `--file <path>` | Encrypted file to decrypt |
| `--output <path>` / `-o` | Output file path |

### `hash-password`: Password Hashing

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

### `vault`: Encrypted Secret Storage

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

### `init`: Initialize Project

Sets up CryptoServe in a project: generates a master key and configures AI tool protection.

```bash
cryptoserve init                            # Interactive setup
cryptoserve init --insecure-storage         # Skip keychain (not recommended)
```

### `login`: Authenticate with Server

```bash
cryptoserve login --server https://crypto.company.com
```

| Flag | Description |
|------|-------------|
| `--server <url>` | Server URL. Required; there is no default. |

`--server` is required as of 0.5.0. The previous built-in default was
`https://localhost:8003`, where nothing runs on a user's machine, so the
out-of-the-box flow could only time out. The CLI cannot know your server, and a
guess that is wrong for everyone is worse than an error naming what to pass.

`login` opens a browser and waits on a localhost callback, so it needs an
interactive session. Without a terminal it exits `2` immediately rather than
printing a URL and blocking for 120 seconds. If the callback port is already
held it says so, instead of failing with a raw `EADDRINUSE` stack trace.

### `context`: List Encryption Contexts

```bash
cryptoserve context                         # List all contexts
cryptoserve context --verbose               # Show key versions and rotation info
cryptoserve context --format json           # JSON output
```

| Flag | Description |
|------|-------------|
| `--verbose` | Show key version details |
| `--format <fmt>` | Output format: `text` (default), `json` |

### `status`: Show Configuration

```bash
cryptoserve status
```

Displays SDK configuration, identity, and server connection status.

---

## Environment

| Variable | Effect |
|---|---|
| `CRYPTOSERVE_HOME` | Absolute path to the state directory holding the master key, vault, credentials and census cache. Overrides everything else. |
| `XDG_CONFIG_HOME` | Used as `$XDG_CONFIG_HOME/cryptoserve` when `CRYPTOSERVE_HOME` is unset. |
| `CRYPTOSERVE_NO_KEYCHAIN` | Set to `1` to never touch the OS keychain. Containers and CI runners have no keychain service, and probing for one costs a subprocess and can hang. |

Default is `~/.cryptoserve`. Set `CRYPTOSERVE_HOME` in CI and in containers so
runs do not write into the invoking user's home directory:

```bash
CRYPTOSERVE_HOME=/run/cryptoserve cryptoserve vault init --password-stdin < pw.txt
```

## Passing a password

Three forms, in descending order of safety:

```bash
printf %s "$VAULT_PW" | cryptoserve vault get KEY --password-stdin   # preferred
cryptoserve vault get KEY --password "$VAULT_PW"                     # visible in ps
cryptoserve vault get KEY                                            # interactive prompt
```

`--password-stdin` was added in 0.5.0. Prefer it: `--password <value>` puts the
secret in `argv`, where it is readable from `ps`, `/proc/<pid>/cmdline` and shell
history for as long as the process runs. The two are mutually exclusive.

Without a terminal and without either flag, every command that needs a password
exits `2` and names what to pass. Before 0.5.0 it printed a Node
"Detected unsettled top-level await" diagnostic, with installed file paths, and
exited `13`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (scan clean, gate passed) |
| `1` | The command ran and reported a failure (gate failed, decryption failed, login failed) |
| `2` | The command could not run as invoked |

Code `2` covers every case where the command could not do the work it was asked
to do, so a result is never reported for something that was not measured:

- a path that does not exist, or exists but is not a directory
  (`scan`, `pqc`, `cbom`, `gate`)
- an option value the command cannot act on: `--min-score abc`, `--min-score 500`,
  `--max-risk bogus`, `--profile helthcare`, `--algorithm BOGUS`, an unknown
  `--format`, an empty `--password`
- the same option given twice
- a required argument that is missing: `encrypt` with no text, `vault set` with
  no value, `context show` with no name
- an unknown command, subcommand or context name
- a password prompt with no terminal to prompt on

Keeping this distinct from `1` is what stops a mistyped CI argument being read as
a clean pass. Before 0.5.0 `gate --min-score abc` parsed to `NaN`, every
comparison against `NaN` was false, and a gate that was failing on score exited
`0`; `gate ./package.json` walked zero source files and certified 100/100.

Changed in 0.5.0: `scan` on a bad path, an unknown command, an unknown context
and an invalid `--algorithm` all exited `1` and now exit `2`.

**The Python CLI (`python -m cryptoserve`) has not been changed.** Its `scan`
still exits `1` on a missing path, so the two SDKs disagree on that one case
until the Python side is brought in line. `gate` already used `2` in both.

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
- **`deps`**: dedicated dependency analysis with binary downloaders
- **`push`**: upload scan results or CBOM to CryptoServe dashboard

### Crypto Tools
- **`token`**: JWT token creation/verification
- **`certs`**: certificate management (generate-csr, self-signed, parse, verify)

### Server Commands (requires login)
- **`logout`**: clear credentials
- **`configure`**: set SDK configuration (token, server URL)
- **`verify`**: server health check
- **`info`**: display identity information
- **`contexts`**: list and search encryption contexts
- **`promote`**: promote application to production
- **`wizard`**: interactive context selection wizard

### Admin Commands
- **`backup`** / **`restore`** / **`backups`**: encrypted backup and restore
- **`ceremony`**: enterprise key ceremony (Shamir's Secret Sharing)
