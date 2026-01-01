# CryptoServe Policy Gate - Pre-commit Hook

Catch cryptographic security issues before they're committed.

## Installation

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/your-org/crypto-serve
    rev: v0.5.0  # Use the latest version
    hooks:
      - id: cryptoserve-gate
```

Then install:

```bash
pre-commit install
```

## Available Hooks

| Hook ID | Description | Policy |
|---------|-------------|--------|
| `cryptoserve-gate` | Standard check | `standard` |
| `cryptoserve-gate-strict` | Blocks quantum-vulnerable | `strict` |
| `cryptoserve-gate-warn` | Fails on warnings too | `standard` |

## Examples

### Standard (Recommended)

```yaml
repos:
  - repo: https://github.com/your-org/crypto-serve
    rev: v0.5.0
    hooks:
      - id: cryptoserve-gate
```

### Strict Mode

```yaml
repos:
  - repo: https://github.com/your-org/crypto-serve
    rev: v0.5.0
    hooks:
      - id: cryptoserve-gate-strict
```

### Custom Arguments

```yaml
repos:
  - repo: https://github.com/your-org/crypto-serve
    rev: v0.5.0
    hooks:
      - id: cryptoserve-gate
        args: ['--policy', 'strict', '--fail-on', 'warnings']
```

### Specific File Types Only

```yaml
repos:
  - repo: https://github.com/your-org/crypto-serve
    rev: v0.5.0
    hooks:
      - id: cryptoserve-gate
        types: [python]  # Only scan Python files
```

## Usage

Once installed, the hook runs automatically on `git commit`:

```bash
$ git commit -m "Add authentication"
CryptoServe Crypto Policy Gate..........................................Passed
```

If issues are found:

```bash
$ git commit -m "Add legacy crypto"
CryptoServe Crypto Policy Gate..........................................Failed
- hook id: cryptoserve-gate
- exit code: 1

FAILED - 1 violation(s) found

VIOLATIONS (blocking):
------------------------------------------------------------
  src/auth.py:45
    Algorithm: md5
    Severity: critical
    Message: MD5 is cryptographically broken. Use SHA-256 or SHA-3.
    Fix: Use SHA-256 or SHA-3 for hashing
```

## Skip Hook Temporarily

```bash
git commit --no-verify -m "WIP: Legacy code migration"
```

## Configuration File

Create `.cryptoserve.yml` in your project root:

```yaml
policy: standard
# Or override specific settings
```
