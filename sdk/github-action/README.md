# CryptoServe Policy Gate - GitHub Action

Scan your code for cryptographic security issues and enforce crypto policies in your CI/CD pipeline.

## Features

- Detect weak/broken algorithms (MD5, SHA1, DES, RC4)
- Warn about quantum-vulnerable algorithms (RSA, ECDSA)
- Multiple policy presets (strict, standard, permissive)
- SARIF output for GitHub Security tab integration
- Works offline - no server required

## Usage

### Basic Usage

```yaml
name: Crypto Policy Check
on: [push, pull_request]

jobs:
  crypto-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: CryptoServe Policy Gate
        uses: your-org/crypto-serve/sdk/github-action@main
```

### With Options

```yaml
- name: CryptoServe Policy Gate
  uses: your-org/crypto-serve/sdk/github-action@main
  with:
    path: 'src/'
    policy: 'strict'
    fail-on: 'warnings'
```

### With SARIF Upload to Security Tab

```yaml
- name: CryptoServe Policy Gate
  uses: your-org/crypto-serve/sdk/github-action@main
  with:
    format: 'sarif'
    upload-sarif: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `policy` | Policy preset: `strict`, `standard`, `permissive` | `standard` |
| `fail-on` | What triggers failure: `violations`, `warnings` | `violations` |
| `format` | Output format: `text`, `json`, `sarif` | `text` |
| `python-version` | Python version to use | `3.11` |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `passed` | Whether the gate check passed (`true`/`false`) |
| `violations` | Number of policy violations found |
| `warnings` | Number of warnings found |
| `quantum-score` | Quantum readiness score (0-100) |

## Policy Presets

| Preset | Blocks | Warns |
|--------|--------|-------|
| `strict` | weak + deprecated + quantum-vulnerable | all findings |
| `standard` | weak + deprecated | quantum-vulnerable |
| `permissive` | critical only | weak + deprecated |

## Examples

### Block Quantum-Vulnerable Code

```yaml
- name: Strict Crypto Gate
  uses: your-org/crypto-serve/sdk/github-action@main
  with:
    policy: 'strict'
```

### Scan Specific Directories

```yaml
- name: Crypto Gate
  uses: your-org/crypto-serve/sdk/github-action@main
  with:
    path: 'src/ lib/ tests/'
```

### Get Outputs

```yaml
- name: Crypto Gate
  id: crypto-check
  uses: your-org/crypto-serve/sdk/github-action@main

- name: Check Results
  run: |
    echo "Passed: ${{ steps.crypto-check.outputs.passed }}"
    echo "Violations: ${{ steps.crypto-check.outputs.violations }}"
    echo "Quantum Score: ${{ steps.crypto-check.outputs.quantum-score }}%"
```
