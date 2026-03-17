# CLI Quickstart

Scan your codebase for cryptographic issues in under 60 seconds. No server, no configuration, no dependencies.

## Install

```bash
npm install -g cryptoserve
# or use without installing:
npx cryptoserve scan .
```

## Step 1: Scan

```bash
cryptoserve scan .
```

This detects crypto libraries, hardcoded secrets, weak algorithm usage, and certificate files.

## Step 2: Post-Quantum Assessment

```bash
cryptoserve pqc
```

Analyzes quantum vulnerability of detected algorithms. Shows SNDL (Store Now, Decrypt Later) risk, migration timeline, and compliance references.

## Step 3: Generate CBOM

```bash
cryptoserve cbom . --format cyclonedx
```

Generates a Cryptographic Bill of Materials in CycloneDX 1.5 or SPDX 2.3 format for compliance audits.

## Step 4: CI/CD Gate

```bash
cryptoserve gate . --min-score 70
```

Returns exit code 0 (pass) or 1 (fail) for CI/CD integration.

## Next Steps

- [Full CLI Reference](../cli.md)
- [CI/CD Integration](../cli.md#cicd-integration)
- [Self-Hosted Platform](quickstart.md) for team key management
