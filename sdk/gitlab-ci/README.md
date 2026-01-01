# CryptoServe Policy Gate - GitLab CI

Scan your code for cryptographic security issues in GitLab CI/CD pipelines.

## Quick Start

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/your-org/crypto-serve/main/sdk/gitlab-ci/.gitlab-ci-template.yml'
```

Or copy the job directly:

```yaml
cryptoserve-gate:
  image: python:3.11-slim
  stage: test
  before_script:
    - pip install --quiet cryptoserve pyyaml
  script:
    - python -m cryptoserve gate . --policy standard --format text
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Configuration

### Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CRYPTOSERVE_POLICY` | Policy preset | `standard` |
| `CRYPTOSERVE_FAIL_ON` | What fails the job | `violations` |
| `CRYPTOSERVE_PATH` | Path to scan | `.` |
| `CRYPTOSERVE_INCLUDE_DEPS` | Scan dependency files | `false` |

### Override Variables

```yaml
cryptoserve-gate:
  extends: .cryptoserve-gate-base
  variables:
    CRYPTOSERVE_POLICY: "strict"
    CRYPTOSERVE_PATH: "src/"
```

## Available Jobs

| Job | Description |
|-----|-------------|
| `cryptoserve-gate` | Standard check with text output |
| `cryptoserve-gate-json` | JSON output with artifacts |
| `cryptoserve-gate-strict` | Strict mode (manual trigger) |
| `cryptoserve-sast` | SARIF output for GitLab SAST |

## Policy Presets

| Preset | Blocks | Warns |
|--------|--------|-------|
| `strict` | weak + deprecated + quantum-vulnerable | all |
| `standard` | weak + deprecated | quantum-vulnerable |
| `permissive` | critical only | weak + deprecated |

## Examples

### Scan Specific Directories

```yaml
cryptoserve-gate:
  extends: .cryptoserve-gate-base
  variables:
    CRYPTOSERVE_PATH: "src/ lib/"
  script:
    - python -m cryptoserve gate $CRYPTOSERVE_PATH --policy standard
```

### Block on Warnings Too

```yaml
cryptoserve-gate:
  extends: .cryptoserve-gate-base
  variables:
    CRYPTOSERVE_FAIL_ON: "warnings"
```

### Require Quantum-Safe Code

```yaml
cryptoserve-gate:
  extends: .cryptoserve-gate-base
  variables:
    CRYPTOSERVE_POLICY: "strict"
```

### Scan Dependencies Too

```yaml
cryptoserve-gate:
  extends: .cryptoserve-gate-base
  variables:
    CRYPTOSERVE_INCLUDE_DEPS: "true"
```
