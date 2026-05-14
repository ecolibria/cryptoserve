# CI/CD Security Pipeline

Every code change to CryptoServe passes through **16+ automated checks** across 4 workflow files before it can be merged. This document describes what those checks do, why they exist, and how they work together to maintain code quality and security.

## Pipeline Flow

```
                          Pull Request Opened
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
            ┌────▼────┐   ┌─────▼─────┐   ┌─────▼─────┐
            │   CI    │   │ Security  │   │  Claude   │
            │Pipeline │   │  Audit    │   │  Review   │
            └────┬────┘   └─────┬─────┘   └─────┬─────┘
                 │               │               │
          ┌──────┴──────┐  ┌────┴────┐    ┌──────┴──────┐
          │ Backend     │  │ Crypto  │    │ Semantic    │
          │ Tests       │  │ Audit   │    │ Code Review │
          │ Lint        │  │ Dep     │    │ Security    │
          │ Frontend    │  │ Audit   │    │ Review      │
          │ SDK Tests   │  │ Matrix  │    └──────┬──────┘
          │ Bandit      │  │ Tests   │           │
          │ pip-audit   │  │ Bandit  │           │
          └──────┬──────┘  │ Format  │           │
                 │         └────┬────┘           │
                 │              │                 │
                 └──────────────┼─────────────────┘
                                │
                       ┌────────▼────────┐
                       │  Auto-Merge     │
                       │  Evaluation     │
                       └────────┬────────┘
                          ┌─────┴─────┐
                     ┌────▼──┐   ┌────▼──────┐
                     │ Auto  │   │  Manual   │
                     │ Merge │   │  Review   │
                     └───────┘   │  Required │
                                 └───────────┘
```

## 1. CI Pipeline (`ci.yml`)

**Triggers:** Push to `main`, pull requests targeting `main`

The CI pipeline runs 5 parallel jobs on every change:

### Backend Tests

Runs the full backend test suite across a Python version matrix.

| Setting | Value |
|---------|-------|
| Runner | `ubuntu-latest` |
| Python versions | 3.11, 3.12 |
| Coverage | `pytest-cov` with XML + terminal output |
| Artifacts | Coverage report uploaded (Python 3.12 only) |

Environment variables `STARTUP_VALIDATION_LEVEL=skip` and `DEV_MODE=true` are set so tests run without requiring a live crypto backend.

### Linting

Enforces consistent code style across the backend.

| Tool | Scope | Configuration |
|------|-------|---------------|
| **Ruff** | `backend/app`, `backend/tests` | `backend/ruff.toml` |
| **Black** | `backend/app`, `backend/tests` | Line length: 120 |

Both checks must pass. Formatting violations and lint errors block merge.

### Frontend Build & Lint

Validates that the frontend compiles and passes lint checks.

| Setting | Value |
|---------|-------|
| Node.js | 20 |
| Package manager | npm (with `npm ci` for reproducible installs) |
| Steps | `npm run lint` then `npm run build` |

A build failure here catches TypeScript type errors and broken imports before they reach `main`.

### SDK Tests

Tests the Python SDK packages in dependency order.

Installs all 4 packages from source (`cryptoserve-core` → `cryptoserve-client` → `cryptoserve-auto` → `cryptoserve`) and runs `pytest` against `sdk/python/tests/`.

### Security Scans

Static analysis and dependency auditing for the backend.

| Tool | What it does |
|------|-------------|
| **Bandit** | Static security analysis. Fails on high-severity + high-confidence findings (`-lll -iii`). Suppresses B413 (pycrypto import; false positive since the project uses `cryptography`). Results uploaded as artifact. |
| **pip-audit** | Checks `backend/requirements.txt` against the PyPI advisory database for known CVEs. |

A second Bandit pass with medium thresholds (`-ll -ii`) runs for informational review but does not block the pipeline.

## 2. Security Audit Pipeline (`security.yml`)

**Triggers:** Push or PR that changes files under `sdk/python/**`

This pipeline runs 5 specialized security jobs when the SDK is modified:

### Cryptographic Best Practices Audit

Runs a custom `crypto_audit.py` scanner against the SDK source code. This scanner checks for:

- Hardcoded keys or nonces
- Use of deprecated/weak algorithms
- Improper random number generation
- Missing key derivation functions

Results are generated in SARIF format and uploaded to the **GitHub Security tab**, making findings visible alongside CodeQL results.

### Dependency Security

Two-part check on SDK dependencies:

| Check | Tool | Details |
|-------|------|---------|
| **CVE scan** | `pip-audit` | Scans installed packages (skips editable installs) for known vulnerabilities |
| **License compliance** | `pip-licenses` | Verifies all dependencies use approved licenses: Apache, MIT, BSD, ISC, PSF, or MPL 2.0 |

License violations indicate a dependency that could create legal risk for downstream users.

### Multi-Version Test Matrix

Runs the full SDK test suite across **4 Python versions**:

| Python | Status |
|--------|--------|
| 3.9 | Supported (minimum) |
| 3.10 | Supported |
| 3.11 | Supported |
| 3.12 | Supported + coverage reporting |

Coverage is collected via `pytest-cov` across both `cryptoserve` and `cryptoserve_core` packages and uploaded as an artifact on the 3.12 run.

### Static Security Analysis (Bandit)

Runs Bandit against SDK code (`sdk/python/cryptoserve` and `sdk/python/packages`) with `--severity-level high` in two passes:

1. **SARIF generation**: Outputs results in SARIF format and uploads to the GitHub Security tab under the `bandit` category (does not fail the pipeline)
2. **Gating check**: Runs the same scan without SARIF output. This pass fails the pipeline if high-severity findings exist.

### Ciphertext Format Regression

Validates that the wire format of encrypted data, password hashes, tokens, and local mode blobs has not changed. This prevents accidental breaking changes to data formats that would make previously encrypted data unreadable.

Four format assertions run:

| Format | Validation |
|--------|-----------|
| **Encryption blob** | Version byte = 1, encrypt/decrypt roundtrip, string encrypt/decrypt roundtrip |
| **Password hash** | scrypt hashes start with `$scrypt$`, PBKDF2 hashes start with `$pbkdf2-sha256$`, verify roundtrip |
| **JWT tokens** | Token has 3 dot-separated parts, `verify_token` and `decode_token` produce correct claims |
| **Local mode** | Binary format: `[ctx_len:2][context][nonce:12][ciphertext+tag]`, context and plaintext roundtrip correctly |

If any of these assertions fail, the pipeline blocks the merge. A format change requires intentional migration, not an accidental regression.

## 3. AI-Powered Code Review (`claude-review.yml`)

**Triggers:** Pull request opened/synchronized/reopened, or issue comment containing `@claude`

This workflow uses [claude-code-action](https://github.com/anthropics/claude-code-action) to perform two independent review passes on every PR.

### Semantic Code Review

Claude reviews the PR diff against domain-specific criteria:

**Cryptographic correctness (critical)**
- Key material must never be logged, serialized to JSON, or returned in API responses
- Algorithm identifiers must match IANA/NIST naming (e.g., `ML-KEM-768`, not `kyber768`)
- Nonces/IVs must never be reused; deterministic generation patterns are flagged
- Random values must use CSPRNG (`secrets` module, not `random`)
- Key derivation must use appropriate KDFs (HKDF, Argon2) with proper salt handling

**Security**
- No hardcoded secrets, API keys, or credentials
- No `eval()`, `exec()`, `pickle.loads()` on untrusted input
- SQL queries must use parameterized statements
- Input validation before use in file paths, shell commands, or queries
- Authentication/authorization checks must not be bypassable

**SDK API stability**
- Public function signatures in `cryptoserve_core`, `cryptoserve_client`, `cryptoserve_auto` must not change without a deprecation path
- New required parameters on existing public functions are flagged as breaking changes
- Type hints on public APIs must be present and accurate
- `__all__` exports must be updated when adding new public symbols

**Test coverage**
- New code paths should have corresponding tests
- Cryptographic operations need both positive and negative test cases
- Edge cases: empty input, maximum sizes, malformed data, expired certificates

**Code quality**
- Functions over 50 lines examined for decomposition
- Deep nesting (>3 levels) flagged with early return suggestions
- No bare `except:`; error handling must be specific
- Resource cleanup via context managers (`with` statements)

The reviewer explicitly skips style/formatting issues (handled by Ruff and Black), import ordering, docstring style, and minor naming preferences.

### Security-Focused Review

A separate pass focused on OWASP-style vulnerabilities:

1. Injection vulnerabilities (SQL, command, path traversal)
2. Authentication/authorization bypasses
3. Insecure deserialization or eval usage
4. Hardcoded credentials or secrets
5. SSRF or open redirect risks
6. Cryptographic misuse (weak algorithms, nonce reuse, key leakage)

**False positive suppressions** prevent noise from:

- Policy/gate files (`*_gate.py`, `*_policies.py`) that reference algorithm names for detection, not usage
- Test files that intentionally use weak cryptographic material as fixtures
- `crypto_audit.py` which references algorithms in documentation
- Scanner output files that contain algorithm names as scan results

The security review outputs a `FINDINGS_COUNT` that feeds into the auto-merge decision.

### Auto-Merge Logic

After both review passes and all CI checks complete, the workflow evaluates whether a PR qualifies for automatic merge. **All** of the following conditions must be true:

| Condition | Threshold |
|-----------|-----------|
| CI checks | All must pass (test, lint, frontend, sdk, security) |
| Security findings | 0 findings from the security review |
| PR author | Must be in trusted list (`dependabot[bot]`, `renovate[bot]`, `decimai`) |
| PR size | 10 files or fewer |
| Lines changed | 200 or fewer (additions + deletions) |
| Protected paths | No changes to protected paths (see below) |
| PR age | At least 5 minutes old (anti-rush safeguard) |

If eligible: the PR is auto-approved and squash-merged.

If not eligible: a comment is posted listing which criteria failed, and a human reviewer is required.

## 4. Release Pipeline (`publish.yml`)

**Triggers:** Push of a `v*` tag (e.g., `v1.6.0`)

The release pipeline builds, verifies, and publishes all SDK packages to PyPI.

### Stages

```
v* tag pushed
     │
     ▼
┌──────────┐
│   Test   │  Python 3.11 + 3.12, backend + SDK tests
└────┬─────┘
     ▼
┌──────────┐
│  Build   │  Build all 4 packages, verify with twine check
└────┬─────┘
     ▼
  Publish (ordered by dependency):
     │
     ├──► core (first, no dependencies)
     │       │
     │       ├──► client (depends on core)
     │       │       │
     │       │       └──► main (depends on core + client)
     │       │
     │       └──► auto (depends on core, parallel with client)
     │
     ▼
┌──────────────┐
│  Provenance  │  Waits for all 4 publish jobs
│              │  SHA-256 checksums + GitHub Release
└──────────────┘
```

### Packages Published

| Package | Description |
|---------|-------------|
| `cryptoserve-core` | Core cryptographic primitives |
| `cryptoserve-client` | Server communication client |
| `cryptoserve-auto` | Auto-configuration and registration |
| `cryptoserve` | Unified SDK (depends on all above) |

### Security Measures

- **PyPI API token**: Publishes to PyPI using a token stored in repository secrets (`PYPI_API_TOKEN`), scoped to the CryptoServe packages
- **twine check**: Validates package metadata and structure before upload
- **SHA-256 checksums**: A `SHA256SUMS.txt` file is generated for all wheel and source distribution artifacts
- **GitHub Release**: Created automatically with generated release notes, checksums, and all `.whl` files attached

## 5. Branch Protection

The `main` branch is protected with the following rules:

| Rule | Setting |
|------|---------|
| Direct push | Blocked; all changes must come through a PR |
| Required reviews | At least 1 approving review |
| Status checks | All CI checks must pass before merge |
| Merge strategy | Squash merge enforced (linear history) |

## 6. Protected Paths

The auto-merge system blocks automatic merging when any of these paths are modified, requiring human review:

| Path | Reason |
|------|--------|
| `.github/workflows/` | CI/CD pipeline configuration |
| `backend/app/core/crypto/` | Core cryptographic implementation |
| `backend/app/auth/` | Authentication system |
| `sdk/python/packages/cryptoserve-core/cryptoserve_core/` | Core SDK cryptographic code |
| `.env` | Environment configuration |
| `docker-compose*` | Infrastructure configuration |

Changes to these paths always require manual review, regardless of PR size or author.

## 7. Summary

| Check | What it catches | Workflow | Trigger |
|-------|----------------|----------|---------|
| Backend tests (3.11, 3.12) | Regressions, logic errors | `ci.yml` | All PRs and pushes to main |
| Ruff lint | Code style violations, unused imports | `ci.yml` | All PRs and pushes to main |
| Black format check | Formatting inconsistencies | `ci.yml` | All PRs and pushes to main |
| Frontend build + lint | TypeScript errors, broken imports | `ci.yml` | All PRs and pushes to main |
| SDK tests | SDK regressions | `ci.yml` | All PRs and pushes to main |
| Bandit (backend) | Security vulnerabilities in backend | `ci.yml` | All PRs and pushes to main |
| pip-audit (backend) | Known CVEs in backend dependencies | `ci.yml` | All PRs and pushes to main |
| Crypto audit | Cryptographic misuse in SDK | `security.yml` | SDK changes only |
| pip-audit (SDK) | Known CVEs in SDK dependencies | `security.yml` | SDK changes only |
| License compliance | Non-permissive dependency licenses | `security.yml` | SDK changes only |
| SDK test matrix (3.9-3.12) | Version-specific regressions | `security.yml` | SDK changes only |
| Bandit (SDK) | Security vulnerabilities in SDK | `security.yml` | SDK changes only |
| Ciphertext format regression | Wire format breaking changes | `security.yml` | SDK changes only |
| Semantic code review | Logic, API stability, crypto correctness | `claude-review.yml` | All PRs |
| Security review | OWASP-style vulnerabilities | `claude-review.yml` | All PRs |
| Auto-merge evaluation | Gate for unreviewed merges | `claude-review.yml` | All PRs |
