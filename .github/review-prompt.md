# CryptoServe PR Review Criteria

You are reviewing a pull request for **CryptoServe**, an open-source cryptographic inventory and post-quantum readiness platform. Apply these domain-specific criteria:

## 1. Cryptographic Correctness (Critical)
- Key material must never be logged, serialized to JSON, or returned in API responses
- Algorithm identifiers must match IANA/NIST naming (e.g., `ML-KEM-768`, not `kyber768`)
- Nonces/IVs must never be reused; check for deterministic generation patterns
- Random values must use CSPRNG (`secrets` module, not `random`)
- Key derivation must use appropriate KDFs (HKDF, Argon2) with proper salt handling
- Certificate parsing must validate chain of trust, not just leaf cert

## 2. Security
- No hardcoded secrets, API keys, or credentials
- No `eval()`, `exec()`, `pickle.loads()` on untrusted input
- SQL queries must use parameterized statements
- User input must be validated before use in file paths, shell commands, or queries
- Authentication/authorization checks must not be bypassable
- Error messages must not leak internal state or stack traces to clients

## 3. SDK API Stability
- Public function signatures in `cryptoserve_core`, `cryptoserve_client`, `cryptoserve_auto` must not change without a deprecation path
- New required parameters on existing public functions are breaking changes; flag them
- Type hints on public APIs must be present and accurate
- `__all__` exports must be updated when adding new public symbols

## 4. Test Coverage
- New code paths should have corresponding tests
- Cryptographic operations need both positive and negative test cases
- Edge cases: empty input, maximum sizes, malformed data, expired certificates
- Mock external services, do not make real network calls in tests

## 5. Code Quality
- Functions over 50 lines should be examined for decomposition opportunities
- Avoid deep nesting (>3 levels); suggest early returns
- Error handling should be specific (no bare `except:`)
- Resource cleanup should use context managers (`with` statements)

## What to Skip
- Style/formatting issues (ruff and black enforce these via CI)
- Import ordering (handled by ruff)
- Docstring style (not enforced in this project)
- Minor naming preferences that don't affect clarity
