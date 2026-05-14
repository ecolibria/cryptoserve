# Release smoke: JS + Python SDK / CLI

Run before tagging a `js-v*` or `v*` (Python) release. Two parts per SDK:

1. **Automated.** Language-specific runner.
   - JS: `npm run release-smoke` in `sdk/javascript/` (~5s, 80+ checks).
   - Python: `python scripts/release_smoke.py` in `sdk/python/` (~10s, 60+ checks).
   Each spawns its CLI as a subprocess and asserts behavior across help,
   scan, pqc, cbom, gate, encrypt/decrypt, hash, and the error
   exit-code matrix. Must end with `PASS N/N`.
2. **Manual.** This checklist. Covers the surfaces the automated runner
   can't exercise without side effects (init, vault, login, census --live)
   and the UX/feel checks that a script can't make.

Every item below traces to a regression we either shipped or caught. Skipping
an item is fine if you can articulate why; write it in the PR description.

## 0. Prerequisites

- [ ] Working tree is clean (`git status`).
- [ ] On a release branch (not main).
- [ ] `package.json` version bumped and matches the planned tag.

## 1. Automated runner

```bash
cd sdk/javascript
npm test          # 270+ unit tests
npm run release-smoke
```

- [ ] `npm test` ends with `pass <N> / fail 0`.
- [ ] `npm run release-smoke` ends with `PASS N/N`.

If anything fails, fix and re-run. Do not ship an "all but one" release.

## 2. Help and version (eyeball)

```bash
node bin/cryptoserve.mjs help
node bin/cryptoserve.mjs version
```

- [ ] `help` lists every command the README mentions (scan, pqc, cbom, gate,
      encrypt, decrypt, hash-password, context, init, vault, login, status,
      census).
- [ ] `version` matches `package.json` exactly. (Drift here is how 0.3.x
      shipped with stale numbers; automated runner now blocks it.)
- [ ] No stray colors in non-TTY output (`NO_COLOR=1 node bin/cryptoserve.mjs help`
      is plain).

## 3. Init (manual; touches keychain + cwd)

The automated runner does not run `init` because it modifies the OS keychain
and the working directory. Do this once in a scratch directory:

```bash
mkdir -p /tmp/cs-init-smoke && cd /tmp/cs-init-smoke
npm init -y >/dev/null
node /path/to/cryptoserve/sdk/javascript/bin/cryptoserve.mjs init
```

- [ ] Reports `Master key stored in OS keychain` (macOS Keychain / Linux
      Secret Service / Windows Credential Manager). Falls back to encrypted
      file if no service is available; both are valid outcomes.
- [ ] Creates `.cryptoserve.json` in cwd.
- [ ] Re-running `init` reports `Master key already configured` and does not
      overwrite the existing key.
- [ ] `init --insecure-storage` clearly warns about plaintext storage.

Cleanup: delete `/tmp/cs-init-smoke` and remove the keychain entry
(`security delete-generic-password -s cryptoserve` on macOS).

## 4. Vault (manual; touches `~/.cryptoserve/vault.enc`)

Run in a throwaway HOME so you do not stomp on a real vault:

```bash
export HOME=$(mktemp -d)
CLI=/path/to/cryptoserve/sdk/javascript/bin/cryptoserve.mjs

node $CLI vault init --password smokepw
node $CLI vault set API_KEY value-xyz --password smokepw
node $CLI vault list --password smokepw
node $CLI vault get API_KEY --password smokepw     # -> value-xyz
node $CLI vault run --password smokepw -- env | grep API_KEY
node $CLI vault delete API_KEY --password smokepw
node $CLI vault reset
```

- [ ] `init` creates the vault and refuses to overwrite an existing one.
- [ ] `set / get / list / delete` round-trip cleanly.
- [ ] `vault run -- env` injects the secret as `$API_KEY` into the child
      process and does **not** leak the value to stdout/stderr in the wrapper.
- [ ] Wrong password on `get` exits non-zero with a clear message; not a
      crash, not a partial decrypt.
- [ ] `reset` removes the vault.

Cleanup: `rm -rf $HOME` (which is the temp dir).

## 5. Census (manual; network + slow)

The automated runner skips both `census` and `census --live` because they
hit npm / PyPI / crates.io and can take 90–120s.

```bash
node bin/cryptoserve.mjs census --live --ecosystems npm --format json | jq .totals
node bin/cryptoserve.mjs census --live --ecosystems npm,pypi,crates | head -30
```

- [ ] `--live --ecosystems npm` returns JSON with non-zero `totals.downloads`.
- [ ] All three ecosystems together produce a table with one row per
      ecosystem and a `Total` row.
- [ ] Top 5 weak packages list shows recognizable names (jsonwebtoken,
      bcrypt, md5, etc.); sanity check that classification still works.
- [ ] NIST 2030 countdown is sensible (years remaining > 0 today; will
      need an update when 2030 passes).
- [ ] Unknown ecosystem (`--ecosystems pizza`) warns to stderr and continues
      with the known ones.

## 6. Login + status (manual; needs a running server)

Skip if you do not have a CryptoServe server reachable. Otherwise:

```bash
node bin/cryptoserve.mjs login --server https://localhost:8003
node bin/cryptoserve.mjs status
```

- [ ] `login` accepts credentials and stores a token.
- [ ] `status` shows server, masked token, expiry, and a `healthy`
      connection badge.
- [ ] `status` with no token shows `Not logged in` (run after deleting
      `~/.cryptoserve/credentials.json`).

## 7. UX sanity

This is the part a runner can't do. Look at the output as a new user.

- [ ] Errors point to a fix. If a command fails, the user knows what to type
      next, not just that it failed.
- [ ] No raw stack traces in normal output (only with `--verbose` or
      unexpected crashes).
- [ ] `--help` for every command shows a one-line description and example
      invocation.
- [ ] Output fits 80 columns when possible. Tables align.
- [ ] No telemetry surprises. The CLI should not phone home. If you add a
      network call to a command that didn't have one, mention it here.

## 8. Cross-SDK parity (manual; known-broken today)

Re-encrypt a string with one SDK, decrypt with the other:

```bash
# JS encrypt -> Python decrypt
BLOB=$(node sdk/javascript/bin/cryptoserve.mjs encrypt "hello" --password p1 --algorithm AES-256-GCM)
python -m cryptoserve decrypt "$BLOB" --password p1

# Python encrypt -> JS decrypt
BLOB=$(python -m cryptoserve encrypt "hello" --password p1)
node sdk/javascript/bin/cryptoserve.mjs decrypt "$BLOB" --password p1
```

Today both directions fail because the SDKs use **structurally different
blob layouts**, not just different version numbers:

- JS (`sdk/javascript/lib/local-crypto.mjs:21`): `FORMAT_VERSION = 4`,
  wire = `[uint16 header-len][JSON header (alg, nonce, kid, ...)][ciphertext][authTag]`,
  then base64 of the whole thing (with a 16-byte salt prefix in the CLI
  `encryptString` wrapper).
- Python (`sdk/python/packages/cryptoserve-core/.../encoding.py:34`):
  `version = 1`, wire = `[uint8 version][uint8 alg-id][uint8 nonce-len][nonce][ciphertext]`,
  base64-encoded.

Aligning the version bytes alone is not enough. The salt prefix and the
JSON-vs-struct header design have to be reconciled too. Until they are:

- [ ] Confirm the failure is the format-mismatch error message ("Unsupported
      blob version: N" from Python or "Invalid ciphertext format" from JS),
      not a new failure mode (crash, partial decrypt, wrong plaintext).
      Wrong-plaintext or partial-decrypt is a release blocker; format
      rejection is the expected stable failure today.
- [ ] Each SDK's own encrypt/decrypt roundtrip still passes; both
      runners cover this in their respective phase 6/7.

## 9. Cleanup

- [ ] Remove any scratch directories you created (`/tmp/cs-*`).
- [ ] If you ran `init`, remove the keychain entry.
- [ ] If you ran the `login` flow, log out (`rm ~/.cryptoserve/credentials.json`).
- [ ] Commit nothing from this session unless it was an intentional fix.

## When this checklist grows

Add an item only when:

1. A bug shipped that this would have caught, **or**
2. A surface stops being covered by `npm run release-smoke`.

Keep the manual list honest. If you find yourself ticking boxes without
reading them, fold the check into `scripts/release-smoke.mjs` and delete
the manual step.

## Future work

- **Backend smoke.** Stand up the FastAPI server against a temp Postgres
  and walk the auth + keys + crypto endpoints. Larger scope; needs its own
  fixture story.
- **Cross-SDK encrypt/decrypt** parity. Section 8 documents the gap today.
  JS uses `FORMAT_VERSION = 4` with a JSON-header wire format, Python uses
  `version = 1` with a struct-header wire format. Converging the layouts
  unlocks an automated assertion in both runners.

# Release smoke: Python SDK / CLI

Run before tagging a `v*` PyPI release. Mirrors the JS structure above.

## 0. Prerequisites (Python)

- [ ] Working tree is clean (`git status`).
- [ ] On a release branch (not main).
- [ ] `sdk/python/pyproject.toml` `version =` matches the planned tag.
- [ ] Sub-package versions in `sdk/python/packages/*/pyproject.toml` match
      what `sdk/python/pyproject.toml` pins.

## 1. Automated runner (Python)

```bash
cd sdk/python
pip install -e packages/cryptoserve-core \
            -e packages/cryptoserve-client \
            -e packages/cryptoserve-auto \
            -e .
pytest tests/ -v --tb=short -x
python scripts/release_smoke.py
```

- [ ] `pytest tests/` exits 0.
- [ ] `python scripts/release_smoke.py` ends with `PASS N/N`.

If anything fails, fix and re-run. Do not ship an "all but one" release.

The runner downloads the `cryptoscan` Go binary the first time `scan` is
invoked. If you see `Downloading cryptoscan vX.Y.Z (...)` in CI logs, that
is expected, not a bug.

## 2. Help & version (eyeball)

```bash
python -m cryptoserve help
python -m cryptoserve version
```

- [ ] `version` matches `sdk/python/pyproject.toml` exactly. The automated
      runner asserts this; eyeball it once anyway.
- [ ] `help` lists every command the README mentions (scan, pqc, cbom, gate,
      encrypt, decrypt, hash-password, contexts, login, status).
- [ ] No stray ANSI escapes in non-TTY output
      (`NO_COLOR=1 python -m cryptoserve help` is plain).

## 3. Contexts (manual; needs login + server)

The automated runner skips `contexts` because it queries the server. With
a running CryptoServe API:

```bash
python -m cryptoserve login
python -m cryptoserve contexts
python -m cryptoserve contexts --example user-pii
```

- [ ] `contexts` lists at least the default seeded contexts (user-pii,
      etc.) with algorithm + compliance fields.
- [ ] `contexts --example user-pii` prints a runnable code snippet.
- [ ] Unknown context name (`contexts --example __nope__`) exits non-zero
      with a clear message; not a stack trace.

## 4. Backup / restore / certs (manual; admin-scoped)

These touch admin-only endpoints and the local filesystem. Smoke them once
per release in a scratch dir:

```bash
python -m cryptoserve certs self-signed --cn smoke.example.com --out /tmp/cs-smoke
python -m cryptoserve certs parse /tmp/cs-smoke/cert.pem
```

- [ ] `certs self-signed` writes `cert.pem` + `key.pem` and reports the
      paths.
- [ ] `certs parse` decodes the cert and surfaces CN, validity, key algo.

## 5. UX sanity (Python)

- [ ] Errors point to a fix.
- [ ] No raw stack traces in normal output. Tracebacks only on truly
      unexpected crashes.
- [ ] Output fits 80 columns when possible.
- [ ] No telemetry surprises. If you add a network call to a command that
      didn't have one, mention it here.

## 6. Cross-SDK parity

Run the cross-SDK section above (§8 of the JS checklist). Today both
directions fail with a blob-version mismatch. Confirm the failure mode
matches before tagging, and treat any other failure (crash, partial
decrypt, wrong plaintext) as a release blocker.
