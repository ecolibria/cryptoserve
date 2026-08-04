# Changelog

All notable changes to CryptoServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [CLI 0.6.0] - 2026-08-03

A minor rather than a patch because the shape of a `gate` violation changed. A
CI job that filters the JSON on `.risk` will read different values after this
release, and that is the point: `.risk` meant two different things depending on
which flags were passed.

### Changed

`gate` had one threshold, `--max-risk`, and it carried two meanings.

`--max-risk` bounds QUANTUM risk: how far a cryptographically relevant quantum
computer would weaken an algorithm. Nothing in the flag name, the help text or
the output said so, while the same output printed `[CRITICAL] md5` using
`critical` to mean security severity. Two meanings, one vocabulary. The
consequences were all reachable from the command line:

- `--max-risk none` FAILED a correct AES-256-GCM + SHA-256 + bcrypt project,
  because SHA-256 carries quantum risk `low`.
- `--max-risk none` PASSED unauthenticated CBC, which `scan` reports at
  severity `medium`. The strictest available setting failed good code and
  passed a real weakness.
- No value of `--max-risk` tightened the gate on security severity at all.
- Medium-severity findings -- unauthenticated CBC, a static IV -- were
  unreachable by any combination of `--max-risk`, `--fail-on-weak` and
  `--min-score`. `gate` counted them as `safe`.

There are now two thresholds, because a finding has two independent properties:

- `--max-risk` keeps its meaning and says so, in the help and in the report,
  which now reads `Max quantum risk`. A quantum-risk violation is labelled
  `[QUANTUM LOW]` rather than `[LOW]`, so no two labels share a vocabulary
  without sharing a meaning.
- `--max-severity` is new and bounds security severity as `scan` reports it.
  It takes `none`, `low` or `medium` and defaults to `medium`, which is exactly
  the previous behaviour: high and critical fail. Lower it to reach medium
  findings.

`--max-severity high` and `--max-severity critical` are refused with exit `2`.
High and critical findings always fail the gate, so a higher value could only
loosen it. Accepting and ignoring it would be a flag that appears to act and
does not; honouring it would make the flag a kill switch for a disabled TLS
certificate check. Refusing by name is the third option.

The default verdict is deliberately unchanged. The defect was that medium
findings were unreachable, not that the gate was lax, and tightening the default
would flip verdicts for every existing CI job on upgrade with no code change --
the same "teaches people to ignore the check" failure this release fixes in the
publish workflow.

### Fixed

- **`--fail-on-weak` rewrote the findings it took over.** AES-ECB reported
  `risk: "high"` normally and `risk: "none"` under the flag; 3DES and Blowfish
  went `high` to `low` the same way; `type` was dropped; and the actionable fix
  (`Replace with AES-256-GCM (any authenticated mode)`) was replaced by a bare
  description (`ECB mode leaks patterns`). The exit code was unaffected, so it
  was not a fail-open, but a CI policy filtering `.risk == "high"` saw nothing
  under the flag whose name sounds strictest. The cause was deduplication
  order: the algorithm-level record silently replaced the scanner's record
  instead of merging with it. Every violation now carries both `risk` (quantum)
  and `severity` (security), neither of which depends on the flags, plus
  `riskBreach` / `severityBreach` / `weak` recording which threshold fired.
- **`gate` counted an algorithm it had just failed on as `safe`.** AES-ECB is
  quantum-`none` and structurally broken, so it appeared in the `safe` count of
  the same summary whose violation list failed the build.
- **`gate` ignored TLS findings entirely.** This is the fifth appearance of one
  fail-open, after secrets, committed private keys, misuse findings and AES-ECB.
  `scan` reported SSLv3 at `critical`, `gate` passed the same tree 100/100, and
  `gate --format sarif` emitted three `level: "error"` results while exiting
  `0` -- one command contradicting itself about one tree, so a CI job uploading
  that report got three code-scanning alerts from a gate that had just told the
  build it passed. Deprecated protocol versions now fail the gate, bounded by
  `--max-severity` and deduplicated by location and protocol.
- The severity of a weak algorithm is now defined once, in the scanner, and
  imported by the gate. It was about to be restated in a second place, which is
  how two commands drift into rating the same algorithm differently.
- **A severity the ladder does not recognise now fails closed.** Comparing
  ladder indices directly meant `indexOf` returned `-1` for an unrecognised
  value and `-1 > anything` is false, so a typo in a single pattern definition
  (`severity: 'moderate'`) would have made that finding unable to breach any
  threshold, silently, while the gate reported the tree clean. A gate must not
  be disarmed by a misspelling.
- **Violation labels now read on one scale.** `[TLS]` and `[MEDIUM]` in the same
  list gave no way to see that the TLS finding was the more severe of the two.
  Severity leads every label that has one and the category follows it
  (`[CRITICAL TLS]`, `[CRITICAL SECRET]`, `[MEDIUM]`), and a quantum-risk
  breach is labelled `[QUANTUM LOW]` so the other axis names itself.
- **A quantum-risk violation is no longer a dead end.** It had no remediation
  line at all, because the answer is a migration rather than a per-line edit.
  It now says so and names `cryptoserve pqc`.

### Notes

`--max-severity` does not reach credential findings. Secrets and committed
private keys fail under their own rule and are waivable only by name, with
`--allow-secrets`; a threshold that could waive them would be a second,
unnamed waiver.

## [CLI 0.5.0] - 2026-07-30

A minor rather than a patch because `census --live` is gone. Under 0.x semver a
breaking change bumps the minor, and a user pinned to `^0.4.0` should not
silently receive a CLI whose flag was deleted -- even one that was reporting
rate-limited requests as zero downloads.

### Fixed

Five defects that shared one shape: an argument the command could not act on was
carried into the work instead of stopping it, so the command reported a confident
result about something it had not measured. All five predate 0.5.0.

- `gate --min-score abc` failed OPEN. `parseInt('abc')` is `NaN` and every
  comparison against `NaN` is false, so the threshold was not lax -- it was
  absent. A gate that was failing on score printed `min: NaN` and exited `0`,
  which means a typo in a CI threshold turned a red build green. `--min-score`
  now requires a number from 0 to 100; `--max-risk` requires one of the five
  levels (an unknown value scored `-1` in the risk order, making every algorithm
  a breach); an unknown `--format` no longer falls back to text. Each exits `2`.
  `Number` rather than `parseInt`, so `--min-score 40abc` is rejected instead of
  silently becoming 40.
- `cbom <path that does not exist>` emitted a valid CBOM asserting
  `quantumReadiness.score: 100, riskLevel: none` and exited `0`, while `scan` and
  `gate` rejected the same path. A mistyped path produced a compliance artifact
  certifying a tree nobody had read. It now exits `2`, and both `cbom` and `gate`
  report how many files they read -- neither showed a count, which is why an
  empty result and a clean result looked identical.
- `cryptoserve init --insecure-storage` died with
  `Cannot access 'configPath' before initialization`. A local `const configPath`
  shadowed the imported `configPath` for the whole function body, so the
  plaintext-storage branch read it from its temporal dead zone. That branch is
  the exact recovery the preceding no-keychain error recommends, so `init`
  dead-ended for every user without a keychain.
- Any password prompt with stdin redirected -- `</dev/null`, a pipe, any CI
  runner -- printed a Node "Detected unsettled top-level await" diagnostic
  carrying installed file paths, and exited `13`. The prompt registered a `data`
  listener that could never fire. It now says what to pass and exits `2`; the
  hint is per-command, because the answer differs (`--password` for most,
  `--insecure-storage` for `init`, a positional value for `vault set`).
  `--password ""` and a bare `--password` were both read as "not supplied" and
  answered with a prompt, so a CI job whose password variable resolved empty
  blocked on a question it could not answer; both are now rejected by name.
- `pqc <path>` accepted the path and then discarded it, analysing the current
  directory instead -- exit `0`, no warning, a confident readiness score for the
  wrong tree. It now analyses the directory it was given and names it, with
  `scannedPath` and `filesScanned` added to the JSON report and a `Directory`
  line in the text report.

An adversarial review of the five fixes above found the same fail-open shape in
five more places, all pre-existing:

- `scan` and `gate` checked only that a path EXISTED. A file exists, walks to
  zero source files and reports a clean tree, so `gate ./package.json
  --min-score 99` certified 100/100 and exited `0` -- the same fail-open as a
  missing path, in the command whose whole job is to fail closed. All four
  path-taking commands now require a directory.
- `pqc --profile helthcare` fell back to `general`, and the warning was
  SUPPRESSED in JSON mode. A CI job asserting HIPAA posture with one transposed
  letter got "not vulnerable / medium", exit `0`, and no signal on any stream.
  `--profile` and `--algorithm` are now validated against the lists their
  implementations actually switch on, rather than a second copy that can drift.
- An option given twice was resolved by `indexOf`, silently taking the first.
  `gate . --min-score 10 $EXTRA_ARGS` therefore discarded a stricter threshold
  the caller appended and never reported the one it ignored. A repeated option
  is now refused.
- `vault set KEY --password PW` read the positional arguments raw and stored the
  literal string `--password` as the secret, exit `0`. That is the exact
  non-interactive form the docs recommend for CI.
- `--min-score 0x10` became 16 and `0b101` became 5, because `Number` accepts
  more shapes than the usage line promises. Only a plain decimal is accepted.

A fresh-user release test then found three more, also pre-existing:

- **`scan` reported no hardcoded secrets in `.env` or any other config file.**
  An AWS key committed in `.env` produced `Secrets found: 0` while the SAME
  literal in `config.js` was found. The walker collected `.env` and then used it
  only for TLS settings; secret detection ran inside the source-file loop,
  behind a language check `.env` can never satisfy. So the highest-value target
  the scanner has returned a deliberate-looking all-clear, on a capability both
  help surfaces advertise. Detection is now one function applied to source and
  config files alike, and `.env.local` / `.env.production` and the other
  value-bearing dotenv variants are collected too (templates are not). The
  report counts source and config files separately, because `Secrets found: 0`
  means something different when no `.env` was read.
- **`cryptoserve login` hung with no terminal**, printing a URL and waiting 120
  seconds on a browser callback that could never arrive, where every other
  interactive command exits `2` at once. It now refuses immediately. A callback
  port that is already held is reported by name rather than killing the process
  with a raw Node `EADDRINUSE` stack trace.
- **`login --server` is now required.** The built-in default was
  `https://localhost:8003`, where nothing runs on a user's machine, so the
  out-of-the-box flow could only ever time out. The CLI cannot know the
  operator's server, and a guess that is wrong for everyone is worse than an
  error naming what to pass.

A re-test after those fixes found one more, and it made the `.env` fix
unreachable from the enforcement path:

- **`gate` ignored hardcoded secrets entirely.** `scan` printed
  `[CRIT] AWS Access Key .env:1` and `gate` on the identical tree returned
  `PASS 100/100`, exit `0`, `violations: []`. The gate evaluated algorithm risk
  only, so the highest-severity finding the scanner produces had no path into
  CI. Two commands reading one tree must not disagree on direction. Secrets are
  now violations, with `file:line`, and `--allow-secrets` waives them by name
  for a documented false positive.

A final re-test found two more, one of them the unswept sibling of the fix
immediately above:

- **A committed private key passed the gate.** `scan` listed
  `Certificate/Key Files: server.key` and `gate` on the same tree returned
  `PASS 100/100`, exit `0`, with no flag that caught it. `-----BEGIN RSA PRIVATE
  KEY-----` was treated identically to a public `-----BEGIN CERTIFICATE-----`.
  Publishing a certificate is routine; publishing the key that signs it is the
  incident. `scan` now reports `privateKeyFiles` separately from `certFiles`,
  and `gate` fails on them (waivable with the same `--allow-secrets`).
- **`vault reset` destroyed the vault with a wrong password, or none at all.**
  It printed `Vault deleted.` and exited `0` either way, while
  `vault delete KEY` with a wrong password correctly refused. Deleting one
  secret was authenticated and deleting all of them was not. `reset` now proves
  it can open the vault first.

A systematic sweep of every finding class `scan` can produce against `gate`
then found the third instance of the same defect, before another review had to:

- **`gate` ignored API-misuse findings.** `scan` reported
  `TLS certificate verification disabled` at severity CRITICAL and `gate`
  exited `0`, because violations were derived from the algorithm inventory and
  a misuse finding carries no algorithm. Disabling certificate verification is
  precisely what a CI gate exists to stop. Misuse findings at `critical` or
  `high` are violations now; a weak ALGORITHM still produces exactly one
  violation rather than two.

A final pre-publish check then caught two defects in that very fix:

- **`--allow-secrets` waived the TLS-verification-bypass finding too**, silently,
  turning a credential waiver into an enforcement kill switch. It waives
  credentials only: a committed secret and a committed private key. Weak
  algorithms, AES-ECB, 3DES and a disabled certificate check are unaffected by
  it, and any waiver is now stated in the human output.
- **AES-ECB and 3DES passed the gate at every `--max-risk` level, including
  `none`.** Deduplication skipped any weak-pattern finding that carried an
  algorithm name, on the assumption it had already produced a violation. Those
  are different sets: ECB is structurally broken rather than quantum-broken, so
  its `quantumRisk` is correctly `none`, it breaches no risk level, and it had
  raised no violation to be deduplicated against. `scan` rated the same line
  `severity: high`. Deduplication is now against the violations actually
  raised, so a HIGH finding is always reachable and a weak algorithm is still
  counted exactly once.

A final check found three more, two of them about surfaces disagreeing:

- **Private-key detection was gated on the file EXTENSION**, so `server.key`
  was found and a byte-identical `id_rsa` was not. `id_rsa` is the most common
  name a committed private key actually has; `id_ed25519`, `deploy_key` and
  `key.txt` were missed the same way. A key's evidence is its first line, so
  small unclassified files are now sniffed for a PEM private-key header. A
  public `-----BEGIN CERTIFICATE-----` is deliberately not a match.
- **`--allow-secrets` did not filter SARIF.** Text said "waived", JSON dropped
  the violation, and SARIF still emitted it at `level: "error"`, so a gate that
  exited `0` uploaded alerts to code scanning for findings it had just declared
  waived. And private keys never reached SARIF at all, so a CI job saw no alert
  for the finding that failed its build. All three surfaces agree now.
- `--allow-secrets` was undocumented on every help surface. A switch that turns
  exit `1` into exit `0` has to be visible in a CI config review.

`gate --help` now also states plainly that `--max-risk` bounds QUANTUM risk
rather than security severity, which is why a weak algorithm fails the gate
regardless of it.

The full sweep now agrees in both directions. Fails by default: a committed
secret, a committed private key (whatever it is named), MD5, SHA-1, RC4,
AES-ECB, 3DES, RSA-1024, and a disabled certificate check. Passes: a public
certificate and a clean SHA-256 tree. `--allow-secrets` moves only the
credential findings, on every output format.

Two detection gaps closed while there:

- `AWS_SECRET_ACCESS_KEY` was not detected. Detection was prefix-driven (`AKIA`,
  `ghp_`, `sk-`), which catches an access key ID and misses its more sensitive
  other half, because a 40-character secret has no prefix to key on. The
  variable it is assigned to is the signal, so the value's length and alphabet
  now qualify it. Verified against three real trees for false positives: the
  only hits were this repository's own deliberate fixtures.
- Placeholder suppression was by FILENAME, so any value in `.env.example` was
  ignored. That is backwards: a template is the file that actually gets
  committed while `.env` is usually gitignored, so a real key pasted into a
  template is the higher-risk case. Templates are scanned, and placeholders are
  filtered by their value (`your-key-here`, `<your-key>`, `changeme`).

### Added
- `--password-stdin` on every command that takes a password. `--password <value>`
  puts the secret in `argv`, where it is readable from `ps`,
  `/proc/<pid>/cmdline` and shell history; this is the `docker login
  --password-stdin` shape and it is now the form the CLI recommends. The two are
  mutually exclusive.
- `CRYPTOSERVE_NO_KEYCHAIN=1` to never touch the OS keychain. Containers and CI
  runners have no keychain service, and probing for one costs a subprocess and
  can hang. It also makes `--insecure-storage` reachable on demand: that branch
  runs only when no master key is found, so on any machine where `cryptoserve
  init` has ever succeeded, a regression test for it silently exercises nothing
  -- which is how the ReferenceError above shipped in the first place.
- `gate --format json` reports `summary.manifestsFound` alongside
  `summary.filesScanned`. The text output could already distinguish a
  manifest-only project from an empty directory; the JSON that CI actually
  parses could not, because both reported `filesScanned: 0`.

### Fixed (census)
- `cryptoserve census` reported collection failures as measurements of zero.
  Every one of the eleven download collectors recorded a failed request as
  `downloads: 0`: 24 sites, plus 6 more in the inline copy behind `--live`.
  pypistats.org rate-limits at the rate the collector asked, so `cryptography`,
  which really has over a billion downloads a month, was printed as none. Three
  runs of identical code hours apart differed by hundreds of millions of
  downloads depending on which packages were throttled that minute.
- The command carried its own package catalog, which had drifted to 357 entries
  against the census's 355, so the CLI and census.cryptoserve.dev disagreed on
  the denominator of every published share.
- The report never showed the collection date, presenting a snapshot as a
  current reading, and never separated measured from modelled downloads. NuGet
  and RubyGems divide a lifetime total by an assumed number of months and
  CocoaPods publishes nothing, so 10.5% of the headline is a proxy times a
  constant. Both are now shown: the collection date leads the report and the
  measured figure is named alongside the combined one.
- `cryptoserve help <command>` printed the full command list instead of that
  command's help. The per-command help existed but only `<command> --help`
  reached it.

### Changed
- **An unknown flag now stops the command (exit `2`) rather than warning and
  continuing.** That was a fail-open in flag-name form: `gate . --min-scoree 95`
  warned, silently fell back to the default threshold, printed `(min: 50)` and
  exited `0`. A typo must not loosen a gate, and an unparseable option *value*
  already exited `2`.
- **`gate` fails on hardcoded secrets and committed private keys by default**,
  and refuses a tree it read no files from rather than certifying it `100/100`. A repository with a
  committed credential that previously passed will now fail; that is the point.
  `--allow-secrets` opts out explicitly.
- Exit `2` now means "the command could not run as invoked" across the whole
  CLI, not just `gate`; one condition should not have two codes. `1` keeps its
  meaning: the command ran and reported a failure. Moved from `1` to `2`: `scan`
  on a bad path, an unknown command, an unknown subcommand, an unknown context
  name, an invalid `--algorithm`, and a missing required argument.
  The Python CLI is unchanged and its `scan` still exits `1` on a missing path,
  so the two SDKs disagree on that one case until Python is brought in line.
- `cryptoserve census` renders the published snapshot from
  census.cryptoserve.dev rather than collecting its own. The census publishes
  dated snapshots, so there is now one definition of the measurement and the
  CLI's figures match the site by construction. Cached for a day;
  `--no-cache` re-fetches.
- `cryptoserve census --live` has been removed. It collected three of the eleven
  ecosystems from a third copy of the fetch logic, with the same silent zeros,
  while the help text advertised all eleven. Running it now prints why and exits
  non-zero.

### Removed
- `lib/census/collectors/`, `lib/census/package-catalog.mjs` and
  `lib/census/aggregator.mjs`. Only `formatNumber` survives, in
  `lib/census/format.mjs`.

## [CLI 0.4.0] - 2026-07-27

### Fixed
- SHA-1 was reported as SHA-256. The JS literal matcher mapped every
  `sha256|sha384|sha512|sha1` hit to the single label `SHA-256`, so
  `createHash('sha1')` appeared in the inventory as a strong hash. HS/ES/PS
  token algorithms collapsed onto `RS256` the same way.
- 3DES, Blowfish and RC2 were undetectable in JavaScript. The weak-cipher
  patterns required a closing quote immediately after the family name, so
  `createCipheriv('des-ede3-cbc', ...)`, `'bf-cbc'` and `'rc2-40-cbc'` matched
  nothing at all.
- JavaScript and TypeScript source algorithms never reached `sourceAlgorithms`,
  so `cbom`, `gate` and `pqc` saw no crypto from JS source at all.
- `require('node:crypto')` was never recognized as an import. The pattern used a
  character class that could match the opening paren or the quote but not both.
- pyca/cryptography idioms were unmatched: `rsa.generate_private_key`,
  `ec.generate_private_key`, `padding.*`, `hashes.*`, and the legacy ciphers
  exposed through `algorithms.TripleDES`, `algorithms.Blowfish`,
  `algorithms.ARC4`.
- CBOM documents named the wrong producer. `cbom.mjs` hardcoded version `0.2.0`,
  so every CycloneDX `metadata.tools[].version` and SPDX `Tool: CryptoServe-`
  string emitted across the 0.3.x line was wrong.
- `gate --format sarif` and `scan --format sarif` were documented but not
  implemented; both fell through to the terminal renderer, so a CI job piping
  the output into `upload-sarif` was handing it a text report.
- `gate` emitted each algorithm twice when `--fail-on-weak` was set, inflating
  the violation count.
- Truncated table cells gave no indication they had been cut, so
  `chacha20-poly1305, argon2, bcr` read as a package named `bcr`.
- A wrong vault password surfaced the raw OpenSSL string "Unsupported state or
  unable to authenticate data".
- `vault init` reported the path `~/.cryptoserve/vault.enc` regardless of where
  it had actually written.

### Added
- Every finding carries `file:line`, and every weak algorithm carries a CWE and
  a named replacement.
- SARIF 2.1.0 output for `scan` and `gate`, with a physical location on every
  result. `--output <file>` writes the document to disk.
- Weak asymmetric key-size detection across languages: `modulusLength`,
  `key_size=`, `rsa.GenerateKey`, `RSA_generate_key`, `RsaPrivateKey::new` and
  `openssl genrsa`, restricted to forms where algorithm and bit length are
  unambiguous in a single expression.
- Weak-algorithm findings are derived from the algorithm database rather than
  per-language regexes, so Go, Python, Java, Rust and C now get the coverage
  that previously existed only for JavaScript.
- API misuse detection distinct from weak algorithms: `createCipher` without an
  IV, non-CSPRNG randomness used for secrets, and disabled TLS verification.
- `CRYPTOSERVE_HOME` and `XDG_CONFIG_HOME` relocate the state directory. Five
  modules previously hardcoded `~/.cryptoserve`, so no test, CI job or container
  could avoid writing into the invoking user's home.
- WebCrypto algorithm names, crypto-js, node-forge, tweetnacl and JOSE
  algorithm identifiers are recognized in JS/TS.
- `aria` and `sm4` added to the algorithm database (133 entries, 22 weak).

### Changed
- JavaScript and TypeScript are scanned by the same table-driven engine as every
  other language instead of a separate code path.
- Algorithm names that appear as call arguments are read from the source and
  canonicalized rather than matched to a fixed label.
- A source-detected library is given an algorithm list only when its file
  imports exactly one crypto library. With two or more, attribution is not
  decidable without dataflow analysis.
- `scan` reports "Source files" (analyzed) and "Files examined" (walked)
  separately. The single "Files scanned" number counted only the former.
- Census collectors have a 15 second per-request deadline and report progress
  without `--verbose`.
- An unrecognized `--format` is an error instead of a silent fall back to text.

---

## [SDK 1.4.3] - 2026-03-18

### Fixed
- CryptoClient and AsyncCryptoClient now accept `base_url` as keyword alias for `server_url` for backwards compatibility
- Clarified easy.py encrypt/decrypt docstrings to state these are offline password-based functions, not server-connected operations with crypto contexts

---

## [CLI 0.3.4] - 2026-03-17

### Added
- `--help` flag support for all subcommands (scan --help, pqc --help, etc.)
- Built-in help text for scan, pqc, cbom, gate, context, vault, encrypt, decrypt, census commands
- Nonexistent path detection with exit code 1 for scan command

### Fixed
- LICENSE file now included in npm package

### Documentation
- README: Added Built-in Help, Use Cases, and Exit Codes sections
- README: Split SDK section into Node.js (offline) and Python (server-connected)
- cli.md: Reconciled gate flags with actual CLI source, added output examples
- cli.md: Added missing census command documentation
- New CLI quickstart guide (docs/getting-started/cli-quickstart.md)

---

## [SDK 1.4.2] - 2026-03-17

### Added
- `encrypt()` now accepts both `str` and `bytes` input (auto-encodes strings to UTF-8)
- `create_token()` and `verify_token()` now accept both `str` and `bytes` keys
- argon2 password hashing support (optional: `pip install cryptoserve-core[password]`)
- `--password` flag for vault and hash-password CLI commands (non-interactive/CI mode)

### Fixed
- Python 3.14 compatibility: updated sqlalchemy (>=2.0.40) and asyncpg (>=0.30.0) pins
- Dockerfile.allinone: application processes now run as non-root user
- SDK hash_verify format normalization (hex/base64 auto-detection)
- Server key exchange now case-insensitive (X25519, x25519, ECDH-P256 all accepted)
- argon2-cffi added to backend production requirements
- Docker liboqs LD_LIBRARY_PATH fixed (PQC operations now work in containers)
- pyhpke added to backend requirements (HPKE endpoints functional)

---

## [SDK 1.0.1] - 2026-02-06

### Fixed
- CLI commands (`verify`, `info`, `configure`, `status`) crashed due to removed `crypto` singleton (removed in v0.7.0)
- Added missing `pyyaml>=6.0` dependency for `cryptoserve gate` command
- Fixed `AESGCMCipher.encrypt()` docstring showing incorrect 3-tuple return (actual: 2-tuple)

---

## [SDK 1.0.0] - 2026-02-06

### Added

#### PyPI Publication
- Published 4 packages to PyPI: `cryptoserve`, `cryptoserve-core`, `cryptoserve-client`, `cryptoserve-auto`
- Install with `pip install cryptoserve` (no more local editable installs required)
- Modular architecture: use individual packages for specific needs

#### Python SDK Features
- `CryptoServe` class with auto-registration and local key caching (~250x speedup)
- `encrypt()` / `decrypt()` with context-based key management
- `encrypt_string()` / `decrypt_string()` for string convenience
- `encrypt_json()` / `decrypt_json()` for JSON objects
- Usage hints (`at_rest`, `in_transit`, `in_use`, `streaming`, `disk`) for automatic algorithm selection
- FastAPI integration with `EncryptedStr` type annotation
- SQLAlchemy integration with `EncryptedString` column type
- CLI with 18 commands: `login`, `logout`, `verify`, `info`, `wizard`, `scan`, `cbom`, `pqc`, `gate`, `certs`, `backup`, `restore`, `ceremony`, and more

#### SDK Packages
- `cryptoserve-core` (0.1.0): Pure crypto primitives (AES-GCM, ChaCha20-Poly1305, RSA, hashing)
- `cryptoserve-client` (0.1.0): HTTP client for CryptoServe API
- `cryptoserve-auto` (0.1.0): Auto-protect third-party libraries

---

## [1.1.0] - 2026-01-03

### Added

#### Certificate Revocation Checking
- OCSP (Online Certificate Status Protocol) support for real-time revocation checking
- CRL (Certificate Revocation List) support with automatic URL extraction
- Combined revocation check with OCSP-to-CRL fallback
- New methods: `get_ocsp_url()`, `get_crl_urls()`, `check_ocsp()`, `check_crl()`, `check_revocation()`

#### Batch Encryption API
- `POST /v1/crypto/batch/encrypt` - Encrypt up to 100 items per request
- `POST /v1/crypto/batch/decrypt` - Decrypt up to 100 items per request
- Client-provided IDs for tracking individual items
- `fail_fast` mode (stop on first error) or continue mode
- AAD (Additional Authenticated Data) support per item

#### SDK Key Bundle Caching
- `GET /v1/crypto/key-bundle` endpoint for SDK local caching
- Enables offline encryption/decryption operations
- Measured 95%+ cache hit rate in production workloads

#### Documentation
- Comprehensive migration guide for AWS KMS, HashiCorp Vault, and crypto libraries
- Cryptographic assessment report documenting NIST compliance

### Fixed
- Dynamic version retrieval in backup metadata (was hardcoded)

### Security
- Certificate revocation checking prevents use of compromised certificates
- Batch API enforces same authorization as single-item operations

---

## [1.0.0] - 2025-01-03

### Added

#### 5-Layer Context Model
- Data Identity layer: sensitivity classification (low/medium/high/critical), PII/PHI/PCI flags
- Regulatory layer: compliance framework support (HIPAA, GDPR, PCI-DSS, SOC2)
- Threat Model layer: quantum resistance requirements, protection lifetime
- Access Patterns layer: frequency-based optimization, latency requirements
- Technical layer: hardware acceleration, key size requirements
- Automatic algorithm selection based on all 5 layers

#### Policy Engine
- Customizable cryptographic policy rules
- Three severity levels: block, warn, info
- Default policies for common security requirements
- Policy evaluation API for testing before deployment
- Context-specific policy scoping
- CI/CD integration support via `/api/policies/check` endpoint

#### Admin Dashboard
- Overview with KPI cards (users, identities, operations, success rate)
- User management with search and pagination
- Global identity management with filtering
- Audit log viewer with export (CSV/JSON)
- Context management with key rotation
- Usage analytics with charts
- System health monitoring

#### Frontend Improvements
- Policies page with interactive policy evaluator
- Dashboard navigation with policies link
- Mobile-responsive layout improvements

#### Backend Features
- PostgreSQL-based context configuration storage
- Context-derived cryptographic requirements
- Algorithm recommendation engine
- Admin API endpoints with role-based access

### Security
- AES-256-GCM encryption by default
- HKDF-SHA256 key derivation
- JWT-based identity tokens
- Full audit logging
- Policy enforcement at runtime

### Infrastructure
- Docker Compose deployment
- GitHub OAuth integration
- CI/CD integration documentation

## [0.1.0] - 2024-12-01

### Added
- Initial release
- Basic encrypt/decrypt operations
- Context-based key management
- Identity management
- Personalized SDK generation
- GitHub OAuth authentication
- Audit logging

---

[CLI 0.3.4]: https://github.com/ecolibria/cryptoserve/compare/cli-v0.3.3...cli-v0.3.4
[SDK 1.4.2]: https://github.com/ecolibria/cryptoserve/compare/sdk-v1.4.1...sdk-v1.4.2
[SDK 1.0.1]: https://github.com/ecolibria/cryptoserve/compare/sdk-v1.0.0...sdk-v1.0.1
[SDK 1.0.0]: https://github.com/ecolibria/cryptoserve/compare/v1.1.0...sdk-v1.0.0
[1.1.0]: https://github.com/ecolibria/cryptoserve/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ecolibria/cryptoserve/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/ecolibria/cryptoserve/releases/tag/v0.1.0
